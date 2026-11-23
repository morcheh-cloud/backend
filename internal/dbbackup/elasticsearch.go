package dbbackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

// Elasticsearch / OpenSearch export: per index its settings (without the
// cluster-made ones), mappings and aliases, then every document read through a
// point in time (a consistent view, sorted by _shard_doc) or, where there is
// none (OpenSearch, Elasticsearch before 7.10), a scroll.

const (
	esPage      = 1000
	esKeepAlive = "2m"
	// A bulk request is sent at this many documents or bytes.
	esBulkDocs  = 1000
	esBulkBytes = 5 << 20
)

// elasticDump writes name (one index; empty = every index that isn't a
// system one) to out. An alias or a data stream is refused: back up the index
// itself, so the file restores into one index.
func elasticDump(ctx context.Context, h *dbmon.HTTPDB, name string, out io.Writer) error {
	var root struct {
		Version struct {
			Number       string `json:"number"`
			Distribution string `json:"distribution"`
		} `json:"version"`
	}
	if err := h.JSON(ctx, http.MethodGet, "/", nil, &root); err != nil {
		return err
	}
	indices, err := esDumpList(ctx, h, name)
	if err != nil {
		return err
	}
	w, err := NewNativeWriter(out, NativeHeader{
		Morche: ElasticNDJSON,
		Engine: dbmon.Elastic,
		Source: dbmon.ElasticFlavor(root.Version.Distribution) + " " + root.Version.Number,
	})
	if err != nil {
		return err
	}
	for _, idx := range indices {
		if err := esDumpIndex(ctx, h, idx, w); err != nil {
			return fmt.Errorf("%s: %w", idx, err)
		}
	}
	return w.Close()
}

// esDumpList is the indices a dump of name covers.
func esDumpList(ctx context.Context, h *dbmon.HTTPDB, name string) ([]string, error) {
	if name == "" {
		var rows []struct {
			Index  string `json:"index"`
			Status string `json:"status"`
		}
		if err := h.JSON(ctx, http.MethodGet, "/_cat/indices?format=json&h=index,status&expand_wildcards=open,closed", nil, &rows); err != nil {
			return nil, err
		}
		var out, closed []string
		for _, r := range rows {
			if dbmon.ElasticSystemIndex(r.Index) {
				continue
			}
			if r.Status == "close" {
				closed = append(closed, r.Index)
				continue
			}
			out = append(out, r.Index)
		}
		if len(closed) > 0 {
			return nil, fmt.Errorf("%s closed, so its documents can't be read. Open it (POST /<index>/_open) or back up the other indices one by one", esList(closed))
		}
		sort.Strings(out)
		return out, nil
	}
	var res struct {
		Indices []struct {
			Name       string   `json:"name"`
			Attributes []string `json:"attributes"`
		} `json:"indices"`
		Aliases []struct {
			Name    string   `json:"name"`
			Indices []string `json:"indices"`
		} `json:"aliases"`
		DataStreams []struct {
			Name    string   `json:"name"`
			Backing []string `json:"backing_indices"`
		} `json:"data_streams"`
	}
	err := h.JSON(ctx, http.MethodGet, "/_resolve/index/"+url.PathEscape(name)+"?expand_wildcards=all", nil, &res)
	switch dbmon.HTTPStatus(err) {
	case 0:
	case http.StatusNotFound:
		return nil, fmt.Errorf("there's no index called %s", name)
	case http.StatusBadRequest:
		// No _resolve (before 7.9): take it as an index.
		return []string{name}, nil
	default:
		return nil, err
	}
	for _, d := range res.DataStreams {
		if d.Name == name {
			return nil, fmt.Errorf("%s is a data stream. Back up its backing indices (%s) one by one; each restores as a plain index", name, strings.Join(d.Backing, ", "))
		}
	}
	for _, a := range res.Aliases {
		if a.Name == name {
			return nil, fmt.Errorf("%s is an alias of %s. Back up the index itself; its aliases go into the file with it", name, strings.Join(a.Indices, ", "))
		}
	}
	for _, i := range res.Indices {
		if i.Name == name {
			for _, a := range i.Attributes {
				if a == "closed" {
					return nil, fmt.Errorf("%s is closed, so its documents can't be read. Open it first (POST /%s/_open)", name, name)
				}
			}
			return []string{name}, nil
		}
	}
	return nil, fmt.Errorf("there's no index called %s", name)
}

func esList(names []string) string {
	if len(names) == 1 {
		return names[0] + " is"
	}
	return strings.Join(names, ", ") + " are"
}

// esDumpIndex writes one index: its definition, then every document.
func esDumpIndex(ctx context.Context, h *dbmon.HTTPDB, idx string, w *NativeWriter) error {
	var def map[string]struct {
		Aliases  json.RawMessage `json:"aliases"`
		Mappings json.RawMessage `json:"mappings"`
		Settings map[string]any  `json:"settings"`
	}
	if err := h.JSON(ctx, http.MethodGet, dbmon.Path(idx), nil, &def); err != nil {
		return err
	}
	d, ok := def[idx]
	if !ok {
		return errors.New("the cluster didn't describe the index")
	}
	settings := map[string]any{}
	if s, ok := d.Settings["index"].(map[string]any); ok {
		dbmon.CleanElasticSettings(s)
		settings["index"] = s
	}
	sraw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	var count struct {
		Count int64 `json:"count"`
	}
	ni := NativeIndex{Name: idx, Settings: sraw, Mappings: d.Mappings, Aliases: d.Aliases}
	if h.JSON(ctx, http.MethodGet, dbmon.Path(idx, "_count"), nil, &count) == nil {
		ni.Documents = &count.Count
	}
	if err := w.Index(ni); err != nil {
		return err
	}
	err = esDumpPIT(ctx, h, idx, w)
	if errors.Is(err, errNoPIT) {
		err = esDumpScroll(ctx, h, idx, w)
	}
	return err
}

var errNoPIT = errors.New("point in time isn't available")

// esHitPage is one page of documents.
type esHitPage struct {
	PitID    string `json:"pit_id"`
	ScrollID string `json:"_scroll_id"`
	Hits     struct {
		Hits []struct {
			ID      string          `json:"_id"`
			Routing string          `json:"_routing"`
			Source  json.RawMessage `json:"_source"`
			Sort    []any           `json:"sort"`
		} `json:"hits"`
	} `json:"hits"`
}

func (p *esHitPage) write(w *NativeWriter) error {
	var b bytes.Buffer
	for _, hit := range p.Hits.Hits {
		b.Reset()
		src := hit.Source
		if len(src) > 0 {
			if err := json.Compact(&b, src); err != nil {
				return fmt.Errorf("document %s: %w", hit.ID, err)
			}
			src = append(json.RawMessage(nil), b.Bytes()...)
		} else {
			// _source turned off in the mapping: nothing to keep but the id.
			src = json.RawMessage("{}")
		}
		raw, err := json.Marshal(ElasticDoc{ID: hit.ID, Routing: hit.Routing, Source: src})
		if err != nil {
			return err
		}
		if err := w.Doc(raw); err != nil {
			return err
		}
	}
	return nil
}

// esPost sends a JSON body and decodes the answer as it streams.
func esPost(ctx context.Context, h *dbmon.HTTPDB, method, path string, body, out any) error {
	res, err := h.Do(ctx, method, path, body, "")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	dec := json.NewDecoder(res.Body)
	dec.UseNumber()
	return dec.Decode(out)
}

// esDumpPIT reads every document through a point in time.
func esDumpPIT(ctx context.Context, h *dbmon.HTTPDB, idx string, w *NativeWriter) error {
	var open struct {
		ID string `json:"id"`
	}
	if err := h.JSON(ctx, http.MethodPost, dbmon.Path(idx, "_pit")+"?keep_alive="+esKeepAlive, nil, &open); err != nil {
		switch dbmon.HTTPStatus(err) {
		case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed:
			return errNoPIT
		}
		return err
	}
	pit := open.ID
	defer func() {
		// A fresh context: closing must happen even when ctx was canceled.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = h.JSON(cctx, http.MethodDelete, "/_pit", map[string]any{"id": pit}, nil)
	}()
	var after []any
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		body := map[string]any{
			"size":             esPage,
			"pit":              map[string]any{"id": pit, "keep_alive": esKeepAlive},
			"sort":             []any{map[string]any{"_shard_doc": "asc"}},
			"track_total_hits": false,
			"_source":          true,
		}
		if after != nil {
			body["search_after"] = after
		}
		var page esHitPage
		if err := esPost(ctx, h, http.MethodPost, "/_search", body, &page); err != nil {
			return err
		}
		if page.PitID != "" {
			pit = page.PitID
		}
		if err := page.write(w); err != nil {
			return err
		}
		n := len(page.Hits.Hits)
		if n < esPage {
			return nil
		}
		after = page.Hits.Hits[n-1].Sort
		if after == nil {
			return errors.New("the cluster didn't say where a page ended")
		}
	}
}

// esDumpScroll reads every document with the scroll API.
func esDumpScroll(ctx context.Context, h *dbmon.HTTPDB, idx string, w *NativeWriter) error {
	var page esHitPage
	if err := esPost(ctx, h, http.MethodPost, dbmon.Path(idx, "_search")+"?scroll="+esKeepAlive, map[string]any{"size": esPage, "sort": []string{"_doc"}}, &page); err != nil {
		return err
	}
	scroll := page.ScrollID
	defer func() {
		if scroll == "" {
			return
		}
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = h.JSON(cctx, http.MethodDelete, "/_search/scroll", map[string]any{"scroll_id": []string{scroll}}, nil)
	}()
	for {
		if err := page.write(w); err != nil {
			return err
		}
		if len(page.Hits.Hits) == 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		page = esHitPage{}
		if err := esPost(ctx, h, http.MethodPost, "/_search/scroll", map[string]any{"scroll": esKeepAlive, "scroll_id": scroll}, &page); err != nil {
			return err
		}
		if page.ScrollID != "" {
			scroll = page.ScrollID
		}
	}
}

// elasticLoad restores a file into the index name. The file holds one index,
// or o.Source picks one of several. An index of that name is removed first
// with o.Replace, refused otherwise; a new one is removed again if the load
// fails.
func elasticLoad(ctx context.Context, h *dbmon.HTTPDB, name string, o RestoreOptions, in io.Reader) error {
	if err := dbmon.CheckElasticIndexName(name); err != nil {
		return err
	}
	r, err := NewNativeReader(in)
	if err != nil {
		return err
	}
	if r.Header.Morche != ElasticNDJSON {
		return errors.New("the file isn't an Elasticsearch export")
	}
	var (
		loading *esLoader
		done    bool
	)
	fail := func(err error) error {
		if loading != nil && !o.Replace {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_ = h.JSON(cctx, http.MethodDelete, dbmon.Path(name), nil, nil)
		}
		return err
	}
	skipping := false
	for !done {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		line, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail(err)
		}
		switch {
		case line.Index != nil:
			if loading != nil {
				if o.Source == "" {
					return fail(errors.New("the file holds several indices. Say which one to restore (" + line.Index.Name + " is one of them)"))
				}
				// The one asked for is whole.
				done = true
				continue
			}
			if o.Source != "" && line.Index.Name != o.Source {
				skipping = true
				continue
			}
			skipping = false
			if err := esPrepare(ctx, h, name, o.Replace); err != nil {
				return err
			}
			if err := esCreate(ctx, h, name, *line.Index); err != nil {
				return err
			}
			loading = &esLoader{h: h, name: name}
		case line.Doc != nil:
			if loading == nil || skipping {
				continue
			}
			if err := loading.add(ctx, line.Doc); err != nil {
				return fail(err)
			}
		case line.End != nil:
			done = true
		}
	}
	if loading == nil {
		if o.Source != "" {
			return fmt.Errorf("the file has no index called %s", o.Source)
		}
		return errors.New("the file holds no index")
	}
	if err := loading.flush(ctx); err != nil {
		return fail(err)
	}
	if err := h.JSON(ctx, http.MethodPost, dbmon.Path(name, "_refresh"), nil, nil); err != nil {
		return fail(err)
	}
	return nil
}

// esPrepare makes room for the index: refuses or removes one that's there.
func esPrepare(ctx context.Context, h *dbmon.HTTPDB, name string, replace bool) error {
	var res struct {
		Indices []struct {
			Name string `json:"name"`
		} `json:"indices"`
		Aliases []struct {
			Name string `json:"name"`
		} `json:"aliases"`
		DataStreams []struct {
			Name string `json:"name"`
		} `json:"data_streams"`
	}
	err := h.JSON(ctx, http.MethodGet, "/_resolve/index/"+url.PathEscape(name)+"?expand_wildcards=all", nil, &res)
	exists := false
	switch dbmon.HTTPStatus(err) {
	case 0:
		for _, d := range res.DataStreams {
			if d.Name == name {
				return fmt.Errorf("%s is a data stream. Restore into another name", name)
			}
		}
		for _, a := range res.Aliases {
			if a.Name == name {
				return fmt.Errorf("%s is an alias. Restore into another name, or into the index it points to", name)
			}
		}
		for _, i := range res.Indices {
			exists = exists || i.Name == name
		}
	case http.StatusNotFound:
	case http.StatusBadRequest:
		// No _resolve: ask the index itself.
		if _, herr := h.Raw(ctx, http.MethodHead, dbmon.Path(name), nil, 0); herr == nil {
			exists = true
		} else if dbmon.HTTPStatus(herr) != http.StatusNotFound {
			return herr
		}
	default:
		return err
	}
	if !exists {
		return nil
	}
	if !replace {
		return fmt.Errorf("an index called %s already exists. Pick another name, or replace it", name)
	}
	return h.JSON(ctx, http.MethodDelete, dbmon.Path(name), nil, nil)
}

// esCreate makes the index with the file's settings and mappings. Aliases
// come back only when restoring under the index's own name, and not the ones
// another index already has.
func esCreate(ctx context.Context, h *dbmon.HTTPDB, name string, idx NativeIndex) error {
	body := map[string]any{}
	if len(idx.Settings) > 0 && string(idx.Settings) != "null" {
		var s map[string]any
		if err := json.Unmarshal(idx.Settings, &s); err != nil {
			return fmt.Errorf("the file's settings can't be read: %w", err)
		}
		if ix, ok := s["index"].(map[string]any); ok {
			dbmon.CleanElasticSettings(ix)
		}
		body["settings"] = s
	}
	if len(idx.Mappings) > 0 && string(idx.Mappings) != "null" {
		body["mappings"] = idx.Mappings
	}
	if name == idx.Name && len(idx.Aliases) > 0 {
		var aliases map[string]json.RawMessage
		if json.Unmarshal(idx.Aliases, &aliases) == nil {
			keep := map[string]json.RawMessage{}
			for a, def := range aliases {
				if _, err := h.Raw(ctx, http.MethodHead, dbmon.Path("_alias", a), nil, 0); err == nil {
					continue // another index has it now
				}
				keep[a] = def
			}
			if len(keep) > 0 {
				body["aliases"] = keep
			}
		}
	}
	if err := h.JSON(ctx, http.MethodPut, dbmon.Path(name), body, nil); err != nil {
		return fmt.Errorf("couldn't create the index %s: %w", name, err)
	}
	return nil
}

// esLoader sends documents in _bulk batches.
type esLoader struct {
	h    *dbmon.HTTPDB
	name string
	buf  bytes.Buffer
	docs int
}

func (l *esLoader) add(ctx context.Context, raw json.RawMessage) error {
	var d ElasticDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("a document in the file can't be read: %w", err)
	}
	action := map[string]any{"_id": d.ID}
	if d.Routing != "" {
		action["routing"] = d.Routing
	}
	a, err := json.Marshal(map[string]any{"index": action})
	if err != nil {
		return err
	}
	l.buf.Write(a)
	l.buf.WriteByte('\n')
	src := d.Source
	if len(src) == 0 {
		src = json.RawMessage("{}")
	}
	l.buf.Write(src)
	l.buf.WriteByte('\n')
	l.docs++
	if l.docs >= esBulkDocs || l.buf.Len() >= esBulkBytes {
		return l.flush(ctx)
	}
	return nil
}

func (l *esLoader) flush(ctx context.Context) error {
	if l.docs == 0 {
		return nil
	}
	res, err := l.h.Do(ctx, http.MethodPost, dbmon.Path(l.name, "_bulk"), l.buf.Bytes(), "application/x-ndjson")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var ans struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			ID     string `json:"_id"`
			Status int    `json:"status"`
			Error  struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := json.NewDecoder(res.Body).Decode(&ans); err != nil {
		return fmt.Errorf("couldn't read the bulk answer: %w", err)
	}
	if ans.Errors {
		for _, it := range ans.Items {
			for _, x := range it {
				if x.Status >= 300 {
					why := x.Error.Reason
					if why == "" {
						why = x.Error.Type
					}
					return fmt.Errorf("document %s was refused: %s", x.ID, why)
				}
			}
		}
		return errors.New("some documents were refused")
	}
	l.buf.Reset()
	l.docs = 0
	return nil
}
