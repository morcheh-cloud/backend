package dbquery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

// Elasticsearch (and OpenSearch) in the data explorer: one cluster, so no
// databases; its indices, aliases and data streams are the objects. Rows are
// read with _search, the Query tab is a Kibana Dev Tools-style console, and
// documents are changed by _id.
type esClient struct {
	h      *dbmon.HTTPDB
	flavor string
}

func openElastic(ctx context.Context, cfg dbmon.Config) (Client, error) {
	h, err := dbmon.OpenHTTP(cfg)
	if err != nil {
		return nil, err
	}
	var root struct {
		Version struct {
			Number       string `json:"number"`
			Distribution string `json:"distribution"`
		} `json:"version"`
	}
	if err := h.JSON(ctx, http.MethodGet, "/", nil, &root); err != nil {
		h.Close()
		return nil, err
	}
	return &esClient{h: h, flavor: dbmon.ElasticFlavor(root.Version.Distribution)}, nil
}

func (c *esClient) Close() error { return c.h.Close() }

// ---- Overview ----

type esCatIndex struct {
	Index     string `json:"index"`
	Health    string `json:"health"`
	Status    string `json:"status"`
	DocsCount string `json:"docs.count"`
	StoreSize string `json:"store.size"`
	Pri       string `json:"pri"`
	Rep       string `json:"rep"`
}

func catInt(s string) *int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func addInt(a, b *int64) *int64 {
	if b == nil {
		return a
	}
	if a == nil {
		return ptr(*b)
	}
	return ptr(*a + *b)
}

func (c *esClient) Overview(ctx context.Context, _ string) (*DatabaseOverview, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	o := &DatabaseOverview{Engine: dbmon.Elastic, Databases: []string{}, Schemas: []string{}, Objects: []DatabaseObject{}, Notes: []string{}}
	var rows []esCatIndex
	if err := c.h.JSON(ctx, http.MethodGet, "/_cat/indices?format=json&bytes=b&expand_wildcards=all&h=index,health,status,docs.count,store.size", nil, &rows); err != nil {
		return nil, err
	}
	byName := map[string]esCatIndex{}
	for _, r := range rows {
		byName[r.Index] = r
		if dbmon.ElasticSystemIndex(r.Index) {
			continue
		}
		o.Objects = append(o.Objects, DatabaseObject{Name: r.Index, Kind: "index", Rows: catInt(r.DocsCount), Bytes: catInt(r.StoreSize)})
	}
	sum := func(obj *DatabaseObject, indices []string) {
		for _, i := range indices {
			r, ok := byName[i]
			if !ok {
				continue
			}
			obj.Rows = addInt(obj.Rows, catInt(r.DocsCount))
			obj.Bytes = addInt(obj.Bytes, catInt(r.StoreSize))
		}
	}
	var ds struct {
		DataStreams []struct {
			Name    string `json:"name"`
			Indices []struct {
				Name string `json:"index_name"`
			} `json:"indices"`
		} `json:"data_streams"`
	}
	if err := c.h.JSON(ctx, http.MethodGet, "/_data_stream?expand_wildcards=open,closed", nil, &ds); err != nil {
		if s := dbmon.HTTPStatus(err); s != http.StatusNotFound && s != http.StatusBadRequest {
			o.Notes = append(o.Notes, "Couldn't list the data streams: "+err.Error())
		}
	} else {
		for _, d := range ds.DataStreams {
			if strings.HasPrefix(d.Name, ".") {
				continue
			}
			obj := DatabaseObject{Name: d.Name, Kind: "data_stream"}
			names := make([]string, len(d.Indices))
			for i, x := range d.Indices {
				names[i] = x.Name
			}
			sum(&obj, names)
			o.Objects = append(o.Objects, obj)
		}
	}
	var aliases []struct {
		Alias string `json:"alias"`
		Index string `json:"index"`
	}
	if err := c.h.JSON(ctx, http.MethodGet, "/_cat/aliases?format=json&h=alias,index", nil, &aliases); err != nil {
		o.Notes = append(o.Notes, "Couldn't list the aliases: "+err.Error())
	} else {
		pointsTo := map[string][]string{}
		var order []string
		for _, a := range aliases {
			if strings.HasPrefix(a.Alias, ".") {
				continue
			}
			if _, ok := pointsTo[a.Alias]; !ok {
				order = append(order, a.Alias)
			}
			pointsTo[a.Alias] = append(pointsTo[a.Alias], a.Index)
		}
		for _, name := range order {
			obj := DatabaseObject{Name: name, Kind: "alias"}
			sum(&obj, pointsTo[name])
			o.Objects = append(o.Objects, obj)
		}
	}
	slices.SortFunc(o.Objects, func(a, b DatabaseObject) int { return strings.Compare(a.Name, b.Name) })
	if len(o.Objects) > maxObjects {
		o.Objects = o.Objects[:maxObjects]
		o.Capped = true
	}
	if len(o.Objects) == 0 && len(rows) > 0 {
		o.Notes = append(o.Notes, "Only system indices (names starting with a dot) are here; they're left out of the list.")
	}
	return o, nil
}

// ---- What a name is ----

// esTarget is what a name points at.
type esTarget struct {
	Kind    string // index, alias, data_stream
	Indices []string
	Aliases []string // an index's aliases
}

func (c *esClient) resolve(ctx context.Context, name string) (*esTarget, error) {
	var res struct {
		Indices []struct {
			Name    string   `json:"name"`
			Aliases []string `json:"aliases"`
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
	err := c.h.JSON(ctx, http.MethodGet, "/_resolve/index/"+url.PathEscape(name)+"?expand_wildcards=all", nil, &res)
	if err != nil {
		if dbmon.HTTPStatus(err) == http.StatusBadRequest {
			// Older than 7.9: no _resolve; take it as an index.
			return &esTarget{Kind: "index", Indices: []string{name}}, nil
		}
		if dbmon.HTTPStatus(err) == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	for _, d := range res.DataStreams {
		if d.Name == name {
			return &esTarget{Kind: "data_stream", Indices: d.Backing}, nil
		}
	}
	for _, a := range res.Aliases {
		if a.Name == name {
			return &esTarget{Kind: "alias", Indices: a.Indices}, nil
		}
	}
	for _, i := range res.Indices {
		if i.Name == name {
			return &esTarget{Kind: "index", Indices: []string{name}, Aliases: i.Aliases}, nil
		}
	}
	return nil, ErrNotFound
}

// readOnlyReason says why documents can't be changed through this name.
func (t *esTarget) readOnlyReason(name string) string {
	switch t.Kind {
	case "data_stream":
		return "A data stream only takes new documents, and its documents can't be changed or removed through it. Change them in its backing index with a query in the Query tab (PUT /<backing index>/_doc/<id>)."
	case "alias":
		if len(t.Indices) != 1 {
			return fmt.Sprintf("The alias %s points to %d indices, so it isn't clear which one a document belongs to. Open one of its indices to change documents.", name, len(t.Indices))
		}
	}
	return ""
}

// ---- Mapping ----

// esField is one mapped field, flattened: objects become dotted paths.
type esField struct {
	Path    string
	Type    string
	Keyword string // a keyword sub-field (name.keyword) to sort and match exactly on
}

type esProp struct {
	Type       string            `json:"type"`
	Properties map[string]esProp `json:"properties"`
	Fields     map[string]esProp `json:"fields"`
}

// esMapping is the flattened mapping of one or more indices.
type esMapping struct {
	fields  []esField
	byPath  map[string]esField
	objects map[string]bool
}

func newMapping() *esMapping {
	return &esMapping{byPath: map[string]esField{}, objects: map[string]bool{}}
}

func (m *esMapping) add(prefix string, props map[string]esProp) {
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		p := props[k]
		path := prefix + k
		if (p.Type == "" || p.Type == "object") && len(p.Properties) > 0 {
			m.objects[path] = true
			m.add(path+".", p.Properties)
			continue
		}
		if _, ok := m.byPath[path]; ok {
			continue
		}
		f := esField{Path: path, Type: cmpStr(p.Type, "object")}
		subs := make([]string, 0, len(p.Fields))
		for s := range p.Fields {
			subs = append(subs, s)
		}
		slices.Sort(subs)
		for _, s := range subs {
			if p.Fields[s].Type == "keyword" && (f.Keyword == "" || s == "keyword") {
				f.Keyword = path + "." + s
			}
		}
		m.byPath[path] = f
		m.fields = append(m.fields, f)
	}
}

func cmpStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// mapping reads the mapping of name (every index behind it, merged).
func (c *esClient) mapping(ctx context.Context, name string) (*esMapping, error) {
	var res map[string]struct {
		Mappings struct {
			Properties map[string]esProp `json:"properties"`
		} `json:"mappings"`
	}
	if err := c.h.JSON(ctx, http.MethodGet, dbmon.Path(name, "_mapping")+"?expand_wildcards=all", nil, &res); err != nil {
		if dbmon.HTTPStatus(err) == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	names := make([]string, 0, len(res))
	for n := range res {
		names = append(names, n)
	}
	// The newest backing index first, so its types win.
	slices.Sort(names)
	slices.Reverse(names)
	m := newMapping()
	for _, n := range names {
		m.add("", res[n].Mappings.Properties)
	}
	return m, nil
}

// ---- Describe ----

func (c *esClient) Describe(ctx context.Context, _, _ string, name string) (*ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	t, err := c.resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	m, err := c.mapping(ctx, name)
	if err != nil {
		return nil, err
	}
	info := &ObjectInfo{Name: name, Kind: t.Kind, Columns: []ObjectColumn{{Name: "_id", Type: "keyword", Key: true}}, Key: []string{"_id"}, Indexes: []ObjectIndex{}, Constraints: []ObjectConstraint{}}
	for _, f := range m.fields {
		col := ObjectColumn{Name: f.Path, Type: f.Type, Nullable: true}
		if f.Keyword != "" {
			col.Extra = "keyword: " + f.Keyword
		}
		info.Columns = append(info.Columns, col)
	}
	info.ReadOnly = t.readOnlyReason(name)

	var rows []esCatIndex
	if err := c.h.JSON(ctx, http.MethodGet, "/_cat/indices/"+url.PathEscape(name)+"?format=json&bytes=b&expand_wildcards=all&h=index,health,status,docs.count,store.size,pri,rep", nil, &rows); err == nil {
		var docs, size *int64
		health := ""
		for _, r := range rows {
			docs = addInt(docs, catInt(r.DocsCount))
			size = addInt(size, catInt(r.StoreSize))
			health = worseHealth(health, r.Health)
		}
		if docs != nil {
			info.Facts = append(info.Facts, ObjectFact{Label: "Documents", Value: strconv.FormatInt(*docs, 10)})
		}
		if size != nil {
			info.Facts = append(info.Facts, ObjectFact{Label: "Size", Value: byteText(*size)})
		}
		if health != "" {
			info.Facts = append(info.Facts, ObjectFact{Label: "Health", Value: health})
		}
		if t.Kind == "index" && len(rows) == 1 {
			info.Facts = append(info.Facts, ObjectFact{Label: "Shards", Value: rows[0].Pri + " primary, " + rows[0].Rep + " replicas each"})
			if rows[0].Status == "close" {
				info.Facts = append(info.Facts, ObjectFact{Label: "State", Value: "closed"})
			}
		}
	}
	if t.Kind != "index" {
		info.Facts = append(info.Facts, ObjectFact{Label: "Indices", Value: strings.Join(t.Indices, ", ")})
	}
	if len(t.Aliases) > 0 {
		info.Facts = append(info.Facts, ObjectFact{Label: "Aliases", Value: strings.Join(t.Aliases, ", ")})
	}

	// The definition: the (newest) index's settings and mappings.
	def := name
	if len(t.Indices) > 0 {
		def = t.Indices[len(t.Indices)-1]
	}
	var whole map[string]struct {
		Settings map[string]any `json:"settings"`
		Mappings map[string]any `json:"mappings"`
	}
	if err := c.h.JSON(ctx, http.MethodGet, dbmon.Path(def)+"?expand_wildcards=all", nil, &whole); err == nil {
		if x, ok := whole[def]; ok {
			if idx, ok := x.Settings["index"].(map[string]any); ok {
				if v, ok := idx["creation_date"].(json.Number); ok {
					if ms, err := v.Int64(); err == nil {
						info.Facts = append(info.Facts, ObjectFact{Label: "Created", Value: time.UnixMilli(ms).UTC().Format("2006-01-02 15:04 UTC")})
					}
				}
				dbmon.CleanElasticSettings(idx)
			}
			b, _ := json.MarshalIndent(map[string]any{"settings": x.Settings, "mappings": x.Mappings}, "", "  ")
			info.Definition = string(b)
		}
	}
	return info, nil
}

func worseHealth(a, b string) string {
	rank := map[string]int{"": 0, "green": 1, "yellow": 2, "red": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func byteText(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---- Rows ----

// esDefaultWindow is index.max_result_window's default: from + size can't
// pass it.
const esDefaultWindow = 10000

func (c *esClient) Rows(ctx context.Context, req RowsRequest) (*RowsPage, error) {
	if req.Table == "" {
		return nil, refused("Pick an index.")
	}
	limit := limitOf(req.Limit, defaultLimit, 1000)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	m, err := c.mapping(ctx, req.Table)
	if err != nil {
		return nil, err
	}
	if end := req.Offset + int64(limit); end > esDefaultWindow {
		window := c.window(ctx, req.Table)
		if end > window {
			return nil, refused("Elasticsearch pages through the first %s documents only (index.max_result_window). Narrow the rows down with filters or a search, or sort the other way to see the last ones.", strconv.FormatInt(window, 10))
		}
	}
	query, err := esRowsQuery(m, req)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"query": query, "from": req.Offset, "size": limit + 1}
	if req.Count {
		body["track_total_hits"] = true
	} else {
		body["track_total_hits"] = false
	}
	if len(req.Sort) > 0 {
		s, err := esSort(m, req.Sort)
		if err != nil {
			return nil, err
		}
		body["sort"] = s
	}
	t, err := c.resolve(ctx, req.Table)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	raw, err := c.h.Raw(ctx, http.MethodPost, dbmon.Path(req.Table, "_search"), body, 64<<20)
	if err != nil {
		return nil, err
	}
	var res esSearchAnswer
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("couldn't read the answer: %w", err)
	}
	hits := res.Hits.Hits
	truncated := len(hits) > limit
	if truncated {
		hits = hits[:limit]
	}
	out := &RowsPage{QueryResult: esHitsResult(hits, m, t.Kind != "index")}
	out.Truncated = truncated
	bj, _ := json.Marshal(body)
	out.Statement = short("POST " + dbmon.Path(req.Table, "_search") + " " + string(bj))
	out.Ms = time.Since(start).Milliseconds()
	if req.Count && res.Hits.Total != nil {
		out.Total = ptr(res.Hits.Total.Value)
		out.Estimated = res.Hits.Total.Relation == "gte"
	}
	return out, nil
}

// window is the index's index.max_result_window (the smallest of the indices
// behind a name).
func (c *esClient) window(ctx context.Context, name string) int64 {
	var res map[string]struct {
		Settings map[string]any `json:"settings"`
		Defaults map[string]any `json:"defaults"`
	}
	if c.h.JSON(ctx, http.MethodGet, dbmon.Path(name, "_settings", "index.max_result_window")+"?include_defaults=true&flat_settings=true&expand_wildcards=all", nil, &res) != nil {
		return esDefaultWindow
	}
	w := int64(-1)
	for _, x := range res {
		v := x.Settings["index.max_result_window"]
		if v == nil {
			v = x.Defaults["index.max_result_window"]
		}
		s := fmt.Sprint(v)
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && (w < 0 || n < w) {
			w = n
		}
	}
	if w < 0 {
		return esDefaultWindow
	}
	return w
}

type esHit struct {
	Index   string          `json:"_index"`
	ID      string          `json:"_id"`
	Routing string          `json:"_routing"`
	Score   *float64        `json:"_score"`
	Source  json.RawMessage `json:"_source"`
}

type esSearchAnswer struct {
	Took     int64 `json:"took"`
	TimedOut bool  `json:"timed_out"`
	Hits     struct {
		Total *struct {
			Value    int64  `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Hits []esHit `json:"hits"`
	} `json:"hits"`
	Aggregations json.RawMessage `json:"aggregations"`
}

// esRowsQuery builds the bool query for a page: the filters, the search and
// the typed condition.
func esRowsQuery(m *esMapping, req RowsRequest) (map[string]any, error) {
	var clauses []any
	for _, f := range req.Filters {
		q, err := esFilter(m, f)
		if err != nil {
			return nil, err
		}
		clauses = append(clauses, q)
	}
	b := map[string]any{}
	if len(clauses) > 0 {
		if req.Match == "any" {
			b["should"] = clauses
			b["minimum_should_match"] = 1
		} else {
			b["filter"] = clauses
		}
	}
	var must []any
	if s := strings.TrimSpace(req.Search); s != "" {
		must = append(must, map[string]any{"bool": map[string]any{
			"should": []any{
				map[string]any{"simple_query_string": map[string]any{"query": s, "fields": []string{"*"}, "lenient": true, "default_operator": "and"}},
				map[string]any{"ids": map[string]any{"values": []string{s}}},
			},
			"minimum_should_match": 1,
		}})
	}
	if w := strings.TrimSpace(req.Where); w != "" {
		q, err := EsWhere(w)
		if err != nil {
			return nil, err
		}
		must = append(must, q)
	}
	if len(must) > 0 {
		b["must"] = must
	}
	if len(b) == 0 {
		return map[string]any{"match_all": map[string]any{}}, nil
	}
	return map[string]any{"bool": b}, nil
}

// EsWhere reads the typed condition of the Rows view: a Query DSL object
// (the "query" part, or a whole search body whose "query" is taken) or a
// Lucene query string (status:active AND price:>10).
func EsWhere(w string) (any, error) {
	body, err := dbmon.ElasticQueryBody(w)
	if err != nil {
		return nil, refused("The condition isn't valid JSON (%v). Write a Query DSL object, or a query string like status:active AND price:>10.", errors.Unwrap(err))
	}
	q, ok := body["query"]
	if !ok {
		return nil, refused("Write a query, e.g. {\"term\": {\"status\": \"active\"}}, or a query string like status:active AND price:>10.")
	}
	return q, nil
}

// exactField is where a value is matched exactly: a text field's keyword
// sub-field when it has one.
func (m *esMapping) exactField(name string) (string, bool) {
	f, ok := m.byPath[name]
	if !ok {
		return name, false
	}
	if f.Type == "text" || f.Type == "match_only_text" {
		if f.Keyword != "" {
			return f.Keyword, true
		}
		return name, false
	}
	return name, true
}

func (m *esMapping) text(name string) bool {
	f, ok := m.byPath[name]
	return ok && (f.Type == "text" || f.Type == "match_only_text" || f.Type == "search_as_you_type")
}

// esWildcardEscape escapes a value for a wildcard pattern.
func esWildcardEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`)
	return r.Replace(s)
}

// esFilter turns one filter into a query.
func esFilter(m *esMapping, f RowFilter) (any, error) {
	col := f.Column
	not := func(q any) any { return map[string]any{"bool": map[string]any{"must_not": []any{q}}} }
	if col == "_id" {
		switch f.Op {
		case "eq":
			return map[string]any{"ids": map[string]any{"values": []string{f.Value}}}, nil
		case "ne":
			return not(map[string]any{"ids": map[string]any{"values": []string{f.Value}}}), nil
		case "in":
			return map[string]any{"ids": map[string]any{"values": nonNilStrings(f.Values)}}, nil
		case "null", "not_null":
			if f.Op == "null" {
				return not(map[string]any{"match_all": map[string]any{}}), nil
			}
			return map[string]any{"match_all": map[string]any{}}, nil
		}
		return nil, refused("_id can be filtered by equals, not equals and is one of.")
	}
	exact, hasExact := m.exactField(col)
	eq := func(v string) any {
		if m.text(col) && !hasExact {
			return map[string]any{"match": map[string]any{col: map[string]any{"query": v, "operator": "and"}}}
		}
		if m.text(col) {
			// The keyword copy holds the whole value as written; match the
			// words too, so "apple" finds "Apple pie".
			return map[string]any{"bool": map[string]any{"should": []any{
				map[string]any{"term": map[string]any{exact: v}},
				map[string]any{"match": map[string]any{col: map[string]any{"query": v, "operator": "and"}}},
			}, "minimum_should_match": 1}}
		}
		return map[string]any{"term": map[string]any{col: v}}
	}
	wild := func(pattern string) any {
		return map[string]any{"wildcard": map[string]any{exact: map[string]any{"value": pattern, "case_insensitive": true}}}
	}
	switch f.Op {
	case "eq":
		return eq(f.Value), nil
	case "ne":
		return not(eq(f.Value)), nil
	case "gt", "gte", "lt", "lte":
		return map[string]any{"range": map[string]any{exact: map[string]any{f.Op: f.Value}}}, nil
	case "contains":
		return wild("*" + esWildcardEscape(f.Value) + "*"), nil
	case "not_contains":
		return not(wild("*" + esWildcardEscape(f.Value) + "*")), nil
	case "starts":
		return map[string]any{"prefix": map[string]any{exact: map[string]any{"value": f.Value, "case_insensitive": true}}}, nil
	case "ends":
		return wild("*" + esWildcardEscape(f.Value)), nil
	case "in":
		vals := nonNilStrings(f.Values)
		if m.text(col) && !hasExact {
			var or []any
			for _, v := range vals {
				or = append(or, eq(v))
			}
			return map[string]any{"bool": map[string]any{"should": or, "minimum_should_match": 1}}, nil
		}
		return map[string]any{"terms": map[string]any{exact: vals}}, nil
	case "null":
		return not(map[string]any{"exists": map[string]any{"field": col}}), nil
	case "not_null":
		return map[string]any{"exists": map[string]any{"field": col}}, nil
	}
	return nil, refused("Unknown filter %q.", f.Op)
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// esSort turns the sort into Elasticsearch's: _id can't be sorted on (8.x
// turns its field data off), so it means index order; a text field sorts on
// its keyword sub-field.
func esSort(m *esMapping, sort []RowSort) ([]any, error) {
	var out []any
	for _, s := range sort {
		dir := "asc"
		if s.Desc {
			dir = "desc"
		}
		col := s.Column
		switch col {
		case "_id", "_doc":
			out = append(out, map[string]any{"_doc": map[string]any{"order": dir}})
			continue
		case "_score":
			out = append(out, map[string]any{"_score": map[string]any{"order": dir}})
			continue
		}
		f, ok := m.byPath[col]
		if !ok {
			return nil, refused("%s isn't in the mapping, so it can't be sorted on.", col)
		}
		field := col
		switch f.Type {
		case "text", "match_only_text", "search_as_you_type":
			if f.Keyword == "" {
				return nil, refused("%s is a text field without a keyword sub-field, so it can't be sorted on. Sort on another field.", col)
			}
			field = f.Keyword
		case "object", "nested", "flattened", "geo_point", "geo_shape", "binary", "dense_vector", "sparse_vector":
			return nil, refused("%s is a %s field, which can't be sorted on.", col, f.Type)
		}
		typ := f.Type
		if field != col {
			typ = "keyword"
		}
		out = append(out, map[string]any{field: map[string]any{"order": dir, "unmapped_type": typ}})
	}
	return out, nil
}

// esHitsResult turns hits into rows: _id (and _index for an alias or data
// stream) first, then the fields, mapped ones in mapping order, others as they
// come. Objects become dotted columns; arrays and leaf-typed objects are
// shown as JSON. Documents = each hit's _source.
func esHitsResult(hits []esHit, m *esMapping, withIndex bool) QueryResult {
	r := QueryResult{Columns: []ResultColumn{}, Rows: [][]*string{}, Documents: []string{}}
	idx := map[string]int{}
	addCol := func(name, typ string) {
		if _, ok := idx[name]; ok {
			return
		}
		idx[name] = len(r.Columns)
		r.Columns = append(r.Columns, ResultColumn{Name: name, Type: typ})
	}
	if withIndex {
		addCol("_index", "keyword")
	}
	addCol("_id", "keyword")
	type cell struct {
		name string
		val  *string
	}
	rows := make([][]cell, len(hits))
	seen := map[string]bool{}
	for i, h := range hits {
		walkSource(h.Source, "", m, func(path string, v *string) {
			rows[i] = append(rows[i], cell{path, v})
			seen[path] = true
		})
	}
	if m != nil {
		for _, f := range m.fields {
			if seen[f.Path] {
				addCol(f.Path, f.Type)
			}
		}
	}
	for _, row := range rows {
		for _, c := range row {
			typ := ""
			if m != nil {
				typ = m.byPath[c.name].Type
			}
			addCol(c.name, typ)
		}
	}
	size := 0
	for i, h := range hits {
		row := make([]*string, len(r.Columns))
		if withIndex {
			row[idx["_index"]] = ptr(h.Index)
		}
		row[idx["_id"]] = ptr(h.ID)
		for _, c := range rows[i] {
			row[idx[c.name]] = c.val
			if c.val != nil {
				size += len(*c.val)
			}
		}
		r.Rows = append(r.Rows, row)
		doc := "{}"
		if len(h.Source) > 0 {
			var b bytes.Buffer
			if json.Compact(&b, h.Source) == nil {
				doc = b.String()
			}
		}
		r.Documents = append(r.Documents, *clip(doc))
		if size > maxResult {
			r.Truncated = true
			r.Rows = r.Rows[:i+1]
			break
		}
	}
	return r
}

// walkSource calls emit for every value of a _source, in the order written:
// objects are walked into (unless the mapping says the path is a field of its
// own, like geo_point or flattened), everything else is one value.
func walkSource(raw json.RawMessage, prefix string, m *esMapping, emit func(path string, v *string)) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return
		}
		key, _ := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return
		}
		path := prefix + key
		v = bytes.TrimSpace(v)
		if len(v) > 0 && v[0] == '{' {
			if _, leaf := m.field(path); !leaf {
				walkSource(v, path+".", m, emit)
				continue
			}
		}
		emit(path, jsonCell(v))
	}
}

func (m *esMapping) field(path string) (esField, bool) {
	if m == nil {
		return esField{}, false
	}
	f, ok := m.byPath[path]
	return f, ok
}

// jsonCell is one JSON value as the panel shows it: strings as they are,
// null as null, anything else as compact JSON.
func jsonCell(v json.RawMessage) *string {
	if len(v) == 0 || string(v) == "null" {
		return nil
	}
	if v[0] == '"' {
		var s string
		if json.Unmarshal(v, &s) == nil {
			return clip(s)
		}
	}
	var b bytes.Buffer
	if json.Compact(&b, v) == nil {
		return clip(b.String())
	}
	return clip(string(v))
}

// ---- The console (Query tab) ----

// esRequest is one request typed in the console.
type esRequest struct {
	Method string
	Path   string
	Body   string // compact JSON, or NDJSON lines ending in \n
	NDJSON bool
	Line   int
	Text   string // as typed, for the result's statement
}

var esRequestLine = regexp.MustCompile(`^(?i)(GET|POST|PUT|DELETE|HEAD|PATCH)\s+(\S+)\s*$`)

// ParseConsole reads Kibana Dev Tools-style text: requests like
//
//	GET /shop/_search
//	{ "query": { "match": { "name": "apple" } } }
//
// one after another; a body is JSON (several lines are fine) or NDJSON for
// _bulk and _msearch. Lines starting with # or // are comments, and
// """triple-quoted""" strings are taken as JSON strings. Text with no request
// line that is JSON is a search on defaultIndex.
func ParseConsole(text, defaultIndex string) ([]esRequest, error) {
	text = tripleQuotes(text)
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var out []esRequest
	var cur *esRequest
	var body []string
	finish := func() error {
		if cur == nil {
			return nil
		}
		if err := cur.setBody(body); err != nil {
			return err
		}
		out = append(out, *cur)
		cur, body = nil, nil
		return nil
	}
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}
		if mm := esRequestLine.FindStringSubmatch(t); mm != nil {
			if err := finish(); err != nil {
				return nil, err
			}
			p := mm[2]
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			cur = &esRequest{Method: strings.ToUpper(mm[1]), Path: p, Line: i + 1, Text: strings.ToUpper(mm[1]) + " " + p}
			continue
		}
		if cur == nil {
			if t == "" {
				continue
			}
			if !strings.HasPrefix(t, "{") {
				return nil, refused("Line %d: start with a request line like GET /my-index/_search, then the JSON body under it.", i+1)
			}
			// A body with no request line: a search.
			p := "/_search"
			if defaultIndex != "" {
				p = dbmon.Path(defaultIndex, "_search")
			}
			cur = &esRequest{Method: http.MethodPost, Path: p, Line: i + 1, Text: "POST " + p}
		}
		body = append(body, line)
	}
	if err := finish(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, refused("Type a request, e.g. GET /_cluster/health or GET /my-index/_search.")
	}
	return out, nil
}

// setBody reads the lines under a request line: one JSON value, or several
// (NDJSON).
func (r *esRequest) setBody(lines []string) error {
	text := strings.TrimSpace(strings.Join(lines, "\n"))
	if text == "" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(text))
	var parts []string
	for {
		var v json.RawMessage
		err := dec.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return refused("The body of %s (line %d) isn't valid JSON: %v", r.Text, r.Line, err)
		}
		var b bytes.Buffer
		_ = json.Compact(&b, v)
		parts = append(parts, b.String())
	}
	if len(parts) == 1 && !esNDJSONPath(r.Path) {
		r.Body = parts[0]
		return nil
	}
	r.NDJSON = true
	r.Body = strings.Join(parts, "\n") + "\n"
	return nil
}

// esNDJSONPath says the endpoint takes NDJSON.
func esNDJSONPath(path string) bool {
	_, ep := esEndpoint(path)
	return ep == "_bulk" || ep == "_msearch" || ep == "_msearch/template"
}

var tripleQuoted = regexp.MustCompile(`(?s)"""(.*?)"""`)

// tripleQuotes turns Kibana's """multi-line strings""" into JSON strings.
func tripleQuotes(s string) string {
	return tripleQuoted.ReplaceAllStringFunc(s, func(m string) string {
		inner := m[3 : len(m)-3]
		b, _ := json.Marshal(inner)
		return string(b)
	})
}

// esEndpoint splits a path into its target (index part) and endpoint: the
// first segment starting with "_" and the rest ("_search/template",
// "_doc/1"). Query strings are left out.
func esEndpoint(path string) (target, endpoint string) {
	p, _, _ := strings.Cut(path, "?")
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "_") {
			return strings.Join(segs[:i], "/"), strings.Join(segs[i:], "/")
		}
	}
	return strings.Join(segs, "/"), ""
}

// esReadPosts are endpoints that take a POST (or PUT, for a body) but only
// read. Matched on the endpoint's start.
var esReadPosts = []string{
	"_search", "_msearch", "_count", "_validate/query", "_explain", "_field_caps",
	"_mget", "_termvectors", "_mtermvectors", "_analyze", "_render/template",
	"_pit", "_sql", "_query", "_eql/search", "_async_search", "_knn_search",
	"_rank_eval", "_terms_enum", "_resolve", "_plugins/_sql", "_plugins/_ppl",
	"_opendistro/_sql", "_opendistro/_ppl", "_cat", "_mvt",
}

// esReadEndpoint says a POST to this endpoint only reads.
func esReadEndpoint(endpoint string) bool {
	for _, r := range esReadPosts {
		if endpoint == r || strings.HasPrefix(endpoint, r+"/") {
			// _sql/close, _pit closes and async-search deletes go by DELETE;
			// _search/scroll reads on. _plugins/_sql only reads.
			return true
		}
	}
	return false
}

// CheckReadElastic refuses a request that may change something when Allow
// changes is off: GET and HEAD go, a POST only to endpoints that read.
func CheckReadElastic(method, path string) error {
	switch method {
	case http.MethodGet, http.MethodHead:
		return nil
	case http.MethodPost:
		_, ep := esEndpoint(path)
		if esReadEndpoint(ep) {
			return nil
		}
	}
	return refused("%s %s may change something. Turn on Allow changes to run it.", method, path)
}

func (c *esClient) Run(ctx context.Context, database, query string, o RunOptions) ([]QueryResult, error) {
	reqs, err := ParseConsole(query, database)
	if err != nil {
		return nil, err
	}
	if !o.Change {
		for _, r := range reqs {
			if err := CheckReadElastic(r.Method, r.Path); err != nil {
				return nil, err
			}
		}
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	limit := limitOf(o.Limit, 1000, 10000)
	var out []QueryResult
	for i, r := range reqs {
		start := time.Now()
		rs, err := c.one(ctx, r, limit)
		if err != nil {
			if len(reqs) > 1 {
				return out, fmt.Errorf("request %d (%s): %w", i+1, r.Text, err)
			}
			return out, err
		}
		for j := range rs {
			rs[j].Ms = time.Since(start).Milliseconds()
		}
		out = append(out, rs...)
	}
	return out, nil
}

// one sends one console request and reads its answer.
func (c *esClient) one(ctx context.Context, r esRequest, limit int) ([]QueryResult, error) {
	var body any
	ct := ""
	if r.Body != "" {
		body = r.Body
		if r.NDJSON {
			ct = "application/x-ndjson"
		}
	}
	res, err := c.h.Do(ctx, r.Method, r.Path, body, ct)
	if err != nil {
		if r.Method == http.MethodHead {
			if s := dbmon.HTTPStatus(err); s != 0 {
				return []QueryResult{{Statement: short(r.Text), Columns: []ResultColumn{}, Rows: [][]*string{}, Message: fmt.Sprintf("%d %s", s, http.StatusText(s))}}, nil
			}
		}
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResult+1))
	if err != nil {
		return nil, err
	}
	if r.Method == http.MethodHead {
		return []QueryResult{{Statement: short(r.Text), Columns: []ResultColumn{}, Rows: [][]*string{}, Message: fmt.Sprintf("%d %s", res.StatusCode, http.StatusText(res.StatusCode))}}, nil
	}
	return esAnswer(short(r.Text), raw, len(raw) > maxResult, limit), nil
}

// esAnswer turns an answer into results: hits as rows, _sql / ES|QL tables
// as rows, aggregations as JSON, anything else as one pretty JSON (or text)
// value.
func esAnswer(statement string, raw []byte, cut bool, limit int) []QueryResult {
	raw = bytes.TrimSpace(raw)
	base := QueryResult{Statement: statement, Columns: []ResultColumn{}, Rows: [][]*string{}}
	if len(raw) == 0 {
		base.Message = "Done"
		return []QueryResult{base}
	}
	var top map[string]json.RawMessage
	if cut || raw[0] != '{' || json.Unmarshal(raw, &top) != nil {
		// _cat without format=json, or too big to read whole.
		base.Columns = []ResultColumn{{Name: "response"}}
		base.Rows = [][]*string{{clip(string(raw))}}
		base.Truncated = cut
		return []QueryResult{base}
	}
	if resp, ok := top["responses"]; ok {
		// _msearch: one result per search.
		var list []json.RawMessage
		if json.Unmarshal(resp, &list) == nil {
			var out []QueryResult
			for i, x := range list {
				out = append(out, esAnswer(fmt.Sprintf("%s [%d]", statement, i+1), x, false, limit)...)
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	if h, ok := top["hits"]; ok && bytes.Contains(h, []byte(`"hits"`)) {
		var a esSearchAnswer
		if json.Unmarshal(raw, &a) == nil {
			hits := a.Hits.Hits
			r := base
			truncated := len(hits) > limit
			if truncated {
				hits = hits[:limit]
			}
			hr := esHitsResult(hits, nil, true)
			r.Columns, r.Rows, r.Documents = hr.Columns, hr.Rows, hr.Documents
			r.Truncated = truncated || hr.Truncated
			total := ""
			if a.Hits.Total != nil {
				rel := ""
				if a.Hits.Total.Relation == "gte" {
					rel = " or more"
				}
				total = fmt.Sprintf("%d%s match", a.Hits.Total.Value, rel)
			}
			r.Message = strings.TrimSpace(fmt.Sprintf("%s · took %d ms", total, a.Took))
			r.Message = strings.TrimPrefix(r.Message, "· ")
			if a.TimedOut {
				r.Message += " · timed out, results are partial"
			}
			aggs := len(a.Aggregations) > 0 && string(a.Aggregations) != "null"
			if !aggs {
				return []QueryResult{r}
			}
			ar := jsonResult(base, "aggregations", a.Aggregations)
			if len(a.Hits.Hits) == 0 {
				ar.Message = r.Message
				return []QueryResult{ar}
			}
			r.Message += " · the aggregations are in the next result"
			return []QueryResult{r, ar}
		}
	}
	if cols, ok := top["columns"]; ok {
		// _sql (rows) and ES|QL (values).
		vals := top["rows"]
		if vals == nil {
			vals = top["values"]
		}
		if t, ok := tableResult(base, cols, vals, limit); ok {
			return []QueryResult{t}
		}
	}
	r := jsonResult(base, "response", raw)
	r.Affected, r.Message = esAffected(top)
	return []QueryResult{r}
}

// jsonResult is one pretty JSON value in one column.
func jsonResult(base QueryResult, column string, raw json.RawMessage) QueryResult {
	var b bytes.Buffer
	if json.Indent(&b, raw, "", "  ") != nil {
		b.Reset()
		b.Write(raw)
	}
	base.Columns = []ResultColumn{{Name: column, Type: "json"}}
	base.Rows = [][]*string{{clip(b.String())}}
	return base
}

// tableResult reads {"columns":[{name,type}], "rows"|"values":[[…]]}.
func tableResult(base QueryResult, cols, vals json.RawMessage, limit int) (QueryResult, bool) {
	var cs []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	var rows [][]json.RawMessage
	if json.Unmarshal(cols, &cs) != nil || len(cs) == 0 || json.Unmarshal(vals, &rows) != nil {
		return base, false
	}
	for _, c := range cs {
		base.Columns = append(base.Columns, ResultColumn{Name: c.Name, Type: c.Type})
	}
	for i, row := range rows {
		if i >= limit {
			base.Truncated = true
			break
		}
		out := make([]*string, len(cs))
		for j := range cs {
			if j < len(row) {
				out[j] = jsonCell(row[j])
			}
		}
		base.Rows = append(base.Rows, out)
	}
	return base, true
}

// esAffected reads how many documents a write answer touched, and a short
// message: result (one document), deleted/updated/created (by query,
// reindex), items (bulk).
func esAffected(top map[string]json.RawMessage) (*int64, string) {
	if raw, ok := top["result"]; ok {
		var res string
		if json.Unmarshal(raw, &res) == nil {
			n := int64(1)
			if res == "noop" || res == "not_found" {
				n = 0
			}
			return &n, "Document " + strings.ReplaceAll(res, "_", " ")
		}
	}
	if raw, ok := top["items"]; ok {
		var items []map[string]struct {
			Status int `json:"status"`
			Error  struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &items) == nil {
			var ok, failed int64
			first := ""
			for _, it := range items {
				for _, x := range it {
					if x.Status < 300 {
						ok++
					} else {
						failed++
						if first == "" {
							first = cmpStr(x.Error.Reason, x.Error.Type)
						}
					}
				}
			}
			msg := fmt.Sprintf("%d done", ok)
			if failed > 0 {
				msg += fmt.Sprintf(", %d failed (the first: %s)", failed, first)
			}
			return &ok, msg
		}
	}
	var n int64
	found := false
	for _, k := range []string{"created", "updated", "deleted"} {
		if raw, ok := top[k]; ok {
			var v int64
			if json.Unmarshal(raw, &v) == nil {
				n += v
				found = true
			}
		}
	}
	if found {
		msg := ""
		if raw, ok := top["failures"]; ok && len(raw) > 2 {
			msg = "Some documents failed; see the answer"
		}
		return &n, msg
	}
	if raw, ok := top["acknowledged"]; ok && string(raw) == "true" {
		return nil, "Acknowledged"
	}
	return nil, ""
}

// elasticRisks lists console requests that drop or empty data, or change who
// may do what; such scripts need the database's name typed to run.
func elasticRisks(script string) []string {
	reqs, err := ParseConsole(script, "")
	if err != nil {
		return nil
	}
	var out []string
	add := func(s string) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, r := range reqs {
		target, ep := esEndpoint(r.Path)
		switch {
		case r.Method == http.MethodDelete && ep == "" && target != "":
			add("DELETE /" + target + " removes the index and every document in it")
		case r.Method == http.MethodDelete && strings.HasPrefix(ep, "_data_stream"):
			add("DELETE " + r.Path + " removes a data stream and its documents")
		case strings.HasPrefix(ep, "_delete_by_query"):
			if q := strings.ReplaceAll(r.Body, " ", ""); r.Body == "" || strings.Contains(q, `"match_all"`) {
				add("_delete_by_query without a narrow query removes every document")
			} else {
				add("_delete_by_query removes documents")
			}
		case strings.HasPrefix(ep, "_security") && r.Method != http.MethodGet:
			add(r.Method + " " + r.Path + " changes who may do what")
		case strings.HasPrefix(ep, "_cluster/settings") && r.Method == http.MethodPut:
			add("PUT _cluster/settings changes the whole cluster")
		case ep == "_close" || strings.HasPrefix(ep, "_shrink") || strings.HasPrefix(ep, "_split") || strings.HasPrefix(ep, "_clone"):
			add(r.Method + " " + r.Path + " takes the index offline or makes a new one")
		case strings.HasPrefix(ep, "_snapshot") && strings.Contains(ep, "_restore"):
			add("restoring a snapshot can replace indices")
		case strings.HasPrefix(ep, "_update_by_query") && (r.Body == "" || strings.Contains(strings.ReplaceAll(r.Body, " ", ""), `"match_all"`)):
			add("_update_by_query without a narrow query changes every document")
		}
	}
	return out
}

// ---- Edit ----

// esChange is one change, ready to send.
type esChange struct {
	op      string
	method  string
	path    string // without the query
	id      string
	routing string
	doc     string // compact JSON
	row     int
}

func (c *esClient) Edit(ctx context.Context, r EditRequest) (*EditResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	t, err := c.resolve(ctx, r.Table)
	if err != nil {
		return nil, err
	}
	if why := t.readOnlyReason(r.Table); why != "" {
		return nil, refused("%s", why)
	}
	index := r.Table
	if t.Kind == "alias" {
		index = t.Indices[0]
	}
	var changes []esChange
	var check []string // ids that must exist
	for i, ch := range r.Changes {
		row := i + 1
		x := esChange{op: ch.Op, row: row}
		var key string
		if v := ch.Key["_id"]; v != nil {
			key = strings.TrimSpace(*v)
		}
		if ch.Op != "delete" {
			doc, id, err := esDocument(ch.Document, row)
			if err != nil {
				return nil, err
			}
			x.doc = doc
			if id != "" {
				if key != "" && key != id {
					return nil, refused("Row %d: the document's _id (%s) isn't the row's (%s). An _id can't be changed; add a new document and remove the old one.", row, id, key)
				}
				if key == "" {
					key = id
				}
			}
		}
		switch ch.Op {
		case "insert":
			if key == "" {
				x.method, x.path = http.MethodPost, dbmon.Path(index, "_doc")
			} else {
				x.method, x.path, x.id = http.MethodPut, dbmon.Path(index, "_create", key), key
			}
		case "update":
			if key == "" {
				return nil, refused("Row %d: the _id is missing.", row)
			}
			x.method, x.path, x.id = http.MethodPut, dbmon.Path(index, "_doc", key), key
			check = append(check, key)
		case "delete":
			if key == "" {
				return nil, refused("Row %d: the _id is missing.", row)
			}
			x.method, x.path, x.id = http.MethodDelete, dbmon.Path(index, "_doc", key), key
			check = append(check, key)
		default:
			return nil, refused("unknown change %q", ch.Op)
		}
		changes = append(changes, x)
	}
	out := &EditResult{Statements: make([]string, len(changes))}
	for i, x := range changes {
		out.Statements[i] = x.shown()
	}
	if r.Preview || len(changes) == 0 {
		return out, nil
	}

	// Every document to change or remove must still be there; nothing is sent
	// otherwise. (Elasticsearch has no transactions: once the writes start,
	// the ones before a failure stay.)
	if len(check) > 0 {
		routing, err := c.existing(ctx, index, check)
		if err != nil {
			return nil, err
		}
		for i := range changes {
			x := &changes[i]
			if x.op == "insert" {
				continue
			}
			rt, ok := routing[x.id]
			if !ok {
				return nil, refused("Row %d (_id %s) was removed since you read it. Nothing was changed; read the rows again.", x.row, x.id)
			}
			x.routing = rt
		}
	}
	start := time.Now()
	for i, x := range changes {
		q := url.Values{}
		if x.routing != "" {
			q.Set("routing", x.routing)
		}
		if i == len(changes)-1 {
			// The rows show the change at once.
			q.Set("refresh", "wait_for")
		}
		path := x.path
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		var body any
		if x.doc != "" {
			body = x.doc
		}
		var res struct {
			Result string `json:"result"`
		}
		if err := c.h.JSON(ctx, x.method, path, body, &res); err != nil {
			msg := err.Error()
			if dbmon.HTTPStatus(err) == http.StatusConflict {
				msg = fmt.Sprintf("a document with _id %s is already there", x.id)
			}
			if i > 0 {
				return out, refused("Row %d: %s. The %d change(s) before it were saved (Elasticsearch has no transactions).", x.row, msg, i)
			}
			return nil, refused("Row %d: %s. Nothing was changed.", x.row, msg)
		}
		if res.Result != "noop" && res.Result != "not_found" {
			out.Affected++
		}
	}
	out.Ran = true
	out.Ms = time.Since(start).Milliseconds()
	return out, nil
}

func (x esChange) shown() string {
	s := x.method + " " + x.path
	if x.doc != "" {
		s += "\n" + x.doc
	}
	return s
}

// esDocument reads a document typed in the editor: a JSON object. An _id
// inside it (as the explorer shows) is taken out and returned, since it's
// not part of the source.
func esDocument(text string, row int) (doc, id string, err error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", "", refused("Row %d: the document is empty.", row)
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return "", "", refused("Row %d isn't a valid JSON document: %v", row, err)
	}
	if obj == nil {
		return "", "", refused("Row %d: a document is a JSON object, like {\"name\": \"apple\"}.", row)
	}
	if v, ok := obj["_id"]; ok {
		s, isText := v.(string)
		if !isText {
			if n, isNum := v.(json.Number); isNum {
				s = n.String()
			} else {
				return "", "", refused("Row %d: _id must be text.", row)
			}
		}
		id = s
		delete(obj, "_id")
	}
	for _, k := range []string{"_index", "_source", "_routing", "_version", "_seq_no", "_primary_term"} {
		if _, ok := obj[k]; ok {
			return "", "", refused("Row %d: %s is Elasticsearch's own field and can't be in a document.", row, k)
		}
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return "", "", err
	}
	return string(b), id, nil
}

// existing reads which of ids are in index, with their routing.
func (c *esClient) existing(ctx context.Context, index string, ids []string) (map[string]string, error) {
	var res struct {
		Docs []struct {
			ID      string `json:"_id"`
			Found   bool   `json:"found"`
			Routing string `json:"_routing"`
		} `json:"docs"`
	}
	body := map[string]any{"ids": ids}
	if err := c.h.JSON(ctx, http.MethodPost, dbmon.Path(index, "_mget")+"?_source=false", body, &res); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, d := range res.Docs {
		if d.Found {
			out[d.ID] = d.Routing
		}
	}
	return out, nil
}

var _ Editor = (*esClient)(nil)
