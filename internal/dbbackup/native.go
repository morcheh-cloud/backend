package dbbackup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

// Elasticsearch and Meilisearch have no dump tool to run on a server: Morche
// reads every document over their HTTP API itself (through the same tunnel
// monitoring uses) and writes one NDJSON file. Restoring sends it back.
//
// The file, before Morche compresses it, is one JSON object per line:
//
//	{"morche":"es_ndjson","version":1,"engine":"elasticsearch","created":"…"}
//	{"index":{"name":"shop",…settings, mappings, aliases / primary key, settings…}}
//	{"doc":{…}}   (every document of that index)
//	{"index":{…}} {"doc":…} …
//	{"end":{"indexes":2,"documents":1234}}
//
// The header's "morche" names the format; the trailer is how a check tells a
// whole file from a cut one.
const (
	ElasticNDJSON = "es_ndjson"
	MeiliNDJSON   = "meili_ndjson"
)

// NativeEngine reports whether Morche backs this engine up itself (no script).
func NativeEngine(engine string) bool {
	return engine == dbmon.Elastic || engine == dbmon.Meili
}

// NativeFormat reports whether a format is one of those files.
func NativeFormat(format string) bool {
	return format == ElasticNDJSON || format == MeiliNDJSON
}

func nativeSpec(t Target) Spec {
	f := ElasticNDJSON
	if t.Engine == dbmon.Meili {
		f = MeiliNDJSON
	}
	return Spec{Format: f, Ext: "ndjson.gz", Pack: true, Native: true}
}

// Dump writes the export of t.Name (one index; empty = every index) to out,
// uncompressed: the caller packs it. cfg reaches the database; its login is
// replaced by t's.
func Dump(ctx context.Context, cfg dbmon.Config, t Target, out io.Writer) error {
	cfg.Username, cfg.Password = t.Username, t.Password
	h, err := dbmon.OpenHTTP(cfg)
	if err != nil {
		return err
	}
	defer h.Close()
	switch t.Engine {
	case dbmon.Elastic:
		return elasticDump(ctx, h, t.Name, out)
	case dbmon.Meili:
		return meiliDump(ctx, h, t.Name, out)
	}
	return errors.New("Morche doesn't back this engine up itself")
}

// Load sends a file Dump wrote (uncompressed) into t.Name. A file of one
// index goes into t.Name whatever it was called; with o.Replace an index of
// that name is removed first, otherwise one that exists is refused.
func Load(ctx context.Context, cfg dbmon.Config, t Target, o RestoreOptions, in io.Reader) error {
	cfg.Username, cfg.Password = t.Username, t.Password
	h, err := dbmon.OpenHTTP(cfg)
	if err != nil {
		return err
	}
	defer h.Close()
	switch o.Format {
	case ElasticNDJSON:
		return elasticLoad(ctx, h, t.Name, o, in)
	case MeiliNDJSON:
		return meiliLoad(ctx, h, t.Name, o, in)
	}
	return errors.New("can't restore " + o.Format)
}

// NativeHeader is a file's first line.
type NativeHeader struct {
	Morche  string `json:"morche"`
	Version int    `json:"version"`
	Engine  string `json:"engine"`
	Created string `json:"created,omitempty"`
	// What the engine said it was (version, OpenSearch).
	Source string `json:"source,omitempty"`
}

// NativeIndex is the line that starts one index's documents. Elasticsearch
// fills Settings (index settings, without the ones the cluster sets itself),
// Mappings and Aliases; Meilisearch PrimaryKey and Settings (GET
// /indexes/{uid}/settings).
type NativeIndex struct {
	Name       string          `json:"name"`
	PrimaryKey string          `json:"primary_key,omitempty"`
	Settings   json.RawMessage `json:"settings,omitempty"`
	Mappings   json.RawMessage `json:"mappings,omitempty"`
	Aliases    json.RawMessage `json:"aliases,omitempty"`
	Documents  *int64          `json:"documents,omitempty" doc:"How many the index said it had when the export began"`
}

// NativeLine is one line after the header: exactly one field is set.
type NativeLine struct {
	Index *NativeIndex    `json:"index,omitempty"`
	Doc   json.RawMessage `json:"doc,omitempty"`
	End   *NativeEnd      `json:"end,omitempty"`
}

// NativeEnd is the last line.
type NativeEnd struct {
	Indexes   int   `json:"indexes"`
	Documents int64 `json:"documents"`
}

// Elasticsearch documents in the file: the id, the source, and the routing
// when one was set.
type ElasticDoc struct {
	ID      string          `json:"_id"`
	Routing string          `json:"_routing,omitempty"`
	Source  json.RawMessage `json:"_source"`
}

// NativeWriter writes the file, line by line.
type NativeWriter struct {
	w       *bufio.Writer
	enc     *json.Encoder
	indexes int
	docs    int64
}

func NewNativeWriter(out io.Writer, h NativeHeader) (*NativeWriter, error) {
	bw := bufio.NewWriterSize(out, 256<<10)
	nw := &NativeWriter{w: bw, enc: json.NewEncoder(bw)}
	nw.enc.SetEscapeHTML(false)
	h.Version = 1
	if h.Created == "" {
		h.Created = time.Now().UTC().Format(time.RFC3339)
	}
	return nw, nw.enc.Encode(h)
}

func (n *NativeWriter) Index(i NativeIndex) error {
	n.indexes++
	return n.enc.Encode(NativeLine{Index: &i})
}

// Doc writes one document; raw must be one line of JSON (compact it first
// when it may hold newlines).
func (n *NativeWriter) Doc(raw json.RawMessage) error {
	n.docs++
	return n.enc.Encode(NativeLine{Doc: raw})
}

// Close writes the trailer and flushes.
func (n *NativeWriter) Close() error {
	if err := n.enc.Encode(NativeLine{End: &NativeEnd{Indexes: n.indexes, Documents: n.docs}}); err != nil {
		return err
	}
	return n.w.Flush()
}

// NativeReader reads the file back.
type NativeReader struct {
	Header NativeHeader
	dec    *json.Decoder
	ended  bool
}

func NewNativeReader(in io.Reader) (*NativeReader, error) {
	dec := json.NewDecoder(bufio.NewReaderSize(in, 256<<10))
	r := &NativeReader{dec: dec}
	if err := dec.Decode(&r.Header); err != nil {
		return nil, fmt.Errorf("the file doesn't start like one Morche exported: %w", err)
	}
	if !NativeFormat(r.Header.Morche) {
		return nil, errors.New("the file isn't one Morche exported from Elasticsearch or Meilisearch")
	}
	return r, nil
}

// Next is the next line; io.EOF after the trailer. A file that ends without
// its trailer is cut short (io.ErrUnexpectedEOF).
func (r *NativeReader) Next() (NativeLine, error) {
	var l NativeLine
	if r.ended {
		return l, io.EOF
	}
	if err := r.dec.Decode(&l); err != nil {
		if errors.Is(err, io.EOF) {
			return l, fmt.Errorf("the file was cut short: %w", io.ErrUnexpectedEOF)
		}
		return l, err
	}
	if l.End != nil {
		r.ended = true
	}
	return l, nil
}

// sniffNative tells a file Dump wrote by its first line.
func sniffNative(head []byte) Sniffed {
	line := head
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		line = head[:i]
	}
	var h NativeHeader
	if !bytes.HasPrefix(bytes.TrimSpace(line), []byte(`{"morche"`)) || json.Unmarshal(line, &h) != nil {
		return Sniffed{}
	}
	switch h.Morche {
	case ElasticNDJSON:
		s := Sniffed{Format: ElasticNDJSON, Engine: dbmon.Elastic, Label: "Elasticsearch export (Morche, NDJSON)"}
		s.Databases = nativeIndexes(head)
		return s
	case MeiliNDJSON:
		s := Sniffed{Format: MeiliNDJSON, Engine: dbmon.Meili, Label: "Meilisearch export (Morche, NDJSON)"}
		s.Databases = nativeIndexes(head)
		return s
	}
	return Sniffed{}
}

// nativeIndexes are the index lines found in head (the first ones only, for
// a big file).
func nativeIndexes(head []byte) []string {
	var out []string
	for line := range bytes.SplitSeq(head, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte(`{"index":`)) {
			continue
		}
		var l NativeLine
		if json.Unmarshal(line, &l) == nil && l.Index != nil {
			out = append(out, l.Index.Name)
		}
	}
	return out
}

// nativeEnds says the tail holds the trailer.
func nativeEnds(tail []byte) bool {
	return bytes.Contains(tail, []byte(`{"end":{"indexes":`))
}
