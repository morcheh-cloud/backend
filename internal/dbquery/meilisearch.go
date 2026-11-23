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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

// meiliClient explores a Meilisearch instance: indexes are the tables,
// documents the rows. There are no databases inside a connection.
type meiliClient struct {
	h *dbmon.HTTPDB
}

func openMeili(ctx context.Context, cfg dbmon.Config) (Client, error) {
	h, err := dbmon.OpenHTTP(cfg)
	if err != nil {
		return nil, err
	}
	if err := h.JSON(ctx, http.MethodGet, "/version", nil, nil); err != nil {
		h.Close()
		return nil, err
	}
	return &meiliClient{h: h}, nil
}

func (c *meiliClient) Close() error { return c.h.Close() }

type meiliIndexMeta struct {
	UID        string     `json:"uid"`
	PrimaryKey *string    `json:"primaryKey"`
	CreatedAt  *time.Time `json:"createdAt"`
	UpdatedAt  *time.Time `json:"updatedAt"`
}

type meiliIndexStats struct {
	NumberOfDocuments int64            `json:"numberOfDocuments"`
	RawDocumentDbSize *int64           `json:"rawDocumentDbSize"`
	IsIndexing        bool             `json:"isIndexing"`
	FieldDistribution map[string]int64 `json:"fieldDistribution"`
}

// meiliErr adds what to do to the errors people run into while exploring.
func meiliErr(err error) error {
	var he *dbmon.HTTPError
	if !errors.As(err, &he) {
		return err
	}
	msg := he.Message
	switch {
	case strings.Contains(msg, "is not filterable"):
		msg += "\nTo filter on it, add it to the index's filterableAttributes setting (PATCH /indexes/{index}/settings with Allow changes on)."
	case strings.Contains(msg, "is not sortable"):
		msg += "\nTo sort by it, add it to the index's sortableAttributes setting (PATCH /indexes/{index}/settings with Allow changes on)."
	case he.Code == "feature_not_enabled" && (strings.Contains(msg, "CONTAINS") || strings.Contains(msg, "contains filter")):
		msg = "Contains and Starts with filters need Meilisearch's containsFilter experimental feature (v1.10 or later). Turn it on with PATCH /experimental-features {\"containsFilter\": true} (master key, Allow changes on), or filter with equals instead."
	case he.Code == "index_not_found":
	default:
		return err
	}
	return &dbmon.HTTPError{Status: he.Status, Code: he.Code, Message: msg}
}

// ---- documents as rows ----

// meiliObject reads a JSON object keeping its keys' order.
func meiliObject(raw json.RawMessage) ([]string, map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	t, err := dec.Token()
	if err != nil {
		return nil, nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, nil, errors.New("not a JSON object")
	}
	var keys []string
	vals := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		k, _ := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, err
		}
		if _, seen := vals[k]; !seen {
			keys = append(keys, k)
		}
		vals[k] = v
	}
	return keys, vals, nil
}

// meiliCell is how one value shows: strings as they are, null as null,
// objects and arrays as compact JSON.
func meiliCell(v json.RawMessage) *string {
	v = bytes.TrimSpace(v)
	if len(v) == 0 || string(v) == "null" {
		return nil
	}
	switch v[0] {
	case '"':
		var s string
		if json.Unmarshal(v, &s) == nil {
			return clip(s)
		}
	case '{', '[':
		var b bytes.Buffer
		if json.Compact(&b, v) == nil {
			return clip(b.String())
		}
	}
	return clip(string(v))
}

func meiliKind(v json.RawMessage) string {
	v = bytes.TrimSpace(v)
	if len(v) == 0 {
		return ""
	}
	switch v[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "boolean"
	case 'n':
		return ""
	}
	return "number"
}

// meiliDocs turns documents into rows: the primary key first, then every
// field in the order first seen.
func meiliDocs(docs []json.RawMessage, pk string) QueryResult {
	r := QueryResult{Columns: []ResultColumn{}, Rows: [][]*string{}, Documents: []string{}}
	idx := map[string]int{}
	type parsed struct {
		keys []string
		vals map[string]json.RawMessage
	}
	all := make([]parsed, len(docs))
	addCol := func(name string) {
		if _, ok := idx[name]; !ok {
			idx[name] = len(r.Columns)
			r.Columns = append(r.Columns, ResultColumn{Name: name})
		}
	}
	for i, d := range docs {
		keys, vals, err := meiliObject(d)
		if err != nil {
			continue
		}
		all[i] = parsed{keys, vals}
		if _, ok := vals[pk]; ok && pk != "" {
			addCol(pk)
		}
	}
	for _, p := range all {
		for _, k := range p.keys {
			addCol(k)
		}
	}
	for i, d := range docs {
		row := make([]*string, len(r.Columns))
		for k, v := range all[i].vals {
			j := idx[k]
			row[j] = meiliCell(v)
			if r.Columns[j].Type == "" {
				r.Columns[j].Type = meiliKind(v)
			}
		}
		r.Rows = append(r.Rows, row)
		var b bytes.Buffer
		if json.Compact(&b, d) != nil {
			r.Documents = append(r.Documents, "{}")
		} else {
			r.Documents = append(r.Documents, *clip(b.String()))
		}
	}
	return r
}

// ---- overview, describe ----

func (c *meiliClient) indexes(ctx context.Context) ([]meiliIndexMeta, int64, error) {
	var list struct {
		Results []meiliIndexMeta `json:"results"`
		Total   int64            `json:"total"`
	}
	if err := c.h.JSON(ctx, http.MethodGet, "/indexes?limit=1000", nil, &list); err != nil {
		return nil, 0, err
	}
	return list.Results, list.Total, nil
}

func (c *meiliClient) Overview(ctx context.Context, _ string) (*DatabaseOverview, error) {
	list, total, err := c.indexes(ctx)
	if err != nil {
		return nil, err
	}
	o := &DatabaseOverview{Engine: dbmon.Meili, Databases: []string{}, Schemas: []string{}, Objects: []DatabaseObject{}, Notes: []string{}}
	var st struct {
		Indexes map[string]meiliIndexStats `json:"indexes"`
	}
	if err := c.h.JSON(ctx, http.MethodGet, "/stats", nil, &st); err != nil {
		o.Notes = append(o.Notes, "Couldn't read the document counts: "+err.Error())
	}
	for _, ix := range list {
		ob := DatabaseObject{Name: ix.UID, Kind: "index"}
		if s, ok := st.Indexes[ix.UID]; ok {
			ob.Rows = ptr(s.NumberOfDocuments)
			ob.Bytes = s.RawDocumentDbSize
		}
		o.Objects = append(o.Objects, ob)
	}
	sort.Slice(o.Objects, func(i, j int) bool { return o.Objects[i].Name < o.Objects[j].Name })
	o.Capped = total > int64(len(list))
	return o, nil
}

// meiliSettings are the settings Describe and Rows look at.
type meiliSettings struct {
	DisplayedAttributes  []string          `json:"displayedAttributes"`
	SearchableAttributes []string          `json:"searchableAttributes"`
	FilterableAttributes []json.RawMessage `json:"filterableAttributes"`
	SortableAttributes   []string          `json:"sortableAttributes"`
	RankingRules         []string          `json:"rankingRules"`
	DistinctAttribute    *string           `json:"distinctAttribute"`
	Pagination           *struct {
		MaxTotalHits int64 `json:"maxTotalHits"`
	} `json:"pagination"`
}

// filterable is the list of filterable patterns; from v1.14 an entry may be
// {"attributePatterns": [...], "features": {...}}.
func (s meiliSettings) filterable() []string {
	var out []string
	for _, raw := range s.FilterableAttributes {
		var name string
		if json.Unmarshal(raw, &name) == nil {
			out = append(out, name)
			continue
		}
		var obj struct {
			AttributePatterns []string `json:"attributePatterns"`
		}
		if json.Unmarshal(raw, &obj) == nil {
			out = append(out, obj.AttributePatterns...)
		}
	}
	return out
}

// meiliMatches says whether a field is covered by one of the attribute
// patterns ("*", "title", "genre*", "*_at", "meta" for "meta.lang").
func meiliMatches(patterns []string, field string) bool {
	for _, p := range patterns {
		switch {
		case p == "*" || p == field:
			return true
		case strings.HasPrefix(field, p+"."):
			return true
		case strings.Contains(p, "*"):
			pre, post, _ := strings.Cut(p, "*")
			post = strings.ReplaceAll(post, "*", "")
			if strings.HasPrefix(field, pre) && strings.HasSuffix(field[len(pre):], post) {
				return true
			}
		}
	}
	return false
}

func (c *meiliClient) index(ctx context.Context, uid string) (*meiliIndexMeta, error) {
	var ix meiliIndexMeta
	if err := c.h.JSON(ctx, http.MethodGet, dbmon.Path("indexes", uid), nil, &ix); err != nil {
		return nil, err
	}
	return &ix, nil
}

func (c *meiliClient) Describe(ctx context.Context, _, _, name string) (*ObjectInfo, error) {
	ix, err := c.index(ctx, name)
	if err != nil {
		return nil, err
	}
	var st meiliIndexStats
	if err := c.h.JSON(ctx, http.MethodGet, dbmon.Path("indexes", name, "stats"), nil, &st); err != nil {
		return nil, err
	}
	raw, err := c.h.Raw(ctx, http.MethodGet, dbmon.Path("indexes", name, "settings"), nil, 4<<20)
	if err != nil {
		return nil, err
	}
	var set meiliSettings
	_ = json.Unmarshal(raw, &set)
	pk := ""
	if ix.PrimaryKey != nil {
		pk = *ix.PrimaryKey
	}
	filterable := set.filterable()

	info := &ObjectInfo{
		Name: name, Kind: "index", Columns: []ObjectColumn{}, Key: []string{},
		Indexes: []ObjectIndex{}, Constraints: []ObjectConstraint{},
	}
	names := make([]string, 0, len(st.FieldDistribution))
	for f := range st.FieldDistribution {
		names = append(names, f)
	}
	if len(names) == 0 {
		seen := map[string]bool{}
		for _, list := range [][]string{set.DisplayedAttributes, set.SearchableAttributes, set.SortableAttributes, filterable} {
			for _, f := range list {
				if !seen[f] && !strings.Contains(f, "*") {
					seen[f] = true
					names = append(names, f)
				}
			}
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if (names[i] == pk) != (names[j] == pk) {
			return names[i] == pk
		}
		return names[i] < names[j]
	})
	if pk != "" && !slices.Contains(names, pk) {
		names = append([]string{pk}, names...)
	}
	for _, f := range names {
		col := ObjectColumn{Name: f, Type: "field", Key: f == pk}
		var tags []string
		if meiliMatches(set.SearchableAttributes, f) {
			tags = append(tags, "searchable")
		}
		if meiliMatches(filterable, f) {
			tags = append(tags, "filterable")
		}
		if meiliMatches(set.SortableAttributes, f) {
			tags = append(tags, "sortable")
		}
		if !meiliMatches(set.DisplayedAttributes, f) {
			tags = append(tags, "hidden from search results")
		}
		col.Extra = strings.Join(tags, ", ")
		if n, ok := st.FieldDistribution[f]; ok && n < st.NumberOfDocuments {
			col.Nullable = true
			col.Comment = fmt.Sprintf("In %d of %d documents", n, st.NumberOfDocuments)
		}
		info.Columns = append(info.Columns, col)
	}
	list := func(l []string) string {
		if len(l) == 0 {
			return "none"
		}
		return strings.Join(l, ", ")
	}
	fact := func(label, value string) {
		if value != "" {
			info.Facts = append(info.Facts, ObjectFact{Label: label, Value: value})
		}
	}
	if pk != "" {
		info.Key = []string{pk}
		fact("Primary key", pk)
	} else {
		fact("Primary key", "not set yet")
		info.ReadOnly = "This index has no primary key yet. Meilisearch picks one when the first documents are added (a field ending in id), or set it with PATCH /indexes/" + name + "."
	}
	fact("Documents", strconv.FormatInt(st.NumberOfDocuments, 10))
	if st.RawDocumentDbSize != nil {
		fact("Size of the documents", fmt.Sprintf("%d bytes", *st.RawDocumentDbSize))
	}
	fact("Searchable", list(set.SearchableAttributes))
	fact("Filterable", list(filterable))
	fact("Sortable", list(set.SortableAttributes))
	fact("Displayed", list(set.DisplayedAttributes))
	fact("Ranking rules", list(set.RankingRules))
	if set.DistinctAttribute != nil {
		fact("Distinct attribute", *set.DistinctAttribute)
	}
	if set.Pagination != nil {
		fact("Most hits a search reaches", strconv.FormatInt(set.Pagination.MaxTotalHits, 10))
	}
	if ix.CreatedAt != nil {
		fact("Created", ix.CreatedAt.UTC().Format(time.RFC3339))
	}
	if ix.UpdatedAt != nil {
		fact("Updated", ix.UpdatedAt.UTC().Format(time.RFC3339))
	}
	if st.IsIndexing {
		fact("Indexing", "yes, right now")
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, raw, "", "  ") == nil {
		info.Definition = pretty.String()
	} else {
		info.Definition = string(raw)
	}
	return info, nil
}

// ---- rows ----

var meiliPlainField = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

func meiliField(name string) string {
	if meiliPlainField.MatchString(name) {
		return name
	}
	return meiliQuote(name)
}

// meiliQuote writes a value as a filter string; Meilisearch compares a
// quoted number as a number.
func meiliQuote(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// meiliCondition is one filter as a Meilisearch filter expression.
func meiliCondition(f RowFilter) (string, error) {
	col := meiliField(f.Column)
	v := meiliQuote(f.Value)
	switch f.Op {
	case "eq":
		return col + " = " + v, nil
	case "ne":
		return col + " != " + v, nil
	case "gt":
		return col + " > " + v, nil
	case "gte":
		return col + " >= " + v, nil
	case "lt":
		return col + " < " + v, nil
	case "lte":
		return col + " <= " + v, nil
	case "contains":
		return col + " CONTAINS " + v, nil
	case "not_contains":
		return "NOT " + col + " CONTAINS " + v, nil
	case "starts":
		return col + " STARTS WITH " + v, nil
	case "ends":
		return "", refused("Meilisearch can't filter on how a value ends. Use contains, or type it in the search box.")
	case "in":
		if len(f.Values) == 0 {
			return "", refused("Give at least one value for %s.", f.Column)
		}
		vals := make([]string, len(f.Values))
		for i, x := range f.Values {
			vals[i] = meiliQuote(x)
		}
		return col + " IN [" + strings.Join(vals, ", ") + "]", nil
	case "null":
		return "(" + col + " IS NULL OR " + col + " NOT EXISTS)", nil
	case "not_null":
		return "(" + col + " EXISTS AND " + col + " IS NOT NULL)", nil
	}
	return "", refused("unknown filter %q", f.Op)
}

// meiliFilter joins the filters (all or any) and the typed-in expression.
func meiliFilter(filters []RowFilter, match, where string) (string, error) {
	var parts []string
	for _, f := range filters {
		c, err := meiliCondition(f)
		if err != nil {
			return "", err
		}
		parts = append(parts, c)
	}
	joined := ""
	if len(parts) == 1 {
		joined = parts[0]
	} else if len(parts) > 1 {
		sep := " AND "
		if match == "any" {
			sep = " OR "
		}
		joined = "(" + strings.Join(parts, ")"+sep+"(") + ")"
	}
	where = strings.TrimSpace(where)
	switch {
	case where == "":
		return joined, nil
	case joined == "":
		return where, nil
	}
	return "(" + where + ") AND (" + joined + ")", nil
}

func (c *meiliClient) Rows(ctx context.Context, r RowsRequest) (*RowsPage, error) {
	if r.Table == "" {
		return nil, refused("Pick an index.")
	}
	limit := limitOf(r.Limit, defaultLimit, 1000)
	filter, err := meiliFilter(r.Filters, r.Match, r.Where)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ix, err := c.index(ctx, r.Table)
	if err != nil {
		return nil, err
	}
	pk := ""
	if ix.PrimaryKey != nil {
		pk = *ix.PrimaryKey
	}
	search := strings.TrimSpace(r.Search)
	// The explorer sorts by the key by default; documents/fetch already
	// returns them in the index's own order, and the key is rarely
	// sortable, so that sort is dropped rather than refused.
	if len(r.Sort) == 1 && pk != "" && r.Sort[0].Column == pk && !r.Sort[0].Desc && search == "" {
		r.Sort = nil
	}
	start := time.Now()
	out := &RowsPage{}
	if search == "" && len(r.Sort) == 0 {
		// Plain paging: documents/fetch counts exactly, but can't sort.
		body := map[string]any{"offset": r.Offset, "limit": limit}
		if filter != "" {
			body["filter"] = filter
		}
		path := dbmon.Path("indexes", r.Table, "documents", "fetch")
		var res struct {
			Results []json.RawMessage `json:"results"`
			Total   int64             `json:"total"`
		}
		if err := c.h.JSON(ctx, http.MethodPost, path, body, &res); err != nil {
			return nil, meiliErr(err)
		}
		out.QueryResult = meiliDocs(res.Results, pk)
		out.Statement = short("POST " + path + " " + meiliJSON(body))
		out.Total = ptr(res.Total)
		out.Truncated = r.Offset+int64(len(res.Results)) < res.Total
	} else {
		body := map[string]any{"q": search}
		if filter != "" {
			body["filter"] = filter
		}
		if len(r.Sort) > 0 {
			var s []string
			for _, x := range r.Sort {
				dir := "asc"
				if x.Desc {
					dir = "desc"
				}
				s = append(s, x.Column+":"+dir)
			}
			body["sort"] = s
		}
		// page + hitsPerPage counts the hits exactly; offset + limit only
		// estimates, so it's used when the page doesn't line up.
		exact := r.Offset%int64(limit) == 0
		if exact {
			body["page"] = r.Offset/int64(limit) + 1
			body["hitsPerPage"] = limit
		} else {
			body["offset"], body["limit"] = r.Offset, limit
		}
		path := dbmon.Path("indexes", r.Table, "search")
		var res struct {
			Hits               []json.RawMessage `json:"hits"`
			EstimatedTotalHits *int64            `json:"estimatedTotalHits"`
			TotalHits          *int64            `json:"totalHits"`
		}
		if err := c.h.JSON(ctx, http.MethodPost, path, body, &res); err != nil {
			return nil, meiliErr(err)
		}
		out.QueryResult = meiliDocs(res.Hits, pk)
		out.Statement = short("POST " + path + " " + meiliJSON(body))
		var total int64
		switch {
		case res.TotalHits != nil:
			total = *res.TotalHits
		case res.EstimatedTotalHits != nil:
			total = *res.EstimatedTotalHits
			out.Estimated = true
		}
		out.Total = &total
		out.Truncated = r.Offset+int64(len(res.Hits)) < total
		var p struct {
			MaxTotalHits int64 `json:"maxTotalHits"`
		}
		if total > 0 && c.h.JSON(ctx, http.MethodGet, dbmon.Path("indexes", r.Table, "settings", "pagination"), nil, &p) == nil &&
			p.MaxTotalHits > 0 && total >= p.MaxTotalHits {
			out.Message = fmt.Sprintf("Searching and sorting reach only the first %d matches (the index's pagination.maxTotalHits setting). Filter more narrowly, or raise that setting.", p.MaxTotalHits)
		}
	}
	out.Ms = time.Since(start).Milliseconds()
	return out, nil
}

func meiliJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// ---- console ----

// meiliRequest is one request typed into the console.
type meiliRequest struct {
	Method, Path string
	Body         []byte
	NDJSON       bool
	Line         int
}

func (q meiliRequest) String() string { return q.Method + " " + q.Path }

var meiliMethodLine = regexp.MustCompile(`(?i)^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)\s*$`)

// meiliParse reads the console: each request is a method and a path on one
// line, then an optional JSON body (or NDJSON lines) up to the next method
// line. Lines starting with # or // are comments.
func meiliParse(text string) ([]meiliRequest, error) {
	var (
		out  []meiliRequest
		cur  *meiliRequest
		body []string
	)
	finish := func() error {
		if cur == nil {
			return nil
		}
		b := strings.TrimSpace(strings.Join(body, "\n"))
		if b != "" {
			switch {
			case json.Valid([]byte(b)):
				cur.Body = []byte(b)
			case meiliNDJSON(b):
				cur.Body, cur.NDJSON = []byte(b), true
			default:
				var x any
				err := json.Unmarshal([]byte(b), &x)
				return refused("Line %d: the body of %s isn't valid JSON: %v", cur.Line, cur, err)
			}
		}
		out = append(out, *cur)
		cur, body = nil, nil
		return nil
	}
	for i, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}
		if m := meiliMethodLine.FindStringSubmatch(t); m != nil {
			if err := finish(); err != nil {
				return nil, err
			}
			path, err := meiliCleanPath(m[2])
			if err != nil {
				return nil, refused("Line %d: %v", i+1, err)
			}
			cur = &meiliRequest{Method: strings.ToUpper(m[1]), Path: path, Line: i + 1}
			continue
		}
		if cur == nil {
			if t == "" {
				continue
			}
			return nil, refused("Line %d: start each request with a method and a path, e.g. POST /indexes/movies/search, then its JSON body on the next lines.", i+1)
		}
		body = append(body, line)
	}
	if err := finish(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, refused("Type a request first, e.g. POST /indexes/movies/search with {\"q\": \"…\"} below it.")
	}
	if len(out) > 50 {
		return nil, refused("That's %d requests; run at most 50 at a time.", len(out))
	}
	return out, nil
}

func meiliNDJSON(b string) bool {
	n := 0
	for l := range strings.SplitSeq(b, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if !json.Valid([]byte(l)) {
			return false
		}
		n++
	}
	return n > 1
}

// meiliCleanPath takes a path, or a whole address pasted from elsewhere.
func meiliCleanPath(p string) (string, error) {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		u, err := url.Parse(p)
		if err != nil {
			return "", fmt.Errorf("%q isn't an address", p)
		}
		p = u.RequestURI()
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	pathOnly, _, _ := strings.Cut(p, "?")
	for seg := range strings.SplitSeq(pathOnly, "/") {
		if seg == ".." || seg == "." {
			return "", fmt.Errorf("%q isn't a Meilisearch path", p)
		}
	}
	return p, nil
}

var meiliReadPosts = []*regexp.Regexp{
	regexp.MustCompile(`^/multi-search$`),
	regexp.MustCompile(`^/indexes/[^/]+/search$`),
	regexp.MustCompile(`^/indexes/[^/]+/documents/fetch$`),
	regexp.MustCompile(`^/indexes/[^/]+/facet-search$`),
	regexp.MustCompile(`^/indexes/[^/]+/similar$`),
}

// meiliSecret are routes whose answers hold keys or other secrets.
var meiliSecret = []string{"/keys", "/webhooks", "/chats"}

// meiliCheckRead refuses what read-only mode can't run: anything but GET and
// the searching POSTs, and the routes that would print keys.
func meiliCheckRead(q meiliRequest) error {
	p, _, _ := strings.Cut(q.Path, "?")
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	for _, s := range meiliSecret {
		if p == s || strings.HasPrefix(p, s+"/") {
			return refused("%s shows API keys or other secrets. Turn on Allow changes to run it.", q)
		}
	}
	switch q.Method {
	case http.MethodGet:
		return nil
	case http.MethodPost:
		for _, re := range meiliReadPosts {
			if re.MatchString(p) {
				return nil
			}
		}
	}
	return refused("%s may change something. Turn on Allow changes to run it.", q)
}

func (c *meiliClient) Run(ctx context.Context, _, query string, o RunOptions) ([]QueryResult, error) {
	reqs, err := meiliParse(query)
	if err != nil {
		return nil, err
	}
	if !o.Change {
		for _, q := range reqs {
			if err := meiliCheckRead(q); err != nil {
				return nil, err
			}
		}
	}
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	limit := o.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	var out []QueryResult
	for i, q := range reqs {
		res, err := c.send(ctx, q, limit)
		if err != nil {
			return out, fmt.Errorf("request %d (%s): %w", i+1, q, meiliErr(err))
		}
		out = append(out, res...)
	}
	return out, nil
}

// send runs one console request and turns its answer into results.
func (c *meiliClient) send(ctx context.Context, q meiliRequest, limit int) ([]QueryResult, error) {
	start := time.Now()
	var body any
	if q.Body != nil {
		body = q.Body
	}
	ctype := ""
	if q.NDJSON {
		ctype = "application/x-ndjson"
	}
	res, err := c.h.Do(ctx, q.Method, q.Path, body, ctype)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResult+1))
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	cut := len(raw) > maxResult
	stmt := short(q.String())
	done := func(r QueryResult) QueryResult {
		r.Statement = stmt
		r.Ms = time.Since(start).Milliseconds()
		return r
	}
	var obj map[string]json.RawMessage
	if cut || json.Unmarshal(raw, &obj) != nil {
		return []QueryResult{done(meiliResponse(raw, cut))}, nil
	}
	p, _, _ := strings.Cut(q.Path, "?")

	// A change answers with a task: wait for it to end.
	if tu, ok := obj["taskUid"]; ok && q.Method != http.MethodGet {
		var uid int64
		if json.Unmarshal(tu, &uid) == nil {
			t, raw, err := meiliWait(ctx, c.h, uid)
			r := meiliResponse(raw, false)
			if err != nil {
				r = meiliResponse(meiliPretty(obj), false)
				r.Message = fmt.Sprintf("Task %d was sent, but waiting for it stopped: %v. It goes on in Meilisearch; look it up with GET /tasks/%d.", uid, err, uid)
				return []QueryResult{done(r)}, nil
			}
			r.Message, r.Affected = meiliTaskSummary(t)
			return []QueryResult{done(r)}, nil
		}
	}

	if _, ok := obj["hits"]; ok {
		return meiliSearchResults(obj, stmt, limit, done), nil
	}
	if rs, ok := obj["results"]; ok {
		var items []json.RawMessage
		if json.Unmarshal(rs, &items) == nil {
			if p == "/multi-search" {
				var out []QueryResult
				for _, it := range items {
					var one map[string]json.RawMessage
					if json.Unmarshal(it, &one) != nil {
						continue
					}
					var uid string
					_ = json.Unmarshal(one["indexUid"], &uid)
					for _, r := range meiliSearchResults(one, stmt, limit, done) {
						if uid != "" {
							r.Statement = short(stmt + " · " + uid)
						}
						out = append(out, r)
					}
				}
				return out, nil
			}
			if meiliAllObjects(items) {
				r := meiliDocs(items[:min(len(items), limit)], "")
				r.Truncated = len(items) > limit
				if !strings.Contains(p, "/documents") {
					r.Documents = nil
				}
				var total int64
				if json.Unmarshal(obj["total"], &total) == nil {
					r.Message = fmt.Sprintf("%d of %d", len(items), total)
				}
				return []QueryResult{done(r)}, nil
			}
		}
	}
	return []QueryResult{done(meiliResponse(raw, false))}, nil
}

func meiliAllObjects(items []json.RawMessage) bool {
	for _, it := range items {
		t := bytes.TrimSpace(it)
		if len(t) == 0 || t[0] != '{' {
			return false
		}
	}
	return true
}

// meiliSearchResults shows a search answer's hits, then its facets when it
// has any.
func meiliSearchResults(obj map[string]json.RawMessage, stmt string, limit int, done func(QueryResult) QueryResult) []QueryResult {
	var hits []json.RawMessage
	_ = json.Unmarshal(obj["hits"], &hits)
	r := meiliDocs(hits[:min(len(hits), limit)], "")
	r.Truncated = len(hits) > limit
	var parts []string
	var n int64
	if json.Unmarshal(obj["totalHits"], &n) == nil && obj["totalHits"] != nil {
		parts = append(parts, fmt.Sprintf("%d hits", n))
	} else if json.Unmarshal(obj["estimatedTotalHits"], &n) == nil && obj["estimatedTotalHits"] != nil {
		parts = append(parts, fmt.Sprintf("about %d hits", n))
	}
	var ms int64
	if json.Unmarshal(obj["processingTimeMs"], &ms) == nil && obj["processingTimeMs"] != nil {
		parts = append(parts, fmt.Sprintf("searched in %d ms", ms))
	}
	r.Message = strings.Join(parts, ", ")
	out := []QueryResult{done(r)}
	var facets map[string]json.RawMessage
	if json.Unmarshal(obj["facetDistribution"], &facets) == nil && len(facets) > 0 {
		f := QueryResult{Columns: []ResultColumn{{Name: "attribute", Type: "string"}, {Name: "values", Type: "object"}}, Rows: [][]*string{}}
		names := make([]string, 0, len(facets))
		for k := range facets {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			f.Rows = append(f.Rows, []*string{ptr(k), meiliCell(facets[k])})
		}
		f = done(f)
		f.Statement = short(stmt + " · facets")
		out = append(out, f)
	}
	return out
}

func meiliPretty(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// meiliResponse is an answer shown whole, pretty-printed when it's JSON.
func meiliResponse(raw []byte, cut bool) QueryResult {
	r := QueryResult{Columns: []ResultColumn{{Name: "response", Type: "json"}}, Rows: [][]*string{}, Truncated: cut}
	var pretty bytes.Buffer
	if !cut && json.Indent(&pretty, raw, "", "  ") == nil {
		raw = pretty.Bytes()
	}
	r.Rows = append(r.Rows, []*string{clip(string(raw))})
	return r
}

// meiliTaskResult is GET /tasks/{uid}.
type meiliTaskResult struct {
	UID     int64          `json:"uid"`
	Status  string         `json:"status"`
	Type    string         `json:"type"`
	Details map[string]any `json:"details"`
	Error   *struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

// meiliWait polls a task until it ends or ctx does.
func meiliWait(ctx context.Context, h *dbmon.HTTPDB, uid int64) (*meiliTaskResult, []byte, error) {
	wait := 50 * time.Millisecond
	path := "/tasks/" + strconv.FormatInt(uid, 10)
	for {
		raw, err := h.Raw(ctx, http.MethodGet, path, nil, 4<<20)
		if err != nil {
			return nil, nil, err
		}
		var t meiliTaskResult
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, nil, fmt.Errorf("couldn't read task %d: %w", uid, err)
		}
		switch t.Status {
		case "succeeded", "failed", "canceled":
			return &t, raw, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, time.Second)
	}
}

func meiliTaskSummary(t *meiliTaskResult) (string, *int64) {
	var affected *int64
	for _, k := range []string{"indexedDocuments", "deletedDocuments"} {
		if f, ok := t.Details[k].(float64); ok {
			n := int64(f)
			if affected != nil {
				n += *affected
			}
			affected = &n
		}
	}
	switch t.Status {
	case "succeeded":
		return fmt.Sprintf("Task %d (%s) succeeded.", t.UID, t.Type), affected
	case "canceled":
		return fmt.Sprintf("Task %d (%s) was canceled.", t.UID, t.Type), affected
	}
	msg := fmt.Sprintf("Task %d (%s) failed.", t.UID, t.Type)
	if t.Error != nil && t.Error.Message != "" {
		msg = fmt.Sprintf("Task %d (%s) failed: %s", t.UID, t.Type, t.Error.Message)
	}
	return msg, affected
}

// ---- editing ----

// meiliKeyText is a primary key value as the rows show it.
func meiliKeyText(v json.RawMessage) (string, bool) {
	v = bytes.TrimSpace(v)
	if len(v) == 0 {
		return "", false
	}
	switch v[0] {
	case '"':
		var s string
		if json.Unmarshal(v, &s) == nil {
			return s, true
		}
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return string(v), true
	}
	return "", false
}

func (c *meiliClient) exists(ctx context.Context, uid, id string) (bool, error) {
	err := c.h.JSON(ctx, http.MethodGet, dbmon.Path("indexes", uid, "documents", id)+"?fields="+url.QueryEscape(id0), nil, nil)
	if err == nil {
		return true, nil
	}
	if dbmon.HTTPStatus(err) == http.StatusNotFound {
		var he *dbmon.HTTPError
		if errors.As(err, &he) && he.Code == "index_not_found" {
			return false, err
		}
		return false, nil
	}
	return false, err
}

// id0 asks for no real field: only whether the document is there matters.
const id0 = "__morche_none"

// Edit adds, replaces and removes documents by primary key. Adds and
// replacements go in one task (all or nothing), removals in a second.
func (c *meiliClient) Edit(ctx context.Context, r EditRequest) (*EditResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ix, err := c.index(ctx, r.Table)
	if err != nil {
		return nil, err
	}
	if ix.PrimaryKey == nil || *ix.PrimaryKey == "" {
		return nil, refused("%s has no primary key yet, so its documents can't be changed one by one. Add documents first (Meilisearch then picks a key), or set one with PATCH /indexes/%s.", r.Table, r.Table)
	}
	pk := *ix.PrimaryKey
	var (
		put     [][]byte
		del     []string
		check   []string // must exist
		absent  []string // must not exist
		touched = map[string]bool{}
	)
	for i, ch := range r.Changes {
		var id string
		if ch.Op != "insert" {
			k := ch.Key[pk]
			if k == nil || *k == "" {
				return nil, refused("Row %d: its %s is missing.", i+1, pk)
			}
			id = *k
		}
		if ch.Op != "delete" {
			doc := []byte(strings.TrimSpace(ch.Document))
			_, vals, err := meiliObject(doc)
			if err != nil {
				return nil, refused("Row %d isn't a valid JSON document: %v", i+1, err)
			}
			got, ok := meiliKeyText(vals[pk])
			if !ok {
				return nil, refused("Row %d: give the document its %s (a whole number or a text of letters, digits, - and _).", i+1, pk)
			}
			if ch.Op == "update" && got != id {
				return nil, refused("Row %d: the document's %s is %s, but it was read as %s. Change the key by adding a new document and removing the old one.", i+1, pk, got, id)
			}
			id = got
			var b bytes.Buffer
			if err := json.Compact(&b, doc); err != nil {
				return nil, refused("Row %d isn't a valid JSON document: %v", i+1, err)
			}
			put = append(put, b.Bytes())
		}
		if touched[id] {
			return nil, refused("Row %d: %s %s is changed twice; change each document once.", i+1, pk, id)
		}
		touched[id] = true
		switch ch.Op {
		case "insert":
			absent = append(absent, id)
		case "update":
			check = append(check, id)
		case "delete":
			check = append(check, id)
			del = append(del, id)
		default:
			return nil, refused("unknown change %q", ch.Op)
		}
	}
	docsPath := dbmon.Path("indexes", r.Table, "documents")
	delPath := docsPath + "/delete-batch"
	out := &EditResult{Statements: []string{}}
	if len(put) > 0 {
		out.Statements = append(out.Statements, "POST "+docsPath+"\n["+string(bytes.Join(put, []byte(",\n")))+"]")
	}
	var ids []byte
	if len(del) > 0 {
		ids, _ = json.Marshal(del)
		out.Statements = append(out.Statements, "POST "+delPath+"\n"+string(ids))
	}
	if r.Preview {
		return out, nil
	}
	for _, id := range check {
		ok, err := c.exists(ctx, r.Table, id)
		if err != nil {
			return out, err
		}
		if !ok {
			return out, refused("There's no document with %s %s any more; reload and try again.", pk, id)
		}
	}
	for _, id := range absent {
		ok, err := c.exists(ctx, r.Table, id)
		if err != nil {
			return out, err
		}
		if ok {
			return out, refused("A document with %s %s already exists; edit that one instead.", pk, id)
		}
	}
	start := time.Now()
	run := func(path string, body []byte) error {
		var task struct {
			TaskUID int64 `json:"taskUid"`
		}
		if err := c.h.JSON(ctx, http.MethodPost, path, body, &task); err != nil {
			return err
		}
		t, _, err := meiliWait(ctx, c.h, task.TaskUID)
		if err != nil {
			return fmt.Errorf("task %d didn't end in time: %w", task.TaskUID, err)
		}
		if t.Status != "succeeded" {
			msg, _ := meiliTaskSummary(t)
			return errors.New(msg)
		}
		_, n := meiliTaskSummary(t)
		if n != nil {
			out.Affected += *n
		}
		out.Ran = true
		return nil
	}
	if len(put) > 0 {
		body := append([]byte("["), bytes.Join(put, []byte(","))...)
		body = append(body, ']')
		if err := run(docsPath, body); err != nil {
			return out, err
		}
	}
	if len(del) > 0 {
		if err := run(delPath, ids); err != nil {
			return out, err
		}
	}
	out.Ms = time.Since(start).Milliseconds()
	return out, nil
}

// meiliRisks lists console requests that drop or empty data, or replace an
// index; such scripts need the database's name typed to run.
func meiliRisks(script string) []string {
	reqs, err := meiliParse(script)
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
		p, err := meiliCleanPath(r.Path)
		if err != nil {
			continue
		}
		p = strings.SplitN(p, "?", 2)[0]
		parts := strings.Split(strings.Trim(p, "/"), "/")
		switch {
		case r.Method == http.MethodDelete && len(parts) == 2 && parts[0] == "indexes":
			add("DELETE " + p + " removes the index and every document in it")
		case r.Method == http.MethodDelete && len(parts) == 3 && parts[0] == "indexes" && parts[2] == "documents":
			add("DELETE " + p + " removes every document of the index")
		case r.Method == http.MethodPost && len(parts) == 4 && parts[2] == "documents" && parts[3] == "delete":
			add("POST " + p + " removes documents matching a filter")
		case r.Method == http.MethodPost && p == "/swap-indexes":
			add("POST /swap-indexes swaps the documents of two indexes")
		case r.Method == http.MethodDelete && p == "/tasks":
			add("DELETE /tasks forgets finished tasks")
		case parts[0] == "keys" && r.Method != http.MethodGet:
			add(r.Method + " " + p + " changes who may do what")
		case r.Method == http.MethodDelete && len(parts) >= 3 && parts[0] == "indexes" && parts[2] == "settings":
			add("DELETE " + p + " resets the index's settings")
		}
	}
	return out
}
