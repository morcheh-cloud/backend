package dbquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/morche/backend/internal/dbmon"
)

type mongoClient struct {
	client *mongo.Client
	def    string // the auth database
}

func openMongo(ctx context.Context, cfg dbmon.Config) (*mongoClient, error) {
	c, err := dbmon.OpenMongo(ctx, cfg, app)
	if err != nil {
		return nil, err
	}
	return &mongoClient{client: c, def: cfg.Database}, nil
}

func (m *mongoClient) Close() error { return m.client.Disconnect(context.Background()) }

var mongoSystem = map[string]bool{"admin": true, "local": true, "config": true}

func (m *mongoClient) Overview(ctx context.Context, database string) (*DatabaseOverview, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	o := &DatabaseOverview{Engine: dbmon.Mongo, Databases: []string{}, Schemas: []string{}, Objects: []DatabaseObject{}, Notes: []string{}}
	names, err := m.client.ListDatabaseNames(ctx, bson.D{}, options.ListDatabases().SetAuthorizedDatabases(true))
	if err != nil {
		o.Notes = append(o.Notes, "Couldn't list the databases: "+err.Error())
		if m.def != "" {
			names = []string{m.def}
		}
	}
	slices.SortFunc(names, func(a, b string) int {
		if mongoSystem[a] != mongoSystem[b] {
			if mongoSystem[a] {
				return 1
			}
			return -1
		}
		return strings.Compare(a, b)
	})
	o.Databases = append(o.Databases, names...)
	o.Database = database
	if o.Database == "" {
		for _, n := range names {
			if !mongoSystem[n] {
				o.Database = n
				break
			}
		}
		if o.Database == "" && len(names) > 0 {
			o.Database = names[0]
		}
	}
	if o.Database == "" {
		return o, nil
	}
	db := m.client.Database(o.Database)
	specs, err := db.ListCollectionSpecifications(ctx, bson.D{})
	if err != nil {
		o.Notes = append(o.Notes, "Couldn't list the collections: "+err.Error())
		return o, nil
	}
	slices.SortFunc(specs, func(a, b mongo.CollectionSpecification) int { return strings.Compare(a.Name, b.Name) })
	for i, s := range specs {
		if i >= maxObjects {
			o.Capped = true
			break
		}
		kind := "collection"
		switch s.Type {
		case "view":
			kind = "view"
		case "timeseries":
			kind = "timeseries"
		}
		o.Objects = append(o.Objects, DatabaseObject{Name: s.Name, Kind: kind})
	}
	// Estimated counts, a few at a time, within a budget.
	cctx, ccancel := context.WithTimeout(ctx, 8*time.Second)
	defer ccancel()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i := range o.Objects {
		if i >= 300 || o.Objects[i].Kind == "view" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if n, err := db.Collection(o.Objects[i].Name).EstimatedDocumentCount(cctx); err == nil {
				o.Objects[i].Rows = &n
			}
		}(i)
	}
	wg.Wait()
	return o, nil
}

func (m *mongoClient) Describe(ctx context.Context, database, _ string, name string) (*ObjectInfo, error) {
	if database == "" {
		database = m.def
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	db := m.client.Database(database)
	info := &ObjectInfo{Name: name, Kind: "collection", Columns: []ObjectColumn{}, Key: []string{"_id"}, Indexes: []ObjectIndex{}, Constraints: []ObjectConstraint{}}
	specs, err := db.ListCollectionSpecifications(ctx, bson.D{{Key: "name", Value: name}})
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return nil, ErrNotFound
	}
	switch specs[0].Type {
	case "view":
		info.Kind = "view"
		info.Key = []string{}
		if v, err := specs[0].Options.LookupErr("pipeline"); err == nil {
			info.Definition = extJSON(v, true)
		}
	case "timeseries":
		info.Kind = "timeseries"
	}
	coll := db.Collection(name)
	cur, err := coll.Aggregate(ctx, mongo.Pipeline{{{Key: "$sample", Value: bson.D{{Key: "size", Value: 100}}}}})
	if err != nil {
		cur, err = coll.Find(ctx, bson.D{}, options.Find().SetLimit(100))
	}
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	type field struct {
		types []string
		seen  int
		null  bool
	}
	fields := map[string]*field{}
	var order []string
	n := 0
	for cur.Next(ctx) {
		n++
		els, _ := cur.Current.Elements()
		for _, e := range els {
			f := fields[e.Key()]
			if f == nil {
				f = &field{}
				fields[e.Key()] = f
				order = append(order, e.Key())
			}
			f.seen++
			t := bsonType(e.Value().Type)
			if t == "null" {
				f.null = true
			} else if !slices.Contains(f.types, t) {
				f.types = append(f.types, t)
			}
		}
	}
	info.Sampled = n
	for _, k := range order {
		f := fields[k]
		info.Columns = append(info.Columns, ObjectColumn{Name: k, Type: strings.Join(f.types, " | "), Nullable: f.null || f.seen < n, Key: k == "_id" && info.Kind != "view"})
	}
	if specs, err := coll.Indexes().ListSpecifications(ctx); err == nil {
		for _, s := range specs {
			unique := s.Unique != nil && *s.Unique
			info.Indexes = append(info.Indexes, ObjectIndex{Name: s.Name, Definition: extJSON(bson.RawValue{Type: bson.TypeEmbeddedDocument, Value: s.KeysDocument}, true), Unique: unique || s.Name == "_id_", Primary: s.Name == "_id_"})
		}
	}
	if n == 0 && info.Kind != "view" {
		info.Columns = append(info.Columns, ObjectColumn{Name: "_id", Type: "objectId"})
	}
	return info, nil
}

func bsonType(t bson.Type) string {
	switch t {
	case bson.TypeDouble:
		return "double"
	case bson.TypeString:
		return "string"
	case bson.TypeEmbeddedDocument:
		return "object"
	case bson.TypeArray:
		return "array"
	case bson.TypeBinary:
		return "binary"
	case bson.TypeObjectID:
		return "objectId"
	case bson.TypeBoolean:
		return "bool"
	case bson.TypeDateTime:
		return "date"
	case bson.TypeNull, bson.TypeUndefined:
		return "null"
	case bson.TypeRegex:
		return "regex"
	case bson.TypeInt32:
		return "int"
	case bson.TypeTimestamp:
		return "timestamp"
	case bson.TypeInt64:
		return "long"
	case bson.TypeDecimal128:
		return "decimal"
	}
	return t.String()
}

// extJSON is a value as relaxed Extended JSON.
func extJSON(v bson.RawValue, indent bool) string {
	b, err := bson.MarshalExtJSON(bson.D{{Key: "v", Value: v}}, false, false)
	if err != nil {
		return v.String()
	}
	s := strings.TrimSpace(string(b))
	s = strings.TrimSuffix(strings.TrimPrefix(s, `{"v":`), "}")
	if indent {
		var out any
		if json.Unmarshal([]byte(s), &out) == nil {
			if p, err := json.MarshalIndent(out, "", "  "); err == nil {
				return string(p)
			}
		}
	}
	return s
}

func cellOf(v bson.RawValue) *string {
	switch v.Type {
	case bson.TypeNull, bson.TypeUndefined:
		return nil
	case bson.TypeString:
		return clip(v.StringValue())
	case bson.TypeObjectID:
		return ptr(v.ObjectID().Hex())
	case bson.TypeDateTime:
		return ptr(v.Time().UTC().Format("2006-01-02 15:04:05.999Z07:00"))
	case bson.TypeInt32:
		return ptr(strconv.FormatInt(int64(v.Int32()), 10))
	case bson.TypeInt64:
		return ptr(strconv.FormatInt(v.Int64(), 10))
	case bson.TypeDouble:
		return ptr(strconv.FormatFloat(v.Double(), 'g', -1, 64))
	case bson.TypeBoolean:
		return ptr(strconv.FormatBool(v.Boolean()))
	}
	return clip(extJSON(v, false))
}

// docsResult turns documents into rows: one column per top-level field.
func docsResult(docs []bson.Raw, truncated bool) QueryResult {
	r := QueryResult{Columns: []ResultColumn{}, Rows: [][]*string{}, Documents: []string{}, Truncated: truncated}
	idx := map[string]int{}
	var types []string
	for _, d := range docs {
		els, _ := d.Elements()
		for _, e := range els {
			if _, ok := idx[e.Key()]; !ok {
				idx[e.Key()] = len(r.Columns)
				r.Columns = append(r.Columns, ResultColumn{Name: e.Key()})
				types = append(types, bsonType(e.Value().Type))
			}
		}
	}
	for i := range r.Columns {
		r.Columns[i].Type = types[i]
	}
	for _, d := range docs {
		row := make([]*string, len(r.Columns))
		els, _ := d.Elements()
		for _, e := range els {
			row[idx[e.Key()]] = cellOf(e.Value())
		}
		r.Rows = append(r.Rows, row)
		b, err := bson.MarshalExtJSON(d, false, false)
		if err != nil {
			r.Documents = append(r.Documents, "{}")
		} else {
			r.Documents = append(r.Documents, *clip(string(b)))
		}
	}
	return r
}

// candidates are the values a typed-in text could mean.
func candidates(v string) []any {
	out := []any{v}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		out = append(out, n)
		if n >= -1<<31 && n < 1<<31 {
			out = append(out, int32(n))
		}
	} else if f, err := strconv.ParseFloat(v, 64); err == nil {
		out = append(out, f)
	}
	switch strings.ToLower(v) {
	case "true":
		out = append(out, true)
	case "false":
		out = append(out, false)
	case "null":
		out = append(out, nil)
	}
	if id, err := bson.ObjectIDFromHex(v); err == nil {
		out = append(out, id)
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		out = append(out, t)
	} else if t, err := time.Parse("2006-01-02", v); err == nil {
		out = append(out, t)
	}
	return out
}

// ordered is the value a comparison uses: a number, a date, else the text.
func ordered(v string) any {
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		return n
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t
	}
	return v
}

func mongoFilter(f RowFilter) (bson.E, error) {
	rx := func(p string) bson.D {
		return bson.D{{Key: "$regex", Value: p}, {Key: "$options", Value: "i"}}
	}
	q := regexp.QuoteMeta(f.Value)
	var v any
	switch f.Op {
	case "eq":
		v = bson.D{{Key: "$in", Value: candidates(f.Value)}}
	case "ne":
		v = bson.D{{Key: "$nin", Value: candidates(f.Value)}}
	case "gt", "gte", "lt", "lte":
		v = bson.D{{Key: "$" + f.Op, Value: ordered(f.Value)}}
	case "contains":
		v = rx(q)
	case "not_contains":
		v = bson.D{{Key: "$not", Value: bson.Regex{Pattern: q, Options: "i"}}}
	case "starts":
		v = rx("^" + q)
	case "ends":
		v = rx(q + "$")
	case "null":
		v = nil
	case "not_null":
		v = bson.D{{Key: "$ne", Value: nil}}
	case "in":
		vals := f.Values
		if len(vals) == 0 {
			for _, s := range strings.Split(f.Value, ",") {
				if s = strings.TrimSpace(s); s != "" {
					vals = append(vals, s)
				}
			}
		}
		var all []any
		for _, s := range vals {
			all = append(all, candidates(s)...)
		}
		v = bson.D{{Key: "$in", Value: all}}
	default:
		return bson.E{}, refused("unknown filter %q", f.Op)
	}
	return bson.E{Key: f.Column, Value: v}, nil
}

// parseJSON reads Extended JSON, or the shell's looser spelling.
func parseJSON(s string, into any) error {
	s = strings.TrimSpace(s)
	if err := bson.UnmarshalExtJSON([]byte(s), false, into); err == nil {
		return nil
	}
	j, err := shellToJSON(s)
	if err != nil {
		return err
	}
	return bson.UnmarshalExtJSON([]byte(j), false, into)
}

func (m *mongoClient) Rows(ctx context.Context, req RowsRequest) (*RowsPage, error) {
	if req.Table == "" {
		return nil, refused("Pick a collection.")
	}
	database := req.Database
	if database == "" {
		database = m.def
	}
	limit := limitOf(req.Limit, defaultLimit, 1000)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	coll := m.client.Database(database).Collection(req.Table)
	var conds bson.A
	for _, f := range req.Filters {
		e, err := mongoFilter(f)
		if err != nil {
			return nil, err
		}
		conds = append(conds, bson.D{e})
	}
	if s := strings.TrimSpace(req.Search); s != "" {
		info, err := m.Describe(ctx, database, "", req.Table)
		if err != nil {
			return nil, err
		}
		var or bson.A
		for _, c := range info.Columns {
			if strings.Contains(c.Type, "string") {
				or = append(or, bson.D{{Key: c.Name, Value: bson.Regex{Pattern: regexp.QuoteMeta(s), Options: "i"}}})
			}
		}
		if id, err := bson.ObjectIDFromHex(s); err == nil {
			or = append(or, bson.D{{Key: "_id", Value: id}})
		}
		if len(or) == 0 {
			or = append(or, bson.D{{Key: "_id", Value: s}})
		}
		conds = append(conds, bson.D{{Key: "$or", Value: or}})
	}
	filter := bson.D{}
	if len(conds) > 0 {
		op := "$and"
		if req.Match == "any" {
			op = "$or"
		}
		filter = bson.D{{Key: op, Value: conds}}
	}
	if w := strings.TrimSpace(req.Where); w != "" {
		var own bson.D
		if err := parseJSON(w, &own); err != nil {
			return nil, refused("The filter isn't valid JSON: %v", err)
		}
		if len(filter) == 0 {
			filter = own
		} else {
			filter = bson.D{{Key: "$and", Value: bson.A{filter, own}}}
		}
	}
	opts := options.Find().SetLimit(int64(limit + 1)).SetSkip(req.Offset)
	if len(req.Sort) > 0 {
		s := bson.D{}
		for _, x := range req.Sort {
			dir := 1
			if x.Desc {
				dir = -1
			}
			s = append(s, bson.E{Key: x.Column, Value: dir})
		}
		opts.SetSort(s)
	}
	start := time.Now()
	cur, err := coll.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	docs, truncated, err := readDocs(ctx, cur, limit)
	if err != nil {
		return nil, err
	}
	fj, _ := bson.MarshalExtJSON(filter, false, false)
	out := &RowsPage{QueryResult: docsResult(docs, truncated)}
	out.Statement = short("db." + req.Table + ".find(" + string(fj) + ")")
	out.Ms = time.Since(start).Milliseconds()
	if req.Count {
		if len(filter) == 0 {
			if n, err := coll.EstimatedDocumentCount(ctx); err == nil {
				out.Total, out.Estimated = &n, true
			}
		} else if !truncated && req.Offset == 0 {
			out.Total = ptr(int64(len(docs)))
		} else {
			cctx, ccancel := context.WithTimeout(ctx, 10*time.Second)
			if n, err := coll.CountDocuments(cctx, filter); err == nil {
				out.Total = &n
			}
			ccancel()
		}
	}
	return out, nil
}

func readDocs(ctx context.Context, cur *mongo.Cursor, limit int) ([]bson.Raw, bool, error) {
	defer cur.Close(ctx)
	var docs []bson.Raw
	size := 0
	for cur.Next(ctx) {
		if len(docs) >= limit || size > maxResult {
			return docs, true, nil
		}
		d := make(bson.Raw, len(cur.Current))
		copy(d, cur.Current)
		size += len(d)
		docs = append(docs, d)
	}
	return docs, false, cur.Err()
}

// mongoQuery is what a typed MongoDB query says.
type mongoQuery struct {
	Database   string          `json:"database"`
	Collection string          `json:"collection"`
	Find       json.RawMessage `json:"find"`
	Projection json.RawMessage `json:"projection"`
	Sort       json.RawMessage `json:"sort"`
	Limit      int64           `json:"limit"`
	Skip       int64           `json:"skip"`
	Aggregate  json.RawMessage `json:"aggregate"`
	Count      json.RawMessage `json:"count"`
	Distinct   string          `json:"distinct"`
	Filter     json.RawMessage `json:"filter"`
	Insert     json.RawMessage `json:"insert"`
	Update     json.RawMessage `json:"update"`
	Set        json.RawMessage `json:"set"`
	Delete     json.RawMessage `json:"delete"`
	Many       bool            `json:"many"`
	Command    json.RawMessage `json:"command"`
}

func (q mongoQuery) kind() string {
	switch {
	case q.Command != nil:
		return "command"
	case q.Aggregate != nil:
		return "aggregate"
	case q.Count != nil:
		return "count"
	case q.Distinct != "":
		return "distinct"
	case q.Insert != nil:
		return "insert"
	case q.Update != nil:
		return "update"
	case q.Delete != nil:
		return "delete"
	}
	return "find"
}

func readMongoQuery(s string) (mongoQuery, error) {
	var q mongoQuery
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ";"))
	if strings.HasPrefix(s, "db.") {
		j, err := shellCall(s)
		if err != nil {
			return q, refused("%v", err)
		}
		s = j
	}
	if err := json.Unmarshal([]byte(s), &q); err != nil {
		j, jerr := shellToJSON(s)
		if jerr != nil || json.Unmarshal([]byte(j), &q) != nil {
			return q, refused("Write the query as JSON, e.g. {\"collection\": \"users\", \"find\": {\"age\": {\"$gt\": 30}}}, or as db.users.find({…}).")
		}
	}
	if q.Collection == "" && q.Command == nil {
		return q, refused("Say which collection: \"collection\": \"…\".")
	}
	return q, nil
}

func mongoRisks(script string) []string {
	q, err := readMongoQuery(script)
	if err != nil {
		return nil
	}
	empty := func(raw json.RawMessage) bool {
		var d bson.D
		return parseJSON(string(raw), &d) == nil && len(d) == 0
	}
	var out []string
	switch q.kind() {
	case "delete":
		if empty(q.Delete) {
			out = append(out, "delete with an empty filter removes every document")
		}
	case "update":
		if q.Many && empty(q.Update) {
			out = append(out, "update with an empty filter changes every document")
		}
	case "command":
		var d bson.D
		if parseJSON(string(q.Command), &d) == nil && len(d) > 0 {
			switch strings.ToLower(d[0].Key) {
			case "drop", "dropdatabase", "dropindexes", "dropuser", "dropallusersfromdatabase", "renamecollection", "shutdown", "createuser", "updateuser", "grantrolestouser", "revokerolesfromuser":
				out = append(out, d[0].Key+" drops data or changes who may do what")
			}
		}
	}
	return out
}

func (m *mongoClient) Run(ctx context.Context, database, script string, o RunOptions) ([]QueryResult, error) {
	q, err := readMongoQuery(script)
	if err != nil {
		return nil, err
	}
	if q.Database != "" {
		database = q.Database
	}
	if database == "" {
		database = m.def
	}
	kind := q.kind()
	if !o.Change {
		switch kind {
		case "insert", "update", "delete", "command":
			return nil, refused("%s may change something. Turn on Allow changes to run it.", kind)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	db := m.client.Database(database)
	coll := db.Collection(q.Collection)
	doc := func(raw json.RawMessage) (bson.D, error) {
		d := bson.D{}
		if len(raw) == 0 || string(raw) == "null" {
			return d, nil
		}
		if err := parseJSON(string(raw), &d); err != nil {
			return nil, refused("Not valid JSON: %v", err)
		}
		return d, nil
	}
	start := time.Now()
	r := QueryResult{Statement: short(script)}
	done := func(res QueryResult) ([]QueryResult, error) {
		res.Statement = r.Statement
		res.Ms = time.Since(start).Milliseconds()
		return []QueryResult{res}, nil
	}
	switch kind {
	case "find":
		filter, err := doc(q.Find)
		if err != nil {
			return nil, err
		}
		limit := o.Limit
		if q.Limit > 0 && int(q.Limit) < limit {
			limit = int(q.Limit)
		}
		opts := options.Find().SetLimit(int64(limit + 1)).SetSkip(q.Skip)
		if p, err := doc(q.Projection); err != nil {
			return nil, err
		} else if len(p) > 0 {
			opts.SetProjection(p)
		}
		if s, err := doc(q.Sort); err != nil {
			return nil, err
		} else if len(s) > 0 {
			opts.SetSort(s)
		}
		cur, err := coll.Find(ctx, filter, opts)
		if err != nil {
			return nil, err
		}
		docs, truncated, err := readDocs(ctx, cur, limit)
		if err != nil {
			return nil, err
		}
		return done(docsResult(docs, truncated && (q.Limit == 0 || int(q.Limit) > limit)))
	case "aggregate":
		var stages []bson.D
		if err := parseJSON(string(q.Aggregate), &stages); err != nil {
			return nil, refused("aggregate takes a list of stages: %v", err)
		}
		if !o.Change {
			for _, s := range stages {
				if len(s) > 0 && (s[0].Key == "$out" || s[0].Key == "$merge") {
					return nil, refused("%s writes into a collection. Turn on Allow changes to run it.", s[0].Key)
				}
			}
		}
		pipe := make(mongo.Pipeline, len(stages))
		copy(pipe, stages)
		cur, err := coll.Aggregate(ctx, pipe)
		if err != nil {
			return nil, err
		}
		docs, truncated, err := readDocs(ctx, cur, o.Limit)
		if err != nil {
			return nil, err
		}
		return done(docsResult(docs, truncated))
	case "count":
		filter, err := doc(q.Count)
		if err != nil {
			return nil, err
		}
		n, err := coll.CountDocuments(ctx, filter)
		if err != nil {
			return nil, err
		}
		return done(QueryResult{Columns: []ResultColumn{{Name: "count", Type: "long"}}, Rows: [][]*string{{ptr(strconv.FormatInt(n, 10))}}})
	case "distinct":
		filter, err := doc(q.Filter)
		if err != nil {
			return nil, err
		}
		res := coll.Distinct(ctx, q.Distinct, filter)
		if res.Err() != nil {
			return nil, res.Err()
		}
		raw, err := res.Raw()
		if err != nil {
			return nil, err
		}
		vals, _ := raw.Values()
		out := QueryResult{Columns: []ResultColumn{{Name: q.Distinct}}, Rows: [][]*string{}}
		for i, v := range vals {
			if i >= o.Limit {
				out.Truncated = true
				break
			}
			out.Rows = append(out.Rows, []*string{cellOf(v)})
		}
		return done(out)
	case "insert":
		raw := strings.TrimSpace(string(q.Insert))
		var docs []bson.D
		if strings.HasPrefix(raw, "[") {
			if err := parseJSON(raw, &docs); err != nil {
				return nil, refused("Not valid JSON: %v", err)
			}
		} else {
			d, err := doc(q.Insert)
			if err != nil {
				return nil, err
			}
			docs = []bson.D{d}
		}
		if len(docs) == 0 {
			return nil, refused("Nothing to insert.")
		}
		res, err := coll.InsertMany(ctx, docs)
		if err != nil {
			return nil, err
		}
		n := int64(len(res.InsertedIDs))
		return done(QueryResult{Columns: []ResultColumn{}, Rows: [][]*string{}, Affected: &n, Message: fmt.Sprintf("Inserted %d", n)})
	case "update":
		filter, err := doc(q.Update)
		if err != nil {
			return nil, err
		}
		change, err := doc(q.Set)
		if err != nil {
			return nil, err
		}
		if len(change) == 0 {
			return nil, refused("Say what to change: \"set\": {\"$set\": {…}}.")
		}
		if !strings.HasPrefix(change[0].Key, "$") {
			change = bson.D{{Key: "$set", Value: change}}
		}
		var res *mongo.UpdateResult
		if q.Many {
			res, err = coll.UpdateMany(ctx, filter, change)
		} else {
			res, err = coll.UpdateOne(ctx, filter, change)
		}
		if err != nil {
			return nil, err
		}
		n := res.ModifiedCount
		return done(QueryResult{Columns: []ResultColumn{}, Rows: [][]*string{}, Affected: &n, Message: fmt.Sprintf("Matched %d, changed %d", res.MatchedCount, res.ModifiedCount)})
	case "delete":
		filter, err := doc(q.Delete)
		if err != nil {
			return nil, err
		}
		var res *mongo.DeleteResult
		if q.Many {
			res, err = coll.DeleteMany(ctx, filter)
		} else {
			res, err = coll.DeleteOne(ctx, filter)
		}
		if err != nil {
			return nil, err
		}
		n := res.DeletedCount
		return done(QueryResult{Columns: []ResultColumn{}, Rows: [][]*string{}, Affected: &n, Message: fmt.Sprintf("Deleted %d", n)})
	case "command":
		cmd, err := doc(q.Command)
		if err != nil {
			return nil, err
		}
		var out bson.Raw
		if err := db.RunCommand(ctx, cmd).Decode(&out); err != nil {
			return nil, err
		}
		return done(docsResult([]bson.Raw{out}, false))
	}
	return nil, errors.New("unknown query")
}

// ---- the mongo shell's spelling ----

var shellCallRe = regexp.MustCompile(`(?s)^db\.(?:getCollection\(\s*["']([^"']+)["']\s*\)|([A-Za-z_$][\w$.-]*?))\.(find|findOne|aggregate|countDocuments|count|distinct|insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany)\((.*?)\)((?:\s*\.\s*(?:sort|limit|skip|projection)\(.*?\))*)$`)
var shellChainRe = regexp.MustCompile(`(?s)\.\s*(sort|limit|skip|projection)\((.*?)\)`)

// shellCall turns db.coll.method(args) into the JSON form.
func shellCall(s string) (string, error) {
	m := shellCallRe.FindStringSubmatch(s)
	if m == nil {
		return "", errors.New("Couldn't read that. Write db.<collection>.find({…}) / aggregate([…]) / countDocuments({…}) / distinct(\"field\", {…}), or the JSON form.")
	}
	coll := m[1]
	if coll == "" {
		coll = m[2]
	}
	args, err := splitArgs(m[4])
	if err != nil {
		return "", err
	}
	for i := range args {
		if args[i], err = shellToJSON(args[i]); err != nil {
			return "", err
		}
	}
	arg := func(i int, def string) string {
		if i < len(args) && strings.TrimSpace(args[i]) != "" {
			return args[i]
		}
		return def
	}
	q := map[string]json.RawMessage{}
	cj, _ := json.Marshal(coll)
	q["collection"] = cj
	switch m[3] {
	case "find", "findOne":
		q["find"] = json.RawMessage(arg(0, "{}"))
		if p := arg(1, ""); p != "" {
			q["projection"] = json.RawMessage(p)
		}
		if m[3] == "findOne" {
			q["limit"] = json.RawMessage("1")
		}
	case "aggregate":
		q["aggregate"] = json.RawMessage(arg(0, "[]"))
	case "countDocuments", "count":
		q["count"] = json.RawMessage(arg(0, "{}"))
	case "distinct":
		var field string
		if json.Unmarshal([]byte(arg(0, `""`)), &field) != nil || field == "" {
			return "", errors.New("distinct needs a field name")
		}
		fj, _ := json.Marshal(field)
		q["distinct"] = fj
		q["filter"] = json.RawMessage(arg(1, "{}"))
	case "insertOne", "insertMany":
		q["insert"] = json.RawMessage(arg(0, "{}"))
	case "updateOne", "updateMany":
		q["update"] = json.RawMessage(arg(0, "{}"))
		q["set"] = json.RawMessage(arg(1, "{}"))
		if m[3] == "updateMany" {
			q["many"] = json.RawMessage("true")
		}
	case "deleteOne", "deleteMany":
		q["delete"] = json.RawMessage(arg(0, "{}"))
		if m[3] == "deleteMany" {
			q["many"] = json.RawMessage("true")
		}
	}
	for _, c := range shellChainRe.FindAllStringSubmatch(m[5], -1) {
		v, err := shellToJSON(c[2])
		if err != nil {
			return "", err
		}
		q[c[1]] = json.RawMessage(v)
	}
	b, err := json.Marshal(q)
	return string(b), err
}

// splitArgs cuts a call's arguments at top-level commas.
func splitArgs(s string) ([]string, error) {
	var out []string
	depth := 0
	var quote rune
	start := 0
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, string(rs[start:i]))
				start = i + 1
			}
		}
	}
	if depth != 0 || quote != 0 {
		return nil, errors.New("brackets or quotes don't match")
	}
	if rest := strings.TrimSpace(string(rs[start:])); rest != "" || len(out) > 0 {
		out = append(out, string(rs[start:]))
	}
	return out, nil
}

// shellToJSON quotes bare keys, turns 'strings' into "strings" and the
// shell's ObjectId("…"), ISODate("…"), NumberLong(…) into Extended JSON.
func shellToJSON(s string) (string, error) {
	rs := []rune(strings.TrimSpace(s))
	var b strings.Builder
	n := len(rs)
	for i := 0; i < n; i++ {
		c := rs[i]
		switch {
		case c == '"' || c == '\'':
			j := i + 1
			var sb strings.Builder
			for j < n && rs[j] != c {
				if rs[j] == '\\' && j+1 < n {
					sb.WriteRune(rs[j])
					j++
				}
				sb.WriteRune(rs[j])
				j++
			}
			if j >= n {
				return "", errors.New("a string isn't closed")
			}
			str := sb.String()
			if c == '\'' {
				str = strings.ReplaceAll(strings.ReplaceAll(str, `\'`, `'`), `"`, `\"`)
			}
			b.WriteString(`"` + str + `"`)
			i = j
		case c == '/' && i+1 < n && rs[i+1] == '/':
			for i < n && rs[i] != '\n' {
				i++
			}
		case c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			j := i
			for j < n && (rs[j] == '_' || rs[j] == '$' || rs[j] == '.' || (rs[j] >= 'a' && rs[j] <= 'z') || (rs[j] >= 'A' && rs[j] <= 'Z') || (rs[j] >= '0' && rs[j] <= '9')) {
				j++
			}
			word := string(rs[i:j])
			k := j
			for k < n && (rs[k] == ' ' || rs[k] == '\t' || rs[k] == '\n' || rs[k] == '\r') {
				k++
			}
			if word == "new" {
				i = k - 1
				continue
			}
			if k < n && rs[k] == ':' {
				b.WriteString(`"` + word + `"`)
				i = j - 1
				continue
			}
			if k < n && rs[k] == '(' {
				end := k + 1
				depth := 1
				for end < n && depth > 0 {
					if rs[end] == '(' {
						depth++
					} else if rs[end] == ')' {
						depth--
					}
					end++
				}
				inner := strings.TrimSpace(string(rs[k+1 : end-1]))
				inner = strings.Trim(inner, `"'`)
				ij, _ := json.Marshal(inner)
				switch word {
				case "ObjectId":
					b.WriteString(`{"$oid":` + string(ij) + `}`)
				case "ISODate", "Date":
					if inner == "" {
						inner = time.Now().UTC().Format(time.RFC3339)
						ij, _ = json.Marshal(inner)
					}
					b.WriteString(`{"$date":` + string(ij) + `}`)
				case "NumberLong":
					b.WriteString(`{"$numberLong":` + string(ij) + `}`)
				case "NumberInt":
					b.WriteString(`{"$numberInt":` + string(ij) + `}`)
				case "NumberDecimal":
					b.WriteString(`{"$numberDecimal":` + string(ij) + `}`)
				case "UUID":
					b.WriteString(`{"$uuid":` + string(ij) + `}`)
				default:
					return "", fmt.Errorf("%s(…) isn't understood here", word)
				}
				i = end - 1
				continue
			}
			switch word {
			case "true", "false", "null":
				b.WriteString(word)
			case "undefined":
				b.WriteString("null")
			default:
				return "", fmt.Errorf("%q isn't a value (put text in quotes)", word)
			}
			i = j - 1
		default:
			b.WriteRune(c)
		}
	}
	return b.String(), nil
}
