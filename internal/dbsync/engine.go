package dbsync

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Side is one end of a sync: a handle on one database. Database names the
// MySQL schema (the database itself); unused on Postgres.
type Side struct {
	DB       *sql.DB
	Dialect  Dialect
	Database string
}

// What to do with a row that exists on both sides with different values.
const (
	Overwrite  = "overwrite"   // the source's copy wins
	KeepTarget = "keep_target" // leave the target's copy
	NewerWins  = "newer_wins"  // the side with the later value in NewerColumn wins
	StopRun    = "stop"        // stop the whole sync
)

// What to do when the target refuses a row.
const (
	SkipRow   = "skip"
	StopTable = "stop_table"
	StopAll   = "stop"
)

type Rules struct {
	Insert      bool
	Delete      bool
	Conflict    string
	NewerColumn string
	OnError     string
	Create      bool   // create tables missing on the target
	NoKey       string // "skip" or "reload": a table without a key is emptied and copied again
	PauseChecks bool   // foreign keys (and on Postgres triggers) off while writing
	Lookback    int    // incremental: seconds to read again behind the mark (time columns)
	Batch       int
}

// Pair says which source table goes to which target table.
type Pair struct {
	From    Ref      `json:"from"`
	To      Ref      `json:"to"`
	Key     []string `json:"key,omitempty" doc:"Columns that identify a row; empty = the table's key"`
	Columns []string `json:"columns,omitempty" doc:"Only these columns; empty = every column both tables have"`
	Track   string   `json:"track,omitempty" doc:"Incremental: the column that grows with each new or changed row"`
}

// Mark is how far an incremental sync has read a table.
type Mark struct {
	Column string    `json:"column"`
	Value  *string   `json:"value"`
	Key    []string  `json:"key,omitempty"`
	At     time.Time `json:"at"`
}

type Value struct {
	Name string  `json:"name"`
	From *string `json:"from,omitempty" doc:"On the target now"`
	To   *string `json:"to,omitempty" doc:"From the source"`
}

type Change struct {
	Op     string   `json:"op" enum:"insert,update,delete,keep"`
	Key    []string `json:"key"`
	Values []Value  `json:"values,omitempty"`
}

type Failure struct {
	Op    string   `json:"op" enum:"insert,update,delete,reload,table"`
	Key   []string `json:"key,omitempty"`
	Error string   `json:"error"`
}

type TableResult struct {
	From     Ref       `json:"from"`
	To       Ref       `json:"to"`
	Key      []string  `json:"key"`
	State    string    `json:"state" enum:"done,failed,skipped,stopped"`
	Note     string    `json:"note,omitempty"`
	Error    string    `json:"error,omitempty"`
	Created  bool      `json:"created,omitempty"`
	Reloaded bool      `json:"reloaded,omitempty"`
	Columns  []string  `json:"columns"`
	Left     []string  `json:"left_out,omitempty" doc:"Source columns the target doesn't have"`
	Read     int64     `json:"read"`
	Same     int64     `json:"same"`
	Inserted int64     `json:"inserted"`
	Updated  int64     `json:"updated"`
	Deleted  int64     `json:"deleted"`
	Kept     int64     `json:"kept" doc:"Rows that differ but were left as the target has them"`
	Failed   int64     `json:"failed"`
	Samples  []Change  `json:"samples,omitempty"`
	Failures []Failure `json:"failures,omitempty"`
	Mark     *Mark     `json:"mark,omitempty"`
	Ms       int64     `json:"ms"`
}

func (r TableResult) Written() int64 { return r.Inserted + r.Updated + r.Deleted }

const (
	maxSamples  = 25
	maxFailures = 50
	maxValue    = 160
)

// ErrStopped is returned when a rule says to stop the whole sync.
var ErrStopped = errors.New("stopped")

// Run is one pass over a list of table pairs.
type Run struct {
	Src, Dst    Side
	Rules       Rules
	DryRun      bool
	Incremental bool
	Marks       map[string]Mark // by Pair.From; read and updated by incremental runs
	// Progress is told about each table as it starts, moves and ends.
	Progress func(table string, index, count int, read, estimate int64)
	Log      func(format string, args ...any)

	w     *sql.Conn
	notes []string
}

// Notes are things worth telling about the whole run (a setting the target
// refused, and so on).
func (r *Run) Notes() []string { return r.notes }

func (r *Run) logf(format string, args ...any) {
	if r.Log != nil {
		r.Log(format, args...)
	}
}

// Do syncs every pair in turn. The error is set when the sync stopped as a
// whole (a rule said so, the context ended or a database went away); the
// results then hold every table reached so far.
func (r *Run) Do(ctx context.Context, pairs []Pair) ([]TableResult, error) {
	if r.Rules.Batch <= 0 {
		r.Rules.Batch = 500
	}
	if r.Rules.Conflict == "" {
		r.Rules.Conflict = Overwrite
	}
	if r.Rules.OnError == "" {
		r.Rules.OnError = SkipRow
	}
	srcTables, err := Tables(ctx, r.Src.DB, r.Src.Dialect, r.Src.Database)
	if err != nil {
		return nil, fmt.Errorf("couldn't read the source's tables: %w", err)
	}
	dstTables, err := Tables(ctx, r.Dst.DB, r.Dst.Dialect, r.Dst.Database)
	if err != nil {
		return nil, fmt.Errorf("couldn't read the target's tables: %w", err)
	}
	src := map[Ref]Table{}
	for _, t := range srcTables {
		src[t.Ref] = t
	}
	dst := map[Ref]Table{}
	for _, t := range dstTables {
		dst[t.Ref] = t
	}

	if !r.DryRun {
		r.w, err = r.Dst.DB.Conn(ctx)
		if err != nil {
			return nil, err
		}
		defer r.release()
		if r.Rules.PauseChecks {
			r.pauseChecks(ctx)
		}
	}

	var out []TableResult
	for i, p := range pairs {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		started := time.Now()
		res := TableResult{From: p.From, To: p.To, State: "done"}
		if r.Progress != nil {
			r.Progress(p.From.String(), i, len(pairs), 0, src[p.From].Rows)
		}
		err := r.table(ctx, p, src, dst, &res, i, len(pairs))
		res.Ms = time.Since(started).Milliseconds()
		switch {
		case err == nil:
		case errors.Is(err, ErrStopped) || ctx.Err() != nil:
			if res.State == "done" {
				res.State = "stopped"
			}
			if res.Error == "" {
				res.Error = err.Error()
			}
			out = append(out, res)
			return out, err
		default:
			res.State = "failed"
			res.Error = err.Error()
			if r.Rules.OnError == StopAll {
				out = append(out, res)
				return out, fmt.Errorf("%s: %w", p.From, err)
			}
		}
		r.logf("%s → %s: %s", p.From, p.To, summary(res))
		out = append(out, res)
	}
	return out, nil
}

func summary(r TableResult) string {
	if r.State == "skipped" {
		return "skipped (" + r.Note + ")"
	}
	s := fmt.Sprintf("%d read, %d same, %d added, %d changed, %d removed", r.Read, r.Same, r.Inserted, r.Updated, r.Deleted)
	if r.Kept > 0 {
		s += fmt.Sprintf(", %d kept", r.Kept)
	}
	if r.Failed > 0 {
		s += fmt.Sprintf(", %d failed", r.Failed)
	}
	if r.Error != "" {
		s += " — " + r.Error
	}
	return s
}

func (r *Run) pauseChecks(ctx context.Context) {
	var err error
	if r.Dst.Dialect == MySQL {
		_, err = r.w.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0")
	} else {
		_, err = r.w.ExecContext(ctx, "SET session_replication_role = replica")
	}
	if err != nil {
		r.notes = append(r.notes, "Foreign keys stayed on: the target login can't turn them off ("+firstLine(err.Error())+").")
		r.logf("couldn't pause foreign key checks: %v", err)
	}
}

func (r *Run) release() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if r.Rules.PauseChecks {
		if r.Dst.Dialect == MySQL {
			r.w.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")
		} else {
			r.w.ExecContext(ctx, "RESET session_replication_role")
		}
	}
	r.w.Close()
}

// ---- One table ----

type plan struct {
	from, to   Table
	cols       []Column // source columns copied, in order
	dcols      []Column // the same columns on the target (their types)
	key        []int    // indexes into cols
	newer      int      // index of NewerColumn in cols, -1 if none
	track      int      // incremental column index, -1 if none
	identity   bool     // target has GENERATED ALWAYS identity columns
	serials    []Column // target columns fed by a sequence
	res        *TableResult
	rules      Rules
	index, all int
}

func (r *Run) table(ctx context.Context, p Pair, src, dst map[Ref]Table, res *TableResult, index, all int) error {
	from, ok := src[p.From]
	if !ok {
		return fmt.Errorf("the source has no table %s", p.From)
	}
	to, exists := dst[p.To]
	if !exists {
		if !r.Rules.Create {
			res.State = "skipped"
			res.Note = "not on the target"
			return nil
		}
		if r.DryRun {
			res.Created = true
			res.Note = "would be created"
			res.Key = from.Key
			for _, c := range from.Columns {
				if !c.Generated {
					res.Columns = append(res.Columns, c.Name)
				}
			}
			var n int64
			if err := r.Src.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+r.Src.Dialect.table(from.Ref)).Scan(&n); err != nil {
				return err
			}
			res.Read, res.Inserted = n, n
			return nil
		}
		if err := createTable(ctx, r.Src, r.Dst, from, p.To); err != nil {
			res.Failures = append(res.Failures, Failure{Op: "table", Error: err.Error()})
			return fmt.Errorf("couldn't create %s on the target: %w", p.To, err)
		}
		tables, err := Tables(ctx, r.Dst.DB, r.Dst.Dialect, r.Dst.Database)
		if err != nil {
			return err
		}
		for _, t := range tables {
			if t.Ref == p.To {
				to, exists = t, true
			}
		}
		if !exists {
			return fmt.Errorf("created %s, but can't find it on the target", p.To)
		}
		res.Created = true
	}

	pl := &plan{from: from, to: to, res: res, rules: r.Rules, newer: -1, track: -1, index: index, all: all}
	want := map[string]bool{}
	for _, c := range p.Columns {
		want[c] = true
	}
	keyNames := p.Key
	if len(keyNames) == 0 {
		keyNames = from.Key
	}
	for _, k := range keyNames {
		want[k] = len(p.Columns) > 0 || want[k]
	}
	for _, c := range from.Columns {
		if c.Generated || (len(p.Columns) > 0 && !want[c.Name]) {
			continue
		}
		dc, ok := to.column(c.Name)
		if !ok {
			res.Left = append(res.Left, c.Name)
			continue
		}
		if dc.Generated {
			continue
		}
		pl.cols = append(pl.cols, c)
		pl.dcols = append(pl.dcols, dc)
		res.Columns = append(res.Columns, c.Name)
		if dc.Identity {
			pl.identity = true
		}
		if dc.Serial {
			pl.serials = append(pl.serials, dc)
		}
	}
	if len(pl.cols) == 0 {
		res.State = "skipped"
		res.Note = "no columns in common"
		return nil
	}
	index_ := func(name string) int {
		for i, c := range pl.cols {
			if c.Name == name {
				return i
			}
		}
		return -1
	}
	for _, k := range keyNames {
		i := index_(k)
		if i < 0 {
			return fmt.Errorf("the key column %s isn't on both sides", k)
		}
		pl.key = append(pl.key, i)
	}
	res.Key = keyNames
	if r.Rules.Conflict == NewerWins {
		pl.newer = index_(r.Rules.NewerColumn)
		if pl.newer < 0 {
			return fmt.Errorf("the column %q that says which copy is newer isn't on both sides", r.Rules.NewerColumn)
		}
	}

	if len(pl.key) == 0 {
		if r.Incremental || r.Rules.NoKey != "reload" {
			res.State = "skipped"
			res.Note = "no primary key or unique key to match rows by"
			return nil
		}
		return r.reload(ctx, pl)
	}
	if r.Incremental {
		track := p.Track
		if track == "" {
			return fmt.Errorf("pick the column that grows with new rows")
		}
		pl.track = index_(track)
		if pl.track < 0 {
			return fmt.Errorf("the column %s isn't on both sides", track)
		}
		err := r.incremental(ctx, pl, p)
		r.fixSequences(ctx, pl)
		return err
	}
	err := r.compare(ctx, pl)
	r.fixSequences(ctx, pl)
	return err
}

// ---- Rows ----

type row []sql.NullString

func (rw row) key(idx []int) string {
	var b strings.Builder
	for _, i := range idx {
		if !rw[i].Valid {
			b.WriteString("\x01")
		} else {
			b.WriteString(rw[i].String)
		}
		b.WriteString("\x00")
	}
	return b.String()
}

func (rw row) keyText(idx []int) []string {
	out := make([]string, len(idx))
	for j, i := range idx {
		out[j] = trim(rw[i])
	}
	return out
}

func trim(v sql.NullString) string {
	if !v.Valid {
		return "NULL"
	}
	if len(v.String) > maxValue {
		return v.String[:maxValue] + "…"
	}
	return v.String
}

func ptr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	s := trim(v)
	return &s
}

func scanRows(rows *sql.Rows, n int) ([]row, error) {
	defer rows.Close()
	var out []row
	for rows.Next() {
		rw := make(row, n)
		dest := make([]any, n)
		for i := range rw {
			dest[i] = &rw[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		out = append(out, rw)
	}
	return out, rows.Err()
}

// ---- SQL pieces ----

func (d Dialect) list(cols []Column) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		// Aliased: on Postgres "id"::text would keep the name id and
		// ORDER BY "id" would then sort the text.
		parts[i] = d.sel(c) + fmt.Sprintf(" AS _morche_%d", i)
	}
	return strings.Join(parts, ", ")
}

func (d Dialect) names(cols []Column) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = d.quote(c.Name)
	}
	return strings.Join(parts, ", ")
}

// param is the n-th placeholder, read as a value of c's type.
func (d Dialect) param(n int, c Column) string {
	if d == MySQL {
		return "?"
	}
	return fmt.Sprintf("$%d::text::%s", n, c.Type)
}

// paramOrd is a placeholder compared the way ord(c) orders.
func (d Dialect) paramOrd(n int, c Column) string {
	if c.Kind != KindText {
		return d.param(n, c)
	}
	if d == MySQL {
		return "CAST(? AS BINARY)"
	}
	return fmt.Sprintf(`$%d::text COLLATE "C"`, n)
}

func (d Dialect) arg(c Column, v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	if d == MySQL && c.Kind == KindBinary {
		return []byte(v.String)
	}
	return v.String
}

// after is "(keys) > (values)" with placeholders from n on.
func (d Dialect) after(cols []Column, n int, op string) string {
	if len(cols) == 1 {
		return d.ord(cols[0]) + " " + op + " " + d.paramOrd(n, cols[0])
	}
	l := make([]string, len(cols))
	rr := make([]string, len(cols))
	for i, c := range cols {
		l[i] = d.ord(c)
		rr[i] = d.paramOrd(n+i, c)
	}
	return "(" + strings.Join(l, ", ") + ") " + op + " (" + strings.Join(rr, ", ") + ")"
}

func (d Dialect) orderBy(cols []Column) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = d.ord(c)
	}
	return strings.Join(parts, ", ")
}

func pick(cols []Column, idx []int) []Column {
	out := make([]Column, len(idx))
	for j, i := range idx {
		out[j] = cols[i]
	}
	return out
}

func keyArgs(d Dialect, cols []Column, rw row, idx []int) []any {
	out := make([]any, len(idx))
	for j, i := range idx {
		out[j] = d.arg(cols[i], rw[i])
	}
	return out
}

// ---- Full compare: keyset pages over both sides ----

func (r *Run) compare(ctx context.Context, pl *plan) error {
	sd, dd := r.Src.Dialect, r.Dst.Dialect
	skeys, dkeys := pick(pl.cols, pl.key), pick(pl.dcols, pl.key)
	n := r.Rules.Batch
	var lo row
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := "SELECT " + sd.list(pl.cols) + " FROM " + sd.table(pl.from.Ref)
		var args []any
		if lo != nil {
			q += " WHERE " + sd.after(skeys, 1, ">")
			args = keyArgs(sd, pl.cols, lo, pl.key)
		}
		q += " ORDER BY " + sd.orderBy(skeys) + fmt.Sprintf(" LIMIT %d", n)
		rows, err := r.Src.DB.QueryContext(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("reading the source: %w", err)
		}
		page, err := scanRows(rows, len(pl.cols))
		if err != nil {
			return fmt.Errorf("reading the source: %w", err)
		}
		var hi row
		if len(page) == n {
			hi = page[len(page)-1]
		}
		pl.res.Read += int64(len(page))

		byKey := make(map[string]int, len(page))
		for i, rw := range page {
			byKey[rw.key(pl.key)] = i
		}
		matched := make([]row, len(page))
		var gone []row

		// The target's rows in (lo, hi], in chunks.
		tlo := lo
		for {
			q := "SELECT " + dd.list(pl.dcols) + " FROM " + dd.table(pl.to.Ref)
			var where []string
			var args []any
			if tlo != nil {
				where = append(where, dd.after(dkeys, 1, ">"))
				args = append(args, keyArgs(dd, pl.dcols, tlo, pl.key)...)
			}
			if hi != nil {
				where = append(where, dd.after(dkeys, len(args)+1, "<="))
				args = append(args, keyArgs(dd, pl.dcols, hi, pl.key)...)
			}
			if len(where) > 0 {
				q += " WHERE " + strings.Join(where, " AND ")
			}
			q += " ORDER BY " + dd.orderBy(dkeys) + fmt.Sprintf(" LIMIT %d", n*4)
			rows, err := r.Dst.DB.QueryContext(ctx, q, args...)
			if err != nil {
				return fmt.Errorf("reading the target: %w", err)
			}
			chunk, err := scanRows(rows, len(pl.dcols))
			if err != nil {
				return fmt.Errorf("reading the target: %w", err)
			}
			for _, t := range chunk {
				if i, ok := byKey[t.key(pl.key)]; ok {
					matched[i] = t
				} else {
					gone = append(gone, t)
				}
			}
			if len(chunk) < n*4 {
				break
			}
			tlo = chunk[len(chunk)-1]
		}

		if err := r.apply(ctx, pl, page, matched); err != nil {
			return err
		}
		if len(gone) > 0 {
			if r.Rules.Delete {
				if err := r.remove(ctx, pl, gone); err != nil {
					return err
				}
			}
		}
		if r.Progress != nil {
			r.Progress(pl.from.String(), pl.index, pl.all, pl.res.Read, pl.from.Rows)
		}
		if hi == nil {
			return nil
		}
		lo = hi
	}
}

// apply writes one page of source rows; matched[i] is the target's copy of
// page[i], or nil.
func (r *Run) apply(ctx context.Context, pl *plan, page, matched []row) error {
	var inserts []row
	for i, s := range page {
		t := matched[i]
		if t == nil {
			if r.Rules.Insert {
				inserts = append(inserts, s)
				r.sample(pl, Change{Op: "insert", Key: s.keyText(pl.key), Values: values(pl, s, nil)})
			}
			continue
		}
		diff := differs(s, t)
		if len(diff) == 0 {
			pl.res.Same++
			continue
		}
		take := false
		switch r.Rules.Conflict {
		case Overwrite:
			take = true
		case NewerWins:
			take = newer(pl.cols[pl.newer], s[pl.newer], t[pl.newer])
		case StopRun:
			pl.res.Failures = append(pl.res.Failures, Failure{Op: "update", Key: s.keyText(pl.key), Error: "differs on the two sides"})
			pl.res.State = "stopped"
			r.sample(pl, Change{Op: "update", Key: s.keyText(pl.key), Values: changed(pl, s, t, diff)})
			if r.DryRun {
				pl.res.Kept++
				continue
			}
			return fmt.Errorf("%w: row %s differs on the two sides", ErrStopped, strings.Join(s.keyText(pl.key), ", "))
		}
		if !take {
			pl.res.Kept++
			r.sample(pl, Change{Op: "keep", Key: s.keyText(pl.key), Values: changed(pl, s, t, diff)})
			continue
		}
		r.sample(pl, Change{Op: "update", Key: s.keyText(pl.key), Values: changed(pl, s, t, diff)})
		if r.DryRun {
			pl.res.Updated++
			continue
		}
		if err := r.update(ctx, pl, s, diff); err != nil {
			if stop := r.failed(pl, "update", s, err); stop != nil {
				return stop
			}
			continue
		}
		pl.res.Updated++
	}
	if len(inserts) == 0 {
		return nil
	}
	if r.DryRun {
		pl.res.Inserted += int64(len(inserts))
		return nil
	}
	return r.insert(ctx, pl, r.w, inserts)
}

func differs(s, t row) []int {
	var out []int
	for i := range s {
		if s[i] != t[i] {
			out = append(out, i)
		}
	}
	return out
}

func values(pl *plan, s row, _ row) []Value {
	var out []Value
	for i, c := range pl.cols {
		if len(out) >= 12 {
			break
		}
		out = append(out, Value{Name: c.Name, To: ptr(s[i])})
	}
	return out
}

func changed(pl *plan, s, t row, diff []int) []Value {
	out := make([]Value, 0, len(diff))
	for _, i := range diff {
		out = append(out, Value{Name: pl.cols[i].Name, From: ptr(t[i]), To: ptr(s[i])})
	}
	return out
}

func (r *Run) sample(pl *plan, c Change) {
	if len(pl.res.Samples) < maxSamples {
		pl.res.Samples = append(pl.res.Samples, c)
	}
}

// failed records a row the target refused; the error it returns stops the
// table or the run.
func (r *Run) failed(pl *plan, op string, rw row, err error) error {
	pl.res.Failed++
	f := Failure{Op: op, Error: firstLine(err.Error())}
	if rw != nil {
		f.Key = rw.keyText(pl.key)
	}
	if len(pl.res.Failures) < maxFailures {
		pl.res.Failures = append(pl.res.Failures, f)
	}
	switch r.Rules.OnError {
	case StopTable:
		return fmt.Errorf("the target refused a row: %s", f.Error)
	case StopAll:
		return fmt.Errorf("%w: the target refused a row of %s: %s", ErrStopped, pl.from.Ref, f.Error)
	}
	return nil
}

// newer says whether the source's value is later than the target's.
func newer(c Column, s, t sql.NullString) bool {
	if !s.Valid {
		return false
	}
	if !t.Valid {
		return true
	}
	if c.Kind == KindNumber {
		a, ok1 := new(big.Rat).SetString(s.String)
		b, ok2 := new(big.Rat).SetString(t.String)
		if ok1 && ok2 {
			return a.Cmp(b) > 0
		}
	}
	if a, ok := parseTime(s.String); ok {
		if b, ok := parseTime(t.String); ok {
			return a.After(b)
		}
	}
	return s.String > t.String
}

var timeLayouts = []string{
	"2006-01-02 15:04:05.999999999-07:00:00",
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999-07",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02",
}

func parseTime(s string) (time.Time, bool) {
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

// ---- Writes ----

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (r *Run) insertSQL(pl *plan, count int) string {
	d := r.Dst.Dialect
	var b strings.Builder
	b.WriteString("INSERT INTO " + d.table(pl.to.Ref) + " (" + d.names(pl.dcols) + ")")
	if pl.identity && d == Postgres {
		b.WriteString(" OVERRIDING SYSTEM VALUE")
	}
	b.WriteString(" VALUES ")
	n := 1
	for i := 0; i < count; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("(")
		for j, c := range pl.dcols {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString(d.param(n, c))
			n++
		}
		b.WriteString(")")
	}
	return b.String()
}

func (r *Run) insertArgs(pl *plan, rows []row) []any {
	args := make([]any, 0, len(rows)*len(pl.dcols))
	for _, rw := range rows {
		for j, c := range pl.dcols {
			args = append(args, r.Dst.Dialect.arg(c, rw[j]))
		}
	}
	return args
}

// insert adds rows in batches; a refused batch is tried again row by row to
// find the rows the target won't take.
func (r *Run) insert(ctx context.Context, pl *plan, ex execer, rows []row) error {
	per := min(r.Rules.Batch, max(1, 60000/len(pl.dcols)))
	for start := 0; start < len(rows); start += per {
		batch := rows[start:min(start+per, len(rows))]
		if _, err := ex.ExecContext(ctx, r.insertSQL(pl, len(batch)), r.insertArgs(pl, batch)...); err == nil {
			pl.res.Inserted += int64(len(batch))
			continue
		} else if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, rw := range batch {
			if _, err := ex.ExecContext(ctx, r.insertSQL(pl, 1), r.insertArgs(pl, []row{rw})...); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if stop := r.failed(pl, "insert", rw, err); stop != nil {
					return stop
				}
				continue
			}
			pl.res.Inserted++
		}
	}
	return nil
}

func (r *Run) update(ctx context.Context, pl *plan, s row, diff []int) error {
	d := r.Dst.Dialect
	var sets, where []string
	var args []any
	n := 1
	for _, i := range diff {
		c := pl.dcols[i]
		sets = append(sets, d.quote(c.Name)+" = "+d.param(n, c))
		args = append(args, d.arg(c, s[i]))
		n++
	}
	for _, i := range pl.key {
		c := pl.dcols[i]
		where = append(where, d.quote(c.Name)+" = "+d.param(n, c))
		args = append(args, d.arg(c, s[i]))
		n++
	}
	_, err := r.w.ExecContext(ctx, "UPDATE "+d.table(pl.to.Ref)+" SET "+strings.Join(sets, ", ")+" WHERE "+strings.Join(where, " AND "), args...)
	return err
}

func (r *Run) deleteSQL(pl *plan, count int) string {
	d := r.Dst.Dialect
	keys := pick(pl.dcols, pl.key)
	n := 1
	tuple := func() string {
		parts := make([]string, len(keys))
		for i, c := range keys {
			parts[i] = d.param(n, c)
			n++
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return "(" + strings.Join(parts, ", ") + ")"
	}
	lhs := d.names(keys)
	if len(keys) > 1 {
		lhs = "(" + lhs + ")"
	}
	items := make([]string, count)
	for i := range items {
		items[i] = tuple()
	}
	return "DELETE FROM " + d.table(pl.to.Ref) + " WHERE " + lhs + " IN (" + strings.Join(items, ", ") + ")"
}

func (r *Run) remove(ctx context.Context, pl *plan, rows []row) error {
	for _, t := range rows {
		r.sample(pl, Change{Op: "delete", Key: t.keyText(pl.key)})
	}
	if r.DryRun {
		pl.res.Deleted += int64(len(rows))
		return nil
	}
	per := min(r.Rules.Batch, max(1, 60000/len(pl.key)))
	for start := 0; start < len(rows); start += per {
		batch := rows[start:min(start+per, len(rows))]
		args := make([]any, 0, len(batch)*len(pl.key))
		for _, t := range batch {
			args = append(args, keyArgs(r.Dst.Dialect, pl.dcols, t, pl.key)...)
		}
		if res, err := r.w.ExecContext(ctx, r.deleteSQL(pl, len(batch)), args...); err == nil {
			n, _ := res.RowsAffected()
			pl.res.Deleted += n
			continue
		} else if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, t := range batch {
			res, err := r.w.ExecContext(ctx, r.deleteSQL(pl, 1), keyArgs(r.Dst.Dialect, pl.dcols, t, pl.key)...)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if stop := r.failed(pl, "delete", t, err); stop != nil {
					return stop
				}
				continue
			}
			n, _ := res.RowsAffected()
			pl.res.Deleted += n
		}
	}
	return nil
}

// ---- Incremental: rows past the mark ----

func (r *Run) incremental(ctx context.Context, pl *plan, p Pair) error {
	sd, dd := r.Src.Dialect, r.Dst.Dialect
	track := pl.cols[pl.track]
	if track.Kind != KindNumber && track.Kind != KindTime {
		return fmt.Errorf("%s must be a number or a date/time to sync only what's new", track.Name)
	}
	order := append([]int{pl.track}, pl.key...)
	ocols := pick(pl.cols, order)
	mark := r.Marks[p.From.String()]
	if mark.Column != track.Name {
		mark = Mark{Column: track.Name}
	}
	first := true
	n := r.Rules.Batch
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := "SELECT " + sd.list(pl.cols) + " FROM " + sd.table(pl.from.Ref)
		var args []any
		switch {
		case mark.Value == nil:
			q += " WHERE " + sd.quote(track.Name) + " IS NOT NULL"
		case first && r.Rules.Lookback > 0 && track.Kind == KindTime:
			if sd == MySQL {
				q += fmt.Sprintf(" WHERE %s >= (? - INTERVAL %d SECOND)", sd.quote(track.Name), r.Rules.Lookback)
			} else {
				q += fmt.Sprintf(" WHERE %s >= (%s - interval '%d seconds')", sd.quote(track.Name), sd.param(1, track), r.Rules.Lookback)
			}
			args = []any{*mark.Value}
		case len(mark.Key) == len(pl.key):
			q += " WHERE " + sd.after(ocols, 1, ">")
			args = append(args, *mark.Value)
			for _, k := range mark.Key {
				args = append(args, k)
			}
			for i, c := range ocols {
				if c.Kind == KindBinary {
					args[i] = sd.arg(c, sql.NullString{String: args[i].(string), Valid: true})
				}
			}
		default:
			q += " WHERE " + sd.ord(track) + " > " + sd.paramOrd(1, track)
			args = []any{*mark.Value}
		}
		first = false
		q += " ORDER BY " + sd.orderBy(ocols) + fmt.Sprintf(" LIMIT %d", n)
		rows, err := r.Src.DB.QueryContext(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("reading the source: %w", err)
		}
		page, err := scanRows(rows, len(pl.cols))
		if err != nil {
			return fmt.Errorf("reading the source: %w", err)
		}
		if len(page) == 0 {
			break
		}
		pl.res.Read += int64(len(page))

		// The target's copies of these rows.
		var targs []any
		for _, s := range page {
			targs = append(targs, keyArgs(dd, pl.dcols, s, pl.key)...)
		}
		q = strings.Replace(r.deleteSQL(pl, len(page)), "DELETE FROM "+dd.table(pl.to.Ref), "SELECT "+dd.list(pl.dcols)+" FROM "+dd.table(pl.to.Ref), 1)
		trows, err := r.Dst.DB.QueryContext(ctx, q, targs...)
		if err != nil {
			return fmt.Errorf("reading the target: %w", err)
		}
		have, err := scanRows(trows, len(pl.dcols))
		if err != nil {
			return fmt.Errorf("reading the target: %w", err)
		}
		byKey := map[string]row{}
		for _, t := range have {
			byKey[t.key(pl.key)] = t
		}
		matched := make([]row, len(page))
		for i, s := range page {
			matched[i] = byKey[s.key(pl.key)]
		}
		if err := r.apply(ctx, pl, page, matched); err != nil {
			pl.res.Mark = &mark
			return err
		}
		last := page[len(page)-1]
		v := last[pl.track].String
		mark.Value = &v
		mark.Key = nil
		for _, i := range pl.key {
			mark.Key = append(mark.Key, last[i].String)
		}
		if r.Progress != nil {
			r.Progress(pl.from.String(), pl.index, pl.all, pl.res.Read, 0)
		}
		if len(page) < n {
			break
		}
	}
	mark.At = time.Now().UTC()
	pl.res.Mark = &mark
	return nil
}

// ---- No key: empty and copy again ----

func (r *Run) reload(ctx context.Context, pl *plan) error {
	sd := r.Src.Dialect
	var n int64
	if err := r.Src.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+sd.table(pl.from.Ref)).Scan(&n); err != nil {
		return err
	}
	pl.res.Read = n
	pl.res.Note = "no key: emptied and copied again"
	if r.DryRun {
		var m int64
		if err := r.Dst.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+r.Dst.Dialect.table(pl.to.Ref)).Scan(&m); err != nil {
			return err
		}
		pl.res.Deleted, pl.res.Inserted = m, n
		pl.res.Reloaded = true
		return nil
	}
	tx, err := r.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "DELETE FROM "+r.Dst.Dialect.table(pl.to.Ref))
	if err != nil {
		pl.res.Failures = append(pl.res.Failures, Failure{Op: "reload", Error: firstLine(err.Error())})
		return fmt.Errorf("couldn't empty the target table: %w", err)
	}
	deleted, _ := res.RowsAffected()
	rows, err := r.Src.DB.QueryContext(ctx, "SELECT "+sd.list(pl.cols)+" FROM "+sd.table(pl.from.Ref))
	if err != nil {
		return err
	}
	defer rows.Close()
	saved := r.Rules.OnError
	r.Rules.OnError = StopTable // half a table is worse than the old one
	defer func() { r.Rules.OnError = saved }()
	var batch []row
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := r.insert(ctx, pl, tx, batch)
		batch = batch[:0]
		return err
	}
	for rows.Next() {
		rw := make(row, len(pl.cols))
		dest := make([]any, len(rw))
		for i := range rw {
			dest[i] = &rw[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		batch = append(batch, rw)
		if len(batch) >= r.Rules.Batch {
			if err := flush(); err != nil {
				return err
			}
			if r.Progress != nil {
				r.Progress(pl.from.String(), pl.index, pl.all, pl.res.Inserted, n)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := flush(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	pl.res.Deleted = deleted
	pl.res.Reloaded = true
	return nil
}

// fixSequences moves a Postgres sequence past the rows copied in, so the
// target's own inserts don't run into them.
func (r *Run) fixSequences(ctx context.Context, pl *plan) {
	if r.DryRun || r.Dst.Dialect != Postgres || pl.res.Inserted == 0 {
		return
	}
	for _, c := range pl.serials {
		q := fmt.Sprintf(`SELECT setval(s, greatest(m, 1), m IS NOT NULL) FROM (SELECT pg_get_serial_sequence($1, $2) s, (SELECT max(%s) FROM %s)::bigint m) x WHERE s IS NOT NULL`,
			Postgres.quote(c.Name), Postgres.table(pl.to.Ref))
		if _, err := r.w.ExecContext(ctx, q, Postgres.table(pl.to.Ref), c.Name); err != nil {
			r.logf("couldn't move the sequence of %s.%s: %v", pl.to.Ref, c.Name, err)
		}
	}
}
