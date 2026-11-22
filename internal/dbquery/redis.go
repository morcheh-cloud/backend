package dbquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/morche/backend/internal/dbmon"
)

type redisClient struct {
	rdb *redis.Client
	db  int
}

func openRedis(ctx context.Context, cfg dbmon.Config, name string) (*redisClient, error) {
	db := 0
	if name == "" {
		name = cfg.Database
	}
	if name != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(name, "db"))
		if err != nil || n < 0 {
			return nil, errors.New("the Redis database is a number, e.g. 0")
		}
		db = n
	}
	rdb, err := dbmon.OpenRedis(ctx, cfg, db, app)
	if err != nil {
		return nil, err
	}
	return &redisClient{rdb: rdb, db: db}, nil
}

func (r *redisClient) Close() error { return r.rdb.Close() }

var keyspaceRe = regexp.MustCompile(`(?m)^db(\d+):keys=(\d+)`)

func (r *redisClient) Overview(ctx context.Context, _ string) (*DatabaseOverview, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	o := &DatabaseOverview{Engine: dbmon.Redis, Databases: []string{}, Schemas: []string{}, Objects: []DatabaseObject{}, Notes: []string{}, Database: strconv.Itoa(r.db)}
	seen := map[int]bool{r.db: true}
	nums := []int{r.db}
	if info, err := r.rdb.Info(ctx, "keyspace").Result(); err == nil {
		for _, m := range keyspaceRe.FindAllStringSubmatch(info, -1) {
			n, _ := strconv.Atoi(m[1])
			if !seen[n] {
				seen[n] = true
				nums = append(nums, n)
			}
		}
	} else {
		o.Notes = append(o.Notes, "Couldn't read the keyspace: "+err.Error())
	}
	sort.Ints(nums)
	for _, n := range nums {
		o.Databases = append(o.Databases, strconv.Itoa(n))
	}
	if n, err := r.rdb.DBSize(ctx).Result(); err == nil {
		o.Keys = &n
	}
	return o, nil
}

func (r *redisClient) Describe(context.Context, string, string, string) (*ObjectInfo, error) {
	return nil, ErrUnsupported
}

// globEscape makes text match itself in a SCAN pattern.
func globEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`, `]`, `\]`).Replace(s)
}

func (r *redisClient) Rows(ctx context.Context, req RowsRequest) (*RowsPage, error) {
	limit := limitOf(req.Limit, defaultLimit, 1000)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	pattern := "*"
	keyType := ""
	for _, f := range req.Filters {
		switch f.Column {
		case "type":
			if f.Op == "eq" {
				keyType = strings.ToLower(f.Value)
			}
		default:
			v := globEscape(f.Value)
			switch f.Op {
			case "eq":
				pattern = v
			case "contains":
				pattern = "*" + v + "*"
			case "starts":
				pattern = v + "*"
			case "ends":
				pattern = "*" + v
			}
		}
	}
	if s := strings.TrimSpace(req.Search); s != "" {
		pattern = "*" + globEscape(s) + "*"
	}
	if w := strings.TrimSpace(req.Where); w != "" {
		pattern = w
	}
	var cursor uint64
	if req.Cursor != "" {
		c, err := strconv.ParseUint(req.Cursor, 10, 64)
		if err != nil {
			return nil, refused("bad cursor")
		}
		cursor = c
	}
	start := time.Now()
	var keys []string
	step := int64(max(limit, 100))
	for i := 0; i < 50 && len(keys) < limit; i++ {
		var batch []string
		var err error
		if keyType != "" {
			batch, cursor, err = r.rdb.ScanType(ctx, cursor, pattern, step, keyType).Result()
		} else {
			batch, cursor, err = r.rdb.Scan(ctx, cursor, pattern, step).Result()
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		if cursor == 0 {
			break
		}
	}
	sort.Strings(keys)
	out := &RowsPage{}
	out.Columns = []ResultColumn{{Name: "key", Type: "key"}, {Name: "type"}, {Name: "ttl", Type: "ms"}, {Name: "size"}}
	out.Rows = [][]*string{}
	if cursor != 0 {
		out.NextCursor = strconv.FormatUint(cursor, 10)
		out.Truncated = true
	}
	if len(keys) > 0 {
		pipe := r.rdb.Pipeline()
		types := make([]*redis.StatusCmd, len(keys))
		ttls := make([]*redis.DurationCmd, len(keys))
		for i, k := range keys {
			types[i] = pipe.Type(ctx, k)
			ttls[i] = pipe.PTTL(ctx, k)
		}
		_, _ = pipe.Exec(ctx)
		pipe = r.rdb.Pipeline()
		sizes := make([]*redis.IntCmd, len(keys))
		for i, k := range keys {
			sizes[i] = sizeCmd(ctx, pipe, types[i].Val(), k)
		}
		_, _ = pipe.Exec(ctx)
		for i, k := range keys {
			ttl := "-1"
			if d := ttls[i].Val(); d > 0 {
				ttl = strconv.FormatInt(d.Milliseconds(), 10)
			}
			var size *string
			if sizes[i] != nil && sizes[i].Err() == nil {
				size = ptr(strconv.FormatInt(sizes[i].Val(), 10))
			}
			out.Rows = append(out.Rows, []*string{ptr(k), ptr(types[i].Val()), ptr(ttl), size})
		}
	}
	out.Statement = "SCAN " + pattern
	out.Ms = time.Since(start).Milliseconds()
	if req.Count && pattern == "*" && keyType == "" {
		if n, err := r.rdb.DBSize(ctx).Result(); err == nil {
			out.Total = &n
		}
	}
	return out, nil
}

func sizeCmd(ctx context.Context, p redis.Cmdable, typ, key string) *redis.IntCmd {
	switch typ {
	case "string":
		return p.StrLen(ctx, key)
	case "list":
		return p.LLen(ctx, key)
	case "hash":
		return p.HLen(ctx, key)
	case "set":
		return p.SCard(ctx, key)
	case "zset":
		return p.ZCard(ctx, key)
	case "stream":
		return p.XLen(ctx, key)
	}
	return nil
}

const keyItems = 1000

func (r *redisClient) Key(ctx context.Context, key string) (*RedisKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	typ, err := r.rdb.Type(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if typ == "none" {
		return nil, ErrNotFound
	}
	kv := &RedisKey{Key: key, Type: typ, TTLMs: -1}
	if d, err := r.rdb.PTTL(ctx, key).Result(); err == nil && d > 0 {
		kv.TTLMs = d.Milliseconds()
	}
	if c := sizeCmd(ctx, r.rdb, typ, key); c != nil {
		kv.Size = c.Val()
	}
	res := &QueryResult{Columns: []ResultColumn{}, Rows: [][]*string{}}
	switch typ {
	case "string":
		s, err := r.rdb.GetRange(ctx, key, 0, maxCell-1).Result()
		if err != nil {
			return nil, err
		}
		kv.Text = text([]byte(s), "")
		kv.Truncated = kv.Size > maxCell
		return kv, nil
	case "hash":
		res.Columns = []ResultColumn{{Name: "field"}, {Name: "value"}}
		vals, _, err := r.rdb.HScan(ctx, key, 0, "*", keyItems).Result()
		if err != nil {
			return nil, err
		}
		for i := 0; i+1 < len(vals) && len(res.Rows) < keyItems; i += 2 {
			res.Rows = append(res.Rows, []*string{text([]byte(vals[i]), ""), text([]byte(vals[i+1]), "")})
		}
		sort.Slice(res.Rows, func(i, j int) bool { return *res.Rows[i][0] < *res.Rows[j][0] })
	case "list":
		res.Columns = []ResultColumn{{Name: "index"}, {Name: "value"}}
		vals, err := r.rdb.LRange(ctx, key, 0, keyItems-1).Result()
		if err != nil {
			return nil, err
		}
		for i, v := range vals {
			res.Rows = append(res.Rows, []*string{ptr(strconv.Itoa(i)), text([]byte(v), "")})
		}
	case "set":
		res.Columns = []ResultColumn{{Name: "member"}}
		vals, _, err := r.rdb.SScan(ctx, key, 0, "*", keyItems).Result()
		if err != nil {
			return nil, err
		}
		sort.Strings(vals)
		for _, v := range vals {
			res.Rows = append(res.Rows, []*string{text([]byte(v), "")})
		}
	case "zset":
		res.Columns = []ResultColumn{{Name: "member"}, {Name: "score"}}
		vals, err := r.rdb.ZRangeWithScores(ctx, key, 0, keyItems-1).Result()
		if err != nil {
			return nil, err
		}
		for _, z := range vals {
			res.Rows = append(res.Rows, []*string{text(z.Member, ""), ptr(strconv.FormatFloat(z.Score, 'g', -1, 64))})
		}
	case "stream":
		res.Columns = []ResultColumn{{Name: "id"}, {Name: "fields"}}
		vals, err := r.rdb.XRevRangeN(ctx, key, "+", "-", 200).Result()
		if err != nil {
			return nil, err
		}
		for _, m := range vals {
			b, _ := json.Marshal(m.Values)
			res.Rows = append(res.Rows, []*string{ptr(m.ID), clip(string(b))})
		}
	default:
		return kv, nil
	}
	kv.Truncated = kv.Size > int64(len(res.Rows))
	kv.Value = res
	return kv, nil
}

// redisLines reads one command per line, with shell-like quoting.
func redisLines(script string) [][]string {
	var out [][]string
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		var args []string
		var b strings.Builder
		in := false
		var quote rune
		rs := []rune(line)
		for i := 0; i < len(rs); i++ {
			c := rs[i]
			switch {
			case quote != 0:
				if c == '\\' && quote == '"' && i+1 < len(rs) {
					i++
					switch rs[i] {
					case 'n':
						b.WriteRune('\n')
					case 't':
						b.WriteRune('\t')
					default:
						b.WriteRune(rs[i])
					}
				} else if c == quote {
					quote = 0
				} else {
					b.WriteRune(c)
				}
			case c == '"' || c == '\'':
				quote, in = c, true
			case c == ' ' || c == '\t':
				if in {
					args = append(args, b.String())
					b.Reset()
					in = false
				}
			default:
				b.WriteRune(c)
				in = true
			}
		}
		if in {
			args = append(args, b.String())
		}
		if len(args) > 0 {
			out = append(out, args)
		}
	}
	return out
}

// redisReads are the commands a read-only run may send.
var redisReads = map[string]bool{
	"GET": true, "MGET": true, "STRLEN": true, "GETRANGE": true, "EXISTS": true, "TYPE": true, "TTL": true, "PTTL": true,
	"EXPIRETIME": true, "PEXPIRETIME": true, "HGET": true, "HGETALL": true, "HMGET": true, "HKEYS": true, "HVALS": true,
	"HLEN": true, "HSCAN": true, "HEXISTS": true, "HSTRLEN": true, "HRANDFIELD": true, "LRANGE": true, "LLEN": true,
	"LINDEX": true, "LPOS": true, "SMEMBERS": true, "SCARD": true, "SISMEMBER": true, "SMISMEMBER": true, "SSCAN": true,
	"SRANDMEMBER": true, "SINTER": true, "SUNION": true, "SDIFF": true, "SINTERCARD": true, "ZRANGE": true,
	"ZRANGEBYSCORE": true, "ZRANGEBYLEX": true, "ZREVRANGE": true, "ZREVRANGEBYSCORE": true, "ZSCORE": true, "ZMSCORE": true,
	"ZCARD": true, "ZCOUNT": true, "ZLEXCOUNT": true, "ZRANK": true, "ZREVRANK": true, "ZSCAN": true, "ZRANDMEMBER": true,
	"XRANGE": true, "XREVRANGE": true, "XLEN": true, "XINFO": true, "XPENDING": true, "SCAN": true, "DBSIZE": true,
	"INFO": true, "MEMORY": true, "OBJECT": true, "PING": true, "TIME": true, "ECHO": true, "LASTSAVE": true,
	"SLOWLOG": true, "BITCOUNT": true, "GETBIT": true, "BITPOS": true, "PFCOUNT": true, "GEOPOS": true, "GEODIST": true,
	"GEOHASH": true, "GEOSEARCH": true, "GEORADIUS_RO": true, "GEORADIUSBYMEMBER_RO": true, "RANDOMKEY": true,
	"JSON.GET": true, "JSON.MGET": true, "JSON.TYPE": true, "JSON.STRLEN": true, "JSON.ARRLEN": true, "JSON.OBJKEYS": true,
	"JSON.OBJLEN": true, "TOUCH": false, "LCS": true, "SUBSTR": true, "DUMP": false, "CLIENT": true, "CONFIG": true,
	"COMMAND": true, "LATENCY": true, "ROLE": true, "FT.SEARCH": true, "FT.INFO": true, "FT._LIST": true, "FT.AGGREGATE": true,
	"TS.GET": true, "TS.RANGE": true, "TS.REVRANGE": true, "TS.INFO": true, "TS.MRANGE": true,
}

// readSub: commands only some of whose sub-commands just read.
var readSub = map[string]map[string]bool{
	"CLIENT":  {"LIST": true, "INFO": true, "GETNAME": true, "ID": true},
	"CONFIG":  {"GET": true},
	"MEMORY":  {"USAGE": true, "STATS": true, "DOCTOR": true},
	"SLOWLOG": {"GET": true, "LEN": true},
	"LATENCY": {"LATEST": true, "HISTORY": true, "DOCTOR": true},
}

func (r *redisClient) Run(ctx context.Context, _ string, script string, o RunOptions) ([]QueryResult, error) {
	lines := redisLines(script)
	if len(lines) == 0 {
		return nil, refused("Type a command first, e.g. GET mykey.")
	}
	if len(lines) > 50 {
		return nil, refused("That's %d commands; run at most 50 at a time.", len(lines))
	}
	if !o.Change {
		for _, l := range lines {
			c := strings.ToUpper(l[0])
			if c == "KEYS" {
				return nil, refused("KEYS stops the server while it walks every key. Use SCAN 0 MATCH pattern instead, or the key browser.")
			}
			ok := redisReads[c]
			if sub, has := readSub[c]; has {
				ok = len(l) > 1 && sub[strings.ToUpper(l[1])]
			}
			if !ok {
				return nil, refused("%s may change something. Turn on Allow changes to run it.", c)
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	var out []QueryResult
	for _, l := range lines {
		start := time.Now()
		args := make([]any, len(l))
		for i, a := range l {
			args[i] = a
		}
		v, err := r.rdb.Do(ctx, args...).Result()
		if err == redis.Nil {
			v, err = nil, nil
		}
		if err != nil {
			if len(lines) > 1 {
				return out, fmt.Errorf("%s: %w", short(strings.Join(l, " ")), err)
			}
			return out, err
		}
		res := redisResult(strings.ToUpper(l[0]), l, v, o.Limit)
		res.Statement = short(strings.Join(l, " "))
		res.Ms = time.Since(start).Milliseconds()
		out = append(out, res)
	}
	return out, nil
}

func redisText(v any) *string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return text([]byte(x), "")
	case []any, map[any]any:
		b, err := json.Marshal(normalizeRedis(x))
		if err != nil {
			return ptr(fmt.Sprint(x))
		}
		return clip(string(b))
	}
	return text(v, "")
}

func normalizeRedis(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeRedis(e)
		}
		return out
	case map[any]any:
		out := map[string]any{}
		for k, e := range x {
			out[fmt.Sprint(k)] = normalizeRedis(e)
		}
		return out
	}
	return v
}

// pairs: commands whose flat answer is field, value, field, value…
func pairs(cmd string, args []string) bool {
	switch cmd {
	case "HGETALL", "CONFIG", "XINFO":
		return true
	case "ZRANGE", "ZRANGEBYSCORE", "ZREVRANGE", "ZREVRANGEBYSCORE":
		for _, a := range args {
			if strings.EqualFold(a, "WITHSCORES") {
				return true
			}
		}
	}
	return false
}

func redisResult(cmd string, args []string, v any, limit int) QueryResult {
	res := QueryResult{Columns: []ResultColumn{}, Rows: [][]*string{}}
	switch x := v.(type) {
	case []any:
		if cmd == "SCAN" || cmd == "HSCAN" || cmd == "SSCAN" || cmd == "ZSCAN" {
			if len(x) == 2 {
				res.Message = "Next cursor: " + fmt.Sprint(x[0])
				if list, ok := x[1].([]any); ok {
					x = list
					if cmd == "HSCAN" || cmd == "ZSCAN" {
						return pairRows(res, x, limit, cmd == "ZSCAN")
					}
				}
			}
		}
		if pairs(cmd, args) && len(x)%2 == 0 {
			return pairRows(res, x, limit, strings.HasPrefix(cmd, "Z"))
		}
		res.Columns = []ResultColumn{{Name: "index"}, {Name: "value"}}
		for i, e := range x {
			if i >= limit {
				res.Truncated = true
				break
			}
			res.Rows = append(res.Rows, []*string{ptr(strconv.Itoa(i + 1)), redisText(e)})
		}
	case map[any]any:
		res.Columns = []ResultColumn{{Name: "field"}, {Name: "value"}}
		for k, e := range x {
			res.Rows = append(res.Rows, []*string{ptr(fmt.Sprint(k)), redisText(e)})
		}
	case string:
		if cmd == "INFO" {
			res.Columns = []ResultColumn{{Name: "field"}, {Name: "value"}}
			for _, line := range strings.Split(x, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				k, val, _ := strings.Cut(line, ":")
				res.Rows = append(res.Rows, []*string{ptr(k), ptr(val)})
			}
			return res
		}
		res.Columns = []ResultColumn{{Name: "value"}}
		res.Rows = append(res.Rows, []*string{redisText(x)})
	default:
		res.Columns = []ResultColumn{{Name: "value"}}
		res.Rows = append(res.Rows, []*string{redisText(x)})
	}
	return res
}

func pairRows(res QueryResult, x []any, limit int, score bool) QueryResult {
	second := "value"
	first := "field"
	if score {
		first, second = "member", "score"
	}
	res.Columns = []ResultColumn{{Name: first}, {Name: second}}
	for i := 0; i+1 < len(x); i += 2 {
		if len(res.Rows) >= limit {
			res.Truncated = true
			break
		}
		res.Rows = append(res.Rows, []*string{redisText(x[i]), redisText(x[i+1])})
	}
	return res
}
