// Package fake is an in-memory ArvanCloud CDN API 4.0 for development: a few
// domains with records, HTTPS/cache/redirect/acceleration settings and made-up
// traffic. Paths are /cdn/4.0/…; the key is the IaaS fake's.
package fake

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Key is the only API key the fake accepts (the IaaS fake's).
const Key = "fake-arvan-0000-4000-8000-000000000000"

type record struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	Name          string          `json:"name"`
	TTL           int             `json:"ttl"`
	Cloud         bool            `json:"cloud"`
	UpstreamHTTPS string          `json:"upstream_https"`
	IPFilterMode  map[string]any  `json:"ip_filter_mode"`
	IsProtected   bool            `json:"is_protected"`
	Usage         []string        `json:"usage"`
	Value         json.RawMessage `json:"value"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

type domain struct {
	ID, Name, Type, Status string
	Plan                   int
	NSKeys, CurrentNS      []string
	Restriction            []string
	Created, Updated       time.Time
	records                []*record
	ssl, caching           map[string]any
	redirect, accel        map[string]any
	dnssec                 bool
	scale                  float64
	sec                    *security
}

func (d *domain) json() map[string]any {
	out := map[string]any{
		"id": d.ID, "name": d.Name, "domain": d.Name, "type": d.Type, "status": d.Status, "plan_level": d.Plan,
		"ns_keys": d.NSKeys, "current_ns": d.CurrentNS, "restriction": d.Restriction, "dns_cloud": false,
		"created_at": d.Created, "updated_at": d.Updated,
	}
	if d.Type == "partial" {
		out["cname_target"] = d.Name + ".cdn.arvancloud.ir"
	}
	return out
}

type Fake struct {
	mu      sync.Mutex
	domains []*domain
}

func rec(t, name string, cloud bool, value any) *record {
	b, _ := json.Marshal(value)
	now := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	r := &record{ID: uuid.NewString(), Type: t, Name: name, TTL: 120, Cloud: cloud, Value: b, Usage: []string{}, CreatedAt: now, UpdatedAt: now}
	if t == "a" || t == "aaaa" || t == "cname" || t == "aname" {
		r.UpstreamHTTPS = "default"
		r.IPFilterMode = map[string]any{"count": "single", "order": "none", "geo_filter": "none"}
	}
	return r
}

func defaults() (ssl, caching, redirect, accel map[string]any) {
	ssl = map[string]any{
		"ssl_status": true, "auto_issue": true, "certificate_mode": "managed", "tls_version": "TLSv1.2",
		"hsts_status": false, "hsts_max_age": "6mo", "hsts_subdomain": false, "hsts_preload": false,
		"https_redirect": true, "replace_http": false, "quic_status": false, "verify_sni": false,
		"certificate_key_type": "ec", "managed_certificate_provider": "lets_encrypt", "fingerprint_status": false,
		"certificates": []any{}, "orders": []any{},
	}
	caching = map[string]any{
		"cache_developer_mode": false, "cache_consistent_uptime": true, "cache_max_size": 104857600,
		"cache_status": "uri", "cache_page_200": "3h", "cache_page_any": "0s", "cache_browser": "default",
		"cache_ignore_sc": false, "cache_cookie": "", "cache_args": false, "cache_arg": "",
	}
	redirect = map[string]any{"f_redirect_to_www": false}
	accel = map[string]any{"status": "off", "extensions": []string{}}
	return
}

func New() *Fake {
	t := time.Date(2026, 6, 10, 9, 0, 0, 0, time.UTC)
	mk := func(name, typ, status string, plan int, scale float64, recs ...*record) *domain {
		ssl, caching, redirect, accel := defaults()
		d := &domain{
			ID: uuid.NewString(), Name: name, Type: typ, Status: status, Plan: plan,
			NSKeys: []string{"c.ns.arvancdn.ir", "f.ns.arvancdn.ir"}, CurrentNS: []string{"c.ns.arvancdn.ir", "f.ns.arvancdn.ir"},
			Restriction: []string{}, Created: t, Updated: t, records: recs,
			ssl: ssl, caching: caching, redirect: redirect, accel: accel, scale: scale,
		}
		if status != "active" {
			d.CurrentNS = []string{"ns1.registrar.example", "ns2.registrar.example"}
		}
		if status == "active" && typ == "full" {
			d.ssl["certificates"] = []any{map[string]any{
				"id": uuid.NewString(), "type": "acme", "active": true, "key_type": "ec",
				"domain_names": []string{name, "*." + name}, "issuer": "Let's Encrypt", "is_revoked": false,
				"expiry_date": time.Now().Add(61 * 24 * time.Hour).UTC().Truncate(time.Hour),
			}}
		}
		return d
	}
	ns := rec("ns", "@", false, map[string]any{"host": "c.ns.arvancdn.ir"})
	ns.IsProtected = true
	ns2 := rec("ns", "@", false, map[string]any{"host": "f.ns.arvancdn.ir"})
	ns2.IsProtected = true
	shop := mk("shop.morche.test", "full", "active", 2, 1,
		ns, ns2,
		rec("a", "@", true, []map[string]any{{"ip": "185.206.92.11"}}),
		rec("a", "www", true, []map[string]any{{"ip": "185.206.92.11"}}),
		rec("a", "api", true, []map[string]any{{"ip": "185.206.92.11", "weight": 100}, {"ip": "185.206.92.12", "weight": 100}}),
		rec("cname", "static", true, map[string]any{"host": "shop-assets.s3.ir-thr-at1.arvanstorage.ir", "host_header": "dest"}),
		rec("a", "panel", false, []map[string]any{{"ip": "185.206.93.40"}}),
		rec("mx", "@", false, map[string]any{"host": "mail.shop.morche.test", "priority": 10}),
		rec("txt", "@", false, map[string]any{"text": "v=spf1 mx -all"}),
		rec("caa", "@", false, map[string]any{"tag": "issue", "value": "letsencrypt.org"}),
	)
	shop.redirect["f_redirect_to_www"] = "www"
	shop.accel = map[string]any{"status": "on", "extensions": []string{"css", "js"}}
	blog := mk("blog.morche.test", "full", "pending", 1, 0,
		rec("a", "@", false, []map[string]any{{"ip": "37.32.10.5"}}),
		rec("cname", "www", false, map[string]any{"host": "blog.morche.test", "host_header": "source"}),
	)
	blog.ssl["ssl_status"] = false
	partner := mk("partner.example.com", "partial", "active", 1, 0.2,
		rec("cname", "cdn", true, map[string]any{"host": "origin.partner.example.com", "host_header": "source"}),
	)
	return &Fake{domains: []*domain{shop, blog, partner}}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"message": msg})
}

func invalid(w http.ResponseWriter, field, msg string) {
	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"message": "The given data was invalid.", "errors": map[string][]string{field: {msg}}})
}

func (f *Fake) find(name string) *domain {
	for _, d := range f.domains {
		if strings.EqualFold(d.Name, name) {
			return d
		}
	}
	return nil
}

func paged(r *http.Request, items []any) map[string]any {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if per < 1 {
		per = 25
	}
	last := int(math.Max(1, math.Ceil(float64(len(items))/float64(per))))
	from := (page - 1) * per
	to := min(from+per, len(items))
	if from > len(items) {
		from = len(items)
	}
	return map[string]any{
		"data": items[from:to],
		"meta": map[string]any{"current_page": page, "last_page": last, "per_page": per, "total": len(items), "from": from + 1, "to": to},
	}
}

func readBody(r *http.Request) map[string]any {
	m := map[string]any{}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = json.Unmarshal(b, &m)
	return m
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Apikey "+Key {
		fail(w, http.StatusUnauthorized, "Unauthenticated.")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/cdn/4.0/")
	if !ok {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	if parts[0] == "waf" && len(parts) == 1 && r.Method == http.MethodGet {
		serveAccountWAF(w)
		return
	}
	if parts[0] != "domains" {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			fail(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		items := []any{}
		for _, d := range f.domains {
			items = append(items, d.json())
		}
		writeJSON(w, http.StatusOK, paged(r, items))
		return
	}
	if len(parts) == 2 && parts[1] == "dns-service" && r.Method == http.MethodPost {
		b := readBody(r)
		name, _ := b["domain"].(string)
		name = strings.ToLower(strings.TrimSpace(name))
		if !strings.Contains(name, ".") {
			invalid(w, "domain", "The domain format is invalid.")
			return
		}
		if f.find(name) != nil {
			invalid(w, "domain", "The domain has already been taken.")
			return
		}
		typ, _ := b["domain_type"].(string)
		if typ != "partial" {
			typ = "full"
		}
		ssl, caching, redirect, accel := defaults()
		now := time.Now().UTC()
		d := &domain{
			ID: uuid.NewString(), Name: name, Type: typ, Status: "pending", Plan: 1,
			NSKeys: []string{"c.ns.arvancdn.ir", "f.ns.arvancdn.ir"}, CurrentNS: []string{"ns1.registrar.example", "ns2.registrar.example"},
			Restriction: []string{}, Created: now, Updated: now, ssl: ssl, caching: caching, redirect: redirect, accel: accel,
		}
		if imp, ok := b["import_dns_records"].(bool); !ok || imp {
			d.records = append(d.records, rec("a", "@", false, []map[string]any{{"ip": "203.0.113.10"}}))
		}
		f.domains = append(f.domains, d)
		writeJSON(w, http.StatusCreated, map[string]any{"message": "Domain created", "data": d.json()})
		return
	}
	d := f.find(parts[1])
	if d == nil {
		fail(w, http.StatusNotFound, "Domain not found")
		return
	}
	sub := parts[2:]
	if serveSecurity(w, r, d, sub) {
		return
	}
	path := strings.Join(sub, "/")
	switch {
	case len(sub) == 0 && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"data": d.json()})
	case len(sub) == 0 && r.Method == http.MethodDelete:
		if r.URL.Query().Get("id") != d.ID {
			invalid(w, "id", "The id doesn't match the domain.")
			return
		}
		for i, x := range f.domains {
			if x == d {
				f.domains = append(f.domains[:i], f.domains[i+1:]...)
				break
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"message": "Domain removed"})
	case path == "ns-keys/check" && r.Method == http.MethodGet:
		// Pending domains become active on the second look.
		if d.Status == "pending" && d.Name != "blog.morche.test" {
			d.Status = "active"
			d.CurrentNS = d.NSKeys
			d.Updated = time.Now().UTC()
			writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"ns_domain": d.CurrentNS, "ns_keys": d.NSKeys}})
			return
		}
		if d.Status != "active" {
			fail(w, http.StatusUnprocessableEntity, "NS records are not set yet")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"ns_domain": d.CurrentNS, "ns_keys": d.NSKeys}})
	case path == "cname-setup/check" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"data": d.json()})
	case path == "dns-records" && r.Method == http.MethodGet:
		items := []any{}
		for _, x := range d.records {
			items = append(items, x)
		}
		writeJSON(w, http.StatusOK, paged(r, items))
	case path == "dns-records" && r.Method == http.MethodPost:
		x, msg, field := f.parseRecord(r, nil)
		if msg != "" {
			invalid(w, field, msg)
			return
		}
		d.records = append(d.records, x)
		writeJSON(w, http.StatusCreated, map[string]any{"message": "Record created", "data": x})
	case path == "dns-records/export" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, bind(d))
	case path == "dns-records/import" && r.Method == http.MethodPost:
		n, err := importBind(d, r)
		if err != nil {
			invalid(w, "f_zone_file", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"message": fmt.Sprintf("%d records imported", n)})
	case path == "dns-records/dnssec" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"data": dnssec(d)})
	case path == "dns-records/dnssec/actions" && r.Method == http.MethodPut:
		b := readBody(r)
		d.dnssec, _ = b["enable"].(bool)
		writeJSON(w, http.StatusOK, map[string]any{"data": dnssec(d)})
	case len(sub) >= 2 && sub[0] == "dns-records":
		var x *record
		idx := -1
		for i, y := range d.records {
			if y.ID == sub[1] {
				x, idx = y, i
			}
		}
		if x == nil {
			fail(w, http.StatusNotFound, "Record not found")
			return
		}
		switch {
		case len(sub) == 2 && r.Method == http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]any{"data": x})
		case len(sub) == 2 && r.Method == http.MethodPut:
			if x.IsProtected {
				fail(w, http.StatusForbidden, "This record is protected")
				return
			}
			y, msg, field := f.parseRecord(r, x)
			if msg != "" {
				invalid(w, field, msg)
				return
			}
			d.records[idx] = y
			writeJSON(w, http.StatusOK, map[string]any{"message": "Record updated", "data": y})
		case len(sub) == 2 && r.Method == http.MethodDelete:
			if x.IsProtected {
				fail(w, http.StatusForbidden, "This record is protected")
				return
			}
			d.records = append(d.records[:idx], d.records[idx+1:]...)
			writeJSON(w, http.StatusOK, map[string]any{"message": "Record removed"})
		case len(sub) == 3 && sub[2] == "cloud" && r.Method == http.MethodPut:
			b := readBody(r)
			on, _ := b["cloud"].(bool)
			if on && x.Type != "a" && x.Type != "aaaa" && x.Type != "cname" && x.Type != "aname" {
				invalid(w, "cloud", "Cloud is only for A, AAAA, CNAME and ANAME records.")
				return
			}
			x.Cloud = on
			x.UpdatedAt = time.Now().UTC()
			writeJSON(w, http.StatusOK, map[string]any{"data": x})
		default:
			fail(w, http.StatusNotFound, "not found")
		}
	case setting(d, path) != nil:
		m := *setting(d, path)
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]any{"data": m})
		case http.MethodPatch, http.MethodPut:
			for k, v := range readBody(r) {
				if _, known := m[k]; !known {
					invalid(w, k, "Unknown setting.")
					return
				}
				m[k] = v
			}
			writeJSON(w, http.StatusOK, map[string]any{"message": "Settings updated", "data": m})
		default:
			fail(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case path == "ssl/issue" && r.Method == http.MethodPost:
		orders, _ := d.ssl["orders"].([]any)
		d.ssl["orders"] = append([]any{map[string]any{
			"id": uuid.NewString(), "order_id": "1001", "status": "processing", "domain_names": []string{d.Name, "*." + d.Name},
			"issuer": "Let's Encrypt", "created_at": time.Now().UTC(),
		}}, orders...)
		writeJSON(w, http.StatusOK, map[string]any{"message": "Issuance requested"})
	case path == "caching/purge" && r.Method == http.MethodPost:
		b := readBody(r)
		if b["purge"] == "individual" {
			urls, _ := b["purge_urls"].([]any)
			if len(urls) == 0 {
				invalid(w, "purge_urls", "Enter at least one address.")
				return
			}
		}
		writeJSON(w, http.StatusCreated, map[string]any{"message": "Cache purged"})
	case path == "reports/traffics" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"data": traffic(d, r.URL.Query().Get("period"))})
	case path == "reports/status/summary" && r.Method == http.MethodGet:
		s := d.scale
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"charts": map[string]any{"status_code": []any{
			map[string]any{"name": "200", "y": int(48000 * s)}, map[string]any{"name": "304", "y": int(9000 * s)},
			map[string]any{"name": "301", "y": int(2100 * s)}, map[string]any{"name": "404", "y": int(800 * s)},
			map[string]any{"name": "502", "y": int(40 * s)},
		}}}})
	default:
		fail(w, http.StatusNotFound, "not found")
	}
}

func setting(d *domain, path string) *map[string]any {
	switch path {
	case "ssl":
		return &d.ssl
	case "caching":
		return &d.caching
	case "settings/www-redirect":
		return &d.redirect
	case "acceleration":
		return &d.accel
	}
	return nil
}

func dnssec(d *domain) map[string]any {
	out := map[string]any{"enabled": d.dnssec, "ds": nil}
	if d.dnssec {
		out["ds"] = d.Name + ". 3600 IN DS 2371 13 2 1F987CC6583E92DF0890718C42A0FD8B0C3EB2D5B1B5D1C2F4A0D2A6B8C9E0F1"
	}
	return out
}

func (f *Fake) parseRecord(r *http.Request, prev *record) (*record, string, string) {
	b := readBody(r)
	t, _ := b["type"].(string)
	t = strings.ToLower(t)
	if prev != nil && t != prev.Type {
		return nil, "The type can't change.", "type"
	}
	name, _ := b["name"].(string)
	if name == "" {
		return nil, "The name field is required.", "name"
	}
	raw, _ := json.Marshal(b["value"])
	switch t {
	case "a", "aaaa":
		var addrs []map[string]any
		if json.Unmarshal(raw, &addrs) != nil || len(addrs) == 0 {
			return nil, "The value must be a list of addresses.", "value"
		}
		for i, a := range addrs {
			ip := net.ParseIP(fmt.Sprint(a["ip"]))
			if ip == nil || (t == "a") != (ip.To4() != nil) {
				return nil, "The ip is invalid.", fmt.Sprintf("value.%d.ip", i)
			}
		}
	case "cname", "mx", "ns":
		var v map[string]any
		if json.Unmarshal(raw, &v) != nil || v["host"] == nil || v["host"] == "" {
			return nil, "The host field is required.", "value.host"
		}
	case "aname", "txt", "spf", "dkim", "srv", "ptr", "caa", "tlsa":
	default:
		return nil, "The selected type is invalid.", "type"
	}
	x := rec(t, name, false, nil)
	if prev != nil {
		x.ID, x.CreatedAt = prev.ID, prev.CreatedAt
	}
	x.Value = raw
	x.UpdatedAt = time.Now().UTC()
	if ttl, ok := b["ttl"].(float64); ok {
		x.TTL = int(ttl)
	}
	x.Cloud, _ = b["cloud"].(bool)
	if u, ok := b["upstream_https"].(string); ok {
		x.UpstreamHTTPS = u
	}
	if m, ok := b["ip_filter_mode"].(map[string]any); ok {
		x.IPFilterMode = m
	}
	if x.Cloud && t != "a" && t != "aaaa" && t != "cname" && t != "aname" {
		return nil, "Cloud is only for A, AAAA, CNAME and ANAME records.", "cloud"
	}
	return x, "", ""
}

func bind(d *domain) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "$ORIGIN %s.\n$TTL 120\n", d.Name)
	for _, r := range d.records {
		var v map[string]any
		_ = json.Unmarshal(r.Value, &v)
		switch r.Type {
		case "a", "aaaa":
			var addrs []map[string]any
			_ = json.Unmarshal(r.Value, &addrs)
			for _, a := range addrs {
				fmt.Fprintf(&sb, "%s\t%d\tIN\t%s\t%v\n", r.Name, r.TTL, strings.ToUpper(r.Type), a["ip"])
			}
		case "cname", "ns":
			fmt.Fprintf(&sb, "%s\t%d\tIN\t%s\t%v.\n", r.Name, r.TTL, strings.ToUpper(r.Type), v["host"])
		case "mx":
			fmt.Fprintf(&sb, "%s\t%d\tIN\tMX\t%v %v.\n", r.Name, r.TTL, v["priority"], v["host"])
		case "txt":
			fmt.Fprintf(&sb, "%s\t%d\tIN\tTXT\t%q\n", r.Name, r.TTL, v["text"])
		case "caa":
			fmt.Fprintf(&sb, "%s\t%d\tIN\tCAA\t0 %v %q\n", r.Name, r.TTL, v["tag"], v["value"])
		}
	}
	return sb.String()
}

// importBind reads simple "name ttl IN TYPE value" lines (A, AAAA, CNAME, TXT).
func importBind(d *domain, r *http.Request) (int, error) {
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return 0, fmt.Errorf("send the file as multipart/form-data")
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	var text []byte
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		if p.FormName() == "f_zone_file" {
			text, _ = io.ReadAll(io.LimitReader(p, 1<<20))
		}
	}
	if len(text) == 0 {
		return 0, fmt.Errorf("the zone file is empty")
	}
	n := 0
	for _, line := range strings.Split(string(text), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || strings.HasPrefix(line, "$") || strings.HasPrefix(line, ";") {
			continue
		}
		name, typ, val := fields[0], strings.ToLower(fields[3]), strings.Join(fields[4:], " ")
		ttl, _ := strconv.Atoi(fields[1])
		var x *record
		switch typ {
		case "a", "aaaa":
			x = rec(typ, name, false, []map[string]any{{"ip": val}})
		case "cname":
			x = rec(typ, name, false, map[string]any{"host": strings.TrimSuffix(val, "."), "host_header": "source"})
		case "txt":
			x = rec(typ, name, false, map[string]any{"text": strings.Trim(val, `"`)})
		default:
			continue
		}
		if ttl > 0 {
			x.TTL = ttl
		}
		d.records = append(d.records, x)
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("no records could be read from the file")
	}
	return n, nil
}

func traffic(d *domain, period string) map[string]any {
	steps, every := 24, time.Hour
	switch period {
	case "1h":
		steps, every = 12, 5*time.Minute
	case "3h":
		steps, every = 18, 10*time.Minute
	case "6h":
		steps, every = 24, 15*time.Minute
	case "12h":
		steps, every = 24, 30*time.Minute
	case "7d":
		steps, every = 28, 6*time.Hour
	case "30d":
		steps, every = 30, 24*time.Hour
	}
	end := time.Now().UTC().Truncate(every)
	var times []string
	var reqT, reqS, trT, trS []int64
	var sumRT, sumRS, sumTT, sumTS int64
	for i := steps - 1; i >= 0; i-- {
		at := end.Add(-time.Duration(i) * every)
		hour := float64(at.Hour())
		wave := 0.55 + 0.45*math.Sin((hour-6)/24*2*math.Pi)
		base := d.scale * wave * float64(every/time.Minute) * 40
		rt := int64(base)
		rs := int64(base * 0.72)
		tt := rt * 52_000
		ts := rs * 61_000
		times = append(times, at.Format(time.RFC3339))
		reqT, reqS, trT, trS = append(reqT, rt), append(reqS, rs), append(trT, tt), append(trS, ts)
		sumRT, sumRS, sumTT, sumTS = sumRT+rt, sumRS+rs, sumTT+tt, sumTS+ts
	}
	sort.Strings(times)
	return map[string]any{
		"statistics": map[string]any{
			"requests": map[string]any{"total": sumRT, "saved": sumRS, "top": end},
			"traffics": map[string]any{"total": sumTT, "saved": sumTS, "top": end},
		},
		"charts": map[string]any{
			"requests": map[string]any{"categories": times, "series": []any{
				map[string]any{"name": "reports.requests.total", "data": reqT},
				map[string]any{"name": "reports.requests.saved", "data": reqS},
			}},
			"traffics": map[string]any{"categories": times, "series": []any{
				map[string]any{"name": "reports.traffics.total", "data": trT},
				map[string]any{"name": "reports.traffics.saved", "data": trS},
			}},
		},
	}
}
