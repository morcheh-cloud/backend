package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/arvancdn"
	"github.com/morche/backend/internal/database/sqlc"
)

// ArvanCloud domains: records, DNSSEC and the CDN settings, under
// /dns-servers/{id}/zones/{zone}/cdn. Reads are plain GETs; every change
// needs the connection to allow changes (mustWrite).

type CDNAddress struct {
	IP      string `json:"ip" minLength:"1" maxLength:"64"`
	Port    *int   `json:"port,omitempty" minimum:"1" maximum:"65535" doc:"Origin port for this address; blank = the record's default"`
	Weight  *int   `json:"weight,omitempty" minimum:"0" maximum:"1000"`
	Country string `json:"country,omitempty" maxLength:"8" doc:"Two-letter code: answer this address to visitors from there"`
}

type CDNIPFilter struct {
	Count     string `json:"count" enum:"single,multi" doc:"single = one address per answer, multi = all"`
	Order     string `json:"order" enum:"none,weighted,rr" doc:"rr = round robin"`
	GeoFilter string `json:"geo_filter" enum:"none,location,country"`
}

// CDNRecordFields is a record as written. Which fields count depends on the
// type: addresses (A, AAAA); host (CNAME, ANAME, MX, NS, PTR, SRV target);
// text (TXT, SPF, DKIM); tag + value (CAA); the tlsa_* fields (TLSA).
type CDNRecordFields struct {
	Name          string       `json:"name" minLength:"1" maxLength:"250" doc:"Relative to the domain: @ for the domain itself, www, *.app…"`
	Type          string       `json:"type" enum:"A,AAAA,CNAME,ANAME,MX,NS,TXT,SRV,SPF,DKIM,PTR,TLSA,CAA"`
	TTL           int          `json:"ttl,omitempty" enum:"120,180,300,600,900,1800,3600,7200,18000,43200,86400,172800,432000" doc:"Seconds; 120 when left out. ArvanCloud sets its own while the CDN is on."`
	Cloud         bool         `json:"cloud" doc:"Through the CDN (A, AAAA, CNAME, ANAME): visitors reach ArvanCloud, which reaches the origin"`
	UpstreamHTTPS string       `json:"upstream_https,omitempty" enum:"default,auto,http,https" doc:"How the CDN reaches the origin"`
	IPFilter      *CDNIPFilter `json:"ip_filter,omitempty" required:"false"`
	Addresses     []CDNAddress `json:"addresses,omitempty" maxItems:"50"`
	Host          string       `json:"host,omitempty" maxLength:"255"`
	HostHeader    string       `json:"host_header,omitempty" enum:"source,dest" doc:"CNAME/ANAME through the CDN: send the visitor's host (source) or the target's (dest)"`
	Port          *int         `json:"port,omitempty" minimum:"0" maximum:"65535"`
	Priority      *int         `json:"priority,omitempty" minimum:"0" maximum:"9999"`
	Weight        *int         `json:"weight,omitempty" minimum:"0" maximum:"1000"`
	Text          string       `json:"text,omitempty" maxLength:"4096"`
	Tag           string       `json:"tag,omitempty" enum:"issue,issuewild,iodef"`
	Value         string       `json:"value,omitempty" maxLength:"4096"`
	TLSAUsage     string       `json:"tlsa_usage,omitempty" maxLength:"255"`
	TLSASelector  string       `json:"tlsa_selector,omitempty" maxLength:"255"`
	TLSAMatching  string       `json:"tlsa_matching_type,omitempty" maxLength:"255"`
	Certificate   string       `json:"certificate,omitempty" maxLength:"8192"`
}

// CDNRecord is a record as read.
type CDNRecord struct {
	ID string `json:"id"`
	CDNRecordFields
	Protected bool       `json:"protected" doc:"ArvanCloud keeps it; it can't be changed or removed"`
	Usage     []string   `json:"usage" doc:"What else uses it at ArvanCloud: transport-layer-proxy, certificate-issuance"`
	Editable  bool       `json:"editable"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

var cloudTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "ANAME": true}

func toCDNRecord(r arvancdn.Record) CDNRecord {
	t := strings.ToUpper(r.Type)
	out := CDNRecord{
		ID: r.ID, Protected: r.IsProtected, Usage: orEmpty(r.Usage), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		CDNRecordFields: CDNRecordFields{
			Name: r.Name, Type: t, TTL: r.TTL, Cloud: r.Cloud, UpstreamHTTPS: r.UpstreamHTTPS,
		},
	}
	if r.IPFilterMode != nil {
		out.IPFilter = &CDNIPFilter{Count: r.IPFilterMode.Count, Order: r.IPFilterMode.Order, GeoFilter: r.IPFilterMode.GeoFilter}
	}
	var v struct {
		Host         string `json:"host"`
		Location     string `json:"location"`
		Domain       string `json:"domain"`
		Target       string `json:"target"`
		HostHeader   string `json:"host_header"`
		Port         *int   `json:"port"`
		Priority     *int   `json:"priority"`
		Weight       *int   `json:"weight"`
		Text         string `json:"text"`
		Tag          string `json:"tag"`
		Value        string `json:"value"`
		Usage        string `json:"usage"`
		Selector     string `json:"selector"`
		MatchingType string `json:"matching_type"`
		Certificate  string `json:"certificate"`
	}
	known := true
	switch t {
	case "A", "AAAA":
		var addrs []CDNAddress
		if json.Unmarshal(r.Value, &addrs) != nil {
			known = false
		}
		out.Addresses = addrs
	case "CNAME", "ANAME", "MX", "NS", "PTR", "SRV", "TXT", "SPF", "DKIM", "CAA", "TLSA":
		if json.Unmarshal(r.Value, &v) != nil {
			known = false
			break
		}
		out.HostHeader, out.Port, out.Priority, out.Weight = v.HostHeader, v.Port, v.Priority, v.Weight
		switch t {
		case "CNAME", "MX", "NS":
			out.Host = v.Host
		case "ANAME":
			out.Host = v.Location
		case "PTR":
			out.Host = v.Domain
		case "SRV":
			out.Host = v.Target
		case "TXT", "SPF", "DKIM":
			out.Text = v.Text
		case "CAA":
			out.Tag, out.Value = v.Tag, v.Value
		case "TLSA":
			out.TLSAUsage, out.TLSASelector, out.TLSAMatching, out.Certificate = v.Usage, v.Selector, v.MatchingType, v.Certificate
		}
	default:
		known = false
	}
	if !known {
		out.Value = string(r.Value)
	}
	out.Editable = known && !r.IsProtected
	return out
}

func trimHost(h string) string { return strings.TrimSuffix(strings.TrimSpace(h), ".") }

// arvanRecord checks a record and builds what ArvanCloud takes. Errors name
// the body's fields.
func arvanRecord(f CDNRecordFields, prefix string) (arvancdn.Record, error) {
	t := f.Type
	name := strings.TrimSpace(f.Name)
	if name == "" {
		name = "@"
	}
	out := arvancdn.Record{Type: strings.ToLower(t), Name: name, TTL: f.TTL, UpstreamHTTPS: f.UpstreamHTTPS}
	if out.TTL == 0 {
		out.TTL = 120
	}
	if cloudTypes[t] {
		out.Cloud = f.Cloud
		if out.UpstreamHTTPS == "" {
			out.UpstreamHTTPS = "default"
		}
	} else {
		out.UpstreamHTTPS = ""
	}
	need := func(field, v, msg string) error {
		if strings.TrimSpace(v) == "" {
			return fieldError(prefix+"."+field, msg, v)
		}
		return nil
	}
	var value any
	switch t {
	case "A", "AAAA":
		if len(f.Addresses) == 0 {
			return out, fieldError(prefix+".addresses", "Add at least one address", nil)
		}
		addrs := make([]CDNAddress, 0, len(f.Addresses))
		for i, a := range f.Addresses {
			ip, err := netip.ParseAddr(strings.TrimSpace(a.IP))
			if err != nil || (t == "A") != ip.Is4() {
				kind := "an IPv4 address like 203.0.113.10"
				if t == "AAAA" {
					kind = "an IPv6 address like 2001:db8::10"
				}
				return out, fieldError(fmt.Sprintf("%s.addresses[%d].ip", prefix, i), "Enter "+kind, a.IP)
			}
			a.IP = ip.String()
			a.Country = strings.ToUpper(strings.TrimSpace(a.Country))
			addrs = append(addrs, a)
		}
		value = addrs
		if f.IPFilter != nil {
			out.IPFilterMode = &arvancdn.IPFilter{Count: f.IPFilter.Count, Order: f.IPFilter.Order, GeoFilter: f.IPFilter.GeoFilter}
		}
	case "CNAME", "ANAME":
		if err := need("host", f.Host, "Enter the target name, like app.example.net"); err != nil {
			return out, err
		}
		hh := f.HostHeader
		if hh == "" {
			hh = "source"
		}
		key := "host"
		if t == "ANAME" {
			key = "location"
		}
		v := map[string]any{key: trimHost(f.Host), "host_header": hh}
		if f.Port != nil && *f.Port > 0 {
			v["port"] = *f.Port
		}
		value = v
	case "MX":
		if err := need("host", f.Host, "Enter the mail server's name"); err != nil {
			return out, err
		}
		pr := 10
		if f.Priority != nil {
			pr = *f.Priority
		}
		value = map[string]any{"host": trimHost(f.Host), "priority": pr}
	case "NS":
		if err := need("host", f.Host, "Enter the nameserver's name"); err != nil {
			return out, err
		}
		value = map[string]any{"host": trimHost(f.Host)}
	case "PTR":
		if err := need("host", f.Host, "Enter the name it points to"); err != nil {
			return out, err
		}
		value = map[string]any{"domain": trimHost(f.Host)}
	case "SRV":
		if err := need("host", f.Host, "Enter the target name"); err != nil {
			return out, err
		}
		if f.Port == nil {
			return out, fieldError(prefix+".port", "Enter the port", nil)
		}
		v := map[string]any{"target": trimHost(f.Host), "port": *f.Port}
		if f.Priority != nil {
			v["priority"] = *f.Priority
		}
		if f.Weight != nil {
			v["weight"] = *f.Weight
		}
		value = v
	case "TXT", "SPF", "DKIM":
		if err := need("text", f.Text, "Enter the text"); err != nil {
			return out, err
		}
		value = map[string]any{"text": f.Text}
	case "CAA":
		if err := need("value", f.Value, "Enter the value, like letsencrypt.org"); err != nil {
			return out, err
		}
		tag := f.Tag
		if tag == "" {
			tag = "issue"
		}
		value = map[string]any{"tag": tag, "value": strings.TrimSpace(f.Value)}
	case "TLSA":
		for field, v := range map[string]string{"tlsa_usage": f.TLSAUsage, "tlsa_selector": f.TLSASelector, "tlsa_matching_type": f.TLSAMatching, "certificate": f.Certificate} {
			if err := need(field, v, "Fill this in"); err != nil {
				return out, err
			}
		}
		value = map[string]any{"usage": f.TLSAUsage, "selector": f.TLSASelector, "matching_type": f.TLSAMatching, "certificate": strings.TrimSpace(f.Certificate)}
	default:
		return out, fieldError(prefix+".type", "Morche can't write this type", t)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return out, internalError(err)
	}
	out.Value = raw
	return out, nil
}

type CDNRecordPath struct {
	DNSZonePath
	Record string `path:"record" minLength:"1" maxLength:"64" doc:"The record's id"`
}

type CDNRecords struct {
	Zone    DNSZone     `json:"zone"`
	Records []CDNRecord `json:"records"`
	DNSSEC  CDNDNSSEC   `json:"dnssec"`
	// Writable says whether Morche may change this domain now.
	Writable bool `json:"writable" doc:"The connection allows changes"`
}

type CDNDNSSEC struct {
	Enabled bool   `json:"enabled"`
	DS      string `json:"ds,omitempty" doc:"The DS record to give the registrar"`
	Known   bool   `json:"known" doc:"false = ArvanCloud didn't say (plan or permission)"`
}

type CDNRecordsOutput struct{ Body CDNRecords }

// cdnRequest is the start of every CDN call: an ArvanCloud connection and a
// clean domain.
func (h *dnsHandler) cdnRequest(ctx context.Context, p DNSZonePath, write bool) (sqlc.DnsServer, *arvancdn.Client, string, error) {
	s, _, err := h.withDNS(ctx, p.ID)
	if err != nil {
		return s, nil, "", err
	}
	if s.Kind != dnsKindArvan {
		return s, nil, "", huma.Error409Conflict("CDN settings are only for ArvanCloud connections")
	}
	if write {
		if err := mustWrite(s); err != nil {
			return s, nil, "", err
		}
	}
	zone, err := cleanZone(p.Zone)
	if err != nil {
		return s, nil, "", err
	}
	cl, err := h.savedArvan(s)
	if err != nil {
		return s, nil, "", internalError(err)
	}
	return s, cl, zone, nil
}

func (h *dnsHandler) cdnRecordsOf(ctx context.Context, s sqlc.DnsServer, cl *arvancdn.Client, zone string) (*CDNRecordsOutput, error) {
	d, err := cl.Domain(ctx, zone)
	if err != nil {
		return nil, arvanError(err)
	}
	raw, err := cl.Records(ctx, zone)
	if err != nil {
		return nil, arvanError(err)
	}
	out := &CDNRecordsOutput{}
	out.Body.Zone = cdnZone(d)
	out.Body.Writable = s.AllowChanges
	out.Body.Records = make([]CDNRecord, 0, len(raw))
	for _, r := range raw {
		out.Body.Records = append(out.Body.Records, toCDNRecord(r))
	}
	slices.SortStableFunc(out.Body.Records, func(a, b CDNRecord) int {
		an, bn := a.Name == "@", b.Name == "@"
		if an != bn {
			if an {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Type, b.Type)
	})
	if sec, err := cl.DNSSEC(ctx, zone); err == nil {
		out.Body.DNSSEC = CDNDNSSEC{Enabled: sec.Enabled, Known: true}
		if sec.DS != nil {
			out.Body.DNSSEC.DS = *sec.DS
		}
	}
	return out, nil
}

// Settings, typed for the spec. ArvanCloud writes some "off" values as the
// JSON false; offKeys turns them into "off" both ways.

type CDNCertificate struct {
	ID          string     `json:"id"`
	Type        string     `json:"type" doc:"acme (free, managed), certum, user (uploaded), origin"`
	Active      bool       `json:"active"`
	KeyType     string     `json:"key_type,omitempty"`
	DomainNames []string   `json:"domain_names"`
	Issuer      string     `json:"issuer"`
	IsRevoked   bool       `json:"is_revoked"`
	ExpiryDate  *time.Time `json:"expiry_date,omitempty"`
}

type CDNCertificateOrder struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	DomainNames []string   `json:"domain_names"`
	Issuer      string     `json:"issuer,omitempty"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
}

type CDNSSL struct {
	SSLStatus        bool                  `json:"ssl_status" doc:"HTTPS on the CDN"`
	AutoIssue        bool                  `json:"auto_issue" doc:"Get and renew a free certificate by itself"`
	CertificateMode  string                `json:"certificate_mode"`
	TLSVersion       string                `json:"tls_version" doc:"Lowest TLS version; blank = ArvanCloud's default"`
	HSTSStatus       bool                  `json:"hsts_status"`
	HSTSMaxAge       string                `json:"hsts_max_age"`
	HSTSSubdomain    bool                  `json:"hsts_subdomain"`
	HSTSPreload      bool                  `json:"hsts_preload"`
	HTTPSRedirect    bool                  `json:"https_redirect"`
	ReplaceHTTP      bool                  `json:"replace_http" doc:"Rewrite http:// links in pages to https://"`
	QUICStatus       bool                  `json:"quic_status" doc:"HTTP/3"`
	VerifySNI        bool                  `json:"verify_sni"`
	KeyType          string                `json:"certificate_key_type"`
	ManagedProvider  string                `json:"managed_certificate_provider"`
	Certificates     []CDNCertificate      `json:"certificates"`
	Orders           []CDNCertificateOrder `json:"orders"`
	FingerprintCheck bool                  `json:"fingerprint_status"`
}

type CDNSSLPatch struct {
	SSLStatus       *bool   `json:"ssl_status,omitempty"`
	AutoIssue       *bool   `json:"auto_issue,omitempty"`
	TLSVersion      *string `json:"tls_version,omitempty" enum:",TLSv1,TLSv1.1,TLSv1.2,TLSv1.3"`
	HSTSStatus      *bool   `json:"hsts_status,omitempty"`
	HSTSMaxAge      *string `json:"hsts_max_age,omitempty" enum:"1mo,2mo,3mo,4mo,5mo,6mo,12mo,24mo"`
	HSTSSubdomain   *bool   `json:"hsts_subdomain,omitempty"`
	HSTSPreload     *bool   `json:"hsts_preload,omitempty"`
	HTTPSRedirect   *bool   `json:"https_redirect,omitempty"`
	ReplaceHTTP     *bool   `json:"replace_http,omitempty"`
	QUICStatus      *bool   `json:"quic_status,omitempty"`
	VerifySNI       *bool   `json:"verify_sni,omitempty"`
	KeyType         *string `json:"certificate_key_type,omitempty" enum:"rsa,ec"`
	ManagedProvider *string `json:"managed_certificate_provider,omitempty" enum:"lets_encrypt,lite_ssl"`
}

type CDNCaching struct {
	DeveloperMode    bool   `json:"cache_developer_mode" doc:"Nothing is cached while it's on"`
	ConsistentUptime bool   `json:"cache_consistent_uptime" doc:"Serve the cached copy while the origin is down"`
	MaxSize          int64  `json:"cache_max_size" doc:"Largest file the CDN caches, in bytes"`
	Status           string `json:"cache_status" doc:"off, uri (the path only) or query_string (path + query)"`
	Page200          string `json:"cache_page_200" doc:"How long to keep 200 answers"`
	PageAny          string `json:"cache_page_any" doc:"How long to keep other answers"`
	Browser          string `json:"cache_browser" doc:"Cache time told to browsers; default = the origin's"`
	IgnoreSetCookie  bool   `json:"cache_ignore_sc" doc:"Cache answers even when they set a cookie"`
	Cookie           string `json:"cache_cookie" doc:"Cookie names that make separate copies"`
	Args             bool   `json:"cache_args" doc:"Only some query arguments make separate copies"`
	Arg              string `json:"cache_arg" doc:"Those arguments"`
}

type CDNCachingPatch struct {
	DeveloperMode    *bool   `json:"cache_developer_mode,omitempty"`
	ConsistentUptime *bool   `json:"cache_consistent_uptime,omitempty"`
	MaxSize          *int64  `json:"cache_max_size,omitempty" minimum:"0" maximum:"2147483648"`
	Status           *string `json:"cache_status,omitempty" enum:"off,uri,query_string"`
	Page200          *string `json:"cache_page_200,omitempty" enum:"0s,1s,2s,3s,4s,5s,6s,7s,8s,9s,10s,30s,1m,3m,5m,10m,30m,45m,1h,3h,5h,10h,12h,24h,3d,7d,10d,15d,30d"`
	PageAny          *string `json:"cache_page_any,omitempty" enum:"0s,1s,2s,3s,4s,5s,6s,7s,8s,9s,10s,30s,1m,3m,5m,10m,30m,45m,1h,3h,5h,10h,12h,24h,3d,7d,10d,15d,30d"`
	Browser          *string `json:"cache_browser,omitempty" enum:"default,0s,1s,2s,3s,4s,5s,6s,7s,8s,9s,10s,30s,1m,3m,5m,10m,30m,45m,1h,3h,5h,10h,12h,24h,3d,7d,10d,15d,30d"`
	IgnoreSetCookie  *bool   `json:"cache_ignore_sc,omitempty"`
	Cookie           *string `json:"cache_cookie,omitempty" maxLength:"500"`
	Args             *bool   `json:"cache_args,omitempty"`
	Arg              *string `json:"cache_arg,omitempty" maxLength:"500"`
}

type CDNRedirect struct {
	WWW string `json:"www_redirect" enum:"off,www,root" doc:"www = example.com → www.example.com; root = the other way"`
}

type CDNAcceleration struct {
	Status     string   `json:"status" enum:"inherit,on,off" doc:"Minify and optimise files"`
	Extensions []string `json:"extensions" doc:"Which: css, js, gif, jpeg, png"`
}

type CDNAccelerationBody struct {
	Status     string   `json:"status" enum:"inherit,on,off"`
	Extensions []string `json:"extensions" maxItems:"5" doc:"css, js, gif, jpeg, png"`
}

// fromArvan reads a settings answer into a typed shape, false → "off" for
// the given keys.
func fromArvan(raw map[string]any, out any, offKeys ...string) error {
	for _, k := range offKeys {
		if v, ok := raw[k].(bool); ok && !v {
			raw[k] = "off"
		}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// toArvan turns a patch into what ArvanCloud takes, "off" → false.
func toArvan(patch any, offKeys ...string) (map[string]any, error) {
	b, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for _, k := range offKeys {
		if m[k] == "off" {
			m[k] = false
		}
	}
	return m, nil
}

// readSetting reads one settings endpoint into out.
func readSetting(ctx context.Context, cl *arvancdn.Client, zone string, set arvancdn.Setting, out any, offKeys ...string) error {
	raw := map[string]any{}
	if err := cl.GetSetting(ctx, zone, set, &raw); err != nil {
		return arvanError(err)
	}
	if err := fromArvan(raw, out, offKeys...); err != nil {
		return huma.Error502BadGateway("ArvanCloud sent settings Morche can't read")
	}
	return nil
}

func writeSetting(ctx context.Context, cl *arvancdn.Client, zone string, set arvancdn.Setting, patch any, offKeys ...string) error {
	body, err := toArvan(patch, offKeys...)
	if err != nil {
		return internalError(err)
	}
	if len(body) == 0 {
		return nil
	}
	if err := cl.SetSetting(ctx, zone, set, body, nil); err != nil {
		return arvanError(err)
	}
	return nil
}

func readSSL(ctx context.Context, cl *arvancdn.Client, zone string) (*CDNSSL, error) {
	var raw struct {
		CDNSSL
		Certificates []CDNCertificate `json:"certificates"`
		Orders       []struct {
			CDNCertificateOrder
			Errors *struct {
				Detail string `json:"detail"`
			} `json:"errors"`
		} `json:"orders"`
	}
	if err := readSetting(ctx, cl, zone, arvancdn.SettingSSL, &raw); err != nil {
		return nil, err
	}
	out := raw.CDNSSL
	out.Certificates = raw.Certificates
	if out.Certificates == nil {
		out.Certificates = []CDNCertificate{}
	}
	out.Orders = []CDNCertificateOrder{}
	for _, o := range raw.Orders {
		ord := o.CDNCertificateOrder
		if o.Errors != nil {
			ord.Error = o.Errors.Detail
		}
		out.Orders = append(out.Orders, ord)
	}
	return &out, nil
}

// CDNReport is the traffic report for a period.
type CDNReport struct {
	Period         string           `json:"period"`
	Requests       CDNTotals        `json:"requests"`
	Traffic        CDNTotals        `json:"traffic" doc:"Bytes"`
	Times          []string         `json:"times"`
	RequestsTotal  []int64          `json:"requests_total"`
	RequestsCached []int64          `json:"requests_cached"`
	TrafficTotal   []int64          `json:"traffic_total"`
	TrafficCached  []int64          `json:"traffic_cached"`
	StatusCodes    []CDNStatusCount `json:"status_codes"`
}

type CDNTotals struct {
	Total  int64 `json:"total"`
	Cached int64 `json:"cached" doc:"Served from the CDN's cache"`
}

type CDNStatusCount struct {
	Code  string `json:"code"`
	Count int64  `json:"count"`
}

func seriesOf(c arvancdn.Chart, suffix string) []int64 {
	for _, s := range c.Series {
		if strings.HasSuffix(s.Name, suffix) {
			return s.Data
		}
	}
	return []int64{}
}

func registerDNSCDN(api huma.API, h *dnsHandler) {
	tags := []string{"DNS"}

	huma.Register(api, huma.Operation{
		OperationID: "list-cdn-records", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/cdn/records",
		Summary: "An ArvanCloud domain's records", Description: "With the domain's state and DNSSEC.", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*CDNRecordsOutput, error) {
		s, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		return h.cdnRecordsOf(ctx, s, cl, zone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "add-cdn-record", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/cdn/records",
		Summary: "Add a record to an ArvanCloud domain", Description: "Answers with the domain's records, fresh.",
		Tags: tags, DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body CDNRecordFields
	}) (*CDNRecordsOutput, error) {
		s, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		rec, err := arvanRecord(in.Body, "body")
		if err != nil {
			return nil, err
		}
		if _, err := cl.CreateRecord(ctx, zone, rec); err != nil {
			return nil, arvanError(err)
		}
		return h.cdnRecordsOf(ctx, s, cl, zone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-record", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/cdn/records/{record}",
		Summary: "Change a record of an ArvanCloud domain", Description: "Answers with the domain's records, fresh.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		CDNRecordPath
		Body CDNRecordFields
	}) (*CDNRecordsOutput, error) {
		s, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		rec, err := arvanRecord(in.Body, "body")
		if err != nil {
			return nil, err
		}
		if _, err := cl.UpdateRecord(ctx, zone, in.Record, rec); err != nil {
			return nil, arvanError(err)
		}
		return h.cdnRecordsOf(ctx, s, cl, zone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-cdn-record", Method: http.MethodDelete, Path: "/dns-servers/{id}/zones/{zone}/cdn/records/{record}",
		Summary: "Remove a record from an ArvanCloud domain", Description: "Answers with the domain's records, fresh.", Tags: tags,
	}, func(ctx context.Context, in *struct{ CDNRecordPath }) (*CDNRecordsOutput, error) {
		s, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := cl.DeleteRecord(ctx, zone, in.Record); err != nil {
			return nil, arvanError(err)
		}
		return h.cdnRecordsOf(ctx, s, cl, zone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-cdn-record-cloud", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/cdn/records/{record}/cloud",
		Summary: "Put a record through the CDN or not", Description: "Answers with the domain's records, fresh.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		CDNRecordPath
		Body struct {
			Cloud bool `json:"cloud"`
		}
	}) (*CDNRecordsOutput, error) {
		s, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if _, err := cl.SetCloud(ctx, zone, in.Record, in.Body.Cloud); err != nil {
			return nil, arvanError(err)
		}
		return h.cdnRecordsOf(ctx, s, cl, zone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-cdn-dnssec", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/cdn/dnssec",
		Summary: "Turn DNSSEC on or off for an ArvanCloud domain", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body struct {
			Enabled bool `json:"enabled"`
		}
	}) (*struct{ Body CDNDNSSEC }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		sec, err := cl.SetDNSSEC(ctx, zone, in.Body.Enabled)
		if err != nil {
			return nil, arvanError(err)
		}
		out := &struct{ Body CDNDNSSEC }{Body: CDNDNSSEC{Enabled: sec.Enabled, Known: true}}
		if sec.DS != nil {
			out.Body.DS = *sec.DS
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "export-cdn-records", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/cdn/records/export",
		Summary: "An ArvanCloud domain's records as a BIND zone file", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*struct {
		Body struct {
			Text string `json:"text"`
		}
	}, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		b, err := cl.Export(ctx, zone)
		if err != nil {
			return nil, arvanError(err)
		}
		out := &struct {
			Body struct {
				Text string `json:"text"`
			}
		}{}
		out.Body.Text = string(b)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "import-cdn-records", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/cdn/records/import",
		Summary: "Add records from a BIND zone file", Description: "Answers with the domain's records, fresh.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body struct {
			Text string `json:"text" minLength:"1" maxLength:"500000" doc:"The zone file's text"`
		}
	}) (*CDNRecordsOutput, error) {
		s, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := cl.Import(ctx, zone, []byte(in.Body.Text)); err != nil {
			return nil, arvanError(err)
		}
		return h.cdnRecordsOf(ctx, s, cl, zone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-cdn-domain", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/cdn/check",
		Summary:     "Ask ArvanCloud to look at a domain's nameservers again",
		Description: "For a pending domain: ArvanCloud checks the nameservers (full) or CNAME (partial) now. Answers with the domain.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*struct{ Body DNSZone }, error) {
		s, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		d, err := cl.Domain(ctx, zone)
		if err != nil {
			return nil, arvanError(err)
		}
		if d.Type == "partial" {
			_, err = cl.CheckCNAME(ctx, zone)
		} else {
			_, err = cl.CheckNS(ctx, zone)
		}
		// A domain that still isn't pointed answers with an error: that's its
		// state, read again below.
		_ = err
		forgetArvanDomains(s.ID)
		if d, err = cl.Domain(ctx, zone); err != nil {
			return nil, arvanError(err)
		}
		return &struct{ Body DNSZone }{Body: cdnZone(d)}, nil
	})

	// Settings

	huma.Register(api, huma.Operation{
		OperationID: "get-cdn-ssl", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/cdn/ssl",
		Summary: "An ArvanCloud domain's HTTPS settings and certificates", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*struct{ Body CDNSSL }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		ssl, err := readSSL(ctx, cl, zone)
		if err != nil {
			return nil, err
		}
		return &struct{ Body CDNSSL }{Body: *ssl}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-ssl", Method: http.MethodPatch, Path: "/dns-servers/{id}/zones/{zone}/cdn/ssl",
		Summary: "Change an ArvanCloud domain's HTTPS settings", Description: "Only the fields sent change. Answers with the settings, fresh.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body CDNSSLPatch
	}) (*struct{ Body CDNSSL }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := writeSetting(ctx, cl, zone, arvancdn.SettingSSL, in.Body); err != nil {
			return nil, err
		}
		ssl, err := readSSL(ctx, cl, zone)
		if err != nil {
			return nil, err
		}
		return &struct{ Body CDNSSL }{Body: *ssl}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "issue-cdn-certificate", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/cdn/ssl/issue",
		Summary:     "Get a free certificate for an ArvanCloud domain",
		Description: "ArvanCloud orders it (Let's Encrypt by default) and installs it on its edge. Answers with the settings; the order shows under orders until it's ready.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body struct {
			Provider string `json:"provider,omitempty" enum:"lets_encrypt,lite_ssl"`
		}
	}) (*struct{ Body CDNSSL }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := cl.IssueCertificate(ctx, zone, in.Body.Provider); err != nil {
			return nil, arvanError(err)
		}
		ssl, err := readSSL(ctx, cl, zone)
		if err != nil {
			return nil, err
		}
		return &struct{ Body CDNSSL }{Body: *ssl}, nil
	})

	cacheOff := []string{"cache_status"}
	huma.Register(api, huma.Operation{
		OperationID: "get-cdn-caching", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/cdn/caching",
		Summary: "An ArvanCloud domain's cache settings", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*struct{ Body CDNCaching }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body CDNCaching }{}
		return out, readSetting(ctx, cl, zone, arvancdn.SettingCaching, &out.Body, cacheOff...)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-caching", Method: http.MethodPatch, Path: "/dns-servers/{id}/zones/{zone}/cdn/caching",
		Summary: "Change an ArvanCloud domain's cache settings", Description: "Only the fields sent change. Answers with the settings, fresh.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body CDNCachingPatch
	}) (*struct{ Body CDNCaching }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := writeSetting(ctx, cl, zone, arvancdn.SettingCaching, in.Body, cacheOff...); err != nil {
			return nil, err
		}
		out := &struct{ Body CDNCaching }{}
		return out, readSetting(ctx, cl, zone, arvancdn.SettingCaching, &out.Body, cacheOff...)
	})

	huma.Register(api, huma.Operation{
		OperationID: "purge-cdn-cache", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/cdn/purge",
		Summary:     "Empty an ArvanCloud domain's CDN cache",
		Description: "Everything, or up to 50 addresses. The next visitors are served by the origin until the cache fills again.",
		Tags:        tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body struct {
			URLs []string `json:"urls,omitempty" maxItems:"50" doc:"Full addresses, like https://example.com/app.css. None = everything."`
		}
	}) (*struct{}, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		var urls []string
		for i, u := range in.Body.URLs {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				return nil, fieldError(fmt.Sprintf("body.urls[%d]", i), "Enter a whole address, starting with https://", u)
			}
			urls = append(urls, u)
		}
		if err := cl.Purge(ctx, zone, urls); err != nil {
			return nil, arvanError(err)
		}
		return nil, nil
	})

	redirectOff := []string{"f_redirect_to_www"}
	readRedirect := func(ctx context.Context, cl *arvancdn.Client, zone string) (*struct{ Body CDNRedirect }, error) {
		var raw struct {
			WWW string `json:"f_redirect_to_www"`
		}
		if err := readSetting(ctx, cl, zone, arvancdn.SettingRedirect, &raw, redirectOff...); err != nil {
			return nil, err
		}
		if raw.WWW == "" {
			raw.WWW = "off"
		}
		return &struct{ Body CDNRedirect }{Body: CDNRedirect{WWW: raw.WWW}}, nil
	}
	huma.Register(api, huma.Operation{
		OperationID: "get-cdn-redirect", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/cdn/redirect",
		Summary: "An ArvanCloud domain's www redirect", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*struct{ Body CDNRedirect }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		return readRedirect(ctx, cl, zone)
	})
	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-redirect", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/cdn/redirect",
		Summary: "Change an ArvanCloud domain's www redirect", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body CDNRedirect
	}) (*struct{ Body CDNRedirect }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		body := map[string]any{"f_redirect_to_www": in.Body.WWW}
		if err := writeSetting(ctx, cl, zone, arvancdn.SettingRedirect, body, redirectOff...); err != nil {
			return nil, err
		}
		return readRedirect(ctx, cl, zone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-cdn-acceleration", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/cdn/acceleration",
		Summary: "An ArvanCloud domain's file optimisation", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*struct{ Body CDNAcceleration }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body CDNAcceleration }{}
		if err := readSetting(ctx, cl, zone, arvancdn.SettingAcceleration, &out.Body); err != nil {
			return nil, err
		}
		if out.Body.Extensions == nil {
			out.Body.Extensions = []string{}
		}
		return out, nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-acceleration", Method: http.MethodPatch, Path: "/dns-servers/{id}/zones/{zone}/cdn/acceleration",
		Summary: "Change an ArvanCloud domain's file optimisation", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body CDNAccelerationBody
	}) (*struct{ Body CDNAcceleration }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		allowed := []string{"css", "js", "gif", "jpeg", "png"}
		ext := []string{}
		for _, e := range in.Body.Extensions {
			if !slices.Contains(allowed, e) {
				return nil, fieldError("body.extensions", "Pick from css, js, gif, jpeg and png", e)
			}
			if !slices.Contains(ext, e) {
				ext = append(ext, e)
			}
		}
		if err := writeSetting(ctx, cl, zone, arvancdn.SettingAcceleration, map[string]any{"status": in.Body.Status, "extensions": ext}); err != nil {
			return nil, err
		}
		out := &struct{ Body CDNAcceleration }{}
		if err := readSetting(ctx, cl, zone, arvancdn.SettingAcceleration, &out.Body); err != nil {
			return nil, err
		}
		if out.Body.Extensions == nil {
			out.Body.Extensions = []string{}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-cdn-report", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/cdn/report",
		Summary: "An ArvanCloud domain's traffic", Description: "Requests and bytes, total and served from the cache, plus status codes.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Period string `query:"period" enum:"1h,3h,6h,12h,24h,7d,30d" default:"24h"`
	}) (*struct{ Body CDNReport }, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		t, err := cl.Traffic(ctx, zone, in.Period)
		if err != nil {
			return nil, arvanError(err)
		}
		rep := CDNReport{
			Period:         in.Period,
			Requests:       CDNTotals{Total: t.Statistics.Requests.Total, Cached: t.Statistics.Requests.Saved},
			Traffic:        CDNTotals{Total: t.Statistics.Traffics.Total, Cached: t.Statistics.Traffics.Saved},
			Times:          orEmpty(t.Charts.Requests.Categories),
			RequestsTotal:  seriesOf(t.Charts.Requests, ".total"),
			RequestsCached: seriesOf(t.Charts.Requests, ".saved"),
			TrafficTotal:   seriesOf(t.Charts.Traffics, ".total"),
			TrafficCached:  seriesOf(t.Charts.Traffics, ".saved"),
			StatusCodes:    []CDNStatusCount{},
		}
		// Status codes are a nicety: a plan without them still shows traffic.
		if codes, err := cl.StatusSummary(ctx, zone, in.Period); err == nil {
			for _, c := range codes {
				rep.StatusCodes = append(rep.StatusCodes, CDNStatusCount{Code: c.Name, Count: c.Y})
			}
		}
		return &struct{ Body CDNReport }{Body: rep}, nil
	})
}
