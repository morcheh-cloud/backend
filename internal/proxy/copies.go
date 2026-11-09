package proxy

import (
	"regexp"
	"strconv"
	"strings"
)

// KeptPage is one answer the proxy keeps for a site (a cache file): the
// page's address, the copy's variant (see Cache.Varies), the app's status
// and when the copy was last fetched or confirmed.
type KeptPage struct {
	URL        string `json:"url" doc:"The page, like https://example.com/blog?page=2"`
	Host       string `json:"host"`
	Path       string `json:"path" doc:"Path and query string"`
	Variant    string `json:"variant,omitempty" doc:"Which separate copy, like mobile,android (Cache.Varies)"`
	Status     int    `json:"status,omitempty" doc:"The app's answer, like 200"`
	AgeSeconds int64  `json:"age_seconds" doc:"Since the copy was fetched from the app, or last confirmed by it"`
	Bytes      int64  `json:"bytes"`
}

// KeptPages is what KeptPagesScript reports: every copy counted, the newest
// ones listed.
type KeptPages struct {
	Total int        `json:"total"`
	Bytes int64      `json:"bytes"`
	Pages []KeptPage `json:"pages"`
}

var variantRe = regexp.MustCompile(`^([A-Za-z0-9_.,-]*)\|`)

// ParseKeptPages reads KeptPagesScript's output. The cache key has no
// separator between scheme and host (httpsexample.com/a), so domains (the
// site's) settle httpshop.com: http://shop.com, not https://hop.com.
func ParseKeptPages(out string, domains []string) (KeptPages, bool) {
	var r KeptPages
	ok := false
	now := int64(0)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		switch {
		case len(f) == 4 && f[0] == "MORCHEH_PAGES":
			n, e1 := strconv.Atoi(f[1])
			kb, e2 := strconv.ParseInt(f[2], 10, 64)
			t, e3 := strconv.ParseInt(f[3], 10, 64)
			if e1 == nil && e2 == nil && e3 == nil {
				r.Total, r.Bytes, now, ok = n, kb*1024, t, true
			}
		case len(f) == 5 && f[0] == "P" && ok:
			mtime, _ := strconv.ParseInt(f[1], 10, 64)
			size, _ := strconv.ParseInt(f[2], 10, 64)
			p := keptPage(strings.TrimPrefix(f[4], "KEY: "), domains)
			if p.Host == "" && p.Path == "" {
				continue
			}
			if st := strings.Fields(f[3]); len(st) >= 2 {
				p.Status, _ = strconv.Atoi(st[1])
			}
			p.AgeSeconds, p.Bytes = max(now-mtime, 0), size
			r.Pages = append(r.Pages, p)
		}
	}
	return r, ok
}

func keptPage(key string, domains []string) KeptPage {
	var p KeptPage
	if m := variantRe.FindStringSubmatch(key); m != nil {
		p.Variant, key = m[1], key[len(m[0]):]
	}
	pick := func(scheme string) bool {
		if !strings.HasPrefix(key, scheme) {
			return false
		}
		rest := key[len(scheme):]
		host, path, _ := strings.Cut(rest, "/")
		if i := strings.IndexByte(host, '?'); i >= 0 {
			host, path = host[:i], "?"+host[i+1:]+"/"+path
		}
		p.Host, p.Path, p.URL = host, "/"+path, scheme+"://"+host+"/"+path
		return true
	}
	known := func(scheme string) bool {
		rest := strings.ToLower(strings.TrimPrefix(key, scheme))
		host, _, _ := strings.Cut(rest, "/")
		for _, d := range domains {
			d = strings.ToLower(d)
			if host == d || (strings.HasPrefix(d, "*.") && strings.HasSuffix(host, d[1:])) {
				return true
			}
		}
		return false
	}
	switch {
	case strings.HasPrefix(key, "https") && known("https"):
		pick("https")
	case strings.HasPrefix(key, "http") && known("http"):
		pick("http")
	case pick("https"), pick("http"):
	default:
		p.Path, p.URL = key, key
	}
	return p
}
