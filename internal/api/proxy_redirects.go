package api

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/proxy"
	"github.com/morcheh/backend/internal/sshpool"
)

// Helpers for a site's redirect list: what its access log says about old
// addresses, whether targets answer, and old sitemaps for a migration.

type RedirectHit struct {
	Path   string    `json:"path" doc:"The address as asked, query included"`
	Status int       `json:"status"`
	Count  int       `json:"count"`
	Last   time.Time `json:"last"`
}

type RedirectMissing struct {
	Path    string    `json:"path" doc:"An address that answered 404 (no query)"`
	Count   int       `json:"count"`
	Last    time.Time `json:"last"`
	Referer string    `json:"referer,omitempty" doc:"The page that linked to it most often"`
}

type RedirectPage struct {
	Path  string `json:"path" doc:"A page that answered 2xx (no query)"`
	Count int    `json:"count"`
}

type ProxyRedirectStats struct {
	Range    string            `json:"range"`
	Since    time.Time         `json:"since"`
	Partial  bool              `json:"partial" doc:"The log was too big to read whole; counts are from the newest part"`
	Missing  bool              `json:"missing" doc:"The site has no access log yet"`
	Answered []RedirectHit     `json:"answered" doc:"Requests answered with 301/302/307/308/410, by address"`
	NotFound []RedirectMissing `json:"not_found" doc:"The most asked addresses that answered 404"`
	Pages    []RedirectPage    `json:"pages" doc:"The most visited pages (2xx, no files like .css or .png)"`
}

type RedirectTargetCheck struct {
	URL      string `json:"url"`
	Status   int    `json:"status" doc:"HTTP status, 0 when it didn't answer"`
	Location string `json:"location,omitempty" doc:"Where a redirect answer points"`
	Millis   int    `json:"millis"`
	Error    string `json:"error,omitempty"`
}

type RedirectSource struct {
	Status    int    `json:"status"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated" doc:"Longer than 10 MB; only the start is here"`
}

var redirectStatsRanges = map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

const (
	redirectCheckMark = "MORCHEH_RDCHECK"
	redirectFetchMax  = 10 << 20
	maxNotFound       = 300
	maxPages          = 3000
	maxAnswered       = 10000
)

// assetExt are file types left out of the page list (a sitemap lists pages).
var assetExt = []string{".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".json", ".txt", ".xml"}

func (h *proxyHandler) registerRedirectTools(api huma.API, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID: "get-proxy-host-redirect-stats", Method: http.MethodGet, Path: "/proxies/{id}/hosts/{host}/redirect-stats",
		Summary:     "What the access log says about a site's redirects",
		Description: "Redirect answers by address (to count each rule's use), the most asked addresses that answered 404 (redirect ideas) and the most visited pages.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID    string `path:"id" format:"uuid"`
		Host  string `path:"host" format:"uuid"`
		Range string `query:"range" enum:"24h,7d,30d" default:"7d"`
	}) (*struct{ Body ProxyRedirectStats }, error) {
		rng := cmp.Or(in.Range, "7d")
		r, d, _, _, err := h.siteOf(ctx, in.ID, in.Host)
		if err != nil {
			return nil, err
		}
		since := time.Now().Add(-redirectStatsRanges[rng])
		chunk, err := h.readAccess(ctx, r.Proxy, d, in.Host, proxy.LogRead{Since: since, Cap: reportCap})
		if err != nil {
			return nil, toProblem(err)
		}
		out := buildRedirectStats(d, chunk.Lines, since)
		out.Range, out.Since, out.Partial, out.Missing = rng, since, chunk.Capped, chunk.Missing
		return &struct{ Body ProxyRedirectStats }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-proxy-redirect-targets", Method: http.MethodPost, Path: "/proxies/{id}/redirects/check",
		Summary:     "Check that redirect targets answer",
		Description: "One GET per address from the proxy's server (curl, 8 s each, 10 at a time, redirects not followed). Nothing is saved.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body struct {
			URLs []string `json:"urls" minItems:"1" maxItems:"100"`
		}
	}) (*struct {
		Body struct {
			Results []RedirectTargetCheck `json:"results"`
		}
	}, error) {
		r, _, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		for i, s := range in.Body.URLs {
			if u, err := url.Parse(s); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || len(s) > 2048 {
				return nil, fieldError(fmt.Sprintf("body.urls[%d]", i), "Use a full address starting with http:// or https://.", s)
			}
		}
		var text string
		err = h.s.withConn(ctx, r.Proxy.ServerID.String(), func(c *sshpool.Conn) error {
			sh, err := h.shell(ctx, r.Proxy, c)
			if err != nil {
				return err
			}
			res, err := sh.hostExec(ctx, targetCheckScript(in.Body.URLs), 150*time.Second, 256<<10)
			if err != nil {
				return err
			}
			text = string(res.output)
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		if strings.Contains(text, redirectCheckMark+" nocurl") {
			return nil, huma.Error422UnprocessableEntity("curl isn't installed on the proxy's server, so targets can't be checked from there.")
		}
		out := &struct {
			Body struct {
				Results []RedirectTargetCheck `json:"results"`
			}
		}{}
		out.Body.Results = parseTargetChecks(text, in.Body.URLs)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "fetch-proxy-redirect-source", Method: http.MethodPost, Path: "/proxies/{id}/redirects/fetch",
		Summary:     "Download a sitemap or list for a redirect migration",
		Description: "The proxy's server downloads the address (curl, 25 s, redirects followed, .gz unpacked) and returns up to 10 MB of text.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body struct {
			URL string `json:"url" maxLength:"2048"`
		}
	}) (*struct{ Body RedirectSource }, error) {
		r, _, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		u, err := url.Parse(strings.TrimSpace(in.Body.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return nil, fieldError("body.url", "Use a full address starting with http:// or https://.", in.Body.URL)
		}
		var res *execResult
		err = h.s.withConn(ctx, r.Proxy.ServerID.String(), func(c *sshpool.Conn) error {
			sh, err := h.shell(ctx, r.Proxy, c)
			if err != nil {
				return err
			}
			res, err = sh.hostExec(ctx, fetchScript(u.String()), 40*time.Second, redirectFetchMax+4096)
			return err
		})
		if err != nil {
			return nil, toProblem(err)
		}
		head, body, _ := strings.Cut(string(res.output), "\n")
		f := strings.Fields(head)
		if len(f) < 2 || f[0] != redirectCheckMark {
			return nil, huma.Error422UnprocessableEntity("The download didn't work.")
		}
		if f[1] == "nocurl" {
			return nil, huma.Error422UnprocessableEntity("curl isn't installed on the proxy's server, so it can't download from there.")
		}
		status, _ := strconv.Atoi(f[1])
		if status == 0 {
			msg := strings.TrimSpace(strings.TrimPrefix(strings.Join(f[2:], " "), "curl: "))
			return nil, huma.Error422UnprocessableEntity(cmp.Or(msg, "No answer from that address."))
		}
		if status >= 400 {
			return nil, huma.Error422UnprocessableEntity(fmt.Sprintf("That address answered %d.", status))
		}
		out := RedirectSource{Status: status, Text: body, Truncated: res.truncated || len(body) > redirectFetchMax}
		if len(out.Text) > redirectFetchMax {
			out.Text = out.Text[:redirectFetchMax]
		}
		return &struct{ Body RedirectSource }{out}, nil
	})
}

func buildRedirectStats(d proxy.Driver, lines []string, since time.Time) ProxyRedirectStats {
	type miss struct {
		count    int
		last     time.Time
		referers map[string]int
	}
	answered := map[[2]string]*RedirectHit{}
	missing := map[string]*miss{}
	pages := map[string]int{}
	for _, l := range lines {
		e, ok := d.ParseAccess(l)
		if !ok || e.Time.Before(since) || (e.Method != "GET" && e.Method != "HEAD") {
			continue
		}
		switch {
		case slices.Contains(proxy.RedirectCodes, e.Status):
			k := [2]string{e.Path, strconv.Itoa(e.Status)}
			a := answered[k]
			if a == nil {
				if len(answered) >= maxAnswered {
					continue
				}
				a = &RedirectHit{Path: e.Path, Status: e.Status}
				answered[k] = a
			}
			a.Count++
			if e.Time.After(a.Last) {
				a.Last = e.Time
			}
		case e.Status == 404:
			p, _, _ := strings.Cut(e.Path, "?")
			m := missing[p]
			if m == nil {
				m = &miss{referers: map[string]int{}}
				missing[p] = m
			}
			m.count++
			if e.Time.After(m.last) {
				m.last = e.Time
			}
			if e.Referer != "" && e.Referer != "-" {
				m.referers[e.Referer]++
			}
		case e.Status >= 200 && e.Status < 300 || e.Status == 304:
			p, _, _ := strings.Cut(e.Path, "?")
			low := strings.ToLower(p)
			if slices.ContainsFunc(assetExt, func(x string) bool { return strings.HasSuffix(low, x) }) {
				continue
			}
			pages[p]++
		}
	}
	out := ProxyRedirectStats{Answered: []RedirectHit{}, NotFound: []RedirectMissing{}, Pages: []RedirectPage{}}
	for _, a := range answered {
		out.Answered = append(out.Answered, *a)
	}
	for p, m := range missing {
		x := RedirectMissing{Path: p, Count: m.count, Last: m.last}
		best := 0
		for r, n := range m.referers {
			if n > best || n == best && r < x.Referer {
				x.Referer, best = r, n
			}
		}
		out.NotFound = append(out.NotFound, x)
	}
	slices.SortFunc(out.NotFound, func(a, b RedirectMissing) int {
		return cmp.Or(b.Count-a.Count, strings.Compare(a.Path, b.Path))
	})
	if len(out.NotFound) > maxNotFound {
		out.NotFound = out.NotFound[:maxNotFound]
	}
	for p, n := range pages {
		out.Pages = append(out.Pages, RedirectPage{Path: p, Count: n})
	}
	slices.SortFunc(out.Pages, func(a, b RedirectPage) int {
		return cmp.Or(b.Count-a.Count, strings.Compare(a.Path, b.Path))
	})
	if len(out.Pages) > maxPages {
		out.Pages = out.Pages[:maxPages]
	}
	return out
}

// targetCheckScript asks each address once, ten at a time; every answer is
// a line "MARK <index> <status> <seconds>\t<location>\t<error>".
func targetCheckScript(urls []string) string {
	var b strings.Builder
	b.WriteString("command -v curl >/dev/null 2>&1 || { echo '" + redirectCheckMark + " nocurl'; exit 0; }\n")
	b.WriteString("check() { curl -sS -o /dev/null --max-time 8 -H 'User-Agent: Morcheh redirect check' -w '" +
		redirectCheckMark + " '\"$1\"' %{http_code} %{time_total}\\t%{redirect_url}\\t%{errormsg}\\n' -- \"$2\" 2>/dev/null || true; }\n")
	for i, u := range urls {
		fmt.Fprintf(&b, "check %d %s &\n", i, quoteAll([]string{u}))
		if (i+1)%10 == 0 {
			b.WriteString("wait\n")
		}
	}
	b.WriteString("wait\n")
	return b.String()
}

func parseTargetChecks(out string, urls []string) []RedirectTargetCheck {
	res := make([]RedirectTargetCheck, len(urls))
	for i, u := range urls {
		res[i] = RedirectTargetCheck{URL: u, Error: "No answer."}
	}
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(line, redirectCheckMark+" ")
		if !ok {
			continue
		}
		parts := strings.Split(rest, "\t")
		f := strings.Fields(parts[0])
		if len(f) < 3 {
			continue
		}
		i, err := strconv.Atoi(f[0])
		if err != nil || i < 0 || i >= len(urls) {
			continue
		}
		c := RedirectTargetCheck{URL: urls[i]}
		c.Status, _ = strconv.Atoi(f[1])
		secs, _ := strconv.ParseFloat(f[2], 64)
		c.Millis = int(secs * 1000)
		if len(parts) > 1 {
			c.Location = strings.TrimSpace(parts[1])
		}
		if c.Status == 0 {
			c.Error = "No answer."
			if len(parts) > 2 && strings.TrimSpace(parts[2]) != "" && !strings.Contains(parts[2], "%{") {
				c.Error = strings.TrimSpace(parts[2])
			}
		}
		res[i] = c
	}
	return res
}

// fetchScript downloads one address; the first line is "MARK <status>
// [error]", the text follows (gzip unpacked).
func fetchScript(u string) string {
	return "command -v curl >/dev/null 2>&1 || { echo '" + redirectCheckMark + " nocurl'; exit 0; }\n" +
		"f=$(mktemp) e=$(mktemp)\ntrap 'rm -f \"$f\" \"$e\"' EXIT\n" +
		"code=$(curl -sSL --compressed --max-redirs 5 --max-time 25 --max-filesize 52428800 -H 'User-Agent: Morcheh sitemap fetch' -o \"$f\" -w '%{http_code}' -- " +
		quoteAll([]string{u}) + " 2>\"$e\")\n" +
		"echo \"" + redirectCheckMark + " ${code:-0} $(head -c 300 \"$e\" | tr '\\n' ' ')\"\n" +
		"if [ \"$(head -c 2 \"$f\" | od -An -tx1 | tr -d ' \\n')\" = 1f8b ]; then gzip -dc \"$f\" 2>/dev/null | head -c " +
		strconv.Itoa(redirectFetchMax+1) + "; else head -c " + strconv.Itoa(redirectFetchMax+1) + " \"$f\"; fi\n"
}
