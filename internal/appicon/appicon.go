// Package appicon finds a web service's icon the way a browser tab would:
// the page's <link rel="apple-touch-icon"> or <link rel="icon">, else
// /favicon.ico.
package appicon

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	xhtml "golang.org/x/net/html"
)

// MaxSize caps the page and the icon read from a service.
const MaxSize = 1 << 20

// ErrNoIcon is every failure. It carries nothing from the service (address,
// body, TLS details), so it is safe to log and to show.
var ErrNoIcon = errors.New("couldn't get an icon from the service")

type Icon struct {
	ContentType string
	Data        []byte
}

var client = &http.Client{
	Timeout: 5 * time.Second,
	// Services are mostly internal panels behind self-signed certificates;
	// an icon is public decoration, so an unverified one is acceptable.
	Transport: &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see above
	},
	Jar: nil, // never carry a cookie from the page to the icon
	CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return ErrNoIcon
		}
		if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
			return ErrNoIcon
		}
		return nil
	},
}

// Fetch loads the page at address and returns the best icon it points to.
func Fetch(ctx context.Context, address string) (*Icon, error) {
	start, err := url.Parse(address)
	if err != nil || (start.Scheme != "http" && start.Scheme != "https") {
		return nil, ErrNoIcon
	}
	start.User = nil
	res, err := get(ctx, start)
	if err != nil {
		return nil, ErrNoIcon
	}
	final := res.Request.URL
	var candidates []*url.URL
	if res.StatusCode < 300 && isHTML(res.Header.Get("Content-Type")) {
		candidates = links(io.LimitReader(res.Body, MaxSize), final)
	}
	res.Body.Close()
	candidates = append(candidates, final.ResolveReference(&url.URL{Path: "/favicon.ico"}))
	for _, u := range candidates {
		if icon, err := fetchImage(ctx, u); err == nil {
			return icon, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, ErrNoIcon
}

func get(ctx context.Context, u *url.URL) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Morcheh icon fetcher")
	return client.Do(req)
}

func fetchImage(ctx context.Context, u *url.URL) (*Icon, error) {
	res, err := get(ctx, u)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	declared, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(declared, "image/") {
		return nil, ErrNoIcon
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, MaxSize+1))
	if err != nil || len(data) > MaxSize {
		return nil, ErrNoIcon
	}
	ct, ok := Sniff(data)
	if !ok {
		return nil, ErrNoIcon
	}
	return &Icon{ContentType: ct, Data: data}, nil
}

func isHTML(contentType string) bool {
	mt, _, _ := mime.ParseMediaType(contentType)
	return mt == "text/html" || mt == "application/xhtml+xml"
}

// links returns the page's icons, apple-touch-icon first, as http(s) URLs.
func links(body io.Reader, base *url.URL) []*url.URL {
	var touch, plain []*url.URL
	z := xhtml.NewTokenizer(body)
	for {
		switch z.Next() {
		case xhtml.ErrorToken:
			return append(touch, plain...)
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			if string(name) == "body" {
				return append(touch, plain...)
			}
			if string(name) != "link" || !hasAttr {
				continue
			}
			var rel, href string
			for {
				k, v, more := z.TagAttr()
				switch string(k) {
				case "rel":
					rel = strings.ToLower(string(v))
				case "href":
					href = strings.TrimSpace(string(v))
				}
				if !more {
					break
				}
			}
			ref, err := url.Parse(href)
			if href == "" || err != nil {
				continue
			}
			u := base.ResolveReference(ref)
			if u.Scheme != "http" && u.Scheme != "https" {
				continue
			}
			u.User = nil
			for _, r := range strings.Fields(rel) {
				if r == "apple-touch-icon" || r == "apple-touch-icon-precomposed" {
					touch = append(touch, u)
					break
				}
				if r == "icon" {
					plain = append(plain, u)
					break
				}
			}
		}
	}
}

var signatures = []struct {
	prefix      string
	contentType string
}{
	{"\x89PNG\r\n\x1a\n", "image/png"},
	{"\xff\xd8\xff", "image/jpeg"},
	{"GIF87a", "image/gif"},
	{"GIF89a", "image/gif"},
	{"\x00\x00\x01\x00", "image/x-icon"},
}

// Sniff names an image from its first bytes; only the formats a logo may be
// served as are accepted.
func Sniff(data []byte) (string, bool) {
	for _, s := range signatures {
		if bytes.HasPrefix(data, []byte(s.prefix)) {
			return s.contentType, true
		}
	}
	if len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP" {
		return "image/webp", true
	}
	if isSVG(data) {
		return "image/svg+xml", true
	}
	return "", false
}

// isSVG accepts a document whose root element is <svg>, after an optional
// XML declaration, doctype and comments.
func isSVG(data []byte) bool {
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	s := strings.TrimPrefix(string(head), "\xef\xbb\xbf")
	for {
		s = strings.TrimLeft(s, " \t\r\n")
		switch {
		case strings.HasPrefix(s, "<?"):
			s = after(s, "?>")
		case strings.HasPrefix(s, "<!--"):
			s = after(s, "-->")
		case strings.HasPrefix(strings.ToLower(s), "<!doctype svg"):
			s = after(s, ">")
		default:
			return strings.HasPrefix(s, "<svg") && len(s) > 4 && strings.ContainsRune(" \t\r\n>/", rune(s[4]))
		}
	}
}

func after(s, end string) string {
	if i := strings.Index(s, end); i >= 0 {
		return s[i+len(end):]
	}
	return ""
}
