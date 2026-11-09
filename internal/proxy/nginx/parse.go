package nginx

import (
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/morcheh/backend/internal/proxy"
)

var (
	streamBlockRe  = regexp.MustCompile(`(?m)^\s*stream\s*\{`)
	brotliModuleRe = regexp.MustCompile(`(?m)^\s*load_module\s+\S*brotli`)
	streamModuleRe = regexp.MustCompile(`(?m)^\s*load_module\s.*ngx_stream_module`)
	wafModuleRe    = regexp.MustCompile(`(?m)^\s*load_module\s+\S*modsecurity`)
	imageModuleRe  = regexp.MustCompile(`(?m)^\s*load_module\s+\S*image_filter`)
)

func (Driver) ParseInspect(out string) proxy.Inspection {
	in := proxy.Inspection{Files: map[string]string{}}
	streamStatic := false
	sections := splitMarked(out, sectionMark)
	for _, l := range strings.Split(sections["facts"], "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
		switch k {
		case "init":
			in.Init = v
		case "ipv6":
			in.IPv6 = true
		case "version":
			in.Installed, in.Version = true, v
		case "running":
			in.Running = true
		case "enabled":
			in.Enabled = true
		case "stream_static":
			streamStatic = true
		}
	}
	if !in.Installed {
		return in
	}
	test := strings.Split(strings.TrimSpace(sections["test"]), "\n")
	if code, ok := strings.CutPrefix(test[len(test)-1], "exit "); ok {
		in.ConfigOK = code == "0"
		if !in.ConfigOK {
			in.ConfigError = testErrors(strings.Join(test[:len(test)-1], "\n"))
		}
	}
	dump := sections["dump"]
	in.SetUp = strings.Contains(dump, "include "+HostsDir+"/*.conf;")
	switch {
	case strings.Contains(dump, "include "+StreamsDir+"/*.conf;"):
		in.Streams = "ready"
	case streamBlockRe.MatchString(dump):
		in.Streams = "taken"
	case streamStatic || streamModuleRe.MatchString(dump):
		in.Streams = "not_wired"
	default:
		in.Streams = "no_module"
	}
	in.Geo = "off"
	if strings.Contains(dump, "geoip2 "+GeoDB) {
		in.Geo = "ready"
	}
	in.Sites = ParseSites(dump)
	if brotliModuleRe.MatchString(dump) {
		in.Brotli = true
	}
	waf, wafRules := wafModuleRe.MatchString(dump), false
	in.ImageFilter = imageModuleRe.MatchString(dump)
	in.StreamGeo = "off"
	if strings.Contains(dump, "# configuration file "+GeoStream+":") {
		in.StreamGeo = "ready"
	}
	for id, text := range splitMarked(sections["files"]+"\n", fileMark) {
		in.Files[id] = text
	}
	for _, l := range strings.Split(sections["released"], "\n") {
		if l = strings.TrimSpace(l); l != "" {
			in.Released = append(in.Released, l)
		}
	}
	in.Certificates = parseCerts(sections["certs"])
	for _, l := range strings.Split(sections["tls"], "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
		switch k {
		case "http3":
			in.HTTP3 = true
		case "auth_request":
			in.AuthRequest = true
		case "brotli":
			in.Brotli = true
		case "modsecurity":
			waf = true
		case "waf_rules":
			wafRules = true
		case "image_filter":
			in.ImageFilter = true
		case "cabundle":
			in.CABundle = v
		case "certbot":
			in.Certbot = v
			if v == "" {
				in.Certbot = "installed"
			}
		}
	}
	in.WAF = waf && wafRules
	return in
}

// splitMarked cuts output at lines like "<mark>name@@"; each part loses the
// newline the script put before the next marker.
func splitMarked(out, mark string) map[string]string {
	parts := map[string]string{}
	name := ""
	var cur strings.Builder
	flush := func() {
		if name != "" {
			parts[name] = strings.TrimSuffix(cur.String(), "\n")
		}
		cur.Reset()
	}
	for _, l := range strings.SplitAfter(out, "\n") {
		t := strings.TrimRight(l, "\n")
		if strings.HasPrefix(t, mark) && strings.HasSuffix(t, "@@") {
			flush()
			name = strings.TrimSuffix(strings.TrimPrefix(t, mark), "@@")
			continue
		}
		cur.WriteString(l)
	}
	flush()
	return parts
}

// testErrors keeps nginx -t's [emerg] / [error] lines, else all of it.
func testErrors(out string) string {
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "[emerg]") || strings.Contains(l, "[error]") || strings.Contains(l, "[crit]") {
			keep = append(keep, strings.TrimSpace(l))
		}
	}
	if len(keep) == 0 {
		return strings.TrimSpace(out)
	}
	return strings.Join(keep, "\n")
}

func parseCerts(out string) []proxy.Certificate {
	var certs []proxy.Certificate
	var issuer, subject string
	finish := func() {
		if len(certs) == 0 {
			return
		}
		c := &certs[len(certs)-1]
		if issuer != "" && issuer == subject {
			c.Issuer = "Self-signed"
		} else {
			c.Issuer = orgOf(issuer)
		}
		issuer, subject = "", ""
	}
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "cert "):
			finish()
			dir := strings.TrimPrefix(t, "cert ")
			source := "morcheh"
			if !strings.HasPrefix(dir, "/") {
				dir = "/etc/letsencrypt/live/" + dir
			}
			if strings.HasPrefix(dir, "/etc/letsencrypt/") {
				source = "certbot"
			}
			certs = append(certs, proxy.Certificate{
				Name: path.Base(dir), Certificate: dir + "/fullchain.pem", Key: dir + "/privkey.pem",
				Domains: []string{}, Source: source,
			})
		case len(certs) == 0:
		case strings.HasPrefix(t, "notAfter="):
			if at, err := time.Parse("Jan _2 15:04:05 2006 MST", strings.Join(strings.Fields(strings.TrimPrefix(t, "notAfter=")), " ")); err == nil {
				certs[len(certs)-1].Expires = &at
			}
		case strings.HasPrefix(t, "issuer="):
			issuer = strings.TrimSpace(strings.TrimPrefix(t, "issuer="))
		case strings.HasPrefix(t, "subject="):
			subject = strings.TrimSpace(strings.TrimPrefix(t, "subject="))
		case strings.Contains(t, "DNS:") || strings.Contains(t, "IP Address:"):
			c := &certs[len(certs)-1]
			for _, part := range strings.Split(t, ",") {
				part = strings.TrimSpace(part)
				if d, ok := strings.CutPrefix(part, "DNS:"); ok {
					c.Domains = append(c.Domains, d)
				} else if d, ok := strings.CutPrefix(part, "IP Address:"); ok {
					c.Domains = append(c.Domains, d)
				}
			}
		}
	}
	finish()
	return certs
}

var (
	orgRe = regexp.MustCompile(`(?:^|[,/])\s*O\s*=\s*("[^"]*"|[^,/]+)`)
	cnRe  = regexp.MustCompile(`(?:^|[,/])\s*CN\s*=\s*("[^"]*"|[^,/]+)`)
)

// orgOf is an issuer's organization (or common name) out of openssl's
// one-line form, old (/C=US/O=X) or new (C = US, O = X).
func orgOf(dn string) string {
	for _, re := range []*regexp.Regexp{orgRe, cnRe} {
		if m := re.FindStringSubmatch(dn); m != nil {
			return strings.Trim(strings.TrimSpace(m[1]), `"`)
		}
	}
	return dn
}

// ---- nginx -T ----

// directive is one statement of an nginx config, with its block if it has
// one.
type directive struct {
	name     string
	args     []string
	line     int
	end      int // line of the closing brace, for blocks
	block    bool
	children []*directive
}

// ParseSites reads every server block out of nginx -T's dump.
func ParseSites(dump string) []proxy.Site {
	sites := []proxy.Site{}
	for _, f := range splitFiles(dump) {
		// Forwards sit inside stream {}: their server blocks aren't sites.
		if strings.HasPrefix(f.path, StreamsDir+"/") || f.path == StreamConf {
			continue
		}
		lines := strings.Split(f.text, "\n")
		var walk func(ds []*directive, parent string)
		walk = func(ds []*directive, parent string) {
			for _, d := range ds {
				if !d.block {
					continue
				}
				if d.name == "server" && parent != "stream" && parent != "upstream" {
					sites = append(sites, siteOf(f.path, d, lines))
					continue
				}
				walk(d.children, d.name)
			}
		}
		walk(parse(f.text), "")
	}
	return sites
}

type confFile struct{ path, text string }

func splitFiles(dump string) []confFile {
	var files []confFile
	var cur *confFile
	var b strings.Builder
	flush := func() {
		if cur != nil {
			cur.text = b.String()
			files = append(files, *cur)
		}
		b.Reset()
	}
	for _, l := range strings.SplitAfter(dump, "\n") {
		t := strings.TrimRight(l, "\n")
		if p, ok := strings.CutPrefix(t, "# configuration file "); ok && strings.HasSuffix(p, ":") {
			flush()
			cur = &confFile{path: strings.TrimSuffix(p, ":")}
			continue
		}
		if cur != nil {
			b.WriteString(l)
		}
	}
	flush()
	return files
}

func siteOf(file string, d *directive, lines []string) proxy.Site {
	s := proxy.Site{
		File: file, Line: d.line, Domains: []string{}, Listen: []string{},
		Managed: strings.HasPrefix(file, Dir+"/"),
	}
	if d.line >= 1 && d.end >= d.line && d.end <= len(lines) {
		s.Text = dedent(lines[d.line-1 : d.end])
	}
	var walk func(ds []*directive, top bool)
	walk = func(ds []*directive, top bool) {
		for _, c := range ds {
			switch c.name {
			case "server_name":
				if top {
					for _, a := range c.args {
						if a != "" && a != "_" && a != `""` {
							s.Domains = append(s.Domains, a)
						}
					}
				}
			case "listen":
				if top && len(c.args) > 0 {
					s.Listen = append(s.Listen, strings.Join(c.args, " "))
					for _, a := range c.args[1:] {
						if a == "ssl" {
							s.TLS = true
						}
					}
				}
			case "ssl_certificate":
				s.TLS = true
			case "proxy_pass":
				if s.Upstream == "" && len(c.args) > 0 {
					s.Upstream = c.args[0]
				}
			case "root":
				if top && len(c.args) > 0 {
					s.Root = c.args[0]
				}
			case "return":
				if s.Redirect == "" && len(c.args) == 2 && strings.HasPrefix(c.args[0], "30") {
					s.Redirect = c.args[1]
				}
			}
			if c.block {
				walk(c.children, false)
			}
		}
	}
	walk(d.children, true)
	return s
}

// dedent strips the block's own indent from every line.
func dedent(lines []string) string {
	indent := len(lines[0]) - len(strings.TrimLeft(lines[0], " \t"))
	out := make([]string, len(lines))
	for i, l := range lines {
		n := len(l) - len(strings.TrimLeft(l, " \t"))
		out[i] = l[min(n, indent):]
	}
	return strings.Join(out, "\n")
}

// parse is a forgiving nginx tokenizer: comments, quotes, ${var}, blocks.
// It never fails; a broken file just yields fewer directives.
func parse(text string) []*directive {
	type frame struct {
		list *[]*directive
		d    *directive
	}
	var root []*directive
	stack := []frame{{list: &root}}
	var words []string
	wordLine := 0
	line := 1
	var word strings.Builder
	inWord := false
	endWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	startWord := func() {
		if !inWord {
			inWord = true
			if len(words) == 0 {
				wordLine = line
			}
		}
	}
	rs := []rune(text)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '\n':
			endWord()
			line++
		case r == ' ' || r == '\t' || r == '\r':
			endWord()
		case r == '#' && !inWord:
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
			i--
		case r == '"' || r == '\'':
			startWord()
			q := r
			for i++; i < len(rs) && rs[i] != q; i++ {
				if rs[i] == '\\' && i+1 < len(rs) {
					i++
				}
				if rs[i] == '\n' {
					line++
				}
				word.WriteRune(rs[i])
			}
		case r == '$' && i+1 < len(rs) && rs[i+1] == '{':
			startWord()
			for ; i < len(rs) && rs[i] != '}'; i++ {
				word.WriteRune(rs[i])
			}
			if i < len(rs) {
				word.WriteRune('}')
			}
		case r == ';':
			endWord()
			if len(words) > 0 {
				top := stack[len(stack)-1]
				*top.list = append(*top.list, &directive{name: words[0], args: words[1:], line: wordLine})
			}
			words = nil
		case r == '{':
			endWord()
			d := &directive{block: true, line: line}
			if len(words) > 0 {
				d.name, d.args, d.line = words[0], words[1:], wordLine
			}
			top := stack[len(stack)-1]
			*top.list = append(*top.list, d)
			stack = append(stack, frame{list: &d.children, d: d})
			words = nil
		case r == '}':
			endWord()
			words = nil
			if len(stack) > 1 {
				stack[len(stack)-1].d.end = line
				stack = stack[:len(stack)-1]
			}
		default:
			startWord()
			word.WriteRune(r)
		}
	}
	return root
}
