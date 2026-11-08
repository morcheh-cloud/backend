// Package proxy is the kind-neutral side of Morcheh's reverse proxies: the
// model of a site (HostConfig), its validation, and the Driver interface each
// proxy kind (nginx first) implements. A driver only builds shell scripts and
// reads their output; the API runs them over SSH.
package proxy

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Host types.
const (
	TypeProxy    = "proxy"
	TypeRedirect = "redirect"
	TypeStatic   = "static"
)

// HostConfig is one site: which names it answers and what it does with them.
type HostConfig struct {
	Domains []string `json:"domains" minItems:"1" maxItems:"50" doc:"Names it answers, like example.com or *.example.com"`
	Type    string   `json:"type" enum:"proxy,redirect,static"`

	// proxy
	Upstream     string `json:"upstream,omitempty" doc:"Where requests go, like http://127.0.0.1:3000" example:"http://127.0.0.1:3000"`
	WebSockets   bool   `json:"websockets,omitempty"`
	PreserveHost bool   `json:"preserve_host,omitempty" doc:"Send the visitor's Host header on, not the upstream's"`

	// redirect
	RedirectTo   string `json:"redirect_to,omitempty" doc:"Where visitors are sent, like https://example.com"`
	RedirectCode int    `json:"redirect_code,omitempty" enum:"0,301,302,307,308" doc:"0 = 301"`
	KeepPath     bool   `json:"keep_path,omitempty" doc:"Add the requested path and query to the target"`

	// static
	Root string `json:"root,omitempty" doc:"Folder the files are served from"`
	SPA  bool   `json:"spa,omitempty" doc:"Answer unknown paths with index.html (single-page apps)"`

	TLS HostTLS `json:"tls" required:"false" doc:"Plain http only when left out"`

	MaxBodyMB      int          `json:"max_body_mb,omitempty" minimum:"0" maximum:"100000" doc:"Largest upload; 0 = the proxy's default"`
	TimeoutSeconds int          `json:"timeout_seconds,omitempty" minimum:"0" maximum:"86400" doc:"How long to wait for the upstream; 0 = the proxy's default"`
	Allow          []string     `json:"allow,omitempty" maxItems:"200" doc:"Only these addresses or ranges may visit; empty = everyone"`
	Headers        []HeaderRule `json:"headers,omitempty" maxItems:"50"`
	Paths          []PathRule   `json:"paths,omitempty" maxItems:"50" doc:"Paths sent somewhere else than the main upstream"`
	Advanced       string       `json:"advanced,omitempty" maxLength:"16384" doc:"Extra directives in the proxy's own language, added inside the site"`
}

// HostTLS serves the site over HTTPS with a certificate already on the server.
type HostTLS struct {
	Enabled     bool   `json:"enabled" required:"false"`
	Certificate string `json:"certificate,omitempty" doc:"Path of the certificate (full chain) on the server"`
	Key         string `json:"key,omitempty" doc:"Path of its private key on the server"`
	ForceHTTPS  bool   `json:"force_https,omitempty" doc:"Send plain http visitors to https"`
	HTTP2       bool   `json:"http2,omitempty"`
	HSTS        bool   `json:"hsts,omitempty" doc:"Tell browsers to only use https for a year"`
}

// HeaderRule sets a header on the way in (to the upstream) or out (to the
// visitor).
type HeaderRule struct {
	To    string `json:"to" enum:"request,response"`
	Name  string `json:"name" maxLength:"100"`
	Value string `json:"value" maxLength:"2000"`
}

// PathRule sends one path somewhere else.
type PathRule struct {
	Path       string `json:"path" maxLength:"500" doc:"Starts with /; matches it and everything under it"`
	Upstream   string `json:"upstream"`
	WebSockets bool   `json:"websockets,omitempty"`
	Advanced   string `json:"advanced,omitempty" maxLength:"4096"`
}

// Problem is one thing wrong with a field, named the way the request body
// spells it (for example "domains[1]" or "tls.key").
type Problem struct {
	Field   string
	Message string
	Value   any
}

func (p Problem) Error() string { return p.Field + ": " + p.Message }

var (
	domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	headerRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)
	// Paths and file names that need no quoting anywhere.
	pathRe = regexp.MustCompile(`^/[A-Za-z0-9._~@%+=,:/\-]*$`)
)

// Normalize tidies what people type: trims, lowercases names, drops blanks
// and duplicates, and clears fields the type doesn't use.
func Normalize(h HostConfig) HostConfig {
	var domains []string
	for _, d := range h.Domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && !slices.Contains(domains, d) {
			domains = append(domains, d)
		}
	}
	h.Domains = domains
	h.Upstream = strings.TrimSpace(h.Upstream)
	h.RedirectTo = strings.TrimSpace(h.RedirectTo)
	h.Root = strings.TrimSpace(h.Root)
	h.TLS.Certificate = strings.TrimSpace(h.TLS.Certificate)
	h.TLS.Key = strings.TrimSpace(h.TLS.Key)
	switch h.Type {
	case TypeProxy:
		h.RedirectTo, h.RedirectCode, h.KeepPath, h.Root, h.SPA = "", 0, false, "", false
	case TypeRedirect:
		h.Upstream, h.WebSockets, h.PreserveHost, h.Root, h.SPA = "", false, false, "", false
		h.Paths, h.TimeoutSeconds = nil, 0
		if h.RedirectCode == 0 {
			h.RedirectCode = 301
		}
	case TypeStatic:
		h.Upstream, h.WebSockets, h.PreserveHost = "", false, false
		h.RedirectTo, h.RedirectCode, h.KeepPath, h.TimeoutSeconds = "", 0, false, 0
	}
	if !h.TLS.Enabled {
		h.TLS = HostTLS{}
	}
	var allow []string
	for _, a := range h.Allow {
		if a = strings.TrimSpace(a); a != "" && !slices.Contains(allow, a) {
			allow = append(allow, a)
		}
	}
	h.Allow = allow
	headers := h.Headers[:0:0]
	for _, x := range h.Headers {
		x.Name, x.Value = strings.TrimSpace(x.Name), strings.TrimSpace(x.Value)
		if x.Name != "" {
			headers = append(headers, x)
		}
	}
	h.Headers = headers
	paths := h.Paths[:0:0]
	for _, p := range h.Paths {
		p.Path, p.Upstream = strings.TrimSpace(p.Path), strings.TrimSpace(p.Upstream)
		if p.Path != "" || p.Upstream != "" {
			paths = append(paths, p)
		}
	}
	h.Paths = paths
	h.Advanced = strings.TrimSpace(strings.ReplaceAll(h.Advanced, "\r\n", "\n"))
	return h
}

// Validate checks a normalized host. Every value that ends up in a config
// file is checked here, so a driver can write them without quoting tricks.
func Validate(h HostConfig) []Problem {
	var out []Problem
	add := func(field, msg string, v any) { out = append(out, Problem{field, msg, v}) }
	if len(h.Domains) == 0 {
		add("domains", "Add at least one domain.", nil)
	}
	for i, d := range h.Domains {
		if !validDomain(d) {
			add(fmt.Sprintf("domains[%d]", i), "Not a domain name (like example.com or *.example.com).", d)
		}
	}
	switch h.Type {
	case TypeProxy:
		if msg := checkUpstream(h.Upstream); msg != "" {
			add("upstream", msg, h.Upstream)
		}
	case TypeRedirect:
		if msg := checkURL(h.RedirectTo); msg != "" {
			add("redirect_to", msg, h.RedirectTo)
		}
		if !slices.Contains([]int{301, 302, 307, 308}, h.RedirectCode) {
			add("redirect_code", "Use 301, 302, 307 or 308.", h.RedirectCode)
		}
	case TypeStatic:
		if !safePath(h.Root) {
			add("root", "Use a full folder path, like /var/www/site (letters, digits and . _ - / only).", h.Root)
		}
	default:
		add("type", "Choose proxy, redirect or static.", h.Type)
	}
	if h.TLS.Enabled {
		if !safePath(h.TLS.Certificate) {
			add("tls.certificate", "Use the full path of the certificate file.", h.TLS.Certificate)
		}
		if !safePath(h.TLS.Key) {
			add("tls.key", "Use the full path of the key file.", h.TLS.Key)
		}
	}
	for i, a := range h.Allow {
		if _, err := netip.ParsePrefix(a); err != nil {
			if _, err := netip.ParseAddr(a); err != nil {
				add(fmt.Sprintf("allow[%d]", i), "Not an address or range (like 10.0.0.0/8).", a)
			}
		}
	}
	for i, x := range h.Headers {
		if x.To != "request" && x.To != "response" {
			add(fmt.Sprintf("headers[%d].to", i), "Choose request or response.", x.To)
		}
		if !headerRe.MatchString(x.Name) {
			add(fmt.Sprintf("headers[%d].name", i), "Letters, digits and - only.", x.Name)
		}
		if strings.ContainsAny(x.Value, "\"\\\n\r") {
			add(fmt.Sprintf("headers[%d].value", i), "Quotes, backslashes and line breaks aren't allowed.", x.Value)
		}
	}
	seen := map[string]bool{}
	for i, p := range h.Paths {
		f := fmt.Sprintf("paths[%d]", i)
		switch {
		case !pathRe.MatchString(p.Path):
			add(f+".path", "Start with / and use letters, digits and . _ - / only.", p.Path)
		case p.Path == "/":
			add(f+".path", "/ is the whole site: set it as the main upstream instead.", p.Path)
		case seen[p.Path]:
			add(f+".path", "This path is listed twice.", p.Path)
		}
		seen[p.Path] = true
		if msg := checkUpstream(p.Upstream); msg != "" {
			add(f+".upstream", msg, p.Upstream)
		}
		if msg := checkAdvanced(p.Advanced); msg != "" {
			add(f+".advanced", msg, nil)
		}
	}
	if msg := checkAdvanced(h.Advanced); msg != "" {
		add("advanced", msg, nil)
	}
	return out
}

func validDomain(d string) bool {
	if len(d) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return true
	}
	return domainRe.MatchString(d)
}

func safePath(p string) bool {
	return pathRe.MatchString(p) && !slices.Contains(strings.Split(p, "/"), "..")
}

func checkUpstream(s string) string {
	if s == "" {
		return "Say where requests go, like http://127.0.0.1:3000."
	}
	return checkURL(s)
}

// checkURL accepts an http(s) address with nothing a config file would need
// to quote.
func checkURL(s string) string {
	if s == "" {
		return "Enter an address."
	}
	if strings.ContainsAny(s, " \t\n\r\"'`;{}\\") {
		return "Spaces, quotes, ; { } and \\ aren't allowed."
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "Use a full address starting with http:// or https://."
	}
	if u.User != nil {
		return "Leave the user name and password out of the address."
	}
	return ""
}

// checkAdvanced keeps raw directives from closing the block they sit in.
func checkAdvanced(s string) string {
	depth := 0
	quote := rune(0)
	for i, line := range strings.Split(s, "\n") {
		for _, r := range line {
			switch {
			case quote != 0:
				if r == quote {
					quote = 0
				}
			case r == '#':
				goto next
			case r == '"' || r == '\'':
				quote = r
			case r == '{':
				depth++
			case r == '}':
				depth--
				if depth < 0 {
					return fmt.Sprintf("Line %d closes a block it didn't open.", i+1)
				}
			}
		}
	next:
	}
	if quote != 0 {
		return "A quote is never closed."
	}
	if depth != 0 {
		return "A { is never closed."
	}
	return ""
}

// Overlaps finds names used by two hosts: each result is a domain of b that a
// already answers.
func Overlaps(a, b []string) []string {
	var out []string
	for _, d := range b {
		if slices.Contains(a, d) {
			out = append(out, d)
		}
	}
	return out
}

// Capabilities says which parts of HostConfig a kind can serve, so the panel
// shows only what works.
type Capabilities struct {
	Types       []string `json:"types"`
	WebSockets  bool     `json:"websockets"`
	Headers     bool     `json:"headers"`
	Paths       bool     `json:"paths"`
	Allow       bool     `json:"allow"`
	Advanced    bool     `json:"advanced" doc:"Raw directives in the proxy's own language"`
	Language    string   `json:"language" doc:"The config language, for syntax colors"`
	ConfigLabel string   `json:"config_label" doc:"What its config is called, like nginx config"`
}

// Env is what rendering needs to know about the server.
type Env struct {
	Version string // like 1.24.0; empty = unknown
	IPv6    bool
}

// Managed is a host as the driver renders it.
type Managed struct {
	ID     string
	Config HostConfig
}

// Status is the proxy's state on its server.
type Status struct {
	Installed   bool
	Version     string
	Running     bool
	Enabled     bool // starts at boot
	SetUp       bool // the panel's sites are loaded
	ConfigOK    bool
	ConfigError string
	IPv6        bool
	Init        string
}

// Site is a server block (or the kind's equivalent) found in the live config.
type Site struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Domains  []string `json:"domains"`
	Listen   []string `json:"listen"`
	TLS      bool     `json:"tls"`
	Upstream string   `json:"upstream,omitempty"`
	Root     string   `json:"root,omitempty"`
	Redirect string   `json:"redirect,omitempty"`
	Text     string   `json:"text,omitempty"`
	Managed  bool     `json:"managed" doc:"Written by Morcheh"`
}

// Certificate is one found on the server (Let's Encrypt's live folders).
type Certificate struct {
	Name        string     `json:"name"`
	Certificate string     `json:"certificate"`
	Key         string     `json:"key"`
	Domains     []string   `json:"domains"`
	Expires     *time.Time `json:"expires,omitempty"`
}

// Inspection is everything the overview shows, read in one go.
type Inspection struct {
	Status
	Files        map[string]string // managed host id → its file on the server
	Sites        []Site
	Certificates []Certificate
}

// Driver is one proxy kind.
type Driver interface {
	Kind() string
	Label() string
	Capabilities() Capabilities
	// Validate adds the kind's own checks to Validate.
	Validate(h HostConfig) []Problem
	// Render is one host's config file.
	Render(id string, h HostConfig, env Env) string
	// InspectScript reads everything; ParseInspect reads its output.
	InspectScript() string
	ParseInspect(out string) Inspection
	// SetupScript installs the proxy with install (a package manager command)
	// when it's missing, wires it up and starts it under init.
	SetupScript(install, init string) string
	// ApplyScript replaces every managed file with files (host id → text),
	// tests the config and reloads, putting the old files back on failure.
	ApplyScript(files map[string]string) string
	// RemoveScript takes everything Morcheh wrote off the server.
	RemoveScript() string
	// ActionScript is test, reload, start, stop or restart.
	ActionScript(action, init string) (string, error)
	// LogScript prints the last lines of a host's log ("" = the proxy's own).
	LogScript(hostID, log string, lines int) string
}

// Exit codes the scripts share.
const (
	ExitNotInstalled = 5
	ExitTestFailed   = 3
	ExitReloadFailed = 4
)

var drivers = map[string]Driver{}

// Register adds a kind; drivers call it from init.
func Register(d Driver) { drivers[d.Kind()] = d }

// Get returns the driver of a kind.
func Get(kind string) (Driver, bool) {
	d, ok := drivers[kind]
	return d, ok
}

// Kinds lists every registered driver.
func Kinds() []Driver {
	out := make([]Driver, 0, len(drivers))
	for _, d := range drivers {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b Driver) int { return strings.Compare(a.Kind(), b.Kind()) })
	return out
}
