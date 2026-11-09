package proxy

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Balance spreads a proxy site's requests (or a stream's connections) over
// several servers running the same app. The main address (upstream or
// stream_to) is always the first server; Servers are the others. With no
// Servers there is no balancing and the main address is used as it is.
type Balance struct {
	Servers []UpstreamServer `json:"servers,omitempty" maxItems:"50" doc:"More servers beside the main address, as host:port; any = load balancing on"`
	// Main holds the main server's options; its address is the upstream's.
	Main   UpstreamServer `json:"main" required:"false" doc:"Options of the main server (its address comes from upstream / stream_to)"`
	Method string         `json:"method,omitempty" enum:",round_robin,least_conn,ip_hash,hash,random" doc:"How a server is picked; empty = round_robin. ip_hash is for sites only"`
	// HashKey is what hash picks by: the visitor's address, the page, a
	// cookie, a header or a query argument (sites); streams hash by address.
	HashKey    string `json:"hash_key,omitempty" enum:",ip,uri,cookie,header,arg" doc:"hash: what the server is picked by; empty = ip"`
	HashName   string `json:"hash_name,omitempty" maxLength:"64" doc:"hash: the cookie, header or argument name"`
	Consistent bool   `json:"consistent,omitempty" doc:"hash: adding or removing a server moves only a few keys (ketama)"`
	RandomTwo  bool   `json:"random_two,omitempty" doc:"random: pick two at random and send to the one with fewer connections"`
	Keepalive  int    `json:"keepalive,omitempty" minimum:"0" maximum:"1024" doc:"Idle connections kept open to the servers, per worker (sites); 0 = none"`
	// MaxFails failures within FailTimeout take a server out for FailTimeout.
	MaxFails    int `json:"max_fails,omitempty" minimum:"0" maximum:"100" doc:"Failures that take a server out for a while; 0 = 1"`
	FailTimeout int `json:"fail_timeout,omitempty" minimum:"0" maximum:"3600" doc:"Seconds the failures are counted in, and how long the server stays out; 0 = 10"`
	// Retry: a failed request is tried on the next server.
	NoRetry      bool     `json:"no_retry,omitempty" doc:"Never try another server when one fails"`
	RetryOn      []string `json:"retry_on,omitempty" maxItems:"11" doc:"When to try the next server (sites): error, timeout, invalid_header, http_500, http_502, http_503, http_504, http_403, http_404, http_429, non_idempotent; empty = error and timeout"`
	Tries        int      `json:"tries,omitempty" minimum:"0" maximum:"20" doc:"Most servers tried for one request; 0 = all of them"`
	RetryTimeout int      `json:"retry_timeout,omitempty" minimum:"0" maximum:"3600" doc:"Seconds after which no other server is tried; 0 = no limit"`
}

// UpstreamServer is one server of a balanced site.
type UpstreamServer struct {
	Address  string `json:"address,omitempty" doc:"host:port, like 10.0.0.6:3000; empty for the main server" example:"10.0.0.6:3000"`
	Weight   int    `json:"weight,omitempty" minimum:"0" maximum:"1000" doc:"Share of the traffic compared with the others; 0 = 1"`
	MaxConns int    `json:"max_conns,omitempty" minimum:"0" maximum:"100000" doc:"Most connections at once; 0 = no limit"`
	Backup   bool   `json:"backup,omitempty" doc:"Only used when the others are down (not with ip_hash, hash or random)"`
	Down     bool   `json:"down,omitempty" doc:"Taken out by hand: gets nothing"`
	Note     string `json:"note,omitempty" maxLength:"200" doc:"What it is, for people"`
}

// On says whether requests are spread over several servers.
func (b Balance) On() bool { return len(b.Servers) > 0 }

// Balancing methods.
const (
	MethodRoundRobin = "round_robin"
	MethodLeastConn  = "least_conn"
	MethodIPHash     = "ip_hash"
	MethodHash       = "hash"
	MethodRandom     = "random"
)

// RetryConditions are the cases a site can try the next server on.
var RetryConditions = []string{
	"error", "timeout", "invalid_header",
	"http_500", "http_502", "http_503", "http_504", "http_403", "http_404", "http_429",
	"non_idempotent",
}

// NoBackup says whether a method can't have backup servers.
func NoBackup(method string) bool {
	return method == MethodIPHash || method == MethodHash || method == MethodRandom
}

var (
	varNameRe    = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// MainServer is the main address as host:port, the port filled in from the
// scheme when the upstream leaves it out; empty when there is none.
func (h HostConfig) MainServer() string {
	if h.IsStream() {
		return h.StreamTo
	}
	u, err := url.Parse(h.Upstream)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func normalizeServer(s UpstreamServer) UpstreamServer {
	s.Address = strings.ToLower(strings.TrimSpace(s.Address))
	s.Note = strings.TrimSpace(s.Note)
	if s.Weight == 1 {
		s.Weight = 0
	}
	return s
}

func normalizeBalance(h HostConfig) HostConfig {
	b := h.Balance
	if h.Type != TypeProxy && h.Type != TypeStream {
		h.Balance = Balance{}
		return h
	}
	servers := b.Servers[:0:0]
	for _, s := range b.Servers {
		if s = normalizeServer(s); s.Address != "" {
			servers = append(servers, s)
		}
	}
	b.Servers = servers
	if len(servers) == 0 {
		h.Balance = Balance{}
		return h
	}
	b.Main = normalizeServer(b.Main)
	b.Main.Address = ""
	if b.Method == "" {
		b.Method = MethodRoundRobin
	}
	if b.Method != MethodHash {
		b.HashKey, b.HashName, b.Consistent = "", "", false
	} else {
		if b.HashKey == "" || h.IsStream() {
			b.HashKey = "ip"
		}
		b.HashName = strings.TrimSpace(b.HashName)
		if b.HashKey == "ip" || b.HashKey == "uri" {
			b.HashName = ""
		}
	}
	if b.Method != MethodRandom {
		b.RandomTwo = false
	}
	if h.IsStream() {
		b.Keepalive, b.RetryOn = 0, nil
	}
	if b.NoRetry {
		b.RetryOn, b.Tries, b.RetryTimeout = nil, 0, 0
	}
	var on []string
	for _, c := range b.RetryOn {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" && !slices.Contains(on, c) {
			on = append(on, c)
		}
	}
	b.RetryOn = on
	h.Balance = b
	return h
}

func validateBalance(h HostConfig, add func(field, msg string, v any)) {
	b := h.Balance
	if !b.On() {
		return
	}
	main := h.MainServer()
	active := !b.Main.Down && !b.Main.Backup
	seen := map[string]bool{main: true}
	for i, s := range b.Servers {
		f := fmt.Sprintf("balance.servers[%d]", i)
		switch msg := checkHostPort(s.Address); {
		case msg != "":
			add(f+".address", msg, s.Address)
		case s.Address == main:
			add(f+".address", "This is the main address already.", s.Address)
		case seen[s.Address]:
			add(f+".address", "This server is listed twice.", s.Address)
		}
		seen[s.Address] = true
		if s.Backup && s.Down {
			add(f+".backup", "A server that's off can't be a backup too.", true)
		}
		if s.Backup && NoBackup(b.Method) {
			add(f+".backup", "Backups only work with round robin and least connections.", true)
		}
		if strings.ContainsAny(s.Note, "\n\r") {
			add(f+".note", "Keep the note on one line.", s.Note)
		}
		if !s.Down && !s.Backup {
			active = true
		}
	}
	if b.Main.Backup && b.Main.Down {
		add("balance.main.backup", "A server that's off can't be a backup too.", true)
	}
	if b.Main.Backup && NoBackup(b.Method) {
		add("balance.main.backup", "Backups only work with round robin and least connections.", true)
	}
	if !active {
		add("balance.servers", "Keep at least one server that's on and isn't a backup.", nil)
	}
	switch b.Method {
	case MethodRoundRobin, MethodLeastConn, MethodRandom:
	case MethodIPHash:
		if h.IsStream() {
			add("balance.method", "Forwards can't use ip_hash: pick hash, which uses the address.", b.Method)
		}
	case MethodHash:
		switch b.HashKey {
		case "ip", "uri":
		case "cookie", "arg":
			if !varNameRe.MatchString(b.HashName) {
				add("balance.hash_name", "Letters, digits and _ only.", b.HashName)
			}
		case "header":
			if !headerNameRe.MatchString(b.HashName) {
				add("balance.hash_name", "Letters, digits and - only.", b.HashName)
			}
		default:
			add("balance.hash_key", "Choose ip, uri, cookie, header or arg.", b.HashKey)
		}
	default:
		add("balance.method", "Choose round_robin, least_conn, ip_hash, hash or random.", b.Method)
	}
	for i, c := range b.RetryOn {
		if !slices.Contains(RetryConditions, c) {
			add(fmt.Sprintf("balance.retry_on[%d]", i), "Not a case nginx knows.", c)
		}
	}
}
