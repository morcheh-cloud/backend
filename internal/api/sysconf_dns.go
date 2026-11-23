package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/sysconf"
)

const (
	resolvConf      = "/etc/resolv.conf"
	resolvedConf    = "/etc/systemd/resolved.conf"
	resolvedDropIn  = "/etc/systemd/resolved.conf.d/90-morche.conf"
	resolvedRestart = "systemctl restart systemd-resolved"
)

var dnsFiles = []string{resolvConf, resolvedConf, resolvedDropIn}

type DnsLink struct {
	Name    string   `json:"name" doc:"Global, or the interface"`
	Servers []string `json:"servers"`
	Search  []string `json:"search"`
}

type DnsOverview struct {
	Revision string    `json:"revision"`
	Manager  string    `json:"manager" enum:"resolved,networkmanager,resolvconf,static" doc:"Who writes /etc/resolv.conf"`
	Servers  []string  `json:"servers" doc:"The DNS servers Morche set (resolved) or the ones in /etc/resolv.conf (static)"`
	Search   []string  `json:"search"`
	Options  []string  `json:"options" doc:"resolv.conf options (static only)"`
	InUse    []string  `json:"in_use" doc:"The servers /etc/resolv.conf points programs at right now"`
	Links    []DnsLink `json:"links" doc:"Per interface, from resolvectl (resolved only)"`
	Editable bool      `json:"editable"`
	Note     string    `json:"note" doc:"Why it can't be edited here, or where the values come from"`
	File     string    `json:"file" doc:"The file a save writes"`
	Writable bool      `json:"writable" doc:"Morche has root or sudo here"`
}

type DnsBody struct {
	Revision string   `json:"revision"`
	Servers  []string `json:"servers" maxItems:"8"`
	Search   []string `json:"search" maxItems:"6"`
	Options  []string `json:"options,omitempty" required:"false" maxItems:"10" doc:"Static only"`
}

type DnsUpdateInput struct {
	ID   string `path:"id" format:"uuid"`
	Body DnsBody
}

// parseResolvectl joins `resolvectl dns` and `resolvectl domain`; links
// with nothing set are left out.
func parseResolvectl(dns, domains string) []DnsLink {
	var links []DnsLink
	index := map[string]int{}
	read := func(out string, servers bool) {
		for _, l := range strings.Split(out, "\n") {
			head, vals, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			name := strings.TrimSpace(head)
			if i := strings.Index(name, "("); i >= 0 {
				name = strings.Trim(name[i:], "()")
			}
			f := strings.Fields(vals)
			if len(f) == 0 {
				continue
			}
			i, ok := index[name]
			if !ok {
				links = append(links, DnsLink{Name: name, Servers: []string{}, Search: []string{}})
				i = len(links) - 1
				index[name] = i
			}
			if servers {
				links[i].Servers = f
			} else {
				links[i].Search = f
			}
		}
	}
	read(dns, true)
	read(domains, false)
	return links
}

func (h *serverHandler) dnsOverview(ctx context.Context, id string) (*DnsOverview, error) {
	o := &DnsOverview{Servers: []string{}, Search: []string{}, Options: []string{}, InUse: []string{}, Links: []DnsLink{}}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		files, rev, err := readConfigFiles(ctx, sh, dnsFiles...)
		if err != nil {
			return err
		}
		o.Revision = rev
		o.Writable = sh.priv != privUser
		link, _ := sh.run(ctx, "readlink "+resolvConf+"; true")
		nm, _ := sh.run(ctx, "systemctl is-active NetworkManager 2>/dev/null; true")
		text, _ := fileText(files, resolvConf)
		live := sysconf.ParseResolvConf(text)
		o.InUse = orEmpty(live.Servers)
		o.Manager = sysconf.ResolverManager(strings.TrimSpace(link), text, strings.TrimSpace(nm) == "active")
		switch o.Manager {
		case "resolved":
			o.Editable, o.File = true, resolvedDropIn
			if drop, ok := fileText(files, resolvedDropIn); ok {
				s, d := sysconf.ParseResolvedConf(drop)
				o.Servers, o.Search = orEmpty(s), orEmpty(d)
				o.Note = "Set by Morche for every interface, on top of what each interface brings."
			} else {
				main, _ := fileText(files, resolvedConf)
				s, d := sysconf.ParseResolvedConf(main)
				o.Servers, o.Search = orEmpty(s), orEmpty(d)
				o.Note = "Nothing set for the whole machine yet: each interface brings its own servers (below)."
			}
			dns, _ := sh.run(ctx, "resolvectl dns 2>/dev/null; true")
			dom, _ := sh.run(ctx, "resolvectl domain 2>/dev/null; true")
			o.Links = parseResolvectl(dns, dom)
		case "static":
			o.Editable, o.File = true, resolvConf
			o.Servers, o.Search, o.Options = orEmpty(live.Servers), orEmpty(live.Search), orEmpty(live.Options)
		case "networkmanager":
			o.Note = "NetworkManager writes /etc/resolv.conf: set DNS on the interface instead (Interfaces tab)."
			o.Servers, o.Search = orEmpty(live.Servers), orEmpty(live.Search)
		case "resolvconf":
			o.Note = "resolvconf writes /etc/resolv.conf from the interfaces: set DNS on the interface instead (Interfaces tab)."
			o.Servers, o.Search = orEmpty(live.Servers), orEmpty(live.Search)
		}
		return nil
	})
	return o, toProblem(err)
}

func checkDnsBody(b DnsBody) error {
	for i, s := range b.Servers {
		if !sysconf.ValidIP(s) {
			return fieldError("body.servers["+itoa(i)+"]", "Not an IP address", s)
		}
	}
	for i, s := range b.Search {
		if !sysconf.ValidHostname(s) {
			return fieldError("body.search["+itoa(i)+"]", "Not a domain", s)
		}
	}
	for i, s := range b.Options {
		if !sysconf.ValidResolvOption(s) {
			return fieldError("body.options["+itoa(i)+"]", "Not a resolv.conf option (like edns0 or timeout:2)", s)
		}
	}
	return nil
}

func dnsSummary(servers []string) string {
	if len(servers) == 0 {
		return "Clear the DNS servers"
	}
	return "DNS servers " + strings.Join(servers, ", ")
}

func registerConfigDns(api huma.API, h *serverHandler) {
	tags := []string{"Server config"}

	huma.Register(api, huma.Operation{
		OperationID: "get-server-dns",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/dns",
		Summary:     "The server's DNS resolver",
		Description: "Who manages /etc/resolv.conf, the servers and search domains set, and (with systemd-resolved) what each interface brings.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body DnsOverview }, error) {
		o, err := h.dnsOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DnsOverview }{*o}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-server-dns",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/dns",
		Summary:     "Set the DNS servers",
		Description: "With systemd-resolved: Morche's drop-in " + resolvedDropIn + " (empty = removed), then resolved restarts. " +
			"With a plain /etc/resolv.conf: that file, other lines kept. 422 when NetworkManager or resolvconf writes the file.",
		Tags: tags,
	}, func(ctx context.Context, in *DnsUpdateInput) (*struct{ Body DnsOverview }, error) {
		b := in.Body
		if err := checkDnsBody(b); err != nil {
			return nil, err
		}
		_, err := h.configChange(ctx, in.ID, b.Revision, func(sh *rootShell) (configPlan, error) {
			files, _, err := readConfigFiles(ctx, sh, dnsFiles...)
			if err != nil {
				return configPlan{}, err
			}
			link, _ := sh.run(ctx, "readlink "+resolvConf+"; true")
			nm, _ := sh.run(ctx, "systemctl is-active NetworkManager 2>/dev/null; true")
			text, _ := fileText(files, resolvConf)
			p := configPlan{Area: "dns", Summary: dnsSummary(b.Servers), Read: dnsFiles}
			switch sysconf.ResolverManager(strings.TrimSpace(link), text, strings.TrimSpace(nm) == "active") {
			case "resolved":
				w := configWrite{Path: resolvedDropIn, Text: sysconf.PrintResolvedDropIn(b.Servers, b.Search)}
				if len(b.Servers) == 0 && len(b.Search) == 0 {
					w = configWrite{Path: resolvedDropIn, Remove: true}
				}
				p.Writes = []configWrite{w}
				p.Apply, p.Undo = resolvedRestart, resolvedRestart
			case "static":
				if len(b.Servers) == 0 {
					return p, fieldError("body.servers", "Give at least one DNS server: without one the server can't look names up", b.Servers)
				}
				r := sysconf.Resolver{Servers: b.Servers, Search: b.Search, Options: b.Options}
				p.Writes = []configWrite{{Path: resolvConf, Text: sysconf.PrintResolvConf(text, r)}}
			default:
				return p, huma.Error422UnprocessableEntity("DNS on this server comes from the network settings: set it on the interface instead")
			}
			return p, nil
		})
		if err != nil {
			return nil, err
		}
		o, err := h.dnsOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DnsOverview }{*o}, nil
	})

	configRestorers["dns"] = func(ctx context.Context, _ *serverHandler, _ string, sh *rootShell, _ []ConfigChangeFile) (configPlan, error) {
		p := configPlan{Read: dnsFiles}
		link, _ := sh.run(ctx, "readlink "+resolvConf+"; true")
		if strings.Contains(link, "systemd/resolve") {
			p.Apply, p.Undo = resolvedRestart, resolvedRestart
		}
		return p, nil
	}
}
