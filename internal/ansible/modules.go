package ansible

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Module is one module ansible-doc knows about.
type Module struct {
	Name        string `json:"name" doc:"Fully qualified name" example:"ansible.builtin.apt"`
	ShortName   string `json:"short_name" example:"apt"`
	Collection  string `json:"collection" example:"ansible.builtin"`
	Description string `json:"description" doc:"One line, may hold Ansible markup (C(), O(), V()…)"`
	Category    string `json:"category" doc:"packages, files, commands, system, users, network, security, source, containers, databases, cloud, flow or other"`
}

// ModuleOption is one parameter of a module.
type ModuleOption struct {
	Name        string         `json:"name"`
	Type        string         `json:"type" doc:"str, bool, int, float, path, list, dict, raw, jsonarg… (empty = str)"`
	Elements    string         `json:"elements,omitempty" doc:"Type of a list's items"`
	Required    bool           `json:"required"`
	Default     any            `json:"default,omitempty"`
	Choices     []any          `json:"choices,omitempty"`
	Aliases     []string       `json:"aliases,omitempty"`
	Description []string       `json:"description" doc:"Paragraphs, may hold Ansible markup"`
	Suboptions  []ModuleOption `json:"suboptions,omitempty" doc:"Keys of a dict (or of each item of a list of dicts)"`
}

// ModuleDoc is everything about a module the builder and the catalog show.
type ModuleDoc struct {
	Module
	Details      []string       `json:"details" doc:"Paragraphs of the long description"`
	Options      []ModuleOption `json:"options" doc:"Sorted by name"`
	Main         []string       `json:"main" doc:"Options worth showing up front besides the required ones"`
	FreeForm     bool           `json:"free_form" doc:"Takes its main argument as a bare string (command, shell, raw…)"`
	CheckMode    string         `json:"check_mode" doc:"full, partial, none or empty when unknown"`
	Examples     string         `json:"examples" doc:"YAML tasks"`
	Notes        []string       `json:"notes"`
	Requirements []string       `json:"requirements"`
	Deprecated   string         `json:"deprecated,omitempty" doc:"Why not to use it, when it's on its way out"`
}

// Catalog reads modules from ansible-doc and keeps them: they only change
// when Ansible is upgraded (a new version empties it).
type Catalog struct {
	mu      sync.Mutex
	version string
	list    []Module
	docs    map[string]*ModuleDoc
}

// docTool is ansible-doc next to the ansible-playbook in use, else on PATH.
func docTool(st Status) (string, error) {
	if st.Path != "" {
		p := filepath.Join(filepath.Dir(st.Path), "ansible-doc")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	p, err := exec.LookPath("ansible-doc")
	if err != nil {
		return "", errors.New("ansible-doc isn't installed on the Morcheh server (it comes with ansible-core)")
	}
	return p, nil
}

func runDoc(ctx context.Context, st Status, args ...string) ([]byte, error) {
	tool, err := docTool(st)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, append([]string{"-t", "module", "--json"}, args...)...)
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_DEPRECATION_WARNINGS=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return nil, fmt.Errorf("ansible-doc failed: %v %s", err, msg)
	}
	return out, nil
}

func (c *Catalog) reset(version string) {
	if c.version != version {
		c.version, c.list, c.docs = version, nil, map[string]*ModuleDoc{}
	}
}

// Modules lists every module, sorted by name.
func (c *Catalog) Modules(ctx context.Context, st Status) ([]Module, error) {
	if !st.Installed {
		return nil, errors.New(st.Problem)
	}
	c.mu.Lock()
	c.reset(st.Version)
	list := c.list
	c.mu.Unlock()
	if list != nil {
		return list, nil
	}
	out, err := runDoc(ctx, st, "--list")
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("ansible-doc's list: %w", err)
	}
	list = make([]Module, 0, len(raw))
	for name, desc := range raw {
		list = append(list, newModule(name, desc))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	c.mu.Lock()
	if c.version == st.Version {
		c.list = list
	}
	c.mu.Unlock()
	return list, nil
}

// ErrNoModule is a name ansible-doc doesn't know.
var ErrNoModule = errors.New("no such module")

var moduleNameRe = regexp.MustCompile(`^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$`)

// Doc describes one module. Short names (apt) resolve like Ansible does,
// through ansible.builtin first.
func (c *Catalog) Doc(ctx context.Context, st Status, name string) (*ModuleDoc, error) {
	if !moduleNameRe.MatchString(name) {
		return nil, ErrNoModule
	}
	list, err := c.Modules(ctx, st)
	if err != nil {
		return nil, err
	}
	var found *Module
	for i := range list {
		if list[i].Name == name {
			found = &list[i]
			break
		}
	}
	if found == nil && !strings.Contains(name, ".") {
		for i := range list {
			if list[i].Name == "ansible.builtin."+name {
				found = &list[i]
				break
			}
		}
		if found == nil {
			for i := range list {
				if list[i].ShortName == name {
					found = &list[i]
					break
				}
			}
		}
	}
	if found == nil {
		return nil, ErrNoModule
	}
	c.mu.Lock()
	d := c.docs[found.Name]
	c.mu.Unlock()
	if d != nil {
		return d, nil
	}
	out, err := runDoc(ctx, st, found.Name)
	if err != nil {
		return nil, err
	}
	d, err = parseDoc(out, *found)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.version == st.Version {
		c.docs[found.Name] = d
	}
	c.mu.Unlock()
	return d, nil
}

func newModule(name, desc string) Module {
	short, coll := name, ""
	if i := strings.LastIndex(name, "."); i >= 0 {
		short, coll = name[i+1:], name[:i]
	}
	return Module{
		Name: name, ShortName: short, Collection: coll,
		Description: strings.TrimSpace(desc), Category: categorize(coll, short),
	}
}

// ---- ansible-doc's JSON ----

type rawOption struct {
	Type        string               `json:"type"`
	Elements    string               `json:"elements"`
	Required    bool                 `json:"required"`
	Default     any                  `json:"default"`
	Choices     json.RawMessage      `json:"choices"`
	Aliases     []string             `json:"aliases"`
	Description json.RawMessage      `json:"description"`
	Suboptions  map[string]rawOption `json:"suboptions"`
}

type rawDoc struct {
	Doc struct {
		ShortDescription string               `json:"short_description"`
		Description      json.RawMessage      `json:"description"`
		Options          map[string]rawOption `json:"options"`
		Notes            json.RawMessage      `json:"notes"`
		Requirements     json.RawMessage      `json:"requirements"`
		Attributes       map[string]struct {
			Support string `json:"support"`
		} `json:"attributes"`
		Deprecated *struct {
			Why         string `json:"why"`
			Alternative string `json:"alternative"`
		} `json:"deprecated"`
	} `json:"doc"`
	Examples json.RawMessage `json:"examples"`
}

// lines reads ansible-doc's text fields: a string or a list of strings.
func lines(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return []string{}
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one = strings.TrimSpace(one); one == "" {
			return []string{}
		}
		return []string{one}
	}
	var many []any
	out := []string{}
	if json.Unmarshal(raw, &many) == nil {
		for _, m := range many {
			if s := strings.TrimSpace(fmt.Sprint(m)); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func choices(raw json.RawMessage) []any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var list []any
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	// Newer docs describe each choice: {value: description}.
	var described map[string]json.RawMessage
	if json.Unmarshal(raw, &described) == nil {
		out := make([]any, 0, len(described))
		for k := range described {
			out = append(out, k)
		}
		sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]) < fmt.Sprint(out[j]) })
		return out
	}
	return nil
}

func options(raw map[string]rawOption) []ModuleOption {
	out := make([]ModuleOption, 0, len(raw))
	for name, o := range raw {
		t := o.Type
		if t == "" {
			t = "str"
		}
		out = append(out, ModuleOption{
			Name: name, Type: t, Elements: o.Elements, Required: o.Required,
			Default: o.Default, Choices: choices(o.Choices), Aliases: o.Aliases,
			Description: lines(o.Description), Suboptions: options(o.Suboptions),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseDoc(out []byte, m Module) (*ModuleDoc, error) {
	var all map[string]rawDoc
	if err := json.Unmarshal(out, &all); err != nil {
		return nil, fmt.Errorf("ansible-doc's description of %s: %w", m.Name, err)
	}
	r, ok := all[m.Name]
	if !ok {
		return nil, ErrNoModule
	}
	d := &ModuleDoc{
		Module:       m,
		Details:      lines(r.Doc.Description),
		Options:      options(r.Doc.Options),
		Notes:        lines(r.Doc.Notes),
		Requirements: lines(r.Doc.Requirements),
	}
	if d.Options == nil {
		d.Options = []ModuleOption{}
	}
	if a, ok := r.Doc.Attributes["check_mode"]; ok {
		d.CheckMode = a.Support
	}
	if r.Doc.Deprecated != nil {
		d.Deprecated = strings.TrimSpace(r.Doc.Deprecated.Why + " " + r.Doc.Deprecated.Alternative)
		if d.Deprecated == "" {
			d.Deprecated = "Deprecated."
		}
	}
	var ex string
	if json.Unmarshal(r.Examples, &ex) == nil {
		d.Examples = strings.Trim(ex, "\n") + "\n"
	}
	if strings.TrimSpace(d.Examples) == "" {
		d.Examples = ""
	}
	for i, o := range d.Options {
		if o.Name == "free_form" {
			d.FreeForm = true
			// It's the module's bare argument, not a key: the builder
			// writes it as one, and it's required only when cmd isn't set.
			d.Options[i].Required = false
		}
	}
	have := map[string]bool{}
	for _, o := range d.Options {
		have[o.Name] = true
	}
	d.Main = []string{}
	for _, n := range featured[m.ShortName] {
		if have[n] {
			d.Main = append(d.Main, n)
		}
	}
	if len(d.Main) == 0 {
		// Unknown module: state, name and src/dest are the usual heart.
		for _, n := range []string{"name", "state", "src", "dest", "path"} {
			if have[n] {
				d.Main = append(d.Main, n)
			}
		}
	}
	return d, nil
}

// ---- Categories and the options shown up front ----

var builtinCategory = map[string]string{
	"apt": "packages", "apt_key": "packages", "apt_repository": "packages",
	"deb822_repository": "packages", "debconf": "packages", "dnf": "packages",
	"dnf5": "packages", "dpkg_selections": "packages", "package": "packages",
	"package_facts": "packages", "pip": "packages", "rpm_key": "packages",
	"yum_repository": "packages",

	"assemble": "files", "blockinfile": "files", "copy": "files", "fetch": "files",
	"file": "files", "find": "files", "lineinfile": "files", "replace": "files",
	"stat": "files", "tempfile": "files", "template": "files", "unarchive": "files",
	"slurp": "files", "get_url": "files",

	"command": "commands", "shell": "commands", "raw": "commands",
	"script": "commands", "expect": "commands",

	"cron": "system", "hostname": "system", "mount_facts": "system",
	"reboot": "system", "service": "system", "service_facts": "system",
	"systemd": "system", "systemd_service": "system", "sysvinit": "system",
	"setup": "system", "gather_facts": "system", "getent": "system",

	"user": "users", "group": "users", "known_hosts": "users",

	"uri": "network", "wait_for": "network", "wait_for_connection": "network",
	"iptables": "network",

	"git": "source", "subversion": "source",

	"assert": "flow", "async_status": "flow", "debug": "flow", "fail": "flow",
	"meta": "flow", "pause": "flow", "set_fact": "flow", "set_stats": "flow",
	"validate_argument_spec": "flow", "include_role": "flow",
	"include_tasks": "flow", "include_vars": "flow", "import_playbook": "flow",
	"import_role": "flow", "import_tasks": "flow", "add_host": "flow",
	"group_by": "flow", "ping": "flow",
}

var collectionCategory = map[string]string{
	"community.docker": "containers", "containers.podman": "containers",
	"kubernetes.core": "containers", "community.kubernetes": "containers",
	"community.mysql": "databases", "community.postgresql": "databases",
	"community.mongodb": "databases", "community.proxysql": "databases",
	"community.crypto": "security", "community.hashi_vault": "security",
	"amazon.aws": "cloud", "community.aws": "cloud", "google.cloud": "cloud",
	"azure.azcollection": "cloud", "openstack.cloud": "cloud",
	"community.digitalocean": "cloud", "hetzner.hcloud": "cloud",
	"community.vmware": "cloud", "vmware.vmware": "cloud",
	"community.libvirt": "cloud", "community.proxmox": "cloud",
	"community.zabbix": "monitoring", "community.grafana": "monitoring",
	"ansible.netcommon": "network", "ansible.utils": "flow",
	"community.rabbitmq": "databases",
}

// By words in the name, first match wins.
var nameCategory = []struct {
	words    []string
	category string
}{
	{[]string{"docker", "podman", "k8s", "helm", "lxc", "lxd", "container"}, "containers"},
	{[]string{"mysql", "postgresql", "mariadb", "mongodb", "redis", "influxdb", "mssql", "sqlite", "elasticsearch", "couchdb"}, "databases"},
	{[]string{"apt", "yum", "dnf", "pacman", "zypper", "snap", "flatpak", "npm", "gem", "pip", "homebrew", "apk", "pkg", "package", "portage", "cpanm", "composer", "yarn", "pnpm", "cargo", "opkg", "rpm"}, "packages"},
	{[]string{"user", "group", "authorized_key", "sudoers", "pam", "passwd"}, "users"},
	{[]string{"ufw", "firewalld", "iptables", "nmcli", "interfaces", "route", "dns", "nginx", "haproxy", "uri", "http", "port", "ip_"}, "network"},
	{[]string{"selinux", "seboolean", "sefcontext", "seport", "openssl", "x509", "acme", "crypto", "gpg", "ssh_", "luks", "vault"}, "security"},
	{[]string{"git", "hg", "bzr", "github", "gitlab", "subversion"}, "source"},
	{[]string{"file", "archive", "ini_", "xml", "copy", "acl", "synchronize", "patch", "line", "template", "json"}, "files"},
	{[]string{"sysctl", "mount", "timezone", "locale", "modprobe", "service", "systemd", "cron", "kernel", "swap", "lvg", "lvol", "parted", "filesystem", "hostname", "reboot", "alternatives", "facts", "launchd", "openrc", "runit", "pam_limits", "capabilities", "make"}, "system"},
	{[]string{"zabbix", "grafana", "nagios", "prometheus", "datadog", "monit", "sensu", "icinga"}, "monitoring"},
	{[]string{"aws", "ec2", "s3", "azure", "gcp", "gce", "openstack", "os_", "hcloud", "digital_ocean", "vmware", "proxmox", "libvirt", "virt"}, "cloud"},
	{[]string{"mail", "slack", "telegram", "matrix", "mattermost", "discord", "irc", "pushover", "say"}, "notify"},
}

func categorize(collection, short string) string {
	if collection == "ansible.builtin" {
		if c, ok := builtinCategory[short]; ok {
			return c
		}
	}
	if c, ok := collectionCategory[collection]; ok {
		return c
	}
	for _, n := range nameCategory {
		for _, w := range n.words {
			if strings.Contains(short, w) {
				return n.category
			}
		}
	}
	return "other"
}

// The options people reach for first, beyond the required ones.
var featured = map[string][]string{
	"apt":                 {"name", "state", "update_cache"},
	"apt_repository":      {"repo", "state", "filename"},
	"apt_key":             {"url", "state"},
	"deb822_repository":   {"name", "uris", "suites", "components", "signed_by", "state"},
	"dnf":                 {"name", "state", "update_cache"},
	"dnf5":                {"name", "state", "update_cache"},
	"package":             {"name", "state"},
	"pip":                 {"name", "state", "requirements", "virtualenv"},
	"yum_repository":      {"name", "description", "baseurl", "gpgkey", "state"},
	"rpm_key":             {"key", "state"},
	"copy":                {"src", "content", "dest", "owner", "group", "mode", "backup"},
	"template":            {"src", "dest", "owner", "group", "mode", "backup"},
	"file":                {"path", "state", "owner", "group", "mode"},
	"lineinfile":          {"path", "regexp", "line", "state", "create"},
	"blockinfile":         {"path", "block", "marker", "state", "create"},
	"replace":             {"path", "regexp", "replace"},
	"get_url":             {"url", "dest", "mode", "checksum"},
	"unarchive":           {"src", "dest", "remote_src", "creates"},
	"fetch":               {"src", "dest", "flat"},
	"find":                {"paths", "patterns", "recurse", "file_type"},
	"stat":                {"path"},
	"assemble":            {"src", "dest"},
	"tempfile":            {"state", "suffix"},
	"slurp":               {"src"},
	"command":             {"chdir", "creates"},
	"shell":               {"chdir", "creates", "executable"},
	"script":              {"chdir", "creates"},
	"expect":              {"command", "responses"},
	"cron":                {"name", "job", "minute", "hour", "day", "month", "weekday", "user", "state"},
	"service":             {"name", "state", "enabled"},
	"systemd":             {"name", "state", "enabled", "daemon_reload"},
	"systemd_service":     {"name", "state", "enabled", "daemon_reload"},
	"sysvinit":            {"name", "state", "enabled"},
	"hostname":            {"name"},
	"reboot":              {"msg", "reboot_timeout"},
	"user":                {"name", "state", "groups", "append", "shell", "password"},
	"group":               {"name", "state", "gid"},
	"known_hosts":         {"name", "key", "state"},
	"uri":                 {"url", "method", "status_code", "return_content"},
	"wait_for":            {"host", "port", "state", "timeout"},
	"wait_for_connection": {"timeout"},
	"iptables":            {"chain", "protocol", "destination_port", "jump", "source"},
	"git":                 {"repo", "dest", "version", "force"},
	"debug":               {"msg", "var"},
	"assert":              {"that", "fail_msg", "success_msg"},
	"fail":                {"msg"},
	"pause":               {"seconds", "minutes", "prompt"},
	"set_fact":            {},
	"include_tasks":       {"file"},
	"import_tasks":        {"file"},
	"include_vars":        {"file", "dir"},
	"include_role":        {"name"},
	"import_role":         {"name"},
	"meta":                {},
	"getent":              {"database", "key"},
	"setup":               {"gather_subset", "filter"},
	"async_status":        {"jid"},
}
