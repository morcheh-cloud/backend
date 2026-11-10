// Package software is Morcheh's application catalog: recipes that install,
// update and remove software on a server over SSH (system packages like
// Docker or Git, and Docker Compose apps like Grafana), the shell scripts
// that do it, what a scan of a server says is there, and a registry client
// that tells whether a container image has a newer build.
package software

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kinds of recipe.
const (
	// System packages from the server's package manager. Install, update and
	// uninstall default to the package manager; a recipe may write its own.
	KindPackage = "package"
	// A Docker Compose app in /opt/morcheh/apps/<id>.
	KindDocker = "docker"
	// Anything else: the recipe writes every script itself.
	KindScript = "script"
)

// System is the pseudo-recipe for "upgrade the server's packages".
const System = "system"

// AppsDir is where Docker apps live on a server, one folder each.
const AppsDir = "/opt/morcheh/apps"

// Package managers a recipe can name packages for. "default" is any other.
var PackageManagers = []string{"apt", "dnf", "yum", "zypper", "apk", "pacman"}

// Recipe is one application in the catalog.
type Recipe struct {
	ID          string `json:"id" yaml:"id" doc:"Short name: lowercase letters, digits and dashes"`
	Name        string `json:"name" yaml:"name"`
	Summary     string `json:"summary" yaml:"summary" doc:"One line"`
	Description string `json:"description,omitempty" yaml:"description"`
	Kind        string `json:"kind" yaml:"kind" enum:"package,docker,script"`
	Category    string `json:"category" yaml:"category"`
	Icon        string `json:"icon,omitempty" yaml:"icon" doc:"A lucide icon name for the panel"`
	Logo        string `json:"logo,omitempty" yaml:"logo" doc:"A brand logo the panel ships (Simple Icons name, e.g. redis); shown in place of the icon when the panel has it"`
	Website     string `json:"website,omitempty" yaml:"website"`
	// Other recipes that must be on the server first (e.g. docker).
	Requires []string `json:"requires,omitempty" yaml:"requires"`
	// Package managers it works with; empty = any.
	OS     []string      `json:"os,omitempty" yaml:"os"`
	Params []RecipeParam `json:"params,omitempty" yaml:"params"`
	Links  []RecipeLink  `json:"links,omitempty" yaml:"links"`
	Notes  string        `json:"notes,omitempty" yaml:"notes" doc:"Shown after it's installed: first steps, where the password is…"`
	// Package names per package manager (apt, dnf…, or default). The first
	// is the one whose version is shown.
	Packages map[string][]string `json:"packages,omitempty" yaml:"packages"`
	// Packages that may stand in for those on a server (the distro's own
	// build, e.g. docker.io for docker-ce): never installed, but updated,
	// removed and read for the version when they're the ones there.
	Also map[string][]string `json:"also,omitempty" yaml:"also" doc:"Other package names it may be installed as (e.g. the distro's build), per package manager: updated and removed when they're the ones on the server"`
	// A command that prints the installed version (used when no package
	// tells it).
	VersionCommand string `json:"version_command,omitempty" yaml:"version"`
	// Shell scripts (POSIX sh, run as root), each optional for a package.
	Install   string `json:"install,omitempty" yaml:"install"`
	Update    string `json:"update,omitempty" yaml:"update"`
	Uninstall string `json:"uninstall,omitempty" yaml:"uninstall"`
	// Docker apps: the compose file, with ${NAME} for the parameters.
	Compose string `json:"compose,omitempty" yaml:"compose"`

	Builtin bool `json:"builtin" yaml:"-"`
	// Taken out of the catalog: no new installs, but earlier ones can still
	// be updated, managed and removed.
	Retired bool `json:"retired,omitempty" yaml:"-" doc:"No longer offered for new installs; earlier installs can still be updated and removed"`
	// A workspace's own recipe: its id, for editing.
	RecordID string `json:"record_id,omitempty" yaml:"-"`
}

// RecipeParam is a value asked for at install time. Package and script recipes get
// it as an environment variable; Docker apps as ${NAME} in the compose file.
type RecipeParam struct {
	Name     string   `json:"name" yaml:"name" doc:"Variable name, upper case"`
	Label    string   `json:"label" yaml:"label"`
	Help     string   `json:"help,omitempty" yaml:"help"`
	Type     string   `json:"type" yaml:"type" enum:"text,number,port,password,bool,select,path,domain,email"`
	Default  string   `json:"default,omitempty" yaml:"default"`
	Required bool     `json:"required,omitempty" yaml:"required"`
	Options  []string `json:"options,omitempty" yaml:"options"`
	// When left empty, a value is made for each server: password or hex.
	Generate string `json:"generate,omitempty" yaml:"generate" enum:"password,hex,"`
}

// Secret params are sealed in the database and shown only to Owners.
func (p RecipeParam) Secret() bool { return p.Type == "password" }

// RecipeLink is an address the app answers on, shown as Open.
type RecipeLink struct {
	Label  string `json:"label" yaml:"label"`
	Port   string `json:"port" yaml:"port" doc:"The port parameter's name, or a number"`
	Path   string `json:"path,omitempty" yaml:"path"`
	Scheme string `json:"scheme,omitempty" yaml:"scheme" enum:"http,https,"`
}

//go:embed recipes/*.yaml recipes/retired/*.yaml
var builtinFS embed.FS

var builtins []Recipe

func init() {
	files, err := fs.Glob(builtinFS, "recipes/*.yaml")
	if err != nil {
		panic(err)
	}
	retired, err := fs.Glob(builtinFS, "recipes/retired/*.yaml")
	if err != nil {
		panic(err)
	}
	files = append(files, retired...)
	for _, f := range files {
		raw, err := builtinFS.ReadFile(f)
		if err != nil {
			panic(err)
		}
		var r Recipe
		if err := yaml.Unmarshal(raw, &r); err != nil {
			panic(fmt.Sprintf("%s: %v", f, err))
		}
		r.Builtin = true
		r.Retired = strings.HasPrefix(f, "recipes/retired/")
		if err := r.Check(); err != nil {
			panic(fmt.Sprintf("%s: %v", f, err))
		}
		builtins = append(builtins, r)
	}
	sort.Slice(builtins, func(i, j int) bool { return builtins[i].Name < builtins[j].Name })
}

// Builtins are the recipes that ship with Morcheh.
func Builtins() []Recipe { return slices.Clone(builtins) }

// IsBuiltin says whether id is taken by a built-in recipe.
func IsBuiltin(id string) bool {
	return slices.ContainsFunc(builtins, func(r Recipe) bool { return r.ID == id })
}

// Find returns the recipe with id from list.
func Find(list []Recipe, id string) (Recipe, bool) {
	i := slices.IndexFunc(list, func(r Recipe) bool { return r.ID == id })
	if i < 0 {
		return Recipe{}, false
	}
	return list[i], true
}

var (
	idRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	paramRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,62}$`)
)

// FieldError says which field of a recipe is wrong.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

func bad(field, msg string) error { return &FieldError{field, msg} }

// Reserved parameter names: they'd change how the shell runs.
func reservedParam(name string) bool {
	switch name {
	case "PATH", "IFS", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "PS4", "HOME", "SHELL", "USER",
		"LOGNAME", "SUDO_ASKPASS", "PM", "PKGS", "COMPOSE_PROJECT_NAME", "COMPOSE_FILE":
		return true
	}
	return strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "BASH_FUNC") ||
		strings.HasPrefix(name, "PYTHON") || strings.HasPrefix(name, "MORCHEH_")
}

// Normalize trims what a person typed.
func (r *Recipe) Normalize() {
	r.ID = strings.TrimSpace(r.ID)
	r.Name = strings.TrimSpace(r.Name)
	r.Summary = strings.TrimSpace(r.Summary)
	r.Category = cmpOr(strings.TrimSpace(r.Category), "Other")
	r.Kind = strings.TrimSpace(r.Kind)
	r.Logo = strings.ToLower(strings.TrimSpace(r.Logo))
	for i := range r.Params {
		p := &r.Params[i]
		p.Name = strings.TrimSpace(p.Name)
		p.Label = cmpOr(strings.TrimSpace(p.Label), p.Name)
		p.Type = cmpOr(strings.TrimSpace(p.Type), "text")
	}
}

// Check says what is wrong with a recipe, if anything.
func (r Recipe) Check() error {
	if !idRe.MatchString(r.ID) {
		return bad("id", "Use lowercase letters, digits and dashes.")
	}
	if r.ID == System {
		return bad("id", "That name is taken.")
	}
	if r.Name == "" || len(r.Name) > 100 {
		return bad("name", "Give it a name (up to 100 characters).")
	}
	for pm, names := range r.Also {
		if pm != "default" && !slices.Contains(PackageManagers, pm) {
			return bad("also", "Unknown package manager "+pm+".")
		}
		for _, n := range names {
			if !packageNameRe.MatchString(n) {
				return bad("also", "Bad package name "+n+".")
			}
		}
	}
	switch r.Kind {
	case KindPackage:
		if len(r.Packages) == 0 {
			return bad("packages", "Name at least one package.")
		}
		for pm, names := range r.Packages {
			if pm != "default" && !slices.Contains(PackageManagers, pm) {
				return bad("packages", "Unknown package manager "+pm+".")
			}
			if len(names) == 0 {
				return bad("packages", "No packages for "+pm+".")
			}
			for _, n := range names {
				if !packageNameRe.MatchString(n) {
					return bad("packages", "Bad package name "+n+".")
				}
			}
		}
	case KindDocker:
		if len(r.Also) > 0 {
			return bad("also", "Only a package recipe has other package names.")
		}
		if strings.TrimSpace(r.Compose) == "" {
			return bad("compose", "Write the compose file.")
		}
		var doc struct {
			Services map[string]any `yaml:"services"`
		}
		if err := yaml.Unmarshal([]byte(r.Compose), &doc); err != nil {
			return bad("compose", "It isn't valid YAML: "+err.Error())
		}
		if len(doc.Services) == 0 {
			return bad("compose", "It has no services.")
		}
		for name := range doc.Services {
			if !serviceRe.MatchString(name) {
				return bad("compose", "Use lowercase letters, digits, dashes and underscores for service names ("+name+").")
			}
		}
	case KindScript:
		if strings.TrimSpace(r.Install) == "" {
			return bad("install", "Write the install script.")
		}
		if strings.TrimSpace(r.VersionCommand) == "" {
			return bad("version", "Write a command that prints the version, so Morcheh can tell it's installed.")
		}
	default:
		return bad("kind", "Pick package, docker or script.")
	}
	for _, os := range r.OS {
		if !slices.Contains(PackageManagers, os) {
			return bad("os", "Unknown package manager "+os+".")
		}
	}
	seen := map[string]bool{}
	for i, p := range r.Params {
		f := fmt.Sprintf("params[%d]", i)
		if !paramRe.MatchString(p.Name) || reservedParam(p.Name) {
			return bad(f+".name", "Use upper case letters, digits and _ (and not a name the shell uses).")
		}
		if seen[p.Name] {
			return bad(f+".name", "Another parameter has this name.")
		}
		seen[p.Name] = true
		switch p.Type {
		case "text", "number", "port", "password", "bool", "path", "domain", "email":
		case "select":
			if len(p.Options) == 0 {
				return bad(f+".options", "Give the choices.")
			}
		default:
			return bad(f+".type", "Unknown type "+p.Type+".")
		}
		switch p.Generate {
		case "", "password", "hex":
		default:
			return bad(f+".generate", "Use password or hex.")
		}
		if p.Default != "" {
			if err := checkValue(p, p.Default, r.Kind); err != nil {
				return bad(f+".default", err.Error())
			}
		}
	}
	if r.Logo != "" && !logoRe.MatchString(r.Logo) {
		return bad("logo", "Use a logo name: lowercase letters and digits.")
	}
	if r.Website != "" {
		u, err := url.Parse(r.Website)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return bad("website", "Use an http(s) address like https://example.com.")
		}
	}
	for i, l := range r.Links {
		if l.Scheme != "" && l.Scheme != "http" && l.Scheme != "https" {
			return bad(fmt.Sprintf("links[%d].scheme", i), "Use http or https.")
		}
		if l.Path != "" && (!strings.HasPrefix(l.Path, "/") || strings.HasPrefix(l.Path, "//")) {
			return bad(fmt.Sprintf("links[%d].path", i), "Start the path with a single /.")
		}
		if l.Port == "" {
			return bad(fmt.Sprintf("links[%d].port", i), "Say which port.")
		}
		if !seen[l.Port] && !portRe.MatchString(l.Port) {
			return bad(fmt.Sprintf("links[%d].port", i), "Use a port number or a parameter's name.")
		}
	}
	return nil
}

var (
	packageNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:@-]*$`)
	serviceRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	portRe        = regexp.MustCompile(`^[0-9]{1,5}$`)
	logoRe        = regexp.MustCompile(`^[a-z0-9]{1,40}$`)
	domainRe      = regexp.MustCompile(`^[A-Za-z0-9*]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)
	numberRe      = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)
)

func checkValue(p RecipeParam, v, kind string) error {
	if strings.ContainsAny(v, "\n\r\x00") {
		return errors.New("Keep it to one line.")
	}
	// Docker apps' values go in a .env file in single quotes.
	if kind == KindDocker && strings.Contains(v, "'") {
		return errors.New("It can't contain a single quote (').")
	}
	if len(v) > 4096 {
		return errors.New("It's too long.")
	}
	switch p.Type {
	case "port":
		n := 0
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil || !portRe.MatchString(v) || n < 1 || n > 65535 {
			return errors.New("Use a port from 1 to 65535.")
		}
	case "number":
		if !numberRe.MatchString(v) {
			return errors.New("Use a number.")
		}
	case "bool":
		if v != "true" && v != "false" {
			return errors.New("Use true or false.")
		}
	case "select":
		if !slices.Contains(p.Options, v) {
			return errors.New("Pick one of " + strings.Join(p.Options, ", ") + ".")
		}
	case "domain":
		if !domainRe.MatchString(v) {
			return errors.New("Use a domain name like app.example.com.")
		}
	case "email":
		if !strings.Contains(v, "@") || strings.ContainsAny(v, " \t") {
			return errors.New("Use an email address.")
		}
	case "path":
		if !strings.HasPrefix(v, "/") {
			return errors.New("Use an absolute path.")
		}
	}
	return nil
}

// Values are the parameters for one server: what was given, else the
// default, else (for Generate) a fresh value. Unknown names are refused.
// It returns the values and the names it generated.
func (r Recipe) Values(given map[string]string) (map[string]string, []string, error) {
	out := map[string]string{}
	var generated []string
	for name := range given {
		if !slices.ContainsFunc(r.Params, func(p RecipeParam) bool { return p.Name == name }) {
			return nil, nil, bad("params."+name, "This app has no such setting.")
		}
	}
	for _, p := range r.Params {
		v := strings.TrimSpace(given[p.Name])
		if p.Type == "password" {
			v = given[p.Name]
		}
		if v == "" {
			v = p.Default
		}
		if v == "" && p.Generate != "" {
			v = generate(p.Generate)
			generated = append(generated, p.Name)
		}
		if v == "" {
			if p.Required {
				return nil, nil, bad("params."+p.Name, p.Label+" is required.")
			}
			if p.Type == "bool" {
				v = "false"
			}
			out[p.Name] = v
			continue
		}
		if err := checkValue(p, v, r.Kind); err != nil {
			return nil, nil, bad("params."+p.Name, err.Error())
		}
		out[p.Name] = v
	}
	return out, generated, nil
}

// CheckGiven checks the values a person typed (before generating any).
func (r Recipe) CheckGiven(given map[string]string) error {
	_, _, err := r.Values(withoutGenerated(r, given))
	return err
}

func withoutGenerated(r Recipe, given map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range given {
		out[k] = v
	}
	for _, p := range r.Params {
		if p.Generate != "" && strings.TrimSpace(out[p.Name]) == "" {
			out[p.Name] = "x" // stands in for the generated value
			if p.Type == "port" {
				out[p.Name] = "1"
			}
		}
	}
	return out
}

const alnum = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

func generate(kind string) string {
	if kind == "hex" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
	var s strings.Builder
	for range 24 {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alnum))))
		s.WriteByte(alnum[n.Int64()])
	}
	return s.String()
}

// Ports are the port values an install will listen on, for the preflight.
func (r Recipe) Ports(values map[string]string) []int {
	var out []int
	for _, p := range r.Params {
		if p.Type != "port" {
			continue
		}
		n := 0
		if _, err := fmt.Sscanf(values[p.Name], "%d", &n); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

// PackagesFor returns the packages to use with package manager pm.
func (r Recipe) PackagesFor(pm string) []string {
	if p, ok := r.Packages[pm]; ok {
		return p
	}
	if pm == "yum" {
		if p, ok := r.Packages["dnf"]; ok {
			return p
		}
	}
	return r.Packages["default"]
}

// Supports says whether the recipe works with package manager pm.
func (r Recipe) Supports(pm string) bool {
	if pm == "" || pm == "none" {
		return r.Kind == KindDocker || len(r.OS) == 0 && r.Kind == KindScript
	}
	if len(r.OS) > 0 && !slices.Contains(r.OS, pm) {
		return false
	}
	if r.Kind == KindPackage && r.Install == "" && len(r.PackagesFor(pm)) == 0 {
		return false
	}
	return true
}

// Images are the container images the compose file names (with ${…}
// left in when the tag is a parameter).
func (r Recipe) Images() []string {
	var out []string
	for _, m := range imageRe.FindAllStringSubmatch(r.Compose, -1) {
		img := strings.Trim(m[1], `"'`)
		if !slices.Contains(out, img) {
			out = append(out, img)
		}
	}
	return out
}

var imageRe = regexp.MustCompile(`(?m)^\s+image:\s*(\S+)\s*$`)

// Project is the compose project name of a Docker app.
func Project(id string) string { return "morcheh-" + id }

// Dir is the folder of a Docker app on the server.
func Dir(id string) string { return AppsDir + "/" + id }

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
