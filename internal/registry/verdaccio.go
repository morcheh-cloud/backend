package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// NPMJS is the public npm registry a Verdaccio mirror fetches from.
const NPMJS = "https://registry.npmjs.org/"

// verdaccioUID is the user the official image runs as.
const verdaccioUID = "10001:65533"

// VerdaccioConfig is what config.yaml and compose.yaml are written from.
type VerdaccioConfig struct {
	Dir       string
	Name      string // shown as the web page's title
	Port      int
	Open      bool   // listen on every address (no proxy in front)
	PublicURL string // https://npm.example.com, "" = whatever the request says
	Settings  RegistrySettings
}

// VerdaccioYAML renders config.yaml: users from htpasswd written by Morche
// (sign-up closed), private scopes first, everything else through the
// mirror when it's on.
func VerdaccioYAML(c VerdaccioConfig) string {
	s := c.Settings
	read := "$authenticated"
	if s.Public {
		read = "$all"
	}
	var b strings.Builder
	w := func(l string) { b.WriteString(l + "\n") }
	w("# Written by Morche: change it from the panel, edits here are replaced.")
	w("storage: /verdaccio/storage")
	w("plugins: /verdaccio/plugins")
	w("web:")
	w("  title: " + yamlStr(c.Name))
	w("auth:")
	w("  htpasswd:")
	w("    file: /verdaccio/conf/htpasswd")
	w("    max_users: -1")
	if s.Mirror {
		w("uplinks:")
		w("  npmjs:")
		w("    url: " + yamlStr(s.Upstream))
		w("    timeout: 30s")
		w("    maxage: 10m")
		w("    cache: true")
	}
	w("packages:")
	pkg := func(pattern string, mirror bool) {
		w("  " + yamlStr(pattern) + ":")
		w("    access: " + yamlStr(read))
		w("    publish: $authenticated")
		w("    unpublish: $authenticated")
		if mirror && s.Mirror {
			w("    proxy: npmjs")
		}
	}
	for _, sc := range s.Scopes {
		pkg(sc+"/*", false)
	}
	pkg("@*/*", true)
	pkg("**", true)
	w("server:")
	w("  keepAliveTimeout: 60")
	w("middlewares:")
	w("  audit:")
	w("    enabled: true")
	w("log:")
	w("  type: stdout")
	w("  format: pretty")
	w("  level: http")
	return b.String()
}

// VerdaccioCompose renders compose.yaml.
func VerdaccioCompose(c VerdaccioConfig) string {
	bind := "127.0.0.1:"
	if c.Open {
		bind = ""
	}
	var b strings.Builder
	w := func(l string) { b.WriteString(l + "\n") }
	w("# Written by Morche for the npm registry " + c.Name + ".")
	w("services:")
	w("  verdaccio:")
	w("    image: verdaccio/verdaccio:" + VerdaccioVersion)
	w("    restart: unless-stopped")
	w("    ports:")
	w("      - " + yamlStr(bind+itoa(c.Port)+":4873"))
	if c.PublicURL != "" {
		w("    environment:")
		w("      VERDACCIO_PUBLIC_URL: " + yamlStr(c.PublicURL))
	}
	w("    volumes:")
	w("      - ./conf:/verdaccio/conf")
	w("      - ./storage:/verdaccio/storage")
	w("    labels:")
	w("      morche.registry: verdaccio")
	return b.String()
}

// HtpasswdLine is one user's line, the password hashed with bcrypt.
func HtpasswdLine(user, password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}
	return user + ":" + string(h), nil
}

// HtpasswdUsers lists the users in an htpasswd file.
func HtpasswdUsers(text string) []string {
	var out []string
	for l := range strings.SplitSeq(text, "\n") {
		if u, _, ok := strings.Cut(strings.TrimSpace(l), ":"); ok && u != "" && !strings.HasPrefix(u, "#") {
			out = append(out, u)
		}
	}
	sort.Strings(out)
	return out
}

// SetHtpasswd replaces (or adds) user's line, or removes it when line is "".
func SetHtpasswd(text, user, line string) string {
	var out []string
	done := false
	for l := range strings.SplitSeq(text, "\n") {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if u, _, _ := strings.Cut(t, ":"); u == user {
			if line != "" && !done {
				out = append(out, line)
				done = true
			}
			continue
		}
		out = append(out, t)
	}
	if line != "" && !done {
		out = append(out, line)
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// VerdaccioInstallScript writes the files and starts it. htpasswd is the
// whole file (the admin's line).
func VerdaccioInstallScript(c VerdaccioConfig, project, htpasswd string) string {
	q := Quote
	return `set -e
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "Docker isn't installed or running on this server" >&2; exit ` + itoa(ExitNoDocker) + `; }
` + composeDetect + `mkdir -p ` + q(c.Dir+"/conf") + ` ` + q(c.Dir+"/storage") + `
cd ` + q(c.Dir) + `
echo "==> Writing the configuration"
` + writeFile(c.Dir+"/compose.yaml", VerdaccioCompose(c)) +
		writeFile(c.Dir+"/conf/config.yaml", VerdaccioYAML(c)) + `umask 077
` + writeFile(c.Dir+"/conf/htpasswd", htpasswd) + `umask 022
chown -R ` + verdaccioUID + ` conf storage
chmod 640 conf/htpasswd
echo "==> Pulling the image"
$C -p ` + q(project) + ` pull 2>&1 | tail -n 5
echo "==> Starting Verdaccio"
$C -p ` + q(project) + ` up -d 2>&1
`
}

// VerdaccioConfigScript rewrites config.yaml (and compose.yaml) and
// recreates the container so it reads them.
func VerdaccioConfigScript(c VerdaccioConfig, project string) string {
	q := Quote
	return `set -e
` + composeDetect + `cd ` + q(c.Dir) + `
` + writeFile(c.Dir+"/compose.yaml", VerdaccioCompose(c)) + writeFile(c.Dir+"/conf/config.yaml", VerdaccioYAML(c)) + `chown ` + verdaccioUID + ` conf/config.yaml
$C -p ` + q(project) + ` up -d --force-recreate 2>&1
`
}

// ReadHtpasswdScript prints the htpasswd file.
func ReadHtpasswdScript(dir string) string {
	return "cat " + Quote(dir+"/conf/htpasswd") + " 2>/dev/null || true\n"
}

// WriteHtpasswdScript replaces the htpasswd file; Verdaccio reads it again
// on the next sign-in.
func WriteHtpasswdScript(dir, text string) string {
	p := dir + "/conf/htpasswd"
	return "set -e\numask 077\n" + writeFile(p, text) + "chown " + verdaccioUID + " " + Quote(p) + "\nchmod 640 " + Quote(p) + "\n"
}

var packageNameRe = regexp.MustCompile(`^(@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$`)

// ValidPackage says whether name is an npm package name.
func ValidPackage(name string) bool { return len(name) <= 214 && packageNameRe.MatchString(name) }

// containerOf finds the Verdaccio container of a compose project.
func containerOf(project string) string {
	return `id=$(docker ps -q --filter label=com.docker.compose.project=` + Quote(project) + ` --filter label=com.docker.compose.service=verdaccio | head -n 1)
[ -n "$id" ] || { echo "Verdaccio isn't running" >&2; exit 71; }
`
}

const listPackagesJS = `const fs=require('fs'),p=require('path');const root='/verdaccio/storage';
let priv=[];try{priv=JSON.parse(fs.readFileSync(p.join(root,'.verdaccio-db.json'))).list||[]}catch(e){}
const out=[];
function add(name,d){let j;try{j=JSON.parse(fs.readFileSync(p.join(d,'package.json')))}catch(e){return}
let n=0,c=0;try{for(const f of fs.readdirSync(d)){if(f.endsWith('.tgz')){c++;try{n+=fs.statSync(p.join(d,f)).size}catch(e){}}}}catch(e){}
const vs=Object.keys(j.versions||{});const tags=j['dist-tags']||{};const t=j.time||{};const l=tags.latest||vs[vs.length-1]||'';
out.push({name,private:priv.includes(name),versions:vs.length,latest:l,modified:t.modified||'',size:n,files:c,description:((j.versions||{})[l]||{}).description||''})}
try{for(const e of fs.readdirSync(root,{withFileTypes:true})){if(!e.isDirectory()||e.name.startsWith('.'))continue;const d=p.join(root,e.name);
if(e.name.startsWith('@')){for(const s of fs.readdirSync(d,{withFileTypes:true}))if(s.isDirectory())add(e.name+'/'+s.name,p.join(d,s.name))}else add(e.name,d)}}catch(e){}
process.stdout.write(JSON.stringify(out))`

const packageJS = `const fs=require('fs'),p=require('path');const name=process.env.MORCHE_PKG;const d=p.join('/verdaccio/storage',name);
let j;try{j=JSON.parse(fs.readFileSync(p.join(d,'package.json')))}catch(e){process.stderr.write('No such package');process.exit(72)}
let priv=[];try{priv=JSON.parse(fs.readFileSync('/verdaccio/storage/.verdaccio-db.json')).list||[]}catch(e){}
const t=j.time||{};const vs=Object.entries(j.versions||{}).map(([v,m])=>{const f=((m.dist||{}).tarball||'').split('/').pop();let size=-1;try{size=fs.statSync(p.join(d,f)).size}catch(e){}
return {version:v,time:t[v]||'',size,deprecated:m.deprecated||'',author:typeof m._npmUser==='object'?(m._npmUser.name||''):''}});
const l=(j['dist-tags']||{}).latest;const m=(j.versions||{})[l]||{};
process.stdout.write(JSON.stringify({name,private:priv.includes(name),dist_tags:j['dist-tags']||{},description:m.description||'',license:typeof m.license==='string'?m.license:'',homepage:m.homepage||'',versions:vs}))`

// ListPackagesScript prints every package Verdaccio keeps, as JSON.
func ListPackagesScript(project string) string {
	return containerOf(project) + `docker exec "$id" node -e ` + Quote(listPackagesJS) + "\n"
}

// PackageScript prints one package's versions, as JSON.
func PackageScript(project, name string) string {
	return containerOf(project) + `docker exec -e MORCHE_PKG=` + Quote(name) + ` "$id" node -e ` + Quote(packageJS) + "\n"
}

// UsageScript prints the bytes under dir.
func UsageScript(dir string) string {
	return "du -sb " + Quote(dir) + " 2>/dev/null | awk '{print $1}'\n"
}

type NPMPackage struct {
	Name        string `json:"name"`
	Private     bool   `json:"private" doc:"Published here (not a copy from the mirror)"`
	Versions    int    `json:"versions"`
	Latest      string `json:"latest"`
	Modified    string `json:"modified"`
	Size        int64  `json:"size" doc:"Bytes of the tarballs kept here"`
	Files       int    `json:"files" doc:"Tarballs kept here"`
	Description string `json:"description"`
}

func ParsePackages(out string) ([]NPMPackage, error) {
	var ps []NPMPackage
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &ps); err != nil {
		return nil, err
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Private != ps[j].Private {
			return ps[i].Private
		}
		return ps[i].Modified > ps[j].Modified
	})
	return ps, nil
}

type NPMVersion struct {
	Version    string `json:"version"`
	Time       string `json:"time"`
	Size       int64  `json:"size" doc:"Bytes of its tarball here; -1 = not kept here (fetched when asked)"`
	Deprecated string `json:"deprecated"`
	Author     string `json:"author"`
}

type NPMPackageDetail struct {
	Name        string            `json:"name"`
	Private     bool              `json:"private"`
	DistTags    map[string]string `json:"dist_tags"`
	Description string            `json:"description"`
	License     string            `json:"license"`
	Homepage    string            `json:"homepage"`
	Versions    []NPMVersion      `json:"versions"`
}

func ParsePackage(out string) (NPMPackageDetail, error) {
	var d NPMPackageDetail
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &d); err != nil {
		return d, err
	}
	sort.Slice(d.Versions, func(i, j int) bool { return d.Versions[i].Time > d.Versions[j].Time })
	if d.DistTags == nil {
		d.DistTags = map[string]string{}
	}
	return d, nil
}

// ---- Verdaccio's API ----

type VerdaccioClient struct{ HTTP }

// Ping is nil when Verdaccio answers.
func (c VerdaccioClient) Ping(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, "/-/ping", nil, nil)
	return err
}

// Whoami checks the admin login.
func (c VerdaccioClient) Whoami(ctx context.Context) (string, error) {
	var w struct {
		Username string `json:"username"`
	}
	_, err := c.do(ctx, http.MethodGet, "/-/whoami", nil, &w)
	return w.Username, err
}

// Unpublish removes a package with every version.
func (c VerdaccioClient) Unpublish(ctx context.Context, name string) error {
	path := "/" + strings.Replace(url.PathEscape(name), "%2F", "%2f", 1) + "/-rev/morche"
	_, err := c.do(ctx, http.MethodDelete, path, nil, nil)
	return err
}

// WaitReady polls fn until it answers nil or the time is up.
func WaitReady(ctx context.Context, limit time.Duration, fn func(context.Context) error) error {
	end := time.Now().Add(limit)
	var err error
	for {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = fn(cctx)
		cancel()
		if err == nil || time.Now().After(end) || ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(4 * time.Second):
		}
	}
}
