package fake

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type storage struct {
	name, typ, content string
	shared             bool
	total, base        int64 // base = space taken by things the fake doesn't list
}

type volume struct {
	volid, format, content string
	size                   int64
	ctime                  int64
	vmid                   int
	notes                  string
	protected              bool
	verified               string
	subtype                string
	kind                   string            // a backup's guest kind
	conf                   map[string]string // a backup's guest config
}

func (s *Server) storageOn(name, nodeName string) *storage {
	for _, st := range s.storages {
		if st.name == name {
			return st
		}
	}
	_ = nodeName
	return nil
}

func storageKey(st *storage, nodeName string) string {
	if st.shared {
		return st.name
	}
	return nodeName + "/" + st.name
}

func (s *Server) volume(nodeName, volid string) (*volume, bool) {
	name, _, _ := strings.Cut(volid, ":")
	st := s.storageOn(name, nodeName)
	if st == nil {
		return nil, false
	}
	for _, v := range s.volumes[storageKey(st, nodeName)] {
		if v.volid == volid {
			return v, true
		}
	}
	return nil, false
}

// guestVolumes are the disk images guests keep on a storage, as content rows.
func (s *Server) guestVolumes(st *storage, nodeName string) []*volume {
	var out []*volume
	for _, id := range s.ids() {
		g := s.guests[id]
		if !st.shared && g.node != nodeName {
			continue
		}
		for _, k := range sortedKeys(g.conf) {
			if !diskKey.MatchString(k) {
				continue
			}
			d := parseDisk(g.conf[k])
			if d.storage != st.name || d.volid == "none" {
				continue
			}
			if d.cdrom && !strings.Contains(d.volid, "cloudinit") {
				continue
			}
			content, format := "images", "raw"
			if g.kind == "lxc" {
				content = "rootdir"
			}
			size := d.size
			if strings.Contains(d.volid, "cloudinit") {
				size = 4 * mib
			}
			if st.typ == "dir" || st.typ == "nfs" {
				format = "qcow2"
			}
			out = append(out, &volume{volid: d.volid, format: format, content: content, size: size, vmid: id, ctime: s.start.Add(-time.Duration(id) * time.Hour).Unix()})
		}
	}
	return out
}

func (s *Server) storageUse(st *storage, nodeName string) (used, total int64) {
	used = st.base
	for _, v := range s.volumes[storageKey(st, nodeName)] {
		used += v.size
	}
	for _, v := range s.guestVolumes(st, nodeName) {
		if st.typ == "lvmthin" || st.typ == "rbd" {
			used += v.size * 45 / 100 // thin: only what's written
		} else {
			used += v.size
		}
	}
	return min(used, st.total), st.total
}

func (s *Server) storageCall(r *http.Request, n *node, p []string) (any, error) {
	if len(p) == 0 {
		want := r.URL.Query().Get("content")
		out := []map[string]any{}
		for _, st := range s.storages {
			if want != "" && !slices.Contains(strings.Split(st.content, ","), want) {
				continue
			}
			used, total := s.storageUse(st, n.name)
			out = append(out, map[string]any{
				"storage": st.name, "type": st.typ, "content": st.content, "active": 1, "enabled": 1,
				"shared": b2i(st.shared), "total": total, "used": used, "avail": total - used,
				"used_fraction": float64(used) / float64(total),
			})
		}
		return out, nil
	}
	st := s.storageOn(p[0], n.name)
	if st == nil {
		return nil, fail(http.StatusInternalServerError, "storage '%s' does not exist", p[0])
	}
	key := storageKey(st, n.name)
	m := r.Method
	switch {
	case len(p) == 2 && p[1] == "content" && m == http.MethodGet:
		q := r.URL.Query()
		content, vmid := q.Get("content"), q.Get("vmid")
		out := []map[string]any{}
		all := append(slices.Clone(s.volumes[key]), s.guestVolumes(st, n.name)...)
		for _, v := range all {
			if content != "" && v.content != content {
				continue
			}
			if vmid != "" && strconv.Itoa(v.vmid) != vmid {
				continue
			}
			row := map[string]any{"volid": v.volid, "format": v.format, "content": v.content, "size": v.size, "ctime": v.ctime}
			if v.vmid > 0 {
				row["vmid"] = v.vmid
			}
			if v.content == "images" || v.content == "rootdir" {
				row["used"] = v.size * 45 / 100
			}
			if v.notes != "" {
				row["notes"] = v.notes
			}
			if v.protected {
				row["protected"] = 1
			}
			if v.verified != "" {
				row["verification"] = map[string]any{"state": v.verified, "upid": ""}
			}
			if v.subtype != "" {
				row["subtype"] = v.subtype
			}
			out = append(out, row)
		}
		return out, nil
	case len(p) == 3 && p[1] == "content" && m == http.MethodDelete:
		volid := p[2]
		if !strings.Contains(volid, ":") {
			volid = st.name + ":" + volid
		}
		list := s.volumes[key]
		i := slices.IndexFunc(list, func(v *volume) bool { return v.volid == volid })
		if i < 0 {
			if s.guestDisk(volid) {
				return nil, fail(http.StatusInternalServerError, "unable to delete '%s' - volume is still in use (guest)", volid)
			}
			return nil, fail(http.StatusInternalServerError, "volume '%s' does not exist", volid)
		}
		v := list[i]
		if v.protected {
			return nil, fail(http.StatusInternalServerError, "can't delete '%s' - protected backup", volid)
		}
		return s.run(n.name, "imgdel", "", time.Second, []string{"Removed volume '" + volid + "'"}, func() error {
			s.volumes[key] = slices.DeleteFunc(s.volumes[key], func(x *volume) bool { return x == v })
			return nil
		}), nil
	case len(p) == 2 && p[1] == "download-url" && m == http.MethodPost:
		return s.downloadURL(r, n, st, key)
	case len(p) == 2 && p[1] == "upload" && m == http.MethodPost:
		return s.upload(r, n, st, key)
	}
	return nil, errNotFound
}

var fileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

func contentDir(content string) string {
	if content == "vztmpl" {
		return "vztmpl"
	}
	return "iso"
}

func (s *Server) addFile(st *storage, key, content, name string, size int64) (*volume, error) {
	if !slices.Contains(strings.Split(st.content, ","), content) {
		return nil, fail(http.StatusInternalServerError, "storage '%s' does not support content-type '%s'", st.name, content)
	}
	if content == "iso" && !strings.HasSuffix(strings.ToLower(name), ".iso") && !strings.HasSuffix(strings.ToLower(name), ".img") {
		return nil, badParam("filename", "wrong file extension")
	}
	if content == "vztmpl" && !regexp.MustCompile(`\.tar\.(gz|xz|zst)$`).MatchString(name) {
		return nil, badParam("filename", "wrong file extension")
	}
	volid := st.name + ":" + contentDir(content) + "/" + name
	for _, v := range s.volumes[key] {
		if v.volid == volid {
			return nil, fail(http.StatusInternalServerError, "refusing to override existing file '%s'", name)
		}
	}
	format := content
	if content == "vztmpl" {
		format = "tzst"
	}
	return &volume{volid: volid, format: format, content: content, size: size, ctime: time.Now().Unix()}, nil
}

func (s *Server) downloadURL(r *http.Request, n *node, st *storage, key string) (any, error) {
	content, raw, name := form(r, "content"), form(r, "url"), form(r, "filename")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, badParam("url", "invalid format - invalid URL '"+raw+"'")
	}
	if name == "" {
		name = path.Base(u.Path)
	}
	if !fileName.MatchString(name) {
		return nil, badParam("filename", "invalid characters in file name")
	}
	size := int64(1800+len(name)*37) * mib
	if content == "vztmpl" {
		size = int64(120+len(name)) * mib
	}
	v, err := s.addFile(st, key, content, name, size)
	if err != nil {
		return nil, err
	}
	sum := form(r, "checksum")
	lines := []string{"downloading " + raw + " to /var/lib/vz/template/" + contentDir(content) + "/" + name + ".tmp." + strconv.Itoa(s.pid)}
	for i := 1; i <= 10; i++ {
		lines = append(lines, fmt.Sprintf("%d%% [%s] %dM", i*10, strings.Repeat("=", i*3), size/mib*int64(i)/10))
	}
	if sum != "" {
		lines = append(lines, "calculating checksum...OK, checksum verified")
	}
	lines = append(lines, "download of '"+raw+"' to '/var/lib/vz/template/"+contentDir(content)+"/"+name+"' finished")
	return s.run(n.name, "download", st.name, 6*time.Second, lines, func() error {
		if strings.Contains(u.Host, "invalid") || strings.HasSuffix(u.Host, ".test") {
			return fmt.Errorf("download failed: 404 Not Found")
		}
		if sum != "" && strings.HasPrefix(strings.ToLower(sum), "bad") {
			return fmt.Errorf("checksum mismatch: got 'e3b0c44298fc1c149afbf4c8996fb924', expected '%s'", sum)
		}
		s.volumes[key] = append(s.volumes[key], v)
		return nil
	}), nil
}

func (s *Server) upload(r *http.Request, n *node, st *storage, key string) (any, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, badParam("filename", "missing file")
	}
	content := ""
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return nil, badParam("filename", "missing file")
		}
		if err != nil {
			return nil, fail(http.StatusBadRequest, "upload failed: %v", err)
		}
		if part.FormName() == "content" {
			b, _ := io.ReadAll(io.LimitReader(part, 64))
			content = strings.TrimSpace(string(b))
			continue
		}
		if part.FormName() != "filename" {
			continue
		}
		name := path.Base(part.FileName())
		if !fileName.MatchString(name) {
			return nil, badParam("filename", "invalid characters in file name")
		}
		// The body is read with the lock released: an upload can be big.
		s.mu.Unlock()
		size, err := io.Copy(io.Discard, part)
		s.mu.Lock()
		if err != nil {
			return nil, fail(http.StatusBadRequest, "upload failed: %v", err)
		}
		v, err := s.addFile(st, key, content, name, size)
		if err != nil {
			return nil, err
		}
		return s.run(n.name, "imgcopy", "", 500*time.Millisecond, []string{
			"starting file import from: /var/tmp/pveupload-" + randHex(8),
			"target node: " + n.name, "target file: /var/lib/vz/template/" + contentDir(content) + "/" + name,
			fmt.Sprintf("file size is: %d", size), "command: cp -- /var/tmp/pveupload-… /var/lib/vz/template/" + contentDir(content) + "/" + name,
			"finished file import successfully",
		}, func() error {
			s.volumes[key] = append(s.volumes[key], v)
			return nil
		}), nil
	}
}

// Backups

func backupVolid(st *storage, g *guest, at time.Time, compress string) (volid, format, subtype string) {
	if st.typ == "pbs" {
		kind := "vm"
		if g.kind == "lxc" {
			kind = "ct"
		}
		return fmt.Sprintf("%s:backup/%s/%d/%s", st.name, kind, g.vmid, at.UTC().Format("2006-01-02T15:04:05Z")), "pbs-" + kind, g.kind
	}
	ext := map[string]string{"zstd": ".zst", "gzip": ".gz", "lzo": ".lzo", "0": ""}[compress]
	base := "vma"
	if g.kind == "lxc" {
		base = "tar"
	}
	return fmt.Sprintf("%s:backup/vzdump-%s-%d-%s.%s%s", st.name, g.kind, g.vmid, at.Format("2006_01_02-15_04_05"), base, ext), base + ext, g.kind
}

func (s *Server) vzdump(r *http.Request, n *node) (any, error) {
	ids := strings.Split(form(r, "vmid"), ",")
	if len(ids) != 1 || ids[0] == "" {
		return nil, badParam("vmid", "the fake backs up one machine at a time")
	}
	id, _ := strconv.Atoi(ids[0])
	g := s.guests[id]
	if g == nil || g.node != n.name {
		return nil, fail(http.StatusInternalServerError, "guest %d is not on node '%s'", id, n.name)
	}
	stName := form(r, "storage")
	if stName == "" {
		stName = "local"
	}
	st := s.storageOn(stName, n.name)
	if st == nil {
		return nil, fail(http.StatusInternalServerError, "storage '%s' does not exist", stName)
	}
	if !strings.Contains(st.content, "backup") {
		return nil, fail(http.StatusInternalServerError, "storage '%s' does not support backups", stName)
	}
	if g.lock != "" {
		return nil, s.lockedErr(g)
	}
	mode := form(r, "mode")
	if mode == "" {
		mode = "snapshot"
	}
	compress := form(r, "compress")
	if compress == "" {
		compress = "zstd"
	}
	notes := strings.NewReplacer("{{guestname}}", g.name(), "{{vmid}}", strconv.Itoa(id), "{{node}}", n.name, "{{cluster}}", "morche-lab").Replace(form(r, "notes-template"))
	protected := formBool(r, "protected")
	wasRunning := g.running()
	at := time.Now()
	volid, format, _ := backupVolid(st, g, at, compress)
	vt := g.noun()
	if g.kind == "qemu" {
		vt = "VM"
	}
	lines := []string{
		fmt.Sprintf("INFO: starting new backup job: vzdump %d --storage %s --mode %s --compress %s", id, stName, mode, compress),
		fmt.Sprintf("INFO: Starting Backup of %s %d (%s)", vt, id, g.kind),
		"INFO: Backup started at " + at.Format("2006-01-02 15:04:05"),
		"INFO: status = " + g.status,
		"INFO: backup mode: " + mode,
	}
	if mode == "stop" && wasRunning {
		lines = append(lines, "INFO: stopping virtual guest")
	}
	for i := 1; i <= 5; i++ {
		lines = append(lines, fmt.Sprintf("INFO: %3d%% (%d.0 GiB of 5.0 GiB) in %ds, read: 210.4 MiB/s, write: 160.2 MiB/s", i*20, i, i))
	}
	if mode == "stop" && wasRunning {
		lines = append(lines, "INFO: restarting virtual guest")
	}
	lines = append(lines, "INFO: archive file size: 2.13GB", "INFO: Finished Backup of "+vt+" "+strconv.Itoa(id)+" (00:00:06)", "INFO: Backup job finished successfully")
	g.lock = "backup"
	if mode == "stop" && wasRunning {
		g.status = "stopped"
	}
	key := storageKey(st, n.name)
	return s.run(n.name, "vzdump", strconv.Itoa(id), 6*time.Second, lines, func() error {
		g.lock = ""
		if mode == "stop" && wasRunning {
			g.status, g.startedAt = "running", time.Now()
		}
		if s.guests[id] != g {
			return fmt.Errorf("job errors")
		}
		_, d := g.bootDisk()
		s.volumes[key] = append(s.volumes[key], &volume{
			volid: volid, format: format, content: "backup", size: d.size/5 + 300*mib, ctime: at.Unix(), vmid: id,
			notes: notes, protected: protected, verified: map[bool]string{true: "ok"}[st.typ == "pbs"],
			subtype: g.kind, kind: g.kind, conf: cloneMap(g.conf),
		})
		return nil
	}), nil
}

// Create and restore

func (s *Server) createOrRestore(r *http.Request, n *node, kind string) (any, error) {
	id, err := strconv.Atoi(form(r, "vmid"))
	if err != nil || id < 100 || id > 999999999 {
		return nil, badParam("vmid", "value must have a minimum value of 100")
	}
	archive := form(r, "archive")
	if kind == "lxc" && formBool(r, "restore") {
		archive = form(r, "ostemplate")
	}
	if archive != "" && (kind == "qemu" || formBool(r, "restore")) {
		return s.restore(r, n, kind, id, archive)
	}
	if s.guests[id] != nil {
		return nil, fail(http.StatusInternalServerError, "unable to create %s %d - %s %d already exists on node '%s'", map[string]string{"qemu": "VM", "lxc": "CT"}[kind], id, map[string]string{"qemu": "VM", "lxc": "CT"}[kind], id, s.guests[id].node)
	}
	g := &guest{vmid: id, kind: kind, node: n.name, status: "stopped", conf: map[string]string{}, lock: "create",
		pending: map[string]string{}, pendingDel: map[string]bool{},
		fwOpts: map[string]string{"enable": "0", "policy_in": "DROP", "policy_out": "ACCEPT"}}
	skip := map[string]bool{"vmid": true, "start": true, "password": true, "ssh-public-keys": true, "storage": true, "pool": true, "ostemplate": true, "unique": true}
	if kind == "lxc" {
		tpl := form(r, "ostemplate")
		if _, ok := s.volume(n.name, tpl); !ok {
			return nil, fail(http.StatusInternalServerError, "volume '%s' does not exist", tpl)
		}
		g.conf["arch"] = "amd64"
		g.conf["ostype"] = "debian"
		for _, os := range []string{"ubuntu", "alpine", "debian", "rocky", "fedora", "archlinux"} {
			if strings.Contains(tpl, os) {
				g.conf["ostype"] = os
			}
		}
		if form(r, "hostname") == "" {
			g.conf["hostname"] = "CT" + strconv.Itoa(id)
		}
	} else if form(r, "name") == "" {
		g.conf["name"] = "VM" + strconv.Itoa(id)
	}
	for k := range r.PostForm {
		if skip[k] {
			continue
		}
		v := form(r, k)
		if (k == "name" || k == "hostname") && !dnsName.MatchString(v) {
			return nil, badParam(k, "value does not look like a valid DNS name")
		}
		if diskKey.MatchString(k) {
			nv, err := s.allocDisk(g, n, k, v)
			if err != nil {
				return nil, err
			}
			v = nv
			g.conf[k] = v // later disks see the earlier ones
		}
		if strings.HasPrefix(k, "net") {
			v = withMAC(kind, v)
		}
		if strings.HasPrefix(k, "ide") && strings.Contains(v, "media=cdrom") {
			iso := parseDisk(v).volid
			if iso != "none" && !strings.Contains(iso, "cloudinit") {
				if _, ok := s.volume(n.name, iso); !ok {
					return nil, fail(http.StatusInternalServerError, "volume '%s' does not exist", iso)
				}
			}
		}
		g.conf[k] = v
	}
	if kind == "lxc" && g.conf["rootfs"] == "" {
		return nil, badParam("rootfs", "property is missing and it is not optional")
	}
	if kind == "qemu" {
		g.conf["smbios1"] = "uuid=" + randHex(4) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(6)
		g.conf["vmgenid"] = randHex(4) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(6)
		if g.conf["cores"] == "" {
			g.conf["cores"] = "1"
		}
		if g.conf["memory"] == "" {
			g.conf["memory"] = "2048"
		}
	}
	start := formBool(r, "start")
	s.guests[id] = g
	typ := "qmcreate"
	lines := []string{}
	for _, k := range sortedKeys(g.conf) {
		if diskKey.MatchString(k) {
			lines = append(lines, "  Logical volume \""+parseDisk(g.conf[k]).volid+"\" created.")
		}
	}
	if kind == "lxc" {
		typ = "vzcreate"
		lines = append(lines, "extracting archive '"+form(r, "ostemplate")+"'", "Total bytes read: 524288000 (500MiB, 210MiB/s)", "Detected container architecture: amd64", "Creating SSH host key 'ssh_host_ed25519_key' - this may take some time ...", "done: SHA256:"+randHex(16)+" root@"+g.name())
	}
	t := s.runTask(n.name, typ, strconv.Itoa(id), 4*time.Second, lines, func() error {
		g.lock = ""
		if start {
			g.status, g.startedAt = "running", time.Now()
		}
		return nil
	})
	t.undo = func() { delete(s.guests, id) }
	return t.upid, nil
}

func (s *Server) restore(r *http.Request, n *node, kind string, id int, archive string) (any, error) {
	v, ok := s.volume(n.name, archive)
	if !ok || v.content != "backup" {
		return nil, fail(http.StatusInternalServerError, "volume '%s' does not exist", archive)
	}
	if v.kind != kind {
		return nil, fail(http.StatusInternalServerError, "the backup is of a %s, not a %s", v.kind, kind)
	}
	old := s.guests[id]
	if old != nil {
		if !formBool(r, "force") {
			return nil, fail(http.StatusInternalServerError, "unable to restore %s %d - %s %d already exists", old.noun(), id, old.noun(), id)
		}
		if old.running() {
			return nil, fail(http.StatusInternalServerError, "unable to restore %s %d - %s is running", old.noun(), id, old.noun())
		}
		if old.lock != "" {
			return nil, s.lockedErr(old)
		}
		if old.node != n.name {
			return nil, fail(http.StatusInternalServerError, "%s %d already exists on node '%s'", old.noun(), id, old.node)
		}
		old.lock = "create"
	}
	stName := form(r, "storage")
	if stName != "" && s.storageOn(stName, n.name) == nil {
		return nil, fail(http.StatusInternalServerError, "storage '%s' does not exist", stName)
	}
	conf := cloneMap(v.conf)
	unique := formBool(r, "unique")
	idx := 0
	for _, k := range sortedKeys(conf) {
		val := conf[k]
		if strings.HasPrefix(k, "unused") {
			delete(conf, k)
			continue
		}
		if strings.HasPrefix(k, "net") && unique {
			conf[k] = regexp.MustCompile(`([0-9A-F]{2}:){5}[0-9A-F]{2}`).ReplaceAllString(val, randMAC())
			continue
		}
		if !diskKey.MatchString(k) {
			continue
		}
		d := parseDisk(val)
		if d.storage == "" || d.volid == "none" || (d.cdrom && !strings.Contains(d.volid, "cloudinit")) {
			continue
		}
		st := d.storage
		if stName != "" {
			st = stName
		}
		if strings.Contains(d.volid, "cloudinit") {
			conf[k] = fmt.Sprintf("%s:vm-%d-cloudinit,media=cdrom", st, id)
			continue
		}
		_, rest, _ := strings.Cut(val, ",")
		conf[k] = fmt.Sprintf("%s:vm-%d-disk-%d,%s", st, id, idx, rest)
		idx++
	}
	delete(conf, "template")
	start := formBool(r, "start")
	typ := "qmrestore"
	if kind == "lxc" {
		typ = "vzrestore"
	}
	lines := []string{
		"restore " + map[bool]string{true: "proxmox backup", false: "vma archive"}[strings.HasPrefix(v.format, "pbs")] + " image: " + archive,
		"new volume ID is '" + strings.Split(conf[firstDisk(conf)], ",")[0] + "'",
	}
	for i := 1; i <= 5; i++ {
		lines = append(lines, fmt.Sprintf("progress %d%% (read %d GiB, zeroes = 31%%)", i*20, i))
	}
	lines = append(lines, "restore image complete")
	if unique {
		lines = append(lines, "  regenerating MAC addresses")
	}
	t := s.runTask(n.name, typ, strconv.Itoa(id), 6*time.Second, lines, func() error {
		g := &guest{vmid: id, kind: kind, node: n.name, status: "stopped", conf: conf,
			pending: map[string]string{}, pendingDel: map[string]bool{},
			fwOpts: map[string]string{"enable": "0", "policy_in": "DROP", "policy_out": "ACCEPT"}}
		if old != nil {
			g.rules, g.fwOpts = old.rules, old.fwOpts
		}
		if start {
			g.status, g.startedAt = "running", time.Now()
		}
		s.guests[id] = g
		return nil
	})
	if old != nil {
		t.undo = func() { old.lock = "" }
	}
	return t.upid, nil
}

func firstDisk(conf map[string]string) string {
	for _, k := range []string{"scsi0", "virtio0", "sata0", "ide0", "rootfs"} {
		if _, ok := conf[k]; ok {
			return k
		}
	}
	return ""
}

// seedVolumes fills the storages with ISOs, templates and a week of backups.
func (s *Server) seedVolumes(now time.Time) {
	add := func(key string, v *volume) { s.volumes[key] = append(s.volumes[key], v) }
	isos := []struct {
		name string
		gb   float64
	}{{"ubuntu-24.04.1-live-server-amd64.iso", 2.6}, {"debian-12.8.0-amd64-netinst.iso", 0.63}, {"virtio-win-0.1.262.iso", 0.7}}
	for i, iso := range isos {
		add("nfs-iso", &volume{volid: "nfs-iso:iso/" + iso.name, format: "iso", content: "iso", size: int64(iso.gb * float64(gib)), ctime: now.Add(-time.Duration(30+i) * 24 * time.Hour).Unix()})
	}
	for _, n := range s.nodes {
		add(n.name+"/local", &volume{volid: "local:iso/virtio-win-0.1.262.iso", format: "iso", content: "iso", size: 700 * mib, ctime: now.Add(-60 * 24 * time.Hour).Unix()})
		for _, t := range []string{"debian-12-standard_12.7-1_amd64.tar.zst", "ubuntu-24.04-standard_24.04-2_amd64.tar.zst", "alpine-3.20-default_20240908_amd64.tar.xz"} {
			add(n.name+"/local", &volume{volid: "local:vztmpl/" + t, format: "tzst", content: "vztmpl", size: 120 * mib, ctime: now.Add(-45 * 24 * time.Hour).Unix()})
		}
	}
	add("nfs-iso", &volume{volid: "nfs-iso:vztmpl/rockylinux-9-default_20240912_amd64.tar.xz", format: "txz", content: "vztmpl", size: 98 * mib, ctime: now.Add(-20 * 24 * time.Hour).Unix()})

	pbs := s.storageOn("pbs", "")
	day := 24 * time.Hour
	for d := 6; d >= 1; d-- {
		at := now.Add(-time.Duration(d) * day).Truncate(day).Add(time.Hour + 30*time.Minute)
		for _, id := range []int{100, 101, 103, 104} {
			if d == 2 && id == 101 {
				continue // that night's backup failed
			}
			g := s.guests[id]
			volid, format, _ := backupVolid(pbs, g, at, "zstd")
			_, disk := g.bootDisk()
			add("pbs", &volume{volid: volid, format: format, content: "backup", size: disk.size/5 + int64(d)*40*mib, ctime: at.Unix(), vmid: id,
				notes: g.name() + " nightly", verified: "ok", subtype: g.kind, kind: g.kind, conf: cloneMap(g.conf), protected: d == 6 && id == 101})
			at = at.Add(4 * time.Minute)
		}
	}
	g := s.guests[102]
	at := now.Add(-3 * day)
	volid, format, _ := backupVolid(s.storageOn("local", "pve2"), g, at, "zstd")
	add("pve2/local", &volume{volid: volid, format: format, content: "backup", size: 18 * gib, ctime: at.Unix(), vmid: 102,
		notes: "Before the domain upgrade", protected: true, kind: g.kind, subtype: g.kind, conf: cloneMap(g.conf)})
}
