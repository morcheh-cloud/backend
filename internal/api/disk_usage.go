package api

import (
	"cmp"
	"context"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/pkg/sftp"

	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

// ---- Types ----

type DiskUsage struct {
	Path   string `json:"path" example:"/var"`
	Parent string `json:"parent" doc:"Empty at /"`
	Size   int64  `json:"size" doc:"Bytes on disk under path, on its own filesystem"`
	// Biggest first.
	Entries    []UsageEntry `json:"entries"`
	More       int          `json:"more" doc:"Smallest entries left out of the list"`
	MoreSize   int64        `json:"more_size" doc:"Bytes in the entries left out"`
	Disk       *UsageDisk   `json:"disk" doc:"The filesystem path lives on; null when df failed"`
	Unreadable int          `json:"unreadable" doc:"Folders du couldn't read: their bytes are missing"`
	Access     string       `json:"access" enum:"root,sudo,user" doc:"Who scanned: as root, through sudo or as the login user"`
	DurationMs int64        `json:"duration_ms"`
}

type UsageEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type" enum:"file,dir,symlink,other"`
	Size int64  `json:"size" doc:"Bytes on disk"`
	// du -x doesn't cross into other filesystems, so their sizes aren't in
	// this folder's total.
	Mount string `json:"mount" doc:"Filesystem type when this is another filesystem's mount point (its bytes aren't counted here); empty otherwise"`
}

type UsageDisk struct {
	Mount     string `json:"mount" example:"/"`
	Device    string `json:"device" example:"/dev/sda1"`
	Type      string `json:"type" example:"ext4"`
	Size      int64  `json:"size"`
	Used      int64  `json:"used"`
	Available int64  `json:"available"`
}

const (
	maxUsageEntries = 500
	usageTimeout    = 5 * time.Minute
)

// ---- Handler ----

func registerDiskUsage(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "disk-usage",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/files/usage",
		Summary:     "What takes the space in a folder",
		Description: "Runs `du -x` one level deep (as root when the login user can) and `df` for the filesystem. " +
			"Stays on path's filesystem: other disks mounted below it are flagged, not counted. Big trees can take minutes.",
		Tags: []string{"Files"},
	}, func(ctx context.Context, in *FilePathQuery) (*struct{ Body DiskUsage }, error) {
		out := &struct{ Body DiskUsage }{}
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			_, p, err := resolvePath(s, in.Path)
			if err != nil {
				return err
			}
			fi, err := s.Stat(p)
			if err != nil {
				return fsError(p, err)
			}
			if !fi.IsDir() {
				return huma.Error422UnprocessableEntity("Not a folder: " + p)
			}
			infos, _ := s.ReadDir(p)

			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			q := terminal.ShellQuote(p)
			res, err := sh.exec(ctx, "df -Pk -- "+q+" 2>/dev/null | tail -n 1 | sed 's/^/@df /'\n"+
				"echo @mounts; cat /proc/mounts 2>/dev/null\n"+
				"echo @du; du -xak -d 1 -- "+q+" 2>&1\n", usageTimeout, 16<<20)
			if err != nil {
				return err
			}
			if res.timedOut {
				return huma.Error504GatewayTimeout("Scanning took too long. Open a smaller folder.")
			}
			out.Body = parseUsage(p, string(res.output), infos)
			out.Body.Access = sh.priv.access()
			out.Body.DurationMs = res.duration.Milliseconds()
			if p != "/" {
				out.Body.Parent = path.Dir(p)
			}
			if out.Body.Size == 0 && len(out.Body.Entries) == 0 && out.Body.Unreadable == 0 && res.code != 0 {
				return huma.Error502BadGateway("du failed: " + lastLines(string(res.output), 2))
			}
			return nil
		})
		return out, toProblem(err)
	})
}

// parseUsage reads the script's output: an @df line, /proc/mounts after
// @mounts and du's lines (and errors) after @du.
func parseUsage(dir, out string, infos []os.FileInfo) DiskUsage {
	u := DiskUsage{Path: dir, Entries: []UsageEntry{}}
	types := make(map[string]string, len(infos))
	for _, fi := range infos {
		types[fi.Name()] = fileType(fi.Mode())
	}
	mounts := map[string]string{} // mount point → fs type (the last mount wins)
	var df []string
	section := ""
	for line := range strings.SplitSeq(out, "\n") {
		switch {
		case strings.HasPrefix(line, "@df "):
			df = strings.Fields(line[4:])
			continue
		case line == "@mounts" || line == "@du":
			section = line
			continue
		case line == "":
			continue
		}
		switch section {
		case "@mounts":
			f := strings.Fields(line)
			if len(f) >= 3 {
				mounts[unescapeMount(f[1])] = f[2]
			}
		case "@du":
			if strings.HasPrefix(line, "du:") {
				u.Unreadable++
				continue
			}
			size, name, ok := strings.Cut(line, "\t")
			kb, err := strconv.ParseInt(size, 10, 64)
			if !ok || err != nil {
				continue
			}
			p := path.Clean(name)
			if p == dir {
				u.Size = kb * 1024
				continue
			}
			if path.Dir(p) != dir {
				continue
			}
			e := UsageEntry{Name: path.Base(p), Path: p, Size: kb * 1024, Type: "other"}
			if t, ok := types[e.Name]; ok {
				e.Type = t
			}
			e.Mount = mounts[p]
			u.Entries = append(u.Entries, e)
		}
	}
	// GNU du -x leaves other filesystems' mount points out entirely.
	for name := range types {
		p := path.Join(dir, name)
		if fs, ok := mounts[p]; ok && !slices.ContainsFunc(u.Entries, func(e UsageEntry) bool { return e.Path == p }) {
			u.Entries = append(u.Entries, UsageEntry{Name: name, Path: p, Type: types[name], Mount: fs})
		}
	}
	// df -P: device, 1024-blocks, used, available, capacity, mount point.
	if len(df) >= 6 {
		size, err1 := strconv.ParseInt(df[1], 10, 64)
		used, err2 := strconv.ParseInt(df[2], 10, 64)
		avail, err3 := strconv.ParseInt(df[3], 10, 64)
		if err1 == nil && err2 == nil && err3 == nil {
			mount := strings.Join(df[5:], " ")
			u.Disk = &UsageDisk{
				Mount: mount, Device: df[0], Type: mounts[mount],
				Size: size * 1024, Used: used * 1024, Available: avail * 1024,
			}
		}
	}
	slices.SortFunc(u.Entries, func(a, b UsageEntry) int {
		return cmp.Or(cmp.Compare(b.Size, a.Size), strings.Compare(a.Name, b.Name))
	})
	if len(u.Entries) > maxUsageEntries {
		for _, e := range u.Entries[maxUsageEntries:] {
			u.MoreSize += e.Size
		}
		u.More = len(u.Entries) - maxUsageEntries
		u.Entries = u.Entries[:maxUsageEntries]
	}
	return u
}

func fileType(m os.FileMode) string {
	switch {
	case m.IsDir():
		return "dir"
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m.IsRegular():
		return "file"
	}
	return "other"
}

// /proc/mounts escapes spaces, tabs, newlines and backslashes as \ooo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
