package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/pkg/sftp"

	"github.com/morche/backend/internal/cmdlog"
	"github.com/morche/backend/internal/docker"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/terminal"
)

// A volume's files, browsed as root on the server that holds them. Paths in
// these requests are relative to the volume: "/" is its top. Everything is
// resolved on the server (symlinks included) and refused when it leads
// outside the volume, so a link a container made (to /etc, say) can't be
// used to reach the host's files.

const (
	dockerVolumeMoveKind = "docker-volume-move"
	dockerVolumeCopyKind = "docker-volume-copy"
	// A root sftp-server nobody used for this long is closed.
	volumeClientIdle = 2 * time.Minute
	volumeCopyLimit  = 12 * time.Hour
)

var errOutsideVolume = huma.Error422UnprocessableEntity("That leads outside the volume")

const volumeNeedsRoot = "Browsing this volume's files needs root: give the login user sudo, or sign in as root."

// volFS is one volume's files for one request.
type volFS struct {
	h     *serverHandler
	id    string
	name  string
	c     *sshpool.Conn
	s     *sftp.Client
	sh    *rootShell
	mount string // the volume's real folder on the server
	// acquire keeps the SFTP session open past the request (a download
	// streams after the handler returns). Call what it returns when done.
	acquire func() func()
}

type VolumeFilePathQuery struct {
	DockerVolumePath
	Path string `query:"path" doc:"Inside the volume; / or empty is its top" example:"/conf"`
}

type VolumeDownloadInput struct {
	DockerVolumePath
	Paths  []string `query:"path,explode" required:"true" minItems:"1" doc:"Inside the volume; repeat for several"`
	Inline bool     `query:"inline" doc:"Show in the browser instead of saving (images, media, PDF, plain text only)"`
	Name   string   `query:"name" doc:"File name for a zip of several paths"`
}

type VolumeUploadInput struct {
	DockerVolumePath
	Path      string `query:"path" required:"true" doc:"Destination inside the volume, including the file name"`
	Overwrite bool   `query:"overwrite" doc:"Replace an existing file"`
	body      io.Reader
	length    int64
}

func (in *VolumeUploadInput) Resolve(ctx huma.Context) []error {
	in.body = ctx.BodyReader()
	in.length, _ = strconv.ParseInt(ctx.Header("Content-Length"), 10, 64)
	return nil
}

// volumeTransferParams is a copy or move inside one volume.
type volumeTransferParams struct {
	ServerID    string   `json:"server_id"`
	Volume      string   `json:"volume"`
	Paths       []string `json:"paths"`
	Destination string   `json:"destination"`
}

// ---- Registration ----

func registerDockerVolumeFiles(api huma.API, h *serverHandler) {
	tags := []string{"Docker"}
	base := "/servers/{id}/docker/volumes/{volume}/files"

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-volume-files",
		Method:      http.MethodGet,
		Path:        base,
		Summary:     "List a folder in a volume",
		Description: "As root (through sudo when needed). Paths are inside the volume; owners are numbers, since a container's users aren't the server's.",
		Tags:        tags,
	}, func(ctx context.Context, in *VolumeFilePathQuery) (*struct{ Body DirListing }, error) {
		out := &struct{ Body DirListing }{}
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			rel := cleanRel(in.Path)
			abs, err := v.real(rel)
			if err != nil {
				return err
			}
			fi, err := v.s.Stat(abs)
			if err != nil {
				return fsError(rel, err)
			}
			if !fi.IsDir() {
				return huma.Error422UnprocessableEntity("Not a folder: " + rel)
			}
			infos, err := v.s.ReadDir(abs)
			if err != nil {
				return fsError(rel, err)
			}
			rel = v.rel(abs)
			out.Body = DirListing{Path: rel, Home: "/", Entries: v.entries(abs, infos)}
			if rel != "/" {
				out.Body.Parent = path.Dir(rel)
			}
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "stat-docker-volume-file",
		Method:      http.MethodGet,
		Path:        base + "/stat",
		Summary:     "Details of one file or folder in a volume",
		Tags:        tags,
	}, func(ctx context.Context, in *VolumeFilePathQuery) (*FileEntryOutput, error) {
		out := &FileEntryOutput{}
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			abs, err := v.place(cleanRel(in.Path))
			if err != nil {
				return err
			}
			out.Body, err = v.stat(abs)
			return err
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "docker-volume-folder-size",
		Method:      http.MethodGet,
		Path:        base + "/size",
		Summary:     "Total size of a folder in a volume",
		Tags:        tags,
	}, func(ctx context.Context, in *VolumeFilePathQuery) (*struct{ Body FolderSize }, error) {
		out := &struct{ Body FolderSize }{}
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			rel := cleanRel(in.Path)
			abs, err := v.real(rel)
			if err != nil {
				return err
			}
			res, err := v.sh.exec(ctx, "du -sk -- "+terminal.ShellQuote(abs)+" 2>/dev/null", execTimeout, 4096)
			if err != nil {
				return err
			}
			if res.timedOut {
				return huma.Error504GatewayTimeout("The server took too long")
			}
			fields := strings.Fields(string(res.output))
			if len(fields) == 0 {
				return huma.Error422UnprocessableEntity("du printed nothing")
			}
			kb, err := strconv.ParseInt(fields[0], 10, 64)
			if err != nil {
				return fmt.Errorf("du: %w", err)
			}
			out.Body = FolderSize{Path: v.rel(abs), Size: kb * 1024}
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "docker-volume-disk-usage",
		Method:      http.MethodGet,
		Path:        base + "/usage",
		Summary:     "What takes the space in a volume's folder",
		Description: "Runs `du -x` one level deep as root, like the server's disk usage.",
		Tags:        tags,
	}, func(ctx context.Context, in *VolumeFilePathQuery) (*struct{ Body DiskUsage }, error) {
		out := &struct{ Body DiskUsage }{}
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			rel := cleanRel(in.Path)
			abs, err := v.real(rel)
			if err != nil {
				return err
			}
			fi, err := v.s.Stat(abs)
			if err != nil {
				return fsError(rel, err)
			}
			if !fi.IsDir() {
				return huma.Error422UnprocessableEntity("Not a folder: " + rel)
			}
			infos, _ := v.s.ReadDir(abs)
			q := terminal.ShellQuote(abs)
			res, err := v.sh.exec(ctx, "df -Pk -- "+q+" 2>/dev/null | tail -n 1 | sed 's/^/@df /'\n"+
				"echo @mounts; cat /proc/mounts 2>/dev/null\n"+
				"echo @du; du -xak -d 1 -- "+q+" 2>&1\n", usageTimeout, 16<<20)
			if err != nil {
				return err
			}
			if res.timedOut {
				return huma.Error504GatewayTimeout("Scanning took too long. Open a smaller folder.")
			}
			u := parseUsage(abs, string(res.output), infos)
			u.Path = v.rel(abs)
			for i := range u.Entries {
				u.Entries[i].Path = v.rel(u.Entries[i].Path)
			}
			if u.Path != "/" {
				u.Parent = path.Dir(u.Path)
			}
			u.Access = v.sh.priv.access()
			u.DurationMs = res.duration.Milliseconds()
			out.Body = u
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "read-docker-volume-file",
		Method:      http.MethodGet,
		Path:        base + "/content",
		Summary:     "Read a text file in a volume",
		Description: "For the editor: UTF-8 text up to 5 MB. Bigger files are 413, binary ones 415.",
		Tags:        tags,
	}, func(ctx context.Context, in *VolumeFilePathQuery) (*struct{ Body FileContent }, error) {
		out := &struct{ Body FileContent }{}
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			rel := cleanRel(in.Path)
			abs, err := v.real(rel)
			if err != nil {
				return err
			}
			f, err := v.s.Open(abs)
			if err != nil {
				return fsError(rel, err)
			}
			defer f.Close()
			fi, err := f.Stat()
			if err != nil {
				return fsError(rel, err)
			}
			if fi.IsDir() {
				return huma.Error422UnprocessableEntity("That's a folder: " + rel)
			}
			if fi.Size() > maxEditable {
				return huma.NewError(http.StatusRequestEntityTooLarge, "Files over 5 MB can't be opened in the editor. Download it instead.")
			}
			var buf bytes.Buffer
			if _, err := f.WriteTo(&buf); err != nil {
				return fsError(rel, err)
			}
			data := buf.Bytes()
			if !isText(data) {
				return huma.NewError(http.StatusUnsupportedMediaType, "This looks like a binary file. Download it instead.")
			}
			out.Body = FileContent{Path: v.rel(abs), Content: string(data), Size: int64(len(data)), Modified: fi.ModTime()}
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID:  "write-docker-volume-file",
		Method:       http.MethodPut,
		Path:         base + "/content",
		Summary:      "Save a text file in a volume",
		Description:  "Overwrites the file in place, keeping its owner and permissions. With expected_modified, refuses (409) if the file changed since it was read. With create, makes a new file.",
		Tags:         tags,
		MaxBodyBytes: maxEditable + 1<<20,
	}, func(ctx context.Context, in *struct {
		DockerVolumePath
		Body struct {
			Path             string     `json:"path" minLength:"1"`
			Content          string     `json:"content"`
			ExpectedModified *time.Time `json:"expected_modified,omitempty"`
			Create           bool       `json:"create,omitempty"`
		}
	}) (*FileEntryOutput, error) {
		out := &FileEntryOutput{}
		b := in.Body
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			rel := cleanRel(b.Path)
			var abs string
			var err error
			flags := os.O_WRONLY | os.O_TRUNC
			if b.Create {
				if abs, err = v.place(rel); err != nil {
					return err
				}
				if _, err := v.s.Lstat(abs); err == nil {
					return huma.Error409Conflict(path.Base(rel) + " already exists")
				}
				flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
			} else {
				if abs, err = v.real(rel); err != nil {
					return err
				}
				fi, err := v.s.Stat(abs)
				if err != nil {
					return fsError(rel, err)
				}
				if fi.IsDir() {
					return huma.Error422UnprocessableEntity("That's a folder: " + rel)
				}
				if b.ExpectedModified != nil && fi.ModTime().Unix() != b.ExpectedModified.Unix() {
					return huma.Error409Conflict("The file changed on the server since you opened it.")
				}
			}
			err = v.logged(ctx, "write "+v.rel(abs), func() error {
				f, err := v.s.OpenFile(abs, flags)
				if err != nil {
					return fsError(rel, err)
				}
				if _, err := f.ReadFrom(strings.NewReader(b.Content)); err != nil {
					f.Close()
					return fsError(rel, err)
				}
				return f.Close()
			})
			if err != nil {
				return err
			}
			out.Body, err = v.stat(abs)
			return err
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "download-docker-volume-files",
		Method:      http.MethodGet,
		Path:        base + "/download",
		Summary:     "Download files from a volume",
		Description: "One file streams as itself (with Range support). Several paths, or a folder, stream as one zip.",
		Tags:        tags,
		Responses: map[string]*huma.Response{
			"200": {
				Description: "The file, or a zip of everything asked for",
				Content:     map[string]*huma.MediaType{"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}}},
			},
		},
	}, h.downloadVolumeFiles)

	huma.Register(api, huma.Operation{
		OperationID: "upload-docker-volume-file",
		Method:      http.MethodPut,
		Path:        base + "/upload",
		Summary:     "Upload a file into a volume",
		Description: "The raw body is the file, written next to the destination and renamed into place once complete. Missing folders are created. An existing file is 409 unless overwrite is set.",
		Tags:        tags,
		RequestBody: &huma.RequestBody{
			Required: true,
			Content:  map[string]*huma.MediaType{"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}}},
		},
	}, h.uploadVolumeFile)

	huma.Register(api, huma.Operation{
		OperationID: "make-docker-volume-folder",
		Method:      http.MethodPost,
		Path:        base + "/mkdir",
		Summary:     "Create a folder in a volume",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerVolumePath
		Body struct {
			Path string `json:"path" minLength:"1"`
		}
	}) (*FileEntryOutput, error) {
		out := &FileEntryOutput{}
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			rel := cleanRel(in.Body.Path)
			abs, err := v.place(rel)
			if err != nil {
				return err
			}
			if _, err := v.s.Lstat(abs); err == nil {
				return huma.Error409Conflict(path.Base(rel) + " already exists")
			}
			if err := v.logged(ctx, "mkdir -p "+v.rel(abs), func() error {
				return fsErrorOr(rel, v.s.MkdirAll(abs))
			}); err != nil {
				return err
			}
			out.Body, err = v.stat(abs)
			return err
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "rename-docker-volume-file",
		Method:      http.MethodPost,
		Path:        base + "/rename",
		Summary:     "Rename or move one file or folder in a volume",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerVolumePath
		Body struct {
			From string `json:"from" minLength:"1"`
			To   string `json:"to" minLength:"1"`
		}
	}) (*FileEntryOutput, error) {
		out := &FileEntryOutput{}
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			from, err := v.place(cleanRel(in.Body.From))
			if err != nil {
				return err
			}
			to, err := v.place(cleanRel(in.Body.To))
			if err != nil {
				return err
			}
			if from == v.mount || to == v.mount {
				return huma.Error422UnprocessableEntity("The volume's top folder can't be renamed")
			}
			if from != to {
				if err := v.move(ctx, from, to); err != nil {
					return err
				}
			}
			out.Body, err = v.stat(to)
			return err
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-docker-volume-files",
		Method:      http.MethodPost,
		Path:        base + "/delete",
		Summary:     "Delete files and folders in a volume",
		Description: "Folders go with everything in them. The volume's top folder is refused.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerVolumePath
		Body FilePathsBody
	}) (*AffectedOutput, error) {
		var n int64
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			paths, err := v.places(in.Body.Paths)
			if err != nil {
				return err
			}
			for _, p := range paths {
				if p == v.mount {
					return huma.Error422UnprocessableEntity("Refusing to delete the whole volume's folder: delete what's inside it instead")
				}
			}
			if _, err := v.sh.run(ctx, "rm -rf -- "+quoteAll(paths)); err != nil {
				return err
			}
			n = int64(len(paths))
			return nil
		})
		return affected(n), err
	})

	huma.Register(api, huma.Operation{
		OperationID: "chmod-docker-volume-files",
		Method:      http.MethodPost,
		Path:        base + "/chmod",
		Summary:     "Change permissions in a volume",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerVolumePath
		Body struct {
			FilePathsBody
			Mode      string `json:"mode" pattern:"^[0-7]{3,4}$" example:"0644"`
			Recursive bool   `json:"recursive,omitempty"`
		}
	}) (*AffectedOutput, error) {
		var n int64
		b := in.Body
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			paths, err := v.reals(b.Paths)
			if err != nil {
				return err
			}
			// GNU chmod -R never follows the links it meets on the way.
			flags := ""
			if b.Recursive {
				flags = "-R "
			}
			if _, err := v.sh.run(ctx, "chmod "+flags+b.Mode+" -- "+quoteAll(paths)); err != nil {
				return err
			}
			n = int64(len(paths))
			return nil
		})
		return affected(n), err
	})

	huma.Register(api, huma.Operation{
		OperationID: "chown-docker-volume-files",
		Method:      http.MethodPost,
		Path:        base + "/chown",
		Summary:     "Change owner and group in a volume",
		Description: "Owners are best given as numbers (uid/gid): a container's users aren't the server's.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerVolumePath
		Body struct {
			FilePathsBody
			Owner     string `json:"owner,omitempty" doc:"uid or user name; empty keeps it"`
			Group     string `json:"group,omitempty" doc:"gid or group name; empty keeps it"`
			Recursive bool   `json:"recursive,omitempty"`
		}
	}) (*AffectedOutput, error) {
		var n int64
		b := in.Body
		if b.Owner == "" && b.Group == "" {
			return nil, fieldError("body.owner", "Choose an owner or a group", b.Owner)
		}
		for loc, val := range map[string]string{"body.owner": b.Owner, "body.group": b.Group} {
			if val != "" && !accountRe.MatchString(val) {
				return nil, fieldError(loc, "Not a valid user or group", val)
			}
		}
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			paths, err := v.reals(b.Paths)
			if err != nil {
				return err
			}
			spec := b.Owner
			if b.Group != "" {
				spec += ":" + b.Group
			}
			// -h: links met inside folders change themselves, never what they point at.
			flags := "-h "
			if b.Recursive {
				flags = "-hR "
			}
			if _, err := v.sh.run(ctx, "chown "+flags+"-- "+terminal.ShellQuote(spec)+" "+quoteAll(paths)); err != nil {
				return err
			}
			n = int64(len(paths))
			return nil
		})
		return affected(n), err
	})

	huma.Register(api, huma.Operation{
		OperationID: "search-docker-volume-files",
		Method:      http.MethodGet,
		Path:        base + "/search",
		Summary:     "Find files by name in a volume",
		Description: "Case-insensitive name match anywhere under path, up to 200 results.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		VolumeFilePathQuery
		Query string `query:"q" minLength:"1" maxLength:"200" doc:"Part of the name; * and ? work as wildcards"`
	}) (*struct{ Body SearchResult }, error) {
		out := &struct{ Body SearchResult }{SearchResult{Items: []FileEntry{}}}
		err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
			abs, err := v.real(cleanRel(in.Path))
			if err != nil {
				return err
			}
			pattern := in.Query
			if !strings.ContainsAny(pattern, "*?") {
				pattern = "*" + escapeGlob(pattern) + "*"
			}
			res, err := v.sh.exec(ctx, "find "+terminal.ShellQuote(abs)+" -iname "+terminal.ShellQuote(pattern)+
				" -print 2>/dev/null | head -n "+strconv.Itoa(maxSearch+1), 30*time.Second, 4<<20)
			if err != nil {
				return err
			}
			var found []string
			for line := range strings.SplitSeq(string(res.output), "\n") {
				if line != "" && line != abs && v.inside(line) {
					found = append(found, line)
				}
			}
			if len(found) > maxSearch {
				found, out.Body.Truncated = found[:maxSearch], true
			}
			if res.timedOut {
				out.Body.Truncated = true
			}
			for _, e := range statMany(v.c, v.s, found) {
				v.fix(&e)
				out.Body.Items = append(out.Body.Items, e)
			}
			return nil
		})
		return out, err
	})

	for _, kind := range []string{"move", "copy"} {
		jobKind := dockerVolumeMoveKind
		summary := "Move files inside a volume"
		if kind == "copy" {
			jobKind, summary = dockerVolumeCopyKind, "Copy files inside a volume"
		}
		huma.Register(api, huma.Operation{
			OperationID:   kind + "-docker-volume-files",
			Method:        http.MethodPost,
			Path:          base + "/" + kind,
			Summary:       summary,
			Description:   "Starts a background job. Copies into the same folder get a free \"copy\" name; any other clash is 409.",
			Tags:          tags,
			DefaultStatus: http.StatusAccepted,
		}, func(ctx context.Context, in *struct {
			DockerVolumePath
			Body TransferFilesBody
		}) (*JobOutput, error) {
			return h.submitVolumeTransfer(ctx, in.ID, in.Volume, jobKind, in.Body)
		})
	}
	h.jobs.Handle(dockerVolumeMoveKind, h.runVolumeTransfer)
	h.jobs.Handle(dockerVolumeCopyKind, h.runVolumeTransfer)
}

// ---- Opening a volume ----

// withVolume finds the volume, opens its files (as root where it can) and
// runs fn. Errors come back as problems.
func (h *serverHandler) withVolume(ctx context.Context, id, name string, fn func(v *volFS) error) error {
	notFound := huma.Error404NotFound("There's no volume " + name + " on this server")
	if !volumeNamePattern.MatchString(name) {
		return notFound
	}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		e, err := h.engine(ctx, id, c)
		if err != nil {
			return err
		}
		vol, err := e.client.InspectVolume(ctx, name)
		if err != nil {
			var de *docker.Error
			if errors.As(err, &de) && de.Status == http.StatusNotFound {
				return notFound
			}
			return err
		}
		if vol.Mountpoint == "" || (vol.Driver != "" && vol.Driver != "local") {
			return huma.Error422UnprocessableEntity(fmt.Sprintf(
				"The %s driver keeps this volume's files elsewhere, so they can't be browsed from the server.", cmpOr(vol.Driver, "volume")))
		}
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		s, acquire, err := h.volumeSFTP(ctx, id, c, sh)
		if err != nil {
			return err
		}
		release := acquire()
		defer release()
		mount, err := s.RealPath(vol.Mountpoint)
		switch {
		case err == nil:
		case errors.Is(err, os.ErrPermission) || (sh.priv == privUser && !errors.Is(err, os.ErrNotExist)):
			return huma.Error403Forbidden(volumeNeedsRoot)
		case errors.Is(err, os.ErrNotExist):
			return huma.Error404NotFound("This volume's folder isn't on the server")
		default:
			return fsError("/", err)
		}
		return fn(&volFS{h: h, id: id, name: name, c: c, s: s, sh: sh, mount: mount, acquire: acquire})
	})
	return dockerProblem(err)
}

// volumeSFTP returns an SFTP client that reads as root: the login's own when
// it is root (or can't be anything else, e.g. rootless Docker), otherwise a
// sftp-server started through sudo.
func (h *serverHandler) volumeSFTP(ctx context.Context, id string, c *sshpool.Conn, sh *rootShell) (*sftp.Client, func() func(), error) {
	if sh.priv == privRoot || sh.priv == privUser {
		s, err := c.SFTP()
		if err != nil {
			return nil, nil, huma.Error502BadGateway("The server doesn't offer SFTP: " + err.Error())
		}
		return s, func() func() { return func() {} }, nil
	}
	e, err := h.volClients.get(ctx, id, c, sh)
	if err != nil {
		return nil, nil, err
	}
	return e.s, func() func() { return h.volClients.acquire(e) }, nil
}

// volumeClients keeps root sftp-servers open between requests: starting one
// through sudo takes a round trip or two.
type volumeClients struct {
	mu sync.Mutex
	m  map[string]*volClient
}

type volClient struct {
	conn *sshpool.Conn
	s    *sftp.Client
	refs int
	last time.Time
	gone chan struct{}
}

func (e *volClient) dead() bool {
	select {
	case <-e.gone:
		return true
	default:
		return false
	}
}

func (vc *volumeClients) get(ctx context.Context, id string, c *sshpool.Conn, sh *rootShell) (*volClient, error) {
	// One per person, so the command log says who browsed.
	key := id
	if u := cmdlog.Of(ctx).UserID; u != nil {
		key += "/" + u.String()
	}
	vc.mu.Lock()
	if e := vc.m[key]; e != nil && e.conn == c && !e.dead() {
		e.last = time.Now()
		vc.mu.Unlock()
		return e, nil
	}
	vc.mu.Unlock()

	e, err := openVolClient(ctx, c, sh)
	if err != nil {
		return nil, err
	}
	vc.mu.Lock()
	defer vc.mu.Unlock()
	if old := vc.m[key]; old != nil && old.conn == c && !old.dead() {
		go e.s.Close() // another request opened one meanwhile
		return old, nil
	}
	if vc.m == nil {
		vc.m = map[string]*volClient{}
	}
	vc.m[key] = e // an older one is closed by its own watch once unused
	go vc.watch(key, e)
	return e, nil
}

func (vc *volumeClients) acquire(e *volClient) func() {
	vc.mu.Lock()
	e.refs++
	e.last = time.Now()
	vc.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			vc.mu.Lock()
			e.refs--
			e.last = time.Now()
			vc.mu.Unlock()
		})
	}
}

// watch closes e once it has been unused for a while (or replaced), and
// forgets it when its session ends on its own.
func (vc *volumeClients) watch(key string, e *volClient) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.gone:
			vc.mu.Lock()
			if vc.m[key] == e {
				delete(vc.m, key)
			}
			vc.mu.Unlock()
			return
		case <-t.C:
			vc.mu.Lock()
			current := vc.m[key] == e
			idle := e.refs == 0 && (!current || time.Since(e.last) > volumeClientIdle)
			if idle && current {
				delete(vc.m, key)
			}
			vc.mu.Unlock()
			if idle {
				e.s.Close() // stdin closes, sftp-server exits, the session ends
				return
			}
		}
	}
}

// The server's own sftp-server, wherever its packages put it.
const volumeSFTPScript = `for p in "$(awk 'tolower($1)=="subsystem" && $2=="sftp" {print $3; exit}' /etc/ssh/sshd_config 2>/dev/null)" ` +
	`/usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/sftp-server ` +
	`/usr/lib/sftp-server /usr/local/libexec/sftp-server /usr/local/libexec/openssh/sftp-server; do ` +
	`[ -n "$p" ] && [ -x "$p" ] && exec "$p"; done; echo "The server has no sftp-server program, which reading a volume as root needs. Install the openssh-sftp-server package (apt, dnf, apk) and try again." >&2; exit 127`

func openVolClient(ctx context.Context, c *sshpool.Conn, sh *rootShell) (*volClient, error) {
	sess, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	sess.Script = "sftp-server  # a Docker volume's files, as root"
	sess.AsRoot, sess.NoStdout = true, true
	errs := &cappedBuffer{limit: 4096}
	sess.Stderr = errs
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	cmd := "sudo -n sh -c " + terminal.ShellQuote(volumeSFTPScript)
	if sh.priv == privSudoPassword {
		// -k: always read the password, so it never ends up in sftp's stream.
		cmd = "sudo -k -S -p '' sh -c " + terminal.ShellQuote(volumeSFTPScript)
	}
	if err := sess.Start(cmd); err != nil {
		sess.Close()
		return nil, err
	}
	if sh.priv == privSudoPassword {
		if _, err := io.WriteString(stdin, sh.password+"\n"); err != nil {
			sess.Close()
			return nil, err
		}
	}

	type result struct {
		s   *sftp.Client
		err error
	}
	ready := make(chan result, 1)
	go func() {
		s, err := sftp.NewClientPipe(stdout, stdin, sftp.UseConcurrentReads(true), sftp.UseConcurrentWrites(true))
		ready <- result{s, err}
	}()
	var r result
	select {
	case r = <-ready:
	case <-time.After(20 * time.Second):
		r.err = errors.New("no answer")
	}
	if r.err != nil {
		sess.Close()
		msg, _ := errs.bytes()
		if text := strings.TrimSpace(string(msg)); text != "" {
			return nil, huma.Error422UnprocessableEntity(lastLines(text, 2))
		}
		return nil, huma.Error422UnprocessableEntity("Couldn't open the volume as root: " + r.err.Error())
	}
	e := &volClient{conn: c, s: r.s, last: time.Now(), gone: make(chan struct{})}
	go func() {
		_ = sess.Wait()
		r.s.Close()
		close(e.gone)
	}()
	return e, nil
}

// ---- Paths ----

// cleanRel makes a path inside the volume clean and absolute ("/" = top).
func cleanRel(p string) string {
	return path.Clean("/" + strings.TrimSpace(p))
}

func (v *volFS) inside(abs string) bool {
	return abs == v.mount || strings.HasPrefix(abs, v.mount+"/")
}

// rel is abs as a path inside the volume.
func (v *volFS) rel(abs string) string {
	if abs == v.mount {
		return "/"
	}
	return strings.TrimPrefix(abs, v.mount)
}

// real resolves rel on the server, symlinks included, and refuses it when
// it ends up outside the volume. Missing parts at the end are kept as given.
func (v *volFS) real(rel string) (string, error) {
	if strings.ContainsRune(rel, 0) {
		return "", huma.Error422UnprocessableEntity("Invalid path")
	}
	rel = cleanRel(rel)
	p := v.mount + strings.TrimSuffix(rel, "/")
	if rel == "/" {
		p = v.mount
	}
	rest := ""
	for {
		r, err := v.s.RealPath(p)
		if err == nil {
			full := path.Join(r, rest)
			if !v.inside(full) {
				return "", errOutsideVolume
			}
			return full, nil
		}
		if !errors.Is(err, os.ErrNotExist) || p == v.mount {
			return "", fsError(rel, err)
		}
		rest = path.Join(path.Base(p), rest)
		p = path.Dir(p)
	}
}

// place is real for everything but the last part, which stays itself (a
// link there is the link, not what it points at): for rename, delete, stat.
func (v *volFS) place(rel string) (string, error) {
	rel = cleanRel(rel)
	if rel == "/" {
		return v.mount, nil
	}
	dir, err := v.real(path.Dir(rel))
	if err != nil {
		return "", err
	}
	return path.Join(dir, path.Base(rel)), nil
}

func (v *volFS) places(rels []string) ([]string, error) {
	return v.resolveAll(rels, v.place)
}

func (v *volFS) reals(rels []string) ([]string, error) {
	return v.resolveAll(rels, v.real)
}

func (v *volFS) resolveAll(rels []string, fn func(string) (string, error)) ([]string, error) {
	out := make([]string, 0, len(rels))
	for _, r := range rels {
		abs, err := fn(r)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, abs) {
			out = append(out, abs)
		}
	}
	return out, nil
}

// ---- Entries ----

func (v *volFS) entries(abs string, infos []os.FileInfo) []FileEntry {
	out := entries(v.c, v.s, abs, infos)
	for i := range out {
		v.fix(&out[i])
	}
	return out
}

func (v *volFS) stat(abs string) (FileEntry, error) {
	fi, err := v.s.Lstat(abs)
	if err != nil {
		return FileEntry{}, fsError(v.rel(abs), err)
	}
	return v.entries(path.Dir(abs), []os.FileInfo{fi})[0], nil
}

// fix turns an entry the server's way into the volume's: paths inside it,
// owners as numbers (the server's names for them mean nothing in the
// container), and links that leave the volume shown as broken.
func (v *volFS) fix(e *FileEntry) {
	e.Path = v.rel(e.Path)
	e.Owner = strconv.FormatUint(uint64(e.UID), 10)
	e.Group = strconv.FormatUint(uint64(e.GID), 10)
	if e.Type == "symlink" {
		if _, err := v.real(e.Path); err != nil {
			e.TargetType = "missing"
		}
	}
}

// ---- Changes ----

// logged writes a change made over SFTP into the command log.
func (v *volFS) logged(ctx context.Context, text string, fn func() error) error {
	sink := v.h.pool.Log
	var hd cmdlog.Handle
	if sink != nil {
		hd = sink.Begin(ctx, cmdlog.Command{
			ServerID: v.id, Origin: cmdlog.Of(ctx), Text: "# volume " + v.name + ": " + text,
			AsRoot: v.sh.priv != privUser, Started: time.Now(),
		})
	}
	err := fn()
	if hd != nil {
		r := cmdlog.Result{}
		if err != nil {
			r.Code, r.Error = 1, err.Error()
		}
		hd.End(r)
	}
	return err
}

func fsErrorOr(rel string, err error) error {
	if err == nil {
		return nil
	}
	return fsError(rel, err)
}

func (v *volFS) move(ctx context.Context, from, to string) error {
	if _, err := v.s.Lstat(to); err == nil {
		return huma.Error409Conflict(path.Base(to) + " already exists")
	}
	err := v.logged(ctx, "mv "+v.rel(from)+" "+v.rel(to), func() error {
		return v.s.Rename(from, to)
	})
	if err == nil {
		return nil
	}
	var se *sftp.StatusError
	if !errors.As(err, &se) {
		return fsError(v.rel(from), err)
	}
	_, err = v.sh.run(ctx, "mv -- "+terminal.ShellQuote(from)+" "+terminal.ShellQuote(to))
	return err
}

// ---- Download & upload ----

func (h *serverHandler) downloadVolumeFiles(ctx context.Context, in *VolumeDownloadInput) (*huma.StreamResponse, error) {
	var (
		sc      *sftp.Client
		paths   []string
		file    *sftp.File
		info    os.FileInfo
		release func()
		top     string
	)
	err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
		var err error
		if paths, err = v.reals(in.Paths); err != nil {
			return err
		}
		sc = v.s
		top = v.mount
		// The top folder zips as what's in it (its own name is the server's _data).
		if i := slices.Index(paths, v.mount); i >= 0 {
			infos, err := v.s.ReadDir(v.mount)
			if err != nil {
				return fsError("/", err)
			}
			kids := make([]string, 0, len(infos))
			for _, fi := range infos {
				kids = append(kids, path.Join(v.mount, fi.Name()))
			}
			paths = append(slices.Delete(paths, i, i+1), kids...)
			if len(paths) == 0 {
				return huma.Error422UnprocessableEntity("The volume is empty")
			}
		}
		if len(paths) == 1 {
			fi, err := v.s.Stat(paths[0])
			if err != nil {
				return fsError(v.rel(paths[0]), err)
			}
			if !fi.IsDir() {
				if file, err = v.s.Open(paths[0]); err != nil {
					return fsError(v.rel(paths[0]), err)
				}
				info = fi
			}
		}
		release = v.acquire()
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &huma.StreamResponse{Body: func(hctx huma.Context) {
		defer release()
		r, w := humachi.Unwrap(hctx)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if file != nil {
			defer file.Close()
			serveFile(w, r, file, info, in.Inline)
			return
		}
		name := in.Name
		if name == "" {
			switch {
			case len(paths) == 1 && paths[0] != top:
				name = path.Base(paths[0])
			case len(paths) > 1 && path.Dir(paths[0]) != top:
				name = path.Base(path.Dir(paths[0]))
			default:
				name = in.Volume
			}
		}
		if !strings.HasSuffix(strings.ToLower(name), ".zip") {
			name += ".zip"
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", disposition("attachment", name))
		writeZip(w, sc, paths)
	}}, nil
}

func (h *serverHandler) uploadVolumeFile(ctx context.Context, in *VolumeUploadInput) (*FileEntryOutput, error) {
	out := &FileEntryOutput{}
	started := false
	err := h.withVolume(ctx, in.ID, in.Volume, func(v *volFS) error {
		if started {
			return huma.Error502BadGateway("Lost the connection to the server during the upload")
		}
		rel := cleanRel(in.Path)
		if rel == "/" {
			return huma.Error422UnprocessableEntity("Give the file a name")
		}
		p, err := v.place(rel)
		if err != nil {
			return err
		}
		dir := path.Dir(p)
		perm := os.FileMode(0)
		var owner *sftp.FileStat
		if fi, err := v.s.Lstat(p); err == nil {
			if fi.IsDir() {
				return huma.Error409Conflict("A folder named " + path.Base(p) + " is already there")
			}
			if !in.Overwrite {
				return huma.Error409Conflict(path.Base(p)+" already exists", &huma.ErrorDetail{Location: "query.path", Message: "exists", Value: in.Path})
			}
			perm = fi.Mode().Perm()
			owner, _ = fi.Sys().(*sftp.FileStat)
		} else if err := v.s.MkdirAll(dir); err != nil {
			return fsError(path.Dir(rel), err)
		}
		if owner == nil {
			// A new file takes the folder's owner, not root's: the container
			// usually runs as that user.
			if fi, err := v.s.Stat(dir); err == nil {
				owner, _ = fi.Sys().(*sftp.FileStat)
			}
		}

		tmp := path.Join(dir, "."+path.Base(p)+".morche-"+randomSuffix())
		f, err := v.s.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return fsError(path.Dir(rel), err)
		}
		started = true
		var body io.Reader = in.body
		if in.length > 0 {
			body = io.LimitReader(in.body, in.length)
		}
		err = v.logged(ctx, "upload "+v.rel(p), func() error {
			_, err := f.ReadFrom(body)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err == nil && in.length > 0 {
				if fi, serr := v.s.Stat(tmp); serr == nil && fi.Size() != in.length {
					err = errors.New("the upload was cut short")
				}
			}
			return err
		})
		if err != nil {
			_ = v.s.Remove(tmp)
			if ctx.Err() != nil {
				return huma.NewError(499, "Upload cancelled")
			}
			return huma.Error502BadGateway("Upload failed: " + err.Error())
		}
		if perm != 0 {
			_ = v.s.Chmod(tmp, perm)
		}
		if owner != nil && v.sh.priv != privUser {
			_ = v.s.Chown(tmp, int(owner.UID), int(owner.GID))
		}
		if err := v.s.PosixRename(tmp, p); err != nil {
			_ = v.s.Remove(p)
			if err := v.s.Rename(tmp, p); err != nil {
				_ = v.s.Remove(tmp)
				return fsError(rel, err)
			}
		}
		out.Body, err = v.stat(p)
		return err
	})
	return out, err
}

// ---- Copy & move ----

// volumePlan pairs each path with its place in dest, like planTransfer.
func (v *volFS) plan(rels []string, rawDest string, copying bool) ([][2]string, error) {
	paths, err := v.places(rels)
	if err != nil {
		return nil, err
	}
	dest, err := v.real(rawDest)
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		if p == v.mount {
			return nil, huma.Error422UnprocessableEntity("The volume's top folder can't be moved or copied into itself")
		}
	}
	// planTransfer works on absolute paths; these are already resolved.
	pairs, err := planTransfer(v.s, paths, dest, copying)
	return pairs, v.hidePaths(err)
}

// hidePaths says the server's paths in err as paths inside the volume.
func (v *volFS) hidePaths(err error) error {
	var m *huma.ErrorModel
	if errors.As(err, &m) {
		m.Detail = strings.ReplaceAll(m.Detail, v.mount+"/", "/")
		m.Detail = strings.ReplaceAll(m.Detail, v.mount, "/")
	}
	return err
}

func (h *serverHandler) submitVolumeTransfer(ctx context.Context, id, volume, kind string, b TransferFilesBody) (*JobOutput, error) {
	copying := kind == dockerVolumeCopyKind
	var dest string
	var names []string
	err := h.withVolume(ctx, id, volume, func(v *volFS) error {
		pairs, err := v.plan(b.Paths, b.Destination, copying)
		if err != nil {
			return err
		}
		if len(pairs) == 0 {
			return huma.Error422UnprocessableEntity("Already in that folder")
		}
		dest = v.rel(path.Dir(pairs[0][1]))
		for _, pr := range pairs {
			names = append(names, path.Base(pr[0]))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	verb := "Move "
	if copying {
		verb = "Copy "
	}
	return submit(ctx, h.jobs, jobs.Spec{
		Kind: kind, Title: verb + what(names) + " to " + dest + " in volume " + volume, Refs: placeRefs(id),
		Params: volumeTransferParams{ServerID: id, Volume: volume, Paths: b.Paths, Destination: dest},
		Target: &JobPlace{ServerID: id, Path: dest, Name: s.Name, Volume: volume},
		Quick:  !copying,
	})
}

func (h *serverHandler) runVolumeTransfer(ctx context.Context, t *jobs.Task) (any, error) {
	var p volumeTransferParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	copying := t.Kind == dockerVolumeCopyKind
	var started bool
	err := h.withVolume(ctx, p.ServerID, p.Volume, func(v *volFS) error {
		if started {
			return errLostPartWay
		}
		pairs, err := v.plan(p.Paths, p.Destination, copying)
		if err != nil {
			return err
		}
		phase := "Moving"
		if copying {
			phase = "Copying"
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.ItemsTotal = phase, len(pairs) })
		started = true
		for _, pair := range pairs {
			if err := ctx.Err(); err != nil {
				return err
			}
			from, to := pair[0], pair[1]
			t.Update(func(pr *jobs.Progress) { pr.Current = path.Base(from) })
			if copying {
				if _, err := v.s.Lstat(to); err == nil {
					return huma.Error409Conflict(path.Base(to) + " already exists")
				}
				res, err := v.sh.exec(ctx, "cp -a -- "+terminal.ShellQuote(from)+" "+terminal.ShellQuote(to), volumeCopyLimit, 8192)
				if err == nil && res.code != 0 {
					err = fmt.Errorf("cp failed: %s", lastLines(string(res.output), 2))
				}
				if err != nil || ctx.Err() != nil {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
					if _, rerr := v.sh.run(cleanup, "rm -rf -- "+terminal.ShellQuote(to)); rerr == nil {
						t.Logf("Removed the unfinished %s", v.rel(to))
					}
					cancel()
					return cmpErr(err, ctx.Err())
				}
			} else if err := v.move(ctx, from, to); err != nil {
				return err
			}
			t.Logf("%s → %s", v.rel(from), v.rel(to))
			t.Update(func(pr *jobs.Progress) { pr.Items++ })
		}
		return nil
	})
	return nil, jobError(err)
}
