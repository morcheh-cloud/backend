package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/docker"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

type DockerScanCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Fixable  int `json:"fixable" doc:"Findings a newer package version fixes"`
}

type DockerImageScan struct {
	ImageID    string            `json:"image_id"`
	Image      string            `json:"image" doc:"Its first tag (or id)"`
	Tags       []string          `json:"tags"`
	Size       int64             `json:"size"`
	InUse      int               `json:"in_use" doc:"Containers made from it"`
	Scanned    bool              `json:"scanned"`
	Counts     *DockerScanCounts `json:"counts,omitempty"`
	Scanner    string            `json:"scanner,omitempty"`
	Error      string            `json:"error,omitempty"`
	ScannedAt  *time.Time        `json:"scanned_at,omitempty"`
	Containers []DockerRef       `json:"containers"`
}

type DockerScanFinding struct {
	ID        string `json:"id" example:"CVE-2024-6387"`
	Severity  string `json:"severity" enum:"CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN"`
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed,omitempty" doc:"The version that fixes it; empty = no fix yet"`
	Title     string `json:"title,omitempty"`
	Target    string `json:"target,omitempty" doc:"Where in the image (OS packages or a language's lock file)"`
	URL       string `json:"url,omitempty"`
}

type DockerImageScanDetails struct {
	DockerImageScan
	Findings []DockerScanFinding `json:"findings" doc:"Worst first, at most 1000"`
}

type DockerScans struct {
	Items   []DockerImageScan `json:"items"`
	Totals  DockerScanCounts  `json:"totals" doc:"Over the scanned images"`
	Scanner string            `json:"scanner" doc:"The scanner image the workspace uses"`
}

type DockerScanBody struct {
	Images []string `json:"images,omitempty" maxItems:"100" doc:"Image ids; empty with all = every image"`
	All    bool     `json:"all,omitempty" doc:"Every image (only the ones containers use with in_use)"`
	InUse  bool     `json:"in_use,omitempty" doc:"With all: only images a container uses"`
}

type DockerScanImagePath struct {
	ServerIDPath
	Image string `path:"image" maxLength:"80" doc:"Image id (sha256:…)"`
}

type dockerScanParams struct {
	ServerID string   `json:"server_id"`
	Images   []string `json:"images"`
}

const (
	dockerScanKind  = "docker-scan"
	maxScanFindings = 1000
)

var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

func scanOf(r sqlc.DockerImageScan) (DockerScanCounts, *time.Time) {
	at := r.ScannedAt
	return DockerScanCounts{
		Critical: int(r.Critical), High: int(r.High), Medium: int(r.Medium),
		Low: int(r.Low), Unknown: int(r.Unknown), Fixable: int(r.Fixable),
	}, &at
}

// imageScans lists a server's images with their last scan.
func (h *serverHandler) imageScans(ctx context.Context, id string) ([]DockerImageScan, error) {
	sid, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	var ims []docker.ImageSummary
	var cs []docker.ContainerSummary
	if err := h.withDocker(ctx, id, func(e *dockerEngine) error {
		if ims, err = e.client.Images(ctx); err != nil {
			return err
		}
		cs, err = e.client.Containers(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	rows, err := h.q.ListDockerImageScans(ctx, sid)
	if err != nil {
		return nil, internalError(err)
	}
	scans := map[string]sqlc.DockerImageScan{}
	for _, r := range rows {
		scans[r.ImageID] = r
	}
	out := make([]DockerImageScan, 0, len(ims))
	for _, im := range ims {
		tags := slices.DeleteFunc(slices.Clone(im.RepoTags), func(t string) bool { return t == "<none>:<none>" })
		if tags == nil {
			tags = []string{}
		}
		s := DockerImageScan{ImageID: im.ID, Image: shortID(im.ID), Tags: tags, Size: im.Size, Containers: []DockerRef{}}
		if len(tags) > 0 {
			s.Image = tags[0]
		}
		for _, c := range cs {
			if c.ImageID == im.ID {
				s.InUse++
				s.Containers = append(s.Containers, DockerRef{ID: c.ID, Name: containerName(c.Names), State: c.State})
			}
		}
		if r, ok := scans[im.ID]; ok {
			s.Scanned, s.Scanner, s.Error = true, r.Scanner, r.Error
			if r.Error == "" {
				counts, _ := scanOf(r)
				s.Counts = &counts
			}
			_, s.ScannedAt = scanOf(r)
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		wa, wb := scanWeight(a), scanWeight(b)
		if wa != wb {
			return wa > wb
		}
		if (a.InUse > 0) != (b.InUse > 0) {
			return a.InUse > 0
		}
		return a.Image < b.Image
	})
	return out, nil
}

func scanWeight(s DockerImageScan) int {
	if s.Counts == nil {
		return -1
	}
	c := s.Counts
	return c.Critical*1_000_000 + c.High*10_000 + c.Medium*100 + c.Low
}

func registerDockerScans(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-scans",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/docker/scans",
		Summary:     "Vulnerability scans of a server's images",
		Description: "Every image with its last scan's counts (worst first).",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body DockerScans }, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		set, err := h.serverDockerSettings(ctx, s)
		if err != nil {
			return nil, err
		}
		items, err := h.imageScans(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		out := DockerScans{Items: items, Scanner: set.ScannerImage}
		for _, it := range items {
			if c := it.Counts; c != nil {
				out.Totals.Critical += c.Critical
				out.Totals.High += c.High
				out.Totals.Medium += c.Medium
				out.Totals.Low += c.Low
				out.Totals.Unknown += c.Unknown
				out.Totals.Fixable += c.Fixable
			}
		}
		return &struct{ Body DockerScans }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-scan",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/docker/scans/{image}",
		Summary:     "An image's vulnerabilities",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerScanImagePath) (*struct{ Body DockerImageScanDetails }, error) {
		items, err := h.imageScans(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		idx := slices.IndexFunc(items, func(s DockerImageScan) bool {
			return s.ImageID == in.Image || shortID(s.ImageID) == in.Image
		})
		if idx < 0 {
			return nil, huma.Error404NotFound("No such image on this server")
		}
		out := DockerImageScanDetails{DockerImageScan: items[idx], Findings: []DockerScanFinding{}}
		if out.Scanned {
			s, err := h.get(ctx, in.ID)
			if err != nil {
				return nil, err
			}
			r, err := h.q.GetDockerImageScan(ctx, sqlc.GetDockerImageScanParams{ServerID: s.ID, ImageID: out.ImageID})
			if err == nil && len(r.Findings) > 0 {
				_ = json.Unmarshal(r.Findings, &out.Findings)
			}
		}
		return &struct{ Body DockerImageScanDetails }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "scan-docker-images",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/docker/scans",
		Summary:       "Scan images for known vulnerabilities",
		Description:   "Runs Trivy on the server: the `trivy` command if installed, else the workspace's scanner image through Docker (its database is cached in the `morcheh-trivy-cache` volume). Runs as a job (kind `docker-scan`).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerScanBody
	}) (*JobOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		ids := in.Body.Images
		if in.Body.All || len(ids) == 0 {
			items, err := h.imageScans(ctx, in.ID)
			if err != nil {
				return nil, err
			}
			ids = nil
			for _, it := range items {
				if in.Body.InUse && it.InUse == 0 {
					continue
				}
				ids = append(ids, it.ImageID)
			}
		}
		if len(ids) == 0 {
			return nil, huma.Error422UnprocessableEntity("There are no images to scan")
		}
		for _, id := range ids {
			if !strings.HasPrefix(id, "sha256:") || !hexID.MatchString(strings.TrimPrefix(id, "sha256:")) {
				return nil, fieldError("body.images", "Use image ids (sha256:…)", id)
			}
		}
		title := "Scan " + plural(len(ids), "image") + " on " + s.Name
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerScanKind, Title: title,
			Params: dockerScanParams{ServerID: in.ID, Images: ids},
			Refs:   placeRefs(in.ID), Target: &JobPlace{ServerID: in.ID, Name: s.Name},
		})
	})
	h.jobs.Handle(dockerScanKind, h.runDockerScan)
}

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			PrimaryURL       string `json:"PrimaryURL"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// scanScript runs trivy on one image and prints its JSON after "@@json",
// or its errors after "@@err".
func scanScript(scanner, image string, ignoreUnfixed bool) string {
	q := terminal.ShellQuote
	opts := "--quiet --format json --scanners vuln"
	if ignoreUnfixed {
		opts += " --ignore-unfixed"
	}
	return `t=$(mktemp); e=$(mktemp); trap 'rm -f "$t" "$e"' EXIT
if command -v trivy >/dev/null 2>&1; then
  echo "@@scanner trivy"
  trivy image ` + opts + ` ` + q(image) + ` >"$t" 2>"$e"; code=$?
else
  echo "@@scanner "` + q(scanner) + `
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro -v morcheh-trivy-cache:/root/.cache/ ` + q(scanner) + ` image ` + opts + ` ` + q(image) + ` >"$t" 2>"$e"; code=$?
fi
if [ $code -ne 0 ]; then echo "@@err"; tail -n 5 "$e"; exit 0; fi
echo "@@json"; cat "$t"`
}

func (h *serverHandler) runDockerScan(ctx context.Context, t *jobs.Task) (any, error) {
	var p dockerScanParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	s, err := h.get(ctx, p.ServerID)
	if err != nil {
		return nil, jobError(err)
	}
	set, err := h.serverDockerSettings(ctx, s)
	if err != nil {
		return nil, jobError(err)
	}
	items, err := h.imageScans(ctx, p.ServerID)
	if err != nil {
		return nil, jobError(err)
	}
	names := map[string]string{}
	for _, it := range items {
		names[it.ImageID] = it.Image
	}
	var failed []string
	var worse []scanWorse
	total := DockerScanCounts{}
	for i, id := range p.Images {
		if t.Canceled() {
			return nil, ctx.Err()
		}
		name, ok := names[id]
		if !ok {
			t.Logf("Skipped %s: not on the server any more", shortID(id))
			continue
		}
		t.Update(func(pr *jobs.Progress) {
			pr.Phase, pr.Current, pr.Items, pr.ItemsTotal = "Scanning", name, i, len(p.Images)
		})
		t.Logf("Scanning %s", name)
		// Scan by id: a tag may have moved on.
		ref := id
		row := sqlc.UpsertDockerImageScanParams{ServerID: s.ID, ImageID: id, Image: name, Findings: []byte("[]")}
		var res *execResult
		err := h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
			var err error
			res, err = sh.hiding(true).exec(ctx, scanScript(set.ScannerImage, ref, set.ScanIgnoreUnfixed), 20*time.Minute, 64<<20)
			return err
		})
		if err == nil && res.timedOut {
			err = errors.New("the scan took longer than 20 minutes")
		}
		if err == nil && res.truncated {
			err = errors.New("the scanner's report was too big")
		}
		if err != nil {
			row.Error = dockerProblemText(err)
		} else {
			out := string(res.output)
			if line, rest, ok := strings.Cut(out, "\n"); ok && strings.HasPrefix(line, "@@scanner ") {
				row.Scanner, out = strings.TrimPrefix(line, "@@scanner "), rest
			}
			switch {
			case strings.HasPrefix(out, "@@err"):
				msg := strings.TrimSpace(strings.TrimPrefix(out, "@@err"))
				if msg == "" {
					msg = "The scanner failed"
				}
				row.Error = msg
			case strings.HasPrefix(out, "@@json"):
				var rep trivyReport
				if err := json.Unmarshal([]byte(strings.TrimPrefix(out, "@@json")), &rep); err != nil {
					row.Error = "Couldn't read the scanner's report"
					break
				}
				var fs []DockerScanFinding
				seen := map[string]bool{}
				for _, r := range rep.Results {
					for _, v := range r.Vulnerabilities {
						key := v.VulnerabilityID + "\x00" + v.PkgName + "\x00" + v.InstalledVersion
						if seen[key] {
							continue
						}
						seen[key] = true
						sev := strings.ToUpper(v.Severity)
						if _, ok := severityRank[sev]; !ok {
							sev = "UNKNOWN"
						}
						switch sev {
						case "CRITICAL":
							row.Critical++
						case "HIGH":
							row.High++
						case "MEDIUM":
							row.Medium++
						case "LOW":
							row.Low++
						default:
							row.Unknown++
						}
						if v.FixedVersion != "" {
							row.Fixable++
						}
						fs = append(fs, DockerScanFinding{
							ID: v.VulnerabilityID, Severity: sev, Package: v.PkgName, Installed: v.InstalledVersion,
							Fixed: v.FixedVersion, Title: v.Title, Target: r.Target, URL: v.PrimaryURL,
						})
					}
				}
				sort.SliceStable(fs, func(i, j int) bool {
					if severityRank[fs[i].Severity] != severityRank[fs[j].Severity] {
						return severityRank[fs[i].Severity] < severityRank[fs[j].Severity]
					}
					if (fs[i].Fixed != "") != (fs[j].Fixed != "") {
						return fs[i].Fixed != ""
					}
					return fs[i].ID < fs[j].ID
				})
				if len(fs) > maxScanFindings {
					fs = fs[:maxScanFindings]
				}
				if fs == nil {
					fs = []DockerScanFinding{}
				}
				row.Findings, _ = json.Marshal(fs)
			default:
				row.Error = "The scanner gave no report"
			}
		}
		if row.Error != "" {
			t.Logf("Couldn't scan %s: %s", name, row.Error)
			failed = append(failed, name)
		} else {
			t.Logf("%s: %d critical, %d high, %d medium, %d low", name, row.Critical, row.High, row.Medium, row.Low)
			total.Critical += int(row.Critical)
			total.High += int(row.High)
			total.Medium += int(row.Medium)
			total.Low += int(row.Low)
			var prev *sqlc.DockerImageScan
			if old, err := h.q.GetDockerImageScan(ctx, sqlc.GetDockerImageScanParams{ServerID: s.ID, ImageID: id}); err == nil {
				prev = &old
			}
			if worseScan(set.NotifyVulns, prev, row) {
				worse = append(worse, scanWorse{image: name, critical: int(row.Critical), high: int(row.High)})
			}
		}
		if err := h.q.UpsertDockerImageScan(ctx, row); err != nil {
			return nil, jobError(internalError(err))
		}
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Items, pr.ItemsTotal = "Done", len(p.Images), len(p.Images) })
	h.notifyDockerVulns(s, set, worse)
	if len(failed) == len(p.Images) && len(failed) > 0 {
		return nil, jobError(errors.New("Couldn't scan " + strings.Join(failed, ", ") + " (see the output)"))
	}
	return total, nil
}
