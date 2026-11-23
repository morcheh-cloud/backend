package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// APIError is the registry's own refusal, with its message.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }

// HTTP is what the clients send requests through: an http.Client whose
// transport dials the server's loopback over SSH.
type HTTP struct {
	Client   *http.Client
	Base     string // http://127.0.0.1:<port>
	User     string
	Password string
}

func (h HTTP) do(ctx context.Context, method, path string, body, out any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.Base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if h.User != "" {
		req.SetBasicAuth(h.User, h.Password)
	}
	res, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if res.StatusCode >= 300 {
		return res, &APIError{Status: res.StatusCode, Message: apiMessage(res.StatusCode, raw)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return res, fmt.Errorf("the registry answered something Morche can't read: %w", err)
		}
	}
	return res, nil
}

// apiMessage digs Harbor's {"errors":[{"message"}]} or Verdaccio's
// {"error":"…"} out of an answer.
func apiMessage(status int, raw []byte) string {
	var h struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &h) == nil {
		if len(h.Errors) > 0 && h.Errors[0].Message != "" {
			return h.Errors[0].Message
		}
		if h.Error != "" {
			return h.Error
		}
	}
	switch status {
	case http.StatusUnauthorized:
		return "The registry refused Morche's admin login"
	case http.StatusForbidden:
		return "The registry doesn't allow that"
	case http.StatusNotFound:
		return "The registry has no such thing"
	}
	t := strings.TrimSpace(string(raw))
	if len(t) > 200 {
		t = t[:200]
	}
	if t == "" {
		t = http.StatusText(status)
	}
	return "The registry answered " + strconv.Itoa(status) + ": " + t
}

// IsNotFound says whether err is the registry's 404.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// ---- Harbor ----

type HarborClient struct{ HTTP }

const hapi = "/api/v2.0"

type HarborHealth struct {
	Status     string `json:"status"`
	Components []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	} `json:"components"`
}

func (c HarborClient) Health(ctx context.Context) (HarborHealth, error) {
	var h HarborHealth
	_, err := c.do(ctx, http.MethodGet, hapi+"/health", nil, &h)
	return h, err
}

// Version is Harbor's own (v2.15.5), from systeminfo.
func (c HarborClient) Version(ctx context.Context) (string, error) {
	var s struct {
		Version string `json:"harbor_version"`
	}
	_, err := c.do(ctx, http.MethodGet, hapi+"/systeminfo", nil, &s)
	v, _, _ := strings.Cut(s.Version, "-")
	return v, err
}

type HarborStats struct {
	Projects int   `json:"total_project_count"`
	Repos    int   `json:"total_repo_count"`
	Storage  int64 `json:"total_storage_consumption"`
}

func (c HarborClient) Statistics(ctx context.Context) (HarborStats, error) {
	var s HarborStats
	_, err := c.do(ctx, http.MethodGet, hapi+"/statistics", nil, &s)
	return s, err
}

type HarborProject struct {
	ID         int               `json:"project_id"`
	Name       string            `json:"name"`
	RegistryID int               `json:"registry_id"`
	RepoCount  int               `json:"repo_count"`
	Metadata   map[string]string `json:"metadata"`
	Created    time.Time         `json:"creation_time"`
	Updated    time.Time         `json:"update_time"`
}

func (c HarborClient) Projects(ctx context.Context) ([]HarborProject, error) {
	var out []HarborProject
	for page := 1; page <= 20; page++ {
		var ps []HarborProject
		if _, err := c.do(ctx, http.MethodGet, hapi+"/projects?page_size=100&page="+strconv.Itoa(page), nil, &ps); err != nil {
			return nil, err
		}
		out = append(out, ps...)
		if len(ps) < 100 {
			break
		}
	}
	return out, nil
}

// CreateProject makes a project; registryID > 0 makes it a proxy cache of
// that registry endpoint.
func (c HarborClient) CreateProject(ctx context.Context, name string, public bool, registryID int) error {
	body := map[string]any{
		"project_name":  name,
		"metadata":      map[string]string{"public": strconv.FormatBool(public)},
		"storage_limit": -1,
	}
	if registryID > 0 {
		body["registry_id"] = registryID
	}
	_, err := c.do(ctx, http.MethodPost, hapi+"/projects", body, nil)
	return err
}

func (c HarborClient) SetProjectPublic(ctx context.Context, name string, public bool) error {
	_, err := c.do(ctx, http.MethodPut, hapi+"/projects/"+url.PathEscape(name), map[string]any{
		"metadata": map[string]string{"public": strconv.FormatBool(public)},
	}, nil)
	return err
}

func (c HarborClient) DeleteProject(ctx context.Context, name string) error {
	_, err := c.do(ctx, http.MethodDelete, hapi+"/projects/"+url.PathEscape(name), nil, nil)
	return err
}

// DockerHubEndpoint finds or makes the Docker Hub registry endpoint a cache
// project pulls through, and returns its id.
func (c HarborClient) DockerHubEndpoint(ctx context.Context) (int, error) {
	var rs []struct {
		ID   int    `json:"id"`
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if _, err := c.do(ctx, http.MethodGet, hapi+"/registries?page_size=100", nil, &rs); err != nil {
		return 0, err
	}
	for _, r := range rs {
		if r.Type == "docker-hub" {
			return r.ID, nil
		}
	}
	res, err := c.do(ctx, http.MethodPost, hapi+"/registries", map[string]any{
		"name": "Docker Hub", "type": "docker-hub", "url": "https://hub.docker.com", "insecure": false,
	}, nil)
	if err != nil {
		return 0, err
	}
	loc := res.Header.Get("Location")
	id, err := strconv.Atoi(loc[strings.LastIndex(loc, "/")+1:])
	if err != nil {
		return 0, errors.New("Harbor didn't say which endpoint it made")
	}
	return id, nil
}

type HarborRepository struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"` // project/repo
	ProjectID int       `json:"project_id"`
	Artifacts int       `json:"artifact_count"`
	Pulls     int       `json:"pull_count"`
	Created   time.Time `json:"creation_time"`
	Updated   time.Time `json:"update_time"`
}

// Repositories lists every repository, or those whose name has q.
func (c HarborClient) Repositories(ctx context.Context, q string, limit int) ([]HarborRepository, int, error) {
	path := hapi + "/repositories?page_size=" + strconv.Itoa(limit) + "&sort=-update_time"
	if q != "" {
		path += "&q=" + url.QueryEscape("name=~"+q)
	}
	var rs []HarborRepository
	res, err := c.do(ctx, http.MethodGet, path, nil, &rs)
	if err != nil {
		return nil, 0, err
	}
	total, _ := strconv.Atoi(res.Header.Get("X-Total-Count"))
	return rs, total, nil
}

type HarborArtifact struct {
	Digest   string    `json:"digest"`
	Size     int64     `json:"size"`
	Type     string    `json:"type"`
	PushTime time.Time `json:"push_time"`
	PullTime time.Time `json:"pull_time"`
	Tags     []struct {
		Name     string    `json:"name"`
		PushTime time.Time `json:"push_time"`
	} `json:"tags"`
	ExtraAttrs struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"extra_attrs"`
	References []struct {
		Platform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"platform"`
	} `json:"references"`
}

// splitRepo turns "project/a/b" into the project and the repository name
// Harbor wants in paths (slashes encoded twice).
func splitRepo(full string) (project, repo string, ok bool) {
	project, rest, ok := strings.Cut(full, "/")
	if !ok || project == "" || rest == "" {
		return "", "", false
	}
	return url.PathEscape(project), strings.ReplaceAll(url.PathEscape(rest), "%2F", "%252F"), true
}

func (c HarborClient) Artifacts(ctx context.Context, full string) ([]HarborArtifact, error) {
	p, r, ok := splitRepo(full)
	if !ok {
		return nil, &APIError{Status: 404, Message: "No such repository"}
	}
	var out []HarborArtifact
	for page := 1; page <= 10; page++ {
		var as []HarborArtifact
		path := hapi + "/projects/" + p + "/repositories/" + r + "/artifacts?with_tag=true&page_size=100&page=" + strconv.Itoa(page)
		if _, err := c.do(ctx, http.MethodGet, path, nil, &as); err != nil {
			return nil, err
		}
		out = append(out, as...)
		if len(as) < 100 {
			break
		}
	}
	return out, nil
}

func (c HarborClient) DeleteRepository(ctx context.Context, full string) error {
	p, r, ok := splitRepo(full)
	if !ok {
		return &APIError{Status: 404, Message: "No such repository"}
	}
	_, err := c.do(ctx, http.MethodDelete, hapi+"/projects/"+p+"/repositories/"+r, nil, nil)
	return err
}

func (c HarborClient) DeleteArtifact(ctx context.Context, full, digest string) error {
	p, r, ok := splitRepo(full)
	if !ok {
		return &APIError{Status: 404, Message: "No such repository"}
	}
	_, err := c.do(ctx, http.MethodDelete, hapi+"/projects/"+p+"/repositories/"+r+"/artifacts/"+url.PathEscape(digest), nil, nil)
	return err
}

type HarborRobot struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"` // robot$name
	Description string    `json:"description"`
	Disabled    bool      `json:"disable"`
	ExpiresAt   int64     `json:"expires_at"` // -1 = never
	Level       string    `json:"level"`
	Created     time.Time `json:"creation_time"`
	Permissions []struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Access    []struct {
			Resource string `json:"resource"`
			Action   string `json:"action"`
		} `json:"access"`
	} `json:"permissions"`
}

// CanPush says whether the robot may push anywhere.
func (r HarborRobot) CanPush() bool {
	for _, p := range r.Permissions {
		for _, a := range p.Access {
			if a.Resource == "repository" && a.Action == "push" {
				return true
			}
		}
	}
	return false
}

func (c HarborClient) Robots(ctx context.Context) ([]HarborRobot, error) {
	var rs []HarborRobot
	_, err := c.do(ctx, http.MethodGet, hapi+"/robots?page_size=100&sort=-creation_time", nil, &rs)
	return rs, err
}

// CreateRobot makes a system robot account on every project that can pull
// (and push when push), valid for days (≤0 = never expires). It answers
// the full name (robot$…) and its secret, shown only now.
func (c HarborClient) CreateRobot(ctx context.Context, name, description string, push bool, days int) (int, string, string, error) {
	access := []map[string]string{{"resource": "repository", "action": "pull"}}
	if push {
		access = append(access,
			map[string]string{"resource": "repository", "action": "push"},
			map[string]string{"resource": "artifact", "action": "delete"},
			map[string]string{"resource": "tag", "action": "create"},
		)
	}
	if days <= 0 {
		days = -1
	}
	var out struct {
		ID     int    `json:"id"`
		Name   string `json:"name"`
		Secret string `json:"secret"`
	}
	_, err := c.do(ctx, http.MethodPost, hapi+"/robots", map[string]any{
		"name": name, "description": description, "duration": days, "level": "system", "disable": false,
		"permissions": []map[string]any{{"kind": "project", "namespace": "*", "access": access}},
	}, &out)
	return out.ID, out.Name, out.Secret, err
}

func (c HarborClient) DeleteRobot(ctx context.Context, id int) error {
	_, err := c.do(ctx, http.MethodDelete, hapi+"/robots/"+strconv.Itoa(id), nil, nil)
	return err
}

// ScheduleGC sets weekly garbage collection (Sunday 03:00), or with now runs
// it once right away. Untagged images go too.
func (c HarborClient) ScheduleGC(ctx context.Context, now bool) error {
	sched := map[string]string{"type": "Custom", "cron": "0 0 3 * * 0"}
	if now {
		sched = map[string]string{"type": "Manual"}
	}
	body := map[string]any{"schedule": sched, "parameters": map[string]any{"delete_untagged": true, "workers": 1}}
	_, err := c.do(ctx, http.MethodPost, hapi+"/system/gc/schedule", body, nil)
	var ae *APIError
	if !now && errors.As(err, &ae) && ae.Status == http.StatusConflict {
		_, err = c.do(ctx, http.MethodPut, hapi+"/system/gc/schedule", body, nil)
	}
	return err
}

// LastGC is when garbage collection last ran and how it ended.
func (c HarborClient) LastGC(ctx context.Context) (status string, at time.Time, err error) {
	var gs []struct {
		Status  string    `json:"job_status"`
		Updated time.Time `json:"update_time"`
	}
	if _, err = c.do(ctx, http.MethodGet, hapi+"/system/gc?page_size=1&sort=-creation_time", nil, &gs); err != nil || len(gs) == 0 {
		return "", time.Time{}, err
	}
	return gs[0].Status, gs[0].Updated, nil
}
