package docker

import (
	"context"
	"encoding/base64"
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

// Event is one line of the engine's event stream.
type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Scope    string `json:"scope"`
	TimeNano int64  `json:"timeNano"`
}

// Events returns the events the engine still remembers between since and
// until (the engine keeps the last 256 or so in memory), oldest first.
func (c *Client) Events(ctx context.Context, since, until time.Time, filters map[string][]string, limit int) ([]Event, error) {
	q := url.Values{
		"since": {strconv.FormatInt(since.Unix(), 10)},
		"until": {strconv.FormatInt(until.Unix(), 10)},
	}
	if len(filters) > 0 {
		b, _ := json.Marshal(filters)
		q.Set("filters", string(b))
	}
	res, err := c.Stream(ctx, http.MethodGet, "/events", q, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	dec := json.NewDecoder(res.Body)
	var out []Event
	for {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
		out = append(out, ev)
		if len(out) > limit {
			out = out[1:]
		}
	}
}

// RegistryAuth is the X-Registry-Auth value for a login ("" without one).
func RegistryAuth(server, username, password string) string {
	if username == "" && password == "" {
		return ""
	}
	b, _ := json.Marshal(map[string]string{"username": username, "password": password, "serveraddress": server})
	return base64.URLEncoding.EncodeToString(b)
}

// Distribution is what the registry says about an image reference.
type Distribution struct {
	Descriptor struct {
		Digest string `json:"digest"`
	} `json:"Descriptor"`
}

// RemoteDigest asks the registry (through the engine) for the digest ref
// points to now.
func (c *Client) RemoteDigest(ctx context.Context, ref, auth string) (string, error) {
	req, err := c.request(ctx, http.MethodGet, "/distribution/"+ref+"/json", nil, nil)
	if err != nil {
		return "", err
	}
	if auth != "" {
		req.Header.Set("X-Registry-Auth", auth)
	}
	res, err := c.send(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var d Distribution
	if err := json.NewDecoder(res.Body).Decode(&d); err != nil {
		return "", fmt.Errorf("reading the registry's answer: %w", err)
	}
	return d.Descriptor.Digest, nil
}

// Login checks a registry login (POST /auth).
func (c *Client) Login(ctx context.Context, server, username, password string) (string, error) {
	var out struct {
		Status string `json:"Status"`
	}
	err := c.Do(ctx, http.MethodPost, "/auth", nil, map[string]string{
		"username": username, "password": password, "serveraddress": server,
	}, &out)
	return out.Status, err
}

// Recreate puts a new container in place of id, from the same settings but
// on the image its reference now points to (pull it first). The old one is
// kept, renamed, until the new one runs; on any failure it comes back.
// Returns the new container's id.
func (c *Client) Recreate(ctx context.Context, id string) (string, error) {
	return c.RecreateWait(ctx, id, 30)
}

// RecreateWait is Recreate giving the old container stop seconds to stop
// (< 0 = its own setting).
func (c *Client) RecreateWait(ctx context.Context, id string, stop int) (string, error) {
	var raw map[string]json.RawMessage
	if err := c.Get(ctx, "/containers/"+url.PathEscape(id)+"/json", nil, &raw); err != nil {
		return "", err
	}
	var meta struct {
		Name  string `json:"Name"`
		State struct {
			Running bool `json:"Running"`
		} `json:"State"`
		Config     map[string]any `json:"Config"`
		HostConfig map[string]any `json:"HostConfig"`
		Network    struct {
			Networks map[string]map[string]any `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	b, _ := json.Marshal(raw)
	if err := json.Unmarshal(b, &meta); err != nil {
		return "", err
	}
	name := strings.TrimPrefix(meta.Name, "/")
	if meta.Config == nil {
		return "", errors.New("the container has no settings to copy")
	}
	img, _ := meta.Config["Image"].(string)
	if img == "" || strings.HasPrefix(img, "sha256:") {
		return "", errors.New("the container was made from an image id, not a name: nothing to update to")
	}
	// The image's own values come back from the new image.
	delete(meta.Config, "Hostname")
	delete(meta.Config, "Domainname")
	body := map[string]any{}
	for k, v := range meta.Config {
		body[k] = v
	}
	body["HostConfig"] = meta.HostConfig
	// Only one network can be given at create; the rest are connected after.
	nets := map[string]map[string]any{}
	for n, ep := range meta.Network.Networks {
		keep := map[string]any{}
		for _, k := range []string{"Aliases", "IPAMConfig", "Links", "DriverOpts"} {
			if v, ok := ep[k]; ok && v != nil {
				keep[k] = v
			}
		}
		if al, ok := keep["Aliases"].([]any); ok {
			// The short id alias belongs to the old container.
			var out []any
			for _, a := range al {
				if s, _ := a.(string); s != "" && !strings.HasPrefix(id, s) {
					out = append(out, a)
				}
			}
			keep["Aliases"] = out
		}
		nets[n] = keep
	}
	mode, _ := meta.HostConfig["NetworkMode"].(string)
	first := ""
	if ep, ok := nets[mode]; ok {
		first = mode
		body["NetworkingConfig"] = map[string]any{"EndpointsConfig": map[string]any{mode: ep}}
	}

	old := name + "-morche-old-" + strconv.FormatInt(time.Now().Unix(), 36)
	if err := c.Rename(ctx, id, old); err != nil {
		return "", err
	}
	restore := func(newID string) {
		bg := context.WithoutCancel(ctx)
		if newID != "" {
			_ = c.RemoveContainer(bg, newID, true, false)
		}
		_ = c.Rename(bg, id, name)
		if meta.State.Running {
			_ = c.Act(bg, id, "start", 0, "")
		}
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := c.Do(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, body, &created); err != nil {
		restore("")
		return "", err
	}
	for n, ep := range nets {
		if n == first || n == "host" || n == "none" || strings.HasPrefix(mode, "container:") {
			continue
		}
		if err := c.Do(ctx, http.MethodPost, "/networks/"+url.PathEscape(n)+"/connect", nil, map[string]any{
			"Container": created.ID, "EndpointConfig": ep,
		}, nil); err != nil {
			restore(created.ID)
			return "", err
		}
	}
	if meta.State.Running {
		if err := c.Act(ctx, id, "stop", stop, ""); err != nil && StatusOf(err) != http.StatusNotModified {
			restore(created.ID)
			return "", err
		}
		if err := c.Act(ctx, created.ID, "start", 0, ""); err != nil {
			restore(created.ID)
			return "", err
		}
	}
	if err := c.RemoveContainer(ctx, id, true, false); err != nil {
		return created.ID, fmt.Errorf("the new container runs, but the old one (%s) couldn't be removed: %w", old, err)
	}
	return created.ID, nil
}
