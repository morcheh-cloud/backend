package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Save streams `docker save` of the given images (ids or references) as one
// tar. The caller closes it.
func (c *Client) Save(ctx context.Context, refs ...string) (io.ReadCloser, error) {
	q := url.Values{"names": refs}
	res, err := c.Stream(ctx, http.MethodGet, "/images/get", q, nil)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

// Load sends a tar made by `docker save` (plain or gzip-compressed: the
// engine unpacks either) and returns what it loaded, e.g. "Loaded image:
// nginx:1.27" lines.
func (c *Client) Load(ctx context.Context, r io.Reader) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/images/load?quiet=1", r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	res, err := c.send(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var loaded []string
	dec := json.NewDecoder(bufio.NewReader(res.Body))
	for {
		var m struct {
			Stream      string `json:"stream"`
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return loaded, fmt.Errorf("reading the engine's answer: %w", err)
		}
		if msg := cmpOr(m.ErrorDetail.Message, m.Error); msg != "" {
			return loaded, &Error{Status: http.StatusBadRequest, Message: msg}
		}
		for line := range strings.SplitSeq(m.Stream, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				loaded = append(loaded, line)
			}
		}
	}
	return loaded, nil
}

// ContainerCreated is the engine's answer to a create.
type ContainerCreated struct {
	ID       string   `json:"Id"`
	Warnings []string `json:"Warnings"`
}

// CreateContainer makes a container from body (Config + HostConfig +
// NetworkingConfig, as the Engine API takes them). name may be empty.
func (c *Client) CreateContainer(ctx context.Context, name, platform string, body any) (ContainerCreated, error) {
	q := url.Values{}
	if name != "" {
		q.Set("name", name)
	}
	if platform != "" {
		q.Set("platform", platform)
	}
	var v ContainerCreated
	return v, c.Do(ctx, http.MethodPost, "/containers/create", q, body, &v)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
