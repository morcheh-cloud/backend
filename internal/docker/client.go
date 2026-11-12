// Package docker is a small client for the Docker Engine API (also served
// by Podman), reached through whatever byte stream a Dialer opens: on
// Morche, a channel of a server's pooled SSH connection.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Dialer opens one new byte stream to the Engine API.
type Dialer func(ctx context.Context) (net.Conn, error)

// Client talks to one engine. It's safe for concurrent use.
type Client struct {
	tr *http.Transport
	hc *http.Client
}

// New returns a client opening at most maxConns streams at a time (each
// stream is one request, or a long one like a log follow).
func New(dial Dialer, maxConns int) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx)
		},
		MaxConnsPerHost:     maxConns,
		MaxIdleConnsPerHost: min(maxConns, 4),
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  true,
	}
	return &Client{tr: tr, hc: &http.Client{Transport: tr}}
}

// Close drops the idle streams; requests still running go on.
func (c *Client) Close() { c.tr.CloseIdleConnections() }

// Error is what the engine answered a request with.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// IsNotFound says err is the engine's 404 (no such container, image…).
func IsNotFound(err error) bool { return StatusOf(err) == http.StatusNotFound }

// StatusOf is the engine's status for err, or 0 when it isn't an answer.
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// request builds a request to path (without the API version prefix: the
// engine then speaks its newest version).
func (c *Client) request(ctx context.Context, method, path string, q url.Values, body any) (*http.Request, error) {
	u := "http://docker" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// Stream sends a request and returns the open response for the caller to
// read and close. An error answer is turned into *Error.
func (c *Client) Stream(ctx context.Context, method, path string, q url.Values, body any) (*http.Response, error) {
	req, err := c.request(ctx, method, path, q, body)
	if err != nil {
		return nil, err
	}
	return c.send(req)
}

func (c *Client) send(req *http.Request) (*http.Response, error) {
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		defer res.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		var m struct {
			Message string `json:"message"`
		}
		msg := strings.TrimSpace(string(b))
		if json.Unmarshal(b, &m) == nil && m.Message != "" {
			msg = m.Message
		}
		if msg == "" {
			msg = res.Status
		}
		return nil, &Error{Status: res.StatusCode, Message: msg}
	}
	return res, nil
}

// Do sends a request and decodes a JSON answer into out (nil = ignore it).
func (c *Client) Do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	res, err := c.Stream(ctx, method, path, q, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		b, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
		*raw = b
		return err
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return fmt.Errorf("reading the engine's answer: %w", err)
	}
	return nil
}

// Get is Do with GET.
func (c *Client) Get(ctx context.Context, path string, q url.Values, out any) error {
	return c.Do(ctx, http.MethodGet, path, q, nil, out)
}

// Ping checks the engine answers.
func (c *Client) Ping(ctx context.Context) error {
	res, err := c.Stream(ctx, http.MethodGet, "/_ping", nil, nil)
	if err != nil {
		return err
	}
	res.Body.Close()
	return nil
}

// PathEscape escapes one path segment (names may hold "/" for images).
func PathEscape(s string) string { return url.PathEscape(s) }
