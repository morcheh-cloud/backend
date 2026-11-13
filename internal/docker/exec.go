package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
)

// ExecResult is what a command run inside a container ended with.
type ExecResult struct {
	ExitCode int
	Output   string // stdout and stderr together, at most 64 KiB
}

// Exec runs cmd inside a running container (as user, "" = the
// container's own) and waits for it to end or ctx to be done.
func (c *Client) Exec(ctx context.Context, id string, cmd []string, user string) (ExecResult, error) {
	var created struct {
		ID string `json:"Id"`
	}
	body := map[string]any{"Cmd": cmd, "AttachStdout": true, "AttachStderr": true, "Tty": false}
	if user != "" {
		body["User"] = user
	}
	if err := c.Do(ctx, http.MethodPost, "/containers/"+PathEscape(id)+"/exec", nil, body, &created); err != nil {
		return ExecResult{}, err
	}
	res, err := c.Stream(ctx, http.MethodPost, "/exec/"+PathEscape(created.ID)+"/start", nil, map[string]any{"Detach": false, "Tty": false})
	if err != nil {
		return ExecResult{}, err
	}
	out := readFramed(res.Body, 64<<10, res.Header.Get("Content-Type") == "application/vnd.docker.raw-stream")
	res.Body.Close()
	if ctx.Err() != nil {
		return ExecResult{Output: out}, ctx.Err()
	}
	var ins struct {
		ExitCode int  `json:"ExitCode"`
		Running  bool `json:"Running"`
	}
	if err := c.Get(ctx, "/exec/"+PathEscape(created.ID)+"/json", nil, &ins); err != nil {
		return ExecResult{Output: out}, err
	}
	if ins.Running {
		return ExecResult{Output: out}, errors.New("the command was still running")
	}
	return ExecResult{ExitCode: ins.ExitCode, Output: out}, nil
}

// readFramed reads an attached stream to its end, keeping at most max bytes.
func readFramed(r io.Reader, max int, raw bool) string {
	var b strings.Builder
	add := func(p []byte) {
		if room := max - b.Len(); room > 0 {
			if len(p) > room {
				p = p[:room]
			}
			b.Write(p)
		}
	}
	if raw {
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Read(buf)
			add(buf[:n])
			if err != nil {
				return b.String()
			}
		}
	}
	br := bufio.NewReaderSize(r, 32<<10)
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return b.String()
		}
		n := binary.BigEndian.Uint32(hdr[4:])
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			add(buf)
			return b.String()
		}
		add(buf)
	}
}
