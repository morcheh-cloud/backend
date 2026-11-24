package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/proxy"
)

const dialTimeout = 20 * time.Second

func selfExe() string {
	p, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return p
}

// redact drops control characters (terminal colours, carriage returns).
func redact(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func socksDialer(s Spec) DialFunc {
	addr := hostPort(s.Config.Host, s.Config.Port)
	var auth *proxy.Auth
	if s.Config.Username != "" {
		auth = &proxy.Auth{User: s.Config.Username, Password: s.Secrets.Password}
	}
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		d, err := proxy.SOCKS5("tcp", addr, auth, &net.Dialer{Timeout: dialTimeout})
		if err != nil {
			return nil, err
		}
		c, err := d.(proxy.ContextDialer).DialContext(ctx, network, target)
		if err != nil {
			return nil, socksMessage(addr, err)
		}
		return c, nil
	}
}

func socksMessage(addr string, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "username/password authentication failed"):
		return errors.New("the SOCKS proxy refused the username or password")
	case strings.Contains(msg, "no acceptable authentication methods"):
		return errors.New("the SOCKS proxy wants a login: set a username and password")
	case strings.Contains(msg, "connection refused") && strings.Contains(msg, addr):
		return fmt.Errorf("nothing answers at %s (is the proxy running?)", addr)
	}
	return fmt.Errorf("through the SOCKS proxy: %w", err)
}

func httpDialer(s Spec) DialFunc {
	addr := hostPort(s.Config.Host, s.Config.Port)
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, errors.New("an HTTP proxy only carries TCP")
		}
		var c net.Conn
		var err error
		d := &net.Dialer{Timeout: dialTimeout}
		if s.Config.TLS {
			c, err = (&tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: s.Config.Host}}).DialContext(ctx, "tcp", addr)
		} else {
			c, err = d.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			return nil, fmt.Errorf("couldn't reach the proxy: %w", err)
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		} else {
			_ = c.SetDeadline(time.Now().Add(dialTimeout))
		}
		req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
		if s.Config.Username != "" {
			cred := base64.StdEncoding.EncodeToString([]byte(s.Config.Username + ":" + s.Secrets.Password))
			req += "Proxy-Authorization: Basic " + cred + "\r\n"
		}
		req += "\r\n"
		if _, err := c.Write([]byte(req)); err != nil {
			c.Close()
			return nil, err
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("the proxy's answer can't be read: %w", err)
		}
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusProxyAuthRequired:
			c.Close()
			return nil, errors.New("the HTTP proxy wants a login (or refused it)")
		case resp.StatusCode/100 != 2:
			c.Close()
			return nil, fmt.Errorf("the HTTP proxy refused: %s", resp.Status)
		}
		_ = c.SetDeadline(time.Time{})
		if br.Buffered() > 0 {
			return &buffered{Conn: c, r: br}, nil
		}
		return c, nil
	}
}

// buffered keeps what the proxy sent after its answer.
type buffered struct {
	net.Conn
	r *bufio.Reader
}

func (b *buffered) Read(p []byte) (int, error) { return b.r.Read(p) }
