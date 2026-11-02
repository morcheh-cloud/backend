package dbmon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// DatabaseTestStep is one step of a connection test.
type DatabaseTestStep struct {
	ID      string `json:"id" enum:"dns,tcp,tls,auth,permissions"`
	Title   string `json:"title" example:"Sign in"`
	Status  string `json:"status" enum:"ok,warning,failed,skipped"`
	Message string `json:"message"`
	Ms      int64  `json:"ms" doc:"How long the step took"`
}

// DatabaseTest is what a connection test found, step by step. Status is the
// status a look would end in.
type DatabaseTest struct {
	Status  string             `json:"status" enum:"online,unreachable,auth_failed,tls_error,blocked,error"`
	Message string             `json:"message"`
	Flavor  string             `json:"flavor,omitempty"`
	Version string             `json:"version,omitempty"`
	Steps   []DatabaseTestStep `json:"steps"`
}

type tester struct {
	t   DatabaseTest
	cfg Config
}

func (t *tester) step(id, title, status, msg string, start time.Time) {
	var ms int64
	if !start.IsZero() {
		ms = time.Since(start).Milliseconds()
	}
	t.t.Steps = append(t.t.Steps, DatabaseTestStep{ID: id, Title: title, Status: status, Message: msg, Ms: ms})
}

// skip marks every step from id on as not reached.
func (t *tester) skip(ids ...string) {
	for _, id := range ids {
		t.step(id, stepTitles[id], "skipped", "Not reached", time.Time{})
	}
}

func (t *tester) fail(status, msg string) *DatabaseTest {
	t.t.Status, t.t.Message = status, msg
	return &t.t
}

var stepTitles = map[string]string{
	"dns":         "Resolve the name",
	"tcp":         "Open the port",
	"tls":         "Encryption",
	"auth":        "Sign in",
	"permissions": "Monitoring permissions",
}

// Diagnose tests a connection step by step: DNS (direct only; a tunnel's
// server resolves the name), TCP, TLS + sign-in, then one full look to find
// what the login can't read. It never fails as a call; the failure is in the
// result.
func Diagnose(ctx context.Context, cfg Config) *DatabaseTest {
	t := &tester{cfg: cfg}

	// DNS.
	if cfg.Tunneled {
		t.step("dns", stepTitles["dns"], "skipped", "Resolved by the server the connection goes through", time.Time{})
	} else {
		start := time.Now()
		addrs, err := resolve(ctx, cfg.Host, cfg.timeout())
		if err != nil {
			t.step("dns", stepTitles["dns"], "failed", err.Error(), start)
			t.skip("tcp", "tls", "auth", "permissions")
			return t.fail(StatusUnreachable, err.Error())
		}
		list := ""
		for i, a := range addrs {
			if i == 3 {
				list += fmt.Sprintf(" and %d more", len(addrs)-3)
				break
			}
			if i > 0 {
				list += ", "
			}
			list += a.String()
		}
		t.step("dns", stepTitles["dns"], "ok", list, start)
	}

	// TCP.
	start := time.Now()
	dctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	raw, err := cfg.dialer()(dctx, "tcp", cfg.addr())
	cancel()
	if err != nil {
		status, msg := Classify(err)
		if status == StatusError {
			status = StatusUnreachable
		}
		t.step("tcp", stepTitles["tcp"], "failed", msg, start)
		t.skip("tls", "auth", "permissions")
		return t.fail(status, msg)
	}
	raw.Close()
	t.step("tcp", stepTitles["tcp"], "ok", "Port "+itoa(cfg.Port)+" accepts connections", start)

	// TLS and sign-in happen together inside each driver's handshake.
	start = time.Now()
	conn, err := Open(ctx, cfg)
	if err != nil {
		status, msg := Classify(err)
		switch status {
		case StatusTLSError:
			t.step("tls", stepTitles["tls"], "failed", msg, start)
			t.skip("auth", "permissions")
		default:
			t.tlsOK(start)
			t.step("auth", stepTitles["auth"], "failed", msg, start)
			t.skip("permissions")
		}
		return t.fail(status, msg)
	}
	defer conn.Close()
	t.tlsOK(start)
	t.step("auth", stepTitles["auth"], "ok", "Signed in as "+cmp(cfg.Username, "the default user"), start)

	// One full look.
	start = time.Now()
	s, err := conn.Collect(ctx, true)
	if err != nil {
		status, msg := Classify(err)
		t.step("permissions", stepTitles["permissions"], "failed", msg, start)
		return t.fail(status, msg)
	}
	t.t.Flavor, t.t.Version = s.Flavor, s.Version
	switch n := len(s.Notes); n {
	case 0:
		t.step("permissions", stepTitles["permissions"], "ok", "Everything could be read", start)
	default:
		msg := s.Notes[0].Message
		if n > 1 {
			msg = fmt.Sprintf("%d things couldn't be read. %s", n, msg)
		}
		t.step("permissions", stepTitles["permissions"], "warning", msg, start)
	}
	t.t.Status = StatusOnline
	return &t.t
}

func (t *tester) tlsOK(start time.Time) {
	switch t.cfg.TLS {
	case TLSDisable, "":
		t.step("tls", stepTitles["tls"], "warning", "Off: passwords and data cross the network readable", time.Time{})
	case TLSRequire:
		t.step("tls", stepTitles["tls"], "ok", "Encrypted (the certificate isn't checked)", start)
	default:
		t.step("tls", stepTitles["tls"], "ok", "Encrypted, certificate verified", start)
	}
}

// resolve looks the host up and refuses it the way DirectDialer would, so the
// step names the problem before anything is dialed.
func resolve(ctx context.Context, host string, timeout time.Duration) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%s doesn't resolve: %w", host, err)
	}
	return addrs, nil
}

// Public reports whether host is a public address (or a name for one).
// Unresolvable names count as not public.
func Public(ctx context.Context, host string) bool {
	addrs, err := resolve(ctx, host, 3*time.Second)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if Internal(a) {
			return false
		}
	}
	return len(addrs) > 0
}
