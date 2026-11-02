package dbmon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// BlockedError is a direct connection refused before it left: the name
// resolves to an address only an admin may allow (loopback, a private
// network, link-local, cloud metadata).
type BlockedError struct{ Addr string }

func (e *BlockedError) Error() string {
	return fmt.Sprintf("%s is an internal address; only an admin can allow internal addresses", e.Addr)
}

// metadata endpoints some clouds serve outside the link-local range.
var metadata = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"), // Alibaba
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IPv6
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Internal reports whether an address is one a direct connection may only
// reach when an admin allowed it.
func Internal(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsInterfaceLocalMulticast() || cgnat.Contains(a) {
		return true
	}
	for _, m := range metadata {
		if a == m {
			return true
		}
	}
	return false
}

// DirectDialer reaches a database over the network from Morcheh itself. The
// check runs on the address actually dialed (after DNS), so a name that
// resolves somewhere internal is refused too, even if it changes later.
func DirectDialer(allowInternal bool) Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !allowInternal {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if Internal(ap.Addr()) {
				return &BlockedError{Addr: ap.Addr().String()}
			}
			return nil
		}
	}
	return d.DialContext
}

// tlsConfig is nil when TLS is off. "require" encrypts without checking who
// answers (like libpq's sslmode=require); "verify" checks the certificate
// against the given CA, or the system's.
func (c Config) tlsConfig() (*tls.Config, error) {
	switch c.TLS {
	case TLSRequire:
		return &tls.Config{ServerName: c.Host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, nil
	case TLSVerify:
		t := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
		if strings.TrimSpace(c.CACert) != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(c.CACert)) {
				return nil, errors.New("the CA certificate isn't valid PEM")
			}
			t.RootCAs = pool
		}
		return t, nil
	}
	return nil, nil
}

func (c Config) dialer() Dialer {
	if c.Dial != nil {
		return c.Dial
	}
	return DirectDialer(false)
}

func itoa(n int) string { return strconv.Itoa(n) }

// ---- Errors ----

// Statuses a failed look ends in.
const (
	StatusOnline      = "online"
	StatusUnreachable = "unreachable"
	StatusAuthFailed  = "auth_failed"
	StatusTLSError    = "tls_error"
	StatusBlocked     = "blocked"
	StatusError       = "error"
)

// Classify turns a connection error into a status and a message a person can
// act on.
func Classify(err error) (string, string) {
	if err == nil {
		return StatusOnline, ""
	}
	var blocked *BlockedError
	if errors.As(err, &blocked) {
		return StatusBlocked, blocked.Error()
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case authError(err, low):
		return StatusAuthFailed, msg
	case strings.Contains(low, "x509:") || strings.Contains(low, "tls:") ||
		strings.Contains(low, "certificate") || strings.Contains(low, "ssl") ||
		strings.Contains(low, "handshake"):
		return StatusTLSError, msg
	}
	var nerr net.Error
	var operr *net.OpError
	var dnserr *net.DNSError
	if errors.As(err, &operr) || errors.As(err, &dnserr) ||
		(errors.As(err, &nerr) && nerr.Timeout()) ||
		errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(low, "connection refused") ||
		strings.Contains(low, "no such host") ||
		strings.Contains(low, "i/o timeout") ||
		strings.Contains(low, "server selection") ||
		strings.Contains(low, "connect: ") ||
		strings.Contains(low, "eof") {
		return StatusUnreachable, msg
	}
	return StatusError, msg
}

func authError(err error, low string) bool {
	if engineAuthError(err) {
		return true
	}
	for _, s := range []string{
		"password authentication failed", "access denied", "login failed",
		"wrongpass", "noauth", "invalid username-password", "authentication failed",
		"auth error", "no pg_hba.conf entry", "invalid password",
	} {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}
