package uptime

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/smtp"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/morcheh/backend/internal/dbmon"
)

func dial(ctx context.Context, env Env, network, address string) (net.Conn, error) {
	d := env.Dial
	if d == nil {
		d = Dialer(dbmon.DirectDialer(env.AllowInternal))
	}
	conn, err := d(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return conn, nil
}

// wrapTLS starts TLS on conn when mode is "tls".
func wrapTLS(ctx context.Context, conn net.Conn, c MonitorConfig, mode string) (net.Conn, error) {
	if mode != "tls" {
		return conn, nil
	}
	name := c.ServerName
	if name == "" {
		name = strings.Trim(strings.TrimSpace(c.Host), "[]")
	}
	tc := tls.Client(conn, &tls.Config{ServerName: name, InsecureSkipVerify: c.IgnoreTLS, MinVersion: tls.VersionTLS10})
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}

func checkTCP(ctx context.Context, c MonitorConfig, env Env) CheckResult {
	start := time.Now()
	conn, err := dial(ctx, env, "tcp", addr(c, 0))
	if err != nil {
		return down("%s", errText(err))
	}
	defer conn.Close()
	conn, err = wrapTLS(ctx, conn, c, c.TLSMode)
	if err != nil {
		return down("TLS failed: %s", errText(err))
	}
	r := CheckResult{Status: Up, Message: "Port is open"}
	if c.TLSMode == "tls" {
		r.Message = "Port is open, TLS works"
		if tc, ok := conn.(*tls.Conn); ok {
			if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
				certWindow(&r, cs.PeerCertificates[0].NotAfter, c.CertDays)
			}
		}
	}
	if c.Send == "" && c.Expect == "" {
		r.took(start)
		return r
	}
	if c.Send != "" {
		if _, err := conn.Write([]byte(unescape(c.Send))); err != nil {
			return down("Couldn't send: %s", errText(err))
		}
	}
	if c.Expect == "" {
		r.took(start)
		return r
	}
	got, err := readUntil(conn, c.Expect, 64<<10)
	r.took(start)
	r.Detail = clip(got, 2000)
	if !strings.Contains(got, unescape(c.Expect)) {
		r.Status = Down
		if err != nil && got == "" {
			r.Message = "No answer: " + errText(err)
		} else {
			r.Message = fmt.Sprintf("%q isn't in the answer", c.Expect)
		}
		return r
	}
	r.Message = "Answered as expected"
	return r
}

// readUntil reads until want shows up, the peer stops, or limit bytes.
func readUntil(conn net.Conn, want string, limit int) (string, error) {
	want = unescape(want)
	var b strings.Builder
	buf := make([]byte, 4096)
	for b.Len() < limit {
		n, err := conn.Read(buf)
		b.Write(buf[:n])
		if strings.Contains(b.String(), want) {
			return b.String(), nil
		}
		if err != nil {
			return b.String(), err
		}
	}
	return b.String(), nil
}

func checkUDP(ctx context.Context, c MonitorConfig, env Env) CheckResult {
	if env.Tunneled {
		return down("UDP can only be checked from Morcheh itself")
	}
	start := time.Now()
	conn, err := dial(ctx, env, "udp", addr(c, 0))
	if err != nil {
		return down("%s", errText(err))
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(unescape(c.Send))); err != nil {
		return down("Couldn't send: %s", errText(err))
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	r := CheckResult{}
	r.took(start)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return down("No answer came back (UDP can't tell a closed port from a silent one)")
		}
		return down("%s", errText(err))
	}
	got := string(buf[:n])
	r.Detail = clip(got, 2000)
	if c.Expect != "" && !strings.Contains(got, unescape(c.Expect)) {
		r.Status = Down
		r.Message = fmt.Sprintf("%q isn't in the answer", c.Expect)
		return r
	}
	r.Status = Up
	r.Message = fmt.Sprintf("Answered (%d bytes)", n)
	return r
}

func checkTLS(ctx context.Context, c MonitorConfig, env Env) CheckResult {
	start := time.Now()
	conn, err := dial(ctx, env, "tcp", addr(c, 443))
	if err != nil {
		return down("%s", errText(err))
	}
	defer conn.Close()
	name := c.ServerName
	if name == "" {
		name = strings.Trim(strings.TrimSpace(c.Host), "[]")
	}
	// Handshake without verifying first so an untrusted or expired certificate
	// still gets its date read, then verify by hand.
	tc := tls.Client(conn, &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
	if err := tc.HandshakeContext(ctx); err != nil {
		return down("TLS handshake failed: %s", errText(err))
	}
	r := CheckResult{Status: Up}
	r.took(start)
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return down("The server sent no certificate")
	}
	leaf := cs.PeerCertificates[0]
	r.Code = tls.VersionName(cs.Version)
	r.Message = fmt.Sprintf("%s, certificate for %s valid until %s", r.Code, leaf.Subject.CommonName, leaf.NotAfter.Format("2 Jan 2006"))
	if !c.IgnoreTLS {
		inter := x509Pool(cs.PeerCertificates[1:])
		if _, err := leaf.Verify(verifyOpts(name, inter)); err != nil {
			t := leaf.NotAfter
			r.CertExpires = &t
			r.Status = Down
			r.Message = "The certificate isn't trusted: " + err.Error()
			return r
		}
	}
	certWindow(&r, leaf.NotAfter, c.CertDays)
	return r
}

// ---- ping ----

var (
	lossRe = regexp.MustCompile(`(\d+(?:\.\d+)?)% packet loss`)
	rttRe  = regexp.MustCompile(`= ([\d.]+)/([\d.]+)/([\d.]+)`)
)

func localRun(ctx context.Context, argv []string) (string, int, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode(), nil
	}
	if err != nil {
		return string(out), -1, err
	}
	return string(out), 0, nil
}

func checkPing(ctx context.Context, c MonitorConfig, env Env) CheckResult {
	host := strings.Trim(strings.TrimSpace(c.Host), "[]")
	if strings.HasPrefix(host, "-") {
		return down("Bad host")
	}
	count := c.Count
	if count <= 0 {
		count = 3
	}
	run := env.Run
	if run == nil {
		// From Morcheh itself: refuse private addresses unless allowed.
		if !env.AllowInternal {
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return down("%s", errText(err))
			}
			for _, ip := range ips {
				if dbmon.Internal(ip) {
					return down("%s", (&dbmon.BlockedError{Addr: ip.String()}).Error())
				}
			}
		}
		run = localRun
	}
	wait := int(env.Timeout.Seconds())
	if wait < 1 {
		wait = 1
	}
	argv := []string{"ping", "-n", "-c", strconv.Itoa(count), "-i", "0.2", "-W", "2", "-w", strconv.Itoa(wait), host}
	out, code, err := run(ctx, argv)
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			return down("ping isn't installed where the check runs")
		}
		return down("Couldn't run ping: %s", errText(err))
	}
	r := CheckResult{Code: strconv.Itoa(code), Detail: clip(out, 2000)}
	loss := 100.0
	if m := lossRe.FindStringSubmatch(out); m != nil {
		loss, _ = strconv.ParseFloat(m[1], 64)
	}
	if m := rttRe.FindStringSubmatch(out); m != nil {
		avg, _ := strconv.ParseFloat(m[2], 64)
		ms := int(avg + 0.5)
		r.LatencyMs = &ms
	}
	switch {
	case loss >= 100:
		r.Status = Down
		r.Message = "No reply"
		if strings.Contains(out, "unknown host") || strings.Contains(out, "Name or service not known") || strings.Contains(out, "Temporary failure in name resolution") {
			r.Message = "The name " + host + " doesn't resolve"
		} else if code != 0 && code != 1 && !strings.Contains(out, "packet loss") {
			r.Message = "ping failed: " + clip(out, 200)
		}
	case loss > 0:
		r.Status = Degraded
		r.Message = fmt.Sprintf("%.0f%% packet loss", loss)
	default:
		r.Status = Up
		r.Message = fmt.Sprintf("%d of %d replies", count, count)
	}
	return r
}

// ---- DNS ----

func checkDNS(ctx context.Context, c MonitorConfig, env Env) CheckResult {
	name := strings.TrimSuffix(strings.TrimSpace(c.Name), ".")
	typ := c.RecordType
	if typ == "" {
		typ = "A"
	}
	resolver := net.DefaultResolver
	if server := strings.TrimSpace(c.Resolver); server != "" {
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(strings.Trim(server, "[]"), "53")
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				if env.Tunneled {
					// SSH tunnels carry TCP only; DNS over TCP works everywhere.
					network = "tcp"
				}
				return dial(ctx, env, network, server)
			},
		}
	}
	start := time.Now()
	var got []string
	var err error
	switch typ {
	case "A", "AAAA":
		var ips []netip.Addr
		netw := "ip4"
		if typ == "AAAA" {
			netw = "ip6"
		}
		ips, err = resolver.LookupNetIP(ctx, netw, name)
		for _, ip := range ips {
			got = append(got, ip.Unmap().String())
		}
	case "CNAME":
		var cn string
		cn, err = resolver.LookupCNAME(ctx, name)
		if cn != "" {
			got = append(got, strings.TrimSuffix(cn, "."))
		}
	case "MX":
		var mx []*net.MX
		mx, err = resolver.LookupMX(ctx, name)
		for _, m := range mx {
			got = append(got, strings.TrimSuffix(m.Host, "."))
		}
	case "NS":
		var ns []*net.NS
		ns, err = resolver.LookupNS(ctx, name)
		for _, n := range ns {
			got = append(got, strings.TrimSuffix(n.Host, "."))
		}
	case "TXT":
		got, err = resolver.LookupTXT(ctx, name)
	default:
		return down("Unknown record type %s", typ)
	}
	r := CheckResult{}
	r.took(start)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			r.Status = Down
			r.Code = "NXDOMAIN"
			r.Message = fmt.Sprintf("No %s record for %s", typ, name)
			return r
		}
		r.Status = Down
		r.Message = errText(err)
		return r
	}
	slices.Sort(got)
	r.Detail = strings.Join(got, "\n")
	r.Code = "NOERROR"
	if len(got) == 0 {
		r.Status = Down
		r.Message = fmt.Sprintf("No %s record for %s", typ, name)
		return r
	}
	for _, want := range c.Expected {
		want = strings.TrimSuffix(strings.TrimSpace(want), ".")
		if want == "" {
			continue
		}
		if !slices.ContainsFunc(got, func(g string) bool { return strings.EqualFold(g, want) }) {
			r.Status = Down
			r.Message = fmt.Sprintf("%s isn't among the answers (%s)", want, clip(strings.Join(got, ", "), 200))
			return r
		}
	}
	r.Status = Up
	r.Message = fmt.Sprintf("%s → %s", typ, clip(strings.Join(got, ", "), 200))
	return r
}

// ---- SMTP ----

func checkSMTP(ctx context.Context, c MonitorConfig, s MonitorSecrets, env Env) CheckResult {
	mode := c.TLSMode
	if mode == "" {
		mode = "starttls"
	}
	defPort := map[string]int{"tls": 465, "starttls": 587, "none": 25}[mode]
	if defPort == 0 {
		defPort = 25
	}
	start := time.Now()
	conn, err := dial(ctx, env, "tcp", addr(c, defPort))
	if err != nil {
		return down("%s", errText(err))
	}
	defer conn.Close()
	host := strings.Trim(strings.TrimSpace(c.Host), "[]")
	conn, err = wrapTLS(ctx, conn, c, mode)
	if err != nil {
		return down("TLS failed: %s", errText(err))
	}
	br := bufio.NewReader(conn)
	banner, err := br.ReadString('\n')
	if err != nil {
		return down("No greeting: %s", errText(err))
	}
	if !strings.HasPrefix(banner, "220") {
		return CheckResult{Status: Down, Code: clip(banner, 3), Message: "The server greeted with: " + clip(banner, 200)}
	}
	// Hand the rest to net/smtp over a conn that replays what we read.
	cl, err := smtp.NewClient(&prefixed{Conn: conn, r: br, first: banner}, host)
	if err != nil {
		return down("SMTP failed: %s", errText(err))
	}
	defer cl.Close()
	if err := cl.Hello("morcheh"); err != nil {
		return down("EHLO was refused: %s", errText(err))
	}
	r := CheckResult{Status: Up, Code: "220", Message: "Greeted: " + clip(strings.TrimPrefix(strings.TrimSpace(banner), "220 "), 160)}
	if mode == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return CheckResult{Status: Down, Code: "220", Message: "The server doesn't offer STARTTLS"}
		}
		if err := cl.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: c.IgnoreTLS, MinVersion: tls.VersionTLS10}); err != nil {
			return down("STARTTLS failed: %s", errText(err))
		}
		if cs, ok := cl.TLSConnectionState(); ok && len(cs.PeerCertificates) > 0 {
			certWindow(&r, cs.PeerCertificates[0].NotAfter, c.CertDays)
		}
	}
	if mode == "tls" {
		if tc, ok := conn.(*tls.Conn); ok {
			if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
				certWindow(&r, cs.PeerCertificates[0].NotAfter, c.CertDays)
			}
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, s.Password, host)); err != nil {
			return CheckResult{Status: Down, Code: "535", Message: "Sign-in was refused: " + errText(err)}
		}
		if r.Status == Up {
			r.Message += ", signed in"
		}
	}
	_ = cl.Quit()
	r.took(start)
	return r
}

// prefixed replays the greeting already read, since net/smtp reads it again.
type prefixed struct {
	net.Conn
	r     *bufio.Reader
	first string
}

func (p *prefixed) Read(b []byte) (int, error) {
	if p.first != "" {
		n := copy(b, p.first)
		p.first = p.first[n:]
		return n, nil
	}
	return p.r.Read(b)
}

func x509Pool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

func verifyOpts(name string, inter *x509.CertPool) x509.VerifyOptions {
	return x509.VerifyOptions{DNSName: name, Intermediates: inter}
}
