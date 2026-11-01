// Package sshprobe connects to a server over SSH, checks that the credentials
// work and reads which operating system it runs.
package sshprobe

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Status values, mirrored by the servers.status column.
const (
	StatusOnline          = "online"
	StatusUnreachable     = "unreachable"
	StatusAuthFailed      = "auth_failed"
	StatusHostKeyMismatch = "host_key_mismatch"
	StatusError           = "error"
)

const timeout = 15 * time.Second

type Target struct {
	Host       string
	Port       int
	User       string
	Password   string
	PrivateKey string
	Passphrase string
	// KnownHostKey is the trusted key in authorized_keys format; empty trusts
	// whatever key the server presents (trust on first use).
	KnownHostKey string
}

type OS struct {
	Family   string // linux, darwin, freebsd, windows…
	ID       string // ubuntu, debian, rocky, macos…
	Name     string // Ubuntu
	Version  string // 24.04
	Kernel   string
	Arch     string
	Hostname string
}

type Result struct {
	Status    string
	Message   string
	LatencyMs int32
	// HostKey is the key the server presented, in authorized_keys format.
	HostKey     string
	Fingerprint string
	// Detected is true when OS holds what the server reported.
	Detected bool
	OS       OS
}

var errHostKeyMismatch = errors.New("host key mismatch")

// ParseSigner validates a PEM/OpenSSH private key, decrypting it with the
// passphrase when one is given.
func ParseSigner(privateKey, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	}
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, errors.New("this private key is encrypted; enter its passphrase")
	}
	return signer, err
}

// Fingerprint formats an authorized_keys line as "SHA256:…"; "" when empty or
// unparsable.
func Fingerprint(authorizedKey string) string {
	if authorizedKey == "" {
		return ""
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(key)
}

// DialError is a failed connection, classified like a check result.
type DialError struct {
	Status  string
	Message string
}

func (e *DialError) Error() string { return e.Message }

// Presented is what the server showed during the handshake.
type Presented struct {
	// HostKey is the key the server presented, in authorized_keys format.
	HostKey     string
	Fingerprint string
	LatencyMs   int32
}

// Dial connects and authenticates; failures are *DialError. The client stays
// open until the caller closes it (no deadline once the handshake is done).
func Dial(ctx context.Context, t Target) (*ssh.Client, Presented, error) {
	var p Presented

	var auth []ssh.AuthMethod
	if t.PrivateKey != "" {
		signer, err := ParseSigner(t.PrivateKey, t.Passphrase)
		if err != nil {
			return nil, p, &DialError{StatusAuthFailed, "Private key: " + err.Error()}
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if t.Password != "" {
		auth = append(auth,
			ssh.Password(t.Password),
			// Many servers only offer keyboard-interactive for passwords.
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = t.Password
				}
				return answers, nil
			}),
		)
	}

	var known ssh.PublicKey
	if t.KnownHostKey != "" {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.KnownHostKey))
		if err == nil {
			known = k
		}
	}

	config := &ssh.ClientConfig{
		User:    t.User,
		Auth:    auth,
		Timeout: timeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			p.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			p.Fingerprint = ssh.FingerprintSHA256(key)
			if known != nil && !bytes.Equal(known.Marshal(), key.Marshal()) {
				return errHostKeyMismatch
			}
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, p, &DialError{StatusUnreachable, dialMessage(err)}
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		status, message := handshakeStatus(err)
		return nil, p, &DialError{status, message}
	}
	_ = conn.SetDeadline(time.Time{})
	p.LatencyMs = int32(time.Since(start).Milliseconds())
	return ssh.NewClient(sshConn, chans, reqs), p, nil
}

// Probe never returns an error: every failure becomes a Result status so the
// caller can store it as the server's state.
func Probe(ctx context.Context, t Target) Result {
	var res Result

	client, p, err := Dial(ctx, t)
	res.HostKey, res.Fingerprint = p.HostKey, p.Fingerprint
	if err != nil {
		var de *DialError
		if errors.As(err, &de) {
			res.Status, res.Message = de.Status, de.Message
		} else {
			res.Status, res.Message = StatusError, err.Error()
		}
		return res
	}
	defer client.Close()
	res.LatencyMs = p.LatencyMs
	res.Status = StatusOnline

	// Dial clears the deadline; keep OS detection inside the check's time.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()

	if osInfo, err := detectOS(client); err == nil {
		res.OS, res.Detected = osInfo, true
	} else {
		res.Message = "Connected, but couldn't detect the OS: " + err.Error()
	}
	return res
}

func dialMessage(err error) string {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return "Host not found: " + dnsErr.Name
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return "Connection timed out"
	case strings.Contains(err.Error(), "connection refused"):
		return "Connection refused: nothing is listening on that port"
	case strings.Contains(err.Error(), "no route to host"):
		return "No route to host"
	}
	return err.Error()
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func handshakeStatus(err error) (status, message string) {
	switch {
	case errors.Is(err, errHostKeyMismatch):
		return StatusHostKeyMismatch, "The server's host key changed since it was first trusted"
	// x/crypto reports a refused keyboard-interactive attempt as an
	// unexpected USERAUTH_FAILURE (51) rather than "unable to authenticate".
	case strings.Contains(err.Error(), "unable to authenticate"),
		strings.Contains(err.Error(), "unexpected message type 51"):
		return StatusAuthFailed, "Authentication failed: check the username and credentials"
	case isTimeout(err):
		return StatusUnreachable, "Timed out during the SSH handshake"
	case strings.Contains(err.Error(), "EOF"), strings.Contains(err.Error(), "connection reset"):
		return StatusUnreachable, "The server closed the connection; is it an SSH server?"
	}
	return StatusError, err.Error()
}

// One script covers Linux (os-release), macOS (sw_vers) and BSDs; Windows'
// OpenSSH runs cmd.exe, where it fails and we fall back to `ver`.
const unixScript = `uname -s; uname -r; uname -m; uname -n; echo ---; cat /etc/os-release 2>/dev/null || sw_vers 2>/dev/null; true`

func detectOS(client *ssh.Client) (OS, error) {
	out, err := run(client, unixScript)
	if err == nil {
		if info, ok := parseUnix(out); ok {
			return info, nil
		}
	}
	if out, werr := run(client, "ver"); werr == nil && strings.Contains(out, "Windows") {
		return parseWindows(out), nil
	}
	if err == nil {
		err = errors.New("unrecognised output")
	}
	return OS{}, err
}

func run(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	out, err := session.Output(cmd)
	return string(out), err
}

func parseUnix(out string) (OS, bool) {
	head, release, _ := strings.Cut(out, "---\n")
	lines := strings.Split(strings.TrimSpace(head), "\n")
	if len(lines) < 4 || lines[0] == "" {
		return OS{}, false
	}
	info := OS{
		Family:   strings.ToLower(strings.TrimSpace(lines[0])),
		Kernel:   strings.TrimSpace(lines[1]),
		Arch:     strings.TrimSpace(lines[2]),
		Hostname: strings.TrimSpace(lines[3]),
	}
	fields := keyValues(release)

	switch {
	case fields["ID"] != "": // os-release
		info.ID = strings.ToLower(fields["ID"])
		info.Name = fields["NAME"]
		info.Version = fields["VERSION_ID"]
		// Some distros' NAME carries a suffix ("Debian GNU/Linux"); keep the
		// short, recognisable form for the common ones.
		if short, ok := shortNames[info.ID]; ok {
			info.Name = short
		}
	case fields["ProductVersion"] != "": // sw_vers
		info.ID, info.Name, info.Version = "macos", "macOS", fields["ProductVersion"]
	default:
		info.ID = info.Family
		info.Name = strings.TrimSpace(lines[0])
		info.Version = info.Kernel
	}
	if info.Family == "darwin" && info.ID == "" {
		info.ID, info.Name = "macos", "macOS"
	}
	return info, true
}

var shortNames = map[string]string{
	"debian":        "Debian",
	"ubuntu":        "Ubuntu",
	"rhel":          "RHEL",
	"centos":        "CentOS",
	"rocky":         "Rocky Linux",
	"almalinux":     "AlmaLinux",
	"fedora":        "Fedora",
	"opensuse-leap": "openSUSE Leap",
	"sles":          "SLES",
	"arch":          "Arch Linux",
	"alpine":        "Alpine",
	"amzn":          "Amazon Linux",
	"ol":            "Oracle Linux",
}

// keyValues reads KEY=value (os-release) and "Key:\tvalue" (sw_vers) lines.
func keyValues(s string) map[string]string {
	fields := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			key, value, ok = strings.Cut(line, ":")
		}
		if ok {
			fields[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return fields
}

// "Microsoft Windows [Version 10.0.20348.2340]"
func parseWindows(out string) OS {
	info := OS{Family: "windows", ID: "windows", Name: "Windows"}
	if _, rest, ok := strings.Cut(out, "Version "); ok {
		info.Version = strings.TrimRight(strings.TrimSpace(rest), "]")
		info.Kernel = info.Version
	}
	return info
}
