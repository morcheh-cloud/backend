// Package uptime checks whether something answers the way it should: web
// addresses, sockets, DNS, certificates, databases, message queues, mail
// servers and things on a panel server (containers, services, commands). It
// knows nothing about the database or HTTP API: the caller passes how to
// reach the network (directly or through a server over SSH) and how to run a
// command, and gets a Result back.
package uptime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/morcheh/backend/internal/dbmon"
)

// Statuses a check ends in.
const (
	Up       = "up"
	Degraded = "degraded"
	Down     = "down"
)

// Kinds of monitor.
const (
	HTTP          = "http"
	TCP           = "tcp"
	UDP           = "udp"
	Ping          = "ping"
	DNS           = "dns"
	TLS           = "tls"
	WebSocket     = "websocket"
	SocketIO      = "socketio"
	SMTP          = "smtp"
	Database      = "database"
	RabbitMQ      = "rabbitmq"
	Kafka         = "kafka"
	NATS          = "nats"
	MQTT          = "mqtt"
	Memcached     = "memcached"
	Elasticsearch = "elasticsearch"
	Docker        = "docker"
	Systemd       = "systemd"
	Command       = "command"
	Push          = "push"
)

// Kinds lists every kind.
var Kinds = []string{
	HTTP, TCP, UDP, Ping, DNS, TLS, WebSocket, SocketIO, SMTP, Database,
	RabbitMQ, Kafka, NATS, MQTT, Memcached, Elasticsearch, Docker, Systemd,
	Command, Push,
}

// OnServer kinds run a command on a panel server, so they need one.
func OnServer(kind string) bool {
	return kind == Docker || kind == Systemd || kind == Command
}

// Config is a monitor's plain settings; each kind reads its own.
type MonitorConfig struct {
	// http, websocket, socketio, elasticsearch
	URL             string            `json:"url,omitempty" maxLength:"2000"`
	Method          string            `json:"method,omitempty" enum:"GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS,"`
	Headers         map[string]string `json:"headers,omitempty" doc:"Request headers (put secret ones in secrets.headers)"`
	Body            string            `json:"body,omitempty" maxLength:"65536"`
	Statuses        []string          `json:"statuses,omitempty" maxItems:"20" doc:"Accepted status codes or ranges, e.g. 200-299, 301; blank = 200-399"`
	NoRedirects     bool              `json:"no_redirects,omitempty" doc:"Don't follow redirects"`
	IgnoreTLS       bool              `json:"ignore_tls,omitempty" doc:"Accept a certificate that doesn't verify"`
	Keyword         string            `json:"keyword,omitempty" maxLength:"1000" doc:"http/websocket: text the answer must (or must not) contain"`
	KeywordMode     string            `json:"keyword_mode,omitempty" enum:"contains,absent,regex," doc:"contains (default), absent, or regex"`
	KeywordCase     bool              `json:"keyword_case,omitempty" doc:"Match case"`
	JSONPath        string            `json:"json_path,omitempty" maxLength:"300" doc:"http: a value in a JSON answer, e.g. status or data.items[0].ok"`
	JSONOp          string            `json:"json_op,omitempty" enum:"eq,ne,contains,gt,lt,exists," doc:"How the value is compared (default eq)"`
	JSONValue       string            `json:"json_value,omitempty" maxLength:"1000"`
	Username        string            `json:"username,omitempty" maxLength:"255" doc:"Basic auth for http; the login for databases, SMTP, queues"`
	DegradedMs      int               `json:"degraded_ms,omitempty" minimum:"0" maximum:"600000" doc:"Slower than this counts as degraded; 0 = never"`
	CertDays        int               `json:"cert_days,omitempty" minimum:"0" maximum:"365" doc:"https/tls: degraded when the certificate expires within this many days; 0 = 14"`
	Host            string            `json:"host,omitempty" maxLength:"255"`
	Port            int               `json:"port,omitempty" minimum:"0" maximum:"65535"`
	TLSMode         string            `json:"tls_mode,omitempty" enum:"none,tls,starttls,disable,require,verify," doc:"tcp/queues: none or tls; smtp: none, tls or starttls; database: disable, require or verify"`
	ServerName      string            `json:"server_name,omitempty" maxLength:"255" doc:"tls: the name to ask for (SNI), when not the host"`
	Send            string            `json:"send,omitempty" maxLength:"4096" doc:"tcp/udp/websocket: what to send once connected (\\r\\n and \\n are understood)"`
	Expect          string            `json:"expect,omitempty" maxLength:"1000" doc:"tcp/udp/websocket: what the answer must contain"`
	Count           int               `json:"count,omitempty" minimum:"0" maximum:"20" doc:"ping: packets to send (default 3)"`
	Name            string            `json:"name,omitempty" maxLength:"255" doc:"dns: the name to look up"`
	RecordType      string            `json:"record_type,omitempty" enum:"A,AAAA,CNAME,MX,NS,TXT," doc:"dns: default A"`
	Resolver        string            `json:"resolver,omitempty" maxLength:"255" doc:"dns: the server to ask (ip or ip:port); blank = the system's"`
	Expected        []string          `json:"expected,omitempty" maxItems:"20" doc:"dns: values the answer must include"`
	Engine          string            `json:"engine,omitempty" enum:"postgres,mysql,mssql,redis,mongodb," doc:"database: which one"`
	Database        string            `json:"database,omitempty" maxLength:"255" doc:"database: the database to connect to"`
	Container       string            `json:"container,omitempty" maxLength:"255" doc:"docker: the container name or id"`
	Unit            string            `json:"unit,omitempty" maxLength:"255" doc:"systemd: the unit, e.g. nginx.service"`
	Script          string            `json:"script,omitempty" maxLength:"16384" doc:"command: a shell command; exit 0 = up, 1 = degraded, anything else = down"`
	Sudo            bool              `json:"sudo,omitempty" doc:"command/docker: run through sudo -n"`
	MinHealthStatus string            `json:"min_health,omitempty" enum:"green,yellow," doc:"elasticsearch: the worst cluster status still counted as up (default green)"`
}

// Secrets is a monitor's secret settings, sealed at rest.
type MonitorSecrets struct {
	Password string            `json:"password,omitempty" maxLength:"1000"`
	Token    string            `json:"token,omitempty" maxLength:"4000" doc:"http/websocket/elasticsearch: sent as Authorization: Bearer; nats: the auth token"`
	Headers  map[string]string `json:"headers,omitempty" doc:"Secret request headers (API keys)"`
}

// Names lists which secrets are set.
func (s MonitorSecrets) Names() []string {
	out := []string{}
	if s.Password != "" {
		out = append(out, "password")
	}
	if s.Token != "" {
		out = append(out, "token")
	}
	for k := range s.Headers {
		out = append(out, "header:"+k)
	}
	return out
}

// Merge keeps saved secrets where the new ones are blank. A secret header
// with a blank value keeps its saved value; one left out is removed.
func (s MonitorSecrets) Merge(saved MonitorSecrets) MonitorSecrets {
	if s.Password == "" {
		s.Password = saved.Password
	}
	if s.Token == "" {
		s.Token = saved.Token
	}
	for k, v := range s.Headers {
		if v == "" {
			s.Headers[k] = saved.Headers[k]
		}
	}
	return s
}

// Dialer opens a network connection: guarded and direct from Morcheh, or
// through a server over SSH.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Runner runs a program (argv) and returns what it printed and its exit code.
// err is only for "couldn't run it at all".
type Runner func(ctx context.Context, argv []string) (out string, code int, err error)

// Env is where a check runs.
type Env struct {
	Dial Dialer
	Run  Runner
	// Tunneled: Dial is an SSH tunnel (names are resolved by the server; no
	// UDP).
	Tunneled      bool
	AllowInternal bool
	Timeout       time.Duration
}

// Result is what one check found.
type CheckResult struct {
	Status      string     `json:"status" enum:"up,degraded,down"`
	LatencyMs   *int       `json:"latency_ms,omitempty"`
	Code        string     `json:"code,omitempty" doc:"The answer in short: an HTTP status, a DNS rcode, an exit code…"`
	Message     string     `json:"message"`
	CertExpires *time.Time `json:"cert_expires,omitempty"`
	// Detail is shown by Test only: the start of the answer.
	Detail string `json:"detail,omitempty"`
	// Locations: what each location found, when checked from several.
	Locations []LocationResult `json:"locations,omitempty"`
}

func down(format string, a ...any) CheckResult {
	return CheckResult{Status: Down, Message: fmt.Sprintf(format, a...)}
}

func (r *CheckResult) took(start time.Time) {
	ms := int(time.Since(start).Milliseconds())
	r.LatencyMs = &ms
}

// FieldError is a setting that's missing or wrong, keyed like the API body.
type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string { return e.Message }

func fe(field, msg string) *FieldError { return &FieldError{"config." + field, msg} }

var hostName = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]%]+$`)

// Validate says what a monitor is missing before it's saved. via says whether
// any of its locations is a panel server.
func Validate(kind string, c MonitorConfig, via bool) *FieldError {
	needHost := func() *FieldError {
		if strings.TrimSpace(c.Host) == "" {
			return fe("host", "Enter the host")
		}
		if !hostName.MatchString(strings.TrimSpace(c.Host)) {
			return fe("host", "Enter a host name or IP address, without a scheme or path")
		}
		return nil
	}
	needPort := func() *FieldError {
		if c.Port <= 0 {
			return fe("port", "Enter the port")
		}
		return nil
	}
	needURL := func(schemes ...string) *FieldError {
		u, err := url.Parse(strings.TrimSpace(c.URL))
		if err != nil || u.Host == "" {
			return fe("url", "Enter the full address, e.g. "+schemes[0]+"://example.com")
		}
		for _, s := range schemes {
			if u.Scheme == s {
				return nil
			}
		}
		return fe("url", "The address must start with "+strings.Join(schemes, ":// or ")+"://")
	}
	if OnServer(kind) && !via {
		return &FieldError{"locations", "Pick the server it runs on"}
	}
	switch kind {
	case HTTP, Elasticsearch:
		if e := needURL("https", "http"); e != nil {
			return e
		}
		for _, s := range c.Statuses {
			if _, _, ok := statusRange(s); !ok {
				return fe("statuses", fmt.Sprintf("%q isn't a status code or range like 200-299", s))
			}
		}
		if c.KeywordMode == "regex" && c.Keyword != "" {
			if _, err := regexp.Compile(c.Keyword); err != nil {
				return fe("keyword", "Not a valid regular expression: "+err.Error())
			}
		}
		if c.JSONPath != "" {
			if _, err := parsePath(c.JSONPath); err != nil {
				return fe("json_path", err.Error())
			}
		}
	case WebSocket:
		return needURL("wss", "ws")
	case SocketIO:
		return needURL("https", "http")
	case TCP, TLS, SMTP, RabbitMQ, Kafka, NATS, MQTT, Memcached:
		if e := needHost(); e != nil {
			return e
		}
		if kind == TCP || kind == TLS {
			return needPort()
		}
	case UDP:
		if via {
			return &FieldError{"locations", "UDP can only be checked from Morcheh itself"}
		}
		if e := needHost(); e != nil {
			return e
		}
		if e := needPort(); e != nil {
			return e
		}
		if c.Send == "" {
			return fe("send", "Enter what to send: a UDP service only answers a request")
		}
	case Ping:
		return needHost()
	case DNS:
		if strings.TrimSpace(c.Name) == "" {
			return fe("name", "Enter the name to look up")
		}
		if via && strings.TrimSpace(c.Resolver) == "" {
			return fe("resolver", "From a server, enter the DNS server to ask (e.g. 1.1.1.1)")
		}
	case Database:
		if c.Engine == "" {
			return fe("engine", "Pick the database")
		}
		return needHost()
	case Docker:
		if strings.TrimSpace(c.Container) == "" {
			return fe("container", "Enter the container's name")
		}
		if !safeArg.MatchString(c.Container) {
			return fe("container", "A container name is letters, digits, dots, dashes and underscores")
		}
	case Systemd:
		if strings.TrimSpace(c.Unit) == "" {
			return fe("unit", "Enter the unit's name")
		}
		if !safeArg.MatchString(c.Unit) {
			return fe("unit", "A unit name is letters, digits, dots, dashes, @ and underscores")
		}
	case Command:
		if strings.TrimSpace(c.Script) == "" {
			return fe("script", "Enter the command")
		}
	case Push:
	default:
		return &FieldError{"kind", "Unknown kind of monitor"}
	}
	return nil
}

var safeArg = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:\-]*$`)

// Check runs one check.
func Check(ctx context.Context, kind string, c MonitorConfig, s MonitorSecrets, env Env) CheckResult {
	if env.Timeout <= 0 {
		env.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, env.Timeout)
	defer cancel()
	var r CheckResult
	switch kind {
	case HTTP:
		r = checkHTTP(ctx, c, s, env)
	case TCP:
		r = checkTCP(ctx, c, env)
	case UDP:
		r = checkUDP(ctx, c, env)
	case Ping:
		r = checkPing(ctx, c, env)
	case DNS:
		r = checkDNS(ctx, c, env)
	case TLS:
		r = checkTLS(ctx, c, env)
	case WebSocket:
		r = checkWebSocket(ctx, c, s, env)
	case SocketIO:
		r = checkSocketIO(ctx, c, s, env)
	case SMTP:
		r = checkSMTP(ctx, c, s, env)
	case Database:
		r = checkDatabase(ctx, c, s, env)
	case RabbitMQ:
		r = checkAMQP(ctx, c, s, env)
	case Kafka:
		r = checkKafka(ctx, c, env)
	case NATS:
		r = checkNATS(ctx, c, s, env)
	case MQTT:
		r = checkMQTT(ctx, c, s, env)
	case Memcached:
		r = checkMemcached(ctx, c, env)
	case Elasticsearch:
		r = checkElastic(ctx, c, s, env)
	case Docker:
		r = checkDocker(ctx, c, env)
	case Systemd:
		r = checkSystemd(ctx, c, env)
	case Command:
		r = checkCommand(ctx, c, env)
	default:
		return down("Unknown kind of monitor %q", kind)
	}
	if r.Status == Down && ctx.Err() != nil && !strings.Contains(r.Message, "Timed out") {
		r.Message = fmt.Sprintf("Timed out after %s", env.Timeout)
	}
	if r.Status == Up && c.DegradedMs > 0 && r.LatencyMs != nil && *r.LatencyMs > c.DegradedMs {
		r.Status = Degraded
		r.Message = fmt.Sprintf("Slow: %s (limit %s)", Ms(*r.LatencyMs), Ms(c.DegradedMs))
	}
	return r
}

// Ms writes milliseconds the way people read them.
func Ms(ms int) string {
	if ms < 1000 {
		return strconv.Itoa(ms) + " ms"
	}
	return strconv.FormatFloat(float64(ms)/1000, 'f', 1, 64) + " s"
}

// errText turns a network error into something a person can act on.
func errText(err error) string {
	var blocked *dbmon.BlockedError
	if errors.As(err, &blocked) {
		return blocked.Error()
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "The name " + dnsErr.Name + " doesn't resolve"
		}
		return "Couldn't resolve " + dnsErr.Name + ": " + dnsErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		msg := opErr.Err.Error()
		switch {
		case strings.Contains(msg, "connection refused"):
			return "Connection refused"
		case strings.Contains(msg, "no route to host"):
			return "No route to host"
		case strings.Contains(msg, "network is unreachable"):
			return "Network is unreachable"
		case strings.Contains(msg, "i/o timeout"):
			return "Timed out"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Timed out"
	}
	msg := err.Error()
	if strings.Contains(msg, "connect failed") {
		// An SSH tunnel's refusal: the server couldn't connect.
		return "The server couldn't connect: " + msg
	}
	return msg
}

func addr(c MonitorConfig, defPort int) string {
	p := c.Port
	if p == 0 {
		p = defPort
	}
	return net.JoinHostPort(strings.Trim(strings.TrimSpace(c.Host), "[]"), strconv.Itoa(p))
}

// unescape turns \n, \r and \t in Send into the characters.
func unescape(s string) string {
	return strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t").Replace(s)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
