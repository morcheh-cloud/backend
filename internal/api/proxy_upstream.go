package api

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/proxy"
	"github.com/morcheh/backend/internal/sshpool"
)

type ProxyUpstreamTest struct {
	OK     bool   `json:"ok" doc:"The upstream answered with a status below 500"`
	Status int    `json:"status" doc:"Its HTTP status; 0 when it didn't answer"`
	Millis int    `json:"millis" doc:"How long the answer took, seen from the proxy's server"`
	Error  string `json:"error,omitempty" doc:"Why it didn't answer"`
}

// registerUpstreamTest: ask the upstream from the proxy's own server, so
// the answer is what nginx would get.
func (h *proxyHandler) registerUpstreamTest(api huma.API, base string, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID: "test-proxy-upstream", Method: http.MethodPost, Path: base + "/hosts/test-upstream",
		Summary:     "Check that the proxy's server can reach an upstream",
		Description: "Sends one GET from the proxy's server (curl, 10 s) with the site's https settings. Nothing is saved.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body struct {
			Upstream    string            `json:"upstream" maxLength:"500"`
			UpstreamTLS proxy.UpstreamTLS `json:"upstream_tls" required:"false"`
		}
	}) (*struct{ Body ProxyUpstreamTest }, error) {
		r, _, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		u, err := url.Parse(strings.TrimSpace(in.Body.Upstream))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return nil, fieldError("body.upstream", "Use a full address starting with http:// or https://.", in.Body.Upstream)
		}
		script := upstreamCurl(u, in.Body.UpstreamTLS)
		out := &struct{ Body ProxyUpstreamTest }{}
		server := r.Proxy.ServerID.String()
		err = h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
			sh, err := h.shell(ctx, r.Proxy, c)
			if err != nil {
				return err
			}
			res, err := sh.exec(ctx, script, 20*time.Second, 8<<10)
			if err != nil {
				return err
			}
			text := string(res.output)
			if sh.box != nil && strings.Contains(text, upstreamMark+" nocurl") {
				// The image has no curl: ask from the server, inside the
				// container's network, with the name as the container
				// resolves it.
				if again, ok := sh.curlInBox(ctx, u, in.Body.UpstreamTLS, text); ok {
					text = again
				}
			}
			out.Body = parseUpstreamCurl(text)
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return out, nil
	})
}

const upstreamMark = "MORCHEH_UPSTREAM"

const resolveMark = "MORCHEH_RESOLVE"

// curlInBox runs the upstream check from the server inside the container's
// network namespace (nsenter), for an image without curl. first is what the
// container printed: the upstream's address as it resolves it.
func (s *proxyShell) curlInBox(ctx context.Context, u *url.URL, t proxy.UpstreamTLS, first string) (string, bool) {
	ci, err := s.info(ctx)
	if err != nil || !ci.Running || ci.Pid <= 0 {
		return "", false
	}
	args := curlArgs(u, t)
	for _, line := range strings.Split(first, "\n") {
		if ip, ok := strings.CutPrefix(strings.TrimSpace(line), resolveMark+" "); ok && net.ParseIP(ip) != nil {
			port := u.Port()
			if port == "" {
				port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
			}
			if strings.Contains(ip, ":") {
				ip = "[" + ip + "]"
			}
			args = append(args[:1], append([]string{"--resolve", u.Hostname() + ":" + port + ":" + ip}, args[1:]...)...)
			break
		}
	}
	script := proxy.HostPath() + "command -v curl >/dev/null 2>&1 && command -v nsenter >/dev/null 2>&1 || { echo '" +
		upstreamMark + " nocurl'; exit 0; }\nnsenter -t " + strconv.Itoa(ci.Pid) + " -n " + quoteAll(args) + " 2>&1\n"
	res, err := s.hostExec(ctx, script, 20*time.Second, 8<<10)
	if err != nil {
		return "", false
	}
	return string(res.output), true
}

func upstreamCurl(u *url.URL, t proxy.UpstreamTLS) string {
	resolve := ""
	if net.ParseIP(u.Hostname()) == nil {
		resolve = "getent hosts " + quoteAll([]string{u.Hostname()}) +
			" 2>/dev/null | awk '{print \"" + resolveMark + " \" $1; exit}'; "
	}
	return "command -v curl >/dev/null 2>&1 || { echo '" + upstreamMark + " nocurl'; " + resolve + "exit 0; }\n" +
		quoteAll(curlArgs(u, t)) + " 2>&1\n"
}

func curlArgs(u *url.URL, t proxy.UpstreamTLS) []string {
	args := []string{"curl", "-sS", "-o", "/dev/null", "--max-time", "10",
		"-w", `\n` + upstreamMark + ` %{http_code} %{time_total}\n`}
	target := u.String()
	if u.Scheme == "https" {
		if !t.Verify {
			args = append(args, "-k")
		} else if t.CA != "" {
			args = append(args, "--cacert", t.CA)
		}
		if t.Certificate != "" && t.Key != "" {
			args = append(args, "--cert", t.Certificate, "--key", t.Key)
		}
		if name := strings.TrimSpace(t.Name); name != "" && name != u.Hostname() {
			port := u.Port()
			if port == "" {
				port = "443"
			}
			args = append(args, "--connect-to", name+":"+port+":"+u.Hostname()+":"+port)
			v := *u
			v.Host = net.JoinHostPort(name, port)
			target = v.String()
		}
	}
	return append(args, "--", target)
}

func parseUpstreamCurl(out string) ProxyUpstreamTest {
	var res ProxyUpstreamTest
	var errs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rest, ok := strings.CutPrefix(line, upstreamMark+" ")
		if !ok {
			errs = append(errs, strings.TrimPrefix(line, "curl: "))
			continue
		}
		if rest == "nocurl" {
			res.Error = "curl isn't installed on the proxy's server, so it can't be checked from there."
			return res
		}
		f := strings.Fields(rest)
		if len(f) == 2 {
			res.Status, _ = strconv.Atoi(f[0])
			secs, _ := strconv.ParseFloat(f[1], 64)
			res.Millis = int(secs * 1000)
		}
	}
	res.OK = res.Status > 0 && res.Status < 500
	if res.Status == 0 {
		res.Error = strings.Join(errs, " ")
		if res.Error == "" {
			res.Error = "No answer."
		}
	}
	return res
}
