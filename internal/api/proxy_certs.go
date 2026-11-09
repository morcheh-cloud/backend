package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/proxy"
	"github.com/morcheh/backend/internal/sshpool"
)

// Certificates on a proxy's server: from an ACME CA with certbot (Let's
// Encrypt, ZeroSSL, Google, SSL.com or any directory URL; certbot renews
// them), self-signed, or uploaded. Each is a background job; the result names
// the files, which a site's HTTPS settings then point at.

const proxyCertKind = "proxy-certificate"

type ProxyCertificateBody struct {
	Body proxy.CertRequest
	ID   string `path:"id" format:"uuid"`
}

type proxyCertParams struct {
	ProxyID  string            `json:"proxy_id"`
	ServerID string            `json:"server_id"`
	Request  proxy.CertRequest `json:"request"`
	// Secrets holds the EAB HMAC key and an uploaded private key, sealed.
	Secrets []byte `json:"secrets,omitempty"`
}

type proxyCertSecrets struct {
	EABHMAC string `json:"eab_hmac,omitempty"`
	Key     string `json:"key,omitempty"`
}

// ProxyCertResult is what a finished job leaves in its result.
type ProxyCertResult struct {
	Name        string   `json:"name"`
	Certificate string   `json:"certificate"`
	Key         string   `json:"key"`
	Domains     []string `json:"domains"`
	Source      string   `json:"source"`
}

type ProxyCAList struct {
	Body struct {
		Authorities []proxy.CA `json:"authorities"`
	}
}

func cleanCertRequest(r proxy.CertRequest) (proxy.CertRequest, error) {
	r.Normalize()
	probs := r.Validate()
	if len(probs) == 0 {
		return r, nil
	}
	details := make([]error, len(probs))
	for i, p := range probs {
		details[i] = &huma.ErrorDetail{Location: "body." + p.Field, Message: p.Message, Value: p.Value}
	}
	return r, huma.Error422UnprocessableEntity(probs[0].Message, details...)
}

func certJobTitle(r proxy.CertRequest, server string) string {
	names := r.Domains[0]
	if len(r.Domains) > 1 {
		names += fmt.Sprintf(" and %d more", len(r.Domains)-1)
	}
	switch r.Source {
	case proxy.CertSelfSigned:
		return "Make a self-signed certificate for " + names + " on " + server
	case proxy.CertUpload:
		return "Save the certificate for " + names + " on " + server
	}
	label := r.DirectoryURL()
	if ca, ok := proxy.CAByID(r.CA); ok {
		label = ca.Label
	}
	return "Get a certificate for " + names + " from " + label + " on " + server
}

func (h *proxyHandler) submitCertificate(ctx context.Context, rawID string, req proxy.CertRequest) (*JobOutput, error) {
	r, d, err := h.getProxy(ctx, rawID)
	if err != nil {
		return nil, err
	}
	if !d.Capabilities().Certificates {
		return nil, huma.Error422UnprocessableEntity(d.Label() + " can't get certificates from the panel yet")
	}
	req, err = cleanCertRequest(req)
	if err != nil {
		return nil, err
	}
	server := r.Proxy.ServerID.String()
	err = h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
		_, err := h.root(ctx, server, c)
		return err
	})
	if err != nil {
		return nil, toProblem(err)
	}
	p := proxyCertParams{ProxyID: rawID, ServerID: server, Request: req}
	if req.EABHMAC != "" || req.Key != "" {
		raw, _ := json.Marshal(proxyCertSecrets{EABHMAC: req.EABHMAC, Key: req.Key})
		p.Secrets = h.s.box.Seal(string(raw))
		p.Request.EABHMAC, p.Request.Key = "", ""
	}
	return submit(ctx, h.s.jobs, jobs.Spec{
		Kind: proxyCertKind, Title: certJobTitle(req, r.ServerName),
		Params: p, Refs: placeRefs(rawID, server),
	})
}

func (h *proxyHandler) runCertificate(ctx context.Context, t *jobs.Task) (any, error) {
	var p proxyCertParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	req := p.Request
	if len(p.Secrets) > 0 {
		plain, err := h.s.box.Open(p.Secrets)
		if err != nil {
			return nil, errors.New("Couldn't read the saved secrets; start it again")
		}
		var s proxyCertSecrets
		_ = json.Unmarshal([]byte(plain), &s)
		req.EABHMAC, req.Key = s.EABHMAC, s.Key
	}
	r, d, err := h.getProxy(ctx, p.ProxyID)
	if err != nil {
		return nil, jobError(err)
	}
	defer h.lock(r.Proxy.ID)()
	defer h.refresh(r.Proxy.ID)

	err = h.s.withConn(ctx, p.ServerID, func(c *sshpool.Conn) error {
		sh, err := h.root(ctx, p.ServerID, c)
		if err != nil {
			return err
		}
		facts, err := sh.run(ctx, hostScript)
		if err != nil {
			return err
		}
		f := parseHost(facts)
		install := func(pkgs ...string) string {
			s, err := packageScript(f.pm, "install", pkgs...)
			if err != nil {
				return "echo 'No package manager Morcheh knows here.'; false"
			}
			return s
		}

		if req.Source == proxy.CertACME {
			// Sites written before the certificate check existed get it now,
			// so a name already served answers the CA too.
			t.Update(func(pr *jobs.Progress) { pr.Phase = "Preparing" })
			if in, err := inspectWith(ctx, sh, d); err == nil && in.SetUp {
				if hosts, err := h.s.q.ListProxyHosts(ctx, r.Proxy.ID); err == nil && len(hosts) > 0 {
					if err := applyFiles(ctx, sh, d, render(d, hosts, envOf(in))); err != nil {
						t.Logf("Couldn't rewrite the sites first (%s); going on.", proxyProblemText(err))
					}
				}
			}
		}

		t.Update(func(pr *jobs.Progress) { pr.Phase = "Getting the certificate" })
		var last []string
		lines := &lineWriter{fn: func(l string) {
			l = scrub(l, req.EABHMAC)
			if l == "" {
				return
			}
			last = append(last, l)
			if len(last) > 8 {
				last = last[1:]
			}
			t.Logf("%s", l)
			installing := strings.HasPrefix(l, "Installing ")
			t.Update(func(pr *jobs.Progress) {
				pr.Current = l
				if installing {
					pr.Locked = true
				} else if strings.HasPrefix(l, "certbot ") || strings.HasPrefix(l, "Asking ") || strings.HasPrefix(l, "Made ") {
					pr.Locked = false
				}
			})
		}}
		res, err := sh.execTo(ctx, d.CertificateScript(req, proxy.Setup{Init: f.init, PM: f.pm, Install: install}), packageTimeout, lines)
		lines.flush()
		switch {
		case err != nil:
			return err
		case res.timedOut:
			return fmt.Errorf("It took longer than %d minutes, so Morcheh stopped waiting", int(packageTimeout.Minutes()))
		case res.code == proxy.ExitNotInstalled:
			return fmt.Errorf("%s isn't installed on this server. Set it up first", d.Label())
		case res.code == proxy.ExitTestFailed:
			return fmt.Errorf("%s refused the temporary block for the check: %s", d.Label(), strings.Join(last, " "))
		case res.code != 0:
			why := ""
			if len(last) > 0 {
				why = ": " + certFailure(last)
			}
			return fmt.Errorf("No certificate%s", why)
		}
		return nil
	})
	if err != nil {
		return nil, jobError(err)
	}
	cert, key := req.Paths()
	return ProxyCertResult{Name: req.Name, Certificate: cert, Key: key, Domains: req.Domains, Source: certSource(req)}, nil
}

func certSource(r proxy.CertRequest) string {
	if r.Source == proxy.CertACME {
		return "certbot"
	}
	return "morcheh"
}

// certFailure picks certbot's most telling line: its "Detail:" or an error,
// else the last one.
func certFailure(lines []string) string {
	for _, l := range lines {
		if d, ok := strings.CutPrefix(strings.TrimSpace(l), "Detail:"); ok {
			return strings.TrimSpace(d)
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.Contains(l, "Error") || strings.Contains(l, "error:") || strings.Contains(l, "Problem") {
			return l
		}
	}
	return lines[len(lines)-1]
}

func registerProxyCertificates(api huma.API, h *proxyHandler, base string, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID: "list-proxy-certificate-authorities", Method: http.MethodGet, Path: base + "/certificates/authorities",
		Summary:     "Certificate authorities the panel can ask over ACME",
		Description: "`custom` (any ACME directory URL) is also accepted.",
		Tags:        tags,
	}, func(ctx context.Context, in *ProxyIDPath) (*ProxyCAList, error) {
		out := &ProxyCAList{}
		out.Body.Authorities = proxy.CAs
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-proxy-certificate", Method: http.MethodPost, Path: base + "/certificates",
		Summary: "Get, make or save a certificate on the proxy's server",
		Description: "`acme`: certbot asks the CA over HTTP-01 (the names must point at this server, port 80 open); certbot is installed when missing and renews the certificate itself. " +
			"`self-signed`: made with openssl. `upload`: the PEM pair is checked and written to " + proxy.SelfDir + "/<name>. " +
			"Secrets (EAB HMAC key, private key) are kept sealed with the job, never in plain text. " +
			"Runs as a background job (kind `" + proxyCertKind + "`); its result has the certificate and key paths.",
		Tags: tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *ProxyCertificateBody) (*JobOutput, error) {
		return h.submitCertificate(ctx, in.ID, in.Body)
	})
	h.s.jobs.Handle(proxyCertKind, h.runCertificate)
}
