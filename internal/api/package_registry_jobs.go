package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/proxy"
	"github.com/morche/backend/internal/registry"
	"github.com/morche/backend/internal/sshpool"
)

const registryDeployTimeout = 40 * time.Minute

// jobRegistry loads the registry a job works on.
func (h *registryHandler) jobRegistry(ctx context.Context, t *jobs.Task) (registryJobParams, sqlc.GetPackageRegistryRow, error) {
	var p registryJobParams
	if err := t.Decode(&p); err != nil {
		return p, sqlc.GetPackageRegistryRow{}, err
	}
	row, err := h.s.q.GetPackageRegistry(ctx, uuid.MustParse(p.RegistryID))
	if isNotFound(err) {
		return p, row, errors.New("The registry is gone")
	}
	return p, row, err
}

// runScript runs a deploy script as root, logging its lines and showing the
// "==> " ones as the job's phase.
func (h *registryHandler) runScript(ctx context.Context, t *jobs.Task, serverID uuid.UUID, script string, secrets ...string) error {
	return h.s.withShell(ctx, serverID.String(), func(_ *sshpool.Conn, sh *rootShell) error {
		var last []string
		lines := &lineWriter{fn: func(l string) {
			for _, s := range secrets {
				if s != "" {
					l = strings.ReplaceAll(l, s, "••••")
				}
			}
			if phase, ok := strings.CutPrefix(l, "==> "); ok {
				t.Update(func(p *jobs.Progress) { p.Phase = phase; p.Current = "" })
				t.Logf("%s", phase)
				return
			}
			last = append(last, l)
			if len(last) > 6 {
				last = last[1:]
			}
			t.Logf("%s", l)
			t.Update(func(p *jobs.Progress) { p.Current = l })
		}}
		res, err := sh.hiding(false, secrets...).execTo(ctx, script, registryDeployTimeout, lines)
		lines.flush()
		switch {
		case err != nil:
			return err
		case res.timedOut:
			return fmt.Errorf("It took longer than %d minutes, so Morche stopped waiting", int(registryDeployTimeout.Minutes()))
		case res.code != 0:
			msg := "the script failed"
			if len(last) > 0 {
				msg = last[len(last)-1]
			}
			return errors.New(msg)
		}
		return nil
	})
}

func (h *registryHandler) fail(r sqlc.PackageRegistry, err error) error {
	err = jobError(err)
	_ = h.s.q.SetPackageRegistryState(context.Background(), sqlc.SetPackageRegistryStateParams{ID: r.ID, State: "failed", Problem: err.Error()})
	return err
}

func (h *registryHandler) runDeploy(ctx context.Context, t *jobs.Task) (any, error) {
	p, row, err := h.jobRegistry(ctx, t)
	if err != nil {
		return nil, err
	}
	r := row.PackageRegistry
	_ = h.s.q.SetPackageRegistryState(ctx, sqlc.SetPackageRegistryStateParams{ID: r.ID, State: "deploying"})
	secret, err := h.adminSecret(r)
	if err != nil {
		return nil, h.fail(r, err)
	}
	var set registry.RegistrySettings
	_ = json.Unmarshal(r.Settings, &set)

	// 1. The compose project.
	switch r.Kind {
	case registry.Harbor:
		if err := h.installHarbor(ctx, t, r, row.ServerHost, set, secret); err != nil {
			return nil, h.fail(r, err)
		}
	case registry.Verdaccio:
		line, err := registry.HtpasswdLine(r.AdminUser, secret)
		if err != nil {
			return nil, h.fail(r, err)
		}
		// Users added later are kept on a second deploy.
		text := line + "\n"
		if old, err := h.root(ctx, r.ServerID, registry.ReadHtpasswdScript(r.Dir)); err == nil && strings.TrimSpace(old) != "" {
			text = registry.SetHtpasswd(old, r.AdminUser, line)
		}
		cfg := verdaccioConfig(r, row.ServerHost, set, r.Name)
		if err := h.runScript(ctx, t, r.ServerID, registry.VerdaccioInstallScript(cfg, r.Project, text), secret, registry.B64(text)); err != nil {
			return nil, h.fail(r, err)
		}
	}

	// 2. Wait for it, then set it up through its API.
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Waiting for it to start"; pr.Current = "" })
	t.Logf("Waiting for it to answer…")
	switch r.Kind {
	case registry.Harbor:
		err = registry.WaitReady(ctx, 10*time.Minute, func(ctx context.Context) error {
			return h.harbor(ctx, r, func(c registry.HarborClient) error {
				hh, err := c.Health(ctx)
				if err != nil {
					return err
				}
				if hh.Status != "healthy" {
					return errors.New("Harbor isn't healthy yet")
				}
				return nil
			})
		})
		if err != nil {
			return nil, h.fail(r, fmt.Errorf("Harbor didn't come up: %s", registryProblem(err).Error()))
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Setting it up" })
		err = h.harbor(ctx, r, func(c registry.HarborClient) error {
			if v, err := c.Version(ctx); err == nil {
				t.Logf("Harbor %s answers.", v)
			}
			return harborSettings(ctx, c, set, t.Logf)
		})
		if err != nil {
			return nil, h.fail(r, fmt.Errorf("Couldn't set Harbor up: %s", registryProblem(err).Error()))
		}
	case registry.Verdaccio:
		err = registry.WaitReady(ctx, 3*time.Minute, func(ctx context.Context) error {
			return h.verdaccio(ctx, r, func(c registry.VerdaccioClient) error {
				if err := c.Ping(ctx); err != nil {
					return err
				}
				_, err := c.Whoami(ctx)
				return err
			})
		})
		if err != nil {
			return nil, h.fail(r, fmt.Errorf("Verdaccio didn't come up: %s", registryProblem(err).Error()))
		}
		t.Logf("Verdaccio answers and takes the admin login.")
	}

	// 3. Publish it and sign Containers in.
	problem := ""
	if r.Domain != "" {
		if err := h.publish(ctx, t, &r, p.Email); err != nil {
			problem = err.Error()
			t.Logf("%s", problem)
		}
	}
	if r.Kind == registry.Harbor && r.DockerRegistryID == nil {
		if err := h.containersLogin(ctx, t, &r, row); err != nil {
			t.Logf("Couldn't add the Containers login: %s", registryProblem(err).Error())
		}
	}
	if err := h.s.q.SetPackageRegistryState(ctx, sqlc.SetPackageRegistryStateParams{ID: r.ID, State: "ready", Problem: problem}); err != nil {
		return nil, internalError(err)
	}
	if fresh, err := h.s.q.GetPackageRegistry(ctx, r.ID); err == nil {
		h.check(ctx, fresh.PackageRegistry)
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Ready"; pr.Current = "" })
	return map[string]string{"registry_id": r.ID.String()}, nil
}

// installHarbor writes harbor.yml, runs Harbor's prepare step and starts it.
func (h *registryHandler) installHarbor(ctx context.Context, t *jobs.Task, r sqlc.PackageRegistry, serverHost string, set registry.RegistrySettings, secret string) error {
	// external_url is what Harbor hands clients (the token realm), so it
	// is always the address they use. Harbor refuses a loopback
	// hostname, which only matters when the server is this machine.
	_, ext := registryAddress(r, serverHost)
	host := r.Domain
	if host == "" {
		host = serverHost
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			host = "harbor.internal"
		}
	}
	// A second deploy must keep the database password of the first, or
	// Harbor can't open its own database.
	db := registry.Password(20)
	if old, err := h.root(ctx, r.ServerID, "cat "+registry.Quote(r.Dir+"/harbor.yml")+" 2>/dev/null || true"); err == nil {
		if pw := registry.HarborDBPassword(old); pw != "" {
			db = pw
		}
	}
	cfg := registry.HarborConfig{Dir: r.Dir, Hostname: host, ExternalURL: ext, Port: int(r.Port), Open: r.Domain == "",
		AdminPassword: secret, DBPassword: db, Scanner: set.Scanner}
	return h.runScript(ctx, t, r.ServerID, registry.HarborInstallScript(cfg, r.Project), secret, db, registry.B64(registry.HarborYML(cfg)))
}

// siteConfig is the reverse proxy site that publishes a registry.
func siteConfig(r sqlc.PackageRegistry, tls *proxy.HostTLS) proxy.HostConfig {
	c := proxy.HostConfig{
		Domains: []string{r.Domain}, Type: "proxy", Upstream: fmt.Sprintf("http://127.0.0.1:%d", r.Port),
		PreserveHost: true, NoBuffering: true, TimeoutSeconds: 900, HideVersion: true,
		// Images and packages can be gigabytes.
		Advanced: "client_max_body_size 0;",
	}
	if tls != nil {
		c.TLS = *tls
	}
	return c
}

// publish puts the registry on its server's reverse proxy and, when asked,
// gets it a certificate and turns https on. An error leaves it on http.
func (h *registryHandler) publish(ctx context.Context, t *jobs.Task, r *sqlc.PackageRegistry, email string) error {
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Publishing it on the reverse proxy" })
	px, _, err := h.usableProxy(ctx, r.ServerID)
	if err != nil {
		return err
	}
	if px == nil {
		return errors.New("The server has no reverse proxy set up, so " + r.Domain + " doesn't reach it yet")
	}
	pid := px.ID.String()
	d, ok := proxy.Get(px.Kind)
	if !ok {
		return errors.New("Morche can't manage this server's proxy")
	}

	// The site, on plain http first.
	var hostID *uuid.UUID
	if r.ProxyHostID != nil {
		if _, err := h.s.q.GetProxyHost(ctx, sqlc.GetProxyHostParams{ID: *r.ProxyHostID, ProxyID: px.ID}); err == nil {
			hostID = r.ProxyHostID
		}
	}
	if hostID == nil {
		c, err := cleanHost(d, siteConfig(*r, nil))
		if err != nil {
			return fmt.Errorf("The proxy refused the site: %s", toProblem(err).Error())
		}
		raw, _ := json.Marshal(c)
		var made uuid.UUID
		_, err = h.proxies.write(ctx, pid, func(q *sqlc.Queries, proxyID uuid.UUID) (string, error) {
			x, err := q.CreateProxyHost(ctx, sqlc.CreateProxyHostParams{
				ProxyID: proxyID, Domains: c.Domains, Enabled: true, Config: raw, Note: "Package registry " + r.Name + " (made by Morche)", ByName: "Morche",
			})
			if err != nil {
				return "", internalError(err)
			}
			made = x.ID
			return "Added " + r.Domain + " for the package registry " + r.Name, nil
		})
		if err != nil {
			return fmt.Errorf("Couldn't add the site %s: %s", r.Domain, toProblem(err).Error())
		}
		hostID = &made
		t.Logf("Added the site %s on the reverse proxy.", r.Domain)
	}
	r.ProxyHostID = hostID
	if err := h.s.q.SetPackageRegistryLinks(ctx, sqlc.SetPackageRegistryLinksParams{ID: r.ID, ProxyHostID: hostID, DockerRegistryID: r.DockerRegistryID, Https: false}); err != nil {
		return internalError(err)
	}
	if !r.Https {
		return nil
	}
	return h.secure(ctx, t, r, px, d, email)
}

// secure gets a Let's Encrypt certificate for the registry's site and turns
// https on.
func (h *registryHandler) secure(ctx context.Context, t *jobs.Task, r *sqlc.PackageRegistry, px *sqlc.Proxy, d proxy.Driver, email string) error {
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Getting a certificate" })
	req, err := cleanCertRequest(proxy.CertRequest{Source: proxy.CertACME, CA: "letsencrypt", Domains: []string{r.Domain}, Email: email})
	if err != nil {
		return err
	}
	res, err := h.proxies.certify(ctx, t, px.ID.String(), px.ServerID.String(), req)
	if err != nil {
		return fmt.Errorf("HTTPS isn't on yet: %s. Check that %s points at this server and port 80 is open, then get HTTPS again", toProblem(err).Error(), r.Domain)
	}
	tls := &proxy.HostTLS{Enabled: true, Certificate: res.Certificate, Key: res.Key, ForceHTTPS: true, ForceCode: 308, HTTP2: true}
	c, err := cleanHost(d, siteConfig(*r, tls))
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(c)
	_, err = h.proxies.write(ctx, px.ID.String(), func(q *sqlc.Queries, proxyID uuid.UUID) (string, error) {
		old, err := q.GetProxyHost(ctx, sqlc.GetProxyHostParams{ID: *r.ProxyHostID, ProxyID: proxyID})
		if err != nil {
			return "", internalError(err)
		}
		if _, err := q.UpdateProxyHost(ctx, sqlc.UpdateProxyHostParams{
			Domains: c.Domains, Enabled: true, Config: raw, Note: old.Note, ByName: "Morche", ID: old.ID, ProxyID: proxyID,
		}); err != nil {
			return "", internalError(err)
		}
		return "Turned on HTTPS for " + r.Domain, nil
	})
	if err != nil {
		return fmt.Errorf("Couldn't turn HTTPS on: %s", toProblem(err).Error())
	}
	r.Https = true
	if err := h.s.q.SetPackageRegistryLinks(ctx, sqlc.SetPackageRegistryLinksParams{ID: r.ID, ProxyHostID: r.ProxyHostID, DockerRegistryID: r.DockerRegistryID, Https: true}); err != nil {
		return internalError(err)
	}
	t.Logf("HTTPS is on for %s.", r.Domain)
	return nil
}

// containersLogin makes a Harbor robot account for Morche and adds it as a
// registry login in Containers, so pulls and update checks can use it.
func (h *registryHandler) containersLogin(ctx context.Context, t *jobs.Task, r *sqlc.PackageRegistry, row sqlc.GetPackageRegistryRow) error {
	address, _ := registryAddress(*r, row.ServerHost)
	short := strings.Split(r.ID.String(), "-")[0]
	var name, secret string
	err := h.harbor(ctx, *r, func(c registry.HarborClient) error {
		if rs, err := c.Robots(ctx); err == nil {
			for _, x := range rs {
				if x.Name == "robot$morche-"+short {
					_ = c.DeleteRobot(ctx, x.ID)
				}
			}
		}
		var err error
		_, name, secret, err = c.CreateRobot(ctx, "morche-"+short, "Morche's login for Containers (pulls, update checks)", true, 0)
		return err
	})
	if err != nil {
		return err
	}
	dr, err := h.s.q.CreateDockerRegistry(ctx, sqlc.CreateDockerRegistryParams{
		WorkspaceID: row.WorkspaceID, Name: r.Name, Address: address, Username: name,
		PasswordEnc: h.s.box.Seal(secret), Servers: "all", ServerIds: []uuid.UUID{},
	})
	if isUniqueViolation(err) {
		return errors.New("Containers already has a login for " + address)
	}
	if err != nil {
		return internalError(err)
	}
	r.DockerRegistryID = &dr.ID
	if err := h.s.q.SetPackageRegistryLinks(ctx, sqlc.SetPackageRegistryLinksParams{ID: r.ID, ProxyHostID: r.ProxyHostID, DockerRegistryID: &dr.ID, Https: r.Https}); err != nil {
		return internalError(err)
	}
	t.Logf("Added the login %s to Containers › Registries.", address)
	return nil
}

func (h *registryHandler) runHTTPS(ctx context.Context, t *jobs.Task) (any, error) {
	p, row, err := h.jobRegistry(ctx, t)
	if err != nil {
		return nil, err
	}
	r := row.PackageRegistry
	r.Https = true
	if err := h.publish(ctx, t, &r, p.Email); err != nil {
		_ = h.s.q.SetPackageRegistryState(ctx, sqlc.SetPackageRegistryStateParams{ID: r.ID, State: "ready", Problem: err.Error()})
		return nil, err
	}
	if r.Kind == registry.Harbor || r.Kind == registry.Verdaccio {
		// The public address changed from http to https: tell it.
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Telling it its new address" })
		var set registry.RegistrySettings
		_ = json.Unmarshal(r.Settings, &set)
		if r.Kind == registry.Verdaccio {
			if _, err := h.root(ctx, r.ServerID, registry.VerdaccioConfigScript(verdaccioConfig(r, row.ServerHost, set, r.Name), r.Project)); err != nil {
				t.Logf("Couldn't restart Verdaccio with its https address: %s", shellFailure(err, "").Error())
			}
		} else if !strings.Contains(registryHarborURL(ctx, h, r), "https://") {
			// Harbor hands clients its address: write it again with https.
			secret, err := h.adminSecret(r)
			if err == nil {
				err = h.installHarbor(ctx, t, r, row.ServerHost, set, secret)
			}
			if err != nil {
				t.Logf("Couldn't give Harbor its https address: %s. Deploy it again.", jobError(err).Error())
			}
		}
	}
	_ = h.s.q.SetPackageRegistryState(ctx, sqlc.SetPackageRegistryStateParams{ID: r.ID, State: "ready", Problem: ""})
	return map[string]string{"registry_id": r.ID.String()}, nil
}

// registryHarborURL reads external_url from harbor.yml.
func registryHarborURL(ctx context.Context, h *registryHandler, r sqlc.PackageRegistry) string {
	out, _ := h.root(ctx, r.ServerID, "grep '^external_url:' "+registry.Quote(r.Dir+"/harbor.yml")+" 2>/dev/null || true")
	return out
}

func (h *registryHandler) runRemove(ctx context.Context, t *jobs.Task) (any, error) {
	p, row, err := h.jobRegistry(ctx, t)
	if err != nil {
		return nil, err
	}
	r := row.PackageRegistry
	_ = h.s.q.SetPackageRegistryState(ctx, sqlc.SetPackageRegistryStateParams{ID: r.ID, State: "removing"})

	t.Update(func(pr *jobs.Progress) { pr.Phase = "Taking it down" })
	if err := h.runScript(ctx, t, r.ServerID, registry.RemoveScript(r.Dir, r.Project, p.KeepData)); err != nil {
		_ = h.s.q.SetPackageRegistryState(ctx, sqlc.SetPackageRegistryStateParams{ID: r.ID, State: "ready", Problem: "Couldn't remove it: " + err.Error()})
		return nil, jobError(err)
	}
	if p.KeepData {
		t.Logf("Left %s on the server.", r.Dir)
	} else {
		t.Logf("Removed %s.", r.Dir)
	}
	if r.ProxyHostID != nil {
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Removing its site" })
		if pid, err := h.s.q.GetProxyHostProxy(ctx, *r.ProxyHostID); err == nil {
			_, err := h.proxies.write(ctx, pid.String(), func(q *sqlc.Queries, proxyID uuid.UUID) (string, error) {
				if err := q.DeleteProxyHost(ctx, sqlc.DeleteProxyHostParams{ID: *r.ProxyHostID, ProxyID: proxyID}); err != nil {
					return "", internalError(err)
				}
				return "Removed " + r.Domain + " with the package registry " + r.Name, nil
			})
			if err != nil {
				t.Logf("Couldn't remove the site %s: %s", r.Domain, toProblem(err).Error())
			} else {
				t.Logf("Removed the site %s.", r.Domain)
			}
		}
	}
	if r.DockerRegistryID != nil {
		if _, err := h.s.q.DeleteDockerRegistry(ctx, sqlc.DeleteDockerRegistryParams{ID: *r.DockerRegistryID, WorkspaceID: row.WorkspaceID}); err == nil {
			t.Logf("Removed its login from Containers › Registries.")
		}
	}
	if err := h.s.q.DeletePackageRegistry(ctx, r.ID); err != nil {
		return nil, internalError(err)
	}
	return map[string]string{"registry_id": r.ID.String()}, nil
}
