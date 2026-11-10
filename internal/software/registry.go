package software

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Registry tells the digest an image tag has in its registry now, so a
// Docker app can say an update is out. Answers are cached for an hour.
type Registry struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]cached
}

type cached struct {
	digest string
	err    error
	at     time.Time
}

const registryTTL = time.Hour

// NewRegistry makes a registry client.
func NewRegistry() *Registry {
	return &Registry{client: &http.Client{Timeout: 20 * time.Second}, cache: map[string]cached{}}
}

var errNoDigest = errors.New("the registry didn't say")

// Latest returns the digest of ref ("grafana/grafana:latest",
// "ghcr.io/x/y:1") in its registry.
func (g *Registry) Latest(ctx context.Context, ref string) (string, error) {
	if strings.Contains(ref, "@") || strings.Contains(ref, "${") {
		return "", errors.New("not a tag")
	}
	g.mu.Lock()
	if c, ok := g.cache[ref]; ok && time.Since(c.at) < registryTTL {
		g.mu.Unlock()
		return c.digest, c.err
	}
	g.mu.Unlock()
	d, err := g.fetch(ctx, ref)
	if ctx.Err() == nil {
		g.mu.Lock()
		g.cache[ref] = cached{d, err, time.Now()}
		g.mu.Unlock()
	}
	return d, err
}

// Split parses a reference into registry host, repository and tag.
func Split(ref string) (host, repo, tag string) {
	name, tag := splitTag(ref)
	if tag == "" {
		tag = "latest"
	}
	first, rest, ok := strings.Cut(name, "/")
	if ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		host, repo = first, rest
	} else {
		host, repo = "registry-1.docker.io", name
	}
	if host == "docker.io" || host == "index.docker.io" {
		host = "registry-1.docker.io"
	}
	if host == "registry-1.docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	return host, repo, tag
}

const manifestTypes = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.docker.distribution.manifest.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json"

func (g *Registry) fetch(ctx context.Context, ref string) (string, error) {
	host, repo, tag := Split(ref)
	u := fmt.Sprintf("https://%s/v2/%s/manifests/%s", host, repo, url.PathEscape(tag))
	res, err := g.head(ctx, u, "")
	if err != nil {
		return "", err
	}
	if res.StatusCode == http.StatusUnauthorized {
		token, err := g.token(ctx, res.Header.Get("WWW-Authenticate"), repo)
		if err != nil {
			return "", err
		}
		res, err = g.head(ctx, u, token)
		if err != nil {
			return "", err
		}
	}
	switch {
	case res.StatusCode == http.StatusNotFound:
		return "", errors.New("the registry has no such tag")
	case res.StatusCode != http.StatusOK:
		return "", fmt.Errorf("the registry answered %d", res.StatusCode)
	}
	d := res.Header.Get("Docker-Content-Digest")
	if d == "" {
		return "", errNoDigest
	}
	return d, nil
}

func (g *Registry) head(ctx context.Context, u, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", manifestTypes)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	res.Body.Close()
	return res, nil
}

var challengeRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// token gets an anonymous pull token as the registry's challenge says.
func (g *Registry) token(ctx context.Context, challenge, repo string) (string, error) {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", errors.New("the registry wants a login")
	}
	p := map[string]string{}
	for _, m := range challengeRe.FindAllStringSubmatch(params, -1) {
		p[m[1]] = m[2]
	}
	realm := p["realm"]
	if !strings.HasPrefix(realm, "https://") {
		return "", errors.New("the registry wants a login")
	}
	q := url.Values{}
	if p["service"] != "" {
		q.Set("service", p["service"])
	}
	q.Set("scope", cmpOr(p["scope"], "repository:"+repo+":pull"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	res, err := g.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the registry refused a token (%d)", res.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", err
	}
	return cmpOr(body.Token, body.AccessToken), nil
}

// CheckImages fills LatestDigest and Update for each image, and says
// whether any has an update. Errors leave the image as it was.
func (g *Registry) CheckImages(ctx context.Context, images []Image) bool {
	any := false
	for i := range images {
		img := &images[i]
		if len(img.Digests) == 0 || strings.HasPrefix(img.Image, "morcheh-rollback/") {
			continue
		}
		d, err := g.Latest(ctx, img.Image)
		if err != nil {
			continue
		}
		img.LatestDigest = d
		img.Update = !containsString(img.Digests, d)
		any = any || img.Update
	}
	return any
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
