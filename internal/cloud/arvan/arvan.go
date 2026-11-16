// Package arvan reads ArvanCloud's cloud servers through its IaaS API v3
// (https://ecc.<region>.arvanapis.ir/v3) with an API key. Each region has
// its own address; the list of regions comes from the API itself.
package arvan

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/morche/backend/internal/cloud"
)

// Config is how to reach ArvanCloud.
type Config struct {
	// Key is the API key, with or without its "Apikey " prefix.
	Key string
	// Dial opens connections.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// BaseURL overrides the address pattern (tests); %s = the region code.
	BaseURL string
	// Timeout for one request; 0 = 20 s.
	Timeout time.Duration
}

const (
	defaultBase = "https://ecc.%s.arvanapis.ir/v3"
	maxBody     = 16 << 20
	perPage     = 100
	maxPages    = 50
)

// Regions known when the API's own list can't be read.
var fallbackRegions = []string{"ir-central1", "ir-northwest1", "ir-southwest1", "eu-west1"}

type Client struct {
	key  string
	base string
	http *http.Client
}

// CleanKey takes the key as pasted: "Apikey xxxx" or just "xxxx".
func CleanKey(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) > 7 && strings.EqualFold(s[:7], "apikey ") {
		s = strings.TrimSpace(s[7:])
	}
	return s
}

// New builds a client. It never follows redirects and ignores proxy
// variables, so the key goes nowhere but ArvanCloud.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	base := cfg.BaseURL
	if base == "" {
		base = defaultBase
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         cfg.Dial,
		TLSClientConfig:     tlsConfig(),
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{
		key:  CleanKey(cfg.Key),
		base: base,
		http: &http.Client{
			Timeout:   timeout,
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// tlsConfig checks the certificate chain as usual. Some regional hosts (like
// ecc.ir-southwest1.arvanapis.ir) present ArvanCloud's certificate for
// *.arvanapis.ir without their own name on it, so for hosts under
// arvanapis.ir a certificate valid for arvanapis.ir is accepted too. Nothing
// else is relaxed.
func tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tls: no certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			leaf := cs.PeerCertificates[0]
			opts := x509.VerifyOptions{DNSName: cs.ServerName, Intermediates: inter}
			_, err := leaf.Verify(opts)
			if err == nil {
				return nil
			}
			var host x509.HostnameError
			if errors.As(err, &host) && strings.HasSuffix(cs.ServerName, ".arvanapis.ir") {
				opts.DNSName = "arvanapis.ir"
				if _, err2 := leaf.Verify(opts); err2 == nil {
					return nil
				}
			}
			return err
		},
	}
}

func (c *Client) url(region, path string) string {
	return fmt.Sprintf(c.base, region) + path
}

type errorBody struct {
	Message string `json:"message"`
	Errors  []struct {
		Field  string `json:"field"`
		Reason string `json:"reason"`
	} `json:"errors"`
}

func (c *Client) do(ctx context.Context, method, region, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(region, path), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Apikey "+c.key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return apiError(res.StatusCode, raw)
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &cloud.APIError{Status: res.StatusCode, Message: "ArvanCloud sent an answer Morche can't read"}
	}
	return nil
}

func apiError(status int, raw []byte) error {
	var eb errorBody
	_ = json.Unmarshal(raw, &eb)
	msg := strings.TrimSpace(eb.Message)
	for _, e := range eb.Errors {
		if e.Reason != "" {
			if e.Field != "" {
				msg += " (" + e.Field + ": " + e.Reason + ")"
			} else {
				msg += " (" + e.Reason + ")"
			}
		}
	}
	switch status {
	case http.StatusUnauthorized:
		return &cloud.AuthError{Message: "ArvanCloud refused the API key"}
	case http.StatusForbidden:
		if msg == "" {
			msg = "not allowed"
		}
		return &cloud.PermissionError{Message: "ArvanCloud: " + msg + ". Check the key's access policy in the ArvanCloud panel."}
	case http.StatusNotFound:
		if msg == "" {
			msg = "not found"
		}
		return &cloud.NotFoundError{Message: "ArvanCloud: " + msg}
	case http.StatusTooManyRequests:
		return &cloud.APIError{Status: status, Message: "ArvanCloud: too many requests, try again in a minute"}
	}
	if msg == "" {
		msg = "HTTP " + strconv.Itoa(status)
	}
	return &cloud.APIError{Status: status, Message: "ArvanCloud: " + msg}
}

// Regions and zones

type zone struct {
	Name   string `json:"name"`
	City   string `json:"city"`
	Region string `json:"region"`
	Code   string `json:"code"`
	State  string `json:"state"`
}

type zoneCache struct {
	mu    sync.Mutex
	zones []zone
	at    time.Time
}

// The zone list is the same for every key; read it at most once an hour.
var zones zoneCache

func (c *Client) zones(ctx context.Context) ([]zone, error) {
	zones.mu.Lock()
	if zones.zones != nil && time.Since(zones.at) < time.Hour {
		z := zones.zones
		zones.mu.Unlock()
		return z, nil
	}
	zones.mu.Unlock()
	var out struct {
		Data []zone `json:"data"`
	}
	var err error
	for _, r := range fallbackRegions {
		if err = c.do(ctx, http.MethodGet, r, "/availability-zones", nil, &out); err == nil {
			break
		}
		var auth *cloud.AuthError
		if errors.As(err, &auth) || ctx.Err() != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	zones.mu.Lock()
	zones.zones, zones.at = out.Data, time.Now()
	zones.mu.Unlock()
	return out.Data, nil
}

type regionInfo struct {
	code, name, city string
	zones            map[string]zone
}

// regionsOf groups the zones by region. Regions the API didn't list but
// that are known are added, so a server there still shows.
func regionsOf(zs []zone) []regionInfo {
	by := map[string]*regionInfo{}
	var order []string
	add := func(code string) *regionInfo {
		if r, ok := by[code]; ok {
			return r
		}
		r := &regionInfo{code: code, zones: map[string]zone{}}
		by[code] = r
		order = append(order, code)
		return r
	}
	for _, z := range zs {
		if z.Region == "" {
			continue
		}
		r := add(z.Region)
		r.zones[z.Code] = z
		if r.city == "" {
			r.city = z.City
		}
	}
	for _, code := range fallbackRegions {
		add(code)
	}
	out := make([]regionInfo, 0, len(order))
	for _, code := range order {
		r := by[code]
		r.name = regionName(*r)
		out = append(out, *r)
	}
	return out
}

func regionName(r regionInfo) string {
	city := r.city
	if city == "" {
		city = map[string]string{
			"ir-central1": "Tehran", "ir-northwest1": "Tabriz", "ir-southwest1": "Ahvaz", "eu-west1": "Germany",
		}[r.code]
	}
	if city == "" {
		return r.code
	}
	return city
}

// Servers

type detail struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	AvailabilityZone string `json:"availabilityZone"`
	CreateDate       string `json:"createDate"`
	BackupEnabled    bool   `json:"backupEnabled"`
	Flavor           struct {
		ID                string  `json:"id"`
		Name              string  `json:"name"`
		CPUCores          float64 `json:"cpuCores"`
		RAMMegaBytes      float64 `json:"ramMegaBytes"`
		RootDiskGigaBytes float64 `json:"rootDiskGigaBytes"`
	} `json:"flavor"`
	Image struct {
		Name    string `json:"name"`
		OS      string `json:"os"`
		Version string `json:"version"`
	} `json:"image"`
	IPAddresses []struct {
		IPAddress   string `json:"ipAddress"`
		IsPublic    bool   `json:"isPublic"`
		MACAddress  string `json:"macAddress"`
		NetworkName string `json:"networkName"`
		Version     any    `json:"version"`
	} `json:"ipAddresses"`
	SSHKeyName string `json:"sshKeyName"`
	State      string `json:"state"`
	TaskState  string `json:"taskState"`
}

// State maps ArvanCloud's (OpenStack's) state and task to ours.
func State(state, task string) string {
	if task != "" && !strings.EqualFold(task, "null") {
		switch strings.ToUpper(state) {
		case "DELETING", "SOFT_DELETED":
			return cloud.StateDeleting
		}
		return cloud.StateBuilding
	}
	switch strings.ToUpper(state) {
	case "ACTIVE":
		return cloud.StateRunning
	case "SHUTOFF", "STOPPED", "PAUSED", "SUSPENDED":
		return cloud.StateStopped
	case "SHELVED", "SHELVED_OFFLOADED":
		return cloud.StateArchived
	case "BUILD", "REBUILD", "RESIZE", "VERIFY_RESIZE", "MIGRATING", "REBOOT", "HARD_REBOOT":
		return cloud.StateBuilding
	case "DELETING", "SOFT_DELETED", "DELETED":
		return cloud.StateDeleting
	case "ERROR":
		return cloud.StateError
	}
	return cloud.StateUnknown
}

func (d detail) server(r regionInfo) cloud.Server {
	s := cloud.Server{
		ID: d.ID, Name: d.Name, Region: r.code, RegionName: r.name, Zone: d.AvailabilityZone,
		ZoneName: d.AvailabilityZone, State: State(d.State, d.TaskState), RawState: d.State,
		Task: d.TaskState, CPU: int(d.Flavor.CPUCores), MemoryMB: int(d.Flavor.RAMMegaBytes),
		DiskGB: int(d.Flavor.RootDiskGigaBytes), Plan: d.Flavor.Name, Image: d.Image.Name,
		OS: d.Image.OS, OSVersion: d.Image.Version, SSHKey: d.SSHKeyName, Backups: d.BackupEnabled,
		Addresses: []cloud.Address{},
	}
	if s.Plan == "" {
		s.Plan = d.Flavor.ID
	}
	if z, ok := r.zones[d.AvailabilityZone]; ok && z.Name != "" {
		s.ZoneName = z.Name
	}
	if t, err := time.Parse(time.RFC3339, d.CreateDate); err == nil {
		s.CreatedAt = &t
	}
	for _, a := range d.IPAddresses {
		v := 4
		if fmt.Sprint(a.Version) == "6" || strings.Contains(a.IPAddress, ":") {
			v = 6
		}
		s.Addresses = append(s.Addresses, cloud.Address{
			IP: a.IPAddress, Version: v, Public: a.IsPublic, Network: a.NetworkName, MAC: a.MACAddress,
		})
	}
	return s
}

func (c *Client) regionServers(ctx context.Context, r regionInfo) ([]cloud.Server, error) {
	var out []cloud.Server
	for page := 1; page <= maxPages; page++ {
		var res struct {
			Data []detail `json:"data"`
			Meta struct {
				Pagination struct {
					LastPage int `json:"lastPage"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		path := "/servers?page=" + strconv.Itoa(page) + "&perPage=" + strconv.Itoa(perPage)
		if err := c.do(ctx, http.MethodGet, r.code, path, nil, &res); err != nil {
			return nil, err
		}
		for _, d := range res.Data {
			out = append(out, d.server(r))
		}
		last := res.Meta.Pagination.LastPage
		if len(res.Data) < perPage || (last > 0 && page >= last) {
			break
		}
	}
	return out, nil
}

// Servers reads every region at once.
func (c *Client) Servers(ctx context.Context) (cloud.List, error) {
	start := time.Now()
	zs, err := c.zones(ctx)
	if err != nil {
		return cloud.List{}, err
	}
	latency := time.Since(start)
	regions := regionsOf(zs)
	type result struct {
		servers []cloud.Server
		err     error
	}
	results := make([]result, len(regions))
	var wg sync.WaitGroup
	for i, r := range regions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := c.regionServers(ctx, r)
			results[i] = result{s, err}
		}()
	}
	wg.Wait()
	list := cloud.List{Servers: []cloud.Server{}, Problems: []cloud.RegionProblem{}, Latency: latency}
	var firstErr error
	failed := 0
	for i, r := range regions {
		list.Regions = append(list.Regions, cloud.Region{Code: r.code, Name: r.name, City: r.city, State: regionState(r)})
		if err := results[i].err; err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			var auth *cloud.AuthError
			if errors.As(err, &auth) {
				return list, err
			}
			status, msg := cloud.Classify(err)
			list.Problems = append(list.Problems, cloud.RegionProblem{Region: r.code, Status: status, Message: msg})
			continue
		}
		list.Servers = append(list.Servers, results[i].servers...)
	}
	if failed == len(regions) {
		return list, firstErr
	}
	sort.SliceStable(list.Servers, func(a, b int) bool {
		return strings.ToLower(list.Servers[a].Name) < strings.ToLower(list.Servers[b].Name)
	})
	return list, nil
}

func regionState(r regionInfo) string {
	state := ""
	for _, z := range r.zones {
		if state == "" || z.State != "UP" {
			state = z.State
		}
	}
	return strings.ToLower(state)
}

func (c *Client) region(ctx context.Context, code string) (regionInfo, error) {
	zs, err := c.zones(ctx)
	if err != nil {
		return regionInfo{}, err
	}
	for _, r := range regionsOf(zs) {
		if r.code == code {
			return r, nil
		}
	}
	return regionInfo{}, &cloud.NotFoundError{Message: "ArvanCloud has no region " + code}
}

// Server reads one server.
func (c *Client) Server(ctx context.Context, region, id string) (cloud.Server, error) {
	r, err := c.region(ctx, region)
	if err != nil {
		return cloud.Server{}, err
	}
	var res struct {
		Data detail `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, r.code, "/servers/"+url.PathEscape(id), nil, &res); err != nil {
		return cloud.Server{}, err
	}
	if res.Data.ID == "" {
		return cloud.Server{}, &cloud.NotFoundError{Message: "ArvanCloud: server not found"}
	}
	return res.Data.server(r), nil
}

// Power turns a server on or off, or restarts it.
func (c *Client) Power(ctx context.Context, region, zone, id, action string) error {
	path := map[string]string{
		cloud.PowerOn: "power-on", cloud.PowerOff: "power-off", cloud.PowerReboot: "reboot",
	}[action]
	if path == "" {
		return &cloud.APIError{Status: http.StatusBadRequest, Message: "unknown power action " + action}
	}
	if _, err := c.region(ctx, region); err != nil {
		return err
	}
	body := map[string]string{"availabilityZone": zone}
	return c.do(ctx, http.MethodPost, region, "/servers/"+url.PathEscape(id)+"/"+path, body, nil)
}

// Rename changes the server's name at ArvanCloud.
func (c *Client) Rename(ctx context.Context, region, zone, id, name string) error {
	if _, err := c.region(ctx, region); err != nil {
		return err
	}
	body := map[string]string{"availabilityZone": zone, "name": name}
	return c.do(ctx, http.MethodPost, region, "/servers/"+url.PathEscape(id)+"/rename", body, nil)
}
