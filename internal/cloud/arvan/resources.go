package arvan

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/morcheh/backend/internal/cloud"
)

// Resources: what else an account has besides servers (firewalls, its own
// networks, extra disks, backup schedules). Every request here is a GET.

type firewallBody struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	RulesCount       int    `json:"rulesCount"`
	ReadOnly         bool   `json:"readOnly"`
	Default          bool   `json:"default"`
	AvailabilityZone string `json:"availabilityZone"`
}

type networkBody struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Subnets []struct {
		CIDR string `json:"cidr"`
	} `json:"subnets"`
}

type volumeBody struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	AvailabilityZone string  `json:"availabilityZone"`
	SizeGigaBytes    float64 `json:"sizeGigaBytes"`
	Type             string  `json:"type"`
	Status           string  `json:"status"`
	ServerID         string  `json:"serverId"`
	ServerName       string  `json:"serverName"`
	CreateDate       string  `json:"createDate"`
}

type scheduleBody struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	AvailabilityZone string `json:"availabilityZone"`
	ServerID         string `json:"serverId"`
	ServerName       string `json:"serverName"`
	NextBackupDate   string `json:"nextBackupDate"`
	SlotsUsed        int    `json:"slotsUsed"`
	MaxSlots         int    `json:"maxSlots"`
}

// list reads every page of a region's list. An empty list comes back as {}.
func list[T any](ctx context.Context, c *Client, region, path string) ([]T, error) {
	var out []T
	for page := 1; page <= maxPages; page++ {
		var res struct {
			Data []T `json:"data"`
			Meta struct {
				Pagination struct {
					LastPage int `json:"lastPage"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		p := path + sep + "page=" + strconv.Itoa(page) + "&perPage=" + strconv.Itoa(perPage)
		if err := c.do(ctx, http.MethodGet, region, p, nil, &res); err != nil {
			return nil, err
		}
		out = append(out, res.Data...)
		last := res.Meta.Pagination.LastPage
		if len(res.Data) < perPage || last == 0 || page >= last {
			break
		}
	}
	return out, nil
}

func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// ownRanges keeps the private ranges: the public networks are the provider's
// own, shared by every account.
func ownRanges(n networkBody) []string {
	var out []string
	for _, s := range n.Subnets {
		p, err := netip.ParsePrefix(s.CIDR)
		if err != nil || !p.Addr().IsPrivate() {
			continue
		}
		out = append(out, s.CIDR)
	}
	return out
}

// Resources reads every region × kind at once. A kind a region doesn't have
// (404) is skipped; a refused key stops everything.
func (c *Client) Resources(ctx context.Context) (cloud.Resources, error) {
	zs, err := c.zones(ctx)
	if err != nil {
		return cloud.Resources{}, err
	}
	regions := regionsOf(zs)
	out := cloud.Resources{
		Firewalls: []cloud.Firewall{}, Networks: []cloud.Network{}, Volumes: []cloud.Volume{},
		Backups: []cloud.BackupSchedule{}, Problems: []cloud.ResourceProblem{},
	}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		authErr error
		first   error
		tried   int
		failed  int
	)
	zoneName := func(r regionInfo, code string) string {
		if z, ok := r.zones[code]; ok && z.Name != "" {
			return z.Name
		}
		return code
	}
	fail := func(r regionInfo, kind string, err error) {
		mu.Lock()
		defer mu.Unlock()
		tried++
		if err == nil {
			return
		}
		var nf *cloud.NotFoundError
		if errors.As(err, &nf) {
			return
		}
		failed++
		if first == nil {
			first = err
		}
		var auth *cloud.AuthError
		if errors.As(err, &auth) {
			authErr = err
			return
		}
		status, msg := cloud.Classify(err)
		out.Problems = append(out.Problems, cloud.ResourceProblem{Region: r.code, Kind: kind, Status: status, Message: msg})
	}
	for _, r := range regions {
		wg.Add(4)
		go func() {
			defer wg.Done()
			items, err := list[firewallBody](ctx, c, r.code, "/firewalls")
			mu.Lock()
			for _, f := range items {
				out.Firewalls = append(out.Firewalls, cloud.Firewall{
					ID: f.ID, Name: f.Name, Region: r.code, Zone: f.AvailabilityZone,
					ZoneName: zoneName(r, f.AvailabilityZone), Rules: f.RulesCount, Builtin: f.ReadOnly, Default: f.Default,
				})
			}
			mu.Unlock()
			fail(r, "firewalls", err)
		}()
		go func() {
			defer wg.Done()
			items, err := list[networkBody](ctx, c, r.code, "/networks")
			mu.Lock()
			for _, n := range items {
				if ranges := ownRanges(n); len(ranges) > 0 {
					out.Networks = append(out.Networks, cloud.Network{
						ID: n.ID, Name: n.Name, Region: r.code, Status: strings.ToLower(n.Status), Subnets: ranges,
					})
				}
			}
			mu.Unlock()
			fail(r, "networks", err)
		}()
		go func() {
			defer wg.Done()
			items, err := list[volumeBody](ctx, c, r.code, "/volumes")
			mu.Lock()
			for _, v := range items {
				out.Volumes = append(out.Volumes, cloud.Volume{
					ID: v.ID, Name: v.Name, Region: r.code, Zone: v.AvailabilityZone,
					ZoneName: zoneName(r, v.AvailabilityZone), SizeGB: int(v.SizeGigaBytes), Type: v.Type,
					Status: strings.ToLower(v.Status), ServerID: v.ServerID, ServerName: v.ServerName,
					CreatedAt: parseTime(v.CreateDate),
				})
			}
			mu.Unlock()
			fail(r, "volumes", err)
		}()
		go func() {
			defer wg.Done()
			items, err := list[scheduleBody](ctx, c, r.code, "/backup-schedules")
			mu.Lock()
			for _, b := range items {
				out.Backups = append(out.Backups, cloud.BackupSchedule{
					ID: b.ID, Name: b.Name, Region: r.code, Zone: b.AvailabilityZone,
					ZoneName: zoneName(r, b.AvailabilityZone), ServerID: b.ServerID, ServerName: b.ServerName,
					NextAt: parseTime(b.NextBackupDate), Used: b.SlotsUsed, Max: b.MaxSlots,
				})
			}
			mu.Unlock()
			fail(r, "backups", err)
		}()
	}
	wg.Wait()
	if authErr != nil {
		return out, authErr
	}
	if tried > 0 && failed == tried {
		return out, first
	}
	byName := func(a, b string) bool { return strings.ToLower(a) < strings.ToLower(b) }
	sort.SliceStable(out.Firewalls, func(i, j int) bool {
		a, b := out.Firewalls[i], out.Firewalls[j]
		if a.Builtin != b.Builtin {
			return !a.Builtin
		}
		return byName(a.Name, b.Name)
	})
	sort.SliceStable(out.Networks, func(i, j int) bool { return byName(out.Networks[i].Name, out.Networks[j].Name) })
	sort.SliceStable(out.Volumes, func(i, j int) bool { return byName(out.Volumes[i].Name, out.Volumes[j].Name) })
	sort.SliceStable(out.Backups, func(i, j int) bool { return byName(out.Backups[i].Name, out.Backups[j].Name) })
	sort.SliceStable(out.Problems, func(i, j int) bool {
		return out.Problems[i].Region+out.Problems[i].Kind < out.Problems[j].Region+out.Problems[j].Kind
	})
	return out, nil
}
