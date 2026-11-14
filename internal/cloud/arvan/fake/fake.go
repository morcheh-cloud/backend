// Package fake is an in-memory ArvanCloud IaaS v3 API for development: a few
// servers in each region that power on/off, reboot and rename like the real
// ones (with a short task in between). Paths are /<region>/v3/….
package fake

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Key is the only API key the fake accepts.
const Key = "fake-arvan-0000-4000-8000-000000000000"

type zone struct {
	Name, City, Country, Region, Code string
}

var zones = []zone{
	{"Bamdad", "Tehran", "Iran", "ir-central1", "ir-thr-ba1"},
	{"Foroogh", "Tehran", "Iran", "ir-central1", "ir-thr-fr1"},
	{"Simin", "Tehran", "Iran", "ir-central1", "ir-thr-si1"},
	{"Goethe", "Germany", "Europe", "eu-west1", "eu-west1-a"},
	{"Qeysar", "Ahwaz", "Iran", "ir-southwest1", "ir-southwest1-a"},
	{"Shahriar", "Tabriz", "Iran", "ir-northwest1", "ir-tbz-sh1"},
}

type server struct {
	ID, Name, Zone, State, Task, Flavor, Image, OS, Version, SSHKey string
	CPU, RAM, Disk                                                  int
	Public, Private                                                 string
	Backup                                                          bool
	Created                                                         time.Time
	busyUntil                                                       time.Time
	after                                                           string
}

type Fake struct {
	mu      sync.Mutex
	servers []*server
}

func New() *Fake {
	t := time.Date(2025, 3, 2, 9, 30, 0, 0, time.UTC)
	return &Fake{servers: []*server{
		{ID: "6f1c2a10-0001-4c1e-9a10-000000000001", Name: "web-1", Zone: "ir-thr-ba1", State: "ACTIVE", Flavor: "g2-4-4-0", Image: "ubuntu-24.04", OS: "ubuntu", Version: "24.04", SSHKey: "ops", CPU: 4, RAM: 4096, Disk: 50, Public: "185.206.92.11", Private: "10.10.0.11", Backup: true, Created: t},
		{ID: "6f1c2a10-0002-4c1e-9a10-000000000002", Name: "web-2", Zone: "ir-thr-fr1", State: "ACTIVE", Flavor: "g2-4-4-0", Image: "ubuntu-24.04", OS: "ubuntu", Version: "24.04", SSHKey: "ops", CPU: 4, RAM: 4096, Disk: 50, Public: "185.206.92.12", Private: "10.10.0.12", Created: t.Add(48 * time.Hour)},
		{ID: "6f1c2a10-0003-4c1e-9a10-000000000003", Name: "db-main", Zone: "ir-thr-si1", State: "ACTIVE", Flavor: "m2-8-16-0", Image: "debian-12", OS: "debian", Version: "12", SSHKey: "ops", CPU: 8, RAM: 16384, Disk: 200, Public: "185.206.93.40", Private: "10.10.0.40", Backup: true, Created: t.Add(-30 * 24 * time.Hour)},
		{ID: "6f1c2a10-0004-4c1e-9a10-000000000004", Name: "staging", Zone: "ir-thr-ba1", State: "SHUTOFF", Flavor: "g2-2-2-0", Image: "ubuntu-22.04", OS: "ubuntu", Version: "22.04", CPU: 2, RAM: 2048, Disk: 25, Public: "185.206.92.77", Private: "10.10.0.77", Created: t.Add(90 * 24 * time.Hour)},
		{ID: "6f1c2a10-0005-4c1e-9a10-000000000005", Name: "eu-edge", Zone: "eu-west1-a", State: "ACTIVE", Flavor: "g2-2-4-0", Image: "rocky-9", OS: "rocky", Version: "9", SSHKey: "eu", CPU: 2, RAM: 4096, Disk: 40, Public: "37.32.10.5", Private: "10.20.0.5", Created: t.Add(120 * 24 * time.Hour)},
		{ID: "6f1c2a10-0006-4c1e-9a10-000000000006", Name: "old-archive", Zone: "ir-tbz-sh1", State: "SHELVED_OFFLOADED", Flavor: "g2-1-1-0", Image: "centos-7", OS: "centos", Version: "7", CPU: 1, RAM: 1024, Disk: 20, Public: "", Private: "10.30.0.9", Created: t.Add(-400 * 24 * time.Hour)},
		{ID: "6f1c2a10-0007-4c1e-9a10-000000000007", Name: "worker-ahvaz", Zone: "ir-southwest1-a", State: "ACTIVE", Flavor: "g2-2-2-0", Image: "ubuntu-24.04", OS: "ubuntu", Version: "24.04", SSHKey: "ops", CPU: 2, RAM: 2048, Disk: 25, Public: "94.101.180.20", Private: "10.40.0.20", Created: t.Add(200 * 24 * time.Hour)},
	}}
}

func regionOf(code string) string {
	for _, z := range zones {
		if z.Code == code {
			return z.Region
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"message": msg, "errors": []any{}})
}

// settle ends a finished task.
func (s *server) settle(now time.Time) {
	if s.Task != "" && now.After(s.busyUntil) {
		s.Task = ""
		s.State = s.after
	}
}

func (s *server) detail() map[string]any {
	ips := []map[string]any{}
	if s.Public != "" {
		ips = append(ips, map[string]any{"ipAddress": s.Public, "isPublic": true, "version": "4", "networkName": "public210", "macAddress": "fa:16:3e:00:00:" + s.ID[len(s.ID)-2:]})
	}
	ips = append(ips, map[string]any{"ipAddress": s.Private, "isPublic": false, "version": "4", "networkName": "private-net", "macAddress": "fa:16:3e:00:01:" + s.ID[len(s.ID)-2:]})
	d := map[string]any{
		"id": s.ID, "name": s.Name, "availabilityZone": s.Zone, "createDate": s.Created.Format(time.RFC3339),
		"backupEnabled": s.Backup, "failoverEnabled": false, "state": s.State,
		"flavor":      map[string]any{"id": s.Flavor, "name": s.Flavor, "cpuCores": s.CPU, "ramMegaBytes": s.RAM, "rootDiskGigaBytes": s.Disk},
		"image":       map[string]any{"id": s.Image, "name": s.Image, "os": s.OS, "version": s.Version},
		"ipAddresses": ips, "sshKeyName": s.SSHKey,
	}
	if s.Task != "" {
		d["taskState"] = s.Task
	}
	return d
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Apikey "+Key {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 3, "message": "invalid credentials"})
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[1] != "v3" {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	region, rest := parts[0], parts[2:]
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	switch {
	case r.Method == http.MethodGet && len(rest) == 1 && rest[0] == "availability-zones":
		data := []map[string]any{}
		for _, z := range zones {
			data = append(data, map[string]any{"name": z.Name, "zone": z.Name, "city": z.City, "country": z.Country, "region": z.Region, "code": z.Code, "isVolumeBacked": true, "state": "UP"})
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": data})
	case r.Method == http.MethodGet && len(rest) == 1 && rest[0] == "servers":
		data := []map[string]any{}
		for _, s := range f.servers {
			if regionOf(s.Zone) == region {
				s.settle(now)
				data = append(data, s.detail())
			}
		}
		if len(data) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": data, "meta": map[string]any{"pagination": map[string]any{"current": 1, "lastPage": 1}}})
	case r.Method == http.MethodGet && len(rest) == 1 && (rest[0] == "firewalls" || rest[0] == "networks" || rest[0] == "volumes" || rest[0] == "backup-schedules"):
		data := f.resources(region, rest[0])
		if len(data) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": data, "meta": map[string]any{"pagination": map[string]any{"current": 1, "lastPage": 1}}})
	case len(rest) >= 2 && rest[0] == "servers":
		var s *server
		for _, c := range f.servers {
			if c.ID == rest[1] && regionOf(c.Zone) == region {
				s = c
			}
		}
		if s == nil {
			fail(w, http.StatusNotFound, "Server does not exist")
			return
		}
		s.settle(now)
		if r.Method == http.MethodGet && len(rest) == 2 {
			writeJSON(w, http.StatusOK, map[string]any{"data": s.detail()})
			return
		}
		if r.Method != http.MethodPost || len(rest) != 3 {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		var body struct {
			AvailabilityZone string `json:"availabilityZone"`
			Name             string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.AvailabilityZone != s.Zone {
			fail(w, http.StatusUnprocessableEntity, "availabilityZone is invalid")
			return
		}
		if s.Task != "" {
			fail(w, http.StatusConflict, "Server is busy with another task")
			return
		}
		busy := func(task, after string) {
			s.Task, s.after, s.busyUntil = task, after, now.Add(6*time.Second)
		}
		switch rest[2] {
		case "power-on":
			if s.State == "ACTIVE" {
				fail(w, http.StatusConflict, "Server is already on")
				return
			}
			busy("POWERING_ON", "ACTIVE")
		case "power-off":
			if s.State != "ACTIVE" {
				fail(w, http.StatusConflict, "Server is not running")
				return
			}
			busy("POWERING_OFF", "SHUTOFF")
		case "reboot":
			if s.State != "ACTIVE" {
				fail(w, http.StatusConflict, "Server is not running")
				return
			}
			busy("REBOOTING", "ACTIVE")
		case "rename":
			if strings.TrimSpace(body.Name) == "" {
				fail(w, http.StatusUnprocessableEntity, "name is required")
				return
			}
			s.Name = strings.TrimSpace(body.Name)
		default:
			fail(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"message": "accepted"})
	default:
		fail(w, http.StatusNotFound, "not found")
	}
}

// resources is a region's firewalls, networks, volumes or backup schedules.
func (f *Fake) resources(region, kind string) []map[string]any {
	data := []map[string]any{}
	firstZone := ""
	for _, z := range zones {
		if z.Region == region {
			firstZone = z.Code
			break
		}
	}
	if firstZone == "" {
		return data
	}
	switch kind {
	case "firewalls":
		data = append(data,
			map[string]any{"id": "fw-cdn-" + region, "name": "CDN", "rulesCount": 14, "readOnly": true, "availabilityZone": firstZone},
			map[string]any{"id": "fw-default-" + region, "name": "Default", "rulesCount": 4, "readOnly": true, "default": true, "availabilityZone": firstZone},
		)
		if region == "ir-central1" {
			data = append(data, map[string]any{"id": "fw-web", "name": "web", "rulesCount": 6, "availabilityZone": "ir-thr-ba1"},
				map[string]any{"id": "fw-db", "name": "database only", "rulesCount": 2, "availabilityZone": "ir-thr-si1"})
		}
	case "networks":
		data = append(data, map[string]any{"id": "net-public-" + region, "name": "public210", "status": "ACTIVE",
			"subnets": []map[string]any{{"cidr": "185.206.92.0/23"}}})
		if region == "ir-central1" {
			data = append(data, map[string]any{"id": "net-private", "name": "private-net", "status": "ACTIVE",
				"subnets": []map[string]any{{"cidr": "10.10.0.0/16"}}})
		}
	case "volumes":
		for _, s := range f.servers {
			if regionOf(s.Zone) == region && s.Backup {
				data = append(data, map[string]any{"id": "vol-" + s.ID[len(s.ID)-4:], "name": s.Name + "-data", "availabilityZone": s.Zone,
					"sizeGigaBytes": 100, "type": "ssd", "status": "in-use", "serverId": s.ID, "serverName": s.Name,
					"createDate": s.Created.Format(time.RFC3339)})
			}
		}
		if region == "ir-central1" {
			data = append(data, map[string]any{"id": "vol-spare", "name": "spare", "availabilityZone": "ir-thr-fr1",
				"sizeGigaBytes": 50, "type": "hdd", "status": "available", "createDate": time.Date(2025, 6, 1, 8, 0, 0, 0, time.UTC).Format(time.RFC3339)})
		}
	case "backup-schedules":
		next := time.Now().Truncate(24 * time.Hour).Add(26 * time.Hour)
		for _, s := range f.servers {
			if regionOf(s.Zone) == region && s.Backup {
				data = append(data, map[string]any{"id": "bk-" + s.ID[len(s.ID)-4:], "name": "nightly " + s.Name, "availabilityZone": s.Zone,
					"serverId": s.ID, "serverName": s.Name, "nextBackupDate": next.Format(time.RFC3339), "slotsUsed": 5, "maxSlots": 7})
			}
		}
	}
	return data
}
