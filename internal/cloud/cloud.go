// Package cloud is the provider-neutral side of cloud accounts: the servers a
// provider's API shows, in one shape, and the few things Morche may ask of
// them (power, rename). Each provider lives in its own package (arvan, …).
package cloud

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Server states, the same for every provider.
const (
	StateRunning  = "running"
	StateStopped  = "stopped"
	StateArchived = "archived" // shelved: off and not holding a host
	StateBuilding = "building"
	StateDeleting = "deleting"
	StateError    = "error"
	StateUnknown  = "unknown"
)

// Power actions.
const (
	PowerOn     = "on"
	PowerOff    = "off"
	PowerReboot = "reboot"
)

type Address struct {
	IP      string `json:"ip"`
	Version int    `json:"version" doc:"4 or 6"`
	Public  bool   `json:"public"`
	Network string `json:"network,omitempty"`
	MAC     string `json:"mac,omitempty"`
}

// Server is one machine as the provider describes it.
type Server struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Region     string     `json:"region" doc:"The provider's region code, part of the server's address in the API"`
	RegionName string     `json:"region_name"`
	Zone       string     `json:"zone"`
	ZoneName   string     `json:"zone_name"`
	State      string     `json:"state" enum:"running,stopped,archived,building,deleting,error,unknown"`
	RawState   string     `json:"raw_state" doc:"The provider's own word for the state"`
	Task       string     `json:"task,omitempty" doc:"What the provider is doing to it right now, if anything"`
	CPU        int        `json:"cpu"`
	MemoryMB   int        `json:"memory_mb"`
	DiskGB     int        `json:"disk_gb"`
	Plan       string     `json:"plan"`
	Image      string     `json:"image"`
	OS         string     `json:"os"`
	OSVersion  string     `json:"os_version"`
	Addresses  []Address  `json:"addresses"`
	SSHKey     string     `json:"ssh_key,omitempty"`
	Backups    bool       `json:"backups"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
}

// Region is where servers can live.
type Region struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	City  string `json:"city"`
	State string `json:"state"`
}

// RegionProblem is a region whose servers couldn't be read.
type RegionProblem struct {
	Region  string `json:"region"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// List is every server an account can see. A region that fails doesn't hide
// the others.
type List struct {
	Servers  []Server
	Problems []RegionProblem
	Regions  []Region
	Latency  time.Duration
}

// Firewall is a set of rules servers can be put behind.
type Firewall struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Region   string `json:"region"`
	Zone     string `json:"zone"`
	ZoneName string `json:"zone_name"`
	Rules    int    `json:"rules"`
	Builtin  bool   `json:"builtin" doc:"Made by the provider; can't be changed"`
	Default  bool   `json:"default" doc:"New servers get it unless told otherwise"`
}

// Network is a private network of the account's own.
type Network struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Region  string   `json:"region"`
	Status  string   `json:"status"`
	Subnets []string `json:"subnets" doc:"Address ranges (CIDR)"`
}

// Volume is an extra disk.
type Volume struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Region     string     `json:"region"`
	Zone       string     `json:"zone"`
	ZoneName   string     `json:"zone_name"`
	SizeGB     int        `json:"size_gb"`
	Type       string     `json:"type"`
	Status     string     `json:"status"`
	ServerID   string     `json:"server_id,omitempty"`
	ServerName string     `json:"server_name,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
}

// BackupSchedule takes a server's backups on a schedule.
type BackupSchedule struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Region     string     `json:"region"`
	Zone       string     `json:"zone"`
	ZoneName   string     `json:"zone_name"`
	ServerID   string     `json:"server_id,omitempty"`
	ServerName string     `json:"server_name,omitempty"`
	NextAt     *time.Time `json:"next_at,omitempty"`
	Used       int        `json:"used" doc:"Backups kept"`
	Max        int        `json:"max" doc:"Backups it keeps at most"`
}

// ResourceProblem is one kind of resource a region couldn't give.
type ResourceProblem struct {
	Region  string `json:"region"`
	Kind    string `json:"kind" enum:"firewalls,networks,volumes,backups"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Resources is what else an account has besides servers. Read only.
type Resources struct {
	Firewalls []Firewall
	Networks  []Network
	Volumes   []Volume
	Backups   []BackupSchedule
	Problems  []ResourceProblem
}

// ResourceReader is a provider that can list more than servers. Only reads.
type ResourceReader interface {
	Resources(ctx context.Context) (Resources, error)
}

// Provider is one account's client.
type Provider interface {
	// Servers reads every region.
	Servers(ctx context.Context) (List, error)
	Server(ctx context.Context, region, id string) (Server, error)
	Power(ctx context.Context, region, zone, id, action string) error
	Rename(ctx context.Context, region, zone, id, name string) error
}

// AuthError: the key was refused.
type AuthError struct{ Message string }

func (e *AuthError) Error() string { return e.Message }

// PermissionError: the key works but may not do this.
type PermissionError struct{ Message string }

func (e *PermissionError) Error() string { return e.Message }

// APIError is any other answer the provider gave.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }

// NotFoundError: the server isn't there (or the key can't see it).
type NotFoundError struct{ Message string }

func (e *NotFoundError) Error() string { return e.Message }

// Classify gives a status (online, auth_failed, tls_error, unreachable,
// error) and a short message.
func Classify(err error) (string, string) {
	if err == nil {
		return "online", ""
	}
	var auth *AuthError
	var perm *PermissionError
	var api *APIError
	var nf *NotFoundError
	switch {
	case errors.As(err, &auth):
		return "auth_failed", auth.Error()
	case errors.As(err, &perm):
		return "auth_failed", perm.Error()
	case errors.As(err, &nf):
		return "error", nf.Error()
	case errors.As(err, &api):
		return "error", api.Error()
	}
	var ue *url.Error
	msg := err.Error()
	if errors.As(err, &ue) {
		msg = ue.Err.Error()
	}
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "x509:") || strings.Contains(low, "tls:"):
		return "tls_error", msg
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, context.DeadlineExceeded):
		return "unreachable", msg
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return "unreachable", msg
	}
	return "error", msg
}
