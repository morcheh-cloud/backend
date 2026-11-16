package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/cloud"
)

// What else an account has at the provider (firewalls, its own networks,
// extra disks, backup schedules). Only read, never changed.

type cloudResCached struct {
	res     cloud.Resources
	err     error
	at      time.Time
	updated time.Time
}

// These change rarely and take many requests (every region × kind).
const cloudResourcesFor = time.Minute

// The API's own names: Huma names schemas by type, and Network/Volume are taken.
type (
	CloudFirewall        cloud.Firewall
	CloudNetwork         cloud.Network
	CloudVolume          cloud.Volume
	CloudBackupSchedule  cloud.BackupSchedule
	CloudResourceProblem cloud.ResourceProblem
)

func convert[T, U any](in []T, f func(T) U) []U {
	out := make([]U, 0, len(in))
	for _, v := range in {
		out = append(out, f(v))
	}
	return out
}

type CloudResourcesOutput struct {
	Body struct {
		Supported bool                   `json:"supported" doc:"False when the provider has no such lists in Morche yet"`
		Firewalls []CloudFirewall        `json:"firewalls"`
		Networks  []CloudNetwork         `json:"networks" doc:"The account's own private networks; the provider's shared public ones are left out"`
		Volumes   []CloudVolume          `json:"volumes"`
		Backups   []CloudBackupSchedule  `json:"backups"`
		Problems  []CloudResourceProblem `json:"problems"`
		ReadAt    time.Time              `json:"read_at"`
	}
}

func (h *cloudHandler) resources(ctx context.Context, in *struct {
	CloudAccountIDPath
	Fresh bool `query:"fresh" doc:"Read again from the provider instead of the minute-old copy"`
}) (*CloudResourcesOutput, error) {
	a, err := h.account(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	out := &CloudResourcesOutput{}
	b := &out.Body
	b.Firewalls, b.Networks, b.Volumes = []CloudFirewall{}, []CloudNetwork{}, []CloudVolume{}
	b.Backups, b.Problems = []CloudBackupSchedule{}, []CloudResourceProblem{}

	h.mu.Lock()
	c, ok := h.res[a.ID]
	h.mu.Unlock()
	if !ok || in.Fresh || !c.updated.Equal(a.UpdatedAt) || time.Since(c.at) >= cloudResourcesFor {
		p, err := h.savedProvider(a)
		if err != nil {
			return nil, err
		}
		reader, can := p.(cloud.ResourceReader)
		if !can {
			b.ReadAt = time.Now()
			return out, nil
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		res, resErr := reader.Resources(cctx)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c = cloudResCached{res: res, err: resErr, at: time.Now(), updated: a.UpdatedAt}
		h.mu.Lock()
		h.res[a.ID] = c
		h.mu.Unlock()
	}
	if c.err != nil {
		return nil, cloudError(c.err)
	}
	b.Supported = true
	b.Firewalls = convert(c.res.Firewalls, func(v cloud.Firewall) CloudFirewall { return CloudFirewall(v) })
	b.Networks = convert(c.res.Networks, func(v cloud.Network) CloudNetwork { return CloudNetwork(v) })
	b.Volumes = convert(c.res.Volumes, func(v cloud.Volume) CloudVolume { return CloudVolume(v) })
	b.Backups = convert(c.res.Backups, func(v cloud.BackupSchedule) CloudBackupSchedule { return CloudBackupSchedule(v) })
	b.Problems = convert(c.res.Problems, func(v cloud.ResourceProblem) CloudResourceProblem { return CloudResourceProblem(v) })
	b.ReadAt = c.at
	return out, nil
}

func registerCloudResources(api huma.API, h *cloudHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "get-cloud-account-resources", Method: http.MethodGet, Path: "/cloud-accounts/{id}/resources",
		Summary:     "List an account's firewalls, networks, disks and backup schedules",
		Description: "Read only. Kept for a minute unless fresh is set.",
		Tags:        []string{"Cloud"},
	}, h.resources)
}
