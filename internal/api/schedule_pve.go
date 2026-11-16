package api

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/proxmox"
)

// The pve-backup and pve-snapshot cron actions: back up (vzdump, to a
// Proxmox storage or a Proxmox Backup Server) or snapshot machines on a
// Proxmox cluster, one machine at a time. Snapshots carry a prefix so older
// ones made by the same cron job can be dropped, keeping the newest few.

// SchedulePVE is the machines and what to do with them.
type SchedulePVE struct {
	ClusterID string `json:"cluster_id" format:"uuid"`
	All       bool   `json:"all,omitempty" doc:"Every machine on the cluster (not templates), read at each run; vmids are left out"`
	VMIDs     []int  `json:"vmids,omitempty" maxItems:"500" doc:"The machines; ignored with all"`
	Skip      []int  `json:"skip,omitempty" maxItems:"500" doc:"With all: machines to leave out"`
	KeepGoing bool   `json:"keep_going,omitempty" doc:"Carry on with the other machines after one fails"`

	// pve-backup
	Storage   string `json:"storage,omitempty" maxLength:"100" doc:"pve-backup: the Proxmox storage (or Backup Server) to back up to"`
	Mode      string `json:"mode,omitempty" enum:"snapshot,suspend,stop," doc:"pve-backup: snapshot = live, no downtime (default); suspend = paused briefly; stop = shut down for the backup, then started again"`
	Compress  string `json:"compress,omitempty" enum:"zstd,lzo,gzip,0," doc:"pve-backup: default zstd"`
	Notes     string `json:"notes,omitempty" maxLength:"200" doc:"pve-backup: note on each backup; {{guestname}}, {{vmid}}, {{node}} and {{cluster}} are filled in by Proxmox"`
	Protected bool   `json:"protected,omitempty" doc:"pve-backup: the storage's own pruning leaves these backups alone"`

	// pve-snapshot
	Prefix  string `json:"prefix,omitempty" maxLength:"20" pattern:"^([A-Za-z][A-Za-z0-9_-]*)?$" doc:"pve-snapshot: snapshots are named <prefix>_<date>_<time>; default auto"`
	Keep    int    `json:"keep,omitempty" minimum:"0" maximum:"100" doc:"pve-snapshot: keep this many snapshots with the prefix per machine and delete older ones; 0 = never delete"`
	VMState bool   `json:"vmstate,omitempty" doc:"pve-snapshot: also save a running VM's memory (slower, larger)"`
}

func pveAction(action string) bool { return action == "pve-backup" || action == "pve-snapshot" }

func (t SchedulePVE) prefix() string { return cmpOr(t.Prefix, "auto") }

func (k *scheduleChecker) pve(action string, b ScheduleBody) error {
	t := b.Task.PVE
	loc := "body.task.pve"
	if t == nil {
		return fieldError(loc+".cluster_id", "Choose a cluster.", nil)
	}
	id, err := uuid.Parse(t.ClusterID)
	if err != nil {
		return fieldError(loc+".cluster_id", "Choose a cluster.", t.ClusterID)
	}
	c, err := k.h.q.GetPVECluster(k.ctx, id)
	if isNotFound(err) || (err == nil && c.WorkspaceID != k.ws) {
		return fieldError(loc+".cluster_id", "This cluster isn't in this workspace.", t.ClusterID)
	}
	if err != nil {
		return internalError(err)
	}
	level := principalOf(k.ctx).Access.WorkspaceLevel(k.ws)
	if level == auth.None {
		return fieldError(loc+".cluster_id", "Not found.", nil)
	}
	if level < auth.Engineer {
		return forbidden(auth.Engineer)
	}
	out := *t
	out.ClusterID = c.ID.String()
	clean := func(ids []int) []int {
		var r []int
		for _, v := range ids {
			if v >= 100 && !slices.Contains(r, v) {
				r = append(r, v)
			}
		}
		sort.Ints(r)
		return r
	}
	out.VMIDs, out.Skip = clean(t.VMIDs), clean(t.Skip)
	if out.All {
		out.VMIDs = nil
	} else {
		out.Skip = nil
		if len(out.VMIDs) == 0 {
			return fieldError(loc+".vmids", "Choose at least one machine, or All machines.", nil)
		}
	}
	switch action {
	case "pve-backup":
		out.Storage = strings.TrimSpace(out.Storage)
		if out.Storage == "" {
			return fieldError(loc+".storage", "Choose where the backups go.", nil)
		}
		out.Prefix, out.Keep, out.VMState = "", 0, false
	case "pve-snapshot":
		out.Prefix = out.prefix()
		out.Storage, out.Mode, out.Compress, out.Notes, out.Protected = "", "", "", "", false
	}
	k.c.task.PVE = &out
	return nil
}

// pveTarget is one machine a run goes through.
type pveTarget struct {
	vmid int
	res  proxmox.Resource
	ok   bool
}

func (r *taskRun) pve(ctx context.Context) (any, error) {
	t := r.plan.Task.PVE
	if t == nil || r.h.pve == nil {
		return r.finish(ctx, "It has no cluster.")
	}
	c, cl, err := r.h.pve.jobClient(ctx, t.ClusterID)
	if err != nil {
		return r.finish(ctx, problemText(err))
	}
	if c.WorkspaceID != r.ws {
		return r.finish(ctx, "The cluster moved to another workspace.")
	}
	if r.acc.WorkspaceLevel(r.ws) < auth.Engineer {
		return r.finish(ctx, fmt.Sprintf("%s no longer has Engineer access to %s.", r.who, c.Name))
	}
	lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	res, err := cl.Resources(lctx, "vm")
	cancel()
	if err != nil {
		_, msg := pveStatus(err)
		return r.finish(ctx, "Couldn't read the cluster: "+cmpOr(msg, err.Error()))
	}
	byID := map[int]proxmox.Resource{}
	for _, m := range res {
		if m.Type == "qemu" || m.Type == "lxc" {
			byID[m.VMID] = m
		}
	}
	var targets []pveTarget
	if t.All {
		for id, m := range byID {
			if m.Template != 1 && !slices.Contains(t.Skip, id) {
				targets = append(targets, pveTarget{vmid: id, res: m, ok: true})
			}
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].vmid < targets[j].vmid })
	} else {
		for _, id := range t.VMIDs {
			m, ok := byID[id]
			targets = append(targets, pveTarget{vmid: id, res: m, ok: ok})
		}
	}
	if len(targets) == 0 {
		return r.finish(ctx, "There are no machines on the cluster to go through.")
	}
	rows := make([]ScheduleEndView, len(targets))
	for i, g := range targets {
		name := fmt.Sprintf("Machine %d", g.vmid)
		if g.ok {
			name = fmt.Sprintf("%s (%d)", guestName(g.res), g.vmid)
		}
		rows[i] = ScheduleEndView{Name: name, Missing: !g.ok}
	}
	r.rows(rows)

	phase := "Backing up"
	if r.plan.Action == "pve-snapshot" {
		phase = "Taking a snapshot of"
	}
	stamp := time.Now().In(r.loc)
	stoppedBy := ""
	for i, g := range targets {
		if ctx.Err() != nil {
			break
		}
		if stoppedBy != "" {
			r.mu.Lock()
			r.results[i].State, r.results[i].Note = "canceled", "Not done: "+stoppedBy+" failed first."
			r.save()
			r.mu.Unlock()
			continue
		}
		r.begin(i, phase)
		var note string
		switch {
		case !g.ok:
			err = errors.New("This machine is no longer on the cluster.")
		case g.res.Template == 1:
			err = errors.New("It's a template: nothing to do.")
		case r.plan.Action == "pve-backup":
			note, err = r.pveBackup(ctx, cl, *t, g.res)
		default:
			note, err = r.pveSnapshot(ctx, cl, *t, g.res, stamp)
		}
		if err != nil && ctx.Err() == nil {
			if _, msg := pveStatus(err); msg != "" {
				err = errors.New(msg)
			}
		}
		r.end(ctx, i, err, note)
		if err != nil && !t.KeepGoing {
			stoppedBy = rows[i].Name
		}
	}
	return r.finish(ctx, "")
}

func (r *taskRun) pveBackup(ctx context.Context, cl *proxmox.Client, t SchedulePVE, m proxmox.Resource) (string, error) {
	pveMarkIfStop(t, m)
	upid, err := cl.Vzdump(ctx, m.Node, m.VMID, proxmox.BackupOptions{
		Storage: t.Storage, Mode: t.Mode, Compress: t.Compress, Notes: t.Notes, Protected: t.Protected,
	})
	if err != nil {
		return "", err
	}
	if err := followUPID(ctx, r.t, cl, upid, "Backing up "+guestName(m)); err != nil {
		return "", err
	}
	pveMarkIfStop(t, m)
	return "Backed up to " + t.Storage + ".", nil
}

// pveMarkIfStop: a stop-mode backup shuts the machine for a while, which the
// monitor mustn't take for an unexpected stop.
func pveMarkIfStop(t SchedulePVE, m proxmox.Resource) {
	if t.Mode == "stop" {
		if id, err := uuid.Parse(t.ClusterID); err == nil {
			markPVEPower(id, m.VMID)
		}
	}
}

var snapStamp = regexp.MustCompile(`^_\d{8}_\d{4}(\d{2})?$`)

func (r *taskRun) pveSnapshot(ctx context.Context, cl *proxmox.Client, t SchedulePVE, m proxmox.Resource, at time.Time) (string, error) {
	kind := proxmox.Kind(m.Type)
	prefix := t.prefix()
	name := prefix + "_" + at.Format("20060102_1504")
	existing, err := cl.Snapshots(ctx, m.Node, kind, m.VMID)
	if err != nil {
		return "", err
	}
	if slices.ContainsFunc(existing, func(s proxmox.Snapshot) bool { return s.Name == name }) {
		name = prefix + "_" + at.Format("20060102_150405")
	}
	desc := "Taken by the Morche cron job " + r.plan.Name
	upid, err := cl.CreateSnapshot(ctx, m.Node, kind, m.VMID, name, desc, t.VMState && m.Status == "running")
	if err != nil {
		return "", err
	}
	if err := followUPID(ctx, r.t, cl, upid, "Taking a snapshot of "+guestName(m)); err != nil {
		return "", err
	}
	note := "Took " + name + "."
	if t.Keep <= 0 {
		return note, nil
	}
	all, err := cl.Snapshots(ctx, m.Node, kind, m.VMID)
	if err != nil {
		return note + " Couldn't read the older snapshots to tidy them.", nil
	}
	var ours []proxmox.Snapshot
	for _, s := range all {
		if strings.HasPrefix(s.Name, prefix) && snapStamp.MatchString(strings.TrimPrefix(s.Name, prefix)) {
			ours = append(ours, s)
		}
	}
	if len(ours) <= t.Keep {
		return note, nil
	}
	// Oldest first: by time taken, then by name (the stamp sorts too).
	sort.Slice(ours, func(i, j int) bool {
		if ours[i].SnapTime != ours[j].SnapTime {
			return ours[i].SnapTime < ours[j].SnapTime
		}
		return ours[i].Name < ours[j].Name
	})
	removed, failed := 0, 0
	for _, s := range ours[:len(ours)-t.Keep] {
		if ctx.Err() != nil {
			break
		}
		upid, err := cl.DeleteSnapshot(ctx, m.Node, kind, m.VMID, s.Name)
		if err == nil {
			err = followUPID(ctx, r.t, cl, upid, "Deleting the old snapshot "+s.Name)
		}
		if err != nil {
			failed++
			r.t.Logf("Couldn't delete %s: %v", s.Name, err)
			continue
		}
		removed++
	}
	if removed > 0 {
		note += fmt.Sprintf(" Deleted %s.", plural(removed, "older snapshot"))
	}
	if failed > 0 {
		note += fmt.Sprintf(" %s couldn't be deleted.", plural(failed, "older snapshot"))
	}
	return note, nil
}
