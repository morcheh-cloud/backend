package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/packages"
	"github.com/morcheh/backend/internal/sshpool"
)

// The package-upgrade cron action: Upgrade all on each server, then the
// cleanups asked for, then a restart where one is needed and allowed.
// Servers are upgraded a few at a time; restarts go one at a time.

// pkgBusy holds the servers a cron job is changing packages on right now.
// Its job is a cron run, not a package job, so the server's own job list
// doesn't show it; the Packages page asks here too.
var pkgBusy sync.Map

func pkgKey(id string) string {
	if u, err := uuid.Parse(id); err == nil {
		return u.String()
	}
	return id
}

// claimPackages marks the server busy; false = it already was.
func claimPackages(id string) bool {
	_, taken := pkgBusy.LoadOrStore(pkgKey(id), true)
	return !taken
}

func releasePackages(id string) { pkgBusy.Delete(pkgKey(id)) }

func packagesClaimed(id string) bool {
	_, ok := pkgBusy.Load(pkgKey(id))
	return ok
}

// pkgUpgrade is one run of the action, shared by its workers.
type pkgUpgrade struct {
	r    *taskRun
	t    *SchedulePackages
	many bool

	mu      sync.Mutex
	working int    // servers inside a package manager step (cancel waits)
	stopped string // the server whose failure stops the rest

	rebootMu     sync.Mutex
	rebootFailed string // a server that didn't come back: no more restarts
}

func (r *taskRun) packages(ctx context.Context) (any, error) {
	t := r.plan.Task.Packages
	if t == nil {
		return r.finish(ctx, "It has no servers.")
	}
	r.rows(r.plan.Destinations)
	n := len(r.results)
	u := &pkgUpgrade{r: r, t: t, many: n > 1}
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(max(t.Parallel, 1), max(n, 1)) {
		wg.Go(func() {
			for i := range next {
				if ctx.Err() != nil || u.stoppedBy() != "" {
					continue
				}
				if !u.one(ctx, i) && !t.KeepGoing {
					u.stop(r.results[i].Name)
				}
			}
		})
	}
	for i := range n {
		if ctx.Err() != nil || u.stoppedBy() != "" {
			break
		}
		next <- i
	}
	close(next)
	wg.Wait()
	if name := u.stoppedBy(); name != "" {
		r.mu.Lock()
		for i := range r.results {
			if r.results[i].State == "pending" {
				r.results[i].State, r.results[i].Note = "canceled", "Not upgraded: "+name+" failed first."
			}
		}
		r.save()
		r.mu.Unlock()
	}
	return r.finish(ctx, "")
}

func (u *pkgUpgrade) stoppedBy() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.stopped
}

func (u *pkgUpgrade) stop(name string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.stopped == "" {
		u.stopped = name
	}
}

// hold keeps the run from being canceled while a package manager works:
// stopping one half way can leave the server's packages broken.
func (u *pkgUpgrade) hold(on bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if on {
		u.working++
	} else {
		u.working--
	}
	locked := u.working > 0
	u.r.t.Update(func(p *jobs.Progress) { p.Locked = locked })
}

// one upgrades server i; false = it failed.
func (u *pkgUpgrade) one(ctx context.Context, i int) bool {
	r, t := u.r, u.t
	d := r.plan.Destinations[i]
	r.begin(i, "Upgrading packages on")
	fail := func(err error) bool {
		r.end(ctx, i, err, "")
		return false
	}
	if err := mayUse(r.acc, r.ws, d, auth.Engineer, r.who); err != nil {
		return fail(err)
	}
	id := *d.ServerID
	srv := r.h.st.servers
	if err := srv.packageJobRunning(ctx, id); err != nil {
		return fail(err)
	}
	if !claimPackages(id) {
		return fail(errors.New("Morcheh is already changing packages on this server."))
	}
	var (
		skip, note string
		restart    bool
	)
	err := srv.withConn(ctx, id, func(c *sshpool.Conn) error {
		defer releasePackages(id)
		sh, err := srv.pkgRoot(ctx, id, c)
		if err != nil {
			return err
		}
		before, err := readPackages(ctx, sh)
		if err != nil {
			return err
		}
		if before.Manager == packages.None {
			return errors.New("No supported package manager was found on it.")
		}
		caps := before.PackageCapabilities
		mode := t.Mode
		switch {
		case mode == packages.ModeSecurity && !caps.Security:
			skip = before.Manager + " doesn't mark security updates, so nothing was upgraded."
			return nil
		case mode == packages.ModeFull && before.Manager != packages.APT:
			mode = packages.ModeAll
		}
		steps := []struct{ action, phase string }{{packages.ActUpgradeAll, "Upgrading"}}
		if t.Autoremove && caps.Autoremove {
			steps = append(steps, struct{ action, phase string }{packages.ActAutoremove, "Removing unneeded packages"})
		}
		if t.Clean {
			steps = append(steps, struct{ action, phase string }{packages.ActClean, "Emptying the package cache"})
		}
		for _, s := range steps {
			script, err := packages.ActionScript(s.action, mode, nil, "")
			if err != nil {
				return err
			}
			timeout := packageActionTimeout
			if s.action == packages.ActUpgradeAll {
				timeout = packageUpgradeTimeout
			}
			asked, err := u.step(ctx, sh, d.Name, s.phase, script, timeout)
			restart = restart || asked
			if err != nil {
				return err
			}
		}
		after, err := readPackages(ctx, sh)
		if err != nil {
			note = "Upgraded; the packages couldn't be read again to count the changes."
			return nil
		}
		restart = restart || after.RebootRequired
		note = upgradeNote(before, after, mode)
		return nil
	})
	switch {
	case err != nil:
		return fail(err)
	case skip != "":
		r.skip(i, skip)
		return true
	case restart && t.Reboot == "if-required":
		more, rerr := u.restart(ctx, d)
		note += " " + more
		if rerr != nil {
			return fail(fmt.Errorf("%s", note))
		}
	case restart:
		note += " It needs a restart."
	}
	r.end(ctx, i, nil, note)
	return true
}

// step runs one package manager script with its output in the job's log.
// asked = the server said it needs a restart.
func (u *pkgUpgrade) step(ctx context.Context, sh *rootShell, name, phase, script string, timeout time.Duration) (asked bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	t := u.r.t
	u.hold(true)
	defer u.hold(false)
	prefix := ""
	if u.many {
		prefix = name + ": "
	}
	t.Logf("%s%s", prefix, phase)
	var last string
	lines := &lineWriter{fn: func(l string) {
		last = l
		if strings.Contains(l, "needs a restart") || strings.Contains(l, "*** System restart required ***") {
			asked = true
		}
		t.Logf("%s%s", prefix, l)
		t.Update(func(p *jobs.Progress) { p.Current = prefix + l })
	}}
	res, err := sh.execTo(ctx, script, timeout, lines)
	lines.flush()
	switch {
	case err != nil:
		return asked, err
	case ctx.Err() != nil:
		return asked, ctx.Err()
	case res.timedOut:
		return asked, fmt.Errorf("%s took longer than %d minutes, so Morcheh stopped waiting.", phase, int(timeout.Minutes()))
	case res.code != 0:
		return asked, fmt.Errorf("The package manager failed (exit %d): %s", res.code, last)
	}
	return asked, nil
}

// restart restarts a server that asked for it, one server at a time, and
// waits until it's back. Once one doesn't come back the rest aren't
// restarted. more is what to add to the row's note.
func (u *pkgUpgrade) restart(ctx context.Context, d ScheduleEndView) (more string, err error) {
	u.rebootMu.Lock()
	defer u.rebootMu.Unlock()
	if u.rebootFailed != "" {
		return "It needs a restart: not restarted, since " + u.rebootFailed + " didn't come back.", nil
	}
	skip, note, sent, err := u.r.rebootOne(ctx, d, &ScheduleReboot{
		OnlyIfRequired: true, SkipIfLoggedIn: u.t.SkipIfLoggedIn, Message: u.t.Message,
	})
	switch {
	case err != nil:
		if sent && ctx.Err() == nil {
			u.rebootFailed = d.Name
		}
		return "Then the restart failed: " + problemText(jobError(err)), err
	case skip:
		return "Not restarted: " + lowerFirst(note), nil
	}
	return "Restarted, " + lowerFirst(note), nil
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// upgradeNote says what changed, from the package lists before and after.
func upgradeNote(before, after *packages.PackagesOverview, mode string) string {
	key := func(p packages.InstalledPackage) string { return p.Name + ":" + p.Arch }
	old := map[string]string{}
	for _, p := range before.Packages {
		if p.State != "config-files" {
			old[key(p)] = p.Version
		}
	}
	var upgraded, added int
	kept := map[string]bool{}
	for _, p := range after.Packages {
		if p.State == "config-files" {
			continue
		}
		k := key(p)
		kept[k] = true
		switch v, ok := old[k]; {
		case !ok:
			added++
		case v != p.Version:
			upgraded++
		}
	}
	removed := 0
	for k := range old {
		if !kept[k] {
			removed++
		}
	}
	var parts []string
	if upgraded > 0 {
		parts = append(parts, plural(upgraded, "package")+" upgraded")
	}
	if added > 0 {
		parts = append(parts, fmt.Sprintf("%d new", added))
	}
	if removed > 0 {
		parts = append(parts, fmt.Sprintf("%d removed", removed))
	}
	note := "Already up to date."
	if len(parts) > 0 {
		note = strings.ToUpper(parts[0][:1]) + parts[0][1:]
		if len(parts) > 1 {
			note += ", " + strings.Join(parts[1:], ", ")
		}
		note += "."
	}
	left := after.Updates
	if mode == packages.ModeSecurity {
		left = after.SecurityCount
	}
	if left > 0 {
		what := "update"
		if mode == packages.ModeSecurity {
			what = "security update"
		}
		note += " " + plural(left, what) + " left (held or kept back)."
	}
	return note
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
