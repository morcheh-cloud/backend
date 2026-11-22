package api

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/morche/backend/internal/events"
)

// The pure parts of automations: does an event start one, and what do the
// {{…}} placeholders in its steps say.

// automationVars is what a run's templates and command env vars read.
type automationVars struct {
	Event      events.Event
	ServerName string
	ServerHost string
	Automation string
	AutoID     uuid.UUID
	RunID      uuid.UUID
	RunURL     string
}

var templateRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}`)

// renderTemplate replaces every {{path}} with its value; an unknown path is
// empty. Plain substitution: nothing is escaped or evaluated.
func renderTemplate(tmpl string, v automationVars) string {
	if !strings.Contains(tmpl, "{{") {
		return tmpl
	}
	return templateRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		return v.lookup(templateRe.FindStringSubmatch(m)[1])
	})
}

// templateHas says whether a text uses any placeholder.
func templateHas(tmpl string) bool { return templateRe.MatchString(tmpl) }

func (v automationVars) lookup(path string) string {
	e := v.Event
	switch path {
	case "event.id":
		return e.ID.String()
	case "event.type":
		return e.Type
	case "event.title":
		return e.Title
	case "event.text":
		return e.Text
	case "event.severity":
		return e.Severity
	case "event.url":
		return e.URL
	case "event.at":
		if e.At.IsZero() {
			return ""
		}
		return e.At.UTC().Format(time.RFC3339)
	case "event.json":
		return v.eventJSON()
	case "subject.kind":
		return e.Subject.Kind
	case "subject.id":
		return e.Subject.ID
	case "subject.name":
		return e.Subject.Name
	case "server.id":
		if e.ServerID == nil {
			return ""
		}
		return e.ServerID.String()
	case "server.name":
		return v.ServerName
	case "server.host":
		return v.ServerHost
	case "automation.name":
		return v.Automation
	case "automation.id":
		if v.AutoID == uuid.Nil {
			return ""
		}
		return v.AutoID.String()
	case "run.id":
		if v.RunID == uuid.Nil {
			return ""
		}
		return v.RunID.String()
	case "run.url":
		return v.RunURL
	}
	if rest, ok := strings.CutPrefix(path, "data."); ok {
		return dataValue(e.Data, rest)
	}
	return ""
}

func (v automationVars) eventJSON() string {
	body, err := webhookPayload(v.Event)
	if err != nil {
		return ""
	}
	return body
}

// dataValue reads a dotted path out of event data: strings as they are,
// numbers and booleans as text, objects and lists as JSON.
func dataValue(data map[string]any, path string) string {
	var cur any = data
	for part := range strings.SplitSeq(path, ".") {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[part]
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(c) {
				return ""
			}
			cur = c[i]
		default:
			return ""
		}
	}
	switch c := cur.(type) {
	case nil:
		return ""
	case string:
		return c
	case bool:
		return strconv.FormatBool(c)
	case float64:
		return strconv.FormatFloat(c, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(c), 'f', -1, 32)
	case int, int32, int64, uint, uint32, uint64:
		return fmt.Sprint(c)
	}
	raw, err := json.Marshal(cur)
	if err != nil {
		return ""
	}
	return string(raw)
}

// automationEnvCap caps each MORCHE_* value (MORCHE_EVENT_JSON can be long).
const automationEnvCap = 32 << 10

// automationEnv is the event as environment variables for a command: the
// values are never spliced into its text.
func automationEnv(v automationVars) map[string]string {
	cut := func(s string) string {
		if len(s) > automationEnvCap {
			s = strings.ToValidUTF8(s[:automationEnvCap], "")
		}
		return strings.ReplaceAll(s, "\x00", "")
	}
	env := map[string]string{
		"MORCHE_EVENT_ID":        v.lookup("event.id"),
		"MORCHE_EVENT_TYPE":      v.Event.Type,
		"MORCHE_EVENT_TITLE":     v.Event.Title,
		"MORCHE_EVENT_TEXT":      v.Event.Text,
		"MORCHE_EVENT_SEVERITY":  v.Event.Severity,
		"MORCHE_EVENT_URL":       v.Event.URL,
		"MORCHE_EVENT_AT":        v.lookup("event.at"),
		"MORCHE_EVENT_JSON":      v.eventJSON(),
		"MORCHE_SUBJECT_KIND":    v.Event.Subject.Kind,
		"MORCHE_SUBJECT_ID":      v.Event.Subject.ID,
		"MORCHE_SUBJECT_NAME":    v.Event.Subject.Name,
		"MORCHE_SERVER_ID":       v.lookup("server.id"),
		"MORCHE_SERVER_NAME":     v.ServerName,
		"MORCHE_SERVER_HOST":     v.ServerHost,
		"MORCHE_AUTOMATION_ID":   v.lookup("automation.id"),
		"MORCHE_AUTOMATION_NAME": v.Automation,
		"MORCHE_RUN_ID":          v.lookup("run.id"),
	}
	for k, val := range env {
		env[k] = cut(val)
	}
	return env
}

// automationMatches says whether an event starts an automation with this
// trigger. tags answers the event's server's tags (only asked when a tag
// filter needs them). Events an automation caused and internal types never
// start one; muted alerts only with include_muted.
func automationMatches(t AutomationTrigger, e events.Event, tags func() []string) bool {
	if t.Kind != "event" || e.ByAutomation() {
		return false
	}
	if typ, ok := events.Lookup(e.Type); !ok || typ.Internal {
		return false
	}
	if e.Muted() && !t.IncludeMuted {
		return false
	}
	if !slices.Contains(t.Events, e.Type) {
		return false
	}
	f := t.Filter
	if len(f.Servers) > 0 && (e.ServerID == nil || !slices.Contains(f.Servers, e.ServerID.String())) {
		return false
	}
	if len(f.Severity) > 0 && !slices.Contains(f.Severity, e.Severity) {
		return false
	}
	if len(f.Subjects) > 0 && !slices.Contains(f.Subjects, e.Subject.ID) {
		return false
	}
	if m := strings.TrimSpace(f.Match); m != "" && !strings.Contains(strings.ToLower(e.Title), strings.ToLower(m)) {
		return false
	}
	if len(f.Tags) > 0 {
		if e.ServerID == nil {
			return false
		}
		have := tags()
		if !slices.ContainsFunc(f.Tags, func(t string) bool {
			return slices.ContainsFunc(have, func(h string) bool { return strings.EqualFold(h, t) })
		}) {
			return false
		}
	}
	return true
}

// automationGate decides whether a matched event may start a run now:
// cooldown per (automation, subject), runs per hour, one run at a time per
// subject (active = runs going for this subject).
// It answers the reason to skip, or "".
func automationGate(cooldown, perHour int32, lastForSubject time.Time, runsLastHour, active int64, now time.Time) string {
	switch {
	case active > 0:
		return "The run before for this was still going."
	case cooldown > 0 && now.Sub(lastForSubject) < time.Duration(cooldown)*time.Second:
		left := time.Duration(cooldown)*time.Second - now.Sub(lastForSubject)
		return fmt.Sprintf("Cooling down: it ran for this less than %s ago (%s left).", fmtSeconds(int64(cooldown)), fmtSeconds(int64(left.Round(time.Second)/time.Second)))
	case perHour > 0 && runsLastHour >= int64(perHour):
		return fmt.Sprintf("It already ran %d times in the last hour (the most it may).", runsLastHour)
	}
	return ""
}

func fmtSeconds(s int64) string {
	switch {
	case s < 120:
		return fmt.Sprintf("%d s", s)
	case s < 7200:
		return fmt.Sprintf("%d min", (s+30)/60)
	}
	return fmt.Sprintf("%d h", (s+1800)/3600)
}

// hookLimiter counts incoming hook calls per automation in a sliding minute.
type hookLimiter struct {
	mu    sync.Mutex
	per   int
	calls map[uuid.UUID][]time.Time
}

func newHookLimiter(per int) *hookLimiter {
	return &hookLimiter{per: per, calls: map[uuid.UUID][]time.Time{}}
}

// allow notes a call and says whether it's within the limit.
func (l *hookLimiter) allow(id uuid.UUID, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	from := now.Add(-time.Minute)
	recent := slices.DeleteFunc(l.calls[id], func(t time.Time) bool { return !t.After(from) })
	if len(recent) >= l.per {
		l.calls[id] = recent
		return false
	}
	l.calls[id] = append(recent, now)
	if len(l.calls) > 10000 {
		for k, v := range l.calls {
			if len(v) == 0 || !v[len(v)-1].After(from) {
				delete(l.calls, k)
			}
		}
	}
	return true
}
