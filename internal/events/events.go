// Package events is Morche's in-process event bus: things that happen in the
// panel (an alert fires, a monitor goes down, a cron job fails…) are
// published here once, where they happen, and anything that wants to react
// (outgoing webhooks, automations) subscribes.
//
// Publishing never blocks: every subscriber has its own buffer, and an event
// that doesn't fit is dropped for that subscriber (and logged). Events live in
// memory only; a subscriber that must not lose them stores them itself (the
// webhook dispatcher writes a delivery row per event).
//
// Rules for publishers:
//   - publish on a state transition, never from a notification send function
//     (sends also carry reminders and are skipped while muted);
//   - an event without a workspace is dropped;
//   - set Origin = "automation:<id>" when an automation caused it, so
//     automations never trigger themselves in a loop;
//   - alert events are published even while muted, with Data["muted"] = true:
//     each subscriber decides what to do with them.
package events

import (
	"log/slog"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Event is one thing that happened.
type Event struct {
	ID          uuid.UUID `json:"id"`
	Type        string    `json:"type" doc:"See GET /events/catalog, e.g. alert.fired"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
	At          time.Time `json:"at"`
	Severity    string    `json:"severity" enum:"info,warning,critical"`
	Title       string    `json:"title"`
	Text        string    `json:"text,omitempty"`
	// URL is the panel page about it, when the panel's address is known.
	URL     string  `json:"url,omitempty"`
	Subject Subject `json:"subject"`
	// ServerID is the server it happened on, when there is one.
	ServerID *uuid.UUID     `json:"server_id,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
	// Origin is "automation:<id>" when an automation caused it (loop guard),
	// empty otherwise.
	Origin string `json:"origin,omitempty"`
}

// Subject is what the event is about.
type Subject struct {
	Kind string `json:"kind" doc:"server, monitor, database, cluster, cronjob, project, alert-rule, automation or webhook"`
	// ID is the subject's id: a UUID for most, "<server id>/<name>" for a
	// compose project.
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Subject kinds.
const (
	SubjectServer     = "server"
	SubjectMonitor    = "monitor"
	SubjectDatabase   = "database"
	SubjectCluster    = "cluster"
	SubjectCronjob    = "cronjob"
	SubjectProject    = "project"
	SubjectAlertRule  = "alert-rule"
	SubjectAutomation = "automation"
	SubjectWebhook    = "webhook"
)

// Severities.
const (
	Info     = "info"
	Warning  = "warning"
	Critical = "critical"
)

// FromAutomation is the Origin of events an automation caused.
func FromAutomation(id uuid.UUID) string { return "automation:" + id.String() }

// ByAutomation says whether an event was caused by an automation.
func (e Event) ByAutomation() bool { return strings.HasPrefix(e.Origin, "automation:") }

// Muted says whether an alert event was published while a mute covered it.
func (e Event) Muted() bool {
	m, _ := e.Data["muted"].(bool)
	return m
}

// Bus fans events out to subscribers. The zero value isn't usable; use New.
// A nil *Bus accepts Publish and drops everything, so code can publish
// without checking whether a bus was wired in (tests).
type Bus struct {
	mu   sync.RWMutex
	subs map[*sub]struct{}
}

type sub struct {
	name string
	ch   chan Event
	// dropped counts events lost since the last one that fit, for the log.
	dropped atomic.Int64
}

// New makes a bus.
func New() *Bus { return &Bus{subs: map[*sub]struct{}{}} }

// Publish hands e to every subscriber without waiting. It fills ID and At
// when they're empty and Severity with info. An event without a workspace or
// type is dropped.
func (b *Bus) Publish(e Event) {
	if b == nil || e.WorkspaceID == uuid.Nil || e.Type == "" {
		return
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if e.Severity == "" {
		e.Severity = Info
	}
	if e.Data != nil {
		// Each subscriber gets the same map: copy it so the publisher can't
		// change it under them.
		e.Data = maps.Clone(e.Data)
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		select {
		case s.ch <- e:
			if n := s.dropped.Swap(0); n > 0 {
				slog.Warn("events: subscriber caught up", "subscriber", s.name, "dropped", n)
			}
		default:
			if n := s.dropped.Add(1); n == 1 || n%100 == 0 {
				slog.Warn("events: subscriber is full, event dropped", "subscriber", s.name, "type", e.Type, "dropped", n)
			}
		}
	}
}

// Subscribe returns a channel with every event published from now on, and a
// function that ends the subscription (and closes the channel). buf is the
// channel's size (at least 1): when the subscriber falls that far behind,
// further events are dropped for it.
func (b *Bus) Subscribe(name string, buf int) (<-chan Event, func()) {
	s := &sub{name: name, ch: make(chan Event, max(buf, 1))}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return s.ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, s)
			b.mu.Unlock()
			close(s.ch)
		})
	}
}
