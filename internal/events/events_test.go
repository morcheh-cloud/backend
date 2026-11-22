package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPublishFillsAndFansOut(t *testing.T) {
	b := New()
	a, stopA := b.Subscribe("a", 4)
	c, stopC := b.Subscribe("c", 4)
	defer stopA()
	defer stopC()
	b.Publish(Event{Type: ServerOffline, WorkspaceID: uuid.New(), Data: map[string]any{"x": 1}})
	for _, ch := range []<-chan Event{a, c} {
		select {
		case e := <-ch:
			if e.ID == uuid.Nil || e.At.IsZero() || e.Severity != Info {
				t.Fatalf("not filled: %+v", e)
			}
		case <-time.After(time.Second):
			t.Fatal("no event")
		}
	}
}

func TestPublishDropsWithoutWorkspaceAndNeverBlocks(t *testing.T) {
	b := New()
	ch, stop := b.Subscribe("slow", 1)
	defer stop()
	b.Publish(Event{Type: ServerOffline}) // no workspace
	ws := uuid.New()
	done := make(chan struct{})
	go func() {
		for range 10 {
			b.Publish(Event{Type: ServerOffline, WorkspaceID: ws})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a full subscriber")
	}
	if e := <-ch; e.WorkspaceID != ws {
		t.Fatalf("got %+v", e)
	}
	var nilBus *Bus
	nilBus.Publish(Event{Type: ServerOffline, WorkspaceID: ws}) // no panic
}

func TestUnsubscribeCloses(t *testing.T) {
	b := New()
	ch, stop := b.Subscribe("x", 1)
	stop()
	stop()
	if _, ok := <-ch; ok {
		t.Fatal("channel still open")
	}
	b.Publish(Event{Type: ServerOffline, WorkspaceID: uuid.New()})
}

func TestCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, typ := range Catalog {
		if seen[typ.Name] {
			t.Errorf("%s twice", typ.Name)
		}
		seen[typ.Name] = true
		if typ.Sample.Type != typ.Name {
			t.Errorf("%s: sample has type %s", typ.Name, typ.Sample.Type)
		}
		if typ.Label == "" || typ.Group == "" || typ.Description == "" || typ.SubjectKind == "" {
			t.Errorf("%s: missing fields", typ.Name)
		}
		if typ.Sample.Subject.Kind == "" || typ.Sample.WorkspaceID == uuid.Nil {
			t.Errorf("%s: sample without subject or workspace", typ.Name)
		}
		if _, err := json.Marshal(typ.Sample); err != nil {
			t.Errorf("%s: %v", typ.Name, err)
		}
	}
	for _, n := range []string{AlertFired, AlertResolved, MonitorDown, MonitorUp, MonitorDegraded, ServerOffline, ServerOnline,
		CronjobFailed, CronjobSucceeded, BackupFailed, BackupSucceeded, DeployFailed, DeploySucceeded, AutomationFailed, TestPing} {
		if !Known(n) {
			t.Errorf("%s isn't in the catalog", n)
		}
	}
	if Known("nope") {
		t.Error("unknown type known")
	}
}

func TestOriginAndMuted(t *testing.T) {
	id := uuid.New()
	e := Event{Origin: FromAutomation(id), Data: map[string]any{"muted": true}}
	if !e.ByAutomation() || !e.Muted() {
		t.Fatal("flags")
	}
	if (Event{}).ByAutomation() || (Event{}).Muted() {
		t.Fatal("zero flags")
	}
}
