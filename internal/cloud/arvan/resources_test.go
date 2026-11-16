package arvan

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/morche/backend/internal/cloud/arvan/fake"
)

func TestResourcesFake(t *testing.T) {
	srv := httptest.NewServer(fake.New())
	defer srv.Close()
	c := New(Config{Key: fake.Key, BaseURL: srv.URL + "/%s/v3"})
	res, err := c.Resources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("problems: %+v", res.Problems)
	}
	// Public networks are the provider's: only the private one is the account's.
	if len(res.Networks) != 1 || res.Networks[0].Subnets[0] != "10.10.0.0/16" {
		t.Fatalf("networks: %+v", res.Networks)
	}
	if res.Firewalls[0].Builtin {
		t.Fatalf("own firewalls should come first: %+v", res.Firewalls[0])
	}
	if len(res.Volumes) == 0 || len(res.Backups) == 0 || res.Backups[0].NextAt == nil {
		t.Fatalf("volumes %+v backups %+v", res.Volumes, res.Backups)
	}
}

func TestResourcesRefusedKey(t *testing.T) {
	srv := httptest.NewServer(fake.New())
	defer srv.Close()
	zones = zoneCache{}
	c := New(Config{Key: "wrong", BaseURL: srv.URL + "/%s/v3"})
	if _, err := c.Resources(context.Background()); err == nil {
		t.Fatal("a refused key must fail")
	}
}
