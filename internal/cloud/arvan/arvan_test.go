package arvan

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/morcheh/backend/internal/cloud"
)

func TestState(t *testing.T) {
	cases := map[[2]string]string{
		{"ACTIVE", ""}:                 cloud.StateRunning,
		{"SHUTOFF", ""}:                cloud.StateStopped,
		{"SHELVED_OFFLOADED", ""}:      cloud.StateArchived,
		{"DELETING", ""}:               cloud.StateDeleting,
		{"ACTIVE", "BUILD"}:            cloud.StateBuilding,
		{"SHUTOFF", "VOLUME_CREATING"}: cloud.StateBuilding,
		{"ERROR", ""}:                  cloud.StateError,
		{"SOMETHING_NEW", ""}:          cloud.StateUnknown,
	}
	for in, want := range cases {
		if got := State(in[0], in[1]); got != want {
			t.Errorf("State(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestCleanKey(t *testing.T) {
	for in, want := range map[string]string{
		"Apikey abc-123": "abc-123", " apikey  abc ": "abc", "abc": "abc",
	} {
		if got := CleanKey(in); got != want {
			t.Errorf("CleanKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegionsOf(t *testing.T) {
	rs := regionsOf([]zone{
		{Name: "Bamdad", City: "Tehran", Region: "ir-central1", Code: "ir-thr-ba1", State: "UP"},
		{Name: "Simin", City: "Tehran", Region: "ir-central1", Code: "ir-thr-si1", State: "UP"},
	})
	if len(rs) != len(fallbackRegions) || rs[0].code != "ir-central1" || len(rs[0].zones) != 2 || rs[0].name != "Tehran" {
		t.Fatalf("regionsOf = %+v", rs)
	}
}

// TestLive reads (only reads) the servers of the account in ARVAN_API_KEY.
func TestLive(t *testing.T) {
	key := os.Getenv("ARVAN_API_KEY")
	if key == "" {
		t.Skip("ARVAN_API_KEY not set")
	}
	c := New(Config{Key: key, Dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	list, err := c.Servers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("regions %+v", list.Regions)
	t.Logf("problems %+v", list.Problems)
	t.Logf("%d servers, latency %s", len(list.Servers), list.Latency)
	for _, s := range list.Servers {
		t.Logf("%s %s %s %s %v", s.Region, s.Name, s.State, s.Plan, s.Addresses)
	}
}
