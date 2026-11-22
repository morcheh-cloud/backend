package arvancdn_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/morche/backend/internal/arvancdn"
	"github.com/morche/backend/internal/arvancdn/fake"
	"github.com/morche/backend/internal/cloud"
)

func client(t *testing.T, key string) *arvancdn.Client {
	srv := httptest.NewServer(fake.New())
	t.Cleanup(srv.Close)
	return arvancdn.New(arvancdn.Config{Key: key, BaseURL: srv.URL + "/cdn/4.0"})
}

func TestRecordsRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := client(t, "Apikey "+fake.Key)
	info, err := c.Check(ctx)
	if err != nil || info.Domains != 3 {
		t.Fatalf("check: %v %+v", err, info)
	}
	recs, err := c.Records(ctx, "shop.morche.test")
	if err != nil || len(recs) == 0 {
		t.Fatalf("records: %v %d", err, len(recs))
	}
	v, _ := json.Marshal([]map[string]any{{"ip": "198.51.100.7"}})
	r, err := c.CreateRecord(ctx, "shop.morche.test", arvancdn.Record{Type: "a", Name: "new", TTL: 300, Value: v})
	if err != nil || r.ID == "" {
		t.Fatalf("create: %v", err)
	}
	if _, err := c.SetCloud(ctx, "shop.morche.test", r.ID, true); err != nil {
		t.Fatalf("cloud: %v", err)
	}
	bad, _ := json.Marshal([]map[string]any{{"ip": "nope"}})
	_, err = c.CreateRecord(ctx, "shop.morche.test", arvancdn.Record{Type: "a", Name: "x", Value: bad})
	var ve *arvancdn.ValidationError
	if !errors.As(err, &ve) || len(ve.Fields) != 1 {
		t.Fatalf("want a validation error, got %v", err)
	}
	if err := c.DeleteRecord(ctx, "shop.morche.test", r.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestSettingsAndErrors(t *testing.T) {
	ctx := context.Background()
	c := client(t, fake.Key)
	raw := map[string]any{}
	if err := c.GetSetting(ctx, "blog.morche.test", arvancdn.SettingRedirect, &raw); err != nil || raw["f_redirect_to_www"] != false {
		t.Fatalf("redirect: %v %v", err, raw)
	}
	if err := c.SetSetting(ctx, "blog.morche.test", arvancdn.SettingCaching, map[string]any{"cache_status": false}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Domain(ctx, "missing.test"); err == nil {
		t.Fatal("want not found")
	} else if _, ok := errors.AsType[*cloud.NotFoundError](err); !ok {
		t.Fatalf("want NotFoundError, got %T", err)
	}
	if _, err := client(t, "wrong").Check(ctx); err == nil {
		t.Fatal("want auth error")
	} else if s, _ := cloud.Classify(err); s != "auth_failed" {
		t.Fatalf("status %s", s)
	}
}
