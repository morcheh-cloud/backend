package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestComposeServiceRollout(t *testing.T) {
	var cfg struct {
		Services map[string]composeService `json:"services"`
	}
	raw := `{"services":{
	  "web":{"image":"app","deploy":{"update_config":{"order":"start-first","delay":"10s"}},
	    "healthcheck":{"test":["CMD","true"],"interval":"5s","timeout":"3s","retries":3,"start_period":"1m30s"},
	    "ports":[{"target":3000}]},
	  "fixed":{"deploy":{"update_config":{"order":"start-first"}},"ports":[{"target":80,"published":"8080"}]},
	  "named":{"container_name":"x","deploy":{"update_config":{"order":"START-FIRST"}}},
	  "off":{"healthcheck":{"disable":true},"deploy":{"update_config":{"order":"start-first"}}},
	  "plain":{"image":"redis"}}}`
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	s := cfg.Services
	if !s["web"].startFirst() || s["plain"].startFirst() || !s["named"].startFirst() {
		t.Fatal("startFirst")
	}
	if why := s["web"].rollBlocker(); why != "" {
		t.Fatalf("web blocked: %s", why)
	}
	for name, want := range map[string]string{"fixed": "8080", "named": "container_name", "off": "turned off"} {
		if why := s[name].rollBlocker(); !strings.Contains(why, want) {
			t.Errorf("%s: %q", name, why)
		}
	}
	// 90s + 4*(5s+3s) + 30s = 152s
	if got := s["web"].healthWait(); got != 152*time.Second {
		t.Errorf("healthWait %s", got)
	}
	if got := s["web"].overlap(); got != 10*time.Second {
		t.Errorf("overlap %s", got)
	}
	if got := s["plain"].healthWait(); got != 4*time.Minute+30*time.Second {
		t.Errorf("default healthWait %s", got)
	}
}
