package api

import (
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func TestHashPasswords(t *testing.T) {
	old := proxy.HostConfig{Auth: proxy.Auth{Mode: "basic", Users: []proxy.AuthUser{{Name: "ali", Hash: "$6$old"}}}}
	c := proxy.HostConfig{Auth: proxy.Auth{Mode: "basic", Users: []proxy.AuthUser{
		{Name: "ali", Hash: "$6$forged"}, {Name: "sara", Password: "pw"},
	}}}
	if err := hashPasswords(&c, &old); err != nil {
		t.Fatal(err)
	}
	if c.Auth.Users[0].Hash != "$6$old" {
		t.Errorf("kept hash = %q", c.Auth.Users[0].Hash)
	}
	if u := c.Auth.Users[1]; !strings.HasPrefix(u.Hash, "$6$") || u.Password != "" {
		t.Errorf("new user = %+v", u)
	}
	if out := withoutPasswords(c); out.Auth.Users[1].Hash != "" {
		t.Errorf("hash leaked")
	}
	bad := proxy.HostConfig{Auth: proxy.Auth{Mode: "basic", Users: []proxy.AuthUser{{Name: "new"}}}}
	if err := hashPasswords(&bad, &old); err == nil {
		t.Errorf("a new name without a password passed")
	}
}

func TestParseUpstreamCurl(t *testing.T) {
	r := parseUpstreamCurl("\n" + upstreamMark + " 302 0.0421\n")
	if !r.OK || r.Status != 302 || r.Millis != 42 {
		t.Errorf("ok = %+v", r)
	}
	r = parseUpstreamCurl("curl: (7) Failed to connect to 10.0.0.1 port 80\n" + upstreamMark + " 000 0.001\n")
	if r.OK || r.Status != 0 || !strings.Contains(r.Error, "Failed to connect") {
		t.Errorf("down = %+v", r)
	}
}
