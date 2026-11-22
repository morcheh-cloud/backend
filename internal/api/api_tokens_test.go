package api

import (
	"strings"
	"testing"
)

func TestNewAPIToken(t *testing.T) {
	tok, hash, err := newAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "morche_") || len(tok) != len("morche_")+40 || !validAPIToken(tok) {
		t.Fatalf("token %q", tok)
	}
	if len(hash) != 32 || len(tokenShown(tok)) != 8 {
		t.Fatal("hash or prefix")
	}
	other, _, _ := newAPIToken()
	if other == tok {
		t.Fatal("two tokens alike")
	}
}

func TestBearerToken(t *testing.T) {
	tok, _, _ := newAPIToken()
	for header, want := range map[string]string{
		"Bearer " + tok:            tok,
		"bearer   " + tok + " ":    tok,
		"Basic " + tok:             "",
		"Bearer":                   "",
		"Bearer morche_short":      "",
		"Bearer " + tok + "x":      "",
		"Bearer " + tok[:46] + "-": "",
		"Bearer " + strings.TrimPrefix(tok, "morche_"): "",
		"": "",
	} {
		if got := bearerToken(header); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}

// A renamed operation would quietly open a hole: every id must be real.
func TestTokenRefusedOperationsExist(t *testing.T) {
	for op := range tokenRefused {
		if _, ok := policies[op]; !ok {
			t.Errorf("tokenRefused lists %q, which has no policy", op)
		}
	}
	for op := range tokenAllowedSessionOps {
		if _, ok := policies[op]; !ok {
			t.Errorf("tokenAllowedSessionOps lists %q, which has no policy", op)
		}
	}
}

// Every session-level operation is refused to tokens, but get-me.
func TestTokenRefusesSessionOperations(t *testing.T) {
	for op, pol := range policies {
		if pol.kind == kindSession && !tokenRefused[op] && !tokenAllowedSessionOps[op] {
			t.Errorf("%s is a session operation that tokens may call: add it to tokenRefused", op)
		}
	}
	for _, op := range []string{"create-api-token", "delete-api-token", "change-password", "admin-update-security", "list-my-sessions", "answer-sign-in-alert", "update-me"} {
		if !tokenRefused[op] {
			t.Errorf("%s isn't refused to tokens", op)
		}
	}
}
