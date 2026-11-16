package api

import (
	"encoding/json"
	"os"
	"testing"
)

// TestWriteSpec writes the OpenAPI spec to $MORCHE_SPEC_OUT, for generating
// the frontend's client without restarting the running server:
//
//	MORCHE_SPEC_OUT=/tmp/openapi.json go test ./internal/api -run TestWriteSpec
func TestWriteSpec(t *testing.T) {
	out := os.Getenv("MORCHE_SPEC_OUT")
	if out == "" {
		t.Skip("MORCHE_SPEC_OUT not set")
	}
	_, api := testRouter(t, "development")
	b, err := json.Marshal(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
