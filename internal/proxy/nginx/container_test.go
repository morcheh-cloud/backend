package nginx

import (
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

// A container is set up again without the server's facts (heal): no
// package manager, no init.
func TestSetupScriptInContainer(t *testing.T) {
	s := Driver{}.SetupScript(proxy.Setup{Init: "none", Container: &proxy.Container{Runtime: "docker", Name: "edge"}})
	if strings.Contains(s, "Installing nginx") || strings.Contains(s, "systemctl") {
		t.Fatalf("a container's setup installs or starts nginx itself:\n%s", s)
	}
	if !strings.Contains(s, "There's no nginx in this container") {
		t.Fatal("missing nginx check")
	}
}

func TestDetectScript(t *testing.T) {
	s := Driver{}.DetectScript()
	for _, want := range []string{"echo \"native ", "native_running", "@@inspect $rt", "nginx|openresty|angie"} {
		if !strings.Contains(s, want) {
			t.Fatalf("DetectScript lacks %q", want)
		}
	}
}
