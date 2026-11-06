package firewall

import (
	"strings"
	"testing"
)

const stockBefore = "#\n# rules.before\n#\n*filter\n:ufw-before-input - [0:0]\nCOMMIT"

func TestForwardsRoundTrip(t *testing.T) {
	list := []Forward{
		{Protocol: "tcp", Port: "8080", ToPort: "9000", Comment: "web app"},
		{Protocol: "udp", Port: "5000:5010", ToAddress: "10.0.0.5", From: "203.0.113.0/24", Interface: "eth0"},
	}
	for i := range list {
		if err := list[i].Normalize(); err != nil {
			t.Fatal(err)
		}
	}
	out, err := UFWSetForwards(stockBefore, list)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "COMMIT\n") {
		t.Errorf("the file must end with a newline: %q", out[len(out)-20:])
	}
	if !strings.HasPrefix(out, forwardBegin) {
		t.Error("the nat block must come first")
	}
	for _, want := range []string{
		"-A MORCHEH-PRE -p tcp --dport 8080 -j REDIRECT --to-ports 9000",
		"-A MORCHEH-PRE -i eth0 -p udp -s 203.0.113.0/24 --dport 5000:5010 -j DNAT --to-destination 10.0.0.5",
		"-A MORCHEH-POST -p udp -d 10.0.0.5 --dport 5000:5010 -j MASQUERADE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	got := ParseUFWForwards(out)
	if len(got) != 2 {
		t.Fatalf("got %d forwards", len(got))
	}
	for i := range got {
		if got[i].ID != list[i].ID || got[i].Comment != list[i].Comment || got[i].Target() != list[i].Target() {
			t.Errorf("forward %d changed: %+v, was %+v", i, got[i], list[i])
		}
	}

	// Writing again replaces the block, and the rest of the file stays.
	again, err := UFWSetForwards(out, list[:1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(again, forwardBegin) != 1 || strings.Contains(again, "10.0.0.5") || !strings.Contains(again, "*filter") {
		t.Errorf("rewrite:\n%s", again)
	}
	empty, err := UFWSetForwards(again, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ParseUFWForwards(empty)) != 0 {
		t.Error("expected no forwards")
	}
	if _, err := UFWSetForwards(forwardBegin+"\nnever closed", nil); err == nil {
		t.Error("a damaged block must be refused")
	}
}

func TestUFWMoveKeepsTheRule(t *testing.T) {
	r := ParseUFW("### tuple ### allow_log tcp 443 0.0.0.0/0 any 0.0.0.0/0 in comment=776562\n", "")[0]
	got := UFWMove(r, 2)
	if len(got) != 2 || !strings.HasPrefix(got[0], "ufw delete") || !strings.Contains(got[1], "insert 2 allow") ||
		!strings.Contains(got[1], "log") || !strings.Contains(got[1], "comment web") {
		t.Errorf("%q", got)
	}
	if got = UFWMove(r, 0); strings.Contains(got[1], "insert") {
		t.Errorf("position 0 appends: %q", got)
	}
}

func TestInputPresent(t *testing.T) {
	rules := ParseUFW(`
### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow udp 80 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in comment=776562
### tuple ### allow tcp 22 0.0.0.0/0 any 10.0.0.1 in
`, "")
	for _, c := range []struct {
		in   Input
		want bool
	}{
		{Input{Action: "allow", Direction: "in", Protocol: "tcp", Port: "80"}, true},
		{Input{Action: "allow", Direction: "in", Protocol: "any", Port: "80"}, true}, // tcp and udp both there
		{Input{Action: "allow", Direction: "in", Protocol: "any", Port: "443"}, false},
		{Input{Action: "allow", Direction: "in", Protocol: "tcp", Port: "443"}, true}, // the note doesn't count
		{Input{Action: "block", Direction: "in", Protocol: "tcp", Port: "80"}, false},
		{Input{Action: "allow", Direction: "in", Protocol: "tcp", Port: "22"}, false}, // only from one address
		{Input{Action: "allow", Direction: "in", Protocol: "tcp", Port: "80,443"}, true},
		{Input{Action: "allow", Direction: "in", Protocol: "tcp", Port: "80,8080"}, false},
	} {
		if got := c.in.Present(rules); got != c.want {
			t.Errorf("%+v: got %v", c.in, got)
		}
	}
}
