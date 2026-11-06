package ansible

import (
	"context"
	"testing"
)

func TestCategorize(t *testing.T) {
	cases := []struct{ coll, short, want string }{
		{"ansible.builtin", "apt", "packages"},
		{"ansible.builtin", "lineinfile", "files"},
		{"ansible.builtin", "shell", "commands"},
		{"ansible.builtin", "debug", "flow"},
		{"community.docker", "docker_container", "containers"},
		{"community.general", "ufw", "network"},
		{"community.general", "timezone", "system"},
		{"ansible.posix", "authorized_key", "users"},
		{"community.general", "slack", "notify"},
		{"community.general", "zzz_unknown", "other"},
	}
	for _, c := range cases {
		if got := categorize(c.coll, c.short); got != c.want {
			t.Errorf("categorize(%s.%s) = %s, want %s", c.coll, c.short, got, c.want)
		}
	}
}

func TestParseDoc(t *testing.T) {
	out := []byte(`{"ansible.builtin.command": {"doc": {
		"description": ["Runs it."],
		"options": {
			"free_form": {"description": "The command"},
			"chdir": {"type": "path", "description": ["Go here first."]},
			"argv": {"type": "list", "elements": "str"},
			"state": {"choices": {"a": "first", "b": "second"}}
		},
		"attributes": {"check_mode": {"support": "partial"}}
	}, "examples": "- name: x\n  ansible.builtin.command: ls\n"}}`)
	d, err := parseDoc(out, newModule("ansible.builtin.command", "Execute"))
	if err != nil {
		t.Fatal(err)
	}
	if !d.FreeForm || d.CheckMode != "partial" || len(d.Options) != 4 {
		t.Fatalf("unexpected %+v", d)
	}
	if d.Options[0].Name != "argv" || d.Options[0].Elements != "str" {
		t.Errorf("options not sorted or typed: %+v", d.Options[0])
	}
	if d.Options[1].Type != "path" || d.Options[1].Description[0] != "Go here first." {
		t.Errorf("chdir: %+v", d.Options[1])
	}
	if len(d.Options[3].Choices) != 2 {
		t.Errorf("described choices: %+v", d.Options[3].Choices)
	}
	if len(d.Main) != 1 || d.Main[0] != "chdir" {
		t.Errorf("main: %v", d.Main)
	}
}

// Against the real ansible-doc when it's installed.
func TestCatalogLive(t *testing.T) {
	st := Detect(context.Background(), Config{Playbook: "ansible-playbook", Sandbox: SandboxOff})
	if !st.Installed {
		t.Skip("ansible isn't installed")
	}
	var c Catalog
	list, err := c.Modules(context.Background(), st)
	if err != nil || len(list) < 10 {
		t.Fatalf("modules: %v (%d)", err, len(list))
	}
	d, err := c.Doc(context.Background(), st, "apt")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "ansible.builtin.apt" || len(d.Options) == 0 || d.Category != "packages" {
		t.Fatalf("apt: %s %d %s", d.Name, len(d.Options), d.Category)
	}
	if _, err := c.Doc(context.Background(), st, "no_such_thing"); err != ErrNoModule {
		t.Fatalf("want ErrNoModule, got %v", err)
	}
}
