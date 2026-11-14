package api

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBuiltinTemplates(t *testing.T) {
	list, err := loadTemplates(templateFiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) < 18 {
		t.Fatalf("only %d templates", len(list))
	}
	seen := map[string]bool{}
	for _, tpl := range list {
		if seen[tpl.ID] {
			t.Errorf("%s twice", tpl.ID)
		}
		seen[tpl.ID] = true
		var doc struct {
			Services map[string]any `yaml:"services"`
		}
		if err := yaml.Unmarshal([]byte(tpl.Compose), &doc); err != nil {
			t.Errorf("%s: compose: %v", tpl.ID, err)
			continue
		}
		if len(doc.Services) == 0 {
			t.Errorf("%s: no services", tpl.ID)
		}
		if len(tpl.Name) > 100 || len(tpl.Category) > 50 || len(tpl.Description) > 1000 {
			t.Errorf("%s: a field is too long", tpl.ID)
		}
		if strings.Contains(tpl.Env, "change-me") {
			t.Errorf("%s: fixed password in .env", tpl.ID)
		}
	}
	for _, id := range []string{"builtin:nginx", "builtin:wordpress", "builtin:postgres"} {
		if !seen[id] {
			t.Errorf("%s is gone (projects link to it)", id)
		}
	}
}
