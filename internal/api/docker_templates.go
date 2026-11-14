package api

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Built-in templates are compose files to start a project from, one YAML file
// each in templates/ (the file name is the slug). Secrets live in the .env part,
// so a project's compose file can be shared without them. The .env may hold
// placeholders the panel fills when a project starts from it: {{secret}},
// {{secret:N}}, {{user}}, {{hex:N}}, {{base64:N}} and {{host}}.
//
// Most of the catalog was converted from Coolify's service templates
// (Apache-2.0, see templates/NOTICE).
//
//go:embed templates/*.yml
var templateFiles embed.FS

var builtinTemplates = mustLoadTemplates(templateFiles)

type templateFile struct {
	Name        string   `yaml:"name"`
	Category    string   `yaml:"category"`
	Description string   `yaml:"description"`
	Website     string   `yaml:"website"`
	Tags        []string `yaml:"tags"`
	Logo        string   `yaml:"logo"`
	Featured    bool     `yaml:"featured"`
	Env         string   `yaml:"env"`
	Compose     string   `yaml:"compose"`
}

func mustLoadTemplates(fsys fs.FS) []DockerTemplate {
	list, err := loadTemplates(fsys)
	if err != nil {
		panic(err)
	}
	return list
}

func loadTemplates(fsys fs.FS) ([]DockerTemplate, error) {
	names, err := fs.Glob(fsys, "templates/*.yml")
	if err != nil {
		return nil, err
	}
	list := make([]DockerTemplate, 0, len(names))
	for _, name := range names {
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		var f templateFile
		if err := yaml.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if f.Name == "" || !strings.Contains(f.Compose, "services:") {
			return nil, fmt.Errorf("%s: needs a name and a compose file with services", name)
		}
		list = append(list, DockerTemplate{
			ID:          "builtin:" + strings.TrimSuffix(path.Base(name), ".yml"),
			Name:        f.Name,
			Description: f.Description,
			Category:    f.Category,
			Website:     f.Website,
			Tags:        f.Tags,
			Logo:        f.Logo,
			Featured:    f.Featured,
			Compose:     f.Compose,
			Env:         f.Env,
			Builtin:     true,
		})
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Featured != list[j].Featured {
			return list[i].Featured
		}
		return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
	})
	return list, nil
}
