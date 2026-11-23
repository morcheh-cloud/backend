package api

import "github.com/morche/backend/internal/auth"

// Who may do what with a server's config files (hosts, DNS, clock, network,
// package sources). Kept here so the whole feature's levels sit together.
var configPolicies = map[string]policy{
	"list-config-changes":   onServer(auth.Viewer),
	"get-config-change":     onServer(auth.Operator),
	"restore-config-change": onServer(auth.Engineer),
	"keep-config-change":    onServer(auth.Engineer),
	"undo-config-change":    onServer(auth.Engineer),
}

// Every write is refused on the public demo.
var configDemoRefused = []string{
	"restore-config-change", "keep-config-change", "undo-config-change",
}

func init() {
	for op, p := range configPolicies {
		policies[op] = p
	}
	for _, op := range configDemoRefused {
		demoRefused[op] = true
	}
}
