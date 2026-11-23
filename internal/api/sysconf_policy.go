package api

import "github.com/morche/backend/internal/auth"

// Who may do what with a server's config files (hosts, DNS, clock, network,
// package sources). Kept here so the whole feature's levels sit together.
var configPolicies = map[string]policy{
	"list-config-changes":   onServer(auth.Operator),
	"get-config-change":     onServer(auth.Operator),
	"restore-config-change": onServer(auth.Engineer),
	"keep-config-change":    onServer(auth.Engineer),
	"undo-config-change":    onServer(auth.Engineer),

	"get-server-hosts":       onServer(auth.Viewer),
	"update-server-hosts":    onServer(auth.Engineer),
	"resolve-server-name":    onServer(auth.Operator),
	"get-server-dns":         onServer(auth.Viewer),
	"update-server-dns":      onServer(auth.Engineer),
	"get-server-clock":       onServer(auth.Viewer),
	"update-server-hostname": onServer(auth.Engineer),
	"update-server-clock":    onServer(auth.Engineer),
	"sync-server-clock":      onServer(auth.Engineer),
	"get-server-network":     onServer(auth.Viewer),
	"preview-server-network": onServer(auth.Engineer),
	"update-server-network":  onServer(auth.Engineer),
}

// Every write is refused on the public demo.
var configDemoRefused = []string{
	"restore-config-change", "keep-config-change", "undo-config-change",
	"update-server-hosts", "update-server-dns", "update-server-hostname",
	"update-server-clock", "sync-server-clock", "update-server-network",
}

func init() {
	for op, p := range configPolicies {
		policies[op] = p
	}
	for _, op := range configDemoRefused {
		demoRefused[op] = true
	}
}
