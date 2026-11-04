package ansible

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Host is one server in a run's inventory, with its decrypted credentials.
type Host struct {
	ServerID string
	// Name is the inventory name (see Names); ServerName the server's own.
	Name       string
	ServerName string
	Address    string
	Port       int
	User       string
	// Password is set for password logins; it also becomes the sudo password.
	Password   string
	PrivateKey string
	Passphrase string
	// HostKey is the trusted key (authorized_keys format). Required: a run
	// never trusts a key it hasn't seen before.
	HostKey string
	// Groups the host belongs to, already valid group names.
	Groups []string
}

var notName = regexp.MustCompile(`[^a-z0-9_]+`)

// GroupName turns a server tag (or an OS id) into an Ansible group name:
// lowercase letters, digits and _, not starting with a digit, never one of
// the built-in groups.
func GroupName(s string) string {
	g := strings.Trim(notName.ReplaceAllString(strings.ToLower(s), "_"), "_")
	switch {
	case g == "":
		return ""
	case g == "all" || g == "ungrouped":
		return "tag_" + g
	case g[0] >= '0' && g[0] <= '9':
		return "_" + g
	}
	return g
}

var notHost = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

// Names gives each server name a unique inventory name: spaces and other
// characters Ansible would trip on become -, and repeats get -2, -3…
func Names(names []string) []string {
	out := make([]string, len(names))
	taken := map[string]bool{"all": true, "localhost": true, "ungrouped": true}
	for i, n := range names {
		base := strings.Trim(notHost.ReplaceAllString(n, "-"), "-.")
		if base == "" {
			base = "server"
		}
		name := base
		for k := 2; taken[strings.ToLower(name)]; k++ {
			name = base + "-" + strconv.Itoa(k)
		}
		taken[strings.ToLower(name)] = true
		out[i] = name
	}
	return out
}

// alias is what ssh calls a host in known_hosts, so two servers behind one
// address with different keys can't vouch for each other.
func alias(h Host) string { return "morcheh-" + h.ServerID }

// writeInventory writes everything a run needs to reach its hosts into dir:
// inventory.json, known_hosts and a key file per key login. Keys with a
// passphrase are written decrypted (dir is private and removed afterwards):
// ansible-playbook can't type a passphrase.
func writeInventory(dir string, hosts []Host) error {
	type group struct {
		Hosts map[string]struct{} `json:"hosts"`
	}
	all := map[string]any{}
	vars := map[string]map[string]any{}
	groups := map[string]*group{}
	var known strings.Builder

	for _, h := range hosts {
		if h.HostKey == "" {
			return fmt.Errorf("%s hasn't been checked yet, so its host key isn't known. Check it first", h.ServerName)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.HostKey))
		if err != nil {
			return fmt.Errorf("%s: the stored host key can't be read: %w", h.ServerName, err)
		}
		fmt.Fprintf(&known, "%s %s", alias(h), ssh.MarshalAuthorizedKey(pub))

		v := map[string]any{
			"ansible_host":           h.Address,
			"ansible_port":           h.Port,
			"ansible_user":           h.User,
			"ansible_ssh_extra_args": "-o HostKeyAlias=" + alias(h),
			"morcheh_server_id":      h.ServerID,
			"morcheh_server_name":    h.ServerName,
		}
		switch {
		case h.PrivateKey != "":
			key, err := plainKey(h.PrivateKey, h.Passphrase)
			if err != nil {
				return fmt.Errorf("%s: %w", h.ServerName, err)
			}
			path := filepath.Join(dir, "keys", h.ServerID)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(path, key, 0o600); err != nil {
				return err
			}
			v["ansible_ssh_private_key_file"] = path
		case h.Password != "":
			v["ansible_password"] = h.Password
			v["ansible_become_password"] = h.Password
		}
		vars[h.Name] = v
		for _, g := range h.Groups {
			if g == "" {
				continue
			}
			if groups[g] == nil {
				groups[g] = &group{Hosts: map[string]struct{}{}}
			}
			groups[g].Hosts[h.Name] = struct{}{}
		}
	}
	all["hosts"] = vars
	if len(groups) > 0 {
		all["children"] = groups
	}
	inv, err := json.MarshalIndent(map[string]any{"all": all}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "inventory.json"), inv, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(known.String()), 0o600)
}

// plainKey returns the private key unencrypted, in a form OpenSSH reads.
func plainKey(key, passphrase string) ([]byte, error) {
	if passphrase == "" {
		k := strings.TrimSpace(key) + "\n"
		if _, err := ssh.ParseRawPrivateKey([]byte(k)); err != nil {
			return nil, fmt.Errorf("the private key can't be read: %w", err)
		}
		return []byte(k), nil
	}
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(key), []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("the private key can't be unlocked: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(raw, "")
	if err != nil {
		return nil, fmt.Errorf("the private key can't be prepared: %w", err)
	}
	return pem.EncodeToMemory(block), nil
}
