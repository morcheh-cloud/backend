// Package packages reads and changes a server's system packages with
// whatever package manager it has (apt, dnf, yum, zypper, apk, pacman). It
// builds shell scripts and parses what they print; the api package runs them.
package packages

import (
	"regexp"
	"slices"
	"strings"
	"time"
)

// Managers Morcheh knows.
const (
	APT    = "apt"
	DNF    = "dnf"
	YUM    = "yum"
	Zypper = "zypper"
	APK    = "apk"
	Pacman = "pacman"
	None   = "none"
)

// MaxNames is how many packages one action, mark or preview takes.
const MaxNames = 200

// MaxPackages is how many installed packages an overview keeps.
const MaxPackages = 20000

// MaxFiles is how many of a package's files the details list.
const MaxFiles = 5000

var (
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:@-]{0,127}$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$`)
	queryRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._ -]{0,63}$`)
)

// ValidName says whether s can be a package name (apt's name:arch too).
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ValidVersion says whether s can be a package version.
func ValidVersion(s string) bool { return versionRe.MatchString(s) }

// ValidQuery says whether s can be searched for.
func ValidQuery(s string) bool { return queryRe.MatchString(strings.TrimSpace(s)) }

// Package is one installed package.
type InstalledPackage struct {
	Name      string     `json:"name" example:"nginx"`
	Version   string     `json:"version" example:"1.24.0-2ubuntu7"`
	Arch      string     `json:"arch,omitempty" example:"amd64"`
	Summary   string     `json:"summary,omitempty" example:"small, powerful, scalable web/proxy server"`
	Section   string     `json:"section,omitempty" doc:"The distribution's category for it" example:"httpd"`
	Size      int64      `json:"size" doc:"Installed size in bytes; 0 when unknown"`
	ChangedAt *time.Time `json:"changed_at,omitempty" doc:"When it was installed or last upgraded, when the manager keeps that"`
	State     string     `json:"state" enum:"installed,config-files,broken" doc:"config-files: removed, but its configuration files are still there (apt); broken: half installed or half removed"`
	Auto      bool       `json:"auto" doc:"Installed as a dependency of another package, not by hand"`
	Held      bool       `json:"held" doc:"Held at its version: upgrades leave it alone"`
	Removable bool       `json:"removable" doc:"No longer needed by anything: autoremove would take it"`
	Latest    string     `json:"latest,omitempty" doc:"A newer version the repositories have" example:"1.24.0-2ubuntu7.1"`
	Security  bool       `json:"security,omitempty" doc:"That update fixes a security problem"`
	Repo      string     `json:"repo,omitempty" doc:"Where the update comes from" example:"noble-updates"`
}

// PackageCapabilities say what this server's package manager can do from here.
type PackageCapabilities struct {
	Hold        bool `json:"hold" doc:"Hold a package at its version"`
	Mark        bool `json:"mark" doc:"Mark a package as installed by hand or as a dependency"`
	Autoremove  bool `json:"autoremove" doc:"Remove packages nothing needs any more"`
	Purge       bool `json:"purge" doc:"Remove with the configuration files"`
	Versions    bool `json:"versions" doc:"Install a chosen version (also an older one)"`
	Security    bool `json:"security" doc:"Tell security updates apart, and install only those"`
	History     bool `json:"history" doc:"Read what was installed, upgraded and removed before"`
	Reinstall   bool `json:"reinstall"`
	AutoUpdates bool `json:"auto_updates" doc:"Turn automatic updates on or off from here"`
	Preview     bool `json:"preview" doc:"Show what an action would change before it runs"`
}

// PackageAutoUpdates is whether the server installs updates by itself.
type PackageAutoUpdates struct {
	Supported bool   `json:"supported" doc:"Morcheh can turn them on or off on this server"`
	Enabled   bool   `json:"enabled"`
	Tool      string `json:"tool,omitempty" example:"unattended-upgrades"`
	Missing   string `json:"missing,omitempty" doc:"The package to install before they can be turned on" example:"unattended-upgrades"`
	Detail    string `json:"detail,omitempty" doc:"What exactly runs, in a few words"`
}

// Overview is a server's packages and updates.
type PackagesOverview struct {
	Manager             string              `json:"manager" enum:"apt,dnf,yum,zypper,apk,pacman,none"`
	Access              string              `json:"access" enum:"root,sudo,user" doc:"How Morcheh acts on the server. Changing packages needs root or sudo"`
	RefreshedAt         *time.Time          `json:"refreshed_at,omitempty" doc:"When the package lists were last downloaded; updates are only as fresh as these"`
	RebootRequired      bool                `json:"reboot_required" doc:"An update (a new kernel, a core library) needs a restart to take effect"`
	RebootPackages      []string            `json:"reboot_packages" doc:"Which packages asked for it, when the server says"`
	CacheBytes          int64               `json:"cache_bytes" doc:"Downloaded package files kept in the cache; -1 when unknown"`
	AutoUpdates         PackageAutoUpdates  `json:"auto_updates"`
	PackageCapabilities PackageCapabilities `json:"capabilities"`
	Packages            []InstalledPackage  `json:"packages"`
	Updates             int                 `json:"updates" doc:"Installed packages with a newer version"`
	SecurityCount       int                 `json:"security_updates" doc:"Of those, the security updates"`
	Removable           int                 `json:"removable"`
	Truncated           bool                `json:"truncated" doc:"More packages are installed than the list holds"`
	Warnings            []string            `json:"warnings" doc:"What couldn't be read"`
}

// PackageVersion is one version the server could have.
type PackageVersion struct {
	Version   string `json:"version" example:"1.24.0-2ubuntu7.1"`
	Repo      string `json:"repo,omitempty" example:"noble-updates/main"`
	Installed bool   `json:"installed"`
}

// PackageInfo is everything about one package.
type PackageInfo struct {
	Name           string           `json:"name" example:"nginx"`
	Installed      bool             `json:"installed"`
	Version        string           `json:"version,omitempty" doc:"The installed version"`
	Latest         string           `json:"latest,omitempty" doc:"The newest version the repositories offer"`
	Arch           string           `json:"arch,omitempty"`
	Summary        string           `json:"summary,omitempty"`
	Description    string           `json:"description,omitempty"`
	Homepage       string           `json:"homepage,omitempty"`
	Maintainer     string           `json:"maintainer,omitempty"`
	License        string           `json:"license,omitempty"`
	Section        string           `json:"section,omitempty"`
	Repo           string           `json:"repo,omitempty"`
	Size           int64            `json:"size"`
	Depends        []string         `json:"depends" doc:"What it needs (alternatives as a | b)"`
	RequiredBy     []string         `json:"required_by" doc:"Installed packages that need it"`
	Files          []string         `json:"files" doc:"Files it installed (not folders)"`
	FilesTruncated bool             `json:"files_truncated"`
	Versions       []PackageVersion `json:"versions" doc:"Versions the server has or could install, newest first"`
}

// PackageMatch is one search result.
type PackageMatch struct {
	Name      string `json:"name" example:"htop"`
	Summary   string `json:"summary,omitempty"`
	Version   string `json:"version,omitempty" doc:"The version the repositories offer"`
	Installed string `json:"installed,omitempty" doc:"The installed version, if any"`
	Repo      string `json:"repo,omitempty"`
}

// PackageChange is one package an action changed or would change.
type PackageChange struct {
	Name   string `json:"name" example:"openssl"`
	Action string `json:"action" enum:"install,upgrade,downgrade,remove,purge,reinstall"`
	From   string `json:"from,omitempty" doc:"Version before"`
	To     string `json:"to,omitempty" doc:"Version after"`
}

// HistoryEntry is one past run of the package manager.
type PackageHistoryEntry struct {
	At      time.Time       `json:"at"`
	Command string          `json:"command,omitempty" example:"apt-get install -y nginx"`
	User    string          `json:"user,omitempty"`
	Changes []PackageChange `json:"changes"`
	Error   string          `json:"error,omitempty"`
	Partial bool            `json:"partial,omitempty" doc:"Only installs and upgrades are known (read from the package database, not a log)"`
}

// PackagePreview is what an action would do.
type PackagePreview struct {
	Changes  []PackageChange `json:"changes"`
	Problems []string        `json:"problems" doc:"Why it can't be done as asked, in the package manager's words"`
	Deferred []string        `json:"deferred" doc:"Updates apt holds back for now (Ubuntu's phased updates reach servers a few at a time); upgrading them by name installs them anyway"`
	KeptBack []string        `json:"kept_back" doc:"Updates left out because they would add or remove other packages; a full upgrade or upgrading them by name takes them"`
}

// CapabilitiesOf says what each manager can do, before what the server
// itself says (a plugin present, a tool installed) is added.
func CapabilitiesOf(pm string) PackageCapabilities {
	switch pm {
	case APT:
		return PackageCapabilities{Hold: true, Mark: true, Autoremove: true, Purge: true, Versions: true, Security: true, History: true, Reinstall: true, AutoUpdates: true, Preview: true}
	case DNF:
		return PackageCapabilities{Mark: true, Autoremove: true, Versions: true, Security: true, History: true, Reinstall: true, Preview: true}
	case YUM:
		return PackageCapabilities{Versions: true, Security: true, History: true, Reinstall: true, Preview: true}
	case Zypper:
		return PackageCapabilities{Hold: true, Autoremove: true, Versions: true, History: true, Reinstall: true, Preview: true}
	case APK:
		return PackageCapabilities{Reinstall: true, Preview: true}
	case Pacman:
		return PackageCapabilities{Mark: true, Autoremove: true, History: true, Reinstall: true, Preview: true}
	}
	return PackageCapabilities{}
}

func uniq(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}
