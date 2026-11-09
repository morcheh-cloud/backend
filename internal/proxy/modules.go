package proxy

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Extra modules a site can use once they're on the server (each one is
// installed by Driver.ModuleScript): a web application firewall and image
// resizing. Countries on port forwards use the third one (stream-geo).

// Modules are the names ModuleScript takes.
const (
	ModuleBrotli      = "brotli"
	ModuleWAF         = "waf"
	ModuleImageFilter = "image-filter"
	ModuleStreamGeo   = "stream-geo"
)

// Modules lists every module, for the API's enum.
var Modules = []string{ModuleBrotli, ModuleWAF, ModuleImageFilter, ModuleStreamGeo}

// WAF is a web application firewall in front of the site: ModSecurity with
// the OWASP Core Rule Set (proxy, static, storage).
type WAF struct {
	// Mode: "" = off, detect = only log what would be refused, block =
	// refuse it with 403.
	Mode string `json:"mode,omitempty" enum:",detect,block" doc:"Empty = off; detect = only log what it would refuse; block = refuse it (403)"`
	// Paranoia is the Core Rule Set's paranoia level: higher catches more
	// attacks and more innocent requests too.
	Paranoia int `json:"paranoia,omitempty" minimum:"0" maximum:"4" doc:"Paranoia level 1-4; 0 = 1"`
	// Threshold is the anomaly score a request needs to be refused: lower is
	// stricter.
	Threshold int `json:"threshold,omitempty" minimum:"0" maximum:"100" doc:"Anomaly score that refuses a request; 0 = 5 (the rule set's default)"`
	// SkipPaths are path prefixes the firewall leaves alone (an admin area
	// that trips rules, an upload endpoint).
	SkipPaths []string `json:"skip_paths,omitempty" maxItems:"50" doc:"Path prefixes the firewall doesn't check, like /api/upload"`
	// SkipRules are rule ids turned off for this site (false alarms).
	SkipRules []int `json:"skip_rules,omitempty" maxItems:"200" doc:"Rule ids turned off for this site, like 942100"`
}

// On says whether the firewall checks the site.
func (w WAF) On() bool { return w.Mode != "" }

// Images resizes pictures on the fly: an image asked for with ?w= and/or
// ?h= comes back at that size (proxy, static, storage).
type Images struct {
	Enabled bool `json:"enabled,omitempty" doc:"Resize jpg, png, gif and webp images asked for with ?w= and ?h="`
	// Mode: resize keeps the proportions inside the box; crop fills it.
	Mode string `json:"mode,omitempty" enum:",resize,crop" doc:"resize keeps the proportions; crop fills the exact size. Empty = resize"`
	// Sizes are the widths and heights asked for that are served; anything
	// else gets the original, so nobody can make the server resize to every
	// size there is.
	Sizes     []int `json:"sizes,omitempty" maxItems:"30" doc:"Widths and heights allowed in ?w= and ?h=; empty = 160, 320, 640, 960, 1280, 1920"`
	Quality   int   `json:"quality,omitempty" minimum:"0" maximum:"100" doc:"JPEG and WebP quality; 0 = 80"`
	MaxSizeMB int   `json:"max_size_mb,omitempty" minimum:"0" maximum:"100" doc:"Largest original resized, in MB; 0 = 10"`
}

// DefaultImageSizes are the sizes when none are chosen.
var DefaultImageSizes = []int{160, 320, 640, 960, 1280, 1920}

// SizesOrDefault are the allowed sizes.
func (i Images) SizesOrDefault() []int {
	if len(i.Sizes) == 0 {
		return DefaultImageSizes
	}
	return i.Sizes
}

var wafPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~!$&()*+,=:@%/-]*$`)

func normalizeModules(h HostConfig) HostConfig {
	if !Serves(h.Type) {
		h.WAF, h.Images = WAF{}, Images{}
		return h
	}
	if !h.WAF.On() {
		h.WAF = WAF{}
	} else {
		var paths []string
		for _, p := range h.WAF.SkipPaths {
			if p = strings.TrimSpace(p); p != "" && !slices.Contains(paths, p) {
				paths = append(paths, p)
			}
		}
		h.WAF.SkipPaths = paths
		var rules []int
		for _, r := range h.WAF.SkipRules {
			if !slices.Contains(rules, r) {
				rules = append(rules, r)
			}
		}
		slices.Sort(rules)
		h.WAF.SkipRules = rules
		if h.WAF.Paranoia == 0 {
			h.WAF.Paranoia = 1
		}
		if h.WAF.Threshold == 0 {
			h.WAF.Threshold = 5
		}
	}
	if !h.Images.Enabled {
		h.Images = Images{}
	} else {
		if h.Images.Mode == "" {
			h.Images.Mode = "resize"
		}
		var sizes []int
		for _, s := range h.Images.Sizes {
			if !slices.Contains(sizes, s) {
				sizes = append(sizes, s)
			}
		}
		slices.Sort(sizes)
		h.Images.Sizes = sizes
	}
	return h
}

func validateModules(h HostConfig, add func(field, msg string, v any)) {
	if h.WAF.On() {
		if h.WAF.Mode != "detect" && h.WAF.Mode != "block" {
			add("waf.mode", "Choose detect or block.", h.WAF.Mode)
		}
		if h.WAF.Paranoia < 1 || h.WAF.Paranoia > 4 {
			add("waf.paranoia", "Use a level from 1 to 4.", h.WAF.Paranoia)
		}
		if h.WAF.Threshold < 1 || h.WAF.Threshold > 100 {
			add("waf.threshold", "Use a score from 1 to 100.", h.WAF.Threshold)
		}
		for i, p := range h.WAF.SkipPaths {
			if !wafPathRe.MatchString(p) {
				add(fmt.Sprintf("waf.skip_paths[%d]", i), "A path starting with /, without spaces or quotes.", p)
			}
		}
		for i, r := range h.WAF.SkipRules {
			if r < 1 || r > 99999999 {
				add(fmt.Sprintf("waf.skip_rules[%d]", i), "Not a rule id.", r)
			} else if b := r / 1000; b == 949 || b == 959 || b == 980 {
				// These only add up what the other rules found.
				add(fmt.Sprintf("waf.skip_rules[%d]", i), "This rule adds up the score; turning it off turns the whole firewall off. Turn off the rules that matched instead.", r)
			}
		}
	}
	if h.Images.Enabled {
		if h.Images.Mode != "resize" && h.Images.Mode != "crop" {
			add("images.mode", "Choose resize or crop.", h.Images.Mode)
		}
		for i, s := range h.Images.Sizes {
			if s < 16 || s > 4096 {
				add(fmt.Sprintf("images.sizes[%d]", i), "Use a size from 16 to 4096 pixels.", s)
			}
		}
		if h.Images.Quality != 0 && (h.Images.Quality < 1 || h.Images.Quality > 100) {
			add("images.quality", "Use a quality from 1 to 100.", h.Images.Quality)
		}
		if h.Images.MaxSizeMB < 0 || h.Images.MaxSizeMB > 100 {
			add("images.max_size_mb", "Use 1 to 100 MB.", h.Images.MaxSizeMB)
		}
	}
}

// WAFEvent is one request the firewall flagged.
type WAFEvent struct {
	Time   string     `json:"time" doc:"When, as the server logged it"`
	IP     string     `json:"ip"`
	Method string     `json:"method"`
	URI    string     `json:"uri" doc:"Path and query string"`
	Status int        `json:"status" doc:"What the visitor got (403 = refused by the firewall)"`
	ID     string     `json:"id" doc:"The request's unique id (the access log's request id, for requests since the site was saved with the firewall on)"`
	// Blocked: the firewall refused the request (the site was on Block);
	// otherwise it only wrote it down.
	Blocked bool `json:"blocked" doc:"The firewall refused it; false = only logged (Log only, or under the score)"`
	Rules  []WAFMatch `json:"rules"`
}

// WAFMatch is a rule that matched a request.
type WAFMatch struct {
	ID       string `json:"id"`
	Message  string `json:"message"`
	Data     string `json:"data,omitempty" doc:"What matched, and where"`
	Severity string `json:"severity,omitempty"`
}
