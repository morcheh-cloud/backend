package firewall

import (
	"regexp"
	"strings"
)

// Rules set by hand in iptables or nftables are shown but not changed: their
// structure is whatever their author made it, so any edit could break it.

var (
	iptProtoRe  = regexp.MustCompile(`(?:^|\s)-p (\S+)`)
	iptDportRe  = regexp.MustCompile(`--dports? (\S+)`)
	iptSourceRe = regexp.MustCompile(`(?:^|\s)-s (\S+)`)
	iptDestRe   = regexp.MustCompile(`(?:^|\s)-d (\S+)`)
	iptIfaceRe  = regexp.MustCompile(`(?:^|\s)-i (\S+)`)
	iptJumpRe   = regexp.MustCompile(`(?:^|\s)-j (\S+)`)
)

// ParseIptables reads the INPUT chain from `iptables -S` output. Docker's and
// other tools' chains hang off FORWARD or their own, so they aren't listed.
func ParseIptables(out string) []FilterRule {
	var rules []FilterRule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "-A INPUT")
		if !ok {
			continue
		}
		r := readOnly(line)
		r.Protocol = first(iptProtoRe, rest, "any")
		r.Port = first(iptDportRe, rest, "")
		r.From = first(iptSourceRe, rest, "")
		r.To = first(iptDestRe, rest, "")
		r.Interface = first(iptIfaceRe, rest, "")
		switch first(iptJumpRe, rest, "") {
		case "ACCEPT":
			r.Action = "allow"
		case "DROP":
			r.Action = "block"
		case "REJECT":
			r.Action = "reject"
		}
		r.setID()
		rules = append(rules, r)
	}
	return rules
}

// IptablesPolicy returns the INPUT chain's default.
func IptablesPolicy(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "-P INPUT "); ok {
			return map[string]string{"ACCEPT": "allow", "DROP": "deny"}[strings.TrimSpace(rest)]
		}
	}
	return ""
}

func first(re *regexp.Regexp, s, fallback string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return fallback
}

func readOnly(raw string) FilterRule {
	return FilterRule{Action: "other", Direction: "in", Protocol: "any", Family: "both", Raw: raw}
}

var (
	nftChainRe  = regexp.MustCompile(`^chain (\S+) \{`)
	nftHookRe   = regexp.MustCompile(`type filter hook input\b.*policy (\w+)`)
	nftPortRe   = regexp.MustCompile(`\b(tcp|udp) dport (\{[^}]*\}|\S+)`)
	nftSaddrRe  = regexp.MustCompile(`\bip6? saddr (\{[^}]*\}|\S+)`)
	nftIfaceRe  = regexp.MustCompile(`\biifname "?([^" ]+)"?`)
	nftActionRe = regexp.MustCompile(`\b(accept|drop|reject)\b`)
)

// ParseNft reads the rules of the chains hooked to input from `nft list
// ruleset`, and their default policy. firewalld's own table is left out.
func ParseNft(out string) (rules []FilterRule, policy string) {
	inChain, hooked, skip := false, false, false
	var pending []string
	flush := func() {
		if hooked {
			for _, line := range pending {
				rules = append(rules, nftRule(line))
			}
		}
		pending, hooked = nil, false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "table "):
			skip = strings.Contains(line, " firewalld ")
		case skip:
		case nftChainRe.MatchString(line):
			inChain, pending, hooked = true, nil, false
		case !inChain:
		case line == "}":
			flush()
			inChain = false
		case nftHookRe.MatchString(line):
			hooked = true
			policy = map[string]string{"accept": "allow", "drop": "deny"}[nftHookRe.FindStringSubmatch(line)[1]]
		case line != "" && !strings.HasPrefix(line, "type "):
			pending = append(pending, line)
		}
	}
	for i := range rules {
		rules[i].setID()
	}
	return rules, policy
}

func nftRule(line string) FilterRule {
	r := readOnly(line)
	if m := nftPortRe.FindStringSubmatch(line); m != nil {
		r.Protocol = m[1]
		r.Port = strings.NewReplacer("{", "", "}", "", " ", "", "-", ":").Replace(m[2])
	}
	if m := nftSaddrRe.FindStringSubmatch(line); m != nil {
		r.From = strings.NewReplacer("{", "", "}", "").Replace(m[1])
		r.From = strings.TrimSpace(r.From)
	}
	r.Interface = first(nftIfaceRe, line, "")
	switch first(nftActionRe, line, "") {
	case "accept":
		r.Action = "allow"
	case "drop":
		r.Action = "block"
	case "reject":
		r.Action = "reject"
	}
	return r
}

// CustomRules says whether raw iptables or nftables output holds input rules
// of its own, beyond those a managed tool wrote there.
func CustomRules(rules []FilterRule) bool {
	for _, r := range rules {
		if !strings.Contains(r.Raw, "ufw") && !strings.Contains(r.Raw, "f2b") &&
			!strings.Contains(r.Raw, "fail2ban") && !strings.Contains(r.Raw, "IN_public") &&
			!strings.Contains(r.Raw, "jump") {
			return true
		}
	}
	return false
}
