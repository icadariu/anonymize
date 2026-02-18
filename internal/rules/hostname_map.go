package rules

import (
	"fmt"
	"regexp"
	"strings"
)

type HostnameMap struct {
	name string
	st   *State
	re   *regexp.Regexp
}

func NewHostnameMap(ruleName string, st *State) (*HostnameMap, error) {
	// Match dotted tokens broadly, then apply strict validation in code.
	re := regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b`)
	return &HostnameMap{name: ruleName, st: st, re: re}, nil
}

func (t *HostnameMap) Apply(in string) (string, error) {
	idxs := t.re.FindAllStringSubmatchIndex(in, -1)
	if len(idxs) == 0 {
		return in, nil
	}

	var b strings.Builder
	b.Grow(len(in))

	last := 0
	replaced := 0

	for _, m := range idxs {
		fullStart, fullEnd := m[0], m[1]
		hostStart, hostEnd := m[2], m[3]

		token := in[hostStart:hostEnd]

		// Avoid mapping dotted numbers like 0.000803442
		if !containsAlpha(token) {
			continue
		}

		// Avoid mapping IPv4-like tokens
		if looksLikeIPv4Token(token) {
			continue
		}

		// NEW: Only treat as hostname if it looks like a real FQDN:
		// - has at least one dot (already true by regex)
		// - TLD (last label) is letters-only and len >= 2 (e.g. com, ro)
		// This prevents mapping things like http.log.access.log0
		if !looksLikeFQDN(token) {
			continue
		}

		tokenLower := strings.ToLower(token)
		if hasDeniedPrefix(t.st.Cfg.HostnameMap.DenyPrefixes, tokenLower) {
			continue
		}

		mapped := t.mapHost(token)

		b.WriteString(in[last:fullStart])
		b.WriteString(mapped)
		last = fullEnd
		replaced++
	}

	if replaced == 0 {
		return in, nil
	}

	b.WriteString(in[last:])
	t.st.Stats.Inc(t.name, replaced)
	return b.String(), nil
}

func (t *HostnameMap) mapHost(host string) string {
	key := strings.ToLower(host)
	if v, ok := t.st.HostMap[key]; ok {
		return v
	}
	t.st.HostN++
	n := t.st.HostN
	mapped := fmt.Sprintf("host%d.example%d.com", n, n)
	t.st.HostMap[key] = mapped
	return mapped
}

func looksLikeIPv4Token(s string) bool {
	for _, r := range s {
		if (r >= '0' && r <= '9') || r == '.' {
			continue
		}
		return false
	}
	return strings.Count(s, ".") == 3
}

func containsAlpha(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func looksLikeFQDN(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	tld := parts[len(parts)-1]
	if len(tld) < 2 || len(tld) > 24 {
		return false
	}
	for _, r := range tld {
		if r < 'A' || (r > 'Z' && r < 'a') || r > 'z' {
			return false
		}
	}
	return true
}

func hasDeniedPrefix(prefixes []string, tokenLower string) bool {
	for _, p := range prefixes {
		pp := strings.ToLower(strings.TrimSpace(p))
		if pp != "" && strings.HasPrefix(tokenLower, pp) {
			return true
		}
	}
	return false
}
