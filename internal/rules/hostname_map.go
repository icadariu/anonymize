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
	return mapHostname(host, t.st)
}

func mapHostname(host string, st *State) string {
	key := strings.ToLower(strings.TrimSuffix(host, "."))
	if key == "" {
		return host
	}
	if v, ok := st.HostMap[key]; ok {
		return v
	}

	mode := strings.ToLower(strings.TrimSpace(st.Cfg.HostnameMap.Mode))
	if mode == "structured" {
		mapped := mapHostnameStructured(key, st)
		st.HostMap[key] = mapped
		return mapped
	}

	// flat mode
	st.HostN++
	n := st.HostN
	mapped := fmt.Sprintf("host%d.example%d.com", n, n)
	st.HostMap[key] = mapped
	return mapped
}

func mapHostnameStructured(hostLower string, st *State) string {
	parts := strings.Split(hostLower, ".")
	if len(parts) < 2 {
		return hostLower
	}

	rootLabels := structuredRootLabels(parts, st)
	if len(rootLabels) < 2 {
		rootLabels = []string{"example", "com"}
	}

	// Preserve overall depth: output has the same label count as input.
	prefixCount := len(parts) - len(rootLabels)
	if prefixCount < 0 {
		prefixCount = 0
	}

	out := make([]string, 0, prefixCount+len(rootLabels))
	for i := 0; i < prefixCount; i++ {
		label := parts[i]
		if i == 0 {
			out = append(out, mapFirstLabel(label, st))
		} else {
			out = append(out, mapOtherLabel(label, st))
		}
	}
	out = append(out, rootLabels...)
	return strings.Join(out, ".")
}

func structuredRootLabels(originalLabels []string, st *State) []string {
	root := strings.ToLower(strings.TrimSpace(st.Cfg.HostnameMap.RootDomain))
	rootParts := strings.Split(root, ".")
	if len(rootParts) < 2 {
		return []string{"example", "com"}
	}

	if st.Cfg.HostnameMap.PreserveTLD {
		tld := originalLabels[len(originalLabels)-1]
		// Only preserve the TLD if it is purely alphabetic.
		for _, r := range tld {
			if r < 'a' || r > 'z' {
				return rootParts
			}
		}
		return []string{rootParts[0], tld}
	}

	return rootParts
}

func mapFirstLabel(label string, st *State) string {
	if v, ok := st.HostFirstLabelMap[label]; ok {
		return v
	}
	st.HostFirstLabelN++
	v := st.Cfg.HostnameMap.HostLabelPrefix + itoa(st.HostFirstLabelN)
	st.HostFirstLabelMap[label] = v
	return v
}

func mapOtherLabel(label string, st *State) string {
	if v, ok := st.HostOtherLabelMap[label]; ok {
		return v
	}
	st.HostOtherLabelN++
	v := st.Cfg.HostnameMap.SubdomainLabelPrefix + itoa(st.HostOtherLabelN)
	st.HostOtherLabelMap[label] = v
	return v
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [32]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + (n % 10))
		n /= 10
	}
	return string(b[i:])
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

// hasDeniedPrefix returns true only when the first label of the hostname looks
// like an already-anonymized token: the label must match <prefix><digits>, e.g.
// "h1", "s3", "host2".  This avoids blocking real hostnames that merely start
// with the same letter (e.g. "sad.corp.com" is NOT blocked by prefix "s").
func hasDeniedPrefix(prefixes []string, tokenLower string) bool {
	// Extract the first label (everything before the first dot).
	firstLabel := tokenLower
	if idx := strings.IndexByte(tokenLower, '.'); idx >= 0 {
		firstLabel = tokenLower[:idx]
	}
	for _, p := range prefixes {
		pp := strings.ToLower(strings.TrimSpace(p))
		if pp == "" || !strings.HasPrefix(firstLabel, pp) {
			continue
		}
		// The remainder after the prefix must be all digits (e.g. "1", "23").
		rest := firstLabel[len(pp):]
		if len(rest) > 0 && isAllDigits(rest) {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
