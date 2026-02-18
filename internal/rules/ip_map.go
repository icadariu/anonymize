package rules

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"anonymize/internal/config"
)

type IPMap struct {
	name       string
	cfg        *config.Config
	st         *State
	re         *regexp.Regexp
	keepPrefix []netip.Prefix
}

func NewIPMap(ruleName string, cfg *config.Config, st *State) (*IPMap, error) {
	// Match candidate IPv4 with optional /cidr.
	re := regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?\b`)

	keep, err := parseKeepCIDRs(cfg.IP.KeepCIDRs)
	if err != nil {
		return nil, err
	}

	return &IPMap{
		name:       ruleName,
		cfg:        cfg,
		st:         st,
		re:         re,
		keepPrefix: keep,
	}, nil
}

func parseKeepCIDRs(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("invalid ip.keep_cidrs entry %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func (t *IPMap) Apply(in string) (string, error) {
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
		ipStart, ipEnd := m[2], m[3]
		cidrStart, cidrEnd := m[4], m[5] // may be -1,-1

		ipStr := in[ipStart:ipEnd]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		ip = ip.To4()
		if ip == nil {
			continue
		}
		// validate octets explicitly (net.ParseIP is permissive with some forms)
		if !validIPv4String(ipStr) {
			continue
		}

		// CIDR parsing (optional)
		cidrSuffix := ""
		if cidrStart != -1 && cidrEnd != -1 && t.cfg.IP.PreserveCIDR {
			cidrText := in[cidrStart:cidrEnd]
			n, err := strconv.Atoi(cidrText)
			if err == nil && n >= 0 && n <= 32 {
				cidrSuffix = "/" + cidrText
			}
		}

		// Determine if we should keep unchanged
		if t.shouldKeep(ipStr) {
			continue
		}

		mapped := t.mapPublic(ipStr) + cidrSuffix

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

func validIPv4String(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func (t *IPMap) shouldKeep(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return true
	}
	for _, p := range t.keepPrefix {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (t *IPMap) mapPublic(ipStr string) string {
	// Base mapping: IP alone is the key, CIDR suffix does NOT affect mapping.
	if v, ok := t.st.PublicIPMap[ipStr]; ok {
		return v
	}
	t.st.PublicIPN++
	n := t.st.PublicIPN

	base := t.cfg.IP.PublicBase
	step := t.cfg.IP.PublicStep
	oct := base + (n-1)*step
	// wrap protection (keep within 1..255); if overflow, fall back to modulo but avoid 0/255.
	if oct < 1 {
		oct = 1
	}
	if oct > 254 {
		// simple wrap; predictable and still stable per-run
		oct = 1 + ((oct - 1) % 254)
	}
	mapped := fmt.Sprintf("%d.%d.%d.%d", oct, oct, oct, oct)
	t.st.PublicIPMap[ipStr] = mapped
	return mapped
}
