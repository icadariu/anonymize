package rules

import (
	"fmt"
	"regexp"
	"strings"

	"anonymize/internal/config"
)

type EmailMap struct {
	name string
	cfg  *config.Config
	st   *State
	re   *regexp.Regexp
}

func NewEmailMap(ruleName string, cfg *config.Config, st *State) (*EmailMap, error) {
	// Simple, pragmatic email matcher.
	// Group 0 = full email, group 1 = local, group 2 = domain
	re := regexp.MustCompile(`\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b`)
	return &EmailMap{name: ruleName, cfg: cfg, st: st, re: re}, nil
}

func (t *EmailMap) Apply(in string) (string, error) {
	matches := t.re.FindAllStringSubmatchIndex(in, -1)
	if len(matches) == 0 {
		return in, nil
	}

	// Build output by splicing.
	var b strings.Builder
	b.Grow(len(in))

	last := 0
	replaced := 0

	for _, m := range matches {
		fullStart, fullEnd := m[0], m[1]
		localStart, localEnd := m[2], m[3]
		domStart, domEnd := m[4], m[5]

		local := in[localStart:localEnd]
		dom := in[domStart:domEnd]

		newLocal := t.mapLocal(local)
		newDom := t.mapDomain(dom)

		b.WriteString(in[last:fullStart])
		b.WriteString(newLocal)
		b.WriteByte('@')
		b.WriteString(newDom)
		last = fullEnd
		replaced++
	}

	b.WriteString(in[last:])
	t.st.Stats.Inc(t.name, replaced)
	return b.String(), nil
}

func (t *EmailMap) mapLocal(local string) string {
	if v, ok := t.st.EmailLocalMap[local]; ok {
		return v
	}
	t.st.EmailLocalN++
	idx := t.st.EmailLocalN
	base := t.cfg.Email.UserPrefix
	var out string
	if idx == 1 {
		out = base
	} else {
		out = fmt.Sprintf("%s%d", base, idx)
	}
	t.st.EmailLocalMap[local] = out
	return out
}

func (t *EmailMap) mapDomain(domain string) string {
	// normalize domains for mapping stability
	d := strings.ToLower(domain)
	if v, ok := t.st.EmailDomainMap[d]; ok {
		return v
	}
	t.st.EmailDomainN++
	idx := t.cfg.Email.DomainStartIndex + (t.st.EmailDomainN - 1)
	out := fmt.Sprintf("%s%d.%s", t.cfg.Email.DomainPrefix, idx, t.cfg.Email.DomainTLD)
	t.st.EmailDomainMap[d] = out
	return out
}
