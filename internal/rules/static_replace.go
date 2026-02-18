package rules

import (
	"fmt"
	"regexp"
	"strings"

	"anonymize/internal/config"
)

type StaticReplace struct {
	name       string
	st         *State
	ignoreCase bool
	pairs      []config.StaticPair

	// Used only when ignoreCase=true
	res []*regexp.Regexp
}

func NewStaticReplace(ruleName string, cfg *config.Config, st *State) (*StaticReplace, error) {
	sr := &StaticReplace{
		name:       ruleName,
		st:         st,
		ignoreCase: cfg.StaticReplace.IgnoreCase,
		pairs:      cfg.StaticReplace.Values,
	}

	if sr.ignoreCase {
		sr.res = make([]*regexp.Regexp, 0, len(sr.pairs))
		for i, p := range sr.pairs {
			from := strings.TrimSpace(p.From)
			if from == "" {
				return nil, fmt.Errorf("static_replace.values[%d].from is empty", i)
			}
			re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(from))
			if err != nil {
				return nil, fmt.Errorf("static_replace.values[%d] compile: %w", i, err)
			}
			sr.res = append(sr.res, re)
		}
	}

	return sr, nil
}

func (t *StaticReplace) Apply(in string) (string, error) {
	out := in
	replaced := 0

	for i, p := range t.pairs {
		from := p.From
		to := p.To

		if from == "" || from == to {
			continue
		}

		if t.ignoreCase {
			re := t.res[i]
			// Count matches for stats
			locs := re.FindAllStringIndex(out, -1)
			if len(locs) == 0 {
				continue
			}
			replaced += len(locs)
			// Use ReplaceAllStringFunc so replacement is literal (no $-expansion surprises)
			out = re.ReplaceAllStringFunc(out, func(_ string) string { return to })
			continue
		}

		c := strings.Count(out, from)
		if c == 0 {
			continue
		}
		replaced += c
		out = strings.ReplaceAll(out, from, to)
	}

	if replaced > 0 {
		t.st.Stats.Inc(t.name, replaced)
	}
	return out, nil
}
