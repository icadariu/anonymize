package rules

import (
	"fmt"
	"regexp"
	"strings"

	"anonymize/internal/config"
)

type RegexMap struct {
	name              string
	re                *regexp.Regexp
	group             int
	replacementPrefix string
	st                *State
}

func NewRegexMap(rc config.RuleConfig, st *State) (*RegexMap, error) {
	re, err := regexp.Compile(rc.Pattern)
	if err != nil {
		return nil, err
	}
	if rc.ReplacementPrefix == "" {
		return nil, fmt.Errorf("replacement_prefix is required for regex_map")
	}
	return &RegexMap{
		name:              rc.Name,
		re:                re,
		group:             rc.Group,
		replacementPrefix: rc.ReplacementPrefix,
		st:                st,
	}, nil
}

func (t *RegexMap) Apply(in string) (string, error) {
	// Submatch indices allow replacing only a capture group.
	idxs := t.re.FindAllStringSubmatchIndex(in, -1)
	if len(idxs) == 0 {
		return in, nil
	}

	// Ensure map storage for this rule
	if _, ok := t.st.GenericMap[t.name]; !ok {
		t.st.GenericMap[t.name] = make(map[string]string)
	}

	var b strings.Builder
	b.Grow(len(in))

	last := 0
	replaced := 0

	for _, m := range idxs {
		fullStart, fullEnd := m[0], m[1]

		// Decide which span we replace: whole match or a specific group
		repStart, repEnd := fullStart, fullEnd
		if t.group > 0 {
			gi := t.group * 2
			if gi+1 < len(m) && m[gi] != -1 && m[gi+1] != -1 {
				repStart, repEnd = m[gi], m[gi+1]
			}
		}

		original := in[repStart:repEnd]
		mapped := t.mapValue(original)

		b.WriteString(in[last:repStart])
		b.WriteString(mapped)
		last = repEnd
		replaced++

		// If we replaced only a subgroup, we still need to include the remainder of the full match.
		// But because we splice by repStart/repEnd, and the next iteration continues from last,
		// this naturally preserves surrounding text.
		_ = fullStart
		_ = fullEnd
	}

	b.WriteString(in[last:])
	t.st.Stats.Inc(t.name, replaced)
	return b.String(), nil
}

func (t *RegexMap) mapValue(original string) string {
	if v, ok := t.st.GenericMap[t.name][original]; ok {
		return v
	}
	t.st.GenericCount[t.name]++
	n := t.st.GenericCount[t.name]
	v := fmt.Sprintf("%s%d", t.replacementPrefix, n)
	t.st.GenericMap[t.name][original] = v
	return v
}
