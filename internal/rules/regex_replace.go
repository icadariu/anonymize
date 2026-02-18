package rules

import (
	"fmt"
	"regexp"

	"anonymize/internal/config"
)

type RegexReplace struct {
	name        string
	re          *regexp.Regexp
	replacement string
	st          *State
}

func NewRegexReplace(rc config.RuleConfig, st *State) (*RegexReplace, error) {
	re, err := regexp.Compile(rc.Pattern)
	if err != nil {
		return nil, err
	}
	if rc.Replacement == "" {
		return nil, fmt.Errorf("replacement is required for regex_replace")
	}
	return &RegexReplace{
		name:        rc.Name,
		re:          re,
		replacement: rc.Replacement,
		st:          st,
	}, nil
}

func (t *RegexReplace) Apply(in string) (string, error) {
	if !t.re.MatchString(in) {
		return in, nil
	}
	// Count occurrences to report stats.
	n := len(t.re.FindAllStringIndex(in, -1))
	out := t.re.ReplaceAllString(in, t.replacement)
	t.st.Stats.Inc(t.name, n)
	return out, nil
}
