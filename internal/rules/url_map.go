package rules

import (
	"net/url"
	"regexp"
	"strings"
)

type URLMap struct {
	name string
	st   *State
	re   *regexp.Regexp
}

func NewURLMap(ruleName string, st *State) (*URLMap, error) {
	// Match http(s) URLs; keep it simple and robust for logs.
	// We'll trim trailing punctuation after match.
	re := regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
	return &URLMap{name: ruleName, st: st, re: re}, nil
}

func (t *URLMap) Apply(in string) (string, error) {
	idxs := t.re.FindAllStringIndex(in, -1)
	if len(idxs) == 0 {
		return in, nil
	}

	var b strings.Builder
	b.Grow(len(in))

	last := 0
	replaced := 0

	for _, m := range idxs {
		start, end := m[0], m[1]
		raw := in[start:end]

		trimmed, trail := trimURLTrailingPunct(raw)

		u, err := url.Parse(trimmed)
		if err != nil || u.Host == "" {
			continue
		}

		host := u.Hostname()
		port := u.Port()

		// Reuse the same hostname mapping as hostname_map
		mappedHost := mapHostname(host, t.st)
		if port != "" {
			u.Host = mappedHost + ":" + port
		} else {
			u.Host = mappedHost
		}

		outURL := u.String() + trail

		b.WriteString(in[last:start])
		b.WriteString(outURL)
		last = end
		replaced++
	}

	if replaced == 0 {
		return in, nil
	}

	b.WriteString(in[last:])
	t.st.Stats.Inc(t.name, replaced)
	return b.String(), nil
}

func trimURLTrailingPunct(s string) (string, string) {
	// Common log punctuation after URLs: ), ], }, ., ,, ;
	i := len(s)
	for i > 0 {
		c := s[i-1]
		if c == ')' || c == ']' || c == '}' || c == '.' || c == ',' || c == ';' {
			i--
			continue
		}
		break
	}
	return s[:i], s[i:]
}
