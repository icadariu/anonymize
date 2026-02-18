package rules

import (
	"regexp"
	"strings"

	"anonymize/internal/config"
)

type KVRedact struct {
	name string
	st   *State

	// JSON-like:
	//  - "key": "value"
	//  - 'key': 'value'
	// RE2 has no backrefs; use alternation.
	// Groups:
	//   double-quote branch: 1=key, 2=value
	//   single-quote branch: 3=key, 4=value
	reJSON *regexp.Regexp

	// Loose:
	//  - key=value
	//  - key: value
	//  - key = "value"
	//  - key:'value'
	// Groups:
	//   1=key
	//   2=sep (:=) with surrounding whitespace
	//   3=quote (optional)
	//   4=value
	//   5=quote (optional)
	reLoose *regexp.Regexp

	keysLower map[string]struct{}
}

func NewKVRedact(ruleName string, cfg *config.Config, st *State) (*KVRedact, error) {
	keysLower := make(map[string]struct{}, len(cfg.Keys.RedactValue))
	for _, k := range cfg.Keys.RedactValue {
		kk := strings.ToLower(strings.TrimSpace(k))
		if kk == "" {
			continue
		}
		keysLower[kk] = struct{}{}
	}

	reJSON := regexp.MustCompile(`(?i)(?:"([A-Za-z0-9_.-]+)"\s*:\s*"([^"\n\r]*)")|(?:'([A-Za-z0-9_.-]+)'\s*:\s*'([^'\n\r]*)')`)
	reLoose := regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]+)(\s*[:=]\s*)(["']?)([^\s,"'}\]]+)(["']?)`)

	return &KVRedact{
		name:      ruleName,
		st:        st,
		reJSON:    reJSON,
		reLoose:   reLoose,
		keysLower: keysLower,
	}, nil
}

func (t *KVRedact) Apply(in string) (string, error) {
	replaced := 0

	out := t.reJSON.ReplaceAllStringFunc(in, func(m string) string {
		sub := t.reJSON.FindStringSubmatch(m)
		if len(sub) < 5 {
			return m
		}

		rawKey := ""
		quote := `"`
		if sub[1] != "" {
			rawKey = sub[1]
			quote = `"`
		} else if sub[3] != "" {
			rawKey = sub[3]
			quote = `'`
		} else {
			return m
		}

		key := strings.ToLower(rawKey)
		if _, ok := t.keysLower[key]; !ok {
			return m
		}

		replaced++
		return quote + rawKey + quote + ":" + quote + "[redacted]" + quote
	})

	out2 := t.reLoose.ReplaceAllStringFunc(out, func(m string) string {
		sub := t.reLoose.FindStringSubmatch(m)
		if len(sub) != 6 {
			return m
		}

		rawKey := sub[1]
		key := strings.ToLower(rawKey)
		if _, ok := t.keysLower[key]; !ok {
			return m
		}

		replaced++
		q := sub[3]
		if q != `"` && q != `'` {
			q = ""
		}

		return rawKey + sub[2] + q + "[redacted]" + q
	})

	if replaced > 0 {
		t.st.Stats.Inc(t.name, replaced)
	}
	return out2, nil
}

