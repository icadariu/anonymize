package rules

import (
	"fmt"

	"anonymize/internal/config"
)

type Transformer interface {
	Apply(in string) (string, error)
}

type State struct {
	Cfg   *config.Config
	Stats StatsSink

	// Per-run maps and counters
	EmailLocalMap  map[string]string
	EmailDomainMap map[string]string
	EmailLocalN    int
	EmailDomainN   int

	PublicIPMap map[string]string
	PublicIPN   int

	// Flat hostname mapping (per run)
	HostMap map[string]string
	HostN   int

	// Structured hostname mapping state (per run)
	HostFirstLabelMap map[string]string
	HostFirstLabelN   int
	HostOtherLabelMap map[string]string
	HostOtherLabelN   int

	GenericMap   map[string]map[string]string // ruleName -> original -> replacement
	GenericCount map[string]int               // ruleName -> counter
}

type StatsSink interface {
	Inc(ruleName string, n int)
}

func NewState(cfg *config.Config, stats StatsSink) (*State, error) {
	return &State{
		Cfg:               cfg,
		Stats:             stats,
		EmailLocalMap:     make(map[string]string),
		EmailDomainMap:    make(map[string]string),
		PublicIPMap:       make(map[string]string),
		HostMap:           make(map[string]string),
		HostFirstLabelMap: make(map[string]string),
		HostOtherLabelMap: make(map[string]string),
		GenericMap:        make(map[string]map[string]string),
		GenericCount:      make(map[string]int),
	}, nil
}

func BuildTransformer(rc config.RuleConfig, cfg *config.Config, st *State) (Transformer, error) {
	switch rc.Type {
	case "email_map":
		return NewEmailMap(rc.Name, cfg, st)
	case "ip_map":
		return NewIPMap(rc.Name, cfg, st)
	case "kv_redact":
		return NewKVRedact(rc.Name, cfg, st)
	case "regex_map":
		return NewRegexMap(rc, st)
	case "regex_replace":
		return NewRegexReplace(rc, st)
	case "hostname_map": // NEW
		return NewHostnameMap(rc.Name, st)
	case "url_map": // NEW
		return NewURLMap(rc.Name, st)
	default:
		return nil, fmt.Errorf("unknown rule type: %s", rc.Type)
	}
}
