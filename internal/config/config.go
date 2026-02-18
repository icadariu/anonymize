package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type StaticReplaceConfig struct {
	IgnoreCase bool         `toml:"ignore_case"`
	Values     []StaticPair `toml:"values"`
}

type StaticPair struct {
	From string `toml:"from"`
	To   string `toml:"to"`
}

type Config struct {
	Version int `toml:"version"`

	Engine        EngineConfig        `toml:"engine"`
	StaticReplace StaticReplaceConfig `toml:"static_replace"`
	HostnameMap   HostnameMapConfig   `toml:"hostname_map"` // <-- add this line

	IP    IPConfig    `toml:"ip"`
	Email EmailConfig `toml:"email"`
	Keys  KeysConfig  `toml:"keys"`

	Rules []RuleConfig `toml:"rules"`
}

type EngineConfig struct {
	Stats bool `toml:"stats"`
}

type IPConfig struct {
	PublicBase   int      `toml:"public_base"`
	PublicStep   int      `toml:"public_step"`
	PreserveCIDR bool     `toml:"preserve_cidr"`
	KeepCIDRs    []string `toml:"keep_cidrs"`
}

type EmailConfig struct {
	UserPrefix       string `toml:"user_prefix"`
	DomainPrefix     string `toml:"domain_prefix"`
	DomainStartIndex int    `toml:"domain_start_index"`
	DomainTLD        string `toml:"domain_tld"`
}

type KeysConfig struct {
	RedactValue []string `toml:"redact_value"`
}

type RuleConfig struct {
	Name              string `toml:"name"`
	Type              string `toml:"type"`
	Enabled           bool   `toml:"enabled"`
	Pattern           string `toml:"pattern"`
	Group             int    `toml:"group"`
	Replacement       string `toml:"replacement"`
	ReplacementPrefix string `toml:"replacement_prefix"`
}

type HostnameMapConfig struct {
	DenyPrefixes []string `toml:"deny_prefixes"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if _, err := toml.Decode(string(b), &cfg); err != nil {
		return nil, fmt.Errorf("parse toml: %w", err)
	}

	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// defaultKeepCIDRs is the baseline list of IANA special-purpose IPv4 ranges
// that should never be anonymized. Applied when the user omits keep_cidrs entirely.
var defaultKeepCIDRs = []string{
	"0.0.0.0/8",         // "This" network (RFC 1122)
	"10.0.0.0/8",        // RFC 1918 private
	"100.64.0.0/10",     // Shared Address Space / CGNAT (RFC 6598)
	"127.0.0.0/8",       // Loopback (RFC 1122)
	"169.254.0.0/16",    // Link-local (RFC 3927)
	"172.16.0.0/12",     // RFC 1918 private
	"192.0.0.0/24",      // IETF Protocol Assignments (RFC 6890)
	"192.0.2.0/24",      // TEST-NET-1 / documentation (RFC 5737)
	"192.88.99.0/24",    // 6to4 Relay Anycast (RFC 3068, deprecated RFC 7526)
	"192.168.0.0/16",    // RFC 1918 private
	"198.18.0.0/15",     // Benchmarking (RFC 2544)
	"198.51.100.0/24",   // TEST-NET-2 / documentation (RFC 5737)
	"203.0.113.0/24",    // TEST-NET-3 / documentation (RFC 5737)
	"224.0.0.0/4",       // Multicast (RFC 1112)
	"240.0.0.0/4",       // Reserved / future use (RFC 1112)
	"255.255.255.255/32", // Limited broadcast (RFC 919)
}

func applyDefaults(cfg *Config) {
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	if cfg.IP.PublicBase == 0 {
		cfg.IP.PublicBase = 111
	}
	if cfg.IP.PublicStep == 0 {
		cfg.IP.PublicStep = 11
	}
	if len(cfg.IP.KeepCIDRs) == 0 {
		cfg.IP.KeepCIDRs = defaultKeepCIDRs
	}

	if cfg.Email.UserPrefix == "" {
		cfg.Email.UserPrefix = "user"
	}
	if cfg.Email.DomainPrefix == "" {
		cfg.Email.DomainPrefix = "example"
	}
	if cfg.Email.DomainStartIndex == 0 {
		cfg.Email.DomainStartIndex = 1
	}
	if cfg.Email.DomainTLD == "" {
		cfg.Email.DomainTLD = "com"
	}
}

func validate(cfg *Config) error {
	if cfg.Version != 1 {
		return fmt.Errorf("unsupported version: %d", cfg.Version)
	}
	if cfg.IP.PublicBase < 1 || cfg.IP.PublicBase > 255 {
		return fmt.Errorf("ip.public_base must be 1..255")
	}
	if cfg.IP.PublicStep < 0 || cfg.IP.PublicStep > 255 {
		return fmt.Errorf("ip.public_step must be 0..255")
	}
	if cfg.Email.DomainStartIndex < 0 {
		return fmt.Errorf("email.domain_start_index must be >= 0")
	}

	for i, p := range cfg.StaticReplace.Values {
		if strings.TrimSpace(p.From) == "" {
			return fmt.Errorf("static_replace.values[%d].from is required", i)
		}
	}

	for i, r := range cfg.Rules {
		if r.Name == "" {
			return fmt.Errorf("rules[%d].name is required", i)
		}
		if r.Type == "" {
			return fmt.Errorf("rules[%d].type is required", i)
		}
	}
	return nil
}
