package engine

import (
	"fmt"
	"io"
	"sort"
	"sync"

	"anonymize/internal/config"
	"anonymize/internal/rules"
)

type Engine struct {
	transformers []rules.Transformer
	stats        *Stats
	state        *rules.State
}

type Stats struct {
	mu     sync.Mutex
	counts map[string]int
}

func NewStats() *Stats {
	return &Stats{counts: make(map[string]int)}
}

func (s *Stats) Inc(ruleName string, n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	s.counts[ruleName] += n
	s.mu.Unlock()
}

func (s *Stats) Snapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.counts))
	for k, v := range s.counts {
		out[k] = v
	}
	return out
}

func New(cfg *config.Config) (*Engine, error) {
	st := NewStats()
	state, err := rules.NewState(cfg, st)
	if err != nil {
		return nil, err
	}

	var ts []rules.Transformer

	// Apply static replacements first (if configured)
	if len(cfg.StaticReplace.Values) > 0 {
		sr, err := rules.NewStaticReplace("static_replace", cfg, state)
		if err != nil {
			return nil, err
		}
		ts = append(ts, sr)
	}

	for _, rc := range cfg.Rules {
		if !rc.Enabled {
			continue
		}
		t, err := rules.BuildTransformer(rc, cfg, state)
		if err != nil {
			return nil, fmt.Errorf("build rule %q (%s): %w", rc.Name, rc.Type, err)
		}
		ts = append(ts, t)
	}

	return &Engine{transformers: ts, stats: st, state: state}, nil
}

// Close drops all accumulated original-value mappings and releases the
// transformer slice. Call it (typically via defer) after processing is done
// so the GC can reclaim the memory that held real secrets.
func (e *Engine) Close() {
	e.state.Clear()
	e.transformers = nil
}

func (e *Engine) Apply(line string) (string, error) {
	out := line
	for _, t := range e.transformers {
		var err error
		out, err = t.Apply(out)
		if err != nil {
			return "", err
		}
	}
	return out, nil
}

func (e *Engine) PrintStats(w io.Writer) {
	snap := e.stats.Snapshot()
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s: %d\n", k, snap[k])
	}
}
