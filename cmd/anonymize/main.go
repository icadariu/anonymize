package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"anonymize/internal/config"
	"anonymize/internal/engine"
)

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".anonymize.toml"
	}
	return filepath.Join(home, ".anonymize.toml")
}

func main() {
	var cfgPath string
	var statsOverride bool

	flag.StringVar(&cfgPath, "config", "", "Path to config file (default: ~/.anonymize.toml)")
	flag.BoolVar(&statsOverride, "stats", false, "Print per-rule stats to stderr (overrides config.engine.stats)")
	flag.Parse()

	usingDefault := strings.TrimSpace(cfgPath) == ""
	if usingDefault {
		cfgPath = defaultConfigPath()
	}

	if usingDefault {
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "No config file found at %s\n\n", cfgPath)
			fmt.Fprintf(os.Stderr, "To get started, copy the example config from the repo:\n\n")
			fmt.Fprintf(os.Stderr, "  cp anonymize-example.toml ~/.anonymize.toml\n\n")
			fmt.Fprintf(os.Stderr, "Edit ~/.anonymize.toml to fit your environment, then run again.\n")
			fmt.Fprintf(os.Stderr, "Or specify a config explicitly:\n\n")
			fmt.Fprintf(os.Stderr, "  anonymize --config /path/to/your/config.toml\n\n")
			os.Exit(1)
		}
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	if statsOverride {
		cfg.Engine.Stats = true
	}

	eng, err := engine.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "engine error: %v\n", err)
		os.Exit(1)
	}
	// Drop all accumulated original-value maps and nudge the GC to collect
	// them before the process exits, reducing the window during which real
	// secrets are reachable in memory.
	defer func() {
		eng.Close()
		runtime.GC()
	}()

	if err := run(os.Stdin, os.Stdout, eng); err != nil {
		fmt.Fprintf(os.Stderr, "run error: %v\n", err)
		os.Exit(1)
	}

	if cfg.Engine.Stats {
		eng.PrintStats(os.Stderr)
	}
}

func run(r io.Reader, w io.Writer, eng *engine.Engine) error {
	scanner := bufio.NewScanner(r)
	// logs/JSON lines can be large; bump limits
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	bw := bufio.NewWriterSize(w, 64*1024)
	defer bw.Flush()

	for scanner.Scan() {
		line := scanner.Text()
		out, err := eng.Apply(line)
		if err != nil {
			return err
		}
		if _, err := bw.WriteString(out); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	}
	return scanner.Err()
}
