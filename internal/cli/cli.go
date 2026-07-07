// Package cli is the planscope command-line interface: a single command
// table drives dispatch, help, and shared device flags, so every
// subcommand resolves the device target the same way (flag > environment
// PLANSCOPE_KEY > config file) and help stays in one place.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	flag "github.com/spf13/pflag"

	"github.com/teemow/planscope/internal/plan"
	"github.com/teemow/planscope/internal/tui"
)

// command is one subcommand: its usage line, one-line summary, group for
// the help listing, and body. run returns the process exit code.
type command struct {
	name    string
	args    string // usage suffix, e.g. "<name> <value>"
	group   string // "device" | "capture" | "general"
	summary string
	run     func(args []string) int
}

// commands is the dispatch table, in help order. Populated in init()
// functions across the package files.
var commands []command

func lookup(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// Main is the CLI entry point; returns the process exit code.
func Main(args []string) int {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if c := lookup(args[0]); c != nil {
			return c.run(args[1:])
		}
		fmt.Fprintf(os.Stderr, "planscope: unknown subcommand %q\n\n%s", args[0], help())
		return 2
	}
	return runDefault(args)
}

// runDefault is the bare-invocation mode: the live TUI against a device,
// or the offline report over piped input.
func runDefault(args []string) int {
	fs := flag.NewFlagSet("planscope", flag.ExitOnError)
	dev := addDeviceFlags(fs)
	bucket := fs.Int("bucket", 15, "timeline bucket size in seconds")
	from := fs.String("from", "", "analyze only after this time (HH:MM:SS, piped mode)")
	to := fs.String("to", "", "analyze only before this time (HH:MM:SS, piped mode)")
	protocol := fs.Bool("protocol", false, "print the pLAN protocol reference manual and exit")
	version := fs.Bool("version", false, "print the planscope version and exit")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `planscope -- interactive pLAN terminal and protocol debugger for CAREL
pLAN buses (pCO/uPC controller + pGD display), talking to an ESP32 bridge
running a planterm-based firmware over the ESPHome native API.

Usage:
  planscope [flags]                 live TUI: bus scope + second pGD terminal
  planscope [flags] < capture.log   offline: reconstruct the screen and print
                                    the full traffic report from a capture
  planscope <subcommand> [flags]    headless device control + capture analysis

%s
Flags:
%s
Device address and API key resolve flag > environment (PLANSCOPE_KEY) >
config file.
`, help(), fs.FlagUsages())
	}
	fs.Parse(args)

	if *version {
		fmt.Println(versionString())
		return 0
	}
	if *protocol {
		fmt.Println(protocolHelp)
		return 0
	}

	// piped/redirected stdin always means "analyze this stream" (so
	// `planscope < capture.log` works even with a device configured),
	// unless --device was given explicitly on the command line
	device := ""
	if isTTY(os.Stdin) || fs.Changed("device") {
		var err error
		if device, _, err = dev.target(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			fs.Usage()
			return 2
		}
	}

	if device != "" {
		_, key := mustTarget(dev)
		tui.Run(device, key, *bucket)
		return 0
	}

	// piped mode: consume the whole stream, then print screen + full report
	an := plan.NewAnalyzer(*bucket)
	an.From, an.To = *from, *to
	if *to == "" && *from != "" {
		an.To = "23:59:59"
	}
	scr := plan.NewScreen()
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if tsMs, declared, seq, burst, ok := plan.ParseLine(line); ok {
			scr.Feed(tsMs, declared, seq, burst)
			if !plan.IsSnapshotLine(line) { // snapshot replay: screen only
				an.Feed(tsMs, declared, seq, burst)
			}
		}
	}
	fmt.Println(scr.Render())
	fmt.Println()
	fmt.Println(an.Report())
	return 0
}

// help renders the subcommand listing from the command table.
func help() string {
	var sb strings.Builder
	sb.WriteString("Subcommands ('planscope <subcommand> --help' for flags):\n")
	for _, g := range []struct{ id, title string }{
		{"device", "device control (uses --device/--key, PLANSCOPE_KEY, or the config file)"},
		{"capture", "capture analysis (files or stdin)"},
		{"general", "general"},
	} {
		fmt.Fprintf(&sb, "\n  %s:\n", g.title)
		for _, c := range commands {
			if c.group != g.id {
				continue
			}
			left := c.name
			if c.args != "" {
				left += " " + c.args
			}
			// wrap the summary under a fixed left column
			fmt.Fprintf(&sb, "    %-26s %s\n", left, c.summary)
		}
	}
	return sb.String()
}

func versionString() string {
	v := "(devel)"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		v = bi.Main.Version
	}
	return "planscope " + v
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// --- config + shared device flags -------------------------------------------

// DefaultConfigPath is ~/.config/planscope/config.
func DefaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "planscope", "config")
}

// LoadConfig reads a `key = value` file (# comments, optional quotes around
// the value). A missing file is fine -- flags/env just take over.
func LoadConfig(path string) map[string]string {
	cfg := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		cfg[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return cfg
}

// deviceFlags are the flags every device command shares.
type deviceFlags struct {
	cfgPath, device, key *string
}

func addDeviceFlags(fs *flag.FlagSet) *deviceFlags {
	return &deviceFlags{
		cfgPath: fs.String("config", DefaultConfigPath(), "config file with 'device = ...' / 'key = ...' lines"),
		device:  fs.String("device", "", "ESPHome device address (host or host:port)"),
		key:     fs.String("key", "", "api.encryption.key of the device (also PLANSCOPE_KEY env var or config file)"),
	}
}

// target resolves device address + key: flag > environment > config file.
func (d *deviceFlags) target() (addr, key string, err error) {
	cfg := LoadConfig(*d.cfgPath)
	addr, key = *d.device, *d.key
	if addr == "" {
		addr = cfg["device"]
	}
	if key == "" {
		key = os.Getenv("PLANSCOPE_KEY")
	}
	if key == "" {
		key = cfg["key"]
	}
	if addr == "" {
		return "", "", fmt.Errorf("no device; pass --device <ip> or set it in %s", *d.cfgPath)
	}
	if !strings.Contains(addr, ":") {
		addr += ":6053"
	}
	return addr, key, nil
}

// mustTarget is target() with the exit-on-error contract of a subcommand.
func mustTarget(d *deviceFlags) (string, string) {
	addr, key, err := d.target()
	if err != nil {
		fmt.Fprintln(os.Stderr, "planscope:", err)
		os.Exit(2)
	}
	return addr, key
}

func init() {
	commands = append(commands,
		command{"help", "", "general", "this listing", func([]string) int {
			fmt.Print(help())
			return 0
		}},
		command{"protocol", "", "general", "print the pLAN protocol reference manual", func([]string) int {
			fmt.Println(protocolHelp)
			return 0
		}},
		command{"version", "", "general", "print the planscope version", func([]string) int {
			fmt.Println(versionString())
			return 0
		}},
	)
}
