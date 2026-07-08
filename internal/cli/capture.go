// The offline capture-analysis subcommands: report (the planscope traffic
// report) plus the decode workbench (analyze, regroup, correlate, records,
// screen, bursts). All read files or stdin.
package cli

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	flag "github.com/spf13/pflag"

	"github.com/teemow/planscope/internal/decode"
	"github.com/teemow/planscope/internal/plan"
)

// readInputs concatenates the given files, or stdin when none are given.
func readInputs(paths []string) (string, error) {
	if len(paths) == 0 {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	var sb strings.Builder
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// inputText is readInputs with the exit-on-error contract of a subcommand.
func inputText(paths []string) string {
	text, err := readInputs(paths)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return text
}

func readFileText(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return string(b)
}

func runReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	bucket := fs.Int("bucket", 15, "timeline bucket size in seconds")
	from := fs.String("from", "", "analyze only after this time (HH:MM:SS)")
	to := fs.String("to", "", "analyze only before this time (HH:MM:SS)")
	_ = fs.Parse(args) // ExitOnError: exits on bad flags
	text := inputText(fs.Args())
	an := plan.NewAnalyzer(*bucket)
	an.From, an.To = *from, *to
	if *to == "" && *from != "" {
		an.To = "23:59:59"
	}
	scr := plan.NewScreen()
	for _, line := range strings.Split(text, "\n") {
		if tsMs, declared, seq, burst, ok := plan.ParseLine(line); ok {
			scr.Feed(tsMs, declared, seq, burst)
			if !plan.IsSnapshotLine(line) { // tee'd snapshot replay: screen only
				an.Feed(tsMs, declared, seq, burst)
			}
		}
	}
	fmt.Println(an.Report())
	return 0
}

func runAnalyze(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	_ = fs.Parse(args) // ExitOnError: exits on bad flags
	decode.ReportAnalyze(decode.ParseFramesText(inputText(fs.Args())))
	return 0
}

func runRegroup(args []string) int {
	fs := flag.NewFlagSet("regroup", flag.ExitOnError)
	lengths := fs.String("lengths", "6,9,12",
		"candidate atomic frame lengths (comma-separated)")
	sumTargets := fs.String("sum-targets", "0xFE,0xFF",
		"good whole-frame byte-sum values mod 256 (comma-separated)")
	_ = fs.Parse(args) // ExitOnError: exits on bad flags
	text := inputText(fs.Args())
	var ls []int
	for _, s := range strings.Split(*lengths, ",") {
		v, err := strconv.ParseInt(strings.TrimSpace(s), 0, 32)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad --lengths:", err)
			return 2
		}
		ls = append(ls, int(v))
	}
	targets := map[int]bool{}
	for _, s := range strings.Split(*sumTargets, ",") {
		v, err := strconv.ParseInt(strings.TrimSpace(s), 0, 32)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad --sum-targets:", err)
			return 2
		}
		targets[int(v)] = true
	}
	stream := decode.Reassemble(decode.ParseFramesText(text))
	atoms, junk := decode.RegroupByChecksum(stream, ls, targets)
	fmt.Printf("reassembled %d bytes -> %d atomic frames (%d unparsed)\n\n",
		len(stream), len(atoms), junk)
	decode.ReportAnalyze(atoms)
	return 0
}

func runCorrelate(args []string) int {
	fs := flag.NewFlagSet("correlate", flag.ExitOnError)
	_ = fs.Parse(args) // ExitOnError: exits on bad flags
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: planscope correlate BASE VARIANT")
		return 2
	}
	decode.ReportCorrelate(
		decode.ParseFramesText(readFileText(fs.Arg(0))),
		decode.ParseFramesText(readFileText(fs.Arg(1))),
		fs.Arg(0), fs.Arg(1))
	return 0
}

func runRecords(args []string) int {
	fs := flag.NewFlagSet("records", flag.ExitOnError)
	_ = fs.Parse(args) // ExitOnError: exits on bad flags
	decode.ReportRecords(decode.ParseTimedText(inputText(fs.Args())))
	return 0
}

func runScreenCmd(args []string) int {
	fs := flag.NewFlagSet("screen", flag.ExitOnError)
	changes := fs.Int("changes", 40, "max distinct values to list per row")
	_ = fs.Parse(args) // ExitOnError: exits on bad flags
	decode.ReportScreen(decode.ParseTimedText(inputText(fs.Args())), *changes)
	return 0
}

func runBursts(args []string) int {
	fs := flag.NewFlagSet("bursts", flag.ExitOnError)
	windowMs := fs.Int("window-ms", 300, "time bin width for burst detection")
	factor := fs.Float64("factor", 3.0, "hot when record count >= factor x median")
	recordMin := fs.Int("record-min", 3, "min 20 0C records in a window to count as a redraw")
	quiet := fs.String("quiet-selectors", "00,02,03,04",
		"baseline selectors seen at steady state (comma-separated hex)")
	_ = fs.Parse(args) // ExitOnError: exits on bad flags
	text := inputText(fs.Args())
	qs := map[int]bool{}
	for _, s := range strings.Split(*quiet, ",") {
		if s = strings.TrimSpace(s); s != "" {
			v, err := strconv.ParseInt(s, 16, 32)
			if err != nil {
				fmt.Fprintln(os.Stderr, "bad --quiet-selectors:", err)
				return 2
			}
			qs[int(v)] = true
		}
	}
	decode.ReportBursts(decode.ParseTimedText(text), *windowMs, *factor, qs, *recordMin)
	return 0
}

func init() {
	commands = append(commands,
		command{"report", "[files]", "capture", "timeline + per-address + failing-frames report (--from, --to, --bucket)", runReport},
		command{"screen", "[files]", "capture", "reconstruct the pGD text screen + row timeline", runScreenCmd},
		command{"analyze", "[files]", "capture", "infer frame grammar (lengths, checksum, fields)", runAnalyze},
		command{"regroup", "[files]", "capture", "re-split merged frames via checksum, then analyze", runRegroup},
		command{"correlate", "BASE VARIANT", "capture", "diff two captures to isolate an event", runCorrelate},
		command{"records", "[files]", "capture", "decode 20 0C field records per selector", runRecords},
		command{"bursts", "[files]", "capture", "find redraw bursts and their field selectors", runBursts},
	)
}
