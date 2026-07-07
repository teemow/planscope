package plan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/teemow/planscope/internal/style"
)

// FailSample is one checksum-failing frame kept verbatim.
type FailSample struct {
	TSms  int
	Bytes []byte
}

// FrameRec is one classified frame for the frames view.
type FrameRec struct {
	TSms     int
	Class    string
	Bytes    []byte
	OK       bool
	Headless bool
}

const (
	maxFailSamples = 200
	maxRecent      = 400
)

// ClassStyle maps traffic classes to their view style.
var ClassStyle = map[string]string{
	"poll": style.Gray, "reply": style.Gray, "ack": style.Gray,
	"walk": "38;5;68", "disp": "36", "key": "1;33", "other": "35",
}

// Analyzer accumulates per-bucket, per-address, and per-frame statistics.
// It is the Go port of the retired Python plan_timeline tool: capture lines
// carry a bit9 apostrophe mark on every address byte (`20'`); splitting a
// burst at those marks yields the real frames on the wire, each validated
// against the two checksum grammars, classified, and counted per time
// bucket and per destination address. Checksum failures are the objective
// garble detector.
type Analyzer struct {
	bucketS  int
	From, To string // optional HH:MM:SS window, empty = all

	buckets   map[int]map[string]int
	perAddr   map[byte]*[2]int // addr -> {frames, cksum fails}
	Fails     []FailSample
	Recent    []FrameRec // ring buffer for the frames view
	Frames    int
	FailCount int
	noBit9    int  // bursts skipped: no bit9 marks, cannot split
	seenBit9  bool // stream carries bit9 marks (plan_control capture lines)

	// capture-transport loss, from the [#seq|N] line numbering: each seq
	// gap is exactly that many capture lines lost (live: capture-stream
	// records the firmware skipped for a stalled client; offline files may
	// still carry legacy log-line loss).
	LastSeq   int // last seen seq, 0 = stream carries no seq numbers
	SeqGaps   int // gap events
	LostLines int // capture lines lost across all gaps
}

// NewAnalyzer returns an analyzer with the given timeline bucket size in
// seconds.
func NewAnalyzer(bucketS int) *Analyzer {
	return &Analyzer{
		bucketS: bucketS,
		buckets: map[int]map[string]int{},
		perAddr: map[byte]*[2]int{},
	}
}

// PerAddr returns the {frames, cksum fails} counters for one address (nil
// when the address was never seen).
func (a *Analyzer) PerAddr(addr byte) *[2]int { return a.perAddr[addr] }

// NoBit9 counts bursts skipped for lacking bit9 marks.
func (a *Analyzer) NoBit9() int { return a.noBit9 }

// Feed ingests one logged burst. declared is the [ N] byte count from the
// log line; fewer parsed bytes means the logger cut the burst off and the
// last frame must not be checksum-judged. Lines without a declared count are
// not frame dumps (prose INFO lines can contain hex-looking words) and are
// ignored here -- the screen decoder handles those permissively. seq is the
// capture-line sequence number (0 = none); a jump of >1 means the capture
// transport lost exactly that many lines.
func (a *Analyzer) Feed(tsMs, declared, seq int, burst []Tok) {
	if len(burst) == 0 || declared == 0 {
		return
	}
	ts := FmtTS(tsMs)
	if a.From != "" && (ts < a.From || ts > a.To) {
		return
	}
	if seq > 0 {
		if a.LastSeq > 0 && seq > a.LastSeq+1 {
			a.SeqGaps++
			a.LostLines += seq - a.LastSeq - 1
		}
		// seq <= lastSeq means the firmware rebooted: rebase, no gap counted
		a.LastSeq = seq
	}
	hasBit9 := false
	for _, t := range burst {
		if t.Bit9 {
			hasBit9 = true
			break
		}
	}
	if hasBit9 {
		a.seenBit9 = true
	} else if !a.seenBit9 {
		// a stream that never shows bit9 marks (plan_capture raw hex)
		// cannot be split into frames -- skip rather than misclassify
		a.noBit9++
		return
	}
	// mark-less bursts within a bit9 stream are continuations of a
	// logger-truncated frame: classified as a headless fragment below
	sec := tsMs / 1000
	bkey := sec - sec%a.bucketS
	b := a.buckets[bkey]
	if b == nil {
		b = map[string]int{}
		a.buckets[bkey] = b
	}
	truncated := len(burst) < declared
	frames, headless := SplitFrames(burst)
	for i, f := range frames {
		class := Classify(f)
		b[class]++
		skipSum := class == "ack" || headless[i] ||
			(truncated && i == len(frames)-1)
		ok := true
		if !skipSum {
			a.Frames++
			pa := a.perAddr[f[0]]
			if pa == nil {
				pa = &[2]int{}
				a.perAddr[f[0]] = pa
			}
			pa[0]++
			ok = ChecksumOK(f)
			if !ok {
				a.FailCount++
				b["cksum_fail"]++
				pa[1]++
				if len(a.Fails) < maxFailSamples {
					a.Fails = append(a.Fails, FailSample{tsMs, append([]byte(nil), f...)})
				}
			}
		}
		a.Recent = append(a.Recent, FrameRec{tsMs, class, append([]byte(nil), f...), ok, headless[i]})
		if len(a.Recent) > maxRecent {
			a.Recent = a.Recent[len(a.Recent)-maxRecent:]
		}
	}
}

func (a *Analyzer) sortedBuckets() []int {
	keys := make([]int, 0, len(a.buckets))
	for k := range a.buckets {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// TimelineTable renders the per-bucket class counts, newest last; maxRows
// limits to the most recent buckets (0 = all). In the TUI a sparkline
// column shows each bucket's total activity; plain output (reports) stays
// byte-identical to the retired Python plan_timeline tool.
func (a *Analyzer) TimelineTable(maxRows int) string {
	cols := append(append([]string{}, Classes...), "cksum_fail")
	keys := a.sortedBuckets()
	if maxRows > 0 && len(keys) > maxRows {
		keys = keys[len(keys)-maxRows:]
	}
	maxTotal := 0
	totals := map[int]int{}
	for _, k := range keys {
		t := 0
		for _, c := range Classes {
			t += a.buckets[k][c]
		}
		totals[k] = t
		if t > maxTotal {
			maxTotal = t
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%8s", "time")
	for _, c := range cols {
		sb.WriteString(" " + style.S(style.Dim, fmt.Sprintf("%10s", c)))
	}
	sb.WriteByte('\n')
	for _, k := range keys {
		fmt.Fprintf(&sb, "%8s", FmtTS(k*1000))
		for _, c := range cols {
			v := a.buckets[k][c]
			cell := fmt.Sprintf(" %10d", v)
			if style.Enabled && c == "cksum_fail" && v > 0 {
				cell = " " + style.S(style.Red, fmt.Sprintf("%10d", v))
			} else if style.Enabled && v == 0 {
				cell = " " + style.S(style.Dim, fmt.Sprintf("%10d", v))
			}
			sb.WriteString(cell)
		}
		if style.Enabled {
			sb.WriteString("  " + style.S("38;5;68", style.Spark(totals[k], maxTotal)))
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// AddrTable renders the per-address traffic and failure counts.
func (a *Analyzer) AddrTable() string {
	var sb strings.Builder
	sb.WriteString(style.S(style.Dim, "per-address (checksummed frames):") + "\n")
	fmt.Fprintf(&sb, "%6s %8s %10s  %s\n", "addr", "frames", "cksum_fail", "who")
	addrs := make([]int, 0, len(a.perAddr))
	maxN := 0
	for k, pa := range a.perAddr {
		addrs = append(addrs, int(k))
		if pa[0] > maxN {
			maxN = pa[0]
		}
	}
	sort.Ints(addrs)
	for _, ai := range addrs {
		pa := a.perAddr[byte(ai)]
		fails := fmt.Sprintf("%10d", pa[1])
		if style.Enabled && pa[1] > 0 {
			fails = style.S(style.Red, fails)
		}
		who := AddrName(byte(ai))
		if style.Enabled && maxN > 0 {
			// traffic share bar: idle slots vs the hot addresses
			n := pa[0] * 24 / maxN
			if n == 0 && pa[0] > 0 {
				n = 1
			}
			who = style.PadTo(who, 18) + style.S("38;5;25", strings.Repeat("█", n))
		}
		fmt.Fprintf(&sb, "  0x%02X %8d %s  %s\n", ai, pa[0], fails, who)
	}
	rate := 0.0
	if a.Frames > 0 {
		rate = float64(a.FailCount) / float64(a.Frames) * 100
	}
	fmt.Fprintf(&sb, "\ntotal: %d frames, %d checksum failures (%.3f%%)",
		a.Frames, a.FailCount, rate)
	if a.LastSeq > 0 {
		loss := fmt.Sprintf("%d capture lines lost in %d gaps", a.LostLines, a.SeqGaps)
		if style.Enabled && a.LostLines > 0 {
			loss = style.S(style.Red, loss)
		}
		fmt.Fprintf(&sb, "\ncapture transport: %s (last seq #%d)", loss, a.LastSeq)
	}
	if a.noBit9 > 0 {
		fmt.Fprintf(&sb, "\n(%d bursts without bit9 marks skipped -- use plan_control capture lines for analysis)", a.noBit9)
	}
	return sb.String()
}

// FailList renders the most recent checksum failures, at most max entries
// (0 = all).
func (a *Analyzer) FailList(max int) string {
	var sb strings.Builder
	if len(a.Fails) == 0 {
		sb.WriteString(style.S(style.Green, "✓") +
			fmt.Sprintf(" no checksum failures in %d frames -- the bus is clean", a.Frames))
		return sb.String()
	}
	fails := a.Fails
	if max > 0 && len(fails) > max {
		fails = fails[len(fails)-max:]
	}
	sb.WriteString(style.S(style.Red, fmt.Sprintf("%d checksum failures", a.FailCount)) +
		fmt.Sprintf(" of %d frames; corrupted frames on the wire have bad sums:\n", a.Frames))
	for _, f := range fails {
		fmt.Fprintf(&sb, "  %s %s\n",
			style.S(style.Gray, "["+FmtTSms(f.TSms)+"]"), style.S(style.Red, HexBytes(f.Bytes)))
	}
	return sb.String()
}

// Report renders the full plan_timeline.py-style report (piped mode / exit).
func (a *Analyzer) Report() string {
	var sb strings.Builder
	sb.WriteString(a.TimelineTable(0))
	sb.WriteByte('\n')
	sb.WriteString(a.AddrTable())
	sb.WriteByte('\n')
	if len(a.Fails) > 0 {
		sb.WriteByte('\n')
		fmt.Fprintf(&sb, "first %d failing frames:\n", len(a.Fails))
		for _, f := range a.Fails {
			fmt.Fprintf(&sb, "  [%s] %s\n", FmtTSms(f.TSms), HexBytes(f.Bytes))
		}
	}
	return sb.String()
}
