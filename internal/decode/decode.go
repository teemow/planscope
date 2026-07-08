// Package decode is the offline frame-grammar workbench: the Go port of
// the retired Python plan_decode tool this project's protocol
// understanding was bootstrapped with.
//
// It ingests raw hex captures (plain hex dumps, or capture lines with
// bit9 apostrophe marks) and reverse-engineers the
// pLAN frame grammar: delimiters, address bytes, length field, checksum --
// then helps split controller->terminal (display) from terminal->controller
// (keypad) frames by correlating two captures. Nothing structural is
// hardcoded: every claim is inferred from the captured bytes and reported
// with the evidence behind it.
//
// Subcommands (wired in internal/cli):
//
//	analyze    infer frame grammar from capture(s)
//	regroup    re-split merged frames via the checksum, then analyze
//	correlate  diff two captures to isolate an event (e.g. a key press)
//	records    decode 20 0C field records -> per-selector stats over time
//	screen     reconstruct the pGD text screen + per-row change timeline
//	bursts     find redraw bursts and the field selectors each carries
package decode

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/teemow/planscope/internal/plan"
)

// --- parsing ---------------------------------------------------------------

var (
	ansiRe  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	tsRe    = regexp.MustCompile(`\[(\d{2}):(\d{2}):(\d{2})\.(\d{3})\]`)
	brackRe = regexp.MustCompile(`\[[^\]]*\]`) // timestamps, levels, tags, [ len ]
	hexRe   = regexp.MustCompile(`^([0-9A-Fa-f]{2})(')?$`)
)

// ParseFramesText extracts one frame per non-empty input line. Bracketed
// groups (esphome timestamps, levels, tags, the harness [ 18] length prefix)
// are stripped; bare two-hex-digit tokens survive. A trailing bit9
// apostrophe (plan_control format) is accepted and dropped -- the offline
// grammar tools treat the line as one byte run either way. Lines starting
// with # are comments.
func ParseFramesText(text string) [][]byte {
	var frames [][]byte
	for _, raw := range strings.Split(text, "\n") {
		line := ansiRe.ReplaceAllString(raw, "")
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		var data []byte
		for _, t := range strings.Fields(brackRe.ReplaceAllString(line, " ")) {
			if m := hexRe.FindStringSubmatch(t); m != nil {
				var b byte
				_, _ = fmt.Sscanf(m[1], "%02X", &b) // hexRe guarantees the format
				data = append(data, b)
			}
		}
		if len(data) > 0 {
			frames = append(frames, data)
		}
	}
	return frames
}

type timedLine struct {
	tsMs int // ms since midnight, -1 = line had no timestamp
	data []byte
}

// ParseTimedText is ParseFramesText keeping the [HH:MM:SS.mmm] timestamp so
// redraw bursts can be located in time.
func ParseTimedText(text string) []timedLine {
	var out []timedLine
	for _, raw := range strings.Split(text, "\n") {
		line := ansiRe.ReplaceAllString(raw, "")
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		ts := -1
		if m := tsRe.FindStringSubmatch(line); m != nil {
			var h, mi, s, ms int
			_, _ = fmt.Sscanf(m[1]+" "+m[2]+" "+m[3]+" "+m[4], "%d %d %d %d", &h, &mi, &s, &ms) // tsRe guarantees the format
			ts = ((h*60+mi)*60+s)*1000 + ms
		}
		var data []byte
		for _, t := range strings.Fields(brackRe.ReplaceAllString(line, " ")) {
			if m := hexRe.FindStringSubmatch(t); m != nil {
				var b byte
				_, _ = fmt.Sscanf(m[1], "%02X", &b) // hexRe guarantees the format
				data = append(data, b)
			}
		}
		if len(data) > 0 {
			out = append(out, timedLine{ts, data})
		}
	}
	return out
}

// --- checksum hypotheses -----------------------------------------------------

func reflectBits(v uint32, n int) uint32 {
	var r uint32
	for i := 0; i < n; i++ {
		r = r<<1 | v&1
		v >>= 1
	}
	return r
}

// crcGeneric is a bit-banged CRC covering the common 8- and 16-bit families.
func crcGeneric(data []byte, width int, poly, init uint32, refin, refout bool, xorout uint32) uint32 {
	topbit := uint32(1) << (width - 1)
	mask := uint32(1)<<width - 1
	crc := init
	for _, b := range data {
		v := uint32(b)
		if refin {
			v = reflectBits(v, 8)
		}
		crc ^= v << (width - 8)
		for i := 0; i < 8; i++ {
			if crc&topbit != 0 {
				crc = crc<<1 ^ poly
			} else {
				crc <<= 1
			}
			crc &= mask
		}
	}
	if refout {
		crc = reflectBits(crc, width)
	}
	return crc ^ xorout
}

func xor8(d []byte) uint32 {
	var v byte
	for _, b := range d {
		v ^= b
	}
	return uint32(v)
}

func sum(d []byte) int {
	s := 0
	for _, b := range d {
		s += int(b)
	}
	return s
}

// The checksum families the brute-force search tries, in a fixed order so
// reports are deterministic.
var checksumAlgos = []struct {
	name  string
	width int
	fn    func([]byte) uint32
}{
	{"sum8", 1, func(d []byte) uint32 { return uint32(sum(d) & 0xFF) }},
	{"sum8_2c", 1, func(d []byte) uint32 { return uint32(-sum(d)) & 0xFF }},
	{"sum8_inv", 1, func(d []byte) uint32 { return uint32(^sum(d)) & 0xFF }},
	{"xor8", 1, xor8},
	{"crc8", 1, func(d []byte) uint32 { return crcGeneric(d, 8, 0x07, 0x00, false, false, 0x00) }},
	{"crc8_maxim", 1, func(d []byte) uint32 { return crcGeneric(d, 8, 0x31, 0x00, true, true, 0x00) }},
	{"crc8_cdma", 1, func(d []byte) uint32 { return crcGeneric(d, 8, 0x9B, 0xFF, false, false, 0x00) }},
	{"sum16_le", 2, func(d []byte) uint32 { return uint32(sum(d) & 0xFFFF) }},
	{"crc16_modbus", 2, func(d []byte) uint32 { return crcGeneric(d, 16, 0x8005, 0xFFFF, true, true, 0x0000) }},
	{"crc16_ccitt", 2, func(d []byte) uint32 { return crcGeneric(d, 16, 0x1021, 0xFFFF, false, false, 0x0000) }},
	{"crc16_xmodem", 2, func(d []byte) uint32 { return crcGeneric(d, 16, 0x1021, 0x0000, false, false, 0x0000) }},
}

type cksHit struct {
	name           string
	dataStart      int // leading header bytes excluded from the checksummed span
	le             bool
	matched, total int
}

func (h cksHit) frac() float64 {
	if h.total == 0 {
		return 0
	}
	return float64(h.matched) / float64(h.total)
}

// searchChecksum brute-forces which (algorithm, header offset, endianness)
// reproduces the trailing byte(s) of the frames. Tries 0..2 leading header
// bytes excluded from the span (delimiter/address are often outside the CRC).
func searchChecksum(frames [][]byte) []cksHit {
	const minLen = 4
	var usable [][]byte
	for _, f := range frames {
		if len(f) >= minLen {
			usable = append(usable, f)
		}
	}
	var hits []cksHit
	if len(usable) == 0 {
		return hits
	}
	for _, algo := range checksumAlgos {
		for start := 0; start <= 2; start++ {
			endians := []bool{false}
			if algo.width == 2 {
				endians = []bool{true, false}
			}
			for _, le := range endians {
				matched, total := 0, 0
				for _, d := range usable {
					if len(d) < start+algo.width+1 {
						continue
					}
					total++
					span := d[start : len(d)-algo.width]
					want := algo.fn(span)
					tail := d[len(d)-algo.width:]
					var got uint32
					if algo.width == 1 {
						got = uint32(tail[0])
					} else if le {
						got = uint32(tail[0]) | uint32(tail[1])<<8
					} else {
						got = uint32(tail[0])<<8 | uint32(tail[1])
					}
					if got == want {
						matched++
					}
				}
				if total > 0 && matched > 0 {
					hits = append(hits, cksHit{algo.name, start, le, matched, total})
				}
			}
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].frac() != hits[j].frac() {
			return hits[i].frac() > hits[j].frac()
		}
		return hits[i].matched > hits[j].matched
	})
	return hits
}

// --- structural inference: delimiters, address, length ----------------------

type countPair struct {
	val   int
	count int
}

// intCounter is a Python collections.Counter lookalike: mostCommon breaks
// count ties by first-seen order, which keeps report output identical to the
// retired plan_decode.py.
type intCounter struct {
	c     map[int]int
	first map[int]int
	n     int
}

func newIntCounter() *intCounter {
	return &intCounter{c: map[int]int{}, first: map[int]int{}}
}

func (ic *intCounter) add(v int) {
	if _, ok := ic.c[v]; !ok {
		ic.first[v] = ic.n
		ic.n++
	}
	ic.c[v]++
}

func (ic *intCounter) mostCommon() []countPair {
	pairs := make([]countPair, 0, len(ic.c))
	for v, n := range ic.c {
		pairs = append(pairs, countPair{v, n})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return ic.first[pairs[i].val] < ic.first[pairs[j].val]
	})
	return pairs
}

func fmtCounter(ic *intCounter, top int) string {
	pairs := ic.mostCommon()
	if len(pairs) > top {
		pairs = pairs[:top]
	}
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = fmt.Sprintf("%02X:%d", p.val, p.count)
	}
	return strings.Join(parts, ", ")
}

func byteHistogram(frames [][]byte) *intCounter {
	c := newIntCounter()
	for _, f := range frames {
		for _, b := range f {
			c.add(int(b))
		}
	}
	return c
}

func leadingBytes(frames [][]byte) *intCounter {
	c := newIntCounter()
	for _, f := range frames {
		if len(f) > 0 {
			c.add(int(f[0]))
		}
	}
	return c
}

func trailingBytes(frames [][]byte) *intCounter {
	c := newIntCounter()
	for _, f := range frames {
		if len(f) > 0 {
			c.add(int(f[len(f)-1]))
		}
	}
	return c
}

func lengthDistribution(frames [][]byte) map[int]int {
	c := map[int]int{}
	for _, f := range frames {
		c[len(f)]++
	}
	return c
}

// guessLengthField reports, per early offset, the best fraction of frames
// whose data[offset] equals the total frame length (+/- a small header
// adjustment). A strong hit means that offset is the length field.
func guessLengthField(frames [][]byte) []struct {
	off  int
	frac float64
} {
	best := map[int]float64{}
	for off := 0; off <= 2; off++ {
		for _, adjust := range []int{0, -1, -2, 1, 2} {
			ok, tot := 0, 0
			for _, f := range frames {
				if len(f) > off {
					tot++
					if int(f[off]) == len(f)+adjust {
						ok++
					}
				}
			}
			if tot > 0 && ok > 0 {
				if frac := float64(ok) / float64(tot); frac > best[off] {
					best[off] = frac
				}
			}
		}
	}
	offs := make([]int, 0, len(best))
	for o := range best {
		offs = append(offs, o)
	}
	sort.Ints(offs)
	out := make([]struct {
		off  int
		frac float64
	}, len(offs))
	for i, o := range offs {
		out[i].off, out[i].frac = o, best[o]
	}
	return out
}

// addressCandidates counts distinct values per early offset. Address and
// delimiter bytes take very few distinct values; payload offsets take many.
func addressCandidates(frames [][]byte, maxOff int) []*intCounter {
	out := make([]*intCounter, maxOff)
	for i := range out {
		out[i] = newIntCounter()
	}
	for _, f := range frames {
		for off := 0; off < maxOff && off < len(f); off++ {
			out[off].add(int(f[off]))
		}
	}
	return out
}

// Reassemble concatenates every captured byte back into one stream. The
// capture harness frames on a 3 ms idle gap, which merges runs of atomic
// frames onto one logged line; reassembling lets us re-split on structure.
func Reassemble(frames [][]byte) []byte {
	var s []byte
	for _, f := range frames {
		s = append(s, f...)
	}
	return s
}

// RegroupByChecksum re-splits a reassembled stream into atomic frames using
// the additive checksum as the boundary oracle: at each position take the
// shortest candidate length whose byte-sum mod 256 lands on a known-good
// constant. lengths and sumTargets come from the analyze step.
func RegroupByChecksum(stream []byte, lengths []int, sumTargets map[int]bool) (atoms [][]byte, junk int) {
	ordered := append([]int(nil), lengths...)
	sort.Ints(ordered)
	// dedupe
	ordered = ordered[:uniqInts(ordered)]
	for i, n := 0, len(stream); i < n; {
		matched := false
		for _, l := range ordered {
			if i+l <= n && sumTargets[sum(stream[i:i+l])&0xFF] {
				atoms = append(atoms, stream[i:i+l])
				i += l
				matched = true
				break
			}
		}
		if !matched {
			junk++
			i++
		}
	}
	return atoms, junk
}

func uniqInts(s []int) int {
	j := 0
	for i, v := range s {
		if i == 0 || v != s[j-1] {
			s[j] = v
			j++
		}
	}
	return j
}

// autocorrelationPeriod finds the smallest lag>0 maximising self-similarity
// of the concatenated stream -- exposes a periodic poll token even if the
// harness split it across logged lines.
func autocorrelationPeriod(frames [][]byte, maxLag int) (int, float64) {
	stream := Reassemble(frames)
	n := len(stream)
	if n < 4 {
		return 0, 0
	}
	bestLag, bestScore := 0, 0.0
	for lag := 1; lag <= maxLag && lag <= n-1; lag++ {
		match := 0
		for i := 0; i < n-lag; i++ {
			if stream[i] == stream[i+lag] {
				match++
			}
		}
		if score := float64(match) / float64(n-lag); score > bestScore {
			bestLag, bestScore = lag, score
		}
	}
	return bestLag, bestScore
}

// classifyDirection splits frames heuristically: controller->terminal display
// frames are long with many distinct payload bytes; terminal->controller
// keypad/link frames are short and repetitive. correlate is the rigorous
// splitter; this is a hint.
func classifyDirection(frames [][]byte) (short, long [][]byte) {
	if len(frames) == 0 {
		return nil, nil
	}
	lens := make([]int, len(frames))
	for i, f := range frames {
		lens[i] = len(f)
	}
	sort.Ints(lens)
	median := lens[len(lens)/2]
	for _, f := range frames {
		distinct := map[byte]bool{}
		for _, b := range f {
			distinct[b] = true
		}
		limit := median / 2
		if limit < 2 {
			limit = 2
		}
		if len(f) <= median && len(distinct) <= limit {
			short = append(short, f)
		} else {
			long = append(long, f)
		}
	}
	return short, long
}

// --- correlation: diff two captures to isolate an event ---------------------

type sigCount struct {
	sig   string // frame bytes as a map key
	count int
}

// sigCounter counts frame signatures preserving first-seen order, matching
// Python's Counter iteration semantics in the retired plan_decode.py.
type sigCounter struct {
	c     map[string]int
	order []string
}

func frameSignatures(frames [][]byte) *sigCounter {
	sc := &sigCounter{c: map[string]int{}}
	for _, f := range frames {
		s := string(f)
		if _, ok := sc.c[s]; !ok {
			sc.order = append(sc.order, s)
		}
		sc.c[s]++
	}
	return sc
}

type byteDiff struct {
	length    int
	base, val []byte
	positions []int
}

// correlateFrames reports frames present in variant but absent from base
// (candidate keypad/event frames) plus byte-position diffs of the dominant
// same-length frames.
func correlateFrames(base, variant [][]byte) (newFrames []sigCount, diffs []byteDiff) {
	sb, sv := frameSignatures(base), frameSignatures(variant)
	for _, sig := range sv.order {
		if sb.c[sig] == 0 {
			newFrames = append(newFrames, sigCount{sig, sv.c[sig]})
		}
	}
	// stable sort: count ties keep first-appearance order, like Python
	sort.SliceStable(newFrames, func(i, j int) bool {
		return newFrames[i].count > newFrames[j].count
	})

	// dominant frame per length; first-seen wins count ties
	dominant := func(sigs *sigCounter) map[int]string {
		best := map[int]sigCount{}
		for _, s := range sigs.order {
			l := len(s)
			if b, ok := best[l]; !ok || sigs.c[s] > b.count {
				best[l] = sigCount{s, sigs.c[s]}
			}
		}
		out := map[int]string{}
		for l, b := range best {
			out[l] = b.sig
		}
		return out
	}
	db, dv := dominant(sb), dominant(sv)
	lengths := make([]int, 0)
	for l := range db {
		if _, ok := dv[l]; ok {
			lengths = append(lengths, l)
		}
	}
	sort.Ints(lengths)
	for _, l := range lengths {
		if db[l] != dv[l] {
			var pos []int
			for i := 0; i < l; i++ {
				if db[l][i] != dv[l][i] {
					pos = append(pos, i)
				}
			}
			diffs = append(diffs, byteDiff{l, []byte(db[l]), []byte(dv[l]), pos})
		}
	}
	return newFrames, diffs
}

// --- display records + redraw bursts ----------------------------------------

var displayHdr = []byte{0x20, 0x0C, 0x08, 0x01}

const displayRecLen = 12

type displayRec struct {
	sel int
	val int
	ok  bool
}

// findDisplayRecords scans a byte run for 12-byte 20 0C field records
// (20 0C 08 01 SS Vh Vl CK | 01 03 20 DB). Header + trailer anchor the
// record; the sum-to-0xFF rule confirms it.
func findDisplayRecords(data []byte) []displayRec {
	var recs []displayRec
	for i, n := 0, len(data); i+displayRecLen <= n; {
		if string(data[i:i+4]) == string(displayHdr) &&
			string(data[i+8:i+12]) == string(plan.Trailer) {
			recs = append(recs, displayRec{
				sel: int(data[i+4]),
				val: int(data[i+5])<<8 | int(data[i+6]),
				ok:  sum(data[i:i+8])&0xFF == 0xFF,
			})
			i += displayRecLen
		} else {
			i++
		}
	}
	return recs
}

// plausibleScale picks the divisor that lands a value range in a sane
// physical band. Pure hint for calibration.
func plausibleScale(vmin, vmax int) string {
	for _, c := range []struct {
		div    int
		lo, hi float64
		unit   string
	}{{100, -40, 120, "x0.01"}, {10, -40, 120, "x0.1"}, {1, -40, 400, "x1"}} {
		a, b := float64(vmin)/float64(c.div), float64(vmax)/float64(c.div)
		if c.lo <= a && a <= c.hi && c.lo <= b && b <= c.hi {
			return fmt.Sprintf("%s -> %.2f..%.2f", c.unit, a, b)
		}
	}
	return "?"
}

type burst struct {
	tMs     int
	bytes   int
	records []displayRec
}

// detectBursts finds redraw windows: a screen switch makes the controller
// refresh every field at once, so the tell-tale is a window carrying many
// 20 0C display records -- not raw byte volume. A window is hot when its
// record count is >= recordMin AND >= factor x the median.
func detectBursts(timed []timedLine, windowMs int, factor float64, recordMin int) []burst {
	binned := map[int][]byte{}
	for _, tl := range timed {
		if tl.tsMs < 0 {
			continue
		}
		w := tl.tsMs / windowMs
		binned[w] = append(binned[w], tl.data...)
	}
	if len(binned) == 0 {
		return nil
	}
	counts := make([]int, 0, len(binned))
	for _, blob := range binned {
		counts = append(counts, len(findDisplayRecords(blob)))
	}
	sort.Ints(counts)
	median := counts[len(counts)/2]
	if median < 1 {
		median = 1
	}
	windows := make([]int, 0, len(binned))
	for w := range binned {
		windows = append(windows, w)
	}
	sort.Ints(windows)
	var hot []burst
	for _, w := range windows {
		blob := binned[w]
		recs := findDisplayRecords(blob)
		if len(recs) >= recordMin && float64(len(recs)) >= factor*float64(median) {
			hot = append(hot, burst{w * windowMs, len(blob), recs})
		}
	}
	return hot
}

// --- reporting ---------------------------------------------------------------

func fmtDict(c map[int]int) string {
	keys := make([]int, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%d: %d", k, c[k])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// pyFloat formats like Python's str(float): 3.0 stays "3.0".
func pyFloat(f float64) string {
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(s, ".e") {
		s += ".0"
	}
	return s
}

// pyStrList renders a []string like Python's repr: ['00', '02'].
func pyStrList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = "'" + s + "'"
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// pyIntList renders an []int like Python's repr: [0, 11, 21].
func pyIntList(items []int) string {
	parts := make([]string, len(items))
	for i, v := range items {
		parts[i] = strconv.Itoa(v)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// ReportAnalyze prints the frame-grammar inference report.
func ReportAnalyze(frames [][]byte) {
	fmt.Printf("frames parsed:        %d\n", len(frames))
	if len(frames) == 0 {
		fmt.Println("no frames -- check the input format")
		return
	}
	fmt.Printf("length distribution:  %s\n", fmtDict(lengthDistribution(frames)))
	fmt.Printf("byte histogram (top): %s\n", fmtCounter(byteHistogram(frames), 8))
	fmt.Printf("leading bytes (top):  %s\n", fmtCounter(leadingBytes(frames), 8))
	fmt.Printf("trailing bytes (top): %s\n", fmtCounter(trailingBytes(frames), 8))

	lag, score := autocorrelationPeriod(frames, 64)
	note := ""
	if score > 0.6 {
		note = "  (likely poll-token period)"
	}
	fmt.Printf("periodicity:          lag=%d self-similarity=%.2f%s\n", lag, score, note)

	fmt.Println("\naddress/delimiter candidates (distinct values per offset):")
	for off, c := range addressCandidates(frames, 3) {
		kind := "varied (payload)"
		if len(c.c) <= 3 {
			kind = "fixed-ish (addr/delim)"
		}
		fmt.Printf("  offset %d: %d distinct  [%s]  %s\n", off, len(c.c), kind, fmtCounter(c, 8))
	}

	fmt.Println("\nlength-field candidates (offset -> match fraction):")
	for _, lf := range guessLengthField(frames) {
		flag := ""
		if lf.frac > 0.8 {
			flag = "  <== likely length field"
		}
		fmt.Printf("  offset %d: %.2f%s\n", lf.off, lf.frac, flag)
	}

	fmt.Println("\nchecksum hypotheses (algo @ header-skip, endian -> match):")
	hits := searchChecksum(frames)
	if len(hits) == 0 {
		fmt.Println("  none -- need more/longer frames, or checksum spans the delimiter")
	}
	if len(hits) > 6 {
		hits = hits[:6]
	}
	for _, h := range hits {
		endian := ""
		if !strings.HasSuffix(h.name, "8") && !strings.HasPrefix(h.name, "xor") {
			if h.le {
				endian = " LE"
			} else {
				endian = " BE"
			}
		}
		flag := ""
		if h.frac() > 0.9 {
			flag = "  <== consistent"
		}
		fmt.Printf("  %-13s skip=%d%s: %d/%d (%.2f)%s\n",
			h.name, h.dataStart, endian, h.matched, h.total, h.frac(), flag)
	}

	fmt.Println("\ndirection split (heuristic):")
	short, long := classifyDirection(frames)
	fmt.Printf("  short_link_or_keypad: %d frames\n", len(short))
	fmt.Printf("  long_display: %d frames\n", len(long))
}

// ReportCorrelate prints the two-capture event-isolation diff.
func ReportCorrelate(base, variant [][]byte, baseName, varName string) {
	fmt.Printf("base    (%s): %d frames\n", baseName, len(base))
	fmt.Printf("variant (%s): %d frames\n\n", varName, len(variant))
	newFrames, diffs := correlateFrames(base, variant)
	fmt.Println("frames present in variant but absent from base " +
		"(candidate keypad/event frames):")
	if len(newFrames) == 0 {
		fmt.Println("  none -- try a longer capture or a more distinct key press")
	}
	if len(newFrames) > 12 {
		newFrames = newFrames[:12]
	}
	for _, nf := range newFrames {
		fmt.Printf("  x%-4d %s\n", nf.count, plan.HexBytes([]byte(nf.sig)))
	}
	fmt.Println("\nbyte-position diffs of the dominant same-length frame " +
		"(idle vs. event):")
	if len(diffs) == 0 {
		fmt.Println("  none")
	}
	for _, d := range diffs {
		fmt.Printf("  len %d: changed offsets %s\n", d.length, pyIntList(d.positions))
		fmt.Printf("    base:    %s\n", plan.HexBytes(d.base))
		fmt.Printf("    variant: %s\n", plan.HexBytes(d.val))
	}
}

// ReportRecords prints per-selector stats of the 20 0C field records.
func ReportRecords(timed []timedLine) {
	type sample struct {
		tsMs int
		val  int
	}
	per := map[int][]sample{}
	bad, total := 0, 0
	for _, tl := range timed {
		for _, r := range findDisplayRecords(tl.data) {
			per[r.sel] = append(per[r.sel], sample{tl.tsMs, r.val})
			total++
			if !r.ok {
				bad++
			}
		}
	}
	fmt.Printf("display records decoded: %d  (bad-checksum: %d)\n", total, bad)
	sels := make([]int, 0, len(per))
	for s := range per {
		sels = append(sels, s)
	}
	sort.Ints(sels)
	names := make([]string, len(sels))
	for i, s := range sels {
		names[i] = fmt.Sprintf("%02X", s)
	}
	fmt.Printf("distinct field selectors: %d  -> %s\n\n", len(per), pyStrList(names))
	if len(per) == 0 {
		fmt.Println("no 20 0C records -- capture more, or check the signature")
		return
	}
	fmt.Printf("%-4s%7s%8s%8s%8s%8s  %-24s  %s\n",
		"SEL", "count", "min", "max", "last", "Δrange", "scale(plausible)", "behaviour")
	for _, sel := range sels {
		vals := per[sel]
		vmin, vmax := vals[0].val, vals[0].val
		monoUp, monoDown := true, true
		for i, v := range vals {
			if v.val < vmin {
				vmin = v.val
			}
			if v.val > vmax {
				vmax = v.val
			}
			if i > 0 {
				if v.val < vals[i-1].val {
					monoUp = false
				}
				if v.val > vals[i-1].val {
					monoDown = false
				}
			}
		}
		last := vals[len(vals)-1].val
		rng := vmax - vmin
		var beh string
		switch {
		case rng == 0:
			beh = "constant (setpoint/flag?)"
		case monoUp || monoDown:
			beh = "monotonic (counter?)"
		case rng <= 5:
			beh = "drift (live sensor?)"
		default:
			beh = "swings (mode/setpoint?)"
		}
		fmt.Printf("%02X  %7d%8d%8d%8d%8d  %-24s  %s\n",
			sel, len(vals), vmin, vmax, last, rng, plausibleScale(vmin, vmax), beh)
	}
	fmt.Println("\nrecent per-selector timeline (last few samples, value x0.01):")
	for _, sel := range sels {
		tail := per[sel]
		if len(tail) > 8 {
			tail = tail[len(tail)-8:]
		}
		parts := make([]string, len(tail))
		for i, s := range tail {
			stamp := "--:--"
			if s.tsMs >= 0 {
				stamp = plan.FmtTSms(s.tsMs)[3:]
			}
			parts[i] = fmt.Sprintf("%s=%.2f", stamp, float64(s.val)/100)
		}
		fmt.Printf("  %02X: %s\n", sel, strings.Join(parts, "  "))
	}
}

// ReportScreen reconstructs and prints the latest text screen per terminal
// plus a per-row change timeline.
func ReportScreen(timed []timedLine, maxChanges int) {
	type rowSample struct {
		tsMs int
		addr byte
		row  int
		text string
	}
	types := newIntCounter()
	var textRows []rowSample
	bad := 0
	for _, tl := range timed {
		for _, fr := range plan.ParseDisplayFrames(tl.data) {
			types.add(int(fr.Typ))
			if !fr.OK {
				bad++
			}
			if fr.Typ == plan.TypeText && len(fr.Payload) > 0 {
				textRows = append(textRows,
					rowSample{tl.tsMs, fr.Addr, int(fr.Payload[0]), plan.RowText(fr.Payload[1:])})
			}
		}
	}
	total := 0
	for _, n := range types.c {
		total += n
	}
	fmt.Printf("display frames decoded: %d  (bad-checksum: %d)\n", total, bad)
	naming := map[int]string{0x0B: "text-row", 0x0C: "numeric-var", 0x64: "graphic-bitmap"}
	var census []string
	for _, p := range types.mostCommon() {
		name := ""
		if n, ok := naming[p.val]; ok {
			name = "/" + n
		}
		census = append(census, fmt.Sprintf("0x%02X%s:%d", p.val, name, p.count))
	}
	fmt.Printf("frame-type census: %s\n\n", strings.Join(census, ", "))
	if len(textRows) == 0 {
		fmt.Println("no 0x0B text-row frames -- capture a redraw, or wrong terminal addr")
		return
	}

	// One screen + timeline per terminal (0x20 = pGD; 0x1F = the ESP's own
	// session, present in captures taken while enrolled).
	addrs := []byte{}
	for _, a := range []byte{plan.EspAddr, plan.TermAddr} {
		for _, r := range textRows {
			if r.addr == a {
				addrs = append(addrs, a)
				break
			}
		}
	}
	for _, a := range addrs {
		latest := map[int]rowSample{}
		lastTS := -1
		for _, r := range textRows {
			if r.addr != a {
				continue
			}
			latest[r.row] = r
			if r.tsMs > lastTS {
				lastTS = r.tsMs
			}
		}
		stamp := "?"
		if lastTS >= 0 {
			stamp = plan.FmtTSms(lastTS)
		}
		fmt.Printf("%s -- latest screen (as of %s):\n", plan.TermName(a), stamp)
		fmt.Println("  +" + strings.Repeat("-", 24) + "+")
		rows := make([]int, 0, len(latest))
		for r := range latest {
			rows = append(rows, r)
		}
		sort.Ints(rows)
		for _, r := range rows {
			t := latest[r].text
			if len(t) > 22 {
				t = t[:22]
			}
			fmt.Printf("  |%-22s|  (row %d)\n", t, r)
		}
		fmt.Println("  +" + strings.Repeat("-", 24) + "+")

		fmt.Println("\nper-row change timeline (consecutive duplicates collapsed):")
		for _, target := range rows {
			var seq []rowSample
			for _, r := range textRows {
				if r.addr == a && r.row == target {
					seq = append(seq, r)
				}
			}
			var deduped []rowSample
			for _, r := range seq {
				if len(deduped) == 0 || deduped[len(deduped)-1].text != r.text {
					deduped = append(deduped, r)
				}
			}
			fmt.Printf("  row %d: %d frames, %d distinct\n", target, len(seq), len(deduped))
			if len(deduped) > maxChanges {
				deduped = deduped[:maxChanges]
			}
			for _, r := range deduped {
				stamp := "--:--:--"
				if r.tsMs >= 0 {
					stamp = plan.FmtTSms(r.tsMs)
				}
				fmt.Printf("    %s  %q\n", stamp, strings.TrimSpace(r.text))
			}
		}
		fmt.Println()
	}
}

// ReportBursts prints the redraw-burst windows and the field selectors each
// carries.
func ReportBursts(timed []timedLine, windowMs int, factor float64,
	quietSelectors map[int]bool, recordMin int) {
	windows := map[int]bool{}
	for _, tl := range timed {
		if tl.tsMs >= 0 {
			windows[tl.tsMs/windowMs] = true
		}
	}
	hot := detectBursts(timed, windowMs, factor, recordMin)
	fmt.Printf("windows scanned: %d  hot (>= %sx median bytes): %d\n\n",
		len(windows), pyFloat(factor), len(hot))
	if len(hot) == 0 {
		fmt.Println("no redraw bursts -- navigate the pGD during capture, then re-run")
		return
	}
	if len(hot) > 20 {
		hot = hot[:20]
	}
	for _, h := range hot {
		selSet := map[int]bool{}
		for _, r := range h.records {
			selSet[r.sel] = true
		}
		sels := make([]int, 0, len(selSet))
		for s := range selSet {
			sels = append(sels, s)
		}
		sort.Ints(sels)
		var selNames, novel []string
		for _, s := range sels {
			selNames = append(selNames, fmt.Sprintf("%02X", s))
			if !quietSelectors[s] {
				novel = append(novel, fmt.Sprintf("%02X", s))
			}
		}
		line := fmt.Sprintf("t=%s  %4dB  records=%d  selectors=%s",
			plan.FmtTSms(h.tMs), h.bytes, len(h.records), pyStrList(selNames))
		if len(novel) > 0 {
			line += "  NEW=" + pyStrList(novel)
		}
		fmt.Println(line)
	}
}
