package plan

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// textFrame builds a valid controller->terminal text-row frame:
// 20 0B LEN 01 ROW <text...> CK | 01 03 20 DB
func textFrame(row byte, text []byte) []byte {
	body := append([]byte{TermAddr, TypeText, byte(5 + len(text) + 1), 0x01, row}, text...)
	sum := 0
	for _, b := range body {
		sum += int(b)
	}
	body = append(body, byte(0xFF-sum&0xFF))
	return append(body, Trailer...)
}

// espFrame builds a text-row frame addressed to the ESP's own session
// (0x1F, no trailer), as the controller paints it while enrolled.
func espFrame(row byte, text string) []byte {
	f := textFrame(row, []byte(text))
	f[0] = EspAddr
	f[len(f)-5] += TermAddr - EspAddr // re-fix CK for the address change
	return f[:len(f)-4]               // strip the trailer
}

func hexLine(data []byte, bit9First bool) string {
	toks := make([]string, len(data))
	for i, b := range data {
		if i == 0 && bit9First {
			toks[i] = fmt.Sprintf("%02X'", b)
		} else {
			toks[i] = fmt.Sprintf("%02X", b)
		}
	}
	return strings.Join(toks, " ")
}

func TestScreen(t *testing.T) {
	scr := NewScreen()
	f2 := textFrame(2, append([]byte("    Hotwater:   39.0"), DegreeByte, 'C'))
	f7 := textFrame(7, []byte("             Auto-On"))

	// frame split across two log lines, poll noise in front
	poll := []byte{0x20, 0x01, 0x01, 0xDD, 0x01, 0x01, 0x20, 0xDD, 0x01}
	blob := append(append([]byte{}, poll...), f2...)
	if scr.FeedLine("[10:20:30.000][D][plan_capture:086]: [ 15] " + hexLine(blob[:15], false)) {
		t.Fatal("half a frame must not change the screen")
	}
	if !scr.FeedLine("[10:20:30.100][D][plan_capture:086]: [ 21] " + hexLine(blob[15:], false)) {
		t.Fatal("completing the frame must change the screen")
	}
	if scr.Rows[TermAddr][2] != "    Hotwater:   39.0°C" {
		t.Fatalf("row 2 = %q", scr.Rows[TermAddr][2])
	}
	if scr.LastTS != ((10*60+20)*60+30)*1000+100 {
		t.Fatalf("timestamp = %d", scr.LastTS)
	}

	// bit9 apostrophe mark on the address byte (plan_control log format)
	if !scr.FeedLine(hexLine(f7, true)) {
		t.Fatal("bit9-marked frame not decoded")
	}
	if scr.Rows[TermAddr][7] != "             Auto-On" {
		t.Fatalf("row 7 = %q", scr.Rows[TermAddr][7])
	}

	// idle poll token: no screen change
	if scr.FeedLine(hexLine(poll, false)) {
		t.Fatal("poll token must not change the screen")
	}

	r := scr.Render()
	for _, want := range []string{"Hotwater", "Auto-On", "10:20:30"} {
		if !strings.Contains(r, want) {
			t.Fatalf("render missing %q:\n%s", want, r)
		}
	}
	// box alignment: every line between the borders is exactly as wide as the
	// border, in runes (the ° glyph is multi-byte in UTF-8)
	lines := strings.Split(r, "\n")
	first := 0
	for i, l := range lines {
		if strings.HasPrefix(l, "+-") {
			first = i
			break
		}
	}
	borderW := len(lines[first])
	for _, l := range lines[first : first+9] {
		if utf8.RuneCountInString(l) != borderW {
			t.Fatalf("misaligned box line %q (%d runes, want %d)", l,
				utf8.RuneCountInString(l), borderW)
		}
	}
}

// Frames to the ESP's own session (0x1F) have no visible trailer -- the ack
// is the ESP's own TX, absent from its RX log -- and must still decode into
// the separate terminal-31 screen.
func TestEspSessionFrame(t *testing.T) {
	f := espFrame(3, "    OutsideT:   17.8")
	scr := NewScreen()
	if !scr.FeedLine(hexLine(f, true)) {
		t.Fatal("ESP-session frame not decoded")
	}
	if scr.Rows[EspAddr][3] != "    OutsideT:   17.8" {
		t.Fatalf("esp row 3 = %q", scr.Rows[EspAddr][3])
	}
	if _, ok := scr.Rows[TermAddr][3]; ok {
		t.Fatal("ESP frame must not paint the pGD screen")
	}
}

func TestChecksumRejected(t *testing.T) {
	f := textFrame(2, append([]byte("    Hotwater:   39.0"), DegreeByte, 'C'))
	f[10] ^= 0xFF // corrupt a text byte, leave CK
	scr := NewScreen()
	scr.FeedLine(hexLine(f, false))
	if _, ok := scr.Rows[TermAddr][2]; ok || scr.Bad != 1 {
		t.Fatalf("bad checksum must not paint: rows=%v bad=%d", scr.Rows, scr.Bad)
	}
}

// The analyzer selftest, ported 1:1 from the retired Python plan_timeline tool.
func TestAnalyzer(t *testing.T) {
	pre := "[12:00:00.000][D][plan_control:589][plan_ctrl]: "
	lines := []string{
		pre + "[  9] 20' 01 01 DD 01 01 20 DD 01",            // poll + unsplit tail
		pre + "[  5] 1F' 01 01 DE 01' ",                      // poll + ack
		pre + "[ 12] 20' 0C 08 01 02 13 33 82 01' 03 20 DB ", // disp + reply
		pre + "[ 12] 02' 02 01 80 00 00 01 80 00 00 00 F9 ",  // roll-call
		pre + "[ 11] 01' 1E 07 20 0D 01 AB 01' 01 20 DD ",    // keypad + reply
		pre + "[  4] 20' 01 01 DC ",                          // BAD checksum
		pre + "[  3] 01' 20 DD ",                             // short junk, bad sum
	}
	an := NewAnalyzer(15)
	for _, l := range lines {
		tsMs, declared, seq, burst, ok := ParseLine(l)
		if !ok {
			t.Fatalf("line not parsed: %q", l)
		}
		an.Feed(tsMs, declared, seq, burst)
	}
	if an.Frames != 9 {
		t.Fatalf("frames = %d, want 9", an.Frames)
	}
	if an.FailCount != 2 {
		t.Fatalf("failCount = %d, want 2", an.FailCount)
	}
	if got := an.PerAddr(0x20); got == nil || got[0] != 3 || got[1] != 1 {
		t.Fatalf("perAddr[0x20] = %v", got)
	}

	// classification of a split display burst
	burst := []Tok{
		{0x20, true}, {0x0C, false}, {0x08, false}, {0x01, false},
		{0x02, false}, {0x13, false}, {0x33, false}, {0x82, false},
		{0x01, true}, {0x03, false}, {0x20, false}, {0xDB, false},
	}
	frames, _ := SplitFrames(burst)
	if len(frames) != 2 || Classify(frames[0]) != "disp" || Classify(frames[1]) != "reply" {
		t.Fatalf("SplitFrames/Classify = %d frames, %s/%s",
			len(frames), Classify(frames[0]), Classify(frames[1]))
	}

	// both checksum grammars
	if !ChecksumOK([]byte{0x01, 0x1E, 0x07, 0x20, 0x0D, 0x01, 0xAB}) {
		t.Fatal("sum-to-0xFF keypad frame must pass")
	}
	if ChecksumOK([]byte{0x20, 0x01, 0x01, 0xDC}) {
		t.Fatal("bad sum must fail")
	}
	// real 0x66 session frame from the 2026-07-02 capture: CRC-16/Modbus LE
	if !ChecksumOK([]byte{0x20, 0x66, 0x08, 0x01, 0x00, 0x01, 0x9D, 0x13}) {
		t.Fatal("CRC-16/Modbus session frame must pass")
	}
}

// mkGraphic builds a valid 0x64 graphic-bitmap frame in the captured wire
// grammar: ADDR 64 LEN 01 <7 misc bytes> x,y,w,h (16-bit BE) <pixels> CRC16LE.
func mkGraphic(addr byte, y, w, h int, fill byte, npx int) []byte {
	f := []byte{addr, 0x64, 0, 0x01, 0x04, 0x04, 0x00, byte(npx), 0x00, 0x00, 0x00,
		0x00, 0x12, byte(y >> 8), byte(y), byte(w >> 8), byte(w), byte(h >> 8), byte(h)}
	for i := 0; i < npx; i++ {
		f = append(f, fill)
	}
	f[2] = byte(len(f) + 2) // LEN counts the whole frame incl. CRC
	crc := CRC16Modbus(f)
	return append(f, byte(crc), byte(crc>>8))
}

func feedRaw(s *Screen, f []byte) {
	burst := make([]Tok, len(f))
	for i, b := range f {
		burst[i] = Tok{b, i == 0}
	}
	s.Feed(1000, len(burst), 0, burst)
}

// The pGD paints menu selection as an inverse-video graphics band. The screen
// must parse CRC16-checksummed 0x64 frames to terminal 31, classify a lit
// band as inverse, a dark repaint as deselect, and reset on session init.
func TestGraphicSelection(t *testing.T) {
	s := NewScreen()
	// a text row 2 + selected band at y=16 (rows 2..3), real menu geometry
	feedRaw(s, []byte{0x1F, 0x0B, 0x08, 0x01, 0x02, 0x41, 0x42, 0x47}) // sums to 0xFF
	feedRaw(s, mkGraphic(0x1F, 16, 114, 16, 0xFF, 30))
	if s.Rows[0x1F][2] != "AB" {
		t.Fatalf("text row lost: %q", s.Rows[0x1F][2])
	}
	if !s.RowInverse(0x1F, 2) || !s.RowInverse(0x1F, 3) || s.RowInverse(0x1F, 4) {
		t.Fatalf("inverse band y=16 h=16 must cover rows 2-3 only: %v", s.Bands[0x1F])
	}
	// selection moves away: same band repainted dark
	feedRaw(s, mkGraphic(0x1F, 16, 114, 16, 0x00, 30))
	if s.RowInverse(0x1F, 2) {
		t.Fatal("dark repaint must deselect the band")
	}
	// icons (narrow) and huge bands must be ignored
	feedRaw(s, mkGraphic(0x1F, 16, 18, 16, 0xFF, 30))
	feedRaw(s, mkGraphic(0x1F, 0, 132, 64, 0xFF, 30))
	if s.RowInverse(0x1F, 2) || s.RowInverse(0x1F, 0) {
		t.Fatal("icon/full-screen frames must not mark inverse bands")
	}
	// 0x65 page sync: the burst after it is a DELTA (live ground
	// truth: D01->D02 repainted only changed rows), so rows must survive;
	// body bands clear like on any page turn.
	feedRaw(s, mkGraphic(0x1F, 16, 114, 16, 0xFF, 30))
	feedRaw(s, []byte{0x1F, 0x65, 0x0F, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0xC9, 0xB9})
	if s.Rows[0x1F][2] != "AB" {
		t.Fatalf("0x65 must keep rows (delta repaint follows): %v", s.Rows[0x1F])
	}
	if s.RowInverse(0x1F, 2) {
		t.Fatal("0x65 must clear body bands")
	}
}

// Band lifecycle: a missed dark repaint must never leave two selections
// (newest lit band below the title bar wins), and a page transition
// (row-0 text change) clears body bands while keeping the title band.
func TestBandLifecycle(t *testing.T) {
	s := NewScreen()
	row0 := func(text string) []byte {
		body := append([]byte{0x1F, TypeText, byte(len(text) + 6), 0x01, 0x00}, text...)
		sum := 0
		for _, b := range body {
			sum += int(b)
		}
		return append(body, byte(0xFF-sum&0xFF))
	}

	// title band + selection on rows 2-3
	feedRaw(s, mkGraphic(0x1F, 0, 132, 8, 0xFF, 30))
	feedRaw(s, mkGraphic(0x1F, 16, 114, 16, 0xFF, 30))
	// selection moves to rows 4-5 but the dark repaint of 16 was LOST:
	// only the new lit band arrives
	feedRaw(s, mkGraphic(0x1F, 32, 114, 16, 0xFF, 30))
	if s.RowInverse(0x1F, 2) || !s.RowInverse(0x1F, 4) {
		t.Fatalf("newest lit band must win below the title bar: %v", s.Bands[0x1F])
	}
	if !s.RowInverse(0x1F, 0) {
		t.Fatal("title band must survive a selection move")
	}

	// page transition: row 0 changes -> body bands go, title band stays
	feedRaw(s, row0("Main menu          1/8"))
	if s.RowInverse(0x1F, 4) {
		t.Fatalf("page transition must clear body bands: %v", s.Bands[0x1F])
	}
	if !s.RowInverse(0x1F, 0) {
		t.Fatal("page transition must keep the title band")
	}

	// same row-0 text repainted again is NOT a transition: bands stay
	feedRaw(s, mkGraphic(0x1F, 16, 114, 16, 0xFF, 30))
	feedRaw(s, row0("Main menu          1/8"))
	if !s.RowInverse(0x1F, 2) {
		t.Fatal("identical row-0 repaint must not clear bands")
	}
}

// A burst whose printed bytes fall short of the declared [ N] count is
// logger-truncated: its last frame must not be checksum-judged.
func TestTruncatedBurst(t *testing.T) {
	an := NewAnalyzer(15)
	l := "[12:00:00.000][D][plan_control:589][plan_ctrl]: [182] 20' 64 95 01 00 80 00 80 01 00 00 00 00 00 00 00 84 00 08 FF FF"
	tsMs, declared, seq, burst, _ := ParseLine(l)
	an.Feed(tsMs, declared, seq, burst)
	if an.FailCount != 0 {
		t.Fatalf("truncated frame counted as failure: %d", an.FailCount)
	}
}

// SetCell: the 0x0C ROW COL CHAR grammar (proven live 2026-07-03) must
// paint single cells into existing rows, pad short rows, and reject
// out-of-range coordinates.
func TestSetCell(t *testing.T) {
	s := NewScreen()
	if !s.SetCell(EspAddr, 4, 19, '1') {
		t.Fatal("cell into empty row must paint")
	}
	if got := s.Rows[EspAddr][4]; got != "                   1" {
		t.Fatalf("padded row: %q", got)
	}
	s.Rows[EspAddr][4] = "Domestic:       39.0" + "\u00b0" + "C"
	if !s.SetCell(EspAddr, 4, 19, '1') {
		t.Fatal("digit change must report changed")
	}
	if got := s.Rows[EspAddr][4]; !strings.Contains(got, "39.1") {
		t.Fatalf("39.0 -> 39.1 expected, got %q", got)
	}
	if s.SetCell(EspAddr, 4, 19, '1') {
		t.Fatal("same char must report unchanged")
	}
	if s.SetCell(EspAddr, 8, 0, 'x') || s.SetCell(EspAddr, 0, 22, 'x') {
		t.Fatal("out-of-range cell must be rejected")
	}
}

// The firmware numbers its capture lines ([#seq|N]); the analyzer must parse
// the format, count seq gaps as dropped log lines, rebase on a firmware
// reboot, and surface the totals in the report.
func TestSeqGaps(t *testing.T) {
	an := NewAnalyzer(15)
	feed := func(seqN int) {
		l := fmt.Sprintf("[12:00:00.000][D][plan_control:589][plan_ctrl]: [#%d|  4] 20' 01 01 DD ", seqN)
		tsMs, declared, seq, burst, ok := ParseLine(l)
		if !ok || seq != seqN || declared != 4 || len(burst) != 4 {
			t.Fatalf("ParseLine(%q) = ts=%d declared=%d seq=%d burst=%d ok=%v",
				l, tsMs, declared, seq, len(burst), ok)
		}
		an.Feed(tsMs, declared, seq, burst)
	}
	feed(1)
	feed(2)
	feed(5) // lines 3 and 4 lost
	if an.SeqGaps != 1 || an.LostLines != 2 {
		t.Fatalf("seqGaps=%d lostLines=%d, want 1/2", an.SeqGaps, an.LostLines)
	}
	feed(1) // firmware reboot: rebase, no gap
	feed(2)
	if an.SeqGaps != 1 || an.LostLines != 2 || an.LastSeq != 2 {
		t.Fatalf("after reboot: seqGaps=%d lostLines=%d lastSeq=%d", an.SeqGaps, an.LostLines, an.LastSeq)
	}
	if out := an.AddrTable(); !strings.Contains(out, "2 capture lines lost in 1 gaps") {
		t.Fatalf("report lacks capture-transport loss:\n%s", out)
	}
}

// A capture seq gap during repaint activity must flag the affected screen
// stale (the lost lines carried display frames; rows/bands are silently
// missing), a gap on the idle bus must not, a repaint continuing right
// after a gap must, and ClearStale (session refresh) recovers.
func TestSeqGapStale(t *testing.T) {
	line := func(seq, tsMs int, hex string) string {
		return fmt.Sprintf("[%02d:%02d:%02d.%03d][plan_cap]: [#%d|%3d] %s",
			tsMs/3600000, tsMs/60000%60, tsMs/1000%60, tsMs%1000,
			seq, len(strings.Fields(hex)), hex)
	}
	paint := hexLine(espFrame(2, "Heating:        10.0"), true)
	poll := "20' 01 01 DD"

	// gap right after a repaint: mid-repaint loss, stale
	s := NewScreen()
	s.FeedLine(line(1, 1000, paint))
	s.FeedLine(line(2, 1100, poll))
	if len(s.Stale) != 0 {
		t.Fatalf("no gap yet, stale=%v", s.Stale)
	}
	s.FeedLine(line(4, 1200, poll)) // line 3 lost, 100 ms after the paint
	if !s.Stale[EspAddr] {
		t.Fatalf("gap during repaint must flag stale, stale=%v", s.Stale)
	}
	if out := s.Render(); !strings.Contains(out, "STALE: repaint lost") {
		t.Fatalf("render lacks the stale marker:\n%s", out)
	}
	s.ClearStale(EspAddr)
	if len(s.Stale) != 0 || !strings.Contains(s.Render(), "Heating") {
		t.Fatalf("ClearStale must drop the flag and keep rows, stale=%v", s.Stale)
	}

	// gap on the idle bus: nothing mid-repaint, not stale -- but a repaint
	// continuing right after the gap means the gap fell inside it
	s = NewScreen()
	s.FeedLine(line(1, 1000, paint))
	s.FeedLine(line(5, 60000, poll)) // 59 s idle before the gap
	if len(s.Stale) != 0 {
		t.Fatalf("idle gap must not flag stale, stale=%v", s.Stale)
	}
	s.FeedLine(line(6, 60200, paint)) // repaint resumes 200 ms after the gap
	if !s.Stale[EspAddr] {
		t.Fatalf("repaint right after a gap must flag stale, stale=%v", s.Stale)
	}
}

// Bursts without bit9 marks (plan_capture format) cannot be split into
// frames and must be skipped by the analyzer, not misjudged.
func TestNoBit9Skipped(t *testing.T) {
	an := NewAnalyzer(15)
	tsMs, declared, seq, burst, _ := ParseLine(
		"[12:00:00.000][D][plan_capture:086]: [  9] 20 01 01 DD 01 01 20 DD 01")
	an.Feed(tsMs, declared, seq, burst)
	if an.Frames != 0 || an.NoBit9() != 1 {
		t.Fatalf("frames=%d noBit9=%d, want 0/1", an.Frames, an.NoBit9())
	}
}
