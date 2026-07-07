package decode

// The plan_decode.py --selftest, ported 1:1: synthesise pLAN-like frames
// with a known grammar and assert the workbench recovers it.

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"

	"github.com/teemow/planscope/internal/plan"
)

// buildSynth builds the synthetic selftest grammar:
// [DELIM=0x20][ADDR][LEN][payload...][crc16_modbus LE], LEN = total frame
// length, checksum spans everything after the delimiter.
func buildSynth(addr byte, payload []byte) []byte {
	total := 3 + len(payload) + 2
	body := append([]byte{0x20, addr, byte(total)}, payload...)
	crc := crcGeneric(body[1:], 16, 0x8005, 0xFFFF, true, true, 0)
	return append(body, byte(crc), byte(crc>>8))
}

func synthFrames(rng *rand.Rand) [][]byte {
	var frames [][]byte
	poll := buildSynth(0x20, []byte{0x01, 0x01})
	for i := 0; i < 40; i++ {
		frames = append(frames, poll)
	}
	for i := 0; i < 40; i++ {
		payload := make([]byte, 20)
		rng.Read(payload)
		frames = append(frames, buildSynth(0x20, payload))
	}
	return frames
}

func TestDecodeChecksumRecovery(t *testing.T) {
	frames := synthFrames(rand.New(rand.NewSource(1)))
	hits := searchChecksum(frames)
	if len(hits) == 0 {
		t.Fatal("checksum search found nothing")
	}
	top := hits[0]
	if top.name != "crc16_modbus" || top.dataStart != 1 || !top.le || top.frac() != 1.0 {
		t.Fatalf("top hit = %+v", top)
	}
}

func TestDecodeLengthAndDelimiter(t *testing.T) {
	frames := synthFrames(rand.New(rand.NewSource(1)))
	found := false
	for _, lf := range guessLengthField(frames) {
		if lf.off == 2 && lf.frac > 0.9 {
			found = true
		}
	}
	if !found {
		t.Fatal("length field not found at offset 2")
	}
	addr := addressCandidates(frames, 3)
	if len(addr[0].c) != 1 || addr[0].c[0x20] == 0 {
		t.Fatalf("delimiter not detected: %v", addr[0].c)
	}
}

func TestDecodeDirectionSplit(t *testing.T) {
	frames := synthFrames(rand.New(rand.NewSource(1)))
	short, long := classifyDirection(frames)
	if len(short) == 0 || len(long) == 0 {
		t.Fatalf("direction split: short=%d long=%d", len(short), len(long))
	}
}

func TestDecodeCorrelate(t *testing.T) {
	frames := synthFrames(rand.New(rand.NewSource(1)))
	keyFrame := buildSynth(0x20, []byte{0x01, 0x42})
	variant := append(append([][]byte{}, frames...),
		keyFrame, keyFrame, keyFrame, keyFrame, keyFrame)
	newFrames, _ := correlateFrames(frames, variant)
	for _, nf := range newFrames {
		if nf.sig == string(keyFrame) {
			return
		}
	}
	t.Fatal("correlation missed the injected key frame")
}

func TestDecodeRegroup(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	sumTo := func(target, length int) []byte {
		body := make([]byte, length-1)
		rng.Read(body)
		return append(body, byte((target-sum(body))&0xFF))
	}
	var merged []byte
	lens := []int{6, 9, 12}
	for i := 0; i < 50; i++ {
		merged = append(merged, sumTo(0xFF, lens[rng.Intn(3)])...)
	}
	atoms, junk := RegroupByChecksum(merged, []int{6, 9, 12}, map[int]bool{0xFF: true})
	if junk != 0 {
		t.Fatalf("regroup left %d unparsed bytes", junk)
	}
	if !bytes.Equal(Reassemble(atoms), merged) {
		t.Fatal("regroup did not reproduce the stream")
	}
	for _, a := range atoms {
		if sum(a)&0xFF != 0xFF {
			t.Fatal("regroup split mid-frame")
		}
	}
}

func TestDecodeParser(t *testing.T) {
	sample := "[21:30:01][D][plan_capture:086]: [ 18] 20 01 01 DD 01 01 20 DD 01\n" +
		"# a comment line\n" +
		"20 0C 08 01 03 13 34 80 01 03 20 DB\n"
	pf := ParseFramesText(sample)
	if len(pf) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(pf))
	}
	if pf[0][0] != 0x20 || pf[0][3] != 0xDD {
		t.Fatal("bad parse")
	}
	if len(pf[0]) != 9 || len(pf[1]) != 12 {
		t.Fatal("length prefix leaked")
	}
}

func TestDecodeDisplayRecords(t *testing.T) {
	mergedLine := "[02:03:04.500][D][plan_capture:102]: [ 21] " +
		"20 0C 08 01 02 13 37 7E 01 03 20 DB " +
		"20 01 01 DD 01 01 20 DD 01\n"
	tl := ParseTimedText(mergedLine)
	if len(tl) == 0 || tl[0].tsMs != ((2*60+3)*60+4)*1000+500 {
		t.Fatalf("timestamp parse: %+v", tl)
	}
	recs := findDisplayRecords(tl[0].data)
	if len(recs) != 1 || recs[0] != (displayRec{0x02, 0x1337, true}) {
		t.Fatalf("record decode wrong: %+v", recs)
	}
	// a corrupted value byte with the old CK must flip ok to false
	bad, _ := hexToBytes("200C08010213387E010320DB")
	badRec := findDisplayRecords(bad)
	if len(badRec) == 0 || badRec[0].ok {
		t.Fatal("checksum should have failed")
	}
}

func hexToBytes(s string) ([]byte, int) {
	var out []byte
	for i := 0; i+2 <= len(s); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'A' && c <= 'F':
				b |= c - 'A' + 10
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			}
		}
		out = append(out, b)
	}
	return out, len(out)
}

func TestDecodeBurstDetector(t *testing.T) {
	rec, _ := hexToBytes("200C08010213377E010320DB") // selector 02, 0x1337
	var timed []timedLine
	for i := 0; i < 20; i++ { // quiet baseline: bytes but zero records
		timed = append(timed, timedLine{1000 + i*300, make([]byte, 200)})
	}
	var redraw []byte
	for i := 0; i < 5; i++ {
		redraw = append(redraw, rec...)
	}
	timed = append(timed, timedLine{10000, redraw})
	hot := detectBursts(timed, 300, 3.0, 3)
	if len(hot) != 1 || hot[0].tMs != (10000/300)*300 || len(hot[0].records) != 5 {
		t.Fatalf("burst miss: %+v", hot)
	}
}

// textFrame builds a valid controller->terminal text-row frame:
// 20 0B LEN 01 ROW <text...> CK | 01 03 20 DB
func textFrame(row byte, text []byte) []byte {
	body := append([]byte{plan.TermAddr, plan.TypeText, byte(5 + len(text) + 1), 0x01, row}, text...)
	s := 0
	for _, b := range body {
		s += int(b)
	}
	body = append(body, byte(0xFF-s&0xFF))
	return append(body, plan.Trailer...)
}

func TestDecodeTextFrameEnvelope(t *testing.T) {
	tf := textFrame(2, append([]byte("    Hotwater:   39.0"), plan.DegreeByte, 'C'))
	poll, _ := hexToBytes("200101DD010120DD01")
	frames := plan.ParseDisplayFrames(append(append([]byte{}, tf...), poll...))
	if len(frames) != 1 || frames[0].Typ != plan.TypeText || !frames[0].OK {
		t.Fatalf("text frame not decoded: %+v", frames)
	}
	if frames[0].Payload[0] != 2 {
		t.Fatal("row byte wrong")
	}
	if got := plan.RowText(frames[0].Payload[1:]); got != "    Hotwater:   39.0°C" {
		t.Fatalf("text decode wrong: %q", got)
	}
	corrupt := append([]byte{}, tf...)
	corrupt[10] ^= 0xFF
	if fr := plan.ParseDisplayFrames(corrupt); len(fr) == 0 || fr[0].OK {
		t.Fatal("corrupted text frame should fail checksum")
	}
}

// The report renderers must not panic and must carry their key content on a
// real-shaped capture (merged lines, timestamps, comments).
func TestDecodeReports(t *testing.T) {
	// smoke: ReportAnalyze / ReportRecords / ReportScreen / ReportBursts all
	// print to stdout; just exercise the pure helpers they depend on
	frames := synthFrames(rand.New(rand.NewSource(1)))
	if lag, _ := autocorrelationPeriod(frames, 64); lag == 0 {
		t.Fatal("autocorrelation found no period")
	}
	if got := plausibleScale(3900, 4100); !strings.Contains(got, "x0.01") {
		t.Fatalf("plausibleScale = %q", got)
	}
	if got := plausibleScale(1<<15, 1<<15); got != "?" {
		t.Fatalf("plausibleScale = %q", got)
	}
}
