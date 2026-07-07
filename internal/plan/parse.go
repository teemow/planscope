// Package plan implements the pLAN protocol layer: parsing capture log
// lines, splitting bursts into frames at the bit9 address marks, both
// checksum grammars (sum-to-0xFF classic frames, CRC-16/Modbus LE on the
// 0x64/0x65/0x66 graphic/session frames), frame classification, the screen
// reconstructor, and the traffic analyzer.
//
// Frame grammar (reverse-engineered; see the planterm protocol reference,
// github.com/teemow/planterm docs/protocol.md). Every controller->terminal
// display frame is
//
//	20 TYPE LEN 01 <payload...> CK   01 03 20 DB
//
// where LEN counts bytes [0..CK] and CK makes sum(bytes[0..LEN-1]) == 0xFF
// mod 256. TYPE 0x0B is a text row: payload = <ROW> <ASCII chars...>.
package plan

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Tok is one captured bus byte with its bit9 address mark.
type Tok struct {
	B    byte
	Bit9 bool
}

var (
	ansiRe  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	tsRe    = regexp.MustCompile(`\[(\d{2}):(\d{2}):(\d{2})\.(\d{3})\]`)
	countRe = regexp.MustCompile(`\[\s*(\d+)\]`)         // legacy [ N] burst byte count
	seqRe   = regexp.MustCompile(`\[#(\d+)\|\s*(\d+)\]`) // firmware [#seq|N]: log-line seq + byte count
	brackRe = regexp.MustCompile(`\[[^\]]*\]`)           // timestamps, levels, tags, [ len ]
	hexRe   = regexp.MustCompile(`^([0-9A-Fa-f]{2})(')?$`)
)

// SnapTag marks a screen-snapshot replay line (seq-0 capture record): real
// wire bytes, but replayed state rather than live traffic -- consumers feed
// them to the screen reconstructor and keep them out of the analyzer's
// traffic/loss statistics.
const SnapTag = "[plan_snap]"

// IsSnapshotLine reports whether a capture line is a snapshot replay.
func IsSnapshotLine(line string) bool { return strings.Contains(line, SnapTag) }

// ParseLine extracts from one log line: the timestamp (ms since midnight,
// wall clock when the line has none -- native-API lines don't), the declared
// burst byte count (0 if absent), the firmware log-line sequence number
// ([#seq|N] capture lines; 0 = none), and the hex tokens with their bit9
// marks. ok is false when the line carries no hex bytes at all.
func ParseLine(raw string) (tsMs, declared, seq int, burst []Tok, ok bool) {
	line := ansiRe.ReplaceAllString(raw, "")
	tsMs = -1
	if m := tsRe.FindStringSubmatch(line); m != nil {
		h, _ := strconv.Atoi(m[1])
		mi, _ := strconv.Atoi(m[2])
		sec, _ := strconv.Atoi(m[3])
		ms, _ := strconv.Atoi(m[4])
		tsMs = ((h*60+mi)*60+sec)*1000 + ms
	}
	if m := seqRe.FindStringSubmatch(line); m != nil {
		seq, _ = strconv.Atoi(m[1])
		declared, _ = strconv.Atoi(m[2])
	} else if m := countRe.FindStringSubmatch(line); m != nil {
		declared, _ = strconv.Atoi(m[1])
	}
	for _, t := range strings.Fields(brackRe.ReplaceAllString(line, " ")) {
		if m := hexRe.FindStringSubmatch(t); m != nil {
			b, _ := strconv.ParseUint(m[1], 16, 8)
			burst = append(burst, Tok{byte(b), m[2] == "'"})
		}
	}
	if len(burst) == 0 {
		return 0, 0, 0, nil, false
	}
	if tsMs < 0 {
		now := time.Now()
		tsMs = (now.Hour()*3600+now.Minute()*60+now.Second())*1000 +
			now.Nanosecond()/1e6
	}
	return tsMs, declared, seq, burst, true
}

// RowText renders a text-row payload; CAREL uses 0xDF for the degree glyph.
func RowText(bs []byte) string {
	var sb strings.Builder
	for _, c := range bs {
		switch {
		case c == DegreeByte:
			sb.WriteRune('°')
		case c >= 0x20 && c < 0x7F:
			sb.WriteByte(c)
		default:
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

// FmtTS formats ms-since-midnight as HH:MM:SS.
func FmtTS(ms int) string {
	if ms < 0 {
		return "--:--:--"
	}
	s := ms / 1000
	return fmt.Sprintf("%02d:%02d:%02d", s/3600, s/60%60, s%60)
}

// FmtTSms formats ms-since-midnight as HH:MM:SS.mmm.
func FmtTSms(ms int) string {
	if ms < 0 {
		return "--:--:--.---"
	}
	return fmt.Sprintf("%s.%03d", FmtTS(ms), ms%1000)
}
