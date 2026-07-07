package plan

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// StaleWindowMs: a capture-stream seq gap within this window of repaint
// activity (paint just before OR just after the gap) means the lost lines
// probably carried display frames -- the reconstruction may silently miss
// rows or bands, so that screen is flagged stale instead. Deliberately
// wider than the settle quiet window (600 ms): erring wide only risks a
// spurious recovery refresh, erring narrow misses real loss.
const StaleWindowMs = 1500

// Change is one recent row repaint.
type Change struct {
	TS   int
	Addr byte
	Row  int
	Text string
}

// Band is one horizontal graphics band the controller painted: inverse
// video (mostly-lit pixels) or not, and its pixel height.
type Band struct {
	Inverse bool
	H       int
}

// Screen accumulates the byte stream into the current screen state of BOTH
// terminals: the pGD (0x20) and, while the ESP is enrolled, the controller
// also paints the ESP's own private session (0x1F) -- that one is what our
// injected keys navigate, so it is the screen that matters when armed.
type Screen struct {
	Rows    map[byte]map[int]string // per terminal address
	Bands   map[byte]map[int]Band   // per terminal: pixel-band y -> band
	Painted map[byte]int            // last repaint (ms) per terminal
	Frames  int
	Bad     int
	Changes []Change // last few row repaints
	buf     []byte   // unconsumed byte stream (frames span log lines)
	LastTS  int      // ms since midnight, -1 = unknown

	// seq-gap staleness: a capture-line seq gap during repaint activity
	// means lost display frames -- that terminal's reconstruction may
	// silently miss rows/bands until an authoritative repaint
	// (session refresh) clears the flag.
	Stale   map[byte]bool
	lastSeq int // last capture-line seq (0 = stream carries none)
	gapTS   int // ts of the last seq gap, -1 = none yet
}

// NewScreen returns an empty reconstruction.
func NewScreen() *Screen {
	return &Screen{Rows: map[byte]map[int]string{}, Bands: map[byte]map[int]Band{},
		Painted: map[byte]int{}, Stale: map[byte]bool{},
		LastTS: -1, gapTS: -1}
}

// ClearStale drops the seq-gap stale flag -- only after an authoritative
// full repaint (enroll toggle), never on ordinary deltas: a delta repaints
// only rows the CONTROLLER changed, so a row lost in the gap stays wrong.
func (s *Screen) ClearStale(addr byte) {
	delete(s.Stale, addr)
}

// clearBodyBands drops every graphics band below the title bar. Called on a
// page transition (row-0 text change): the new page repaints its own bands,
// and a selection band whose dark repaint was lost in the log stream must
// not survive onto the next page as a phantom highlight. Title-bar bands
// (y < 8) stay -- the status screen repaints row 0 every minute without
// touching its title band.
func (s *Screen) clearBodyBands(addr byte) {
	for y := range s.Bands[addr] {
		if y >= TitleBarPx {
			delete(s.Bands[addr], y)
		}
	}
}

// SetCell paints one character cell (a 0x0C ROW COL CHAR frame); reports
// whether the visible text changed. A cell update into a never-painted row
// lands on spaces -- the controller only sends these against a screen it
// already drew, so that covers reconnects mid-page.
func (s *Screen) SetCell(addr byte, row, col int, ch byte) bool {
	if row < 0 || row >= 8 || col < 0 || col >= MinWidth {
		return false
	}
	if s.Rows[addr] == nil {
		s.Rows[addr] = map[int]string{}
	}
	r := []rune(s.Rows[addr][row])
	for len(r) <= col {
		r = append(r, ' ')
	}
	r[col] = []rune(RowText([]byte{ch}))[0]
	text := string(r)
	if s.Rows[addr][row] == text {
		return false
	}
	s.Rows[addr][row] = text
	return true
}

// RowInverse reports whether a text row is covered by an inverse-video
// graphics band (the pGD paints menu selection and title bars this way).
func (s *Screen) RowInverse(addr byte, row int) bool {
	for y, b := range s.Bands[addr] {
		if b.Inverse && row >= y/8 && row < (y+b.H+7)/8 {
			return true
		}
	}
	return false
}

// feedGraphic digests one 0x64 graphic-bitmap frame. Ground truth (menu
// navigation capture 2026-07-02): payload = 7 unknown/fragmentation bytes,
// then x,y,w,h as 16-bit BE, then vertical-byte pixel data. The pGD renders
// menu selection (and title bars) as inverse-video bands: a band painted
// mostly-lit is inverse, mostly-dark is normal. Track that per band-y so the
// TUI can highlight the selected menu item.
// ponytail: fragment 2+ of a split band carries the same x/y/w/h, so
// last-writer-wins per y is fine -- fragments of an inverse band are all
// FF-heavy anyway.
func (s *Screen) feedGraphic(addr byte, payload []byte) {
	if len(payload) < 16 {
		return
	}
	y := int(payload[9])<<8 | int(payload[10])
	w := int(payload[11])<<8 | int(payload[12])
	h := int(payload[13])<<8 | int(payload[14])
	if w < 40 || h < 8 || h > 32 || y > 64 {
		return // icons / large-font fragments, not a row band
	}
	px := payload[15:]
	set := 0
	for _, b := range px {
		for ; b != 0; b &= b - 1 {
			set++
		}
	}
	if s.Bands[addr] == nil {
		s.Bands[addr] = map[int]Band{}
	}
	b := Band{Inverse: set*2 > len(px)*8, H: h}
	// Menu invariant: below the title bar at most one band is lit -- the
	// selection. The controller moves it by painting the old band dark and
	// the new one lit; when the dark repaint is lost (log-line drop), the
	// stale band would show two selections forever. Newest lit band wins.
	if b.Inverse && y >= TitleBarPx {
		for y2, b2 := range s.Bands[addr] {
			if y2 != y && y2 >= TitleBarPx && b2.Inverse {
				delete(s.Bands[addr], y2)
			}
		}
	}
	s.Bands[addr][y] = b
}

// FeedLine ingests one log line; reports whether the visible screen changed.
func (s *Screen) FeedLine(raw string) bool {
	tsMs, declared, seq, burst, ok := ParseLine(raw)
	if !ok {
		return false
	}
	return s.Feed(tsMs, declared, seq, burst)
}

// Feed ingests one burst; declared is the logger's [ N] pair count, used to
// detect logger-truncated lines (declared > len(burst)); seq is the capture
// line number (0 = none) -- a jump marks screens mid-repaint as stale.
func (s *Screen) Feed(tsMs, declared, seq int, burst []Tok) bool {
	if seq > 0 {
		if s.lastSeq > 0 && seq > s.lastSeq+1 {
			// capture lines lost: any terminal painted within the window
			// before the gap was likely mid-repaint -- its lost frames are
			// unrecoverable, flag the reconstruction stale
			s.gapTS = tsMs
			for addr, p := range s.Painted {
				if tsMs-p < StaleWindowMs {
					s.Stale[addr] = true
				}
			}
		}
		// seq <= lastSeq = firmware reboot / fresh stream: rebase, no gap
		s.lastSeq = seq
	}
	truncated := declared > len(burst)
	if truncated {
		// logger-truncated line (ESPHome caps a log message at ~255 chars, so
		// big graphics frames lose their tail): frame continuity is broken.
		// Parse what the buffer holds, then start over.
		defer func() { s.buf = nil }()
	}
	for _, t := range burst {
		s.buf = append(s.buf, t.B)
	}
	s.LastTS = tsMs
	if truncated {
		// Salvage graphic frames whose tail was cut off: the x,y,w,h header
		// and the leading pixel bytes survive, which is all the inverse-band
		// heuristic needs. No CRC possible -- feedGraphic's geometry sanity
		// checks are the gate. (ponytail: density from a truncated pixel run;
		// selection bands are solid FF or 00, so any prefix is representative)
		for i := 0; i+24 <= len(s.buf); i++ {
			if (s.buf[i] == TermAddr || s.buf[i] == EspAddr) && s.buf[i+1] == TypeGraphic &&
				s.buf[i+3] == 0x01 && int(s.buf[i+2]) > len(s.buf)-i {
				s.feedGraphic(s.buf[i], s.buf[i+4:])
			}
		}
	}

	changed := false
	consumed := 0
	for _, fr := range ParseDisplayFrames(s.buf) {
		consumed = fr.End
		s.Frames++
		if !fr.OK {
			s.Bad++
			continue
		}
		if s.gapTS >= 0 && tsMs-s.gapTS < StaleWindowMs {
			// display frames continuing right after a seq gap: the gap fell
			// inside this repaint, part of it is lost
			s.Stale[fr.Addr] = true
		}
		s.Painted[fr.Addr] = tsMs
		switch {
		case fr.Typ == TypeText && len(fr.Payload) > 0:
			row := int(fr.Payload[0])
			text := RowText(fr.Payload[1:])
			if s.Rows[fr.Addr] == nil {
				s.Rows[fr.Addr] = map[int]string{}
			}
			if s.Rows[fr.Addr][row] != text {
				if row == 0 {
					// row-0 content change = page transition: the old
					// page's selection band must not haunt the new page
					s.clearBodyBands(fr.Addr)
				}
				s.Rows[fr.Addr][row] = text
				s.Changes = append(s.Changes, Change{tsMs, fr.Addr, row, text})
				if len(s.Changes) > 6 {
					s.Changes = s.Changes[1:]
				}
				changed = true
			}
		case fr.Typ == 0x0C && len(fr.Payload) == 3:
			// single-cell update: ROW COL CHAR -- how the controller
			// repaints one drifting digit, and the ONLY repaint an
			// edit-mode value change or a PIN digit gets (proven live
			// 2026-07-03: the B01 setpoint edit and both password gates
			// answer with these; the earlier SEL/HH/LL "numeric var"
			// reading was a misparse of exactly these frames).
			// NOT flagged as a screen change: cell updates are value
			// drift, and live pages (status, D I/O) emit them at ~1 Hz
			// forever -- counting them would keep settle-waiters from
			// ever seeing a quiet page. Readers that care about the
			// value (editValue's waitChange) watch rows directly.
			s.SetCell(fr.Addr, int(fr.Payload[0]), int(fr.Payload[1]), fr.Payload[2])
		case fr.Typ == TypeGraphic:
			s.feedGraphic(fr.Addr, fr.Payload)
			changed = true
		case fr.Typ == TypeInit:
			// 0x65 is a page-sync marker, NOT a blank-slate init: the burst
			// after it is a DELTA against the current screen (live ground
			// truth 2026-07-03: page turns repainted only the changed rows),
			// so rows must survive; body bands clear like on any page turn.
			s.clearBodyBands(fr.Addr)
			changed = true
		}
	}
	s.buf = s.buf[consumed:]
	// ponytail: poll/keepalive bytes between display frames are never
	// consumed, so cap the buffer; a display frame straddling the trim is
	// lost, which at <=200 B/frame is a once-in-hours single-row miss.
	if len(s.buf) > 8192 {
		s.buf = append([]byte(nil), s.buf[len(s.buf)-512:]...)
	}
	return changed
}

// Render draws both terminals as plain-text boxes (piped mode, exit
// scrollback).
func (s *Screen) Render() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "live screens   last frame %s   display frames %d (bad %d)\n",
		FmtTS(s.LastTS), s.Frames, s.Bad)
	// ESP's own session first when present: that's the one injected keys act
	// on. The pGD box always shows (even empty) as the passive reference.
	order := []byte{EspAddr, TermAddr}
	for _, addr := range order {
		rows := s.Rows[addr]
		if addr == EspAddr && len(rows) == 0 {
			continue
		}
		// width in runes, not bytes: the degree glyph is multi-byte in UTF-8
		width := MinWidth
		nRows := MinRows
		for r, t := range rows {
			if n := utf8.RuneCountInString(t); n > width {
				width = n
			}
			if r+1 > nRows {
				nRows = r + 1
			}
		}
		name := TermName(addr)
		if s.Stale[addr] {
			name += "   STALE: repaint lost in a seq gap"
		}
		sb.WriteString(name + "\n")
		border := "+" + strings.Repeat("-", width) + "+\n"
		sb.WriteString(border)
		for r := 0; r < nRows; r++ {
			t := []rune(rows[r])
			if len(t) > width {
				t = t[:width]
			}
			mark := "|"
			if s.RowInverse(addr, r) {
				mark = "#" // inverse-video band (selected menu item / title bar)
			}
			sb.WriteString(mark + string(t) + strings.Repeat(" ", width-len(t)) + mark + "\n")
		}
		sb.WriteString(border)
	}
	sb.WriteString("recent row changes:")
	for _, c := range s.Changes {
		fmt.Fprintf(&sb, "\n  %s  %02X row %d: %q", FmtTS(c.TS), c.Addr, c.Row,
			strings.TrimSpace(c.Text))
	}
	return sb.String()
}
