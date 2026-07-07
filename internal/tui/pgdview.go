package tui

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/teemow/planscope/internal/plan"
	"github.com/teemow/planscope/internal/style"
)

// pGD1 physical key order, left to right.
var keycaps = []struct {
	code  byte
	label string
}{
	{plan.KeyAlarm, "ALRM"}, {plan.KeyPrg, "PRG"}, {plan.KeyEsc, "ESC"},
	{plan.KeyUp, "▲"}, {plan.KeyEnter, "↵"}, {plan.KeyDown, "▼"},
}

func centerIn(s string, w int) string {
	pad := w - style.VisLen(s)
	if pad < 0 {
		return s
	}
	l := pad / 2
	return strings.Repeat(" ", l) + s + strings.Repeat(" ", pad-l)
}

// screenView draws one terminal centered in a pane of width w, styled as a
// pGD: a gray bezel around the blue-backlit LCD, with the six physical keys
// as keycaps below (the injected key flashes). While enrolled (or armed) it
// shows the ESP's own session (0x1F) -- that is the screen injected keys
// navigate and it stays live for the whole session; otherwise it shows the
// pGD's (0x20), because the ESP session freezes on disenroll and would only
// ever be stale.
func (a *app) screenView(w int) string {
	s := a.scr
	addr := byte(plan.TermAddr)
	if (a.armed || a.enrolled) && len(s.Rows[plan.EspAddr]) > 0 {
		addr = plan.EspAddr
	}
	rows := s.Rows[addr]
	width, nRows := plan.MinWidth, plan.MinRows
	for r, t := range rows {
		if n := utf8.RuneCountInString(t); n > width {
			width = n
		}
		if r+1 > nRows {
			nRows = r + 1
		}
	}
	// keycap row first: the bezel must fit both it and the LCD
	var caps strings.Builder
	for i, k := range keycaps {
		if i > 0 {
			caps.WriteString(style.S(style.Bezel, "  "))
		}
		st := style.Keycap
		if a.lastKey == k.code && time.Since(a.lastKeyAt) < time.Second {
			st = style.KeyHit
		}
		caps.WriteString(style.S(st, " "+k.label+" "))
	}
	capsW := style.VisLen(caps.String())

	lcdW := width + 2 // one LCD cell of padding each side
	bezW := max(lcdW+8, capsW+4)
	if (bezW-lcdW)%2 != 0 {
		bezW++ // keep the LCD inset symmetric
	}
	ind := ""
	if m := (w - bezW) / 2; m > 0 {
		ind = strings.Repeat(" ", m)
	}
	bez := func(inner string) string { return ind + style.S(style.Bezel, inner) }
	blank := strings.Repeat(" ", bezW)
	lcdInset := (bezW - lcdW) / 2

	var b []string
	b = append(b, "", ind+centerIn(style.S(style.Dim, plan.TermName(addr)), bezW), bez(blank))
	for r := 0; r < nRows; r++ {
		t := []rune(rows[r])
		if len(t) > width {
			t = t[:width]
		}
		cell := " " + string(t) + strings.Repeat(" ", width-len(t)) + " "
		st := style.LCD
		if s.RowInverse(addr, r) {
			st = style.LCDInv // selected menu item / title bar
		}
		lcd := style.S(st, cell)
		if len(rows) == 0 && r == nRows/2 {
			// nothing painted yet: the controller only repaints changed rows
			lcd = style.S(style.LCDDim, centerIn("waiting for row repaints", lcdW))
		}
		b = append(b, ind+style.S(style.Bezel, strings.Repeat(" ", lcdInset))+lcd+
			style.S(style.Bezel, strings.Repeat(" ", bezW-lcdInset-lcdW)))
	}
	b = append(b, bez(blank))
	capPad := bezW - capsW
	l := capPad / 2
	b = append(b, ind+style.S(style.Bezel, strings.Repeat(" ", l))+caps.String()+
		style.S(style.Bezel, strings.Repeat(" ", capPad-l)))
	b = append(b, bez(blank), "")

	fresh := ""
	if p, ok := s.Painted[addr]; ok && s.LastTS >= 0 {
		age := (s.LastTS - p) / 1000
		if age < 0 {
			age = 0
		}
		fresh = style.S(style.Dim, fmt.Sprintf(" · repainted %ds ago", age))
		if age > 30 {
			fresh = style.S(style.Yellow, fmt.Sprintf(" · STALE: repainted %ds ago", age))
		}
	}
	if s.Stale[addr] {
		fresh += style.S(style.Red, " · STALE: repaint lost in a seq gap")
	}
	meta := fmt.Sprintf("%s %s %s %d %s%s", style.S(style.Dim, "last frame"), plan.FmtTS(s.LastTS),
		style.S(style.Dim, "· display frames"), s.Frames, style.S(style.Dim, fmt.Sprintf("(bad %d)", s.Bad)), fresh)
	b = append(b, ind+centerIn(meta, bezW))
	b = append(b, "")
	for _, c := range s.Changes {
		who := "pGD"
		if c.Addr == plan.EspAddr {
			who = "ESP"
		}
		line := fmt.Sprintf("%s  %s %s", style.S(style.Gray, plan.FmtTS(c.TS)),
			style.S(style.Yellow, fmt.Sprintf("%s row %d", who, c.Row)), strings.TrimSpace(c.Text))
		b = append(b, ind+"  "+line)
	}
	return strings.Join(b, "\n")
}
