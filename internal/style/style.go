// Package style is the ANSI styling layer shared by the TUI and the
// report renderers. Everything goes through S(), which is a no-op unless
// Enabled is on -- so piped reports and the exit scrollback stay plain and
// grep-able, and the report output remains byte-identical to the retired
// Python plan_timeline tool.
package style

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Enabled turns styling on (the TUI sets it while it owns the terminal).
var Enabled bool

const (
	Dim    = "2"
	Gray   = "90"
	Red    = "1;31"
	Green  = "32"
	Yellow = "33"
	Title  = "1;36"
	TabOn  = "1;38;5;231;48;5;25" // white on pGD blue
	TabOff = "90"
	LCD    = "1;38;5;231;48;5;25" // the pGD's blue-backlit LCD
	Armed  = "1;97;41"
	KeyBar = "38;5;250;48;5;236"

	// pGD terminal look: a gray bezel around the blue-backlit LCD, with
	// the six physical keys as keycaps below.
	Bezel  = "48;5;238;38;5;238"
	Keycap = "48;5;250;38;5;235;1"
	KeyHit = "48;5;220;38;5;16;1"
	LCDDim = "2;3;38;5;231;48;5;25"
	LCDInv = "1;38;5;25;48;5;231" // inverse video: blue on white (selection)
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// S styles s with the given SGR code when styling is enabled.
func S(code, s string) string {
	if !Enabled || code == "" || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// VisLen is the visible width of a possibly-styled string, in runes.
func VisLen(s string) int {
	return utf8.RuneCountInString(ansiRe.ReplaceAllString(s, ""))
}

// PadTo pads s with spaces to visible width w.
func PadTo(s string, w int) string {
	if d := w - VisLen(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

// Spark renders v out of max as one sparkline rune.
func Spark(v, max int) string {
	if v <= 0 || max <= 0 {
		return " "
	}
	i := (v*len(sparkRunes) - 1) / max
	if i >= len(sparkRunes) {
		i = len(sparkRunes) - 1
	}
	return string(sparkRunes[i])
}
