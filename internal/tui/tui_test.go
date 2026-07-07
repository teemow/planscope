package tui

import (
	"strings"
	"testing"

	"github.com/teemow/planscope/internal/plan"
	"github.com/teemow/planscope/internal/style"
)

// The TUI views must render without panicking and carry their key content.
func TestViews(t *testing.T) {
	a := &app{scr: plan.NewScreen(), an: plan.NewAnalyzer(15), view: "1"}
	a.feedLine("[12:00:00.000][D][plan_control:589][plan_ctrl]: [ 12] 20' 0C 08 01 02 13 33 82 01' 03 20 DB ")
	a.feedLine("[12:00:00.100][D][plan_control:589][plan_ctrl]: [ 11] 01' 1E 07 20 0D 01 AB 01' 01 20 DD ")
	a.feedLine("[12:00:00.200][D][plan_control:589][plan_ctrl]: [  4] 20' 01 01 DC ")
	for v, want := range map[string]string{
		"1": "terminal 32 (pGD)",
		"2": "KEY ALARM",
		"3": "cksum_fail",
		"4": "uPC controller",
		"5": "checksum failures",
	} {
		a.view = v
		if got := a.body(40, 100); !strings.Contains(got, want) {
			t.Fatalf("view %s missing %q:\n%s", v, want, got)
		}
	}
}

// The styled pGD view must render at any pane width without panicking
// (regression: keycap row wider than the bezel caused a negative Repeat).
func TestScreenViewStyled(t *testing.T) {
	style.Enabled = true
	defer func() { style.Enabled = false }()
	a := &app{scr: plan.NewScreen(), an: plan.NewAnalyzer(15), view: "1"}
	for _, w := range []int{20, 40, 80, 200} {
		if got := a.screenView(w); !strings.Contains(got, "waiting for row repaints") {
			t.Fatalf("width %d: missing empty-LCD hint", w)
		}
	}
	// single-cell update: '6' lands at row 4 col 0x13 of the pGD screen
	a.feedLine("[12:00:00.000][D][plan_control:589][plan_ctrl]: [ 12] 20' 0C 08 01 04 13 36 7D 01' 03 20 DB ")
	out := a.screenView(80)
	if !strings.Contains(out, "6") || strings.Contains(out, "waiting for row repaints") {
		t.Fatalf("cell update not painted:\n%s", out)
	}
}
