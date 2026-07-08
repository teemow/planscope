// Package tui is the interactive pLAN terminal: the live bus scope plus a
// second pGD terminal driven over the bridge's PLANCAP capture-and-control
// socket (key-injection commands).
//
// Views (keys 1-5):
//
//	1 screen     the pGD display rendered live (text-row frames, type 0x0B)
//	2 frames     every frame on the wire, decoded and described
//	3 timeline   per-interval traffic counts (poll/disp/walk/key/... + cksum)
//	4 addresses  per-address traffic and checksum failures
//	5 errors     checksum-failing frames verbatim (the objective garble detector)
//
// Terminal keys (device mode): arrows Up/Down, Enter, Esc, p (PRG) and
// a (ALARM) are sent to the pGD menu via the bridge. Transmit is gated: `w`
// toggles the device's write-enable (the arm command); while disarmed the
// bridge drops injected keys, matching the safety model of the device
// config.
package tui

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/teemow/planscope/internal/device"
	"github.com/teemow/planscope/internal/esphome"
	"github.com/teemow/planscope/internal/plan"
	"github.com/teemow/planscope/internal/style"
)

type view struct{ key, name string }

var views = []view{
	{"1", "screen"}, {"2", "frames"}, {"3", "timeline"},
	{"4", "addresses"}, {"5", "errors"},
}

type app struct {
	mu     sync.Mutex
	scr    *plan.Screen
	an     *plan.Analyzer
	view   string
	status string
	tty    bool
	height int
	width  int
	dirty  bool
	device string

	cap       *esphome.CapConn // live PLANCAP session, nil while disconnected
	armed     bool             // our view of the ESP's write-enable gate
	enrolled  bool             // device-reported: answering polls as terminal 31
	stateSeen bool             // a device state event arrived (state is truth, not guess)

	lastKey   byte // most recently injected key, for the keycap flash
	lastKeyAt time.Time

	sess *device.Session // headless twin of this connection (device events)

	// holdWait: armed against a device with a menu walker (plan_observe
	// firmware), but the walk has not yielded the session yet (the EvHold
	// event); keys are dropped until it does, so they never interleave
	// with an observability walk.
	holdWait bool
}

func (a *app) feedLine(line string) {
	tsMs, declared, seq, burst, ok := plan.ParseLine(line)
	if !ok {
		return
	}
	a.mu.Lock()
	a.scr.Feed(tsMs, declared, seq, burst)
	if !plan.IsSnapshotLine(line) { // replayed state primes the screen only
		a.an.Feed(tsMs, declared, seq, burst)
	}
	a.mu.Unlock()
}

// feedEvent ingests one typed device event: the state events are the badge
// truth (they survive reconnects and other clients flipping the switches).
func (a *app) feedEvent(e esphome.Event) {
	if e.Kind != esphome.EvState {
		return
	}
	a.mu.Lock()
	a.armed = e.Armed
	a.enrolled = e.Enroll != esphome.EnrollNo
	a.stateSeen = true
	a.mu.Unlock()
}

// feedDiag surfaces the bridge's warning/error diagnostics in the status
// line (info/debug prose stays on the capture feed and in tee files).
func (a *app) feedDiag(d esphome.Diag) {
	if d.Severity > esphome.DiagWarning {
		return
	}
	a.mu.Lock()
	a.status = "device: " + d.Text
	a.mu.Unlock()
	a.repaint()
}

// tabsLine is the top bar: app name, view tabs, connection dot.
func (a *app) tabsLine(w int) string {
	var sb strings.Builder
	sb.WriteString(" " + style.S(style.Title, "planscope") + "  ")
	for _, v := range views {
		tab := " " + v.key + " " + v.name + " "
		if v.key == a.view {
			sb.WriteString(style.S(style.TabOn, tab))
		} else {
			sb.WriteString(style.S(style.TabOff, tab))
		}
	}
	left := sb.String()
	dot := style.S(style.Red, "●") + style.S(style.Dim, " offline")
	if a.cap != nil {
		dot = style.S(style.Green, "●") + style.S(style.Dim, " "+a.device)
	}
	gap := w - style.VisLen(left) - style.VisLen(dot) - 1
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + dot
}

// statsLine is the second bar: counters and the write-enable badge.
func (a *app) statsLine() string {
	fails := fmt.Sprintf("%d", a.an.FailCount)
	if a.an.FailCount > 0 {
		fails = style.S(style.Red, fails)
	}
	loss := "" // only when the firmware numbers its capture lines ([#seq|N])
	if a.an.LastSeq > 0 {
		n := fmt.Sprintf("%d", a.an.LostLines)
		if a.an.LostLines > 0 {
			n = style.S(style.Red, n)
		}
		loss = fmt.Sprintf(" %s %s", style.S(style.Dim, "· log loss"), n)
	}
	stale := ""
	if len(a.scr.Stale) > 0 {
		// a seq gap fell into a repaint: rows/bands may be silently missing
		stale = " " + style.S(style.Red, " STALE screen — repaint lost in a seq gap ")
	}
	arm := style.S(style.Dim, " disarmed ")
	if a.armed {
		arm = style.S(style.Armed, " ARMED — keys go to the heat pump ")
	}
	enr := ""
	if a.enrolled {
		enr = style.S(style.Yellow, " enrolled as terminal 31 ")
	}
	if !a.stateSeen {
		enr = style.S(style.Dim, " state? ") // no device state event yet
	}
	return fmt.Sprintf(" %s %s %s %d %s %s%s%s   %s%s",
		style.S(style.Dim, "last frame"), plan.FmtTS(a.scr.LastTS),
		style.S(style.Dim, "· frames"), a.an.Frames,
		style.S(style.Dim, "· cksum fails"), fails, loss, stale, arm, enr)
}

// statusLine colors the transient status by its content.
func (a *app) statusLine() string {
	s := a.status
	switch {
	case s == "":
		return ""
	case strings.Contains(s, "lost"), strings.Contains(s, "failed"),
		strings.Contains(s, "no "):
		return " " + style.S(style.Red, s)
	case strings.Contains(s, "NOT sent"), strings.Contains(s, "ARMED"):
		return " " + style.S(style.Yellow, s)
	case strings.Contains(s, "connected"), strings.Contains(s, "sent"):
		return " " + style.S(style.Green, s)
	}
	return " " + style.S(style.Dim, s)
}

func (a *app) keyBar(w int) string {
	if !style.Enabled {
		return " up/down enter esc p a: pGD keys · w: write-enable · 1-5: views · q: quit"
	}
	base := "\x1b[48;5;236;38;5;245m"
	hi := "\x1b[48;5;236;1;38;5;252m"
	bar := base + "  " + hi + "↑↓ ⏎ Esc p a" + base + " pGD keys  ·  " +
		hi + "w" + base + " write-enable  ·  " +
		hi + "1-5" + base + " views  ·  " +
		hi + "q" + base + " quit"
	return style.PadTo(bar, w) + "\x1b[0m"
}

// pressKey injects one pGD keycode via a capture-socket command.
func (a *app) pressKey(code byte) {
	a.mu.Lock()
	cap, armed, holdWait := a.cap, a.armed, a.holdWait
	a.mu.Unlock()
	name := plan.KeyNames[code]
	if armed && holdWait {
		a.mu.Lock()
		a.status = fmt.Sprintf("key %s NOT sent -- waiting for the observability walk to yield", name)
		a.mu.Unlock()
		a.paintNow()
		return
	}
	msg := ""
	switch {
	case cap == nil:
		msg = "not connected -- key dropped"
	case !armed:
		msg = fmt.Sprintf("key %s NOT sent -- disarmed, press w to arm", name)
	default:
		if _, err := cap.Command(esphome.CmdInjectKey, code); err != nil {
			msg = fmt.Sprintf("key %s failed: %v", name, err)
		} else {
			msg = fmt.Sprintf("key %s sent (%s)", name, time.Now().Format("15:04:05"))
			a.mu.Lock()
			a.lastKey, a.lastKeyAt = code, time.Now()
			a.mu.Unlock()
		}
	}
	a.mu.Lock()
	a.status = msg
	a.mu.Unlock()
	a.paintNow()
}

// toggleArmed flips the ESP's write path. Keys are injected in terminal 31's
// own poll slot (tx_mode 2), which only exists while the ESP is enrolled on
// the pLAN -- so arming means enroll + arm as one unit. Disarming does NOT
// disenroll: leaving the net makes the controller rebuild it (FF-walk + pGD
// re-ident + repaint = a "no link" flash on the physical display, ground
// truth 2026-07-03), so enrollment is session-scoped instead: it survives
// arm/disarm toggles and is dropped once, on quit. (While we are enrolled
// the uPC hands its single poll slot mostly to us and serves the pGD only
// sporadically -- the physical display's intermittent "no link" is inherent
// to being enrolled on this controller, so we must not stay enrolled past
// the session either.)
func (a *app) toggleArmed() {
	a.mu.Lock()
	cap, target := a.cap, !a.armed
	a.mu.Unlock()
	msg := ""
	if cap == nil {
		msg = "not connected"
	} else {
		// A device with a menu walker (plan_observe firmware): arming holds
		// its walk; keys stay gated (holdWait) until the running walk
		// yields, so they never interleave with an observability scrape.
		// Walker presence is known from its own EvHold events (there is no
		// capability flag on the wire) -- awaitScrapeHold sizes its wait
		// accordingly.
		h0 := a.sess.ScrapeHolds()
		if target {
			// best effort: a failure here surfaces through the arm error below
			_, _ = cap.Command(esphome.CmdEnroll, 1)
		}
		if _, err := cap.Command(esphome.CmdArm, boolArg(target)); err != nil {
			msg = fmt.Sprintf("arm command failed: %v", err)
		} else {
			a.mu.Lock()
			a.armed = target
			a.holdWait = target
			a.mu.Unlock()
			if target {
				msg = "ARMED + enrolled as terminal 31; waiting for a device walker to yield..."
				go a.awaitScrapeHold(h0)
			} else {
				msg = "disarmed: key injection off (still enrolled until quit)"
			}
		}
	}
	a.mu.Lock()
	a.status = msg
	a.mu.Unlock()
	a.paintNow()
}

func boolArg(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// awaitScrapeHold clears the post-arm key gate once the device's menu walk
// yields the session -- or after the walker wait window (the worst-case
// cycle once a walker has shown itself, else a short grace: a device
// without a walker never yields).
func (a *app) awaitScrapeHold(h0 int) {
	window := device.HoldYield
	if !a.sess.HasObserve() {
		window = 3 * time.Second
	}
	ok := a.sess.WaitScrapeIdle(h0, window)
	a.mu.Lock()
	if a.holdWait { // a disarm meanwhile already cleared it
		a.holdWait = false
		if ok {
			a.status = "ARMED; observability walk yielded: arrows/Enter/Esc/p/a press pGD keys"
		} else {
			a.status = "ARMED: arrows/Enter/Esc/p/a press pGD keys (pGD keypad is parked until disarm)"
		}
	}
	a.mu.Unlock()
	a.paintNow()
}

func (a *app) framesView(max int) string {
	var sb strings.Builder
	recent := a.an.Recent
	if len(recent) > max {
		recent = recent[len(recent)-max:]
	}
	sb.WriteString(style.S(style.Dim, " live frames (newest last)") + "\n")
	for _, r := range recent {
		mark := " "
		if !r.OK {
			mark = style.S(style.Red, "✗")
		}
		hx := plan.HexBytes(r.Bytes)
		if len(hx) > 50 {
			hx = hx[:47] + style.S(style.Dim, "...")
		}
		if !r.OK {
			hx = style.S(style.Red, hx)
		}
		fmt.Fprintf(&sb, " %s %s %s %s %s\n",
			style.S(style.Gray, plan.FmtTSms(r.TSms)), mark,
			style.PadTo(style.S(plan.ClassStyle[r.Class], r.Class), 5),
			style.PadTo(hx, 50),
			style.S(style.Dim, plan.Describe(r.Bytes, r.Class)))
	}
	return sb.String()
}

// body renders the current view, sized to fit rows lines and w columns.
func (a *app) body(rows, w int) string {
	switch a.view {
	case "1":
		if style.Enabled {
			return a.screenView(w)
		}
		return a.scr.Render()
	case "2":
		return a.framesView(rows - 2)
	case "3":
		return a.an.TimelineTable(rows - 2)
	case "4":
		return a.an.AddrTable()
	case "5":
		return a.an.FailList(rows - 2)
	}
	return ""
}

// repaint marks the UI dirty; the paint ticker batches actual redraws so a
// busy bus doesn't turn every log line into a full-screen write (flicker).
func (a *app) repaint() {
	a.mu.Lock()
	a.dirty = true
	a.mu.Unlock()
}

func (a *app) paintNow() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.tty {
		return
	}
	h, w := a.height, a.width
	if h == 0 {
		h = 40
	}
	if w == 0 {
		w = 100
	}
	lines := []string{a.tabsLine(w), a.statsLine(), ""}
	lines = append(lines, strings.Split(a.body(h-5, w), "\n")...)
	// pin status + key bar to the bottom; clamp tall views
	if len(lines) > h-2 {
		lines = lines[:h-2]
	}
	for len(lines) < h-2 {
		lines = append(lines, "")
	}
	lines = append(lines, a.statusLine(), a.keyBar(w))
	// raw mode needs explicit carriage returns; \x1b[K erases each line's
	// tail so a shorter view leaves no residue of the previous one
	fmt.Print("\x1b[H" + strings.Join(lines, "\x1b[K\r\n") + "\x1b[0J")
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// Run connects to the device and runs the interactive TUI (or the plain
// line-mode fallback when stdout is not a terminal) until q/Ctrl+C.
func Run(addr, key string, bucket int) {
	a := &app{scr: plan.NewScreen(), an: plan.NewAnalyzer(bucket), view: "1"}
	a.device = addr
	a.tty = isTTY(os.Stdout) && isTTY(os.Stdin)
	// headless twin of this connection: same capture stream, own screen
	// reconstruction -- it tracks the typed device events for the arm path
	a.sess = device.NewSession(addr, key)

	var oldState *term.State
	var once sync.Once
	restore := func() {
		once.Do(func() {
			if a.tty {
				if oldState != nil {
					_ = term.Restore(int(os.Stdin.Fd()), oldState) // teardown
				}
				fmt.Print("\x1b[?1049l\x1b[?25h")
			}
			// leave the final state in the scrollback, unstyled
			style.Enabled = false
			fmt.Println(a.scr.Render())
			fmt.Println()
			fmt.Println(a.an.AddrTable())
		})
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; restore(); os.Exit(0) }()

	// One PLANCAP connection carries everything: bus bytes, typed device
	// events, diagnostics, and the command write path.
	feedMu := sync.Mutex{}
	feed := func(line string) {
		feedMu.Lock()
		a.feedLine(line)
		feedMu.Unlock()
		a.sess.FeedLine(line) // serializes itself
		a.repaint()
	}
	feedEv := func(e esphome.Event) {
		a.feedEvent(e)
		a.sess.FeedEvent(e)
		a.repaint()
	}
	status := "connected to " + addr + " -- 1-5 views, w write-enable, " +
		"arrows/Enter/Esc/p/a pGD keys, q quits"
	onConn := func(c *esphome.CapConn) {
		a.sess.BindCap(c)
		a.mu.Lock()
		a.cap = c
		// fail-safe: assume disarmed after (re)connect until the device's
		// state event (replayed right at attach) reports the truth. If the
		// ESP is in fact still armed from before, the mismatch only blocks
		// our own key sending until w re-arms -- it never transmits.
		a.armed = false
		a.enrolled = false
		a.stateSeen = false
		a.status = status
		a.mu.Unlock()
		a.repaint()
	}
	onDrop := func(err error) {
		a.sess.UnbindCap()
		a.sess.CaptureDrop(err)
		a.mu.Lock()
		a.cap = nil
		a.armed = false
		a.enrolled = false
		a.stateSeen = false
		a.status = fmt.Sprintf("capture stream lost (%v), reconnecting -- q to quit", err)
		a.mu.Unlock()
		a.repaint()
	}
	a.mu.Lock()
	a.status = "connecting to " + addr + " ..."
	a.mu.Unlock()
	go esphome.CaptureLoop(addr, key, nil, esphome.CaptureHooks{
		OnLine:  feed,
		OnEvent: feedEv,
		OnAck:   a.sess.FeedAck,
		OnDiag:  a.feedDiag,
		OnConn:  onConn,
		OnDrop:  onDrop,
	})

	if a.tty {
		var err error
		if oldState, err = term.MakeRaw(int(os.Stdin.Fd())); err != nil {
			a.tty = false
		} else {
			style.Enabled = true
			fmt.Print("\x1b[?1049h\x1b[?25l") // alt screen, hide cursor
			if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
				a.width, a.height = w, h
			}
			go func() { // batch redraws; a busy bus logs hundreds of lines/s
				for range time.Tick(80 * time.Millisecond) {
					a.mu.Lock()
					d := a.dirty
					a.dirty = false
					a.mu.Unlock()
					if d {
						a.paintNow()
					}
				}
			}()
			winch := make(chan os.Signal, 1)
			signal.Notify(winch, syscall.SIGWINCH)
			go func() {
				for range winch {
					if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
						a.mu.Lock()
						a.width, a.height = w, h
						a.mu.Unlock()
						a.paintNow()
					}
				}
			}()
			go a.keyboardLoop(restore)
		}
	}
	a.repaint()
	select {} // the keyboard loop and the signal handler own every exit path
}

// keyboardLoop reads raw-mode keys: view switching + pGD terminal keys.
func (a *app) keyboardLoop(restore func()) {
	buf := make([]byte, 8)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			switch c := buf[i]; {
			case c == 'q', c == 0x03: // q or Ctrl+C in raw mode
				// End of session: disarm (releases a device walker's hold)
				// and -- only without walker firmware, which owns enrollment
				// 24/7 -- leave the pLAN net so the pGD gets the poll slot
				// back (one rebuild flash now instead of a starved display
				// forever).
				a.mu.Lock()
				cap, armed, enrolled := a.cap, a.armed, a.enrolled
				a.mu.Unlock()
				if cap != nil {
					if armed {
						if _, err := cap.Command(esphome.CmdArm, 0); err != nil {
							fmt.Fprintln(os.Stderr, "planscope: disarm on exit:", err)
						}
					}
					if enrolled && !a.sess.HasObserve() {
						if _, err := cap.Command(esphome.CmdEnroll, 0); err != nil {
							fmt.Fprintln(os.Stderr, "planscope: disenroll on exit:", err)
						}
					}
				}
				restore()
				os.Exit(0)
			case c >= '1' && c <= '5':
				a.mu.Lock()
				a.view = string(c)
				a.mu.Unlock()
				a.paintNow()
			case c == 0x1b && i+2 < n && buf[i+1] == '[':
				switch buf[i+2] {
				case 'A':
					a.pressKey(plan.KeyUp)
				case 'B':
					a.pressKey(plan.KeyDown)
				}
				i += 2
			case c == 0x1b: // bare Esc (ponytail: a split \x1b[A read would
				// misfire ESC; never seen in practice)
				a.pressKey(plan.KeyEsc)
			case c == '\r', c == '\n':
				a.pressKey(plan.KeyEnter)
			case c == 'p':
				a.pressKey(plan.KeyPrg)
			case c == 'a':
				a.pressKey(plan.KeyAlarm)
			case c == 'w':
				a.toggleArmed()
			}
		}
	}
}
