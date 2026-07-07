// Package device drives the live device: a headless session over the
// bridge's PLANCAP capture-and-control socket, which streams the capture
// into the screen reconstructor and drives the pGD menu programmatically
// via capture-socket commands (arm/enroll/key injection). The TUI does
// exactly what the session does, interactively.
//
// Page identity comes from the application's own page ID in the top-right
// of row 0 (A01, B01, D14, ...), so navigation is verifiable at every step
// instead of blind key sequences.
package device

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/teemow/planscope/internal/esphome"
	"github.com/teemow/planscope/internal/plan"
)

// SettleQuiet is the bus-quiet window that means "repaint done". Derived
// from archived menu-walk captures of the reference installation:
// inter-frame gaps within key-triggered repaints max out at 467 ms and the
// first frame lands <= 431 ms after the TX, so 600 ms covers the worst
// case with ~1.3x margin -- while staying below the ~0.8-1.3 s periodic
// value refresh on live-value pages, which the old 1.5 s value chased
// forever.
const SettleQuiet = 600 * time.Millisecond

// txConfirm bounds Press(): worst case before the first TX is the firmware's
// no-clean-slot retry cycle (2 s injection deadline per attempt).
const txConfirm = 5 * time.Second

// HoldYield bounds the wait for the EvHold event after arming: a running
// scrape cycle takes <= ~30 s worst case (verify timeouts + recovery
// Esc's). Exported for the TUI's arm path, which runs the same wait.
const HoldYield = 45 * time.Second

// holdGrace is the walker-yield wait on a device that has not (yet) shown
// a walker: an IDLE walker yields within milliseconds of the arm taking
// effect, so this catches the common case; a device without a walker never
// yields, so the full HoldYield would stall every Arm(). See holdWindow.
const holdGrace = 3 * time.Second

// rebuildSig marks the controller's FF-walk net rebuild (one walk ~5 s
// after every membership change) on a capture line: a roll-call probe
// carrying the all-FF membership map, which only the reset walk uses. The
// walk re-inits our terminal session -- screen resets to the status page,
// in-flight keys are discarded -- so navigation must wait it out. Detected
// HOST-side from the capture bytes: a firmware-logged event was tried and
// reverted -- the one-instruction ISR delta broke enrollment outright (the
// documented ISR-shape sensitivity, see claim_mask_ in plan_terminal.h).
// The walk's first ~7 frames all match (map FF FF FF ..), so a single frame
// split across capture records cannot hide a walk; rebuildDedup coalesces
// them into one event (walks are >=4.5 s apart, measured).
const rebuildSig = "' 02 01 FF FF FF"

const rebuildDedup = 2 * time.Second

// Session is one headless live session.
type Session struct {
	addr, key string
	tee       func(string) // optional: every raw capture line

	feedMu     sync.Mutex // serializes FeedLine/FeedEvent/FeedAck
	mu         sync.Mutex
	cond       *sync.Cond // on mu; broadcast on every device event
	scr        *plan.Screen
	cap        *esphome.CapConn // nil while disconnected
	armed      bool             // device-reported truth (EvState events)
	enrolled   bool             // device-reported ("drain" counts: still on the link)
	stateSeen  bool
	txSeen     int       // TX/accepted events seen (Press() confirmation)
	txKey      byte      // keycode of the latest TX/accepted event
	joins      int       // EvJoin events (actual link joins)
	holds      int       // EvHold events (a device menu walker yielded)
	walker     bool      // sticky: an EvHold was seen -- the device runs a menu walker
	nackSeen   int       // rejected/unknown-op acks seen (Press() fail-fast)
	nackID     byte      // command id of the latest such ack
	nackStatus byte      // its status
	resets     int       // FF-walk net rebuilds seen on the capture (session re-inits)
	lastReset  time.Time // dedup: one walk spans several matching capture lines
	wantArmed  bool      // desired state; the enroll watchdog restores it
	preJoined  bool      // device was on the link before Arm(): no rebuild follows
	capDown    bool      // established capture stream dropped; clears when data flows again
	noWatch    bool      // Refresh() toggles enrollment on purpose
	noRecover  bool      // opt out of seq-gap auto-refresh (callers with their own cadence)
	onTx       func()    // optional: TX/accepted evidence hook (latency measurements)

	done chan struct{}
}

// NewSession returns an unconnected session for the given device address
// and PLANCAP key (the device's api.encryption.key; empty for a keyless
// bridge).
func NewSession(addr, key string) *Session {
	s := &Session{addr: addr, key: key, scr: plan.NewScreen(), done: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// BindCap attaches a live PLANCAP connection (the TUI shares its own
// capture stream with its headless session twin).
func (s *Session) BindCap(c *esphome.CapConn) {
	s.mu.Lock()
	s.cap = c
	s.stateSeen = false // await fresh device truth (replayed right at attach)
	s.mu.Unlock()
}

// UnbindCap detaches the connection after a drop.
func (s *Session) UnbindCap() {
	s.mu.Lock()
	s.cap = nil
	s.mu.Unlock()
}

// Connect dials the device's PLANCAP socket and keeps the session attached
// (5 s retry) until Close(). It blocks until the first stream is
// established (fail fast on a bad target or key). The one connection
// carries everything: bus bytes, typed device events, diagnostics, and the
// command write path.
func (s *Session) Connect() error {
	if !s.noRecover {
		s.autoRecover() // seq-gap staleness heals itself when idle
	}
	first := make(chan error, 1)
	go func() {
		connected := false
		addr := esphome.CaptureAddr(s.addr)
		for {
			select {
			case <-s.done:
				return
			default:
			}
			was, err := esphome.RunCapture(addr, s.key, esphome.CaptureHooks{
				OnLine:  s.FeedLine,
				OnEvent: s.FeedEvent,
				OnAck:   s.FeedAck,
				OnConn: func(c *esphome.CapConn) {
					s.BindCap(c)
					if !connected {
						connected = true
						first <- nil
					}
				},
			})
			s.UnbindCap()
			if was {
				s.FeedLine(fmt.Sprintf("[plan_cap]: capture stream lost (%v) -- another client attached? reconnecting", err))
				s.CaptureDrop(err)
			}
			if !connected {
				first <- err
				return
			}
			select {
			case <-s.done:
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
	return <-first
}

// Close disarms when the write path is open (never leave it armed
// unattended; enrollment stays -- leaving would flash the physical pGD,
// `planscope call set_enroll false` leaves explicitly) and tears the
// connection down.
func (s *Session) Close() {
	s.mu.Lock()
	cap, armed := s.cap, s.armed || s.wantArmed
	s.wantArmed = false
	s.mu.Unlock()
	close(s.done)
	if cap != nil {
		if armed {
			cap.Command(esphome.CmdArm, 0)
		}
		cap.Close() // unblocks the read loop
	}
}

// Disenroll drops the pLAN membership explicitly (the pGD gets its poll
// slot back).
func (s *Session) Disenroll() {
	s.command(esphome.CmdEnroll, 0)
}

// FeedLine ingests one capture line (screen bytes off the capture
// stream). The FF-walk rebuild stays a host-side detection from the
// capture BYTES on purpose: a firmware-logged event was tried and
// reverted (the documented ISR-shape sensitivity). It serializes itself,
// so tee callers need no locking of their own.
func (s *Session) FeedLine(line string) {
	s.feedMu.Lock()
	defer s.feedMu.Unlock()
	if s.tee != nil {
		s.tee(line)
	}
	s.mu.Lock()
	if strings.Contains(line, rebuildSig) && !plan.IsSnapshotLine(line) &&
		time.Since(s.lastReset) > rebuildDedup {
		s.lastReset = time.Now()
		s.resets++
	}
	if tsMs, declared, seq, burst, ok := plan.ParseLine(line); ok {
		s.scr.Feed(tsMs, declared, seq, burst)
		s.capDown = false // capture data flowing again: the stream is ours
	}
	s.cond.Broadcast() // every WaitFor wakes on the event that satisfies it
	s.mu.Unlock()
}

// CaptureDrop signals that an ESTABLISHED capture stream ended. The stream
// is single-client (newest wins), so this normally means another client --
// a parallel planscope log/observe/TUI, or any tool on TCP 6054 -- took it
// over, leaving this session blind: no screen bytes, no TX confirmations,
// no write path. Pending Press() waits fail fast on it instead of timing
// out one by one. (Exported for the TUI, which runs its own CaptureLoop
// and shares it with its headless session twin.)
func (s *Session) CaptureDrop(error) {
	s.mu.Lock()
	s.capDown = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// FeedEvent ingests one typed device event off the capture stream: state
// truth, link joins, TX verdicts, the walker's yield -- plus the enroll
// watchdog: when the device reports the session down (firmware reboot,
// another client) while we want it up, restore it. The state event repeats
// every 10 s, so a silent drop heals within that.
func (s *Session) FeedEvent(e esphome.Event) {
	s.feedMu.Lock()
	defer s.feedMu.Unlock()
	if s.tee != nil {
		s.tee("[plan_evt]: " + e.String())
	}
	var fix *esphome.CapConn
	var tx func()
	s.mu.Lock()
	s.capDown = false // events ride the capture stream: it is ours
	switch e.Kind {
	case esphome.EvState:
		s.armed = e.Armed
		s.enrolled = e.Enroll != esphome.EnrollNo // drain counts: still on the link
		s.stateSeen = true
		if s.wantArmed && !s.noWatch && (!s.armed || !s.enrolled) {
			fix = s.cap
		}
	case esphome.EvTxFired, esphome.EvKeyAccepted:
		s.txSeen++
		s.txKey = e.Key
		tx = s.onTx
	case esphome.EvJoin:
		s.joins++
	case esphome.EvHold:
		s.holds++
		s.walker = true
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	if tx != nil {
		tx()
	}
	if fix != nil {
		fix.Command(esphome.CmdEnroll, 1)
		fix.Command(esphome.CmdArm, 1)
	}
}

// FeedAck ingests one command ack off the capture stream. Accepted acks
// carry no information the resulting events do not; rejections and
// unknown ops fail pending Press() waits fast instead of a blind timeout.
func (s *Session) FeedAck(a esphome.Ack) {
	s.feedMu.Lock()
	defer s.feedMu.Unlock()
	if s.tee != nil && a.Status != esphome.AckOK {
		s.tee("[plan_ack]: " + a.String())
	}
	s.mu.Lock()
	s.capDown = false // acks ride the capture stream: it is ours
	if a.Status != esphome.AckOK {
		s.nackSeen++
		s.nackID = a.ID
		s.nackStatus = a.Status
	}
	s.cond.Broadcast()
	s.mu.Unlock()
}

// WaitFor blocks until cond (evaluated with the session lock held) holds or
// the timeout expires. Every device event (FeedLine/FeedEvent) broadcasts,
// so the wait wakes the moment the satisfying event arrives; a fallback
// tick re-checks conditions that change outside the feed on a quiet
// stream.
func (s *Session) WaitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	s.mu.Lock()
	defer s.mu.Unlock()
	for !cond() {
		d := time.Until(deadline)
		if d <= 0 {
			return false
		}
		if d > 250*time.Millisecond {
			d = 250 * time.Millisecond
		}
		t := time.AfterFunc(d, s.cond.Broadcast)
		s.cond.Wait()
		t.Stop()
	}
	return true
}

// Arm enrolls terminal 31 and opens the write path as one unit (keys are
// injected in our own poll slot, which only exists while enrolled), then
// waits for the firmware's explicit join event ("enrolled: first poll
// answered") -- the actual link join, not the enroll=yes wish flag. A fresh
// enroll joins with the next roll-call walk (~12 s cadence); an already-
// joined device re-fires the event on its next answered poll (tens of ms),
// so Arm() returning means keys have a live poll slot to ride in.
func (s *Session) Arm(timeout time.Duration) error {
	// The capture stream replays a state event right at attach, so waiting
	// for device truth costs nothing -- and it is what tells us whether the
	// device is ALREADY on the link (then no membership change follows and
	// the post-join rebuild wait can be skipped). The confirm wait below
	// needs stateSeen anyway.
	s.mu.Lock()
	down := s.cap == nil
	s.mu.Unlock()
	if down {
		return fmt.Errorf("not connected")
	}
	s.WaitFor(timeout, func() bool { return s.stateSeen })
	// wantArmed only once the commands are actually going out: it drives the
	// watchdog, and a failed Arm() must not leave a silent re-arm behind.
	s.mu.Lock()
	s.wantArmed = true
	j0, h0 := s.joins, s.holds
	preArmed := s.stateSeen && s.armed
	// Already on the link before we asked (a walker firmware owns
	// enrollment 24/7, or a previous session left it up): enroll is a
	// no-op, no membership change happens, and no post-join net rebuild
	// will come -- AwaitJoin() can skip its rebuild window. The capture
	// stream replays a state event right at attach, so stateSeen is
	// normally long true by now; when it is not, stay conservative.
	s.preJoined = s.stateSeen && s.enrolled
	s.mu.Unlock()
	if err := s.command(esphome.CmdEnroll, 1); err != nil {
		return err
	}
	if err := s.command(esphome.CmdArm, 1); err != nil {
		return err
	}
	if !s.WaitFor(timeout, func() bool { return s.stateSeen && s.armed && s.enrolled }) {
		return fmt.Errorf("device did not confirm armed+enrolled within %v", timeout)
	}
	if !s.WaitFor(timeout, func() bool { return s.joins > j0 }) {
		return fmt.Errorf("no link join within %v (roll-call walk missing?)", timeout)
	}
	// A walker firmware (e.g. plan_observe) walks the menu on this very
	// session. Arming holds its scheduler; wait until the running walk
	// yields (the EvHold event, re-fired per arm) so our keys queue BEHIND
	// the walk instead of interleaving with it. A device that was already
	// armed before us (a killed session left the write path open) has been
	// holding all along -- its announce fired before we connected and no
	// walk can be running, so skip the wait instead of idling out.
	if !preArmed && !s.WaitFor(s.holdWindow(), func() bool { return s.holds > h0 }) && s.HasObserve() {
		return fmt.Errorf("device walker did not yield within %v (scrape wedged mid-route? try `planscope call observe_pause true`)", HoldYield)
	}
	return nil
}

// holdWindow is how long Arm() waits for a walker's yield: the full
// worst-case walk once a walker has shown itself (any EvHold this
// session), else a short grace. PLANCAP carries no "walker present"
// capability flag, so the walker's own events are the only evidence.
// ponytail: on the very first arm of a fresh session against a walker
// that is MID-ROUTE, the yield lands after the grace and one route may
// interleave; every later arm of the session waits the full window.
func (s *Session) holdWindow() time.Duration {
	if s.HasObserve() {
		return HoldYield
	}
	return holdGrace
}

// HasObserve reports whether the device has shown a menu walker (an
// EvHold event this session) -- e.g. the plan_observe firmware, which owns
// pLAN enrollment 24/7 (teardowns must not disenroll it) and holds its
// menu walk while armed.
func (s *Session) HasObserve() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.walker
}

// ScrapeHolds returns the count of walker yield events seen (the TUI's
// arm path waits on it going up, like Arm() does internally).
func (s *Session) ScrapeHolds() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holds
}

// WaitScrapeIdle blocks until a new walk-yield event arrives (holds >
// since) or the timeout expires.
func (s *Session) WaitScrapeIdle(since int, timeout time.Duration) bool {
	return s.WaitFor(timeout, func() bool { return s.holds > since })
}

// Disarm closes the write path but stays enrolled (leaving makes the
// controller rebuild the net -- the "no link" flash on the physical pGD --
// and staying is free: the ISR answers polls).
func (s *Session) Disarm() error {
	s.mu.Lock()
	s.wantArmed = false
	s.mu.Unlock()
	return s.command(esphome.CmdArm, 0)
}

// ErrCaptureLost marks a key press that failed because the device's
// single-client capture stream (the only carrier of screen bytes, TX
// confirmations AND the write path) was taken over by another client.
// Retrying the route is pointless while the thief holds the stream, so
// Navigate gives up on it immediately.
var ErrCaptureLost = errors.New(
	"the device capture stream was taken by another client (a parallel planscope log/observe/TUI, or another tool on TCP 6054) -- the stream is single-client, newest wins; stop the other client and retry")

// Press injects one pGD keycode via a capture-socket command and returns
// once the firmware confirms the key hit the wire -- the EvTxFired or
// EvKeyAccepted event, whichever lands first -- instead of returning
// fire-and-forget. The events carry the keycode, so the confirmation is
// attributed to THIS key (a late retry of the previous key can no longer
// satisfy it). The repaint the key triggers is still the caller's to
// await (WaitSettle / ExpectPage). A rejected ack (disarmed gate, full
// queue) fails immediately -- the device says why in a diagnostic.
//
// Confirmations arrive on the capture stream; when that stream is lost to
// another client the wait fails IMMEDIATELY with ErrCaptureLost -- naming
// the actual problem -- instead of a blind timeout per key.
func (s *Session) Press(code byte) error {
	s.mu.Lock()
	cap, armed, tx0, n0, down := s.cap, s.wantArmed, s.txSeen, s.nackSeen, s.capDown
	s.mu.Unlock()
	if cap == nil {
		return fmt.Errorf("not connected -- key %s dropped", plan.KeyNames[code])
	}
	if !armed {
		return fmt.Errorf("not armed -- key %s dropped", plan.KeyNames[code])
	}
	if down {
		return fmt.Errorf("key %s: %w", plan.KeyNames[code], ErrCaptureLost)
	}
	id, err := cap.Command(esphome.CmdInjectKey, code)
	if err != nil {
		return err
	}
	confirmed := func() bool { return s.txSeen > tx0 && s.txKey == code }
	nacked := func() bool { return s.nackSeen > n0 && s.nackID == id }
	if !s.WaitFor(txConfirm, func() bool { return confirmed() || nacked() || s.capDown }) {
		return fmt.Errorf("key %s: no TX/accepted confirmation within %v", plan.KeyNames[code], txConfirm)
	}
	s.mu.Lock()
	ok, rejected, status := confirmed(), nacked(), s.nackStatus
	s.mu.Unlock()
	if rejected {
		return fmt.Errorf("key %s: rejected by the device (ack status %d)", plan.KeyNames[code], status)
	}
	if !ok {
		return fmt.Errorf("key %s: %w", plan.KeyNames[code], ErrCaptureLost)
	}
	return nil
}

// WaitSettle blocks until no display frame for our session (terminal 31)
// has arrived for quiet -- the repaint after a key press is done (port of
// the menuwalk.sh settle loop). Returns false when the screen never went
// quiet within 10x quiet.
func (s *Session) WaitSettle(quiet time.Duration) bool {
	deadline := time.Now().Add(10 * quiet)
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := s.scr.Painted[plan.EspAddr]
	quietSince := time.Now()
	for {
		if time.Since(quietSince) >= quiet {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		// wake on the next frame (broadcast) or when the quiet window ends
		t := time.AfterFunc(time.Until(quietSince.Add(quiet)), s.cond.Broadcast)
		s.cond.Wait()
		t.Stop()
		if p := s.scr.Painted[plan.EspAddr]; p != seen {
			seen = p
			quietSince = time.Now()
		}
	}
}

// PageID returns the current page's ID from row 0 of the ESP's own screen,
// or "" when the page carries none (status anchor, alarms) or nothing is
// painted yet.
func (s *Session) PageID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pageIDLocked()
}

func (s *Session) pageIDLocked() string {
	f := strings.Fields(s.scr.Rows[plan.EspAddr][0])
	if n := len(f); n > 0 && plan.PageIDRe.MatchString(f[n-1]) {
		return f[n-1]
	}
	return ""
}

// ExpectPage waits until the ESP screen shows the given page ID.
func (s *Session) ExpectPage(id string, timeout time.Duration) error {
	if s.WaitFor(timeout, func() bool { return s.pageIDLocked() == id }) {
		return nil
	}
	s.mu.Lock()
	got, row0 := s.pageIDLocked(), s.scr.Rows[plan.EspAddr][0]
	s.mu.Unlock()
	return fmt.Errorf("expected page %s, screen shows %q (row 0 %q)", id, got, row0)
}

// WaitRow waits until the given ESP-screen row matches re and returns the
// row text (the value read-back for config macros).
func (s *Session) WaitRow(row int, re *regexp.Regexp, timeout time.Duration) (string, error) {
	var got string
	if s.WaitFor(timeout, func() bool {
		got = s.scr.Rows[plan.EspAddr][row]
		return re.MatchString(got)
	}) {
		return got, nil
	}
	return "", fmt.Errorf("row %d never matched %v (last %q)", row, re, got)
}

// Row snapshots one ESP-screen row.
func (s *Session) Row(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scr.Rows[plan.EspAddr][i]
}

// ScreenRows snapshots the ESP terminal's rows (error context and dumps).
func (s *Session) ScreenRows() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]string, plan.MinRows)
	for r := range rows {
		rows[r] = s.scr.Rows[plan.EspAddr][r]
	}
	return rows
}

// Refresh forces a full authoritative repaint by toggling enrollment: the
// controller repaints a re-joining terminal from scratch (the trick from
// the menu walk -- some row updates otherwise arrive only as graphics).
//
// Sequenced on the controller's OBSERVED recovery choreography (captured
// live 2026-07-03) so it is deterministic instead of racing it:
//
//  1. leave (immediate since the firmware dropped the refuted drain) and
//     wait until the controller provably noticed -- it re-adopts the
//     physical pGD and session-inits it, so Painted[TermAddr] advances.
//     Re-enrolling before that point sometimes went unnoticed entirely
//     (no authoritative repaint) and sometimes triggered a DELAYED net
//     rebuild that landed mid-route and reset the session.
//  2. re-enroll; the next walk (FF-walk ~5 s after the churn, or the ~12 s
//     periodic roll-call) adopts us; session re-init repaints from scratch.
//  3. the join is itself a membership change, so the controller runs one
//     more FF-walk ~5 s later that re-inits the session AGAIN (back to the
//     status page). Wait that rebuild out (AwaitRebuild) -- keys pressed
//     across it are discarded.
//
// Costs one "no link" flash on the physical pGD and ~12-15 s. The watchdog
// is suspended for the duration; arming is restored when it was on. The
// repaint clears the ESP screen's seq-gap stale flag. Mutually exclusive:
// a second refresh (auto-recovery vs explicit) errors out instead of
// interleaving enroll toggles.
func (s *Session) Refresh() error {
	s.mu.Lock()
	if s.noWatch {
		s.mu.Unlock()
		return fmt.Errorf("refresh already in progress")
	}
	rearm := s.wantArmed
	pgd0 := s.scr.Painted[plan.TermAddr]
	s.noWatch = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.noWatch = false
		s.mu.Unlock()
	}()
	if err := s.command(esphome.CmdEnroll, 0); err != nil {
		return err
	}
	// the firmware's graceful drain ends in the 15 s deadline hard stop
	// (the controller never roll-calls an established terminal, so the
	// renounce never fires); "enroll=no" arrives when we actually go silent
	if !s.WaitFor(20*time.Second, func() bool { return s.stateSeen && !s.enrolled }) {
		return fmt.Errorf("disenroll (drain) not confirmed")
	}
	// ponytail: "controller dropped us" is read from the pGD's session-init
	// frames -- assumes the physical pGD is on the bus (this rig's is). The
	// timeout fallback just proceeds; worst case is the old racy behavior.
	s.WaitFor(15*time.Second, func() bool { return s.scr.Painted[plan.TermAddr] != pgd0 })
	s.mu.Lock()
	p0, j0 := s.scr.Painted[plan.EspAddr], s.joins
	s.mu.Unlock()
	if err := s.command(esphome.CmdEnroll, 1); err != nil {
		return err
	}
	if rearm {
		if err := s.command(esphome.CmdArm, 1); err != nil {
			return err
		}
	}
	// the rejoin lands with the next walk; the firmware's explicit join
	// event separates "never joined" from "joined but no repaint"
	if !s.WaitFor(20*time.Second, func() bool { return s.joins > j0 }) {
		return fmt.Errorf("no link join after re-enroll")
	}
	if !s.WaitFor(20*time.Second, func() bool { return s.scr.Painted[plan.EspAddr] != p0 }) {
		return fmt.Errorf("joined but no repaint after re-enroll")
	}
	s.AwaitRebuild(10 * time.Second)
	s.mu.Lock()
	s.scr.ClearStale(plan.EspAddr) // repainted from scratch: authoritative again
	s.mu.Unlock()
	return nil
}

// command sends one capture-socket command against the CURRENT connection,
// retrying while the capture auto-reconnect is replacing it (5 s
// backoff) -- Refresh() spans tens of seconds, long enough for a held
// pointer to go stale mid-sequence (observed: "use of closed network
// connection" killing a refresh).
func (s *Session) command(op, arg byte) error {
	deadline := time.Now().Add(8 * time.Second)
	var err error
	for {
		s.mu.Lock()
		cap := s.cap
		s.mu.Unlock()
		if cap != nil {
			if _, err = cap.Command(op, arg); err == nil {
				return nil
			}
		} else {
			err = fmt.Errorf("not connected")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("command %d: %w", op, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// AwaitRebuild waits out the controller's post-churn net rebuild: one
// FF-walk re-inits the terminal session (full repaint to the status page,
// in-flight keys discarded) some seconds after a membership change --
// measured 4.5-6.1 s after a drop-and-rejoin, but up to ~20 s after a
// rejoin the controller absorbed without a walk, hence the caller-chosen
// window. Call after any join before pressing keys. When the walk arrives,
// wait for its re-init repaint and settle; when none comes within the
// window (already-stable link), just settle and move on.
func (s *Session) AwaitRebuild(window time.Duration) {
	s.mu.Lock()
	r0, p0 := s.resets, s.scr.Painted[plan.EspAddr]
	s.mu.Unlock()
	if s.WaitFor(window, func() bool { return s.resets > r0 }) {
		s.WaitFor(10*time.Second, func() bool { return s.scr.Painted[plan.EspAddr] != p0 })
	}
	s.WaitSettle(SettleQuiet)
}

// AwaitJoin runs the fresh-enroll startup choreography after Arm(): a fresh
// enroll session-inits with a full repaint; the join is a membership
// change, so one more FF-walk resets the session seconds later -- keys
// pressed across it are discarded. Every armed flow spends this wait once
// before pressing keys.
// A session that was already on the link before Arm() (preJoined) caused
// no membership change -- no rebuild will ever come, so the whole wait
// is skipped instead of idling out the 25 s window.
func (s *Session) AwaitJoin() {
	s.mu.Lock()
	pre := s.preJoined
	p0 := s.scr.Painted[plan.EspAddr]
	s.mu.Unlock()
	if pre {
		s.WaitSettle(SettleQuiet)
		return
	}
	s.WaitFor(10*time.Second, func() bool { return s.scr.Painted[plan.EspAddr] != p0 })
	s.AwaitRebuild(25 * time.Second)
}

// Stale reports whether the ESP screen's reconstruction is flagged stale
// (a capture seq gap fell into a repaint; frames were lost).
func (s *Session) Stale() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scr.Stale[plan.EspAddr]
}

// needRecover is the auto-recovery decision: the ESP screen is stale, the
// device is on the link (refresh toggles enrollment, pointless otherwise),
// and no refresh is already running.
func (s *Session) needRecover() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scr.Stale[plan.EspAddr] && s.enrolled && !s.noWatch
}

// autoRecover starts the seq-gap recovery loop: when the ESP screen is
// stale AND idle (settled -- never fighting a repaint in flight), run
// Refresh() for an authoritative repaint, which clears the flag. Runs
// until Close(); a failed refresh leaves the flag set for the next round.
// On by default (Connect); callers that interleave their own key presses
// with their own refresh cadence set noRecover -- a recovery
// refresh disenrolls for up to ~30 s and any press in that window is lost.
func (s *Session) autoRecover() {
	go func() {
		for {
			select {
			case <-s.done:
				return
			case <-time.After(time.Second):
			}
			if s.needRecover() && s.WaitSettle(SettleQuiet) {
				s.Refresh()
			}
		}
	}()
}
