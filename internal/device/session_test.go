package device

import (
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/teemow/planscope/internal/esphome"
	"github.com/teemow/planscope/internal/plan"
)

// textFrame builds a valid controller->terminal text-row frame:
// 20 0B LEN 01 ROW <text...> CK | 01 03 20 DB
func textFrame(row byte, text []byte) []byte {
	body := append([]byte{plan.TermAddr, plan.TypeText, byte(5 + len(text) + 1), 0x01, row}, text...)
	sum := 0
	for _, b := range body {
		sum += int(b)
	}
	body = append(body, byte(0xFF-sum&0xFF))
	return append(body, plan.Trailer...)
}

// A session that was on the link before Arm() caused no membership change;
// AwaitJoin must skip the rebuild window instead of idling it out.
func TestAwaitJoinPreJoinedSkips(t *testing.T) {
	s := NewSession("", "")
	s.preJoined = true
	t0 := time.Now()
	s.AwaitJoin()
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("preJoined AwaitJoin idled %v (rebuild window not skipped)", d)
	}
}

// espFrame builds a text-row frame addressed to the ESP's own session
// (0x1F, no trailer), as the controller paints it while enrolled.
func espFrame(row byte, text string) []byte {
	f := textFrame(row, []byte(text))
	f[0] = plan.EspAddr
	f[len(f)-5] += plan.TermAddr - plan.EspAddr // re-fix CK for the address change
	return f[:len(f)-4]                         // strip the trailer
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

func TestSessionPageID(t *testing.T) {
	s := NewSession("", "")
	if got := s.PageID(); got != "" {
		t.Fatalf("empty screen pageID = %q", got)
	}

	// status anchor row 0 carries no page ID -- its trailing token is the
	// plant name, which must not be mistaken for one
	s.FeedLine(hexLine(espFrame(0, "02:18 03/07/26 Plant1"), true))
	if got := s.PageID(); got != "" {
		t.Fatalf("status anchor pageID = %q, want none", got)
	}

	for _, tc := range []struct{ row0, id string }{
		{" On/Off Unit       A01", "A01"},
		{" Thermoreg. Unit   B01", "B01"},
		{" Valve             D14", "D14"},
		{" Working hours    Gd01", "Gd01"},
		{" I/O Config.      Hb01", "Hb01"},
	} {
		s.FeedLine(hexLine(espFrame(0, tc.row0), true))
		if got := s.PageID(); got != tc.id {
			t.Fatalf("row 0 %q -> pageID %q, want %q", tc.row0, got, tc.id)
		}
	}

	if err := s.ExpectPage("Hb01", 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := s.ExpectPage("B01", 60*time.Millisecond); err == nil {
		t.Fatal("ExpectPage must fail on the wrong page")
	}
}

func TestSessionWaitRow(t *testing.T) {
	s := NewSession("", "")
	s.FeedLine(hexLine(espFrame(4, "Domestic:       39.0"), true))
	got, err := s.WaitRow(4, regexp.MustCompile(`Domestic:\s+([\d.]+)`), 100*time.Millisecond)
	if err != nil || got != "Domestic:       39.0" {
		t.Fatalf("WaitRow = %q, %v", got, err)
	}
	if _, err := s.WaitRow(5, regexp.MustCompile(`x`), 60*time.Millisecond); err == nil {
		t.Fatal("WaitRow must time out on an absent row")
	}
}

// The state event is the device truth the watchdog acts on; drain still
// counts as enrolled (on the link until the roll-call walk finishes it).
func TestSessionStateEvent(t *testing.T) {
	s := NewSession("", "")
	s.FeedEvent(esphome.Event{Kind: esphome.EvState, Armed: true, Enroll: esphome.EnrollDrain, TxMode: 2})
	if !s.stateSeen || !s.armed || !s.enrolled {
		t.Fatalf("state = seen:%v armed:%v enrolled:%v", s.stateSeen, s.armed, s.enrolled)
	}
	s.FeedEvent(esphome.Event{Kind: esphome.EvState, Enroll: esphome.EnrollNo, TxMode: 2})
	if s.armed || s.enrolled {
		t.Fatalf("state = armed:%v enrolled:%v, want down", s.armed, s.enrolled)
	}
	// wantArmed with no connection: the watchdog must not panic on nil conn
	s.wantArmed = true
	s.FeedEvent(esphome.Event{Kind: esphome.EvState, Enroll: esphome.EnrollNo, TxMode: 2})
}

// FeedEvent counts the device events: TX/accepted evidence for Press(),
// the link join for Arm()/Refresh(), the observe walk-yield.
func TestSessionEventCounters(t *testing.T) {
	s := NewSession("", "")
	s.FeedEvent(esphome.Event{Kind: esphome.EvTxFired, Key: 0x0F})
	s.FeedEvent(esphome.Event{Kind: esphome.EvKeyAccepted, Key: 0x0F})
	if s.txSeen != 2 || s.txKey != 0x0F {
		t.Fatalf("txSeen = %d key 0x%02X, want 2 events for key 0x0F", s.txSeen, s.txKey)
	}
	s.FeedEvent(esphome.Event{Kind: esphome.EvJoin})
	if s.joins != 1 {
		t.Fatalf("joins = %d, want 1", s.joins)
	}
	// the plan_observe walk-yield handshake (fires when arming holds the
	// firmware's scrape and the running walk finished)
	s.FeedEvent(esphome.Event{Kind: esphome.EvHold})
	s.FeedEvent(esphome.Event{Kind: esphome.EvHold, Paused: true})
	if s.holds != 2 {
		t.Fatalf("holds = %d, want 2", s.holds)
	}
	// FF-walk net rebuild, detected from the capture bytes; the walk's
	// first frames all carry the FF map, deduped into ONE event
	s.FeedLine("[plan_cap]: [#31| 12] 02' 02 01 FF FF FF FF 00 00 00 00 FE")
	s.FeedLine("[plan_cap]: [#32| 12] 03' 02 01 FF FF FF FD 00 00 00 00 FF")
	if s.resets != 1 {
		t.Fatalf("resets = %d, want 1 (walk deduped)", s.resets)
	}
	// a snapshot replay of the same bytes is state, not a live walk
	s.lastReset = time.Time{}
	s.FeedLine("[plan_snap]: [#0| 12] 02' 02 01 FF FF FF FF 00 00 00 00 FE")
	if s.resets != 1 {
		t.Fatalf("resets = %d after snapshot line, want still 1", s.resets)
	}
	// the regular ~12 s roll-call walk (established map, no FF) is no reset
	s.FeedLine("[plan_cap]: [#33| 12] 0C' 02 01 C0 00 00 01 40 00 00 00 EF")
	if s.resets != 1 {
		t.Fatalf("resets = %d after regular roll-call, want still 1", s.resets)
	}
}

// WaitFor must wake on the FeedEvent broadcast, not poll to a deadline: the
// event lands at ~20 ms and the fallback tick is 250 ms, so an event-driven
// wake finishes well under 150 ms.
func TestSessionWaitForWakesOnEvent(t *testing.T) {
	s := NewSession("", "")
	go func() {
		time.Sleep(20 * time.Millisecond)
		s.FeedEvent(esphome.Event{Kind: esphome.EvJoin})
	}()
	start := time.Now()
	if !s.WaitFor(2*time.Second, func() bool { return s.joins > 0 }) {
		t.Fatal("join event not seen")
	}
	if d := time.Since(start); d > 150*time.Millisecond {
		t.Fatalf("WaitFor returned after %v, want an event-driven wake", d)
	}
}

// readCommand consumes one plaintext command frame off the fake device
// side of the pipe (marker 0x00 + u16 BE len + [type id op arg]).
func readCommand(t *testing.T, server net.Conn) (id, op, arg byte) {
	t.Helper()
	buf := make([]byte, 7)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Error("fake device read:", err)
		return
	}
	if buf[0] != 0x00 || buf[2] != 4 || buf[3] != 0x03 {
		t.Errorf("command frame = % X, want a 4-byte type-0x03 record", buf)
	}
	return buf[4], buf[5], buf[6]
}

// Press() sends the inject-key command on the capture socket and returns
// on the firmware's TX/accepted event -- and only for the key it pressed:
// another key's late retry must not satisfy it.
func TestSessionPressWaitsForTX(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	s := NewSession("", "")
	s.cap = esphome.NewTestCapConn(client)
	s.wantArmed = true
	go func() {
		_, op, arg := readCommand(t, server) // the inject-key command going out
		if op != esphome.CmdInjectKey || arg != plan.KeyEnter {
			t.Errorf("command = op %d arg 0x%02X, want inject_key Enter", op, arg)
		}
		time.Sleep(20 * time.Millisecond)
		// a stale retry of a DIFFERENT key first: must not confirm Enter
		s.FeedEvent(esphome.Event{Kind: esphome.EvTxFired, Key: plan.KeyUp, Attempt: 3})
		s.FeedEvent(esphome.Event{Kind: esphome.EvKeyAccepted, Key: plan.KeyEnter})
	}()
	start := time.Now()
	if err := s.Press(plan.KeyEnter); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Press returned after %v, want the accepted event", d)
	}
}

// A rejected ack (armed gate, full queue) fails the press immediately with
// the device's verdict instead of idling out the 5 s TX-confirm timeout.
func TestSessionPressFailsFastOnNack(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	s := NewSession("", "")
	s.cap = esphome.NewTestCapConn(client)
	s.wantArmed = true
	go func() {
		id, _, _ := readCommand(t, server)
		time.Sleep(20 * time.Millisecond)
		s.FeedAck(esphome.Ack{ID: id, Status: esphome.AckRejected})
	}()
	start := time.Now()
	err := s.Press(plan.KeyEnter)
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("Press = %v, want the rejection", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Press failed only after %v, want immediately on the nack", d)
	}
}

// A capture-stream drop (another client took the single-client stream)
// must fail a pending Press immediately with ErrCaptureLost -- not after
// the full 5 s confirmation timeout -- and block further presses until
// data flows again.
func TestSessionPressFailsFastOnCaptureLoss(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	s := NewSession("", "")
	s.cap = esphome.NewTestCapConn(client)
	s.wantArmed = true
	go func() {
		readCommand(t, server) // the inject-key command going out
		time.Sleep(20 * time.Millisecond)
		s.CaptureDrop(fmt.Errorf("EOF"))
	}()
	start := time.Now()
	err := s.Press(plan.KeyEnter)
	if !errors.Is(err, ErrCaptureLost) {
		t.Fatalf("Press error = %v, want ErrCaptureLost", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Press failed only after %v, want immediately on the drop", d)
	}
	// still down: the next press refuses without touching the device
	if err := s.Press(plan.KeyEnter); !errors.Is(err, ErrCaptureLost) {
		t.Fatalf("Press on a down stream = %v, want ErrCaptureLost", err)
	}
	// capture data flowing again clears the flag
	s.FeedLine(hexLine(espFrame(0, "02:18 03/07/26 Plant1"), true))
	s.mu.Lock()
	down := s.capDown
	s.mu.Unlock()
	if down {
		t.Fatal("capDown must clear when capture data flows again")
	}
}

// Arm() drives the device purely over capture-socket commands -- enroll
// then arm -- and returns once the device confirms (state event), joins
// (join event) and the menu walker yields (hold event).
func TestSessionArmCommandSequence(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	s := NewSession("", "")
	s.cap = esphome.NewTestCapConn(client)
	// connect-time truth (the stream replays it right at attach)
	s.FeedEvent(esphome.Event{Kind: esphome.EvState, Armed: false, Enroll: esphome.EnrollNo})
	go func() {
		_, op1, arg1 := readCommand(t, server)
		_, op2, arg2 := readCommand(t, server)
		if op1 != esphome.CmdEnroll || arg1 != 1 || op2 != esphome.CmdArm || arg2 != 1 {
			t.Errorf("commands = (%d,%d) (%d,%d), want enroll(1) then arm(1)", op1, arg1, op2, arg2)
		}
		s.FeedEvent(esphome.Event{Kind: esphome.EvState, Armed: true, Enroll: esphome.EnrollYes})
		s.FeedEvent(esphome.Event{Kind: esphome.EvJoin})
		s.FeedEvent(esphome.Event{Kind: esphome.EvHold})
	}()
	start := time.Now()
	if err := s.Arm(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	// the hold event must satisfy the walker wait immediately (no grace idle)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Arm returned after %v, want event-driven", d)
	}
	if !s.HasObserve() {
		t.Fatal("the hold event must mark the device as running a walker")
	}
}

func TestSessionSettleAndGuards(t *testing.T) {
	s := NewSession("", "")
	// nothing painted, nothing arriving: quiet from the start
	start := time.Now()
	if !s.WaitSettle(60 * time.Millisecond) {
		t.Fatal("idle screen must settle")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("settle on an idle screen must not stall")
	}
	// disconnected sessions refuse to press or arm
	if err := s.Press(plan.KeyEnter); err == nil {
		t.Fatal("Press without connection must error")
	}
	if err := s.Arm(10 * time.Millisecond); err == nil {
		t.Fatal("Arm without connection must error")
	}
}

// Session plumbing for the seq-gap staleness: FeedLine -> screen, Stale()
// sees it.
func TestSessionSeqGapStale(t *testing.T) {
	line := func(seq, tsMs int, hex string) string {
		return fmt.Sprintf("[%02d:%02d:%02d.%03d][plan_cap]: [#%d|%3d] %s",
			tsMs/3600000, tsMs/60000%60, tsMs/1000%60, tsMs%1000,
			seq, len(strings.Fields(hex)), hex)
	}
	s := NewSession("", "")
	s.FeedLine(line(1, 1000, hexLine(espFrame(2, "Heating:        10.0"), true)))
	s.FeedLine(line(3, 1100, "20' 01 01 DD"))
	if !s.Stale() {
		t.Fatal("Session.Stale() must report the seq-gap flag")
	}
}
