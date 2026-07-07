package esphome

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/teemow/planscope/internal/plan"
)

// --- record encoders (the server side of spec section 5) --------------------

// capRecord encodes one bus-bytes record as the bridge sends it (type 0x00).
func capRecord(seq, tsMs, drops uint32, pairs []plan.Tok) []byte {
	b := make([]byte, 15, 15+2*len(pairs))
	b[0] = recPairs
	binary.LittleEndian.PutUint32(b[1:], seq)
	binary.LittleEndian.PutUint32(b[5:], tsMs)
	binary.LittleEndian.PutUint32(b[9:], drops)
	binary.LittleEndian.PutUint16(b[13:], uint16(len(pairs)))
	for _, t := range pairs {
		bit9 := byte(0)
		if t.Bit9 {
			bit9 = 1
		}
		b = append(b, t.B, bit9)
	}
	return b
}

// evRecord encodes one event record (type 0x01).
func evRecord(tsMs uint32, kind, a, bb byte) []byte {
	b := make([]byte, 8)
	b[0] = recEvent
	binary.LittleEndian.PutUint32(b[1:], tsMs)
	b[5], b[6], b[7] = kind, a, bb
	return b
}

// diagRecord encodes one diagnostic record (type 0x02).
func diagRecord(tsMs uint32, severity byte, text string) []byte {
	b := make([]byte, 8, 8+len(text))
	b[0] = recDiag
	binary.LittleEndian.PutUint32(b[1:], tsMs)
	b[5] = severity
	binary.LittleEndian.PutUint16(b[6:], uint16(len(text)))
	return append(b, text...)
}

// ackRecord encodes one command ack (type 0x04).
func ackRecord(tsMs uint32, id, status byte) []byte {
	b := make([]byte, 7)
	b[0] = recAck
	binary.LittleEndian.PutUint32(b[1:], tsMs)
	b[5], b[6] = id, status
	return b
}

// --- an in-process PLANCAP server (spec sections 2-4) ------------------------

// capServer is one accepted fake-bridge connection: banner sent, mode
// established (Noise responder handshake on a keyed server, plaintext
// hello otherwise), ready to exchange records.
type capServer struct {
	t   *testing.T
	c   net.Conn
	enc *noise.CipherState // server->client; nil = plaintext
	dec *noise.CipherState
}

func (s *capServer) readFrame() (byte, []byte) {
	var h [3]byte
	if _, err := io.ReadFull(s.c, h[:]); err != nil {
		s.t.Error("server read frame:", err)
		return 0xFF, nil
	}
	body := make([]byte, int(h[1])<<8|int(h[2]))
	if _, err := io.ReadFull(s.c, body); err != nil {
		s.t.Error("server read frame body:", err)
		return 0xFF, nil
	}
	return h[0], body
}

func (s *capServer) writeFrame(marker byte, body []byte) {
	f := append([]byte{marker, byte(len(body) >> 8), byte(len(body))}, body...)
	if _, err := s.c.Write(f); err != nil {
		s.t.Error("server write:", err)
	}
}

// serveCap runs banner + mode selection on a fresh connection. key "" =
// keyless plaintext server.
func serveCap(t *testing.T, c net.Conn, key string) *capServer {
	s := &capServer{t: t, c: c}
	if _, err := c.Write([]byte(captureBanner)); err != nil {
		t.Error("server banner:", err)
		return s
	}
	marker, body := s.readFrame()
	if key == "" {
		if marker != 0x00 || len(body) != 0 {
			t.Errorf("keyless server: first frame = marker 0x%02X len %d, want plaintext hello", marker, len(body))
		}
		return s
	}
	psk, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:               noise.HandshakeNN,
		Initiator:             false,
		Prologue:              []byte(captureBanner),
		PresharedKey:          psk,
		PresharedKeyPlacement: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if marker != 0x01 || len(body) == 0 || body[0] != 0x00 {
		t.Errorf("keyed server: first frame = marker 0x%02X, want Noise handshake", marker)
		return s
	}
	if _, _, _, err := hs.ReadMessage(nil, body[1:]); err != nil {
		// PSK mismatch: the spec's exact error text, then close
		s.writeFrame(0x01, append([]byte{0x01}, "Handshake MAC failure"...))
		c.Close()
		return s
	}
	msg2, cs0, cs1, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.writeFrame(0x01, append([]byte{0x00}, msg2...))
	s.dec, s.enc = cs0, cs1 // cs0 = initiator->responder
	return s
}

// send frames (and on a keyed session encrypts) one record.
func (s *capServer) send(rec []byte) {
	if s.enc != nil {
		ct, err := s.enc.Encrypt(nil, nil, rec)
		if err != nil {
			s.t.Error("server encrypt:", err)
			return
		}
		s.writeFrame(0x01, ct)
		return
	}
	s.writeFrame(0x00, rec)
}

// readCommand receives one client command record.
func (s *capServer) readCommand() (id, op, arg byte) {
	marker, body := s.readFrame()
	rec := body
	if s.dec != nil {
		if marker != 0x01 {
			s.t.Errorf("command frame marker = 0x%02X, want Noise", marker)
			return
		}
		var err error
		if rec, err = s.dec.Decrypt(nil, nil, body); err != nil {
			s.t.Error("server decrypt:", err)
			return
		}
	}
	if len(rec) != 4 || rec[0] != recCmd {
		s.t.Errorf("command record = % X, want 4-byte type 0x03", rec)
		return
	}
	return rec[1], rec[2], rec[3]
}

// throwawayKey generates a fresh random 32-byte base64 PSK (never a real
// device key).
func throwawayKey(t *testing.T) string {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k)
}

// espToks builds a trailer-less ESP-session (terminal 31) text frame as
// (byte, bit9) pairs -- the frames the live session actually consumes.
func espToks(row byte, text string) []plan.Tok {
	body := append([]byte{plan.EspAddr, plan.TypeText, byte(5 + len(text) + 1), 0x01, row}, text...)
	sum := 0
	for _, b := range body {
		sum += int(b)
	}
	f := append(body, byte(0xFF-sum&0xFF))
	out := make([]plan.Tok, len(f))
	for i, b := range f {
		out[i] = plan.Tok{B: b, Bit9: i == 0}
	}
	return out
}

// pollToks is the ESP's own poll token (1F' 01 01 DE): the idle traffic
// that separates display bursts on the real bus.
func pollToks() []plan.Tok {
	return []plan.Tok{{B: 0x1F, Bit9: true}, {B: 0x01}, {B: 0x01}, {B: 0xDE}}
}

// --- tests -------------------------------------------------------------------

// The capture client must reassemble records into frame-aligned capture
// lines (frames split across records reunite), surface stream gaps as line-
// seq jumps for the analyzer, declare in-band ISR drops, render
// diagnostics as [plan_diag] lines, and paint the screen identically on
// the keyless plaintext mode.
func TestCaptureStreamPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	e2 := espToks(2, "    Hotwater:   39.0")
	e7 := espToks(7, "             Auto-On")
	e3 := espToks(3, "    OutsideT:   17.8")
	snap := espToks(5, " System T:      23.9")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		s := serveCap(t, c, "")
		// state event right at session start (the bridge's connect-time
		// truth): armed=yes enroll=drain tx_mode=2
		s.send(evRecord(890, byte(EvState), 1|(EnrollDrain<<1), 2))
		// screen-snapshot replay (seq 0): one complete cached frame,
		// primes the screen without touching the live-traffic accounting
		s.send(capRecord(0, 900, 0, snap))
		// frame e2 split mid-frame across two records; e7 + a poll token
		// complete the second (the poll's bit9 mark proves e7 complete)
		s.send(capRecord(1, 1000, 0, e2[:10]))
		// events and diagnostics interleave without breaking reassembly
		s.send(evRecord(1005, byte(EvTxFired), 0x0F, 0))
		s.send(diagRecord(1023, DiagInfo, "injecting key 0x0F: 3 poll-slot(s)"))
		s.send(capRecord(2, 1010, 0, append(append(e2[10:], e7...), pollToks()...)))
		s.send(evRecord(1020, byte(EvKeyAccepted), 0x0F, 1))
		s.send(evRecord(1030, byte(EvJoin), 0, 0))
		s.send(evRecord(1040, byte(EvHold), 1, 0))
		// record 3 lost (stalled-client skip): seq jumps to 4 with 6 ISR-
		// dropped bytes declared in-band; carries a fresh complete frame
		s.send(capRecord(4, 1200, 6, append(e3, pollToks()...)))
		time.Sleep(2 * time.Second) // idle: tail flush, then test ends
	}()

	scr := plan.NewScreen()
	an := plan.NewAnalyzer(15)
	var mu strings.Builder
	var events []Event
	done := make(chan struct{})
	go func() {
		RunCapture(ln.Addr().String(), "", CaptureHooks{
			OnLine: func(line string) {
				mu.WriteString(line + "\n")
				scr.FeedLine(line)
				if tsMs, declared, seq, burst, ok := plan.ParseLine(line); ok && !plan.IsSnapshotLine(line) {
					an.Feed(tsMs, declared, seq, burst)
				}
				if scr.Rows[plan.EspAddr][3] != "" {
					select {
					case <-done:
					default:
						close(done)
					}
				}
			},
			OnEvent: func(e Event) { events = append(events, e) },
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("screen never completed; lines:\n%s", mu.String())
	}

	if got := scr.Rows[plan.EspAddr][2]; got != "    Hotwater:   39.0" {
		t.Fatalf("row 2 = %q (split frame not reassembled)", got)
	}
	if got := scr.Rows[plan.EspAddr][7]; got != "             Auto-On" {
		t.Fatalf("row 7 = %q", got)
	}
	if got := scr.Rows[plan.EspAddr][3]; got != "    OutsideT:   17.8" {
		t.Fatalf("row 3 = %q (post-gap frame lost)", got)
	}
	if scr.Bad != 0 {
		t.Fatalf("%d frames judged bad -- record boundaries corrupted frames", scr.Bad)
	}
	// the lost record must surface as analyzer loss, the drop counter as a line
	if an.LostLines != 1 || an.SeqGaps != 1 {
		t.Fatalf("lostLines=%d seqGaps=%d, want 1/1; lines:\n%s",
			an.LostLines, an.SeqGaps, mu.String())
	}
	if !strings.Contains(mu.String(), "isr_dropped=6") {
		t.Fatalf("in-band ISR drop count not surfaced:\n%s", mu.String())
	}
	// the diagnostic record becomes a [plan_diag] line on the same feed
	if !strings.Contains(mu.String(), "[plan_diag][info]: injecting key 0x0F") {
		t.Fatalf("diagnostic not rendered as a line:\n%s", mu.String())
	}
	// the seq-0 snapshot primes the screen, is tagged, and never pollutes
	// the analyzer or the gap accounting (live seq starting at 1 is no gap)
	if got := scr.Rows[plan.EspAddr][5]; got != " System T:      23.9" {
		t.Fatalf("row 5 = %q (snapshot replay not painted)", got)
	}
	if !strings.Contains(mu.String(), "[plan_snap]: [#0|") {
		t.Fatalf("snapshot line not tagged:\n%s", mu.String())
	}
	if an.Frames != 3 {
		t.Fatalf("analyzer counted %d frames, want 3 live (snapshot must not count)", an.Frames)
	}
	// typed events decode in order with their kind-specific fields
	if len(events) != 5 {
		t.Fatalf("events = %d, want 5: %v", len(events), events)
	}
	st := events[0]
	if st.Kind != EvState || !st.Armed || st.Enroll != EnrollDrain || st.TxMode != 2 || st.TsMs != 890 {
		t.Fatalf("state event = %+v", st)
	}
	if tx := events[1]; tx.Kind != EvTxFired || tx.Key != 0x0F || tx.Attempt != 0 {
		t.Fatalf("tx event = %+v", tx)
	}
	if ac := events[2]; ac.Kind != EvKeyAccepted || ac.Key != 0x0F || ac.Attempt != 1 {
		t.Fatalf("accepted event = %+v", ac)
	}
	if events[3].Kind != EvJoin {
		t.Fatalf("join event = %+v", events[3])
	}
	if h := events[4]; h.Kind != EvHold || !h.Paused {
		t.Fatalf("hold event = %+v", h)
	}
}

// A keyed session: Noise handshake with a throwaway PSK, encrypted records
// in both directions, a client command decrypted server-side and acked
// back through the encrypted stream.
func TestCaptureNoiseRoundtrip(t *testing.T) {
	key := throwawayKey(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	frame := espToks(2, "    Hotwater:   39.0")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		s := serveCap(t, c, key)
		s.send(evRecord(100, byte(EvState), 1|(EnrollYes<<1), 2))
		s.send(capRecord(1, 200, 0, append(frame, pollToks()...)))
		s.send(diagRecord(300, DiagWarning, "key 0x0F rejected: queue full"))
		// the client's command comes in encrypted; nack it
		id, op, arg := s.readCommand()
		if op != CmdInjectKey || arg != 0x0F {
			t.Errorf("command = op %d arg 0x%02X, want inject_key 0x0F", op, arg)
		}
		s.send(ackRecord(400, id, AckRejected))
		time.Sleep(2 * time.Second)
	}()

	scr := plan.NewScreen()
	var mu strings.Builder
	var events []Event
	var acks []Ack
	var conn *CapConn
	done := make(chan struct{})
	go func() {
		RunCapture(ln.Addr().String(), key, CaptureHooks{
			OnLine: func(line string) {
				mu.WriteString(line + "\n")
				scr.FeedLine(line)
			},
			OnEvent: func(e Event) {
				events = append(events, e)
				// the state event proves the session: fire the command
				if e.Kind == EvState {
					if _, err := conn.Command(CmdInjectKey, 0x0F); err != nil {
						t.Error("command:", err)
					}
				}
			},
			OnAck: func(a Ack) {
				acks = append(acks, a)
				close(done)
			},
			OnConn: func(c *CapConn) { conn = c },
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("no ack within 5s; lines:\n%s", mu.String())
	}

	if got := scr.Rows[plan.EspAddr][2]; got != "    Hotwater:   39.0" {
		t.Fatalf("row 2 = %q (encrypted record not painted)", got)
	}
	if len(events) == 0 || events[0].Kind != EvState || !events[0].Armed {
		t.Fatalf("events = %+v, want the state event first", events)
	}
	if !strings.Contains(mu.String(), "[plan_diag][warn]: key 0x0F rejected") {
		t.Fatalf("diagnostic missing:\n%s", mu.String())
	}
	if len(acks) != 1 || acks[0].Status != AckRejected {
		t.Fatalf("acks = %+v, want one rejection", acks)
	}
	// rejections surface on the line feed too (tee files, `planscope log`)
	if !strings.Contains(mu.String(), "[plan_ack]: ack id=1 rejected") {
		t.Fatalf("nack not surfaced as a line:\n%s", mu.String())
	}
}

// A wrong key must fail the handshake with the spec's exact error text
// mapped to a human diagnosis, never an unexplained hang or EOF.
func TestCaptureWrongKey(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		serveCap(t, c, throwawayKey(t)) // sends "Handshake MAC failure" and closes
	}()
	connected, err := RunCapture(ln.Addr().String(), throwawayKey(t),
		CaptureHooks{OnLine: func(string) {}})
	if connected || err == nil || !strings.Contains(err.Error(), "invalid encryption key") {
		t.Fatalf("connected=%v err=%v, want the invalid-key diagnosis", connected, err)
	}
}

// Event.String renders wire input; an out-of-range enroll value (firmware
// drift) must render, not panic the capture goroutine.
func TestEventStringMalformedEnroll(t *testing.T) {
	e := decodeEvent(1, byte(EvState), 3<<1, 0) // enroll=3: no such state
	if got := e.String(); !strings.Contains(got, "enroll=?") {
		t.Fatalf("String() = %q, want enroll=?", got)
	}
}

func TestCaptureAddr(t *testing.T) {
	if got := CaptureAddr("192.0.2.10:6053"); got != "192.0.2.10:6054" {
		t.Fatalf("CaptureAddr = %q", got)
	}
	if got := CaptureAddr("192.0.2.10"); got != "192.0.2.10:6054" {
		t.Fatalf("CaptureAddr = %q", got)
	}
}
