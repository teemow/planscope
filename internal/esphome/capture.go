// Client for PLANCAP, the bridge's authenticated capture-and-control
// protocol -- the ONLY device interface for planscope's live features. One
// TCP connection (port = API port + 1) carries everything:
//
//   - capture: every byte on the pLAN with its 9th bit, lossless,
//   - typed device events (state truth, link joins, TX verdicts),
//   - diagnostics: the bridge's plan-related prose as typed records,
//     ordered with the very bus bytes they refer to,
//   - commands: arm/disarm, enroll/disenroll, key injection, with acks.
//
// The normative spec is planterm's docs/capture-protocol.md
// (github.com/teemow/planterm); this file implements the client side
// as-is -- no version negotiation, firmware and tools change in lockstep.
//
// Wire summary: banner "PLANCAP" (7 bytes, unframed), then frames
// `u8 marker (0x01 Noise / 0x00 plaintext) + u16 BE len + body`. With a
// key, the client runs a Noise NNpsk0_25519_ChaChaPoly_SHA256 handshake
// (prologue "PLANCAP", PSK = the device's api.encryption.key) and every
// frame body is one encrypted record; without a key it sends the
// plaintext hello (empty 0x00 frame) and records travel bare. One frame =
// one record; all record integers little-endian.
//
// TCP makes the transport lossless; the two residual loss modes are
// declared in-band instead of vanishing:
//
//   - ISR->stream-buffer overflow: a cumulative dropped-bytes counter in
//     every bus-bytes record,
//   - a stalled client: the firmware skips records but keeps counting seq,
//     so the client sees an honest gap.
//
// The client re-emits byte records as standard capture lines
// ("[#seq|  N] 20' 01 ..."), cut at bit9 frame boundaries, so every
// existing consumer -- screen decoder, analyzer, tee files, offline
// subcommands -- speaks it unchanged. Diagnostics become "[plan_diag]"
// lines on the same feed: logs and tee files keep full observability
// without any device log-stream subscription (a logger may drop lines
// under load, so no tool ever consumes one programmatically).
package esphome

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/teemow/planscope/internal/plan"
)

// captureBanner is both the 7-byte banner and the Noise prologue (the
// different prologue domain-separates PLANCAP from the ESPHome API, which
// shares the same PSK).
const captureBanner = "PLANCAP"

// Record types (spec section 5). 0x00-0x02 and 0x04 flow server->client,
// 0x03 client->server.
const (
	recPairs = 0x00
	recEvent = 0x01
	recDiag  = 0x02
	recCmd   = 0x03
	recAck   = 0x04
)

// Command ops (spec 5.4).
const (
	CmdArm       = 1 // arg: 0 disarm, 1 arm
	CmdEnroll    = 2 // arg: 0 leave (graceful drain), 1 join
	CmdInjectKey = 3 // arg: keycode
)

// Ack statuses (spec 5.5).
const (
	AckOK        = 0
	AckRejected  = 1
	AckUnknownOp = 2
)

// EventKind mirrors the bridge's EV_* values (spec 5.2) -- the wire
// protocol for typed device events.
type EventKind byte

const (
	EvState       EventKind = 1 // device truth: armed/enroll/tx_mode
	EvJoin        EventKind = 2 // first poll to our address answered since enroll
	EvTxFired     EventKind = 3 // a keypad report went out (per attempt)
	EvKeyAccepted EventKind = 4 // verdict: no rejection signature
	EvHold        EventKind = 5 // a menu walker on the device yielded the session
)

// Enroll states carried by EvState.
const (
	EnrollNo    = 0
	EnrollYes   = 1
	EnrollDrain = 2 // graceful leave in progress: still on the link
)

// Event is one typed device event off the capture stream.
type Event struct {
	Kind EventKind
	TsMs uint32 // device millis()
	// EvState
	Armed  bool
	Enroll byte // EnrollNo/EnrollYes/EnrollDrain
	TxMode byte
	// EvTxFired / EvKeyAccepted
	Key     byte
	Attempt byte
	// EvHold
	Paused bool // explicit pause (else: yielded to the armed write path)
}

// String renders the event as a log-style line (tee files, `planscope log`).
func (e Event) String() string {
	switch e.Kind {
	case EvState:
		// e.Enroll is raw wire input; an out-of-range value (firmware
		// drift) must not panic the capture goroutine.
		enroll := "?"
		if names := [...]string{"no", "yes", "drain"}; int(e.Enroll) < len(names) {
			enroll = names[e.Enroll]
		}
		armed := "no"
		if e.Armed {
			armed = "yes"
		}
		return fmt.Sprintf("state armed=%s enroll=%s tx_mode=%d", armed, enroll, e.TxMode)
	case EvJoin:
		return "join: first poll answered"
	case EvTxFired:
		return fmt.Sprintf("tx key=0x%02X attempt=%d", e.Key, e.Attempt)
	case EvKeyAccepted:
		return fmt.Sprintf("accepted key=0x%02X attempt=%d", e.Key, e.Attempt)
	case EvHold:
		if e.Paused {
			return "hold: scrape idle (paused)"
		}
		return "hold: scrape idle (armed)"
	}
	return fmt.Sprintf("unknown event kind=%d", e.Kind)
}

// decodeEvent unpacks the kind-specific a/b bytes.
func decodeEvent(tsMs uint32, kind, a, b byte) Event {
	e := Event{Kind: EventKind(kind), TsMs: tsMs}
	switch e.Kind {
	case EvState:
		e.Armed = a&1 != 0
		e.Enroll = a >> 1
		e.TxMode = b
	case EvTxFired, EvKeyAccepted:
		e.Key, e.Attempt = a, b
	case EvHold:
		e.Paused = a != 0
	}
	return e
}

// Ack is the server's answer to one command record (spec 5.5): the echoed
// command id plus accepted/rejected/unknown-op. "Accepted" means
// dispatched -- the outcome arrives as events (state, join, TX verdicts).
type Ack struct {
	TsMs   uint32
	ID     byte
	Status byte
}

// String renders the ack as a log-style line.
func (a Ack) String() string {
	names := [...]string{"accepted", "rejected", "unknown op"}
	st := fmt.Sprintf("status=%d", a.Status)
	if int(a.Status) < len(names) {
		st = names[a.Status]
	}
	return fmt.Sprintf("ack id=%d %s", a.ID, st)
}

// Diag is one diagnostic record (spec 5.3): the bridge's plan-related
// prose, typed and ordered with the bus bytes it refers to. Free-form text
// for humans -- anything a machine must react to is an event or an ack,
// so clients never parse it.
type Diag struct {
	TsMs     uint32
	Severity byte // 1 error, 2 warning, 3 info, 4 debug
	Text     string
}

// Diag severities.
const (
	DiagError   = 1
	DiagWarning = 2
	DiagInfo    = 3
	DiagDebug   = 4
)

// String renders the diagnostic as a capture-feed line.
func (d Diag) String() string {
	sev := "?"
	if names := [...]string{"", "error", "warn", "info", "debug"}; int(d.Severity) < len(names) && d.Severity > 0 {
		sev = names[d.Severity]
	}
	return fmt.Sprintf("[plan_diag][%s]: %s", sev, d.Text)
}

// CaptureAddr derives the capture-stream address: the API port + 1
// (6053 -> 6054).
func CaptureAddr(apiAddr string) string {
	host, _, err := net.SplitHostPort(apiAddr)
	if err != nil {
		host = apiAddr
	}
	return net.JoinHostPort(host, "6054")
}

// --- the established connection (write side) --------------------------------

// CapConn is one established PLANCAP session's write half: it frames (and
// on a keyed session encrypts) client command records. Reads stay inside
// RunCapture; commands may come from any goroutine.
type CapConn struct {
	c   net.Conn
	enc *noise.CipherState // client->server; nil = plaintext session

	wmu sync.Mutex // serializes writes AND the enc nonce sequence
	id  byte       // wrapping command-id counter (opaque echo token)
}

// NewTestCapConn wires a plaintext CapConn over an existing pipe
// (offline tests only).
func NewTestCapConn(c net.Conn) *CapConn { return &CapConn{c: c} }

// Close tears the connection down (unblocks the read loop).
func (cc *CapConn) Close() error { return cc.c.Close() }

// Command sends one command record (spec 5.4) and returns the id its ack
// will echo. Fire-and-forget on the wire; correlate the ack (and the
// resulting events) for the outcome.
func (cc *CapConn) Command(op, arg byte) (byte, error) {
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	cc.id++
	rec := []byte{recCmd, cc.id, op, arg}
	var frame []byte
	if cc.enc != nil {
		ct, err := cc.enc.Encrypt(nil, nil, rec)
		if err != nil {
			return 0, err
		}
		frame = append([]byte{0x01, byte(len(ct) >> 8), byte(len(ct))}, ct...)
	} else {
		frame = append([]byte{0x00, 0x00, byte(len(rec))}, rec...)
	}
	_, err := cc.c.Write(frame)
	return cc.id, err
}

// --- framing + handshake -----------------------------------------------------

// readCapFrame reads one frame (marker + u16 BE length + body).
func readCapFrame(c net.Conn) (marker byte, body []byte, err error) {
	var h [3]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return 0, nil, err
	}
	if h[0] > 0x01 {
		if h[0] == '2' {
			// The retired unauthenticated stream sent the 8-byte banner
			// "PLANCAP2" followed by raw records; its eighth byte lands here.
			return 0, nil, fmt.Errorf("firmware speaks the retired PLANCAP2 stream -- update plan_bridge")
		}
		return 0, nil, fmt.Errorf("bad frame marker 0x%02X", h[0])
	}
	body = make([]byte, int(h[1])<<8|int(h[2]))
	_, err = io.ReadFull(c, body)
	return h[0], body, err
}

// capHandshake runs the client (initiator) side of the Noise handshake
// (spec 4) and returns the write half plus the server->client cipher.
func capHandshake(c net.Conn, key string) (*CapConn, *noise.CipherState, error) {
	psk, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(psk) != 32 {
		return nil, nil, fmt.Errorf("key must be a base64-encoded 32-byte value (the api.encryption.key from the device YAML)")
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:               noise.HandshakeNN,
		Initiator:             true,
		Prologue:              []byte(captureBanner),
		PresharedKey:          psk,
		PresharedKeyPlacement: 0,
	})
	if err != nil {
		return nil, nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	// 0x01 frame, body = status byte 0x00 + noise handshake message 1
	out := append([]byte{0x01, byte((len(msg1) + 1) >> 8), byte(len(msg1) + 1), 0x00}, msg1...)
	if _, err := c.Write(out); err != nil {
		return nil, nil, err
	}
	marker, body, err := readCapFrame(c)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// spec 3: a closed connection without any response frame after a
			// Noise handshake means a key configuration mismatch (keyless
			// server) or another client's takeover mid-handshake
			return nil, nil, fmt.Errorf("device closed the connection during the handshake -- keyless device? drop the -key")
		}
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	if marker != 0x01 || len(body) == 0 {
		return nil, nil, fmt.Errorf("handshake: malformed response frame")
	}
	if body[0] != 0x00 {
		txt := string(body[1:])
		if txt == "Handshake MAC failure" {
			return nil, nil, fmt.Errorf("invalid encryption key")
		}
		return nil, nil, fmt.Errorf("handshake rejected: %s", txt)
	}
	_, send, recv, err := hs.ReadMessage(nil, body[1:])
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	return &CapConn{c: c, enc: send}, recv, nil
}

// --- line reassembly ---------------------------------------------------------

// fmtBurst renders (byte, bit9) pairs in the capture hex format (20' 01 ...).
func fmtBurst(burst []plan.Tok) string {
	var sb strings.Builder
	for _, t := range burst {
		if t.Bit9 {
			fmt.Fprintf(&sb, "%02X' ", t.B)
		} else {
			fmt.Fprintf(&sb, "%02X ", t.B)
		}
	}
	return strings.TrimRight(sb.String(), " ")
}

// capLiner reassembles bus-bytes records into frame-aligned capture lines.
type capLiner struct {
	pending []plan.Tok
	devSeq  uint32 // last device record seq
	outSeq  int    // client line counter (jumps encode loss)
	drops   uint32 // last in-band cumulative ISR drop count
	onLine  func(string)
}

// emit cuts everything up to the LAST bit9 mark into one line (those frames
// are complete: the next frame's address byte follows them); the tail stays
// pending until more data or an idle flush proves it complete.
func (l *capLiner) emit(tail bool) {
	cut := 0
	for i, t := range l.pending {
		if t.Bit9 {
			cut = i
		}
	}
	if tail {
		cut = len(l.pending)
	}
	if cut == 0 {
		// ponytail: unbounded garbage without bit9 marks cannot happen on a
		// healthy bus; cap defensively so a broken tap can't eat memory.
		if len(l.pending) < 2048 {
			return
		}
		cut = len(l.pending)
	}
	burst := l.pending[:cut]
	l.pending = append([]plan.Tok(nil), l.pending[cut:]...)
	l.outSeq++
	l.onLine(fmt.Sprintf("[plan_cap]: [#%d|%3d] %s", l.outSeq, len(burst), fmtBurst(burst)))
}

func (l *capLiner) record(seq, tsMs, drops uint32, pairs []plan.Tok) {
	_ = tsMs // device clock; host wall time is the session convention
	if seq == 0 {
		// Screen-snapshot replay: right at session start the bridge sends
		// its cached display frames (latest valid frame per terminal row) as
		// seq-0 records, one complete frame each, so the reconstruction
		// never starts blank. Marked #0 so consumers prime the screen but
		// keep it out of the live-traffic/loss accounting (plan.ParseLine).
		l.onLine(fmt.Sprintf("%s: [#0|%3d] %s", plan.SnapTag, len(pairs), fmtBurst(pairs)))
		return
	}
	switch {
	case l.devSeq != 0 && seq > l.devSeq+1:
		// stream gap (firmware cut a stalled client's backlog): continuity
		// broken -- drop the pending fragment, jump the line counter by the
		// lost record count so the analyzer books the loss exactly.
		l.pending = nil
		l.outSeq += int(seq - l.devSeq - 1)
	case seq <= l.devSeq:
		// device rebooted: fresh stream, rebase (analyzer rebases with us)
		l.pending = nil
		l.outSeq = 0
	}
	l.devSeq = seq
	if drops != l.drops {
		l.drops = drops
		l.onLine(fmt.Sprintf("[plan_cap]: isr_dropped=%d bytes total (stream buffer overflow)", drops))
	}
	l.pending = append(l.pending, pairs...)
	l.emit(false)
}

// --- the session -------------------------------------------------------------

// CaptureHooks are the callbacks one PLANCAP session feeds. Only OnLine
// and OnEvent are required by most callers; the rest are optional (nil).
type CaptureHooks struct {
	OnLine  func(string) // capture hex lines, diagnostic lines, stream prose
	OnEvent func(Event)  // typed device events
	OnAck   func(Ack)    // command acks (also rendered onto OnLine)
	OnDiag  func(Diag)   // diagnostics as records (also rendered onto OnLine)
	OnConn  func(*CapConn)
	OnDrop  func(error) // an ESTABLISHED stream dropped (CaptureLoop only)
}

// parseRecord dispatches one decrypted record body (spec 5). Unknown
// record types desynchronize nothing (frames delimit records) but signal
// protocol drift, so they stay fatal per spec 7.
func parseRecord(rec []byte, l *capLiner, h CaptureHooks) error {
	if len(rec) == 0 {
		return fmt.Errorf("empty record")
	}
	switch rec[0] {
	case recPairs:
		if len(rec) < 15 {
			return fmt.Errorf("short bus-bytes record (%d bytes)", len(rec))
		}
		seq := binary.LittleEndian.Uint32(rec[1:])
		tsMs := binary.LittleEndian.Uint32(rec[5:])
		drops := binary.LittleEndian.Uint32(rec[9:])
		np := int(binary.LittleEndian.Uint16(rec[13:]))
		raw := rec[15:]
		if len(raw) != 2*np {
			return fmt.Errorf("bus-bytes record: %d pairs declared, %d bytes carried", np, len(raw))
		}
		pairs := make([]plan.Tok, np)
		for i := range pairs {
			pairs[i] = plan.Tok{B: raw[2*i], Bit9: raw[2*i+1] != 0}
		}
		l.record(seq, tsMs, drops, pairs)
	case recEvent:
		if len(rec) != 8 {
			return fmt.Errorf("event record: %d bytes", len(rec))
		}
		e := decodeEvent(binary.LittleEndian.Uint32(rec[1:]), rec[5], rec[6], rec[7])
		if h.OnEvent != nil {
			h.OnEvent(e)
		}
	case recDiag:
		if len(rec) < 8 {
			return fmt.Errorf("diagnostic record: %d bytes", len(rec))
		}
		n := int(binary.LittleEndian.Uint16(rec[6:]))
		if len(rec) != 8+n {
			return fmt.Errorf("diagnostic record: len %d declared, %d carried", n, len(rec)-8)
		}
		d := Diag{TsMs: binary.LittleEndian.Uint32(rec[1:]), Severity: rec[5], Text: string(rec[8:])}
		l.onLine(d.String())
		if h.OnDiag != nil {
			h.OnDiag(d)
		}
	case recAck:
		if len(rec) != 7 {
			return fmt.Errorf("ack record: %d bytes", len(rec))
		}
		a := Ack{TsMs: binary.LittleEndian.Uint32(rec[1:]), ID: rec[5], Status: rec[6]}
		if a.Status != AckOK {
			l.onLine("[plan_ack]: " + a.String())
		}
		if h.OnAck != nil {
			h.OnAck(a)
		}
	default:
		return fmt.Errorf("unknown record type %d (protocol drift?)", rec[0])
	}
	return nil
}

// RunCapture connects one PLANCAP session and feeds the hooks until the
// connection drops. With a key the session is Noise-encrypted; without
// one it uses the keyless plaintext mode. connected reports whether the
// session was established (banner + mode): a drop AFTER that means an
// established stream ended -- on this single-client stream that is the
// signature of another client taking it over (or a device reboot), which
// callers surface instead of going silently blind.
func RunCapture(addr, key string, h CaptureHooks) (connected bool, err error) {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false, err
	}
	defer func() { _ = c.Close() }()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return false, err
	}
	banner := make([]byte, len(captureBanner))
	if _, err := io.ReadFull(c, banner); err != nil {
		return false, fmt.Errorf("capture banner: %w", err)
	}
	if string(banner) != captureBanner {
		return false, fmt.Errorf("not a %s stream (banner %q)", captureBanner, banner)
	}

	var cc *CapConn
	var dec *noise.CipherState
	if key != "" {
		if cc, dec, err = capHandshake(c, key); err != nil {
			return false, err
		}
	} else {
		// plaintext hello: an empty 0x00 frame, keyless servers only
		if _, err := c.Write([]byte{0x00, 0x00, 0x00}); err != nil {
			return false, err
		}
		cc = &CapConn{c: c}
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return false, err
	}
	h.OnLine("[plan_cap]: connected (authenticated capture-and-control stream)")
	if h.OnConn != nil {
		h.OnConn(cc)
	}

	l := &capLiner{onLine: h.OnLine}
	var hdr [3]byte
	for {
		// The pLAN idles at ~40 polls/s so records normally flow constantly;
		// a quiet gap before the next frame is the tail-flush boundary. The
		// first header byte is awaited alone so a frame split across TCP
		// segments can never be mistaken for idleness.
		if err := c.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return true, err
		}
		if _, err := io.ReadFull(c, hdr[:1]); err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				return true, err
			}
			l.emit(true) // bus idle: the pending frame is complete
			if err := c.SetReadDeadline(time.Now().Add(90 * time.Second)); err != nil {
				return true, err
			}
			if _, err := io.ReadFull(c, hdr[:1]); err != nil {
				return true, err // >90 s without even a state event = dead link
			}
		}
		if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return true, err
		}
		if hdr[0] > 0x01 {
			return true, fmt.Errorf("bad frame marker 0x%02X", hdr[0])
		}
		if _, err := io.ReadFull(c, hdr[1:]); err != nil {
			return true, err
		}
		body := make([]byte, int(hdr[1])<<8|int(hdr[2]))
		if _, err := io.ReadFull(c, body); err != nil {
			return true, err
		}
		rec := body
		if dec != nil {
			if hdr[0] != 0x01 {
				return true, fmt.Errorf("plaintext frame on an encrypted session")
			}
			if rec, err = dec.Decrypt(nil, nil, body); err != nil {
				return true, fmt.Errorf("decrypt: %w", err)
			}
		} else if hdr[0] != 0x00 {
			return true, fmt.Errorf("encrypted frame on a plaintext session (device got a key?)")
		}
		if err := parseRecord(rec, l, h); err != nil {
			return true, err
		}
	}
}

// CaptureLoop dials the capture stream forever (5 s retry), feeding the
// hooks; it stops when done closes (a nil channel never does). An
// ESTABLISHED stream that drops is announced on OnLine (the stream is
// single-client, newest wins -- a drop means another client took it) and,
// when OnDrop is set, signaled there too so sessions can fail pending key
// presses fast instead of timing out blind.
func CaptureLoop(apiAddr, key string, done chan struct{}, h CaptureHooks) {
	addr := CaptureAddr(apiAddr)
	for {
		connected, err := RunCapture(addr, key, h)
		if connected {
			h.OnLine(fmt.Sprintf("[plan_cap]: capture stream lost (%v) -- another client attached? reconnecting", err))
			if h.OnDrop != nil {
				h.OnDrop(err)
			}
		}
		select {
		case <-done:
			return
		case <-time.After(5 * time.Second):
		}
	}
}
