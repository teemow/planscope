// Package esphome is the PLANCAP capture-and-control client (capture.go)
// plus a minimal ESPHome native-API client. The API client exists ONLY
// for `planscope call` -- one-shot invocation of arbitrary user-defined
// services on ESPHome devices (set_tx_mode, set_turnaround, ...): connect
// on TCP 6053, do the Noise NNpsk0 handshake (or plaintext when no key is
// given), discover the services, execute one, disconnect. Everything a
// live session needs -- data, commands, diagnostics -- rides the PLANCAP
// socket on TCP 6054 instead.
//
// Wire format (mirrors aioesphomeapi):
//
//	noise:     0x01 <len:2 BE> <ciphertext>; plaintext inside a frame is
//	           <type:2 BE> <len:2 BE> <protobuf>. Handshake: client sends
//	           "\x01\x00\x00" (hello) + one frame 0x00+<noise msg1>; server
//	           answers hello (proto byte, name\0, mac\0) + 0x00+<noise msg2>.
//	           Pattern Noise_NNpsk0_25519_ChaChaPoly_SHA256, prologue
//	           "NoiseAPIInit\x00\x00", PSK = base64-decoded 32 bytes.
//	plaintext: 0x00 <varint len> <varint type> <protobuf>
package esphome

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/flynn/noise"
)

// ESPHome api.proto message type ids (only the ones we use).
const (
	msgHelloRequest                 = 1
	msgHelloResponse                = 2
	msgConnectRequest               = 3
	msgConnectResponse              = 4
	msgDisconnectRequest            = 5
	msgDisconnectResponse           = 6
	msgPingRequest                  = 7
	msgPingResponse                 = 8
	msgListEntitiesRequest          = 11
	msgListEntitiesDoneResponse     = 19
	msgListEntitiesServicesResponse = 41
	msgExecuteServiceRequest        = 42
)

// MsgExecuteServiceRequest is exported for wire-level tests.
const MsgExecuteServiceRequest = msgExecuteServiceRequest

// --- minimal protobuf encode/decode (3 field shapes are all we need) -------

func pVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

// PFieldVarint appends one varint protobuf field.
func PFieldVarint(buf []byte, field int, v uint64) []byte {
	return pVarint(pVarint(buf, uint64(field)<<3), v)
}

func pFieldBytes(buf []byte, field int, b []byte) []byte {
	buf = pVarint(buf, uint64(field)<<3|2)
	return append(pVarint(buf, uint64(len(b))), b...)
}

func pFieldFixed32(buf []byte, field int, v uint32) []byte {
	buf = pVarint(buf, uint64(field)<<3|5)
	return binary.LittleEndian.AppendUint32(buf, v)
}

// PBFixed32Field extracts the given fixed32 field from a message.
func PBFixed32Field(msg []byte, field int) uint32 {
	for len(msg) > 0 {
		tag, n := binary.Uvarint(msg)
		if n <= 0 {
			return 0
		}
		msg = msg[n:]
		switch tag & 7 {
		case 0:
			_, n := binary.Uvarint(msg)
			if n <= 0 {
				return 0
			}
			msg = msg[n:]
		case 2:
			l, n := binary.Uvarint(msg)
			if n <= 0 || uint64(len(msg[n:])) < l {
				return 0
			}
			msg = msg[n+int(l):]
		case 5:
			if len(msg) < 4 {
				return 0
			}
			if int(tag>>3) == field {
				return binary.LittleEndian.Uint32(msg)
			}
			msg = msg[4:]
		case 1:
			if len(msg) < 8 {
				return 0
			}
			msg = msg[8:]
		default:
			return 0
		}
	}
	return 0
}

// PBBytesField extracts the given length-delimited field from a message,
// skipping everything else. Returns nil if absent.
func PBBytesField(msg []byte, field int) []byte {
	for len(msg) > 0 {
		tag, n := binary.Uvarint(msg)
		if n <= 0 {
			return nil
		}
		msg = msg[n:]
		switch tag & 7 {
		case 0:
			_, n := binary.Uvarint(msg)
			if n <= 0 {
				return nil
			}
			msg = msg[n:]
		case 2:
			l, n := binary.Uvarint(msg)
			if n <= 0 || uint64(len(msg[n:])) < l {
				return nil
			}
			if int(tag>>3) == field {
				return msg[n : n+int(l)]
			}
			msg = msg[n+int(l):]
		case 5:
			if len(msg) < 4 {
				return nil
			}
			msg = msg[4:]
		case 1:
			if len(msg) < 8 {
				return nil
			}
			msg = msg[8:]
		default:
			return nil
		}
	}
	return nil
}

// --- framing ----------------------------------------------------------------

// Conn is one established API connection. The zero services map is filled
// asynchronously from the entity listing after connect.
type Conn struct {
	C   net.Conn
	enc *noise.CipherState // nil = plaintext protocol
	dec *noise.CipherState

	wmu sync.Mutex // writes come from the read loop AND the caller

	svcMu    sync.Mutex
	services map[string]uint32 // user-defined service name -> key
}

// NewTestConn wires a Conn over an existing pipe with a fixed service table
// (offline tests only).
func NewTestConn(c net.Conn, services map[string]uint32) *Conn {
	return &Conn{C: c, services: services}
}

func (a *Conn) writeMsg(typ int, payload []byte) error {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	return a.writeMsgLocked(typ, payload)
}

func (a *Conn) writeMsgLocked(typ int, payload []byte) error {
	var frame []byte
	if a.enc != nil {
		plain := make([]byte, 4, 4+len(payload))
		binary.BigEndian.PutUint16(plain[0:], uint16(typ))
		binary.BigEndian.PutUint16(plain[2:], uint16(len(payload)))
		plain = append(plain, payload...)
		ct, err := a.enc.Encrypt(nil, nil, plain)
		if err != nil {
			return err
		}
		frame = append([]byte{0x01, byte(len(ct) >> 8), byte(len(ct))}, ct...)
	} else {
		frame = pVarint(pVarint([]byte{0x00}, uint64(len(payload))), uint64(typ))
		frame = append(frame, payload...)
	}
	_, err := a.C.Write(frame)
	return err
}

// readRaw reads one raw noise frame (0x01 <len:2> <body>).
func readRaw(c net.Conn) ([]byte, error) {
	var h [3]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 0x01 {
		if h[0] == 0x00 {
			return nil, fmt.Errorf("device speaks plaintext protocol; drop the -key")
		}
		return nil, fmt.Errorf("bad frame marker 0x%02X", h[0])
	}
	body := make([]byte, int(h[1])<<8|int(h[2]))
	_, err := io.ReadFull(c, body)
	return body, err
}

func (a *Conn) readMsg() (int, []byte, error) {
	if a.enc != nil {
		frame, err := readRaw(a.C)
		if err != nil {
			return 0, nil, err
		}
		msg, err := a.dec.Decrypt(nil, nil, frame)
		if err != nil {
			return 0, nil, fmt.Errorf("decrypt: %w", err)
		}
		if len(msg) < 4 {
			return 0, nil, fmt.Errorf("short message (%d bytes)", len(msg))
		}
		return int(binary.BigEndian.Uint16(msg[0:])), msg[4:], nil
	}
	// plaintext: 0x00 <varint len> <varint type> <payload>
	one := func() (uint64, error) {
		var v uint64
		for shift := 0; ; shift += 7 {
			var b [1]byte
			if _, err := io.ReadFull(a.C, b[:]); err != nil {
				return 0, err
			}
			v |= uint64(b[0]&0x7F) << shift
			if b[0] < 0x80 {
				return v, nil
			}
		}
	}
	var m [1]byte
	if _, err := io.ReadFull(a.C, m[:]); err != nil {
		return 0, nil, err
	}
	if m[0] != 0x00 {
		return 0, nil, fmt.Errorf("device speaks encrypted protocol; pass the -key (marker 0x%02X)", m[0])
	}
	l, err := one()
	if err != nil {
		return 0, nil, err
	}
	typ, err := one()
	if err != nil {
		return 0, nil, err
	}
	payload := make([]byte, l)
	_, err = io.ReadFull(a.C, payload)
	return int(typ), payload, err
}

// --- user-defined services (the ESP's api: actions:) -----------------------

// ExecService calls a user-defined ESPHome service by name with one encoded
// ExecuteServiceArgument. Service keys are learned from the entity listing at
// connect time.
func (a *Conn) ExecService(name string, arg []byte) error {
	a.svcMu.Lock()
	k, ok := a.services[name]
	a.svcMu.Unlock()
	if !ok {
		return fmt.Errorf("device has no %q service", name)
	}
	req := pFieldFixed32(nil, 1, k)
	req = pFieldBytes(req, 2, arg)
	return a.writeMsg(msgExecuteServiceRequest, req)
}

// ExecServiceBool calls a service with one bool argument.
func (a *Conn) ExecServiceBool(name string, v bool) error {
	var arg []byte
	if v {
		arg = PFieldVarint(nil, 1, 1)
	}
	return a.ExecService(name, arg)
}

// ExecServiceInt calls a service with one integer argument.
func (a *Conn) ExecServiceInt(name string, v int64) error {
	zz := uint64(v<<1) ^ uint64(v>>63) // sint32 field 5 (api >= 1.3)
	return a.ExecService(name, PFieldVarint(nil, 5, zz))
}

// HasService reports whether the device advertised the named service.
func (a *Conn) HasService(name string) bool {
	a.svcMu.Lock()
	defer a.svcMu.Unlock()
	_, ok := a.services[name]
	return ok
}

// --- handshake + session -----------------------------------------------------

func noiseHandshake(c net.Conn, key string) (*Conn, error) {
	psk, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(psk) != 32 {
		return nil, fmt.Errorf("key must be a base64-encoded 32-byte value (the api.encryption.key from the device YAML)")
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:               noise.HandshakeNN,
		Initiator:             true,
		Prologue:              []byte("NoiseAPIInit\x00\x00"),
		PresharedKey:          psk,
		PresharedKeyPlacement: 0,
	})
	if err != nil {
		return nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	// client hello (empty frame) + handshake frame (0x00 + noise msg1)
	out := []byte{0x01, 0x00, 0x00}
	out = append(out, 0x01, byte((len(msg1)+1)>>8), byte(len(msg1)+1), 0x00)
	out = append(out, msg1...)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	// server hello: proto byte + server name (informational, skip)
	hello, err := readRaw(c)
	if err != nil {
		return nil, fmt.Errorf("server hello: %w (device rebooting or connection slots full?)", err)
	}
	if len(hello) == 0 || hello[0] != 0x01 {
		return nil, fmt.Errorf("server chose unknown protocol")
	}
	// server handshake: 0x00 + noise msg2, or 0x01 + error text
	resp, err := readRaw(c)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	if len(resp) == 0 || resp[0] != 0x00 {
		txt := strings.TrimRight(string(resp[1:]), "\x00")
		if txt == "Handshake MAC failure" {
			return nil, fmt.Errorf("invalid encryption key")
		}
		return nil, fmt.Errorf("handshake rejected: %s", txt)
	}
	_, send, recv, err := hs.ReadMessage(nil, resp[1:])
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return &Conn{C: c, enc: send, dec: recv}, nil
}

// Connect dials the device and runs handshake + hello + connect. The
// caller owns the returned connection (and must close its C).
func Connect(addr, key string) (*Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	var a *Conn
	if key != "" {
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			_ = c.Close()
			return nil, err
		}
		if a, err = noiseHandshake(c, key); err != nil {
			_ = c.Close()
			return nil, err
		}
	} else {
		a = &Conn{C: c}
	}
	// hello + connect (empty password; auth is the noise key)
	hello := pFieldBytes(nil, 1, []byte("planscope"))
	hello = PFieldVarint(hello, 2, 1) // api_version_major
	hello = PFieldVarint(hello, 3, 9) // api_version_minor
	if err := a.writeMsg(msgHelloRequest, hello); err != nil {
		_ = c.Close()
		return nil, err
	}
	if err := a.writeMsg(msgConnectRequest, nil); err != nil {
		_ = c.Close()
		return nil, err
	}
	return a, nil
}

// handleSession processes one session-bookkeeping message (service
// discovery, ping, disconnect). Returns done=true once the entity listing
// completed, and an error when the device asked to disconnect.
func (a *Conn) handleSession(typ int, payload []byte) (done bool, err error) {
	switch typ {
	case msgPingRequest:
		return false, a.writeMsg(msgPingResponse, nil)
	case msgDisconnectRequest:
		_ = a.writeMsg(msgDisconnectResponse, nil) // best-effort courtesy reply
		return false, fmt.Errorf("device requested disconnect")
	case msgListEntitiesServicesResponse:
		name := string(PBBytesField(payload, 1))
		if k := PBFixed32Field(payload, 2); name != "" && k != 0 {
			a.svcMu.Lock()
			if a.services == nil {
				a.services = map[string]uint32{}
			}
			a.services[name] = k
			a.svcMu.Unlock()
		}
	case msgListEntitiesDoneResponse:
		return true, nil
	}
	return false, nil
}

// CallService is the one-shot mode: connect, discover the user-defined
// services, execute one by name, confirm delivery with a ping, disconnect.
// The value encoding matches the plan_control device YAML actions: bools go
// as ExecuteServiceArgument bool (field 1), ints as sint (field 5).
func CallService(addr, key, name string, arg []byte) error {
	a, err := Connect(addr, key)
	if err != nil {
		return err
	}
	defer func() { _ = a.C.Close() }()
	if err := a.writeMsg(msgListEntitiesRequest, nil); err != nil {
		return err
	}
	for {
		if err := a.C.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return fmt.Errorf("service discovery: %w", err)
		}
		typ, payload, err := a.readMsg()
		if err != nil {
			return fmt.Errorf("service discovery: %w", err)
		}
		done, err := a.handleSession(typ, payload)
		if err != nil {
			return err
		}
		if done {
			break
		}
	}
	if err := a.ExecService(name, arg); err != nil {
		return err
	}
	// a ping round-trip after the (unacknowledged) service call proves the
	// device processed the ordered stream up to and including it
	if err := a.writeMsg(msgPingRequest, nil); err != nil {
		return err
	}
	for {
		if err := a.C.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return fmt.Errorf("confirm: %w", err)
		}
		typ, payload, err := a.readMsg()
		if err != nil {
			return fmt.Errorf("confirm: %w", err)
		}
		if typ == msgPingResponse {
			break
		}
		if _, err := a.handleSession(typ, payload); err != nil {
			return err
		}
	}
	_ = a.writeMsg(msgDisconnectRequest, nil) // best-effort goodbye
	return nil
}
