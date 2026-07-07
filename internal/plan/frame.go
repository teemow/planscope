package plan

import (
	"fmt"
	"regexp"
)

// PageIDRe matches the application's own page code in the top-right of
// row 0 (A01, B01, C02, D14, Gd01, ...) -- the anchor for verifiable
// navigation. Pages like a status screen may carry none.
var PageIDRe = regexp.MustCompile(`^[A-Z][A-Za-z]{0,2}\d{2}$`)

// Bus addresses, frame types, and pGD geometry.
const (
	TermAddr    = 0x20 // the physical pGD (terminal 32)
	EspAddr     = 0x1F // the ESP's own session (terminal 31)
	TypeText    = 0x0B
	TypeGraphic = 0x64 // graphic bitmap (CRC-16 checksummed, like 0x65/0x66)
	TypeInit    = 0x65 // session init
	TypeCtl     = 0x66 // session ack/ctl
	DegreeByte  = 0xDF // CAREL's degree glyph
	MinWidth    = 22   // pGD text mode is 22 columns
	MinRows     = 8
	TitleBarPx  = 8 // bands at pixel y < 8 are the title bar; y >= 8 is the body
)

// pGD keypad codes (protocol reference, keypad section).
const (
	KeyEsc   = 0x01
	KeyPrg   = 0x06
	KeyAlarm = 0x0D
	KeyEnter = 0x0E
	KeyUp    = 0x0F
	KeyDown  = 0x10
)

// KeyNames maps keypad codes to their labels.
var KeyNames = map[byte]string{
	KeyEsc: "ESC", KeyPrg: "PRG", KeyAlarm: "ALARM",
	KeyEnter: "ENTER", KeyUp: "UP", KeyDown: "DOWN",
}

// Trailer is the display-frame trailer / pGD ack (01 03 20 DB).
var Trailer = []byte{0x01, 0x03, 0x20, 0xDB}

// SplitFrames splits a burst into frames at the bit9-marked address bytes.
// Bytes before the first mark (mid-frame capture start) form a headless
// fragment that is classified but never checksum-judged.
func SplitFrames(burst []Tok) (frames [][]byte, headless []bool) {
	var cur []byte
	curHeadless := true
	for _, t := range burst {
		if t.Bit9 && len(cur) > 0 {
			frames = append(frames, cur)
			headless = append(headless, curHeadless)
			cur, curHeadless = nil, false
		} else if t.Bit9 {
			curHeadless = false
		}
		cur = append(cur, t.B)
	}
	if len(cur) > 0 {
		frames = append(frames, cur)
		headless = append(headless, curHeadless)
	}
	return
}

// Classes are the traffic classes, in display order.
var Classes = []string{"poll", "disp", "walk", "key", "reply", "ack", "other"}

// Classify assigns a coarse traffic class; the first byte is the
// destination address.
func Classify(f []byte) string {
	n := len(f)
	if n == 1 {
		return "ack"
	}
	addr, ftype := f[0], f[1]
	switch {
	case n == 4 && ftype == 0x01:
		if addr == 0x01 {
			return "reply"
		}
		return "poll"
	case n == 4 && ftype == 0x03:
		return "reply" // 01 03 20 DB display-frame trailer / link reply
	case ftype == 0x02:
		return "walk" // roll-call / address scan
	case n >= 3 && ftype == 0x1E && f[2] == 0x07:
		return "key" // keypad report 01' 1E 07 20 KK NN CC
	case ftype >= 0x0B && ftype <= 0x0F, ftype >= 0x60 && ftype <= 0x6F:
		return "disp"
	}
	return "other"
}

// CRC16Modbus computes the CRC-16/Modbus of data.
func CRC16Modbus(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// ChecksumOK validates against both checksum grammars on the bus
// (verified 2026-07-02): classic frames byte-sum to 0xFF; graphic/session
// frames (0x64/0x65/0x66) carry CRC-16/Modbus little-endian as the last
// two bytes.
func ChecksumOK(f []byte) bool {
	sum := 0
	for _, b := range f {
		sum += int(b)
	}
	if sum&0xFF == 0xFF {
		return true
	}
	if len(f) >= 4 {
		crc := CRC16Modbus(f[:len(f)-2])
		return f[len(f)-2] == byte(crc) && f[len(f)-1] == byte(crc>>8)
	}
	return false
}

// Describe renders one frame human-readably for the frames view.
func Describe(f []byte, class string) string {
	switch class {
	case "poll":
		return fmt.Sprintf("poll -> terminal 0x%02X", f[0])
	case "reply":
		if f[1] == 0x03 {
			return "display trailer / link reply"
		}
		return "link reply (idle answer to poll)"
	case "walk":
		return fmt.Sprintf("roll-call probe -> 0x%02X", f[0])
	case "ack":
		return fmt.Sprintf("ack 0x%02X", f[0])
	case "key":
		if len(f) >= 7 {
			name := KeyNames[f[4]]
			if name == "" {
				name = fmt.Sprintf("0x%02X", f[4])
			}
			return fmt.Sprintf("KEY %s (hold %d)", name, f[5])
		}
		return "keypad report (short)"
	case "disp":
		switch f[1] {
		case 0x0B:
			if len(f) >= 7 {
				return fmt.Sprintf("text row %d: %q", f[4], RowText(f[5:len(f)-1]))
			}
		case 0x0C:
			if len(f) >= 8 {
				return fmt.Sprintf("numeric field SEL=0x%02X value=%d", f[4], int(f[5])<<8|int(f[6]))
			}
		case 0x64:
			return fmt.Sprintf("graphic bitmap (%d B, CRC16)", len(f))
		case 0x65:
			return "session init (CRC16)"
		case 0x66:
			return "session ack/ctl (CRC16)"
		}
		return fmt.Sprintf("display frame type 0x%02X", f[1])
	}
	return fmt.Sprintf("type 0x%02X", f[1])
}

// HexBytes renders bytes as space-separated uppercase hex.
func HexBytes(bs []byte) string {
	out := make([]byte, 0, 3*len(bs))
	for i, b := range bs {
		if i > 0 {
			out = append(out, ' ')
		}
		out = fmt.Appendf(out, "%02X", b)
	}
	return string(out)
}

// AddrName names the well-known bus addresses.
func AddrName(a byte) string {
	switch {
	case a == 0x01:
		return "uPC controller"
	case a == TermAddr:
		return "pGD display"
	case a == EspAddr:
		return "ESP (terminal 31)"
	case a >= 0x02 && a <= 0x1E:
		return "roll-call slot"
	}
	return ""
}

// TermName names a display terminal address.
func TermName(addr byte) string {
	if addr == EspAddr {
		return "terminal 31 (ESP -- our session, keys act here)"
	}
	return "terminal 32 (pGD)"
}

// Frame is one controller->terminal display frame.
type Frame struct {
	Addr    byte // destination terminal (0x20 = pGD, 0x1F = the ESP)
	Typ     byte
	Payload []byte // excludes header and checksum
	OK      bool   // checksum passed (byte-sum or CRC-16, per type)
	End     int    // offset just past the frame (incl. trailer for 0x20)
}

// ParseDisplayFrames scans a byte run for the controller->terminal envelope,
// for BOTH terminals: the pGD (0x20) and the ESP's own session (0x1F).
// pGD frames anchor on the 0x20 address + 0x01 marker + LEN-consistent
// trailer (the pGD's ack, visible on the wire), then confirm with the
// checksum. Frames to 0x1F have NO visible trailer -- the ack is the ESP's
// own transmission, which never appears in its RX log -- so they anchor on
// the address + marker and require the checksum instead. Two checksum
// grammars: classic frames byte-sum to 0xFF (last byte = check byte);
// graphic/session frames (0x64/0x65/0x66) end in CRC-16/Modbus LE.
func ParseDisplayFrames(data []byte) []Frame {
	var out []Frame
	n := len(data)
	for i := 0; i+4 <= n; {
		if (data[i] == TermAddr || data[i] == EspAddr) && data[i+3] == 0x01 {
			l := int(data[i+2])
			end := i + l
			if l > 4 && l < 250 && end <= n {
				ckLen := 1
				var ok bool
				if t := data[i+1]; t == TypeGraphic || t == TypeInit || t == TypeCtl {
					ckLen = 2
					crc := CRC16Modbus(data[i : end-2])
					ok = data[end-2] == byte(crc) && data[end-1] == byte(crc>>8)
				} else {
					sum := 0
					for _, b := range data[i:end] {
						sum += int(b)
					}
					ok = sum&0xFF == 0xFF
				}
				hasTrailer := end+4 <= n && string(data[end:end+4]) == string(Trailer)
				if data[i] == TermAddr && hasTrailer {
					out = append(out, Frame{data[i], data[i+1], data[i+4 : end-ckLen], ok, end + 4})
					i = end + 4
					continue
				}
				if data[i] == EspAddr && ok {
					out = append(out, Frame{data[i], data[i+1], data[i+4 : end-ckLen], true, end})
					i = end
					continue
				}
			}
		}
		i++
	}
	return out
}
