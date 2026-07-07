package esphome

import (
	"net"
	"testing"
)

// inject_key must go out as ExecuteServiceRequest: fixed32 service key +
// one ExecuteServiceArgument with the keycode zigzag-encoded in field 5.
func TestExecServiceWire(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	a := NewTestConn(client, map[string]uint32{"inject_key": 0xCAFE0001})

	go func() {
		if err := a.ExecServiceInt("inject_key", 0x0F); err != nil {
			t.Error(err)
		}
	}()
	// plaintext framing: 0x00 <varint len> <varint type> <payload>
	buf := make([]byte, 64)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x00 || int(buf[2]) != msgExecuteServiceRequest {
		t.Fatalf("frame header % X", buf[:3])
	}
	payload := buf[3:n]
	if got := PBFixed32Field(payload, 1); got != 0xCAFE0001 {
		t.Fatalf("service key = 0x%X", got)
	}
	arg := PBBytesField(payload, 2)
	// field 5 varint, zigzag(0x0F) = 0x1E
	if want := []byte{0x28, 0x1E}; string(arg) != string(want) {
		t.Fatalf("arg = % X, want % X", arg, want)
	}

	if err := a.ExecService("no_such_service", nil); err == nil {
		t.Fatal("unknown service must error")
	}
}
