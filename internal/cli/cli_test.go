package cli

import (
	"os"
	"testing"
	"time"

	"github.com/teemow/planscope/internal/esphome"
)

func TestLoadConfig(t *testing.T) {
	f := t.TempDir() + "/config"
	if err := os.WriteFile(f, []byte(
		"# planscope\ndevice = 192.0.2.10\nkey = \"abc==\"\n\njunk line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := LoadConfig(f)
	if cfg["device"] != "192.0.2.10" || cfg["key"] != "abc==" {
		t.Fatalf("cfg = %v", cfg)
	}
	if len(LoadConfig(f+".missing")) != 0 {
		t.Fatal("missing file must yield empty config")
	}
}

// Live check against the real ESP (read-only: establishes the PLANCAP
// session and awaits the replayed state event; presses nothing).
// Gated: PLANSCOPE_LIVE=1 go test -run TestLiveCapture -v
func TestLiveCapture(t *testing.T) {
	if os.Getenv("PLANSCOPE_LIVE") == "" {
		t.Skip("set PLANSCOPE_LIVE=1 to run against the device")
	}
	cfg := LoadConfig(DefaultConfigPath())
	if cfg["device"] == "" {
		t.Fatal("no device in config")
	}
	states := make(chan esphome.Event, 1)
	go esphome.RunCapture(esphome.CaptureAddr(cfg["device"]+":6053"), cfg["key"],
		esphome.CaptureHooks{
			OnLine: func(string) {},
			OnEvent: func(e esphome.Event) {
				if e.Kind == esphome.EvState {
					select {
					case states <- e:
					default:
					}
				}
			},
		})
	select {
	case <-states:
	case <-time.After(10 * time.Second):
		t.Fatal("no state event within 10s (handshake failed, or stream taken?)")
	}
}
