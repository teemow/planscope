// planscope is an interactive pLAN terminal and protocol debugger for
// CAREL pLAN buses (pCO/µPC controllers + pGD displays), the companion
// tool to the planterm library (github.com/teemow/planterm). It talks to
// an ESP32 bridge on the bus over the ESPHome native API: it streams and
// decodes every frame live, AND sends key presses through the bridge's
// inject_key service, so the TUI acts as a second pGD terminal with a
// built-in protocol analyzer.
//
// All functionality lives under internal/:
//
//	internal/plan     pLAN frame grammar, screen reconstruction, traffic
//	                  analysis (the protocol core)
//	internal/esphome  ESPHome native-API client + raw capture stream
//	internal/device   headless device sessions (enroll, key injection,
//	                  settle detection)
//	internal/decode   offline frame-grammar workbench
//	internal/tui      the interactive terminal UI
//	internal/cli      command table, flags, dispatch
//	internal/style    ANSI styling helpers
package main

import (
	"os"

	"github.com/teemow/planscope/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
