// The device-control subcommands: log and call. Both resolve the target
// through the shared device flags. Menu-navigation macros (get/set/sweep
// and friends) are device-application-specific -- they need a route and
// extractor registry for the concrete controller application, so they
// live with the consumer, not here.
package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/teemow/planscope/internal/esphome"
)

func runLog(args []string) int {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	dev := addDeviceFlags(fs)
	_ = fs.Parse(args) // ExitOnError: exits on bad flags
	addr, key := mustTarget(dev)
	// Capture records carry the device clock; stamp host wall time so
	// offline --from/--to analysis of the tee works. Everything comes off
	// the PLANCAP stream (TCP 6054): bus bytes as hex lines, typed device
	// events as [plan_evt] lines, the bridge's diagnostics as [plan_diag]
	// lines. The key is the device's api.encryption.key.
	var outMu sync.Mutex
	printLine := func(line string) {
		outMu.Lock()
		fmt.Printf("[%s]%s\n", time.Now().Format("15:04:05.000"), line)
		outMu.Unlock()
	}
	printEvent := func(e esphome.Event) { printLine("[plan_evt]: " + e.String()) }
	fmt.Fprintf(os.Stderr, "planscope: streaming the capture from %s\n", esphome.CaptureAddr(addr))
	// reconnects forever
	esphome.CaptureLoop(addr, key, nil, esphome.CaptureHooks{OnLine: printLine, OnEvent: printEvent})
	return 0
}

func runCall(args []string) int {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	dev := addDeviceFlags(fs)
	_ = fs.Parse(args) // ExitOnError: exits on bad flags
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: planscope call <service> [value]\n"+
			"e.g.   planscope call set_enroll true\n"+
			"       planscope call set_turnaround 420\n"+
			"       planscope call inject_key 0x0F")
		return 2
	}
	svc := fs.Arg(0)
	var arg []byte
	if fs.NArg() > 1 {
		v := fs.Arg(1)
		switch strings.ToLower(v) {
		case "true", "on":
			arg = esphome.PFieldVarint(nil, 1, 1)
		case "false", "off":
			arg = nil // proto3 default false is encoded as absent
		default:
			n, err := strconv.ParseInt(v, 0, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "value %q is neither true/false nor an integer\n", v)
				return 2
			}
			zz := uint64(n<<1) ^ uint64(n>>63)
			arg = esphome.PFieldVarint(nil, 5, zz)
		}
	}
	addr, k := mustTarget(dev)
	if err := esphome.CallService(addr, k, svc, arg); err != nil {
		fmt.Fprintln(os.Stderr, "call failed:", err)
		return 1
	}
	val := ""
	if fs.NArg() > 1 {
		val = " " + fs.Arg(1)
	}
	fmt.Printf("%s%s executed on %s at %s\n", svc, val, addr,
		time.Now().Format("15:04:05"))
	return 0
}

func init() {
	commands = append(commands,
		command{"log", "", "device", "stream capture lines + device events + diagnostics to stdout (the capture stream is single-client, newest wins)", runLog},
		command{"call", "<service> [value]", "device", "execute a user-defined service once (set_armed, set_enroll, inject_key, ...)", runCall},
	)
}
