# planscope

An interactive **pLAN terminal and protocol debugger** for CAREL pLAN buses
(pCO/µPC controllers + pGD display terminals) — the companion tool to
[planterm](https://github.com/teemow/planterm), the open-source pLAN
terminal protocol library.

planscope talks to an ESP32 bridge that sits on the pLAN (a device running
a planterm-based capture/terminal firmware) over **PLANCAP**, the bridge's
authenticated capture-and-control protocol (TCP 6054, Noise-encrypted). It
streams every frame on the bus, splits bursts into real frames at the bit9
address marks (`20'`), validates both checksum grammars (sum-to-`0xFF`
classic frames, CRC-16/Modbus little-endian on the `0x64/0x65/0x66`
graphic/session frames), decodes and classifies everything — and it
**sends key presses back** through the same connection, so your terminal
acts as a second pGD with a built-in protocol analyzer.

The protocol itself is documented in the
[planterm protocol reference](https://github.com/teemow/planterm/blob/main/docs/protocol.md);
`planscope protocol` prints a condensed version next to the live views.
planscope was extracted from a private heat-pump reverse-engineering
project and is verified against one µPC + pGD installation; reports from
other pLAN hardware are very welcome.

**What you need for the live features** — a bridge device that speaks
[PLANCAP](https://github.com/teemow/planterm/blob/main/docs/capture-protocol.md):
an ESP32 (or similar) on the pLAN's RS-485 bus running a firmware that
serves the capture-and-control socket, summarized in
["The device side"](#the-device-side-what-the-firmware-must-provide)
below. The supported firmware is planterm's
[`plan_bridge` ESPHome component](https://github.com/teemow/planterm/tree/main/esphome/components/plan_bridge)
(consumable as an ESPHome external component; planterm also provides the
protocol engine and session code if you want to roll your own).
**Without a bridge device**, planscope still works as a pure offline
analyzer over hex capture files (everything under "Offline capture
analysis").

## Views

| key | view      | shows |
|-----|-----------|-------|
| `1` | screen    | the pGD display rendered live (text-row frames) |
| `2` | frames    | every frame on the wire, decoded and described |
| `3` | timeline  | per-interval traffic counts per class + checksum failures |
| `4` | addresses | per-address traffic, failures, and who each address is |
| `5` | errors    | checksum-failing frames verbatim — the objective garble detector |

## Terminal keys

| key | action |
|-----|--------|
| `↑` `↓` | pGD UP / DOWN |
| `Enter` | pGD ENTER |
| `Esc`   | pGD ESC |
| `p`     | pGD PRG |
| `a`     | pGD ALARM |
| `w`     | arm: write-enable **+ enroll as terminal 31** (PLANCAP commands) |
| `1`-`5` | switch view |
| `q`     | quit |

Key injection is **gated**: the bridge boots disarmed and drops injected
keys until `w` arms it. Arming also **enrolls the bridge as pLAN terminal
31** — keys are injected in terminal 31's own poll slot, which only exists
while enrolled. While enrolled the controller parks its keypad poll slot on
31, so the physical pGD's keypad is dead and its display is served only
sporadically (occasional "no link" flicker is inherent to being enrolled).
Disarming with `w` only drops the write gate — **enrollment persists for
the session** and is released once on quit (`q`), because every leave costs
a net rebuild (FF-walk + pGD re-ident + repaint). **Always quit rather than
kill** the TUI so the pGD gets its poll slot back. planscope assumes
disarmed after every (re)connect, which can only block — never cause — a
transmission, and reconnects automatically when the device reboots.

## Install

```sh
go install github.com/teemow/planscope@latest
```

or clone and `go build .`

## Usage

Put the device address and API key in `~/.config/planscope/config` once:

```
device = 192.0.2.10
key = "<api-encryption-key>"
```

then just run:

```sh
planscope
```

`key` is the device's `api.encryption.key` (base64, from the device YAML)
— one key secures both the ESPHome API and the PLANCAP socket; omit it
for a keyless device. Everything can also be given on the command line
(flags beat the `PLANSCOPE_KEY` env var, which beats the config file):

```sh
planscope --device 192.0.2.10 --key '<api-encryption-key>'
planscope --config /path/to/other/config
```

## Headless device control

```sh
planscope log > run.log            # tee the capture stream to a file:
                                   # bus bytes, device events, diagnostics
                                   # (host [HH:MM:SS.mmm] timestamps added)
planscope call set_tx_mode 2       # one-shot ESPHome service call
planscope call set_turnaround 420
```

`call` is the one command that does NOT use PLANCAP: it invokes an
arbitrary user-defined service over the ESPHome native API (TCP 6053) on
devices that expose extra tuning knobs there. `true`/`false` encode as
bool, anything else as an integer. A ping round-trip after the call
confirms the device processed it. Everything else — data, arm/enroll,
key injection, diagnostics — rides the PLANCAP socket.

The device capture stream is **single-client, newest wins**: a parallel
`planscope log` (or a second TUI) steals the stream and blinds the running
session. One live planscope at a time.

Menu-navigation macros (transactional get/set of named config values,
scrape routes, alarm-history dumps) are **not** part of this tool: they
need a route and field-extractor registry for the concrete controller
*application*, which is installation-specific data. The generic session
engine they run on (enroll/arm choreography, TX-confirmed key presses,
settle detection, verified page identity) ships in `internal/device`.

## Offline capture analysis

Piped input analyzes a saved capture instead of a live device and prints
the full report at EOF — screen, timeline, per-address table, and every
failing frame verbatim:

```sh
planscope < capture.log
planscope --bucket 60 --from 14:00:00 --to 14:30:00 < capture.log
planscope report --bucket 60 capture.log        # same report, as a subcommand
```

The grammar workbench that bootstrapped the protocol understanding lives
on as subcommands. They accept raw hex captures or bit9-marked capture
lines, files or stdin:

```sh
planscope analyze idle.log            # infer lengths, checksum, length field
planscope regroup idle.log            # re-split merged frames via checksum
planscope correlate idle.log keys.log # diff two captures -> event frames
planscope records idle.log            # 20 0C field records per selector
planscope screen idle.log             # reconstruct the pGD text screen
planscope bursts navigate.log         # find redraw bursts per selector
planscope help                        # all subcommands and their flags
```

## The device side (what the firmware must provide)

The bridge serves **PLANCAP** on TCP 6054 (the ESPHome API port + 1); the
normative wire specification is
[planterm's capture-protocol.md](https://github.com/teemow/planterm/blob/main/docs/capture-protocol.md).
In short:

- **One authenticated connection carries everything.** After the 7-byte
  banner `PLANCAP`, the client (planscope) runs a Noise
  `NNpsk0_25519_ChaChaPoly_SHA256` handshake — same suite as the ESPHome
  native API, same pre-shared key (`api.encryption.key`), different
  prologue — and every frame after it is one encrypted record. A device
  configured without a key falls back to a plaintext mode.
- **Server → client records:** raw bus bytes (with seq numbers, the
  in-band ISR drop counter, and a screen-snapshot replay at session
  start so clients never start blank), typed device events (state truth,
  link join, TX fired / key accepted, walker hold), and diagnostics
  (the bridge's plan-related prose as typed records, ordered with the
  very bus bytes they refer to).
- **Client → server records:** commands — arm/disarm, enroll/disenroll,
  inject key — each acked by the server. planscope needs **no other
  channel** for its live features; nothing ever subscribes to a device
  log stream (a logger may drop lines under load, so nothing
  data-bearing travels there).
- The stream is single-client: a new connection replaces the old one.

The client re-emits byte records as text capture lines
(`[#seq|  N] 20' 01 01 DD ...` — two hex digits per byte, a trailing
apostrophe marking bytes that carried the 9th bit), which is also the
format all offline subcommands consume; device events and diagnostics
become `[plan_evt]`/`[plan_diag]` lines on the same feed.

**Security:** both directions are encrypted and authenticated with the
PSK — a passive observer learns timing and sizes, not content (the
display shows service PINs while they are typed); an active attacker
without the key can inject nothing. There is no identity beyond the key.
The keyless plaintext mode has none of these properties: run keyless
bridges on trusted networks only, or better, configure a key.

## Code layout

A thin `main.go` dispatches into `internal/`:

| package | responsibility |
|---------|----------------|
| `internal/plan`    | the protocol core: line/frame parsing, both checksum grammars, screen reconstruction, traffic analysis |
| `internal/esphome` | the PLANCAP capture-and-control client (TCP 6054, Noise/plaintext) + a minimal ESPHome API client for `planscope call` |
| `internal/device`  | stateful headless sessions: arm/enroll choreography, TX-confirmed key presses, settle detection |
| `internal/decode`  | the offline frame-grammar workbench |
| `internal/tui`     | the interactive terminal UI (views, pGD rendering, keyboard) |
| `internal/cli`     | the command table: dispatch, unified help, shared device flags, config |
| `internal/style`   | ANSI styling helpers |

Dependencies flow strictly downward: `cli` → `tui`/`device`/`decode` →
`esphome`/`plan` → `style`. Each package carries its own tests:

```sh
go test ./...
```

## License

MIT — see [LICENSE](LICENSE).
