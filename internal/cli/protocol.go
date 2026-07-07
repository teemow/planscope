package cli

// protocolHelp is the pLAN protocol reference manual (planscope protocol).
const protocolHelp = `THE pLAN PROTOCOL -- what planscope shows you
(reverse-engineered; full reference: github.com/teemow/planterm docs/protocol.md)

Physical layer
  RS485 multidrop bus, 62500 baud, 9 data bits: the 9th bit is SET on the
  first byte of every frame and marks it as an ADDRESS byte (shown as 20').
  Everything between two address bytes belongs to one frame.

Who is who (destination address = first byte of a frame)
  0x01  the uPC controller (bus master)
  0x20  the pGD display terminal (default pLAN address 32)
  0x1F  terminal 31 -- the ESP32 bridge enrolls here
  0x02..0x1E  the roll-call slots the controller scans for new terminals

Link layer -- the idle heartbeat (~93% of traffic)
  poll       20' 01 01 DD        controller asks a terminal "alive?"
  reply      01' 01 20 DD        terminal answers within ~420 us
  ack        01'                 controller acknowledges
  Every enrolled terminal must answer every poll or its link resets ~2 s
  later (the pGD shows NO LINK). The ESP answers its 0x1F polls from an ISR.

Roll-call -- how a terminal joins
  walk       0xNN' 02 01 80 00 00 01 80 00 00 00 CK
  The controller cycles probes through unenrolled addresses; answering the
  probe for your address enrolls you as that terminal.

Keypad -- how key presses travel (terminal -> controller)
  in the response slot of a poll, back-to-back:
  01' 1E 07 20 KK NN CC   +   01' 01 20 DD
  keypad report (body sums to 0xFE) + the normal link reply.
  KK: 01 ESC  06 PRG  0D ALARM  0E ENTER  0F UP  10 DOWN
  NN ramps while a key is held; CC is the make-weight check byte.

Display session -- how the screen gets painted (controller -> terminal)
  envelope   20 TYPE LEN 01 <payload> CK | 01 03 20 DB
  0x0B  text row     payload = ROW + ASCII chars (0xDF = degree glyph)
  0x0C  single cell  payload = ROW COL CHAR (drifting digits, edit mode)
  0x0D  cursor       payload = ROW COL 01 (edit focus position)
  0x64  graphic bitmap (icons / large font pixel runs)
  0x65  session init   0x66  session ack/ctl
  The controller opens a display session ONLY for terminals in its
  configured terminal list; it repaints only rows that changed.

Checksums -- the objective garble detector (two grammars!)
  classic frames        whole frame byte-sums to 0xFF (mod 256)
  0x64/0x65/0x66 frames CRC-16/Modbus over the body, little-endian trailer
  A checksum failure in the errors view = a corrupted frame on the wire.`
