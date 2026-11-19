# Variants, configs and IOCs

Reversed with baksmali from three APKs. "Matches repo" means the wire protocol and the config
format are implemented by this repo's Java code.

| Sample (sha256) | Package | Built | Matches repo? |
|---|---|---|---|
| `2c5e656af90044cf5cc694519a42477cb18bd4b2722b1474cdead4a8748d3f70` | `com.Security.Update` | 2012-04 | No, variant A (below) |
| `75da4e84ac7241ba4c2f5391115b4a63f83c855ef548d8b179d5d2e3045467a1` | `com.security.patch` | 2013-07 | Yes |
| `63d59a1a83d91c86f73e62f385ef440495e7623fbef9ca1636cac9e872a18de7` | `com.core.android.defender` | 2015-05 | Yes |

Build dates are from the zip entry timestamps, so treat them as approximate. Signing certs:
`2c5e` and `75da` are Android Debug certs, `63d5` is an `Unknown` release cert (2014-08).

## C&C addresses / domains

| Source | Server |
|---|---|
| `2c5e` (variant A) | `notcompatibleapp.eu:8014`, `3na3budet9.ru:8014` |
| `75da` | `173.242.124.163:443` |
| `63d5` | `46.246.122.22:443` |
| `resources/default.config` | `94.185.85.131:443` |

`java -cp <jar> diff.notcompatible.c.bot.decrypt res/raw/data` decodes both config formats.

## Variant A (`com.Security.Update`)

Not the RSA/RC4 protocol this repo implements.

* **Config** (`res/raw/data`, 48 bytes): AES-256-ECB, no padding, key = SHA-256 of the string
  `ZTY4MGE5YQo`. Plaintext is NUL-padded ASCII `Server1|Server2|Port1|Port2`. A missing port
  falls back to 8014. `Config.Save()` rewrites it to `files/data.bin` after a server update.
* **Transport:** plaintext TCP, no key exchange. It alternates between Server1 and Server2 on
  reconnect (1 s poll loop).
* **Frame** (`MuxPacket`): `[ver=4][channel u16 LE][type u8][length u32 LE][payload]`.
  `type` must be 0 (data for proxy channel) or 1 (control), anything else is dropped.
* **Hello** (bot to server on connect): `04 00 00 01 05 00 00 00 | 00 07 00 <ConnectType u16 LE>`.
* **Server commands** (type 1, first payload byte):

  | Byte | Action |
  |---|---|
  | `01` | open proxy: byte1 = 0 for IPv4 (`a b c d`, port big-endian), 1 for `len + hostname` then port big-endian |
  | `03` | close channel |
  | `04` | ping, bot replies type 1 payload `05` |
  | `FD` | set timeout (u32 LE at 1..4), drops the link |
  | `FE` | set reserve server: ASCII host then port big-endian in the last 2 bytes, saved as Server2/Port2 |
  | `FF` | set primary server, same encoding, saved as Server1/Port1, drops the link |

* **Errors:** type 1, payload `FC <code>`; 1 = no such channel, 2 = unknown command.

Detection: `scripts/notcompatiblec.sig` (`notcompatiblea-client-hello`), `scripts/notcompatiblec.zeek`
(`Possible_VariantA_Hello`) and `scripts/notcompatiblec.nse` (`--script-args notcompatiblec.variant=a|all`,
or automatically on tcp/8014). The NSE reply check was only tested against a mock that sends a ping
frame; no real variant A server has been probed.

## C/D builds (`com.security.patch`, `com.core.android.defender`)

Same protocol, same tags, same RSA public key as `resources/default.pub`, config format identical
to `resources/default.config` (RC4 with an all-zero 20-byte key, TLV `SET` packet with `Sign`,
`DATA/GROUP/SERV/IP/PORT`, `LID`). Differences between the two:

* `75da` only: `Receiver` starts the service on `BOOT_COMPLETED` / `USER_PRESENT`;
  `check_subnet` prints `"subnet a.b.c.d e.f.g.h"` when it rejects a peer; prints
  `"P2P Incoming RSA not load"` / `"UDP P2P Incoming RSA not load"` before closing.
* `63d5` only: `Receiver` just prints `"===> " + action` (it never starts the service, so this
  looks like a debug/broken build); `ThreadServer.SendSET` closes the C&C link when connected;
  `link.init` clears `writeBuffer`.

* `ConectionManager.getServer`: `63d5` resets the server index when `count <= index` (so it rotates
  through the C&C list on failures), `75da` resets when `count >= index` and so never moves past the
  first server. This is the one difference that is visible from outside: after a failed connect a
  `63d5` bot dials the next C&C, a `75da` bot keeps retrying the first. Static markers (package name,
  cert, embedded C&C) are still the easiest way to tell them apart.

Both apply the same P2P admission rules: reject a duplicate ip:port, reject a peer in the same /24 as
an existing link (`check_subnet` returns false on a match), and mark a peer hub-only above 20 links.
