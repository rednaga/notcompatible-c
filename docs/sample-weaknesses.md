# Weaknesses in the real C/D samples (and where the repo differed)

Everything here was read out of the smali of the two samples this repo targets
(`75da4e84…` com.security.patch and `63d59a1a…` com.core.android.defender, see
[variants.md](variants.md)). It is **static analysis only**: nothing was run against a live node
or server. Class names below are the samples' own (`p2plink`, `udppoint`, ...). Every function
mentioned is byte-for-byte equivalent in both samples unless a difference is called out.

The point of this page is to separate three things that were getting mixed up:

1. weaknesses the **malware** has (this is what matters if you are watching or probing nodes),
2. bugs that were only in this **reconstruction** and have been fixed, and
3. things in the reconstruction that are still not the same as the samples.

## 1. Weaknesses present in the samples

None of these is evidence of a way to execute code on a node. They are protocol and availability
properties.

### 1.1 C&C session does not authenticate the server (`link.onConnect` / `link.onRead`)
The bot sends its per-run RSA-1024 modulus, accepts whatever RSA-wrapped RC4 key comes back
(`rsa.decode2`, raw `RSA/NONE/NoPadding`), sets up RC4 and sends `HELO`. There is no check that the
other end knows anything secret. The bundled `res/raw/pub` key is only used to verify the `Sign` on
`SET` config packets (`rsa.check`), not on `CONN`/`SEND`/`SHUT`. Anything that can answer the outbound
connection (redirect, sinkhole, on-path) can issue `CONN` proxy requests through the bot.

### 1.2 Nested packet parser can spin forever (`packet.unpack`)
For a packet with the "has children" bit set the parser runs
`while (buffer.Size != 0) { child = unpack(buffer); if (child != null) add(child); }`.
`unpack` returns null **without consuming anything** when fewer than 5 bytes remain or when the child's
declared size is larger than what is left, so a nested packet with trailing bytes or an oversized child
loops forever. There is no depth or size bound. TCP (C&C and P2P), UDP and proxy sockets are all
serviced by one selector thread (`ThreadServer.run` → `NIOServer.DispQuery`), and each handler is wrapped
in `catch (Exception)` - which swallows crashes but not an infinite loop - so one peer that reaches
`unpack` stalls the whole process. "Reaches `unpack`" only requires finishing the unauthenticated key
exchange below.

### 1.3 P2P/UDP key exchange is unauthenticated and the RC4 key comes from `Math.random()`
The accepting side of a P2P link generates 100 key bytes with `Math.round(Math.random() * 256)`
(`p2plink.onRead`, `udppoint.RecvPublic`) and sends them encrypted to the public key the remote end
just supplied. The remote end can be anyone. `Math.random()` is a 48-bit LCG, so the key is not
100 bytes of entropy; how much is practically recoverable was **not** tested. `* 256` with `round`
also produces 256 half the time as often as other values, which wraps to 0.

### 1.4 UDP reuses the RC4 keystream (`udppoint.sendEncrypt`, `udpquery.postdata`)
Every datagram is `0x02 || RC4(key, datagram)` with a **fresh** `RC4` object built from the same
100-byte session key, in both directions. Every datagram therefore starts at keystream offset 0 and
identical plaintext prefixes (the 7-byte `udp_header`, tag bytes) give identical ciphertext.

### 1.5 Unbounded UDP peer state (`udpmixer.onRead`)
A datagram from an unknown source allocates a `udppoint` and adds it to the list **before** anything is
validated; the list has no cap (`udppointlist.Add`). The only expiry is the 60 s janitor in
`udpmixer.check`. Source addresses are spoofable, so this is a memory/CPU growth vector.

TCP is tighter than the repo used to be (see 3.1): `P2PListen.onAccept` rejects a duplicate ip:port **and**
any peer in the same /24 as an existing link (`P2PConnectionList.check_subnet`). Above 20 links
(`GetConnection() > 20`) a new peer is only marked `isOnlyHub`, not rejected.

### 1.6 Peer-supplied hub lists are trusted (`p2plink.ParseCommand`, `HubList.LoadFromPacket`)
`HUBLIST` and `UDPHUBLIST` packets from any connected peer add every `Item` (IP/Port/LC) that is not
already known, with no signature check and no count limit, and the result is saved (`hl.bin`/`uhl.bin`).
The connection manager later dials entries from that list, so a peer can steer a node's outbound
connections.

### 1.7 UDP fragment reassembly delivers partial messages (`udpqueryitem.put`)
After every fragment `put` calls `udpquery.FullSeq` with whatever has been collected (parts 1..N that
happen to be present), which deletes the item and passes the data on. For a multi-fragment message the
first fragment alone is delivered as if it were complete and later fragments start a new item with the same
sequence number. It likely goes unnoticed because most messages fit in one 500-byte fragment
(`udp_header.Count == 1` bypasses this path).

### 1.8 Smaller things
* `data.bin` (saved config) is RC4 with an all-zero 20-byte key (`config.<init>`, `new byte[0x14]`).
* RSA is 1024-bit with raw, unpadded operations (`RSA/NONE/NoPadding`).
* Key-exchange frames are not buffered: if the declared length is bigger than the bytes read so far,
  the link is closed (`p2plink.onRead`, `link.onRead`) rather than waiting for more data.
* The sample never writes its private key to disk (`rsa.GenKey` runs at startup, in memory only).
* **`HubList.GetHubListForSend` always returns an empty list.** Its loop is `for (i = 0; i < count; i++)`
  where `count` is a local that starts at 0 and is only incremented inside the loop. Every `HUBLIST` /
  `UDPHUBLIST` the bot sends in answer to `GETHUB` (TCP and UDP) is a tag with no `Item`s, so a real node
  never hands out hubs. This repo now does the same (`HubList.getHubListFordSend`).
* **`udppoint.SendGetSET` skips the 7-byte UDP header** that every other UDP message gets, so a peer's
  `udpquery.postdata` cannot parse the `GETSET` properly. Reproduced.
* **UDP fragment fields are written in the opposite order to how the bot's own receiver reads them**
  (`udppoint.send` writes `[total][index]`, `udpquery.postdata` reads `[index][total]`), so messages over
  500 bytes cannot be received by another copy of the bot. This repo keeps sending `[index][total]`,
  which is what a receiver expects, and single-fragment messages are identical either way.
* **`ConectionManager.getServer` differs between the samples**, see [variants.md](variants.md).
* A `HUBLIST` entry is only worth keeping if it is reachable: `HubList.ClearExpired` deletes every unused
  entry with status -1 (the "expiry" window is on the wrong side of `now`, so in practice any failed hub
  goes), and hub lists are sorted most-recently-connected first (`list.prSort` is a descending quicksort).

## 2. Reconstruction bugs found by this comparison (fixed)

Regression tests: `P2PLinkKeysetTest`, `SampleParityTest`, `SampleStructuresTest`,
`MockControllerIntegrationTest` (now writes the real on-disk layout).

**Crypto / key exchange**

| Where | Was | Sample behaviour |
|---|---|---|
| `P2PLink.onRead` key generation | wrote `rc4KeysetData[1]` every iteration, ~8 bits of key | fills `[1..100]`, sets `[0] = 7` afterwards |
| `P2PLink.onRead` (incoming) | closed when declared length **<** bytes read, read past the buffer when larger | closes when declared length **>** bytes read |
| `P2PLink.onRead` (outgoing) | second, unreachable key-generation block with an inverted `loadPublic` test | one block per direction |
| `Link.onRead` | key exchange also ran in states the bot ignores | only in `KEY_EXCHANGE_DONE`, parse only when `ONLINE` |
| `RSA.check` | threw on a short result, NPE on null, rejected an exactly digest-sized result | false on null / shorter; compares the digest-sized tail |

**Config / SET handling** (all of these made a bot built from this repo advertise itself differently)

| Where | Was | Sample behaviour |
|---|---|---|
| `Config` UUID | `Double.parseDouble("4643211215818981376")`: the raw IEEE-754 bit pattern of `256.0` read as a decimal, so every byte was `0xFF` | `(byte) (int) (random() * 256.0)` |
| `Config` PORT | same mistake, always 65535 (then `+1024` fixed up in `ThreadServer`) | `(int) (2048.0 + random() * 35000.0)`, no fixup |
| config root | `SET` was the root and the bot's own values lived inside it | root is `CONFIG` with `SET` (Sign + DATA) as a child, next to `UUID`/`GROUP`/`PORT`; old files are migrated on load |
| `Packet.getByName` | also matched the packet's own tag, which hid the layout error | children only |
| `P2PLink.recvSET` | looked for `Sign` inside `DATA` (never found, so SET was never accepted over P2P) and stored `DATA` only | `Sign`/`DATA` are siblings; the whole SET packet is stored |
| `Link.recvSET`, `Link.sendHello` LID | stored `DATA` only; read LID from the wrong level | whole SET packet, `SET -> DATA -> LID` |
| `ConnectionManager.load` | walked the wrong level, no fallback | `CONFIG -> SET -> DATA -> GROUP`, resets group/index if the saved group is gone |
| `ConnectionManager.getServer` | `count > index` reset the index every time | follows `63d5` (`count <= index`), see variants.md |

**P2P behaviour**

| Where | Was | Sample behaviour |
|---|---|---|
| `P2PConnectionList/UDPMixer.checkSubnet` | true on a /24 *match*; the listener's call was commented out | true when OK; `P2PListen` requires it |
| `P2PLink.recvHello` | pushed SET/hubs and closed when **not** hub-only; added a hub entry without `OP`; always dialled back | hub-only does that; entry needs `OP` + `PORT` and no existing entry; dial back needs `TM` + `PORT` |
| `P2PLink.recvLID` | `else sendSET()` also on equal LIDs | two independent checks |
| `P2PLink.onConnect` | did not reset `hr.connectCount` | resets it |
| `ThreadServer.checkP2PConnection` | closed *connected* links 15s after `lastConnect` (0 for incoming), never reaped dead ones; wrote `item.lastConnect` | closes links that are **not** connected and idle 15s (`lastUsedTime`); does not touch `lastConnect` |
| `ThreadServer.checkHub` | gated both requests on candidate counts, `udp.count < 100` | C&C `GETHUB` if `count < 100 || cand < 5`; peers unless `hub.cand >= 100 && hub.count >= 100 && udp.cand >= 5 && udp.count >= 1000` |

**Hub lists / structures**

| Where | Was | Sample behaviour |
|---|---|---|
| `HubList.clearExpired` | deleted when `lastConnect - 0x65813800 >= now` (never) | `< now` |
| `HubList.getHubListFordSend` | listed up to 21 entries | empty, see 1.8 |
| `HubListSortConnected` | compared `object2` with itself, so every sort was a no-op | compares `LastConnect` |
| `List.sort` / `List.getItem` | `count > 2` (2 items never sorted); walked off the end and NPEd | `count >= 2`; null |
| `Packet.unpack` | needed `size > 5` | `Size >= 5` |

**Sockets**

| Where | Was | Sample behaviour |
|---|---|---|
| `TCPSocket.onRead` | EOF called `onNoConnect` and never `onClose` (a closing proxy peer sent `NOCN`, not `DISC`, and stayed in the list) | EOF: `close`, `onClose`, `cancel` |
| `TCPSocket.onWrite` | closed the channel on any partial write | never closes on a partial write |
| `TCPSocket.onConnect` | cleared an already-set `OP_WRITE` | leaves it |
| `Link.recvSHUT` | set `sendAndClose` and then always closed | queued data: flag only, otherwise close |
| `ProxyLink.connect` | an unresolvable domain threw into `NIOServer`, closing the C&C link | catches `UnresolvedAddressException`, sends `NOCN` |
| `NIOServer` | refused connects were only logged; `checkTimeout` skipped the entry after a removal | everything goes through `onClose` + cancel; re-checks the same index |
| UDP: `createU2ULink` | inverted test and an unchecked null | only for peers not already linked, null-checked |
| UDP: `UDPPoint.check` | ping condition reversed | `lastChangeTime + 30000 < longCheckTime` |
| UDP: janitors | skipped an entry after each delete, `UDPQuery` expired at 6s, no self-IP check | same index re-checked, 60s, drops its own IP |
| UDP: `seq` | started at 0 | starts at 1, so the first message is 2 |
| UDP: `sendGetSET` | went through `send` (with header) | bare encrypted packet, see 1.8 |

## 3. Still different from the samples (deliberate or unfixable)

Wire-visible:
* `ThreadServer.portOpen` substitutes `127.0.0.1` when the node's own IP is not known yet; the bot would
  throw there (and drop the connection) instead.
* The HELO `CT` (connection type) is always 0. The bot sends the Android `NetworkInfo` type, which a
  desktop JVM does not have.
* UDP fragments are sent `[index][total]`, see 1.8.
* `ThreadServer.sendSET` follows `75da`; `63d5` also closes the C&C link there.
* `ConnectionManager.getServer` follows `63d5`; `75da` never rotates servers.

Behavioural / robustness (kept on purpose):
* `ThreadServer.run` keeps looping on any exception; the bot only catches `InterruptedException` and
  `IOException` and otherwise lets the thread die.
* `p2pLink`/hub selection compares `item.ip.equals(ip)`; the bot compares object references, which almost
  never match, so it will occasionally try to connect to itself.
* `NIOServer` sleeps one second before the first read of a `Link` (a repo hack for slow servers), and
  `ProxyLink.writeData` dumps proxied traffic to disk (with a reverse DNS lookup per read/write) for
  analysis. Neither exists in the bot, and the reverse lookup runs on the single selector thread.
* `Link.sendHello` tolerates a missing `LDGROUP`; the bot would throw.
* `client.public` / `client.private` are written by this repo (default permissions). The bot never
  persists its key.
* `MyBuffer.asInt64` shifts correctly; the bot's version mis-shifts when LID bytes 3 or 4 are set (LID
  >= 2^24). Every config seen so far has LID 1.
* `HubList.getNextToConnect` falls back to the last item scanned (the bot returns null); the callers
  never reach that case. `HubListSortTested` (unused in both) still compares `object2` with itself.
* `HubListItem.port`/`connectCount` are `long` here, `int` in the bot. Logging, `toString` and the
  `p2pThreadServer` / `udpThreadServer` / driver classes are repo tooling with no sample counterpart.
* `P2PLink.init` does not null the key streams / `hr` as the bot does; `UDPHeader.unpack` accepts both
  `0xFE05` and `0xFF05` as the magic; `udppoint.SendPublic` sets status 2, here `KEY_EXCHANGE_START`.

## 4. How far the comparison went

Every class in `net/`, `net/tcp`, `net/udp` and `objects/` was compared against both samples by reading
the smali (four independent passes, with the highest-impact items re-verified by hand). Everything is
static: nothing was run against a live node, and one pass can miss a difference. C and D are identical
in all of the code behind sections 1 and 2; the only differences between them are the ones listed in
[variants.md](variants.md).
