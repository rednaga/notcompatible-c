# Zeek signature for the NotCompatible.C bot<->C&C / bot<->bot TCP key exchange.
#
# Validated on Zeek 9.0.1 against a synthetic pcap (not real captured traffic):
# 5/5 expected hits (lengths 128/256/511/64, and the length word split across
# a separate packet from the key bytes), 0 false positives across 260
# should-not-match connections: 60 explicit cases (TLS, HTTP, SSH,
# DNS-over-TCP, Postgres, out-of-range lengths, a matching blob arriving
# mid-stream, a matching blob sent by the responder instead of the
# originator, 50 TLS-like payloads) plus 200 random binary payloads.
# Not validated against real NotCompatible.C traffic or
# a production sensor's live traffic -- treat a hit as "worth checking", see
# below.
#
# `zeek -r some.pcap notcompatiblec.sig` does NOT work -- a bare positional
# file is loaded as a script, not a signature file, and errors with "unknown
# identifier signature". Use `zeek -r some.pcap -s notcompatiblec.sig`, or
# `@load-sigs ./notcompatiblec.sig` as notcompatiblec.zeek does.
#
# What this matches, from Link.onConnect()/onRead() in the reversed client
# (src/main/java/diff/notcompatible/c/bot/net/tcp/Link.java):
#   client -> server: 4-byte little-endian length N, then N bytes of an RSA
#                      public key modulus (no leading zero byte). N is the
#                      byte length of a real RSA key -- in every
#                      sample/config this repo has seen N=128 (RSA-1024), but
#                      other key sizes the botnet may have used elsewhere
#                      aren't ruled out.
#
# Zeek's signature language has no way to say "read a length field, then
# match that many following bytes" (no backreferences), so this can only
# approximate the real check: it looks for a plausible little-endian length
# prefix (64-511 bytes, i.e. roughly RSA-512 through RSA-4096) immediately at
# the start of a TCP payload from the connection originator, while trying to
# rule out the two things that would otherwise swamp it with false positives
# on 443/8080/etc: a TLS record (starts 0x16 0x03) and an HTTP request line.
#
# This is a coarse PASSIVE heuristic, not a protocol validator -- treat a hit
# as "worth checking", not as a confirmed finding. Pair it with an ACTIVE
# check (this repo's notcompatiblec.nse, or scripts/zmap_verify.py) against
# resp_h before treating it as real -- a passive signature can't tell a real
# NotCompatible.C handshake apart from any other small binary protocol that
# happens to start with a plausible-looking length word.

signature notcompatiblec-looks-like-tls {
    ip-proto == tcp
    payload /^\x16\x03/
    tcp-state originator
}

signature notcompatiblec-looks-like-http {
    ip-proto == tcp
    payload /^(GET|POST|HEAD|PUT|OPTIONS|CONNECT) /
    tcp-state originator
}

signature notcompatiblec-client-pubkey {
    ip-proto == tcp
    # Little-endian dword length in [64, 511], immediately followed by the
    # start of the "key" bytes: 64-255 when byte1 is 0x00 and byte0 >= 0x40,
    # or 256-511 for any byte0 when byte1 is 0x01. Upper two length bytes
    # always zero (no sample needs a >64KB "key"). (The simpler
    # [\x00-\xff][\x00-\x01] originally here also matched lengths 0-63 --
    # confirmed by testing, e.g. length 8 and 8 zero bytes -- which this
    # tightens up.)
    payload /^([\x40-\xff]\x00|[\x00-\xff]\x01)\x00\x00/
    tcp-state originator
    requires-signature !notcompatiblec-looks-like-tls
    requires-signature !notcompatiblec-looks-like-http
    event "notcompatiblec: possible bot key-exchange start"
}

# ---------------------------------------------------------------------------
# Variant A (com.Security.Update, 2012) -- a different, plaintext protocol.
#
# Reversed from MixerSocket.onConnect()/MuxPacket.pack() in the sample with
# sha256 2c5e656af90044cf5cc694519a42477cb18bd4b2722b1474cdead4a8748d3f70.
# There is no RSA/RC4 here: the bot connects to a host:port from its AES config
# (the sample's are notcompatibleapp.eu / 3na3budet9.ru on tcp/8014) and first
# sends one 13-byte mux frame:
#     04            version (always 4)
#     00 00         channel (u16 LE, 0 = control)
#     01            dataType (1 = control)
#     05 00 00 00   payload length (u32 LE) = 5
#     00 07 00 tt tt   payload: 0x07 command, tt tt = ConnectType (u16 LE)
# Only the fixed bytes are matched (ConnectType is whatever ThreadServer.connType holds).
# This is a much more specific pattern than the C one above (11 fixed bytes), but,
# like that one, it has only been tested against synthetic traffic.
signature notcompatiblea-client-hello {
    ip-proto == tcp
    payload /^\x04\x00\x00\x01\x05\x00\x00\x00\x00\x07\x00/
    tcp-state originator
    event "notcompatiblea: possible variant A bot hello"
}
