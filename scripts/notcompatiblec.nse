local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Attempts to detect a NotCompatible.C bot or C&C by performing the bot's own TCP
key-exchange handshake: send a dword length prefix followed by that many bytes
of a bogus "RSA public key" (any 1024-bit-shaped blob will do), and check
whether the peer replies with its own dword-length-prefixed blob the way
Link.onConnect()/onRead() in the reversed bot expect.

NotCompatible.C servers are reported to sit on port 443; infected P2P nodes
listen on a port the bot itself picked at random, so this script intentionally
does not restrict itself to 443.

Reference: https://github.com/rednaga/notcompatible-c
]]

author = "Tim 'diff' Strazzere"
license = "GPL 2.0"
categories = {"malware", "discovery"}

-- Any TCP port is a candidate (servers sit on 443, but infected P2P nodes
-- listen on a port the bot itself picked at random). Only bother probing
-- ports nmap already found open (or open|filtered, since a firewall that
-- only allows this traffic through may report that way); there is no reason
-- to spend a connect+probe cycle on a port we already know is closed.
portrule = function(host, port)
  return port.protocol == "tcp" and (port.state == "open" or port.state == "open|filtered")
end

-- Fixed probe: a 4-byte little-endian length (0x80 = 128) followed by 128
-- bytes standing in for an RSA-1024 public key modulus. The bot/server side
-- never validates this as a real key before replying with its own encrypted
-- RC4 session key (see Link.onRead() in the client source), so any
-- plausible-looking 128-byte blob works for detection purposes.
local PROBE = "\x80\x00\x00\x00" ..
    "\x1B\xB8\x95\xF3\x89\x52\x1E\xDA\xD3\xD5\x8B\xC3\xC0\x09\xF0\x3C" ..
    "\x4E\x78\x0D\x3F\x52\x57\xC1\x6E\x52\x54\xD7\x31\x45\x7E\x11\x7C" ..
    "\x86\x4D\x0A\x9C\x07\x11\x71\x1A\xD4\x54\x8D\x35\x5A\x17\x74\x93" ..
    "\xA8\xEA\x1B\x6E\xCA\xEE\x5A\x62\x38\x17\x26\x19\x8E\xD8\x26\xA7" ..
    "\xAE\xEC\x56\x95\x47\x85\x28\x6A\xF0\x4A\x08\x60\xD6\xDD\xEE\xE0" ..
    "\xA3\xAF\x85\xB6\x1F\xFC\x91\x98\x08\xA0\xD9\xEB\x65\xF0\xFA\x59" ..
    "\xC0\xFB\xE4\x27\x6F\x68\x68\xF9\xFB\x8F\x84\x44\xFD\x66\x90\x66" ..
    "\x06\xD4\x18\x21\xCB\x79\xB0\xCA\xDA\x69\x15\x13\x9F\x2C\x66\x77"

-- The expected reply is a dword length prefix too; 94.185.85.131 (and
-- everything else this script has been tested against) answers with a
-- 128-byte RSA-encrypted RC4 key, i.e. \x80\x00\x00\x00, matching the real
-- global key's size (resources/default.pub is a 1024-bit/128-byte modulus).
-- This is checked as a PREFIX, not an exact match: a server is free to flush
-- the 4-byte header and the ciphertext in one TCP write, in which case a
-- single recv() can return all 132+ bytes at once.
local EXPECTED_PREFIX = "\x80\x00\x00\x00"

action = function(host, port)
  local socket = nmap.new_socket()
  -- Keep this short and explicit. Nmap's own default NSE socket timeout is
  -- much longer than you want per-host when sweeping a whole port range or
  -- a large IP block: an ordinary open port that just ignores the probe
  -- (any plain HTTPS/SSH/etc. server) will otherwise tie up a connection for
  -- the full default timeout instead of a few seconds.
  socket:set_timeout(4000)

  local status, err = socket:connect(host, port)
  if not status then
    stdnse.debug1("connect to %s:%d failed: %s", host.ip, port.number, err or "?")
    return nil
  end

  status, err = socket:send(PROBE)
  if not status then
    stdnse.debug1("send to %s:%d failed: %s", host.ip, port.number, err or "?")
    socket:close()
    return nil
  end

  local response
  status, response = socket:receive()
  socket:close()

  if not status or not response or #response < 4 or response:sub(1, 4) ~= EXPECTED_PREFIX then
    -- Not a match: say nothing, rather than printing a negative line for
    -- every ordinary open port a broad scan touches.
    return nil
  end

  local out = {}
  if port.number == 443 then
    table.insert(out, "NotCompatible.C Server (gateway/operational C&C)")
  else
    table.insert(out, "NotCompatible.C Node (infected P2P peer)")
  end
  table.insert(out, ("Replied with a %d-byte dword-prefixed blob to the bot's key-exchange probe"):format(#response))

  return stdnse.format_output(true, out)
end
