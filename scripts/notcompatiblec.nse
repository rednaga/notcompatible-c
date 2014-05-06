local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
 
description = [[
Attempt to see if there is an active NotCompatible.C host (server or p2p host) on target ip.
]]
 
author = "Tim 'diff' Strazzere"
license = "GPL 2.0"
categories = {"malware"}
 
-- returns true if port is likely to be a NotCompatible.C node, false otherwise
-- normal servers are always on port 443, but nodes randomly generate ports
portrule = function(host, port)
    return port.protocol == "tcp"
--            and (port.state == "open" or port.state == "filtered")
end
 
action = function(host, port)
  local out = {}
 
  -- make the "OPTIONS / HTTP/1.0" request
  local socket = nmap.new_socket()
  socket:connect(host, port)
  socket:send("\x80\x00\x00\x00\x1B\xB8\x95\xF3\x89\x52\x1E\xDA\xD3\xD5\x8B\xC3\xC0\x09\xF0\x3C\x4E\x78\x0D\x3F\x52\x57\xC1\x6E\x52\x54\xD7\x31\x45\x7E\x11\x7C\x86\x4D\x0A\x9C\x07\x11\x71\x1A\xD4\x54\x8D\x35\x5A\x17\x74\x93\xA8\xEA\x1B\x6E\xCA\xEE\x5A\x62\x38\x17\x26\x19\x8E\xD8\x26\xA7\xAE\xEC\x56\x95\x47\x85\x28\x6A\xF0\x4A\x08\x60\xD6\xDD\xEE\xE0\xA3\xAF\x85\xB6\x1F\xFC\x91\x98\x08\xA0\xD9\xEB\x65\xF0\xFA\x59\xC0\xFB\xE4\x27\x6F\x68\x68\xF9\xFB\x8F\x84\x44\xFD\x66\x90\x66\x06\xD4\x18\x21\xCB\x79\xB0\xCA\xDA\x69\x15\x13\x9F\x2C\x66\x77")
  s,response = socket:receive()
  socket:close()
 
 if(response == "\x80\x00\x00\x00") then
   if(port.number == 443) then
      return "NotCompatible.C Server"
   else
      return "NotCompatible.C Node"
   end
 else
   return "Not NotCompatible.C Server/Node"
 end

  -- form the output
  table.insert(out, string.format("Request         : Random key handshake for NotCompatible.C"))
  table.insert(out, string.format("Host            : %s (%s)", host.ip, host.name))
  table.insert(out, string.format("Port            : %s", port.number))
  table.insert(out, string.match(response, "Allow: [^r]*rn"));
 
  return stdnse.format_output(true, out)
end
