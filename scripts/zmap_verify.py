#!/usr/bin/env python3
"""
Stage-2 application-layer verifier for a zmap discovery scan, for finding
live NotCompatible.C nodes/servers.

zmap itself is a stateless SYN scanner: it is good at finding "is TCP/443 (or
whatever port) open on this address" across the whole IPv4 space very fast,
but it does not maintain a TCP connection or send/parse an application-layer
payload. There is no stock zmap probe module that performs the bot's own
handshake (send a dword-length-prefixed fake RSA key, check for a matching
dword-length-prefixed reply) -- that needs a real connection with buffered
reads, which is exactly what zmap intentionally does not do.

The standard way to use zmap for this kind of census is a two-stage
pipeline, the same pattern zmap's own authors use with zgrab/zgrab2:

    zmap -p <port> --output-fields=saddr <range or allowlist> \
        | python3 scripts/zmap_verify.py --port <port> -o results.jsonl

This script is stage 2: it takes the list of IPs zmap found with that port
open, and for each one does the real protocol check this repo's NSE script
(scripts/notcompatiblec.nse) does, concurrently and with a tight timeout, so
it is safe to point at the millions of candidates a /0 zmap scan on 443 can
produce.

Output is JSON Lines, one object per address that replied with a plausible
NotCompatible.C handshake response, suitable for further triage (e.g.
cross-referencing against abuse contacts before any notification, or feeding
into a takedown/sinkhole coordination effort). This script only completes
the bot's own TCP key exchange -- it never requests a hub list, never opens
a CONN/SEND proxy channel, and never does anything past the initial
reachability/protocol check.
"""

import argparse
import asyncio
import json
import sys
import time

# Same fixed probe the NSE script sends: a 4-byte little-endian length (128)
# followed by 128 bytes standing in for an RSA-1024 public key modulus. The
# bot/server side never validates this as a real key before replying with
# its own RSA-encrypted RC4 session key (see Link.onRead() in the client
# source) -- any plausible-looking 128-byte blob is enough to elicit it.
PROBE = bytes.fromhex(
    "800000001bb895f389521edad3d58bc3c009f03c4e780d3f5257c16e5254d731457e117c"
    "864d0a9c0711711ad4548d355a177493a8ea1b6ecaee5a62381726198ed826a7aeec569"
    "54785286af04a0860d6ddeee0a3af85b61ffc919808a0d9eb65f0fa59c0fbe4276f6868"
    "f9fb8f8444fd66906606d41821cb79b0cada6915139f2c6677"
)  # byte-for-byte identical to the PROBE string in notcompatiblec.nse
EXPECTED_PREFIX = b"\x80\x00\x00\x00"


async def check_one(ip: str, port: int, timeout: float) -> dict | None:
    t0 = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return None

    try:
        writer.write(PROBE)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        writer.close()

    if not response or len(response) < 4 or response[:4] != EXPECTED_PREFIX:
        return None

    return {
        "ip": ip,
        "port": port,
        "response_len": len(response),
        "rtt_ms": round((time.monotonic() - t0) * 1000, 1),
        "role": "server" if port == 443 else "node",
    }


async def worker(queue: "asyncio.Queue[str]", port: int, timeout: float,
                  out, concurrency_sem: asyncio.Semaphore, counters: dict):
    while True:
        ip = await queue.get()
        if ip is None:
            queue.task_done()
            return
        async with concurrency_sem:
            result = await check_one(ip, port, timeout)
        counters["checked"] += 1
        if result:
            counters["hits"] += 1
            out.write(json.dumps(result) + "\n")
            out.flush()
            print(f"[+] {ip}:{port} -> {result['role']} "
                  f"({result['response_len']} bytes, {result['rtt_ms']} ms)",
                  file=sys.stderr)
        queue.task_done()


async def main_async(args):
    queue: "asyncio.Queue[str]" = asyncio.Queue()
    sem = asyncio.Semaphore(args.concurrency)
    counters = {"checked": 0, "hits": 0}

    with open(args.output, "a") as out:
        workers = [
            asyncio.create_task(worker(queue, args.port, args.timeout, out, sem, counters))
            for _ in range(args.concurrency)
        ]

        source = sys.stdin if args.input == "-" else open(args.input)
        for line in source:
            ip = line.strip().split(",")[0]  # tolerate zmap's CSV output-fields format
            if ip and ip != "saddr":
                await queue.put(ip)
        if source is not sys.stdin:
            source.close()

        for _ in workers:
            await queue.put(None)
        await asyncio.gather(*workers)

    print(f"checked={counters['checked']} hits={counters['hits']}", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-i", "--input", default="-",
                    help="file of candidate IPs (one per line, or zmap CSV with an saddr "
                         "column), default stdin")
    p.add_argument("-o", "--output", required=True, help="JSON Lines output file (appended)")
    p.add_argument("--port", type=int, default=443, help="TCP port to probe (default 443)")
    p.add_argument("--timeout", type=float, default=4.0,
                    help="per-connection timeout in seconds (default 4.0)")
    p.add_argument("--concurrency", type=int, default=200,
                    help="number of connections in flight at once (default 200; keep this "
                         "modest -- this is meant to confirm a short zmap candidate list, "
                         "not to re-implement zmap's own scale)")
    args = p.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
