#!/usr/bin/env python3
"""Smoke-test a running exav container over the clamd-compatible TCP port.

Exercises the wire protocol end-to-end against the built image: PING/PONG,
VERSIONCOMMANDS, and an INSTREAM scan of the EICAR test string (which the
built-in baseline database detects), so CI proves the image actually scans —
not just that it starts. Usage: docker-smoke.py [host] [port].
"""
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3310

# The standard EICAR anti-malware test string (harmless; every scanner detects).
# Reversed, and flipped back at run time, so the 68-byte sequence is not stored
# anywhere in this tree. See `exav_unpack::eicar` for why that matters: a file
# carrying it is quarantined by any scanner that reads this repo or its releases.
EICAR = rb"*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X"[::-1]


def wait_for_port(timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((HOST, PORT), timeout=2).close()
            return
        except OSError:
            time.sleep(1)
    sys.exit(f"daemon at {HOST}:{PORT} never came up")


def send(payload):
    """One command per connection (clamd closes after a non-session command)."""
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.sendall(payload)
    chunks = []
    while True:
        b = s.recv(4096)
        if not b:
            break
        chunks.append(b)
    s.close()
    return b"".join(chunks).rstrip(b"\0").decode(errors="replace")


def cmd(word):
    return send(b"z" + word + b"\0")


def instream(data):
    frame = b"zINSTREAM\0" + len(data).to_bytes(4, "big") + data + (0).to_bytes(4, "big")
    return send(frame)


wait_for_port()

ping = cmd(b"PING")
print("PING ->", ping)
assert ping == "PONG", f"expected PONG, got {ping!r}"

vc = cmd(b"VERSIONCOMMANDS")
print("VERSIONCOMMANDS ->", vc)
assert "INSTREAM" in vc and "IDSESSION" in vc, vc

clean = instream(b"totally benign content")
print("INSTREAM(clean) ->", clean)
assert clean.endswith("OK"), clean

found = instream(EICAR)
print("INSTREAM(eicar) ->", found)
assert "FOUND" in found, found

print("smoke test OK")
