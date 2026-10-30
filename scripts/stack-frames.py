#!/usr/bin/env python3
"""Audits the stack frames of the functions that recurse into nested input.

A container inside a container, a group inside a group: each level of nesting
keeps the frames of the walk that reads it on the stack while the next level is
read. A walk that holds a decoder or a large model value by value has a frame of
tens of kilobytes, and sixteen levels (more with `--max-unpack-depth`) are past
the stack of a worker thread. The size of a frame is a property of the compiled
code, not of the source, and a release build and a test build differ, so it is
read from the release binary.

    scripts/stack-frames.py target/release/exav [more binaries...]
    scripts/stack-frames.py --all --min-kib 8 target/release/exav

Exits 1 when a function that is on a recursion path has a frame over
`--max-kib` (16 by default). The functions are the WATCHED patterns below; add
the walk of a format here when it is added.

Needs `objdump` (binutils or LLVM's, which the toolchain's `llvm-tools` has),
on aarch64 or x86_64.
"""

import argparse
import re
import shutil
import subprocess
import sys

# Demangled names, matched anywhere in the name.
WATCHED = [
    # The walk of each container format and the shared streaming of members.
    r"exav_unpack::formats::\w+::walk\b",
    r"exav_unpack::formats::\w+::walk_\w+",
    r"exav_unpack::stream::",
    # The scan's own recursion into members.
    r"exav_core::walk_members",
    r"exav_core::scan_found",
    r"exav_core::scan_object",
    # The converters' walks of shapes, blocks, groups and nested values.
    r"exav_render::formats::office::\w+::(?:\w+::)*(?:shape|group|drawable|drawables|block|list|body|inlines|walk|find_shape)\b",
    r"exav_render::formats::(?:gltf|ifc|cad)::.*::(?:value|item|curve|profile|unit|entity|document)\b",
]

FRAME_AARCH64 = re.compile(r"\bsub\s+sp, sp, #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?")
PROBE_AARCH64 = re.compile(r"\bsub\s+x\d+, sp, #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?")
FRAME_X86 = re.compile(r"\bsub\s+\$(0x[0-9a-f]+),%rsp")
PROBE_X86 = re.compile(r"\blea\s+-(0x[0-9a-f]+)\(%rsp\),%r11")
PROBESTACK_X86 = re.compile(r"\bmov\s+\$(0x[0-9a-f]+),%eax")
LABEL = re.compile(r"^[0-9a-f]+ <(.+)>:$")


def value(match):
    v = int(match.group(1), 0)
    if match.lastindex and match.lastindex >= 2 and match.group(2):
        v <<= int(match.group(2))
    return v


def frames(binary, objdump):
    """Yields (frame bytes, demangled name) for every function."""
    out = subprocess.run(
        [objdump, "-dC", "--no-show-raw-insn", binary],
        capture_output=True,
        text=True,
        errors="replace",
        check=True,
    ).stdout
    name, seen, total, probed, pending_eax = None, 0, 0, False, 0
    for line in out.splitlines():
        label = LABEL.match(line.strip())
        if label:
            if name and total:
                yield total, name
            name, seen, total, probed, pending_eax = label.group(1), 0, 0, False, 0
            continue
        if name is None:
            continue
        seen += 1
        if seen > 60:
            if total:
                yield total, name
            name = None
            continue
        # aarch64: a frame over a page is probed in a loop whose limit is the
        # whole frame, then the rest is taken off.
        m = PROBE_AARCH64.search(line)
        if m and not probed:
            probed, total = True, total + value(m)
            continue
        m = FRAME_AARCH64.search(line)
        if m:
            v = value(m)
            if not (probed and v == 4096):
                total += v
            continue
        # x86_64: the same, `lea` for the limit or `__rust_probestack`.
        m = PROBE_X86.search(line)
        if m and not probed:
            probed, total = True, total + int(m.group(1), 16)
            continue
        m = PROBESTACK_X86.search(line)
        if m:
            pending_eax = int(m.group(1), 16)
            continue
        if pending_eax and "probestack" in line:
            total, pending_eax = total + pending_eax, 0
            continue
        m = FRAME_X86.search(line)
        if m:
            v = int(m.group(1), 16)
            if not (probed and v == 4096):
                total += v
    if name and total:
        yield total, name


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("binaries", nargs="+")
    ap.add_argument("--max-kib", type=int, default=16, help="the largest frame a watched function may have")
    ap.add_argument("--min-kib", type=int, default=0, help="with --all, the smallest frame to list")
    ap.add_argument("--all", action="store_true", help="list every function over --min-kib, watched or not")
    args = ap.parse_args()
    objdump = shutil.which("objdump") or shutil.which("llvm-objdump")
    if not objdump:
        sys.exit("stack-frames: no objdump on the PATH")
    watched = [re.compile(p) for p in WATCHED]
    bad = []
    for binary in args.binaries:
        listed = {}
        for size, name in frames(binary, objdump):
            hit = any(p.search(name) for p in watched)
            if args.all and size >= args.min_kib * 1024:
                listed[name] = (size, hit)
            if hit and size > args.max_kib * 1024:
                bad.append((size, name, binary))
        for name, (size, hit) in sorted(listed.items(), key=lambda kv: -kv[1][0]):
            print(f"{size // 1024:>6} KiB {'*' if hit else ' '} {name[:160]}")
    for size, name, binary in sorted(bad, reverse=True):
        print(f"{binary}: {size // 1024} KiB frame in {name[:200]}")
    if bad:
        sys.exit(
            f"stack-frames: {len(bad)} watched function(s) over {args.max_kib} KiB: "
            "a value held by this function stays on the stack while the next level of "
            "nesting is read; move it into a function of its own, or box it"
        )
    print(f"stack-frames: every watched function is within {args.max_kib} KiB")


if __name__ == "__main__":
    main()
