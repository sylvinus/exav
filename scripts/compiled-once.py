#!/usr/bin/env python3
"""Checks that the code of exav's crates is compiled once in a binary.

A reader (the walk of a container format) is generic over what its caller
stops with, and over the source it reads. Each type it is used with compiles it
again, in each crate that uses it: the readers were in exav three times, a
disk's layouts six times, and the binaries 2 to 4 MiB larger for it. This
script reads the release binaries and fails on what the types did not
forbid:

  1. a function of exav's crates defined more than once under one name
     (two crates compiled the same instance of a generic);
  2. a reader (`exav_unpack::formats::*::walk*`, `extract_*` and
     `exav_unpack::stream::*`) compiled for more than one type;
  3. a generic family of exav's own code compiled for several types, when it
     is not in ALLOWED below with its reason.

    scripts/compiled-once.py target/release/exav target/release/exav-grep ...
    scripts/compiled-once.py --list target/release/exav     # every family

`make compiled-once` builds each binary alone, as the release workflow does
(`cargo build --release -p <package>`: the package set changes the binary), and
the wasm with its names kept (`--config profile.release.strip=false`), and runs
this on them. A `.wasm` is read through its name section.

Needs `nm` and `c++filt` (binutils, with Rust demangling) on Linux.
"""

import argparse
import collections
import re
import subprocess
import sys

# Functions of exav's crates, by the name they have once demangled.
OURS = re.compile(r"^<*(?:exav|exav_[a-z0-9_]+)::")

# A reader, whatever the family: never allowed more than one instance.
READER = re.compile(
    r"^(?:exav_unpack::formats::[a-z0-9_]+(?:::[a-z0-9_]+)*::(?:walk|walk_\w+|extract_\w+)"
    r"|exav_unpack::stream::[A-Za-z0-9_:]+)$"
)

# Code that is compiled for several types on purpose, by a part of its name
# without the generics, each with the reason. Keep this short: an entry is here
# because one copy per type is faster in a loop that runs per byte, per symbol
# or per instruction, or because the compiler wrote it, not because it was left.
ALLOWED = {
    "<exav_unpack::formats::ppmd7::model::Ppmd7>::": (
        "the model runs once per decoded symbol, and the range decoder of 7z "
        "and the one of RAR 3 are inlined into it"
    ),
    "exav_pe_emu::cpu::lanes": (
        "the arithmetic of the emulator on an operand of 8, 16, 32 or 64 bits "
        "runs for every instruction it emulates"
    ),
    "exav_core::engine::advance_": (
        "the matcher steps a signature along the bytes of an object, held "
        "(`[u8]`) or read where it lies (`dyn ByteSource`), with a lowercased "
        "view or not: per byte"
    ),
    "exav_core::engine::verify": "the verification of a match, per byte, as the matcher",
    "exav_core::engine::gap_split_match": "a match with gaps, per byte, as the matcher",
    "<exav_core::engine::Verifier": "the verification of a match, per byte, as the matcher",
    "exav_core::grams::": "the gram index along the bytes of an object: per byte",
    "<exav_core::grams::": "the gram index along the bytes of an object: per byte",
    "serde_core::de::": (
        "written by serde's derive for each type and each deserializer the "
        "databases are read with, and once in each codegen unit for a recursive type"
    ),
    "serde_core::ser::": "written by serde's derive for each type the databases are written with",
    "exav_core::database::": "the writer and the reader of the database file, one per record type",
    "clap_builder::builder::value_parser": "written by clap for each value parser",
    "exav::daemon::": (
        "the daemon's connection code, once for each transport (a Unix socket, "
        "a TCP stream, a descriptor passed); no loop over bytes"
    ),
    "exav_imagehash::dct::": "the transform in f32 and in f64, which are different code",
    "exav_render::formats::cad::dwg::entities::push": (
        "one per entity struct, each filling a different type"
    ),
}


def allowed(name):
    return any(part in name for part in ALLOWED)

# Less than this many bytes beyond the largest copy is not worth the report: a
# small function the optimiser copied into several codegen units, or a
# constructor that boxes what it is given.
MIN_EXTRA = 4096


def demangle(names):
    """The Rust-demangled `names`, with crate disambiguators removed."""
    out = subprocess.run(
        ["c++filt", "-s", "rust"], input="\n".join(names), capture_output=True, text=True
    ).stdout.split("\n")
    return [re.sub(r"\[[0-9a-f]{12,16}\]", "", n) for n in out[: len(names)]]


def uleb(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return r, i


def wasm_symbols(path):
    """(size, mangled name) of each function of a wasm module: the size of its
    code and the name the name section gives it."""
    data = open(path, "rb").read()
    assert data[:4] == b"\0asm", "not a wasm module"
    i = 8
    imports = 0
    bodies = []
    names = {}
    while i < len(data):
        sid = data[i]
        size, i = uleb(data, i + 1)
        end = i + size
        if sid == 2:
            n, j = uleb(data, i)
            for _ in range(n):
                for _ in range(2):
                    ln, j = uleb(data, j)
                    j += ln
                kind = data[j]
                j += 1
                if kind == 0:
                    _, j = uleb(data, j)
                    imports += 1
                elif kind in (1, 2):
                    if kind == 1:
                        j += 1
                    flags, j = uleb(data, j)
                    _, j = uleb(data, j)
                    if flags & 1:
                        _, j = uleb(data, j)
                elif kind == 3:
                    j += 2
        elif sid == 10:
            n, j = uleb(data, i)
            for _ in range(n):
                ln, j = uleb(data, j)
                bodies.append(ln)
                j += ln
        elif sid == 0:
            ln, j = uleb(data, i)
            if data[j : j + ln] == b"name":
                j += ln
                while j < end:
                    sub = data[j]
                    sl, j = uleb(data, j + 1)
                    se = j + sl
                    if sub == 1:
                        n, k = uleb(data, j)
                        for _ in range(n):
                            idx, k = uleb(data, k)
                            nl, k = uleb(data, k)
                            names[idx] = data[k : k + nl].decode("utf-8", "replace")
                            k += nl
                    j = se
        i = end
    return [(s, names.get(imports + n, "")) for n, s in enumerate(bodies)]


def elf_symbols(path):
    out = subprocess.run(
        ["nm", "-S", "--defined-only", path], capture_output=True, text=True, check=True
    ).stdout
    syms = []
    for line in out.splitlines():
        p = line.split(" ", 3)
        if len(p) == 4 and p[2] in "tTwW":
            syms.append((int(p[1], 16), p[3]))
    return syms


def symbols(path):
    """(size, normalised name) of the functions of exav's crates in `path`."""
    with open(path, "rb") as f:
        wasm = f.read(4) == b"\0asm"
    raw = wasm_symbols(path) if wasm else elf_symbols(path)
    names = demangle([n for _, n in raw])
    syms = []
    for (size, _), name in zip(raw, names):
        name = re.sub(r"::h[0-9a-f]{16}$", "", name)
        name = re.sub(r"\.llvm\.\d+$", "", name)
        if OURS.match(name):
            syms.append((size, name))
    return syms


def without_generics(name):
    """`name` without the generics of its path: `a::b::<T>`, and the type
    arguments of the type an impl is for; `<a::B<T> as c::D<U>>::f` becomes
    `<a::B as c::D>::f`."""
    out = []
    depth = 0
    # An impl's `<Self as Trait>` is part of the key, its arguments are not.
    keep = 1 if name.startswith("<") else 0
    for ch in name:
        if ch == "<":
            depth += 1
            if depth <= keep:
                out.append(ch)
            continue
        if ch == ">":
            if depth <= keep:
                out.append(ch)
            depth -= 1
            continue
        if depth <= keep:
            out.append(ch)
    return "".join(out).removesuffix("::")


def check(path, list_all):
    syms = symbols(path)
    failures = 0
    print(f"{path}: {len(syms)} functions of exav's crates")

    # 1. The same name defined several times.
    same = collections.defaultdict(list)
    for size, name in syms:
        same[name].append(size)
    dups = sorted(
        ((sum(v) - max(v), len(v), k) for k, v in same.items() if len(v) > 1), reverse=True
    )
    dups = [d for d in dups if d[0] >= MIN_EXTRA and not allowed(d[2])]
    if dups:
        failures += 1
        print(
            f"  FAIL 1: {len(dups)} functions defined more than once "
            f"({sum(d[0] for d in dups)} bytes in the extra copies)"
        )
        for extra, n, name in dups[:12]:
            print(f"    {extra:8d} bytes, x{n}  {name[:150]}")

    # 2 and 3. Families: the instances of one name without its generics.
    fam = collections.defaultdict(lambda: collections.defaultdict(int))
    for size, name in syms:
        fam[without_generics(name)][name] += size
    several = {k: v for k, v in fam.items() if len(v) > 1}
    readers = {k: v for k, v in several.items() if READER.match(k)}
    others = {
        k: v
        for k, v in several.items()
        if k not in readers
        and not allowed(k)
        and sum(v.values()) - max(v.values()) >= MIN_EXTRA
    }

    def show(label, group, limit):
        rows = sorted(
            ((sum(v.values()) - max(v.values()), len(v), k, v) for k, v in group.items()),
            reverse=True,
        )
        print(
            f"  FAIL {label}: {len(rows)} compiled for several types "
            f"({sum(r[0] for r in rows)} bytes beyond the largest copy of each)"
        )
        for extra, n, key, inst in rows[:limit]:
            print(f"    {extra:8d} bytes, {n} instances  {key[:130]}")
            for name, size in sorted(inst.items(), key=lambda x: -x[1])[:2]:
                print(f"        {size:8d}  {name[:150]}")

    if readers:
        failures += 1
        show("2 (readers)", readers, 12)
    if others:
        failures += 1
        show("3 (families)", others, 12 if not list_all else len(others))
    if not failures:
        print("  ok")
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("binaries", nargs="+")
    ap.add_argument("--list", action="store_true", help="print every family, not the first")
    args = ap.parse_args()
    failed = sum(check(b, args.list) for b in args.binaries)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
