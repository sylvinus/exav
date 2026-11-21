#!/usr/bin/env python3
"""Refuse a file that holds an absolute path of the machine that built it.

A released binary, wasm module, npm tarball, crate or chart that carries
`/home/runner/.cargo/registry/...` tells whoever downloads it where and by
whom it was built, and makes two builds of the same source differ. The release
builds map the checkout, the cargo home and the rustup home to fixed names
(scripts/build-flags.sh); this checks that nothing slipped through.

USAGE:
  python3 -I scripts/check-build-paths.py [--source] [--also PATH]... [--except SUFFIX]... FILE_OR_DIR...

Files are read as bytes. Archives (gzip, tar, zip, a crate, an npm tarball, a
docker image saved as tar) are opened, and the archives inside them. A
directory is walked. A path that does not exist is an error, so that a glob
that matched nothing does not pass.

Looked for:
  - `/Users/` and `/home/` followed by a path, `C:\\Users\\` and `C:/Users/`
    (any drive letter, any case);
  - the checkout this script is in, $CARGO_HOME (or ~/.cargo), $RUSTUP_HOME
    (or ~/.rustup), the home directory, and every --also PATH, each followed by
    a separator. The fixed names the builds map to (/exav, /cargo, /rustup)
    are never looked for.

--except SUFFIX skips a file whose name, as printed (archive!member), ends with
SUFFIX: a file of a dependency that is shipped as it was built upstream.

--source looks only for the second list. It is for source archives (crates),
whose tests and docs name `/home/x` and `C:\\Users\\x` as examples.

Exit status: 0 nothing found, 1 a path found (each file and path is printed),
2 a usage error or a file that cannot be read.
"""

import argparse
import gzip
import os
import re
import sys
import tarfile
import zipfile

FIXED = {"/exav", "/cargo", "/rustup"}
CHUNK = 1 << 24
OVERLAP = 4096
TAIL = rb"[\x21-\x7e]{0,80}"
GENERIC = [
    rb"/Users/" + TAIL,
    rb"/home/" + TAIL,
    rb"(?i:[a-z]:[\\/]+users[\\/]+)" + TAIL,
]
MAX_DEPTH = 4


def needle(path):
    """A pattern for `path` followed by a separator; either separator matches either."""
    p = path.rstrip("/\\")
    if p in FIXED or len(p) < 4:
        return None
    body = b"".join(rb"[\\/]+" if c in "/\\" else re.escape(c.encode()) for c in p)
    return body + rb"[\\/]+" + TAIL


def patterns(source, also):
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    home = os.path.expanduser("~")
    roots = [
        repo,
        os.environ.get("CARGO_HOME") or os.path.join(home, ".cargo"),
        os.environ.get("RUSTUP_HOME") or os.path.join(home, ".rustup"),
        home,
        *also,
    ]
    # A symlinked directory (/tmp, /var on macOS) is named by its target in a build.
    found = [n for n in map(needle, dict.fromkeys(roots + [os.path.realpath(r) for r in roots])) if n]
    return found if source else GENERIC + found


def scan(data, rx, found):
    """Append the paths found in the bytes of the file object `data`."""
    tail = b""
    while True:
        block = data.read(CHUNK)
        if not block:
            return
        buf = tail + block
        for m in rx.finditer(buf):
            if m.end() > len(tail):
                found.append(m.group().decode("ascii", "replace"))
        tail = buf[-OVERLAP:]


def kind(head):
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:4] == b"PK\x03\x04":
        return "zip"
    if head[257:262] == b"ustar":
        return "tar"
    return None


def walk(name, f, rx, out, depth=0):
    """Scan `f`, a seekable file object named `name`, and what it holds."""
    head = f.read(512)
    f.seek(0)
    k = kind(head)
    try:
        if k == "gzip":
            f = gzip.GzipFile(fileobj=f)
            head = f.read(512)
            f.seek(0)
            k = "tar" if kind(head) == "tar" else None
        if k == "tar" and depth < MAX_DEPTH:
            with tarfile.open(fileobj=f, mode="r:") as t:
                for info in t:
                    if info.isfile():
                        walk(f"{name}!{info.name}", t.extractfile(info), rx, out, depth + 1)
        elif k == "zip" and depth < MAX_DEPTH:
            with zipfile.ZipFile(f) as z:
                for info in z.infolist():
                    if not info.is_dir():
                        with z.open(info) as m:
                            walk(f"{name}!{info.filename}", m, rx, out, depth + 1)
        else:
            found = []
            scan(f, rx, found)
            if found and not name.endswith(tuple(out["skip"])):
                out["hits"].append((name, found))
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, NotImplementedError) as e:
        out["errors"].append(f"{name}: {e}")


def files(args):
    for a in args:
        if os.path.isdir(a):
            for root, _, names in os.walk(a):
                for n in sorted(names):
                    p = os.path.join(root, n)
                    if os.path.isfile(p) and not os.path.islink(p):
                        yield p
        elif os.path.isfile(a):
            yield a
        else:
            print(f"check-build-paths: {a}: no such file or directory", file=sys.stderr)
            sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", action="store_true", help="only the build machine's own paths (for crates)")
    ap.add_argument("--also", action="append", default=[], metavar="PATH", help="one more path of the build machine")
    ap.add_argument("--except", dest="skip", action="append", default=[], metavar="SUFFIX", help="ignore a file whose name (archive!member) ends with SUFFIX")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()
    rx = re.compile(b"|".join(b"(?:" + p + b")" for p in patterns(a.source, a.also)))
    out = {"hits": [], "errors": [], "skip": a.skip}
    count = 0
    for p in files(a.paths):
        count += 1
        with open(p, "rb") as f:
            walk(p, f, rx, out)
    for e in out["errors"]:
        print(f"check-build-paths: cannot read {e}", file=sys.stderr)
    for name, found in out["hits"]:
        distinct = list(dict.fromkeys(found))
        for path in distinct[:3]:
            print(f"{name}: {path}")
        if len(distinct) > 3:
            print(f"{name}: and {len(distinct) - 3} more")
    if out["errors"]:
        sys.exit(2)
    if out["hits"]:
        print(f"check-build-paths: {len(out['hits'])} of {count} files hold a path of the build machine", file=sys.stderr)
        sys.exit(1)
    print(f"check-build-paths: {count} files, no path of the build machine")


if __name__ == "__main__":
    main()
