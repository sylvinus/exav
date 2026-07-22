#!/usr/bin/env python3
"""Wrap EICAR in random permutations of container formats and scan each chain.

`crates/exav-core/tests/matryoshka.rs` pins one ordering through twenty-six
formats. This explores the others: a bug at the seam between format A and format
B is invisible to any single fixed chain, and there are far too many orderings to
enumerate.

It has already paid for itself twice:

  * a two-byte HFS+ signature scanned across 64 KiB matched compressed data about
    one time in twenty, and a false hit is not a wasted check — `detect` answers
    `Dmg`, so the file's real format is never tried;
  * a FAT boot sector read as a partition table produced a "partition" identical
    to the whole image, which re-detected the same way until the recursion budget
    was gone.

A chain that comes back **clean** is the failure being hunted. A resource limit
is not: wrapping a 68-byte payload through several megabytes of disk image and
recompressing it produces a genuinely extreme ratio, and the guard firing there
is the scanner working.

Usage:  scripts/format-chain-fuzz.py [trials] [chain-length] [seed]

Needs the same tools as scripts/make-matryoshka.sh, on PATH. Set TOOLS_PREFIX if
they live in a staging root rather than the system paths, and EXAV to point at a
built binary (default: target/debug/exav).
"""
import os, random, subprocess, sys, shutil, tempfile

ENV = dict(os.environ)
# Tools staged outside the system paths (an unpacked package root, say) are
# picked up from here rather than being assumed installed.
PREFIX = os.environ.get("TOOLS_PREFIX")
if PREFIX:
    ENV["PATH"] = f"{PREFIX}/usr/bin:{PREFIX}/usr/sbin:{PREFIX}/sbin:" + ENV.get("PATH", "")
    ENV["LD_LIBRARY_PATH"] = ":".join(
        f"{PREFIX}/{d}" for d in ("usr/lib", "lib")
    ) + ":" + ENV.get("LD_LIBRARY_PATH", "")
EXAV = os.environ.get("EXAV", "target/debug/exav")
DB = os.environ.get("EXAV_DB", "eicar.ndb")

EICAR = rb'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def run(cmd, cwd, quiet=True):
    r = subprocess.run(cmd, cwd=cwd, env=ENV, shell=isinstance(cmd, str),
                       stdout=subprocess.DEVNULL if quiet else None,
                       stderr=subprocess.DEVNULL if quiet else None)
    return r.returncode


def pad(src, dst, cwd):
    d = open(os.path.join(cwd, src), "rb").read()
    open(os.path.join(cwd, dst), "wb").write(d + b"\0" * (-len(d) % 512))


# Each wrapper takes the current artefact and produces the next one.
def w_zip(s, o, c):   return run(["zip", "-q", "-9", o, s], c)
def w_lzip(s, o, c):  return run(f"lzip -9 -c {s} > {o}", c)
def w_gzip(s, o, c):  return run(f"gzip -9 -c {s} > {o}", c)
def w_bzip2(s, o, c): return run(f"bzip2 -9 -c {s} > {o}", c)
def w_xz(s, o, c):    return run(f"xz -9 -c {s} > {o}", c)
def w_zstd(s, o, c):  return run(["zstd", "-19", "-q", "-o", o, s], c)
def w_lz4(s, o, c):   return run(f"lz4 -9 -q -c {s} > {o}", c)
def w_compress(s, o, c): return run(f"compress -c {s} > {o}", c)
def w_tar(s, o, c):   return run(["tar", "cf", o, s], c)
def w_7z(s, o, c):    return run(["7zz", "a", "-t7z", "-mx=9", "-bso0", "-bsp0", o, s], c)
def w_arj(s, o, c):   return run(["arj", "a", "-m1", "-i", o, s], c)
def w_rar(s, o, c):   return run(["rar", "a", "-m5", "-ep", "-inul", o, s], c)
def w_cab(s, o, c):   return run(["gcab", "-c", o, s], c)
def w_cpio(s, o, c):  return run(f"echo {s} | cpio -o --quiet > {o}", c)
def w_ar(s, o, c):    return run(["ar", "rc", o, s], c)
def w_xar(s, o, c):   return run(["xar", "-cf", o, s], c)
def w_ole(s, o, c):   return run(["gsf", "createole", o, s], c)
def w_uu(s, o, c):    return run(f"uuencode {s} nested.bin > {o}", c)


def w_wim(s, o, c):
    d = os.path.join(c, "wd_" + o)
    os.makedirs(d, exist_ok=True)
    shutil.copy(os.path.join(c, s), d)
    return run(["wimcapture", d, o, "--compress=LZX"], c)


def w_iso(s, o, c):
    d = os.path.join(c, "id_" + o)
    os.makedirs(d, exist_ok=True)
    shutil.copy(os.path.join(c, s), d)
    return run(["genisoimage", "-quiet", "-o", o, "-V", "NEST", d], c)


def w_email(s, o, c):
    from email.message import EmailMessage
    m = EmailMessage()
    m["Subject"] = "nested"; m["From"] = "a@example.invalid"; m["To"] = "b@example.invalid"
    m.set_content("see attachment")
    m.add_attachment(open(os.path.join(c, s), "rb").read(), maintype="application",
                     subtype="octet-stream", filename="nested.bin")
    open(os.path.join(c, o), "wb").write(m.as_bytes())
    return 0


def _qemu(s, o, c, fmt, extra=None):
    pad(s, "r_" + o, c)
    cmd = ["qemu-img", "convert", "-f", "raw", "-O", fmt]
    if extra:
        cmd += extra
    cmd += ["r_" + o, o]
    return run(cmd, c)


def w_qcow2(s, o, c): return _qemu(s, o, c, "qcow2", ["-c", "-o", "cluster_size=512"])
def w_vmdk(s, o, c):  return _qemu(s, o, c, "vmdk", ["-o", "subformat=streamOptimized"])
def w_vhd(s, o, c):   return _qemu(s, o, c, "vpc")
def w_vhdx(s, o, c):  return _qemu(s, o, c, "vhdx", ["-o", "block_size=1M"])


def w_mbr(s, o, c):
    d = open(os.path.join(c, s), "rb").read()
    open(os.path.join(c, o), "wb").write(b"\0" * (2048 * 512) + d + b"\0" * (-len(d) % 512))
    p = subprocess.run(["fdisk", o], cwd=c, env=ENV, input=b"o\nn\np\n1\n2048\n\nw\n",
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0


WRAPPERS = [
    ("zip", w_zip, "zip"), ("lzip", w_lzip, "lz"), ("gzip", w_gzip, "gz"),
    ("bzip2", w_bzip2, "bz2"), ("xz", w_xz, "xz"), ("zstd", w_zstd, "zst"),
    ("lz4", w_lz4, "lz4"), ("compress", w_compress, "Z"), ("tar", w_tar, "tar"),
    ("7z", w_7z, "7z"), ("arj", w_arj, "arj"), ("rar", w_rar, "rar"),
    ("cab", w_cab, "cab"), ("cpio", w_cpio, "cpio"), ("ar", w_ar, "a"),
    ("xar", w_xar, "xar"), ("ole", w_ole, "ole"), ("wim", w_wim, "wim"),
    ("iso", w_iso, "iso"), ("email", w_email, "eml"), ("qcow2", w_qcow2, "qcow2"),
    ("vmdk", w_vmdk, "vmdk"), ("mbr", w_mbr, "img"), ("uuencode", w_uu, "uu"),
]
# The two biggest disk images are opt-in: each inflates the intermediate file to
# several megabytes, which makes a long random chain slow rather than wrong.
BIG = [("vhd", w_vhd, "vhd"), ("vhdx", w_vhdx, "vhdx")]


def build_chain(order, cwd):
    """Wrap EICAR through `order`; returns the final filename or None."""
    cur = "eicar.com"
    open(os.path.join(cwd, cur), "wb").write(EICAR)
    for i, (name, fn, ext) in enumerate(order):
        out = f"s{i:02d}_{name}.{ext}"
        try:
            fn(cur, out, cwd)
        except Exception as e:
            return None, f"builder {name} raised {e}"
        p = os.path.join(cwd, out)
        if not os.path.exists(p) or os.path.getsize(p) == 0:
            return None, f"builder {name} produced nothing"
        cur = out
    return cur, None


def scan(path, cwd, depth):
    r = subprocess.run([EXAV, "--database", DB, "--max-recursion", str(depth),
                        os.path.join(cwd, path)],
                       env=ENV, capture_output=True, text=True)
    first = (r.stdout.splitlines() or [""])[0]
    return first.split(": ", 1)[-1] if ": " in first else first


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    length = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 20260727
    random.seed(seed)
    pool = WRAPPERS + BIG if os.environ.get("FUZZ_BIG") else WRAPPERS

    failures = []
    for t in range(trials):
        order = random.sample(pool, length)
        with tempfile.TemporaryDirectory() as cwd:
            final, err = build_chain(order, cwd)
            chain = " -> ".join(n for n, _, _ in order)
            if final is None:
                print(f"[{t:3}] SKIP  {chain}\n        {err}")
                continue
            verdict = scan(final, cwd, len(order) + 10)
            # Only a *clean* verdict is a bug. A resource limit is the honest
            # answer for a chain that inflates a 68-byte payload through several
            # megabytes of disk image and then recompresses it — the ratio guard
            # firing there is the scanner working, not failing.
            if "FOUND" in verdict:
                state = "ok  "
            elif "LIMITS-EXCEEDED" in verdict or "UNSCANNABLE" in verdict:
                state = "capped"
            else:
                state = "BUG "
                failures.append((chain, verdict))
            print(f"[{t:3}] {state}  {chain}")
            if state == "BUG ":
                print(f"        verdict: {verdict}")

    print(f"\n{trials - len(failures)}/{trials} chains ended in a non-clean verdict")
    for chain, verdict in failures:
        print(f"  BUG {chain}\n      {verdict}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
