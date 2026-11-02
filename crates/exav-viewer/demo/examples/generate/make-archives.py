#!/usr/bin/env python3
"""Writes the demo's archive examples into ../files/archives/.

    python3 -I make-archives.py [OUT_DIR]

Output: CC0-1.0, a public domain dedication by the exav project. The members
are files of this demo (../files/text and ../files/images, so run make-text.py
and make-images.py first) and short texts written here.

Needs: Python 3, and the programs 7z (p7zip-full), genisoimage, zstd, gcab,
dpkg-deb, cpio and ar. A file whose program is missing is skipped.

Written by Python alone: the zip, the tar family (tar, gz, bz2, xz), the jar,
the comic book archive (cbz), and the RAR 5 file, which is built here from the
published format (stored members: no program writes RAR without the
proprietary rar). The encrypted ones use 7z; their password is in the file
name's credit: "exav".

Same bytes on every run, except the ISO image (genisoimage stamps the time) and
the encrypted files (7z picks a random salt).
"""
import bz2
import gzip
import io
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.join(HERE, "..", "files")
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(FILES, "archives")
os.makedirs(OUT, exist_ok=True)
EPOCH = 946684800  # 2000-01-01 00:00:00 UTC
DATE = (2000, 1, 1, 0, 0, 0)
PASSWORD = "exav"


def have(tool):
    return shutil.which(tool) is not None


def read(*parts):
    with open(os.path.join(FILES, *parts), "rb") as f:
        return f.read()


README = """Example archive
===============

This archive holds a few files of the exav demo. It is in the public domain
(CC0-1.0). Look at the folders: docs, data, images, src, an empty one, and a
folder with accented and Japanese names.
""".encode()

MEMBERS = [
    ("README.txt", README, True),
    ("docs/field-guide.md", read("text", "field-guide.md"), True),
    ("docs/field-notes.txt", read("text", "field-notes.txt"), True),
    ("data/harbour-log.csv", read("text", "harbour-log.csv"), True),
    ("data/recipes.json", read("text", "recipes.json"), True),
    ("images/scene-indexed.png", read("images", "scene-indexed.png"), False),
    ("src/life.py", read("text", "life.py"), True),
    ("src/lru.rs", read("text", "lru.rs"), True),
    ("café/日本語.txt", "Names with accents and Japanese characters.\n".encode(), True),
]
DIRS = ["docs", "data", "images", "src", "src/empty", "café"]


def stage(root):
    """The members as files on disk with fixed times, for the programs that read a folder."""
    for d in DIRS:
        os.makedirs(os.path.join(root, d), exist_ok=True)
    for name, data, _ in MEMBERS:
        path = os.path.join(root, name)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o644)
    for p, dirs, files in os.walk(root):
        for n in dirs + files:
            os.utime(os.path.join(p, n), (EPOCH, EPOCH))
        os.utime(p, (EPOCH, EPOCH))


# ---------------------------------------------------------------------- zip


def make_zip(path, members=MEMBERS, dirs=DIRS, comment=b"exav example archive, CC0-1.0"):
    with zipfile.ZipFile(path, "w") as z:
        z.comment = comment
        for d in dirs:
            zi = zipfile.ZipInfo(d + "/", DATE)
            zi.external_attr = (0o40755 << 16) | 0x10
            zi.create_system = 3
            z.writestr(zi, b"")
        for name, data, deflate in members:
            zi = zipfile.ZipInfo(name, DATE)
            zi.external_attr = 0o100644 << 16
            zi.create_system = 3
            zi.compress_type = zipfile.ZIP_DEFLATED if deflate else zipfile.ZIP_STORED
            z.writestr(zi, data, compresslevel=9)


def zip_bytes(members, dirs=()):
    buf = io.BytesIO()
    make_zip(buf, members, dirs, comment=b"")
    return buf.getvalue()


# ---------------------------------------------------------------------- tar


def tar_bytes():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        def info(name, kind=tarfile.REGTYPE, size=0, mode=0o644, link=""):
            ti = tarfile.TarInfo(name)
            ti.type, ti.size, ti.mode, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname, ti.linkname = kind, size, mode, EPOCH, 0, 0, "", "", link
            return ti

        for d in DIRS:
            t.addfile(info(d + "/", tarfile.DIRTYPE, mode=0o755))
        for name, data, _ in MEMBERS:
            t.addfile(info(name, size=len(data)), io.BytesIO(data))
        t.addfile(info("link-to-readme", tarfile.SYMTYPE, link="README.txt", mode=0o777))
    return buf.getvalue()


def gz(data):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, compresslevel=9) as f:
        f.write(data)
    return buf.getvalue()


def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


# ------------------------------------------------------------------ RAR 5


def vint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def rar_block(htype, fields, data=b"", flags=0):
    """One RAR 5 block: CRC32, header size, type, flags, [data size], fields, then the data."""
    body = vint(htype) + vint(flags | (2 if data else 0)) + (vint(len(data)) if data else b"") + fields
    size = vint(len(body))
    return struct.pack("<I", zlib.crc32(size + body)) + size + body + data


def rar5(members, dirs):
    out = bytearray(b"Rar!\x1a\x07\x01\x00")
    out += rar_block(1, vint(0))
    for d in dirs:
        name = d.encode()
        out += rar_block(2, vint(0x1 | 0x2) + vint(0) + vint(0o40755) + struct.pack("<I", EPOCH) + vint(0) + vint(1) + vint(len(name)) + name)
    for n, data, _ in members:
        name = n.encode()
        out += rar_block(2, vint(0x2 | 0x4) + vint(len(data)) + vint(0o100644) + struct.pack("<I", EPOCH) + struct.pack("<I", zlib.crc32(data)) + vint(0) + vint(1) + vint(len(name)) + name, data)
    out += rar_block(5, vint(0))
    return bytes(out)


# --------------------------------------------------------------------- main

make_zip(os.path.join(OUT, "sample.zip"))
tar = tar_bytes()
write("sample.tar", tar)
write("sample.tar.gz", gz(tar))
write("sample.tar.bz2", bz2.compress(tar, 9))
write("sample.tar.xz", lzma.compress(tar, format=lzma.FORMAT_XZ, preset=9))
log = read("text", "server.log")
write("server.log.gz", gz(log))
write("server.log.bz2", bz2.compress(log, 9))
write("server.log.xz", lzma.compress(log, format=lzma.FORMAT_XZ, preset=9))
write("sample.rar", rar5(MEMBERS, DIRS))

# A jar and a comic book archive are zips under other names.
jar_members = [
    ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nCreated-By: exav make-archives.py\r\nMain-Class: example.Main\r\n\r\n", True),
    ("example/Main.java", b"package example;\n\npublic class Main {\n    public static void main(String[] args) {\n        System.out.println(\"hello from a jar\");\n    }\n}\n", True),
    ("example/messages.properties", b"greeting=hello\nfarewell=goodbye\n", True),
]
make_zip(os.path.join(OUT, "example.jar"), jar_members, ["META-INF", "example"], comment=b"")
pages = [(f"page-{i:02d}.png", read("images", n), False) for i, n in enumerate(["scene-indexed.png", "scene-indexed.png"], 1)]
comic = pages + [("ComicInfo.xml", b'<?xml version="1.0"?>\n<ComicInfo><Title>Two pages</Title><Series>exav examples</Series><PageCount>2</PageCount></ComicInfo>\n', True)]
make_zip(os.path.join(OUT, "pages.cbz"), comic, [], comment=b"")

# The nested one: a zip holding a tar.gz holding a 7z holding a zip.
with tempfile.TemporaryDirectory() as tmp:
    stage_dir = os.path.join(tmp, "stage")
    stage(stage_dir)
    inner_zip = zip_bytes([("deep.txt", b"Four archives down.\n", True), ("field-guide.md", read("text", "field-guide.md"), True), ("scene-indexed.png", read("images", "scene-indexed.png"), False)])
    if have("7z"):
        work = os.path.join(tmp, "inner")
        os.makedirs(work)
        with open(os.path.join(work, "inner.zip"), "wb") as f:
            f.write(inner_zip)
        os.utime(os.path.join(work, "inner.zip"), (EPOCH, EPOCH))
        subprocess.run(["7z", "a", "-t7z", "-mx=9", "-bd", "-y", os.path.join(tmp, "inner.7z"), "inner.zip"], cwd=work, check=True, capture_output=True)
        with open(os.path.join(tmp, "inner.7z"), "rb") as f:
            inner_7z = f.read()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
            ti = tarfile.TarInfo("inner.7z")
            ti.size, ti.mtime, ti.mode = len(inner_7z), EPOCH, 0o644
            t.addfile(ti, io.BytesIO(inner_7z))
            ti = tarfile.TarInfo("note.txt")
            note = b"This tar.gz holds a 7z that holds a zip.\n"
            ti.size, ti.mtime, ti.mode = len(note), EPOCH, 0o644
            t.addfile(ti, io.BytesIO(note))
        outer = gz(buf.getvalue())
        make_zip(os.path.join(OUT, "matryoshka.zip"), [("README.txt", b"A zip, holding a tar.gz, holding a 7z, holding a zip. Open them in turn.\n", True), ("inner.tar.gz", outer, False)], [], comment=b"")

    # Programs that read a folder.
    if have("7z"):
        for name, args in [
            ("sample.7z", ["-t7z", "-mx=9"]),
            ("encrypted-aes.zip", ["-tzip", f"-p{PASSWORD}", "-mem=AES256"]),
            ("encrypted-zipcrypto.zip", ["-tzip", f"-p{PASSWORD}", "-mem=ZipCrypto"]),
            ("encrypted.7z", ["-t7z", "-mx=5", f"-p{PASSWORD}", "-mhe=off"]),
        ]:
            target = os.path.join(OUT, name)
            if os.path.exists(target):
                os.remove(target)
            subprocess.run(["7z", "a", *args, "-bd", "-y", target, "."], cwd=stage_dir, check=True, capture_output=True)
    if have("genisoimage"):
        subprocess.run(["genisoimage", "-quiet", "-no-pad", "-R", "-J", "-joliet-long", "-V", "EXAV_EXAMPLE", "-input-charset", "utf-8", "-o", os.path.join(OUT, "sample.iso"), stage_dir], check=True, capture_output=True)
    if have("zstd"):
        subprocess.run(["zstd", "-q", "-19", "-f", "-o", os.path.join(OUT, "sample.tar.zst"), "-"], input=tar, check=True, capture_output=True)
    if have("gcab"):
        target = os.path.join(OUT, "sample.cab")
        if os.path.exists(target):
            os.remove(target)
        files = ["README.txt", "docs/field-guide.md", "data/recipes.json", "src/life.py"]
        subprocess.run(["gcab", "-c", "-n", target, *files], cwd=stage_dir, check=True, capture_output=True)
    if have("ar"):
        target = os.path.join(OUT, "libexample.a")
        if os.path.exists(target):
            os.remove(target)
        subprocess.run(["ar", "rcsD", target, "README.txt"], cwd=stage_dir, check=True, capture_output=True)
        for name in ("docs/field-notes.txt",):
            subprocess.run(["ar", "rD", target, name], cwd=stage_dir, check=True, capture_output=True)
    if have("cpio"):
        names = "\n".join(["README.txt", "docs/field-guide.md", "data/recipes.json", "src/life.py"]) + "\n"
        data = subprocess.run(["cpio", "-o", "-H", "newc", "--quiet", "--reproducible"], input=names.encode(), cwd=stage_dir, check=True, capture_output=True).stdout
        write("sample.cpio", data)
    if have("dpkg-deb"):
        pkg = os.path.join(tmp, "pkg")
        os.makedirs(os.path.join(pkg, "DEBIAN"))
        os.makedirs(os.path.join(pkg, "usr", "share", "doc", "exav-example"))
        with open(os.path.join(pkg, "DEBIAN", "control"), "w") as f:
            f.write("Package: exav-example\nVersion: 1.0\nSection: misc\nPriority: optional\nArchitecture: all\nMaintainer: exav project <noreply@example.invalid>\nDescription: an example package\n A package that holds a README, for the exav demo (CC0-1.0).\n")
        shutil.copy(os.path.join(stage_dir, "README.txt"), os.path.join(pkg, "usr", "share", "doc", "exav-example", "README"))
        shutil.copy(os.path.join(stage_dir, "docs", "field-guide.md"), os.path.join(pkg, "usr", "share", "doc", "exav-example", "field-guide.md"))
        for p, dirs, files in os.walk(pkg):
            for n in dirs + files:
                os.utime(os.path.join(p, n), (EPOCH, EPOCH))
        env = dict(os.environ, SOURCE_DATE_EPOCH=str(EPOCH))
        subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "-b", pkg, os.path.join(OUT, "exav-example.deb")], check=True, capture_output=True, env=env)
