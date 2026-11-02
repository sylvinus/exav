#!/usr/bin/env python3
"""Seeds made with the tools that write each format, for the fuzz targets.

    scripts/fuzz-seeds-generate.py OUT [AREA...]   # adds OUT/<target>/gen_*

The fixtures of the repository are one file of each format, and the files of
the wild (`fuzz-seeds-wild.sh`) are what happens to be on the disk. These are
made: every compression and layout the archive tools write, the filesystems
`mkfs` writes, the documents an office suite saves in every format it has, the
pictures Pillow, libjpeg, OpenJPEG and jbig2enc write with their options, the
PDFs `reportlab` and `qpdf` write, the drawings `ezdxf` writes for every DXF
version, the mail Python's `email` package writes, and signatures from a
grammar. A seed is at most MAX_BYTES (64 KiB, as the others); a tool that is
not installed leaves its seeds out, with a word on stderr.

AREA is one or more of: archives, filesystems, disks, documents, images, pdf,
drawings, mail, signatures, text. The default is all of them.

Seeds are deterministic (a fixed random seed) so that a run is comparable with
the last. What the seeds are worth is measured, not assumed: docs/FUZZING.md,
"Synthesized seeds".
"""
import base64
import gzip
import bz2
import io
import lzma
import os
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import zlib

OUT = sys.argv[1]
AREAS = set(sys.argv[2:]) or {
    "archives", "filesystems", "disks", "documents", "images", "pdf",
    "drawings", "mail", "signatures", "text",
}
MAX_BYTES = int(os.environ.get("MAX_BYTES", "65536"))
random.seed(20261030)
TMP = tempfile.mkdtemp(prefix="exav-seeds-")
COUNT = {}

# The antivirus test string, written backwards: this tree may not carry it
# (scripts/release.sh, crates/exav/tests/self_scan.rs).
EICAR = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X"[::-1].encode()


def note(msg):
    print(msg, file=sys.stderr)


def put(target, name, data):
    """One seed, if it is not too big."""
    if not data or len(data) > MAX_BYTES:
        return False
    d = os.path.join(OUT, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "gen_" + name), "wb") as f:
        f.write(data)
    COUNT[target] = COUNT.get(target, 0) + 1
    return True


def put_file(target, name, path):
    with open(path, "rb") as f:
        return put(target, name, f.read(MAX_BYTES + 1))


def container(name, data):
    """A file for the targets that take any file, and the same behind the
    headers of the framed ones (fuzz_targets/full_pipeline.rs, seekable.rs)."""
    if put("containers", name, data):
        put("full_pipeline", name, b"\0\0\0" + data)
        put("seekable", name, b"\0\0\x08\0" + data)
        return True
    return False


def run(*cmd, cwd=None, input=None, timeout=120):
    try:
        r = subprocess.run(cmd, cwd=cwd, input=input, capture_output=True, timeout=timeout)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def have(tool):
    return shutil.which(tool) is not None


def need(*tools):
    missing = [t for t in tools if not have(t)]
    if missing:
        note("skipped (not installed): " + ", ".join(missing))
    return not missing


def work(name):
    d = os.path.join(TMP, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    return d


def text_blob(n, seed):
    r = random.Random(seed)
    words = ["alpha", "beta", "gamma", "delta", "payload", "macro", "document", "report", "invoice", "total"]
    return " ".join(r.choice(words) + str(r.randrange(100)) for _ in range(n)).encode()


def payloads():
    """Small files of the kinds an archive holds."""
    r = random.Random(7)
    return {
        "readme.txt": b"Hello, world.\n" * 3,
        "notes/long.txt": text_blob(400, 1),
        "bin/random.bin": bytes(r.randrange(256) for _ in range(900)),
        "bin/zeros.bin": bytes(3000),
        "bin/mz.exe": b"MZ" + bytes(58) + struct.pack("<I", 0x80) + bytes(64) + b"PE\0\0" + bytes(200),
        "scripts/run.js": b"var x = 'a'; eval(unescape('%61%6c%65%72%74'));\n",
        "data/test.com": EICAR,
        "empty.txt": b"",
    }


def write_tree(root, files):
    for name, data in files.items():
        p = os.path.join(root, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)


# --- archives ---------------------------------------------------------------

def archives():
    files = payloads()
    names = list(files)
    # zip: every method Python writes, and the tools' other layouts.
    for tag, method, level in (("store", zipfile.ZIP_STORED, None), ("deflate", zipfile.ZIP_DEFLATED, 9),
                               ("bzip2", zipfile.ZIP_BZIP2, 9), ("lzma", zipfile.ZIP_LZMA, None)):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w", method, compresslevel=level) as z:
            for n, d in files.items():
                z.writestr(n, d)
            z.comment = b"a comment"
        container(f"zip_{tag}", b.getvalue())
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for n in names[:3]:
            zi = zipfile.ZipInfo(n)
            zi.compress_type = zipfile.ZIP_DEFLATED
            with z.open(zi, "w", force_zip64=True) as w:
                w.write(files[n])
    container("zip_zip64", b.getvalue())
    w = work("zip")
    write_tree(w, files)
    if have("zip"):
        for tag, args in (("zipcrypto", ["-P", "secret"]), ("level0", ["-0"]), ("level9", ["-9"]),
                          ("junk_paths", ["-j"]), ("symlinks", ["-y"]), ("extra", ["-X"])):
            out = os.path.join(TMP, f"z_{tag}.zip")
            if os.path.exists(out):
                os.remove(out)
            if run("zip", "-q", "-r", *args, out, ".", cwd=w):
                put_file("containers", f"zip_{tag}", out)
    if have("7z"):
        for tag, args in (("7z_lzma", ["-t7z", "-m0=lzma"]), ("7z_lzma2", ["-t7z", "-m0=lzma2"]),
                          ("7z_ppmd", ["-t7z", "-m0=ppmd"]), ("7z_bzip2", ["-t7z", "-m0=bzip2"]),
                          ("7z_deflate", ["-t7z", "-m0=deflate"]), ("7z_copy", ["-t7z", "-m0=copy"]),
                          ("7z_bcj", ["-t7z", "-m0=bcj", "-m1=lzma"]), ("7z_solid", ["-t7z", "-ms=on"]),
                          ("7z_nonsolid", ["-t7z", "-ms=off"]), ("7z_aes", ["-t7z", "-psecret"]),
                          ("7z_aes_headers", ["-t7z", "-psecret", "-mhe=on"]),
                          ("7z_noheadercompress", ["-t7z", "-mhc=off"]),
                          ("zip_aes", ["-tzip", "-psecret", "-mem=AES256"]), ("zip_ppmd", ["-tzip", "-m0=ppmd"]),
                          ("zip_deflate64", ["-tzip", "-m0=deflate64"]), ("zip_bzip2_7z", ["-tzip", "-m0=bzip2"]),
                          ("tar_7z", ["-ttar"]), ("wim", ["-twim"]), ("xz_7z", ["-txz"]),
                          ("gzip_7z", ["-tgzip"]), ("bzip2_7z", ["-tbzip2"])):
            out = os.path.join(TMP, f"s_{tag}")
            for e in os.listdir(TMP):
                if e.startswith(f"s_{tag}"):
                    os.remove(os.path.join(TMP, e))
            single = args[0] in ("-txz", "-tgzip", "-tbzip2")
            src = os.path.join(w, "notes/long.txt") if single else "."
            if run("7z", "a", "-bd", "-y", *args, out + ".x", src, cwd=w):
                for e in os.listdir(TMP):
                    if e.startswith(f"s_{tag}.x"):
                        put_file("containers", tag, os.path.join(TMP, e))
                        if tag == "wim":
                            put_file("fsimage", tag, os.path.join(TMP, e))
                            put("fsimage", "wim_pick", bytes([8]) + open(os.path.join(TMP, e), "rb").read())
                        if tag.startswith("7z_"):
                            put("fsimage", tag, bytes([7]) + open(os.path.join(TMP, e), "rb").read())
    # tar in every dialect, then compressed.
    for tag, fmt in (("gnu", tarfile.GNU_FORMAT), ("pax", tarfile.PAX_FORMAT), ("ustar", tarfile.USTAR_FORMAT)):
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w", format=fmt) as t:
            for n, d in files.items():
                ti = tarfile.TarInfo(n)
                ti.size = len(d)
                ti.mtime = 1700000000
                t.addfile(ti, io.BytesIO(d))
            link = tarfile.TarInfo("link")
            link.type = tarfile.SYMTYPE
            link.linkname = "readme.txt"
            t.addfile(link)
            long = tarfile.TarInfo("d/" * 40 + "very_long_file_name_" + "x" * 60)
            long.size = 3
            t.addfile(long, io.BytesIO(b"abc"))
        raw = b.getvalue()
        container(f"tar_{tag}", raw)
        if tag == "gnu":
            container("tar_gz", gzip.compress(raw, 9, mtime=0))
            container("tar_bz2", bz2.compress(raw))
            container("tar_xz", lzma.compress(raw))
            container("tar_lzma", lzma.compress(raw, format=lzma.FORMAT_ALONE))
            container("tar_xz_crc64", lzma.compress(raw, check=lzma.CHECK_CRC64))
            container("tar_xz_sha256", lzma.compress(raw, check=lzma.CHECK_SHA256))
            container("tar_xz_nocheck", lzma.compress(raw, check=lzma.CHECK_NONE))
            container("tar_xz_multi", lzma.compress(raw[:2048]) + lzma.compress(raw[2048:4096]))
            container("tar_gz_multi", gzip.compress(raw[:1024], mtime=0) + gzip.compress(raw[1024:], mtime=0))
            container("tar_bz2_multi", bz2.compress(raw[:1024]) + bz2.compress(raw[1024:]))
            container("tar_zlib", zlib.compress(raw))
            for tool, ext, extra in (("zstd", "zst", []), ("lz4", "lz4", []), ("lzop", "lzo", []),
                                     ("zstd", "zst_dict", ["--long=20"])):
                if have(tool):
                    src = os.path.join(TMP, "x.tar")
                    open(src, "wb").write(raw)
                    out = os.path.join(TMP, f"x.tar.{ext}")
                    if os.path.exists(out):
                        os.remove(out)
                    if tool == "zstd":
                        ok = run("zstd", "-q", "-f", *extra, src, "-o", out)
                    elif tool == "lz4":
                        ok = run("lz4", "-q", "-f", src, out)
                    else:
                        ok = run("lzop", "-q", "-f", "-o", out, src)
                    if ok:
                        put_file("containers", f"tar_{ext}", out)
    # cpio, ar, deb.
    if have("cpio"):
        for tag, fmt in (("newc", "newc"), ("crc", "crc"), ("odc", "odc"), ("bin", "bin")):
            listing = "\n".join(n for n in names if n != "empty.txt").encode()
            r = subprocess.run(["cpio", "-o", "-H", fmt, "--quiet"], input=listing, cwd=w, capture_output=True)
            if r.returncode == 0:
                container(f"cpio_{tag}", r.stdout)
    if have("ar"):
        out = os.path.join(TMP, "a.a")
        if os.path.exists(out):
            os.remove(out)
        if run("ar", "rcs", out, "readme.txt", "bin/mz.exe", "data/test.com", cwd=w):
            put_file("containers", "ar", out)
    if have("dpkg-deb"):
        d = work("deb")
        write_tree(os.path.join(d, "usr/share/doc/x"), {"readme": b"x" * 100, "test.com": EICAR})
        os.makedirs(os.path.join(d, "DEBIAN"))
        open(os.path.join(d, "DEBIAN/control"), "w").write(
            "Package: x\nVersion: 1\nArchitecture: all\nMaintainer: a <a@b>\nDescription: x\n")
        open(os.path.join(d, "DEBIAN/postinst"), "w").write("#!/bin/sh\necho hi\n")
        os.chmod(os.path.join(d, "DEBIAN/postinst"), 0o755)
        for comp in ("gzip", "xz", "zstd", "none"):
            out = os.path.join(TMP, f"x_{comp}.deb")
            if run("dpkg-deb", f"-Z{comp}", "-b", d, out):
                put_file("containers", f"deb_{comp}", out)
    # cab.
    if have("gcab"):
        out = os.path.join(TMP, "c.cab")
        if os.path.exists(out):
            os.remove(out)
        if run("gcab", "-c", out, "readme.txt", "notes/long.txt", "data/test.com", cwd=w):
            put_file("containers", "cab_gcab", out)
        out = os.path.join(TMP, "c0.cab")
        if os.path.exists(out):
            os.remove(out)
        if run("gcab", "-c", "-n", out, "readme.txt", "notes/long.txt", "data/test.com", cwd=w):
            put_file("containers", "cab_gcab_store", out)
    # Single-stream formats and encodings of a file.
    blob = files["notes/long.txt"]
    container("gz", gzip.compress(blob, 6, mtime=0))
    gz = io.BytesIO()
    with gzip.GzipFile(filename="name.txt", mode="wb", fileobj=gz, mtime=1) as f:
        f.write(blob)
    container("gz_name", gz.getvalue())
    container("bz2", bz2.compress(blob))
    container("xz", lzma.compress(blob))
    container("lzma_alone", lzma.compress(blob, format=lzma.FORMAT_ALONE))
    container("zlib", zlib.compress(blob))
    container("uuencode", b"begin 644 test.com\n" + b"".join(
        bytes([32 + len(blob[i:i + 45])]) + _uu(blob[i:i + 45]) + b"\n" for i in range(0, 300, 45)) + b"`\nend\n")
    container("base64_zip", base64.encodebytes(open(os.path.join(TMP, "z_level9.zip"), "rb").read()) if os.path.exists(os.path.join(TMP, "z_level9.zip")) else b"")
    container("html_smuggling", b"<html><script>var b='" + base64.b64encode(zlib.compress(blob)) + b"';var d=atob(b);</script></html>")
    # Truncations of the above are the mutator's, but a few cut points are the
    # ones a reader meets: a cut inside a header, a trailer and a member.
    for name in ("zip_deflate", "7z_lzma", "tar_gz", "tar_xz", "tar_bz2"):
        p = os.path.join(OUT, "containers", "gen_" + name)
        if os.path.exists(p):
            d = open(p, "rb").read()
            for cut in (len(d) - 1, len(d) - 20, len(d) // 2, 40):
                container(f"{name}_cut{cut}", d[:cut])


def _uu(chunk):
    out = bytearray()
    chunk = chunk + b"\0" * (-len(chunk) % 3)
    for i in range(0, len(chunk), 3):
        a, b, c = chunk[i:i + 3]
        for v in (a >> 2, (a << 4 | b >> 4) & 63, (b << 2 | c >> 6) & 63, c & 63):
            out.append(32 + v if v else 96)
    return bytes(out)


# --- filesystems ------------------------------------------------------------

def trimmed(path):
    """A disk image up to its last non-zero byte, rounded to a sector."""
    d = open(path, "rb").read()
    d = d.rstrip(b"\0")
    return d + b"\0" * (-len(d) % 512)


def filesystems():
    files = payloads()
    src = work("fs")
    write_tree(src, files)
    small = work("fs-small")
    write_tree(small, {k: v[:600] for k, v in files.items() if k in ("readme.txt", "notes/long.txt", "bin/mz.exe", "data/test.com")})
    if have("mke2fs"):
        for tag, args, size in (("ext2", ["-t", "ext2", "-O", "^resize_inode"], 64), ("ext3", ["-t", "ext3", "-O", "^resize_inode"], 4096),
                                ("ext4", ["-t", "ext4", "-O", "^has_journal,^resize_inode"], 512),
                                ("ext4_inline", ["-t", "ext4", "-O", "^has_journal,^resize_inode,inline_data"], 512),
                                ("ext4_bigalloc", ["-t", "ext4", "-O", "^has_journal,^resize_inode,bigalloc", "-C", "4096"], 1024),
                                ("ext4_64bit", ["-t", "ext4", "-O", "^has_journal,^resize_inode,64bit,meta_bg"], 512)):
            img = os.path.join(TMP, f"{tag}.img")
            if os.path.exists(img):
                os.remove(img)
            if run("mke2fs", "-q", "-F", "-b", "1024", "-N", "24", *args, "-d", small, img, str(size)):
                d = trimmed(img)
                container(tag, d)
                put("fsimage", tag, bytes([0]) + d)
                put("vdisk", tag + "_all", b"\xff" + d)
    if have("mkfs.vfat") and have("mcopy"):
        for tag, args in (("fat12", ["-F", "12"]), ("fat16", ["-F", "16"]), ("fat32", ["-F", "32"])):
            img = os.path.join(TMP, f"{tag}.img")
            if os.path.exists(img):
                os.remove(img)
            size = {"fat12": 512, "fat16": 8192, "fat32": 66000}[tag]
            subprocess.run(["truncate", "-s", f"{size}K", img])
            if run("mkfs.vfat", *args, "-S", "512", "-n", "SEED", img):
                for n in ("readme.txt", "notes/long.txt", "bin/mz.exe", "data/test.com"):
                    run("mcopy", "-i", img, os.path.join(small, n), "::" + os.path.basename(n))
                run("mmd", "-i", img, "::DIR")
                run("mcopy", "-i", img, os.path.join(small, "readme.txt"), "::DIR/LONGER_FILE_NAME_HERE.txt")
                d = trimmed(img)
                container(tag, d)
                put("vdisk", tag, bytes([5]) + d)
    if have("mkfs.exfat"):
        img = os.path.join(TMP, "exfat.img")
        subprocess.run(["truncate", "-s", "8M", img])
        if run("mkfs.exfat", img):
            d = trimmed(img)
            put("fsimage", "exfat", bytes([1]) + d)
            container("exfat", d)
    if have("mksquashfs"):
        for comp in ("gzip", "xz", "lzo", "lz4", "zstd", "lzma"):
            out = os.path.join(TMP, f"s_{comp}.sqfs")
            if os.path.exists(out):
                os.remove(out)
            if run("mksquashfs", src, out, "-comp", comp, "-b", "4096", "-noappend", "-quiet", "-no-progress"):
                d = open(out, "rb").read()
                container(f"squashfs_{comp}", d)
                put("fsimage", f"squashfs_{comp}", bytes([2]) + d)
        out = os.path.join(TMP, "s_frag.sqfs")
        if os.path.exists(out):
            os.remove(out)
        if run("mksquashfs", src, out, "-comp", "gzip", "-b", "4096", "-noappend", "-no-fragments", "-quiet", "-no-progress"):
            put("fsimage", "squashfs_nofrag", bytes([2]) + open(out, "rb").read())
    if have("mkfs.erofs"):
        for tag, args in (("erofs", []), ("erofs_lz4", ["-zlz4"]), ("erofs_lz4hc", ["-zlz4hc"]),
                          ("erofs_lzma", ["-zlzma"]), ("erofs_inline", ["-E", "force-inode-compact"])):
            out = os.path.join(TMP, f"{tag}.img")
            if os.path.exists(out):
                os.remove(out)
            if run("mkfs.erofs", *args, out, src):
                d = trimmed(out)
                container(tag, d)
                put("fsimage", tag, bytes([5]) + d)
    if have("mkisofs"):
        for tag, args in (("iso", []), ("iso_joliet", ["-J"]), ("iso_rr", ["-R"]), ("iso_joliet_rr", ["-J", "-R"]),
                          ("iso_udf", ["-udf"]), ("iso_l2", ["-iso-level", "4"]), ("iso_boot", ["-no-pad"])):
            out = os.path.join(TMP, f"{tag}.iso")
            if os.path.exists(out):
                os.remove(out)
            if run("mkisofs", "-quiet", "-o", out, *args, small):
                d = trimmed(out)
                container(tag, d)
                put("fsimage", tag, bytes([0xff]) + d)


# --- virtual disks ----------------------------------------------------------

def disks():
    if not need("qemu-img", "mkfs.vfat", "mcopy"):
        return
    raw = os.path.join(TMP, "disk.raw")
    subprocess.run(["truncate", "-s", "2M", raw])
    run("mkfs.vfat", "-F", "12", raw)
    run("mcopy", "-i", raw, os.path.join(TMP, "fs-small", "readme.txt"), "::README.TXT")
    run("mcopy", "-i", raw, os.path.join(TMP, "fs-small", "data", "test.com"), "::TEST.COM")
    for tag, fmt, opts, pick in (("qcow2", "qcow2", [], 0), ("qcow2_v2", "qcow2", ["-o", "compat=0.10"], 0),
                                 ("qcow2_zlib", "qcow2", ["-c"], 0), ("qcow2_zstd", "qcow2", ["-c", "-o", "compression_type=zstd"], 0),
                                 ("qcow2_cluster4k", "qcow2", ["-o", "cluster_size=4096"], 0),
                                 ("vmdk_sparse", "vmdk", [], 1), ("vmdk_stream", "vmdk", ["-o", "subformat=streamOptimized"], 1),
                                 ("vhd_dynamic", "vpc", [], 2), ("vhd_fixed", "vpc", ["-o", "subformat=fixed"], 2),
                                 ("vhdx", "vhdx", [], 3)):
        out = os.path.join(TMP, f"d_{tag}")
        if os.path.exists(out):
            os.remove(out)
        if run("qemu-img", "convert", "-f", "raw", "-O", fmt, *opts, raw, out):
            d = open(out, "rb").read()
            if len(d) > MAX_BYTES:
                d = d.rstrip(b"\0")
                d += b"\0" * (-len(d) % 512)
            put("vdisk", tag, bytes([pick]) + d)
            container(tag, d)
    # A partition table around a FAT volume.
    vol = open(raw, "rb").read().rstrip(b"\0")
    vol += b"\0" * (-len(vol) % 512)
    mbr = bytearray(512)
    mbr[0x1BE:0x1BE + 16] = struct.pack("<B3sB3sII", 0x80, b"\0\2\0", 0x01, b"\0\0\0", 1, len(vol) // 512)
    mbr[510:512] = b"\x55\xAA"
    put("vdisk", "mbr_fat12", bytes([6]) + bytes(mbr) + vol)
    put("fsimage", "mbr_fat12", bytes([6]) + bytes(mbr) + vol)


# --- documents ---------------------------------------------------------------

ODF_NS = ('xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
          'xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" '
          'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
          'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
          'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
          'xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" '
          'xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" '
          'xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" '
          'xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0" '
          'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/"')


def png_bytes(w, h, mode="RGB"):
    from PIL import Image
    im = Image.new(mode, (w, h))
    px = im.load()
    for y in range(h):
        for x in range(w):
            v = (x * 7 % 256, y * 9 % 256, (x * y) % 256)
            px[x, y] = v if mode == "RGB" else v[0]
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


def fodt(variant):
    r = random.Random(variant)
    img = base64.b64encode(png_bytes(16, 12)).decode()
    paras = "".join(
        f'<text:p text:style-name="P{i % 3}">{text_blob(r.randrange(3, 30), i).decode()} '
        f'<text:span text:style-name="B">bold</text:span> <text:a xlink:href="http://example.org/{i}">link {i}</text:a>'
        f'<text:note text:note-class="footnote"><text:note-body><text:p>note {i}</text:p></text:note-body></text:note></text:p>'
        for i in range(2 + variant * 3))
    lst = "<text:list>" + "".join(f"<text:list-item><text:p>item {i}</text:p>" + (
        "<text:list><text:list-item><text:p>sub</text:p></text:list-item></text:list>" if i % 2 else "") + "</text:list-item>"
        for i in range(4)) + "</text:list>"
    tbl = ('<table:table table:name="T1"><table:table-column table:number-columns-repeated="3"/>' + "".join(
        "<table:table-row>" + "".join(f'<table:table-cell office:value-type="string"><text:p>c{i}{j}</text:p></table:table-cell>'
                                      for j in range(3)) + "</table:table-row>" for i in range(3 + variant)) + "</table:table>")
    frame = (f'<draw:frame draw:name="img" text:anchor-type="as-char" svg:width="2cm" svg:height="1.5cm"><draw:image>'
             f'<office:binary-data>{img}</office:binary-data></draw:image></draw:frame>')
    return (f'<?xml version="1.0" encoding="UTF-8"?><office:document {ODF_NS} '
            f'office:mimetype="application/vnd.oasis.opendocument.text" office:version="1.3"><office:font-face-decls/>'
            f'<office:styles><style:style style:name="B" style:family="text"><style:text-properties fo:font-weight="bold" fo:color="#aa0000"/></style:style></office:styles>'
            f'<office:automatic-styles><style:style style:name="P0" style:family="paragraph"><style:paragraph-properties fo:text-align="center"/></style:style>'
            f'<style:style style:name="P1" style:family="paragraph"><style:text-properties fo:font-size="14pt" fo:font-style="italic"/></style:style>'
            f'<style:style style:name="P2" style:family="paragraph"><style:paragraph-properties fo:margin-left="1cm" fo:background-color="#eeeeee"/></style:style>'
            f'</office:automatic-styles><office:body><office:text><text:h text:outline-level="1">Title {variant}</text:h>'
            f'{paras}{lst}{tbl}<text:p>{frame}<text:bookmark text:name="b{variant}"/><text:date/></text:p></office:text></office:body></office:document>')


def fods(variant):
    r = random.Random(100 + variant)
    rows = "".join(
        "<table:table-row>" + "".join(
            (f'<table:table-cell office:value-type="float" office:value="{r.randrange(1000) / 10}"><text:p>x</text:p></table:table-cell>' if j % 3 else
             f'<table:table-cell office:value-type="string"><text:p>text{i}{j}</text:p></table:table-cell>') for j in range(6)) +
        f'<table:table-cell table:formula="of:=SUM([.A{i + 1}:.E{i + 1}])" office:value-type="float" office:value="0"/>' +
        "</table:table-row>" for i in range(4 + variant * 3))
    return (f'<?xml version="1.0" encoding="UTF-8"?><office:document {ODF_NS} '
            f'office:mimetype="application/vnd.oasis.opendocument.spreadsheet" office:version="1.3"><office:body><office:spreadsheet>'
            f'<table:table table:name="Sheet1"><table:table-column table:number-columns-repeated="7"/>{rows}</table:table>'
            f'<table:table table:name="Sheet2"><table:table-row><table:table-cell office:value-type="date" office:date-value="2026-01-0{1 + variant % 9}"><text:p>d</text:p></table:table-cell>'
            f'<table:table-cell office:value-type="percentage" office:value="0.5"><text:p>50%</text:p></table:table-cell>'
            f'<table:table-cell office:value-type="currency" office:currency="EUR" office:value="9.5"><text:p>9.5</text:p></table:table-cell></table:table-row></table:table>'
            f'</office:spreadsheet></office:body></office:document>')


def fodp(variant):
    slides = "".join(
        f'<draw:page draw:name="s{i}"><draw:frame presentation:class="title" svg:x="1cm" svg:y="1cm" svg:width="20cm" svg:height="3cm"><draw:text-box>'
        f'<text:p>Slide {i} {variant}</text:p></draw:text-box></draw:frame><draw:frame svg:x="1cm" svg:y="5cm" svg:width="20cm" svg:height="8cm"><draw:text-box>'
        f'<text:list><text:list-item><text:p>point {i}</text:p></text:list-item><text:list-item><text:p>another</text:p></text:list-item></text:list></draw:text-box></draw:frame>'
        f'<draw:rect svg:x="2cm" svg:y="14cm" svg:width="4cm" svg:height="2cm"><text:p>box</text:p></draw:rect>'
        f'<draw:ellipse svg:x="8cm" svg:y="14cm" svg:width="3cm" svg:height="3cm"/>'
        f'<draw:line svg:x1="1cm" svg:y1="18cm" svg:x2="15cm" svg:y2="19cm"/></draw:page>' for i in range(1 + variant))
    return (f'<?xml version="1.0" encoding="UTF-8"?><office:document {ODF_NS} '
            f'office:mimetype="application/vnd.oasis.opendocument.presentation" office:version="1.3"><office:body><office:presentation>'
            f'{slides}</office:presentation></office:body></office:document>')


def documents():
    if not need("soffice"):
        return
    src = work("lo-src")
    for v in range(4):
        open(os.path.join(src, f"t{v}.fodt"), "w").write(fodt(v))
        open(os.path.join(src, f"s{v}.fods"), "w").write(fods(v))
        open(os.path.join(src, f"p{v}.fodp"), "w").write(fodp(v))
    profile = "file://" + os.path.join(TMP, "lo-profile")
    plans = [
        # (glob extension, filter name, extension of output, targets)
        ("fodt", "MS Word 97", "doc", ["docs_doc"]),
        ("fodt", "MS Word 97 Vorlage", "dot", ["docs_doc"]),
        ("fodt", "Rich Text Format", "rtf", ["docs_rtf"]),
        ("fodt", "MS Word 2003 XML", "xml", ["docs_wml"]),
        ("fodt", "HTML (StarWriter)", "html", ["docs_html"]),
        ("fodt", "writer8", "odt", ["docs_odt"]),
        ("fodt", "OpenDocument Text Flat XML", "fodt", ["docs_odt"]),
        ("fodt", "MS Word 2007 XML", "docx", []),
        ("fods", "MS Excel 97", "xls", ["sheets_xls"]),
        ("fods", "MS Excel 5.0/95", "xls", ["sheets_xls"]),
        ("fods", "MS Excel 2003 XML", "xml", ["sheets_text"]),
        ("fods", "SYLK", "slk", ["sheets_text"]),
        ("fods", "HTML (StarCalc)", "html", ["sheets_text"]),
        ("fods", "calc8", "ods", ["sheets_ods"]),
        ("fods", "OpenDocument Spreadsheet Flat XML", "fods", ["sheets_ods"]),
        ("fods", "Calc MS Excel 2007 XML", "xlsx", []),
        ("fodp", "MS PowerPoint 97", "ppt", ["slides_ppt"]),
        ("fodp", "impress8", "odp", ["slides_odp"]),
        ("fodp", "OpenDocument Presentation Flat XML", "fodp", ["slides_odp"]),
        ("fodp", "Impress MS PowerPoint 2007 XML", "pptx", []),
        ("fodp", "draw8", "odg", ["slides_odg"]),
    ]
    for ext, flt, out_ext, targets in plans:
        outdir = work(f"lo-out-{out_ext}-{flt.replace(' ', '_').replace('(', '').replace(')', '')}")
        ok = run("soffice", f"-env:UserInstallation={profile}", "--headless", "--norestore",
                 "--convert-to", f"{out_ext}:{flt}", "--outdir", outdir,
                 *[os.path.join(src, f) for f in sorted(os.listdir(src)) if f.endswith("." + ext)], timeout=240)
        produced = sorted(os.listdir(outdir)) if os.path.isdir(outdir) else []
        if not ok or not produced:
            note(f"documents: {flt} produced nothing")
            continue
        for f in produced:
            data = open(os.path.join(outdir, f), "rb").read()
            tag = f"{flt.replace(' ', '_').lower()}_{f}"
            for t in targets:
                put(t, tag, data)
            container(tag, data)
            # Over the size of a seed (a thumbnail, the summary streams): the
            # stream the converter reads is one.
            if out_ext == "ppt" and len(data) > MAX_BYTES:
                try:
                    import olefile
                    ole = olefile.OleFileIO(io.BytesIO(data))
                    put("slides_ppt", tag + "_document_stream", ole.openstream("PowerPoint Document").read())
                except Exception as e:
                    note(f"documents: ppt stream: {type(e).__name__}")
            # The text view (first byte picks the reader: fuzz_targets/visible_text.rs).
            pick = {"doc": 11, "dot": 11, "xls": 12, "ppt": 13, "rtf": 14, "slk": 16, "fodt": 17, "fods": 18, "fodp": 19}.get(out_ext)
            if out_ext == "xml":
                pick = 15
            if pick:
                put("visible_text", tag, bytes([pick]) + data)


# --- images ------------------------------------------------------------------

def images():
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        note("images: Pillow is not installed")
        return
    r = random.Random(11)

    def picture(w, h, mode="RGB"):
        im = Image.new("RGB", (w, h))
        d = ImageDraw.Draw(im)
        for i in range(0, w + h, 5):
            d.line([(0, i), (i, 0)], fill=(i * 3 % 256, i * 5 % 256, i * 7 % 256))
        d.ellipse([w // 4, h // 4, 3 * w // 4, 3 * h // 4], outline=(255, 0, 0), fill=(0, (w * 3) % 256, 90))
        d.text((2, 2), "exav", fill=(255, 255, 255))
        if mode == "RGB":
            return im
        if mode == "RGBA":
            a = Image.linear_gradient("L").resize((w, h))
            im.putalpha(a)
            return im
        if mode == "P":
            return im.convert("P", palette=Image.ADAPTIVE, colors=16)
        if mode == "1":
            return im.convert("1")
        return im.convert(mode)

    def save(target, name, im, fmt, **kw):
        b = io.BytesIO()
        try:
            im.save(b, fmt, **kw)
        except Exception as e:  # a mode a format cannot hold
            return False
        ok = put(target, name, b.getvalue())
        if ok:
            container(name, b.getvalue())
        return ok

    sizes = [(1, 1), (2, 3), (7, 5), (16, 16), (33, 17), (64, 48), (100, 3), (3, 100)]
    for (w, h) in sizes:
        for mode in ("RGB", "RGBA", "L", "LA", "P", "1"):
            im = picture(w, h, mode)
            save("imagehash", f"png_{mode}_{w}x{h}", im, "PNG")
            if (w, h) in ((16, 16), (33, 17)):
                save("imagehash", f"gif_{mode}_{w}x{h}", im if mode in ("P", "L", "1") else im.convert("P"), "GIF")
                save("imagehash", f"bmp_{mode}_{w}x{h}", im if mode in ("RGB", "RGBA", "L", "P", "1") else im.convert("RGB"), "BMP")
                save("imagehash", f"webp_{mode}_{w}x{h}", im if mode in ("RGB", "RGBA") else im.convert("RGB"), "WEBP")
                save("imagehash", f"webp_lossless_{mode}_{w}x{h}", im if mode in ("RGB", "RGBA") else im.convert("RGB"), "WEBP", lossless=True)
                save("imagehash", f"ico_{mode}_{w}x{h}", im.convert("RGBA"), "ICO")
                save("imagehash", f"tga_{mode}_{w}x{h}", im if mode in ("RGB", "RGBA", "L") else im.convert("RGB"), "TGA")
                save("imagehash", f"ppm_{mode}_{w}x{h}", im if mode in ("RGB", "L", "1") else im.convert("RGB"), "PPM")
                for comp in ("raw", "tiff_lzw", "tiff_adobe_deflate", "packbits", "tiff_jpeg", "tiff_deflate"):
                    mm = im if mode in ("RGB", "RGBA", "L", "P", "1") else im.convert("RGB")
                    if comp == "tiff_jpeg":
                        mm = mm.convert("RGB")
                    save("raw_preview", f"tiff_{comp}_{mode}_{w}x{h}", mm, "TIFF", compression=None if comp == "raw" else comp)
                    save("imagehash", f"tiff_{comp}_{mode}_{w}x{h}", mm, "TIFF", compression=None if comp == "raw" else comp)
                if mode == "1":
                    for comp in ("group3", "group4"):
                        save("imagehash", f"tiff_{comp}_{w}x{h}", im, "TIFF", compression=comp)
    # 16-bit and float TIFF and PNG.
    for mode in ("I;16", "I", "F"):
        im = Image.new(mode, (24, 18))
        px = im.load()
        for y in range(18):
            for x in range(24):
                px[x, y] = (x * 1000 + y * 37) % (65536 if mode == "I;16" else 1000000) if mode != "F" else x * 1.5 + y / 3
        save("imagehash", f"tiff_{mode}", im, "TIFF")
        save("raw_preview", f"tiff_{mode}", im, "TIFF")
        if mode == "I;16":
            save("imagehash", "png_16bit", im, "PNG")
    # JPEG: every sampling and mode libjpeg writes.
    if have("cjpeg"):
        ppm = os.path.join(TMP, "j.ppm")
        picture(97, 61).save(ppm)
        pgm = os.path.join(TMP, "j.pgm")
        picture(97, 61).convert("L").save(pgm)
        n = 0
        for samp in ("1x1", "2x1", "1x2", "2x2", "4x1", "4x2", "1x4"):
            for q in (5, 50, 95, 100):
                for extra in ([], ["-progressive"], ["-optimize"], ["-restart", "3"], ["-dct", "float"], ["-dct", "fast"], ["-arithmetic"], ["-baseline"]):
                    if (q, tuple(extra)) not in ((50, ()), (95, ("-progressive",)), (5, ("-optimize",)), (100, ("-restart", "3")),
                                                 (50, ("-dct", "float")), (95, ("-dct", "fast")), (50, ("-arithmetic",)), (5, ("-baseline",))):
                        continue
                    out = os.path.join(TMP, "j.jpg")
                    if run("cjpeg", "-quality", str(q), "-sample", f"{samp},1x1,1x1", *extra, "-outfile", out, ppm):
                        name = f"jpeg_{samp}_q{q}_{'_'.join(e.strip('-') for e in extra) or 'plain'}"
                        d = open(out, "rb").read()
                        put("imagehash", name, d)
                        put("raw_preview", name, d)
                        container(name, d)
                        n += 1
        for extra in ([], ["-progressive"], ["-grayscale"], ["-restart", "1"]):
            out = os.path.join(TMP, "g.jpg")
            if run("cjpeg", "-quality", "70", *extra, "-outfile", out, pgm):
                put("imagehash", "jpeg_gray_" + "_".join(e.strip("-") for e in extra), open(out, "rb").read())
        # One scan for each component, and spectral selection and refinement.
        scans = os.path.join(TMP, "scans.txt")
        for tag, script in (("scan_each", "0: 0 63 0 0;\n1: 0 63 0 0;\n2: 0 63 0 0;\n"),
                            ("progressive_refine", "0,1,2: 0 0 0 1;\n0: 1 5 0 2;\n2: 1 63 0 1;\n1: 1 63 0 1;\n0: 6 63 0 2;\n0: 1 63 2 1;\n0,1,2: 0 0 1 0;\n2: 1 63 1 0;\n1: 1 63 1 0;\n0: 1 63 1 0;\n")):
            open(scans, "w").write(script)
            out = os.path.join(TMP, "s.jpg")
            if run("cjpeg", "-quality", "80", "-sample", "2x2,1x1,1x1", "-scans", scans, "-outfile", out, ppm):
                put("imagehash", f"jpeg_{tag}", open(out, "rb").read())
    # JPEG 2000: OpenJPEG's options.
    if have("opj_compress"):
        png = os.path.join(TMP, "o.png")
        picture(90, 70, "RGB").save(png)
        pgm_png = os.path.join(TMP, "og.png")
        picture(90, 70).convert("L").save(pgm_png)
        variants = [("default", []), ("lossy", ["-r", "20"]), ("res3", ["-n", "3"]), ("cb16", ["-b", "16,16"]),
                    ("tiles32", ["-t", "32,32"]), ("tiles16", ["-t", "16,16"]), ("sop_eph", ["-SOP", "-EPH"]),
                    ("rlcp", ["-p", "RLCP"]), ("rpcl", ["-p", "RPCL"]), ("pcrl", ["-p", "PCRL"]), ("cprl", ["-p", "CPRL"]),
                    ("irreversible", ["-I", "-r", "10"]), ("layers", ["-r", "30,10,1"]), ("mct0", ["-mct", "0"]),
                    ("roi", ["-ROI", "c=0,U=10"]), ("bypass", ["-M", "1"]), ("reset", ["-M", "2"]), ("termall", ["-M", "4"]),
                    ("vcausal", ["-M", "8"]), ("pterm", ["-M", "16"]), ("segsym", ["-M", "32"]), ("tlm", ["-TLM"]),
                    ("plt", ["-PLT"]), ("offset", ["-d", "5,7"]), ("tileoffset", ["-T", "3,2", "-t", "32,32"]),
                    ("subsample", ["-s", "2,2"]), ("precincts", ["-c", "[32,32],[16,16]"]), ("gray", None)]
        for tag, args in variants:
            for ext in ("j2k", "jp2"):
                if tag == "gray" and ext == "jp2":
                    continue
                out = os.path.join(TMP, f"o.{ext}")
                if os.path.exists(out):
                    os.remove(out)
                if run("opj_compress", "-i", pgm_png if tag == "gray" else png, "-o", out, *(args or [])):
                    d = open(out, "rb").read()
                    put("imagehash", f"jp2_{tag}_{ext}", d)
                    container(f"jp2_{tag}_{ext}", d)
    # JBIG2 and fax.
    if have("jbig2"):
        pbm = os.path.join(TMP, "b.pbm")
        picture(120, 80).convert("1").save(pbm)
        for tag, args in (("generic", []), ("symbol", ["-s"]), ("symbol_refine", ["-s", "-r"]), ("pdf", ["-p"]), ("sloppy", ["-s", "-S"])):
            r_ = subprocess.run(["jbig2", *args, pbm], capture_output=True, cwd=TMP)
            if r_.returncode == 0 and put("imagehash", f"jbig2_{tag}", r_.stdout):
                pass
    if have("tiffcp") and "tiff" in os.environ.get("EXAV_SEEDS_TIFFCP", "1"):
        base = os.path.join(TMP, "t.tif")
        picture(70, 50).save(base, compression="tiff_lzw")
        for tag, args in (("tiled16", ["-t", "-w", "16", "-l", "16"]), ("planar", ["-p", "separate"]), ("rows2", ["-r", "2"]),
                          ("bigtiff", ["-8"]), ("lzw_predictor", ["-c", "lzw:2"]), ("deflate_predictor", ["-c", "zip:2"]),
                          ("lzma", ["-c", "lzma"]), ("zstd", ["-c", "zstd"]), ("jpeg_ycbcr", ["-c", "jpeg:r:80"]),
                          ("jpeg_raw", ["-c", "jpeg:r:80", "-t", "-w", "16", "-l", "16"]), ("lsb2msb", ["-L"]), ("msb2lsb", ["-B"])):
            out = os.path.join(TMP, "t2.tif")
            if os.path.exists(out):
                os.remove(out)
            if run("tiffcp", *args, base, out):
                d = open(out, "rb").read()
                put("imagehash", f"tiffcp_{tag}", d)
                put("raw_preview", f"tiffcp_{tag}", d)
                container(f"tiffcp_{tag}", d)


# --- PDF ---------------------------------------------------------------------

def pdf_objects(extra_objs, trailer_extra=""):
    """A PDF written by hand: `extra_objs` are the bodies of objects 4 and up."""
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>"] + extra_objs
    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for o in offs:
        out += f"{o:010} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R {trailer_extra} >>\nstartxref\n{x}\n%%EOF\n".encode()
    return bytes(out)


def stream(dict_extra, data):
    return f"<< /Length {len(data)} {dict_extra} >>\nstream\n".encode() + data + b"\nendstream"


def a85(data):
    return base64.a85encode(data, adobe=True)


def lzw(data):
    """PDF/TIFF LZW (MSB first, early change), enough for short inputs."""
    table = {bytes([i]): i for i in range(256)}
    nxt, bits, out, acc, nacc = 258, 9, [], 0, 0

    def emit(code):
        nonlocal acc, nacc
        acc = acc << bits | code
        nacc += bits
        while nacc >= 8:
            out.append(acc >> (nacc - 8) & 255)
            nacc -= 8
    emit(256)
    w = b""
    for c in data:
        wc = w + bytes([c])
        if wc in table:
            w = wc
        else:
            emit(table[w])
            table[wc] = nxt
            nxt += 1
            if nxt + 1 > (1 << bits) and bits < 12:
                bits += 1
            w = bytes([c])
    if w:
        emit(table[w])
    emit(257)
    if nacc:
        out.append(acc << (8 - nacc) & 255)
    return bytes(out)


def pdf():
    content = b"BT /F1 12 Tf 20 150 Td (Hello exav) Tj 0 -20 Td [(Ke) 20 (rning)] TJ ET 0 0 1 rg 20 20 60 60 re f"
    deflated = zlib.compress(content)
    cases = {
        "plain": [stream("", content)],
        "flate": [stream("/Filter /FlateDecode", deflated)],
        "ascii85": [stream("/Filter /ASCII85Decode", a85(content))],
        "asciihex": [stream("/Filter /ASCIIHexDecode", content.hex().encode() + b">")],
        "lzw": [stream("/Filter /LZWDecode", lzw(content))],
        "runlength": [stream("/Filter /RunLengthDecode", bytes([len(content) - 1]) + content + b"\x80")],
        "chain_a85_flate": [stream("/Filter [/ASCII85Decode /FlateDecode]", a85(deflated))],
        "chain_hex_lzw_flate": [stream("/Filter [/ASCIIHexDecode /FlateDecode]", deflated.hex().encode() + b">")],
        "filter_by_ref": [stream("/Filter 5 0 R", deflated), b"/FlateDecode"],
        "decodeparms_predictor": [stream("/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >>", zlib.compress(b"\x02" + bytes(range(4)) * 3))],
        "crypt_identity": [stream("/Filter [/Crypt /FlateDecode] /DecodeParms [<< /Name /Identity >> null]", deflated)],
        "form_xobject": [stream("", b"q /Fm1 Do Q"), stream("/Type /XObject /Subtype /Form /BBox [0 0 10 10]", content)],
        "uri_action": [stream("", content), b"<< /Type /Annot /Subtype /Link /Rect [0 0 50 50] /A << /S /URI /URI (http://example.org/x) >> >>"],
        "js_action": [stream("", content), b"<< /S /JavaScript /JS (app.alert\\(1\\);) >>"],
        "launch": [stream("", content), b"<< /S /Launch /F (cmd.exe) /P (/c calc) >>"],
        "embedded_file": [stream("", content), stream("/Type /EmbeddedFile /Params << /Size 14 >>", EICAR)],
        "object_stream": [stream("", content), stream("/Type /ObjStm /N 1 /First 4", b"5 0 \n<< /A 1 >>")],
        "xfa": [stream("", content), stream("/Type /XFA", b"<xdp:xdp xmlns:xdp='http://ns.adobe.com/xdp/'><x/></xdp:xdp>")],
        "unterminated": [b"<< /Length 5 >>\nstream\nabc"],
        "huge_length": [stream("/Length2 99999999", content)],
    }
    for tag, objs in cases.items():
        d = pdf_objects(objs)
        container(f"pdf_{tag}", d)
        put("visible_text", f"pdf_{tag}", bytes([7]) + d)
    # reportlab and qpdf.
    base = None
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.utils import ImageReader
        for tag, kw in (("rl_text", {}), ("rl_uncompressed", {"pageCompression": 0}), ("rl_encrypted", {})):
            b = io.BytesIO()
            c = canvas.Canvas(b, pagesize=(200, 200), **kw)
            c.setTitle("seed")
            c.drawString(20, 150, "Hello exav " + tag)
            c.linkURL("http://example.org/a", (10, 10, 100, 40), relative=0)
            c.bookmarkPage("p")
            c.addOutlineEntry("Page", "p")
            c.drawImage(ImageReader(io.BytesIO(png_bytes(20, 20))), 20, 20, 40, 40)
            c.showPage()
            c.drawString(20, 150, "page 2")
            c.save()
            d = b.getvalue()
            container(tag, d)
            put("visible_text", tag, bytes([7]) + d)
            base = base or d
    except ImportError:
        note("pdf: reportlab is not installed")
    if base and have("qpdf"):
        src = os.path.join(TMP, "base.pdf")
        open(src, "wb").write(base)
        for tag, args in (("qdf", ["--qdf", "--object-streams=disable"]), ("objstm", ["--object-streams=generate", "--stream-data=compress"]),
                          ("linearized", ["--linearize"]), ("uncompressed", ["--stream-data=uncompress"]),
                          ("rc4_40", ["--encrypt", "", "owner", "40", "--"]), ("rc4_128", ["--encrypt", "", "owner", "128", "--use-aes=n", "--"]),
                          ("aes_128", ["--encrypt", "", "owner", "128", "--use-aes=y", "--"]), ("aes_256", ["--encrypt", "", "owner", "256", "--"]),
                          ("aes_256_user", ["--encrypt", "secret", "owner", "256", "--"]),
                          ("no_meta_enc", ["--encrypt", "", "owner", "128", "--use-aes=y", "--cleartext-metadata", "--"])):
            out = os.path.join(TMP, "q.pdf")
            if os.path.exists(out):
                os.remove(out)
            subprocess.run(["qpdf", *args, src, out], capture_output=True)
            if os.path.exists(out):
                d = open(out, "rb").read()
                container(f"qpdf_{tag}", d)
                put("visible_text", f"qpdf_{tag}", bytes([7]) + d)
    # PDFs that carry the image streams the viewer's decoders read.
    if have("opj_compress"):
        j2k = os.path.join(TMP, "o.j2k")
        if os.path.exists(j2k):
            d = pdf_objects([stream("", b"q 100 0 0 100 0 0 cm /Im Do Q"),
                             stream("/Type /XObject /Subtype /Image /Width 90 /Height 70 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /JPXDecode",
                                    open(j2k, "rb").read())])
            container("pdf_jpx", d)


# --- drawings ---------------------------------------------------------------

def drawings():
    try:
        import ezdxf
        from ezdxf import colors
    except ImportError:
        note("drawings: ezdxf is not installed")
        return
    r = random.Random(5)
    for version in ("R12", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018"):
        for flavour in ("shapes", "text", "dims", "blocks", "hatch", "layouts", "splines", "polylines", "3d"):
            try:
                doc = ezdxf.new(version, setup=True)
                msp = doc.modelspace()
                doc.layers.add("L1", color=3)
                if flavour == "shapes":
                    msp.add_line((0, 0), (10, 5), dxfattribs={"layer": "L1"})
                    msp.add_circle((5, 5), 3)
                    msp.add_arc((0, 0), 4, 10, 120)
                    msp.add_point((1, 1))
                    if version != "R12":
                        msp.add_ellipse((0, 0), (5, 0), 0.5)
                    msp.add_solid([(0, 0), (1, 0), (1, 1), (0, 1)])
                    msp.add_3dface([(0, 0, 0), (1, 0, 1), (1, 1, 0), (0, 1, 1)])
                if flavour == "text":
                    msp.add_text("Hello é world", dxfattribs={"height": 2, "rotation": 30})
                    if version != "R12":
                        msp.add_mtext("Line one\\PLine {\\C1;two} \\fArial|b1;bold\\f", dxfattribs={"char_height": 1.5})
                if flavour == "dims" and version != "R12":
                    msp.add_linear_dim(base=(5, 3), p1=(0, 0), p2=(10, 0)).render()
                    msp.add_radius_dim((0, 0), (3, 0)).render() if hasattr(msp, "add_radius_dim") else None
                    msp.add_angular_dim_2l(base=(0, 5), line1=((0, 0), (5, 0)), line2=((0, 0), (0, 5))).render()
                if flavour == "blocks":
                    blk = doc.blocks.new("B1")
                    blk.add_line((0, 0), (1, 1))
                    blk.add_text("blk")
                    for i in range(5):
                        msp.add_blockref("B1", (i * 3, i), dxfattribs={"xscale": 1 + i / 4, "rotation": i * 15})
                    if version != "R12":
                        att = doc.blocks.new("B2")
                        att.add_attdef("TAG", (0, 0), text="v")
                        msp.add_blockref("B2", (0, 0)).add_auto_attribs({"TAG": "x"})
                if flavour == "hatch" and version != "R12":
                    h = msp.add_hatch(color=2)
                    h.paths.add_polyline_path([(0, 0), (4, 0), (4, 4), (0, 4)])
                    h2 = msp.add_hatch()
                    h2.set_pattern_fill("ANSI31", scale=0.5)
                    h2.paths.add_polyline_path([(5, 0), (9, 0), (9, 4)])
                    h3 = msp.add_hatch()
                    if version not in ("R2000",):
                        h3.set_gradient((255, 0, 0), (0, 0, 255))
                    h3.paths.add_polyline_path([(10, 0), (14, 0), (14, 4)])
                if flavour == "layouts" and version != "R12":
                    lay = doc.layouts.new("Layout2")
                    lay.add_viewport(center=(5, 5), size=(10, 10), view_center_point=(0, 0), view_height=20)
                    msp.add_line((0, 0), (3, 3))
                if flavour == "splines" and version != "R12":
                    msp.add_spline([(0, 0), (1, 2), (3, 3), (5, 0)])
                    msp.add_open_spline([(0, 0), (1, 2), (3, 3), (5, 0)], degree=3)
                if flavour == "polylines":
                    msp.add_polyline2d([(0, 0), (2, 0, 0.5), (2, 2), (0, 2)], close=True)
                    if version != "R12":
                        msp.add_lwpolyline([(0, 0, 0, 0, 0.3), (5, 0, 0.5, 0.5, 0), (5, 5)], format="xyseb")
                    msp.add_polyline3d([(0, 0, 0), (1, 1, 1), (2, 0, 2)])
                if flavour == "3d" and version not in ("R12",):
                    mesh = msp.add_mesh()
                    mesh.dxf.subdivision_levels = 0
                    with mesh.edit_data() as m:
                        m.vertices = [(0, 0, 0), (1, 0, 0), (1, 1, 0), (0, 1, 1)]
                        m.faces = [(0, 1, 2), (0, 2, 3)]
                s = io.StringIO()
                doc.write(s)
                d = s.getvalue().encode("utf-8" if version in ("R2007", "R2010", "R2013", "R2018") else "cp1252", "replace")
                name = f"dxf_{version}_{flavour}"
                for t in ("cad_dxf", "drawing"):
                    put(t, name, d)
                container(name, d)
                put("visible_text", name, bytes([8]) + d)
            except Exception as e:
                note(f"drawings: {version} {flavour}: {type(e).__name__}")
    # Binary DXF, when ezdxf writes it.
    try:
        doc = ezdxf.new("R2018")
        doc.modelspace().add_line((0, 0), (1, 1))
        b = io.BytesIO()
        doc.write(b, fmt="bin")
        put("cad_dxf", "dxf_binary", b.getvalue())
        put("drawing", "dxf_binary", b.getvalue())
        container("dxf_binary", b.getvalue())
    except Exception as e:
        note(f"drawings: binary DXF: {type(e).__name__}")


# --- mail ---------------------------------------------------------------------

def mail():
    from email.message import EmailMessage
    from email import policy, encoders
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email.mime.application import MIMEApplication
    from email.mime.message import MIMEMessage
    r = random.Random(3)
    attach = {"a.txt": b"plain\n", "a.bin": bytes(r.randrange(256) for _ in range(200)), "a.com": EICAR, "a.zip": b"PK\x05\x06" + bytes(18)}

    def base(subject="seed"):
        m = EmailMessage(policy=policy.SMTP)
        m["From"], m["To"], m["Subject"] = "a@example.org", "b@example.org", subject
        m["Date"] = "Fri, 30 Oct 2026 10:00:00 +0000"
        return m
    m = base()
    m.set_content("Body text\n")
    container("eml_plain", m.as_bytes())
    for tag, cte in (("base64", "base64"), ("qp", "quoted-printable"), ("8bit", "8bit")):
        m = base()
        m.set_content("Hello éè world\n" * 3, cte=cte, charset="utf-8")
        container(f"eml_text_{tag}", m.as_bytes())
    m = base()
    m.set_content("Hello ascii world\n" * 3, cte="7bit")
    container("eml_text_7bit", m.as_bytes())
    for tag, mt, cte in (("base64", ("application", "octet-stream"), "base64"), ("qp", ("application", "x-msdownload"), "quoted-printable"),
                         ("uu", ("application", "x-uuencode"), "x-uuencode")):
        m = base()
        m.set_content("see attachment\n")
        for n, d in attach.items():
            if cte == "x-uuencode":
                continue
            m.add_attachment(d, maintype=mt[0], subtype=mt[1], filename=n, cte=cte)
        if m.is_multipart():
            container(f"eml_attach_{tag}", m.as_bytes())
    m = base()
    m.set_content("text\n")
    m.add_alternative("<html><body><a href='http://example.org'>x</a></body></html>", subtype="html")
    m.add_attachment(attach["a.zip"], maintype="application", subtype="zip", filename="a.zip")
    container("eml_alternative", m.as_bytes())
    inner = base("inner")
    inner.set_content("inner body\n")
    inner.add_attachment(attach["a.com"], maintype="application", subtype="octet-stream", filename="a.com")
    outer = base("outer")
    outer.set_content("outer\n")
    outer.add_attachment(inner)
    container("eml_nested", outer.as_bytes())
    deep = inner
    for i in range(6):
        w = base(f"level{i}")
        w.set_content("wrapped\n")
        w.add_attachment(deep)
        deep = w
    container("eml_nested_deep", deep.as_bytes())
    raw = base().as_bytes() + b"X-Uuencoded: yes\r\n\r\nbegin 644 a.com\r\n" + b"".join(bytes([32 + len(EICAR[i:i + 45])]) + _uu(EICAR[i:i + 45]) + b"\r\n" for i in range(0, len(EICAR), 45)) + b"`\r\nend\r\n"
    container("eml_uuencoded", raw)
    # MIME in the ways mail clients are lenient about.
    for tag, body in (
        ("unclosed", b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.encodebytes(EICAR)),
        ("bad_base64", b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.encodebytes(EICAR).replace(b"A", b"A!", 1) + b"--b--\r\n"),
        ("no_boundary_quotes", b"Content-Type: multipart/mixed; boundary=\"a b\"\r\n\r\n--a b\r\nContent-Type: text/plain\r\n\r\nx\r\n--a b--\r\n"),
        ("folded_headers", b"Subject: a\r\n very\r\n long\r\nContent-Type: text/plain;\r\n charset=\"utf-8\"\r\n\r\nx\r\n"),
        ("encoded_words", b"Subject: =?UTF-8?B?w6nDqQ==?= =?ISO-8859-1?Q?=E9?=\r\n\r\nx\r\n"),
        ("rfc2231", b"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*0*=utf-8''a%20; filename*1=b.com\r\n\r\nx\r\n"),
        ("mbox", b"From a@example.org Fri Oct 30 10:00:00 2026\r\nSubject: x\r\n\r\nbody\r\n\r\nFrom b@example.org Fri Oct 30 10:00:01 2026\r\nSubject: y\r\n\r\nbody2\r\n"),
    ):
        container(f"eml_{tag}", body)
    # TNEF (winmail.dat): signature, key, then attribute records.
    container("tnef_empty", struct.pack("<IH", 0x223E9F78, 1) + bytes(10))


# --- signatures -----------------------------------------------------------

def signatures():
    r = random.Random(9)
    hexb = lambda n: "".join(f"{r.randrange(256):02x}" for _ in range(n))
    ndb, ldb, yar = [], [], []
    for i in range(60):
        parts = [hexb(r.randrange(2, 6))]
        for _ in range(r.randrange(0, 4)):
            parts.append(r.choice(["*", f"{{{r.randrange(1, 8)}}}", f"{{{r.randrange(0, 4)}-{r.randrange(4, 12)}}}", "??", "(" + hexb(2) + "|" + hexb(2) + ")",
                                   "(B)", "(L)", "!(" + hexb(1) + "|" + hexb(1) + ")", f"{hexb(1)[0]}?", f"?{hexb(1)[0]}"]))
            parts.append(hexb(r.randrange(2, 5)))
        tgt = r.choice([0, 1, 2, 3, 4, 5, 6, 7, 9, 10])
        off = r.choice(["*", "0", f"{r.randrange(100)}", "EOF-" + str(r.randrange(1, 50)), "EP+" + str(r.randrange(10)), "SL+" + str(r.randrange(10)), "S0+" + str(r.randrange(5)), f"{r.randrange(10)},{r.randrange(100)}"])
        ndb.append(f"Seed.N{i}:{tgt}:{off}:{''.join(parts)}")
        sub = [hexb(3), hexb(2) + "*" + hexb(2), "(" + hexb(2) + "|" + hexb(2) + ")" + hexb(1)]
        n = r.randrange(1, 4)
        logic = r.choice(["&", "|"]).join(str(k) for k in range(n))
        ldb.append(f"Seed.L{i};Target:{tgt};{logic};" + ";".join(sub[:n]))
    conditions = ["any of them", "all of them", "2 of ($a, $b, $c)", "$a at 0 or $b in (0..100)", "for any i in (1..#a) : (@a[i] < 100)",
                  "#a > 1 and filesize < 1MB", "uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x4550", "math.entropy(0, filesize) > 6",
                  'hash.md5(0, 8) == "00" or $c']
    for i in range(30):
        condition = r.choice(conditions)
        yar.append(f'''rule seed_{i} {{
  meta: a = "x{i}" n = {i}
  strings:
    $a = "{text_blob(1, i).decode()}" {r.choice(["", "nocase", "wide", "ascii wide", "fullword", "xor", "base64"])}
    $b = {{ {hexb(2)} [{r.randrange(1, 4)}-{r.randrange(4, 8)}] ({hexb(1)} | {hexb(1)}) {hexb(2)} }}
    $c = /ab[0-9]{{{r.randrange(1, 4)}}}c+/ {r.choice(["", "nocase"])}
  condition: {condition}
}}''')
    import_hdr = 'import "pe"\nimport "elf"\nimport "math"\nimport "hash"\nimport "dotnet"\nimport "string"\n'
    put("sigs", "ndb_gen", ("\n".join(ndb) + "\n").encode())
    put("ndb_compile", "ndb_gen", ("\n".join(ndb) + "\n").encode())
    put("sigs", "ldb_gen", ("\n".join(ldb) + "\n").encode())
    put("ndb_compile", "ldb_gen", ("\n".join(ldb) + "\n").encode())
    for i in range(0, len(ndb), 6):
        put("sigs", f"ndb_{i}", ("\n".join(ndb[i:i + 6]) + "\n").encode())
        put("ndb_compile", f"ndb_{i}", ("\n".join(ndb[i:i + 6]) + "\n").encode())
    # yara: [rule length u16 LE][rules][data].
    data = [b"MZ" + bytes(60) + struct.pack("<I", 64) + b"PE\0\0" + bytes(100), b"\x7fELF" + bytes(60), b"hello world MARKER ab12c abccc secret\n" * 3]
    for i in range(0, len(yar), 3):
        text = (import_hdr + "\n".join(yar[i:i + 3])).encode()[:4096]
        for k, d in enumerate(data):
            put("yara", f"rules_{i}_{k}", struct.pack("<H", len(text)) + text + d)
    # pcre: [flags: u8][pattern length u16 LE][pattern][haystack].
    pats = [r"a+b*c?", r"(?i)hello\s+world", r"[a-f0-9]{4,8}", r"(foo|bar)baz\b", r"^\x4d\x5a.{0,60}PE", r"(?<=a)b(?!c)", r"\d{3}-\d{4}",
            r"(a|b)*?c", r"[^\x00-\x1f]{5}", r"(?:ab){2,4}", r"\bword\b", r"a.{2,5}z", r"(?s)x.y", r"(\w+)@(\w+)\.com", r"\x00\x01.*\xff", r"(?x) a b c # comment"]
    for i, p in enumerate(pats):
        pb = p.encode()
        for f in (0, 1, 2, 5):
            put("pcre", f"p{i}_{f}", bytes([f]) + struct.pack("<H", len(pb)) + pb + b"hello world abbbc foo baz 123-4567 a@b.com abcabcabc xay\x00\x01zz\xff")


# --- text formats -------------------------------------------------------------

def text():
    r = random.Random(13)
    md = []
    for i in range(12):
        md.append("\n".join([
            f"# Heading {i}", "", f"Setext {i}", "=" * 8, "", "*em* **strong** `code` ~~gone~~ <b>html</b> &amp; &#x41;",
            "", "> quote", "> > nested", "", "1. one", "2. two", "   - sub", "", "| a | b |", "|:--|--:|", f"| {i} | 2 |", "",
            "```rust", "fn main() {}", "```", "", f"[link](http://example.org/{i} \"t\") ![img](x.png) <http://a.b/c> [ref][1]", "", "[1]: http://ref.example/",
            "", "- [ ] task", "- [x] done", "", "Term\n: definition", "", "---", "Footnote[^1]", "", "[^1]: note"]))
    for i, d in enumerate(md):
        put("markdown", f"md_{i}", d.encode())
        put("visible_text", f"md_{i}", b"\0" + d.encode())
    # HTML pages: tokenizer states, entities, tables, scripts.
    for i in range(10):
        h = (f"<!DOCTYPE html><html><head><title>t{i}</title><style>p{{color:red}}</style><meta charset='utf-8'></head><body>"
             f"<h1>h</h1><p class=a>text &amp; &lt; &#{65 + i}; &#x{41 + i:x}; &copy;<br><a href=\"javascript:alert({i})\">x</a> "
             f"<a href='https://www.paypal.com/'>http://evil.example/</a><img src='data:image/png;base64,{base64.b64encode(png_bytes(4, 4)).decode()}' alt='a'>"
             f"<table><tr><td colspan=2>a<td>b<tr><th>c</table><ul><li>1<li>2</ul><script>var a='<b>';</script><!-- c --><![CDATA[x]]></body></html>")
        put("docs_html", f"html_{i}", h.encode())
        put("visible_text", f"html_{i}", b"\1" + h.encode())
    # RTF.
    for i in range(8):
        rtf = (r"{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0 Times New Roman;}{\f1\fnil Arial;}}{\colortbl;\red255\green0\blue0;}"
               r"\viewkind4\uc1\pard\b Bold\b0 \i it\i0\par {\field{\*\fldinst HYPERLINK \"http://example.org/" + str(i) + r"\"}{\fldrslt link}}"
               r"\par \u233? \'e9 \tab \bullet {\pict\wmetafile8 0102030405}{\object\objemb{\*\objclass Package}{\objdata 0105000002000000}}"
               r"\trowd\cellx1000\cellx2000\intbl a\cell b\cell\row {\footnote note}{\header h}\par}")
        put("docs_rtf", f"rtf_{i}", rtf.encode())
        put("visible_text", f"rtf_{i}", bytes([14]) + rtf.encode())
    # Word 2003 XML and SpreadsheetML.
    wml = ('<?xml version="1.0"?><?mso-application progid="Word.Document"?><w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml" '
           'xmlns:wx="http://schemas.microsoft.com/office/word/2003/auxHint"><w:body><wx:sect><w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Title</w:t></w:r></w:p>'
           '<w:p><w:r><w:rPr><w:b/></w:rPr><w:t>bold</w:t></w:r><w:hlink w:dest="http://example.org"><w:r><w:t>link</w:t></w:r></w:hlink></w:p>'
           '<w:tbl><w:tr><w:tc><w:p><w:r><w:t>c</w:t></w:r></w:p></w:tc></w:tr></w:tbl></wx:sect></w:body></w:wordDocument>')
    put("docs_wml", "wml_1", wml.encode())
    put("docs_wml", "wml_1_utf16", b"\xff\xfe" + wml.encode("utf-16-le"))
    put("visible_text", "wml_1", bytes([15]) + wml.encode())
    sml = ('<?xml version="1.0"?><?mso-application progid="Excel.Sheet"?><Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" '
           'xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"><Styles><Style ss:ID="s1"><Font ss:Bold="1"/><Interior ss:Color="#FF0000" ss:Pattern="Solid"/></Style></Styles>'
           '<Worksheet ss:Name="S"><Table><Row><Cell ss:StyleID="s1"><Data ss:Type="String">a</Data></Cell><Cell><Data ss:Type="Number">1.5</Data></Cell>'
           '<Cell ss:Formula="=RC[-1]+1"><Data ss:Type="Number">2</Data></Cell><Cell ss:HRef="http://example.org"><Data ss:Type="String">l</Data></Cell></Row></Table></Worksheet></Workbook>')
    put("sheets_text", "sml_1", bytes([0]) + sml.encode())
    put("sheets_text", "html_1", bytes([1]) + b"<table><tr><td colspan=2 style='color:red'>a<td>b<tr><td rowspan=2>c<td>d</table>")
    put("sheets_text", "slk_1", bytes([2]) + b"ID;PWXL;N;E\nB;Y3;X3;D0 0 2 2\nC;Y1;X1;K\"a\"\nC;Y1;X2;K2.5\nC;Y2;X1;K3;E1+R[-1]C\nE\n")
    # XDP, XML, and the markup the unpackers read.
    for i in range(3):
        put("containers", f"xdp_{i}", ("<?xml version='1.0'?><xdp:xdp xmlns:xdp='http://ns.adobe.com/xdp/'><pdf xmlns='http://ns.adobe.com/xdp/pdf/'><document><chunk>"
                                      + base64.b64encode(b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF").decode() + "</chunk></document></pdf></xdp:xdp>").encode())
    # 3D: OBJ, PLY, STL, glTF variants.
    obj = "o x\n" + "".join(f"v {i} {i * 2 % 5} {i % 3}\n" for i in range(12)) + "vn 0 0 1\nvt 0 0\nusemtl m\n" + "".join(f"f {i}/1/1 {i + 1}/1/1 {i + 2}/1/1\n" for i in range(1, 10)) + "f 1 2 3 4 5\nf -3 -2 -1\ng grp\nl 1 2\n"
    put("mesh", "obj_1", obj.encode())
    put("mesh", "obj_neg_indices", b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf -1 -2 -3\n")
    stl_ascii = "solid s\n" + "".join(f"facet normal 0 0 1\n outer loop\n  vertex {i} 0 0\n  vertex {i + 1} 0 0\n  vertex {i} 1 0\n endloop\nendfacet\n" for i in range(4)) + "endsolid s\n"
    put("ifc", "stl_ascii", stl_ascii.encode())
    stl_bin = bytes(80) + struct.pack("<I", 4) + b"".join(struct.pack("<12fH", 0, 0, 1, i, 0, 0, i + 1, 0, 0, i, 1, 0, 0) for i in range(4))
    put("ifc", "stl_binary", stl_bin)
    put("mesh", "stl_binary", stl_bin)
    for order, tag in (("<", "little"), (">", "big")):
        head = f"ply\nformat binary_{tag}_endian 1.0\nelement vertex 4\nproperty float x\nproperty float y\nproperty float z\nproperty float nx\nproperty float ny\nproperty float nz\nproperty uchar red\nproperty uchar green\nproperty uchar blue\nelement face 2\nproperty list uchar uint vertex_indices\nend_header\n"
        body = b"".join(struct.pack(order + "6f3B", i, 0, 0, 0, 0, 1, i * 20, 5, 9) for i in range(4)) + struct.pack(order + "BIII", 3, 0, 1, 2) + struct.pack(order + "BIII", 3, 1, 2, 3)
        put("mesh", f"ply_{tag}", head.encode() + body)
    # IFC: a STEP file with the entity kinds the engine draws.
    ifc = ("ISO-10303-21;\nHEADER;\nFILE_DESCRIPTION(('ViewDefinition [CoordinationView]'),'2;1');\nFILE_NAME('a.ifc','2026-01-01T00:00:00',(''),(''),'','','');\n"
           "FILE_SCHEMA(('IFC4'));\nENDSEC;\nDATA;\n#1=IFCPROJECT('0',$,'P',$,$,$,$,$,$);\n#2=IFCCARTESIANPOINT((0.,0.,0.));\n"
           "#3=IFCAXIS2PLACEMENT3D(#2,$,$);\n#4=IFCLOCALPLACEMENT($,#3);\n#5=IFCCARTESIANPOINT((0.,0.));\n#6=IFCAXIS2PLACEMENT2D(#5,$);\n"
           "#7=IFCRECTANGLEPROFILEDEF(.AREA.,$,#6,2.,1.);\n#8=IFCDIRECTION((0.,0.,1.));\n#9=IFCEXTRUDEDAREASOLID(#7,#3,#8,3.);\n"
           "#10=IFCSHAPEREPRESENTATION($,'Body','SweptSolid',(#9));\n#11=IFCPRODUCTDEFINITIONSHAPE($,$,(#10));\n#12=IFCWALL('1',$,'W',$,$,#4,#11,$,$);\nENDSEC;\nEND-ISO-10303-21;\n")
    put("ifc", "ifc_wall", ifc.encode())
    for k, scale in enumerate(("0.001", "1000000.", "-3.", "1E300", "0.")):
        put("ifc", f"ifc_wall_s{k}", ifc.replace("2.,1.);", f"{scale},{scale});").encode())
    gl = {"asset": {"version": "2.0"}, "scene": 0, "scenes": [{"nodes": [0]}], "nodes": [{"mesh": 0}], "meshes": [{"primitives": [{"attributes": {"POSITION": 0}, "mode": m} for m in (0, 1, 3, 4, 5, 6)]}],
          "accessors": [{"bufferView": 0, "componentType": 5126, "count": 3, "type": "VEC3", "min": [0, 0, 0], "max": [1, 1, 0]}],
          "bufferViews": [{"buffer": 0, "byteLength": 36}], "buffers": [{"byteLength": 36, "uri": "data:application/octet-stream;base64," + base64.b64encode(struct.pack("<9f", 0, 0, 0, 1, 0, 0, 0, 1, 0)).decode()}]}
    import json
    put("mesh", "gltf_modes", json.dumps(gl).encode())


AREA_FUNCS = {
    "archives": archives, "filesystems": filesystems, "disks": disks, "documents": documents, "images": images,
    "pdf": pdf, "drawings": drawings, "mail": mail, "signatures": signatures, "text": text,
}

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    # The pieces that others read (the small source tree the disks are made from)
    # come first.
    order = [a for a in ("archives", "filesystems", "disks", "documents", "images", "pdf", "drawings", "mail", "signatures", "text") if a in AREAS]
    for area in order:
        try:
            AREA_FUNCS[area]()
        except Exception as e:
            import traceback
            note(f"{area}: {type(e).__name__}: {e}")
            traceback.print_exc()
    shutil.rmtree(TMP, ignore_errors=True)
    for t in sorted(COUNT):
        print(f"gen {t}: {COUNT[t]}")
