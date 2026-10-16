#!/usr/bin/env python3
"""Small seeds written from what each fuzz target's source reads.

    scripts/fuzz-seeds-synth.py OUT      # adds OUT/<target>/synth_*

Run by scripts/fuzz-seeds.sh after the fixture seeds. Each block below says
which code the seeds are for and where in the source that code is, so that a
change to the input format of a target is a change to its block here. What the
seeds are worth is measured, not assumed: docs/FUZZING.md, "Synthesized seeds".
"""
import gzip
import io
import os
import struct
import sys
import tarfile

OUT = sys.argv[1]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)


def put(target, name, data):
    d = os.path.join(OUT, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "synth_" + name), "wb") as f:
        f.write(data)


def read(path, limit=65535):
    with open(path, "rb") as f:
        return f.read(limit)


DB = sorted(f for f in os.listdir("fuzz/db") if f.startswith("fuzz."))
# The antivirus test string, written backwards: this tree may not carry it
# (scripts/release.sh, crates/exav/tests/self_scan.rs).
EICAR = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X"[::-1].encode()

# --- sigs, ndb_compile, bytecode: signature text (fuzz_targets/sigs.rs,
# ndb_compile.rs, bytecode.rs). One file of each kind of fuzz/db/ whole, then
# its lines one at a time (a line is what a mutation most often breaks).
for name in DB:
    ext = name.rsplit(".", 1)[1]
    text = read("fuzz/db/" + name)
    if ext in ("ndb", "ldb", "db", "hdb", "hsb", "fdb", "imp", "mdb"):
        for t in ("sigs", "ndb_compile"):
            put(t, f"file_{ext}", text)
        for i, line in enumerate(text.splitlines()):
            put("ndb_compile", f"{ext}_line{i:02}", line + b"\n")
            put("sigs", f"{ext}_line{i:02}", line + b"\n")
    if ext == "cbc":
        put("bytecode", "write32", text)
        # Reader::number / data / fixed read raw bytes: the format's own
        # nibble encoding (0x60 + nibble), a number then a data run.
        put("bytecode", "numbers", b"a`b`cabc`d" + b"|ab`cdef")
        for i, line in enumerate(text.splitlines()):
            put("bytecode", f"line{i:02}", line + b"\n")

# --- parser_recursion: [depth: u16 LE][shape: u8][payload]
# (fuzz_targets/parser_recursion.rs): shape 0 and 1 nest PDF arrays and
# dictionaries, 2 wraps them in a PDF, 3 nests XML for XDP.
payloads = [b"1 0 R", b"/Type /Page", b"x", b"(a) <00> 1.5 true null"]
for shape in range(4):
    for depth in (0, 1, 2, 3, 8, 64, 400, 5000):
        for i, p in enumerate(payloads[:2] if shape < 2 else payloads[2:3]):
            put("parser_recursion", f"s{shape}_d{depth}_{i}", struct.pack("<HB", depth, shape) + p)

# --- rar3_ppmd: [unpacked size: u64 LE][window bits - 10, mod 15: u32 LE][packed]
# (fuzz_targets/rar3_ppmd.rs). The packed bytes of the RAR4 fixtures that use
# PPMd, and noise, at three sizes and window widths.
packed = [read(f"crates/exav-unpack/tests/fixtures/rar4/{n}", 4096) for n in ("solid_ppmd.rar", "two_windows.rar", "solid_x86.rar")]
packed += [bytes(range(256)) * 4, b"\x00" * 64, b"\xff" * 64]
for i, p in enumerate(packed):
    for unp, win in ((16, 0), (1000, 7), (65536, 14)):
        put("rar3_ppmd", f"p{i}_{unp}_{win}", struct.pack("<QI", unp, win) + p)

# --- x86_decode: the bytes of one instruction (fuzz_targets/x86_decode.rs
# decodes at most 15 and compares with iced). Encodings by the features the
# decoder branches on: ModRM modes, SIB, displacement widths, prefixes, the 0F
# and 0F38/0F3A maps, x87, SSE, VEX and EVEX, and the length limit.
INSNS = """
90 c3 cc 55 5d 89e5 8b4508 8b4d0c 83ec10 83c410 31c0 29d8 01d8 f7e3 f7f1 0fafc3
0fb6c0 0fbe00 0fb7c1 0fbfc1 e812345678 e912345678 eb05 7405 0f8412345678 ff15 12345678
ff2485 12345678 ff7508 ffe0 ffd0 6a00 68 12345678 b8 12345678 c745fc01000000 8d0485 00000000
8d4c2404 8b0424 8b448804 8b848800010000 668b4508 678b00 f3a5 f2ae a4 aa 0f1f4400 00
660f1f440000 cd80 0fa2 0f31 f00fb10a 0fc70e 0fc70f d9ee dd45f8 d8c1 d9c9 df e0 9b 0f28c1
660f6f00 f30f104508 f20f1000 0f1100 c5f877 c5fc28c1 c4e17c28c1 62f17c4828c1 62f1fd4810c1
0f01d0 f30f1efb 8ed8 c8100000 c20800 0f38 00c1 0f3a0fc108 660f3a63c10a 0f0b 0fbae005 0fa4c104
0fc8 0f1808 8f00 c60000 86e0 87d8 f6c101 f7c101000000 80f805 81f8 00010000 83f8ff 3c41 3d 00010000
a1 00000000 a3 00000000 8a05 00000000 c3 cb ca0800 e2fe e3fe 0f9fc0 0f4fc1 0f95 c0 69c01000 0000
6bc010 c1e004 d1e0 d3e0 0fa5c1 0fadc1 f4 fa fb 0f06 0f09 9c 9d 60 61 c9 c8 0000 00 e8 ff ff ff ff
2e 3e 26 36 64 65 66 67 f0 f2 f3 6666666666666666666690 2e2e2e2e2e2e2e2e2e2e2e2e2e90
66670f1f840000000000 f0f0f0f0f0f0f0f0f0f0f0f0f0f090 0f0f c0 0f0fc10c 0fb8c1 f30fb8c1 f30fbcc1
0f38f0 00 0f38f1 00 660f3817 c1 0fc4c10a 0fc5c10a 660fd6 00 f30f7e00 0f0d08 0f0d00 0f2a c1
f20f2ac1 f30f2cc1 0f5ac1 660f5bc1 0f12 c1 0f16c1 0fc6c108 0fc2c101 660f70c108 0f71d008 0f73f80
"""
for i, tok in enumerate(INSNS.split()):
    try:
        put("x86_decode", f"insn{i:03}", bytes.fromhex(tok))
    except ValueError:
        pass
# Joined tokens: the encodings above split by whitespace for readability.
for i, line in enumerate(INSNS.strip().splitlines()):
    try:
        put("x86_decode", f"line{i:02}", bytes.fromhex(line.replace(" ", ""))[:15])
    except ValueError:
        pass


# --- pe_emulator: a PE the emulator runs (fuzz_targets/pe_emulator.rs; the
# loader is exav-pe-emu's image.rs: sections mapped at their RVAs, entry at
# AddressOfEntryPoint). A minimal PE32 with one section of code, in the shapes
# packers' stubs take: a decrypt loop, pushad/popad around it, a call-pop, a
# jump to a computed address, writes into its own section.
def pe32(code, entry=0x1000, imports=b""):
    sect = code.ljust(0x200, b"\x90")
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 0, 0, 0x200, 0, 0, entry, 0x1000, 0x1000,
                      0x400000, 0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0, 0x2000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\x00" * (0xE0 - len(opt))
    sec = struct.pack("<8sIIIIIIHHI", b".text", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0xE0000020)
    hdr = (dos + b"PE\x00\x00" + coff + opt + sec).ljust(0x200, b"\x00")
    return hdr + sect


STUBS = {
    "nop_ret": b"\x90\x90\xc3",
    "xor_loop": bytes.fromhex("b900010000 be00104000 8036 5a 46 e2f9 c3".replace(" ", "")),
    "pushad_popad": bytes.fromhex("60 e800000000 5d 81ed 06104000 b905000000 8d7500 ac 34aa e2fb 61 c3".replace(" ", "")),
    "jmp_reg": bytes.fromhex("b8 10104000 ffe0 90 90 90 90 90 90 90 90 90 90 90 90 c3".replace(" ", "")),
    "self_write": bytes.fromhex("c6 05 20104000 90 c6 05 21104000 c3 eb 00 90 c3".replace(" ", "")),
    "rep_movs": bytes.fromhex("be00104000 bf00114000 b940000000 f3a5 c3".replace(" ", "")),
    "call_ret": bytes.fromhex("e8 01000000 c3 c3".replace(" ", "")),
    "stack": bytes.fromhex("6a01 6a02 5b 59 01cb 53 58 c3".replace(" ", "")),
    "int3": b"\xcc",
    "bad": b"\x0f\x0b",
    "loop_forever": bytes.fromhex("eb fe".replace(" ", "")),
    "fs_access": bytes.fromhex("64 a1 30000000 8b40 0c c3".replace(" ", "")),
}
for name, code in STUBS.items():
    # `pe_emulator` reads `pe` (a link, see fuzz-seeds.sh).
    put("pe", name, pe32(code))

# --- cvd: the signature container (fuzz_targets/cvd.rs, exav-core cvd.rs): a
# 512-byte `ClamAV-VDB:` header then a gzip'd tar (.cvd) or a raw tar (.cld).
# Each file of fuzz/db/ alone, so the loader's route for each extension is a
# seed of its own; and the header's variants.
HEAD = b"ClamAV-VDB:01 Jan 2026 00-00 +0000:%d:%d:90:" + b"0" * 32 + b":dsig:exav-fuzz:1700000000"


def tar_of(names):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for n in names:
            t.add("fuzz/db/" + n, arcname=n)
    return buf.getvalue()


for n in DB:
    ext = n.rsplit(".", 1)[1]
    t = tar_of([n])
    put("cvd", f"cvd_{ext}", (HEAD % (1, 1)).ljust(512, b" ") + gzip.compress(t))
    put("cvd", f"cld_{ext}", (HEAD % (1, 1)).ljust(512, b" ") + t)
put("cvd", "header_only", (HEAD % (1, 1)).ljust(512, b" "))
put("cvd", "empty_gzip", (HEAD % (1, 1)).ljust(512, b" ") + gzip.compress(b""))
put("cvd", "wide_header", b"ClamAV-VDB:" + b":".join([b"x"] * 9) + b" " * 460)

# --- full_pipeline and analyze: the options half of the input
# (fuzz/options.rs). The smallest fixtures under bit patterns that turn on
# each alert, the structured-data and phishing checks, the block cache, the
# production bounds; full_pipeline behind its zero header, analyze with the
# bits as its last two bytes.
small = sorted((f for f in os.listdir(os.path.join(OUT, "containers")) if os.path.getsize(os.path.join(OUT, "containers", f)) < 3000),
               key=lambda f: os.path.getsize(os.path.join(OUT, "containers", f)))[:24]
extra = [("eicar", EICAR), ("text", b"hello world MARKER secret\nhttp://paypal.com.evil.example/login\n4111111111111111 078-05-1120\n")]
bodies = [(f, read(os.path.join(OUT, "containers", f))) for f in small] + extra
for bits in (0x00FF, 0x0FFF, 0x2001, 0xE0FF, 0xFFFF, 0x8001):
    for n, b in bodies:
        put("full_pipeline", f"bits{bits:04x}_{n}", struct.pack("<HB", bits, 0) + b)
        # `analyze` reads `containers` (a link, see fuzz-seeds.sh).
        put("containers", f"bits{bits:04x}_{n}", b + struct.pack("<H", bits))
for fail in (1, 64, 255):
    for n, b in bodies[:12]:
        put("seekable", f"fail{fail}_{n}", struct.pack("<HBB", 0xE0FF, 8, fail) + b)
        put("seekable", f"piece1_fail{fail}_{n}", struct.pack("<HBB", 0x2000, 0, fail) + b[:2048])

# --- authenticode: a signed PE (exav-core authenticode/mod.rs analyze_pe walks
# the certificate table); the fixture with each byte of its signature region
# left alone is the seed, so copies with the digest algorithm, table length
# and PKCS#7 length fields at their ends are what the mutator should reach.
signed = read("crates/exav-core/tests/fixtures/authenticode/signed_mismatch.exe")
for i, delta in enumerate((0, 1, 8, 64)):
    put("authenticode", f"trunc{i}", signed[: len(signed) - delta])
put("authenticode", "doubled", signed + signed[-256:])

# --- vdisk: [format: u8][image] (fuzz_targets/vdisk.rs; FORMATS: 4 NTFS, 5 FAT,
# 6 partition table; 7 and more try every format). The filesystem fixtures are gzipped
# images of mostly zeros, so what a volume walk reads first is cut out: a FAT
# image up to its last used byte, and the NTFS image up to the end of the
# first run of `$MFT` (84 KiB, over the target's buffer limit, so it is walked
# in place); each alone and as the partition of an MBR and of a GPT disk.
# What is past the cut reads as missing.
def unmask_gunzip(path):
    raw = read(path, 1 << 30)
    if path.endswith(".xor"):
        raw = bytes(b ^ 0x5A for b in raw)
    return gzip.decompress(raw)


FIXTURES = "crates/exav-unpack/tests/fixtures/"
fat = unmask_gunzip(FIXTURES + "fat/fragmented.img.gz.xor").rstrip(b"\0")
fat += b"\0" * (-len(fat) % 512)
ntfs = unmask_gunzip(FIXTURES + "ntfs/fragmented.img.gz.xor")[:86016]
for kind, volume in (("fat", fat), ("ntfs", ntfs)):
    mbr = bytearray(512)
    mbr[0x1BE : 0x1BE + 16] = struct.pack("<B3sB3sII", 0x80, b"\0\2\0", 0x0C if kind == "fat" else 0x07, b"\0\0\0", 1, len(volume) // 512)
    mbr[510:512] = b"\x55\xAA"
    gpt = bytearray(3 * 512)
    gpt[512:520] = b"EFI PART"
    struct.pack_into("<QII", gpt, 512 + 72, 2, 1, 128)
    gpt[1024] = 0xAB
    struct.pack_into("<QQ", gpt, 1024 + 32, 3, 2 + len(volume) // 512)
    put("vdisk", kind, bytes([4 if kind == "ntfs" else 5]) + volume)
    put("vdisk", f"{kind}_in_mbr", bytes([6]) + bytes(mbr) + volume)
    put("vdisk", f"{kind}_in_gpt", bytes([6]) + bytes(gpt) + volume)
