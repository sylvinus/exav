#!/usr/bin/env python3
"""Write a UDF 2.50 image whose tree lives in a Metadata Partition.

No tool at hand writes one: mkudffs 2.3 only offers 2.50 on BD-R, with a VAT,
and pycdlib writes type-1 partition maps only. So this writer follows ECMA-167
and OSTA UDF 2.50 directly, and it is independent of exav: check its output with
the Linux kernel before trusting it, as metadata.iso.gz was:

    python3 make_metadata_iso.py README BIG PAYLOAD out.iso
    sudo mount -o loop,ro -t udf out.iso /mnt && sha256sum $(find /mnt -type f)

README, BIG and PAYLOAD are the three files of udf_only.iso.gz (`7zz x`). The
kernel reads them back with the same digests, and falls back to the mirror when
the metadata file's entry (sector 257) is blanked. The fixture is out.iso
gzipped and masked (see ../README.md).

Layout: a type-1 map for partition 0 and a metadata map over it. The metadata
file is split over two extents and mirrored. Directories and file entries are
in the metadata partition, directory data reached through short_ads (which
resolve in the partition of the entry holding them). readme.txt is stored in
its own entry; nested/big.bin and nested/deeper/payload.zip are in the physical
partition, reached through long_ads, big.bin over two extents.
"""
import struct
import sys

SECTOR = 2048
PART_START = 257  # physical partition 0 starts after the anchor
UDF_REV = 0x0250


def crc_itu(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def tag(ident, body, location):
    """A descriptor: 16-byte tag over `body` (the bytes after the tag)."""
    head = struct.pack("<HHBBHHHI", ident, 3, 0, 0, 1, crc_itu(body), len(body), location)
    checksum = (sum(head[0:4]) + sum(head[5:16])) & 0xFF
    return head[:4] + bytes([checksum]) + head[5:] + body


def regid(ident, suffix=b""):
    return b"\0" + ident.ljust(23, b"\0") + suffix.ljust(8, b"\0")


def udf_suffix():
    return struct.pack("<H", UDF_REV)


def charspec():
    return b"\0" + b"OSTA Compressed Unicode".ljust(63, b"\0")


def dstring(text, size):
    raw = b"\x08" + text
    return raw.ljust(size - 1, b"\0") + bytes([len(raw)])


def long_ad(length, lbn, part):
    return struct.pack("<IIH", length, lbn, part) + b"\0" * 6


def short_ad(length, pos):
    return struct.pack("<II", length, pos)


def icbtag(file_type, ad_kind):
    return struct.pack("<IHHHBB", 0, 4, 0, 1, 0, file_type) + b"\0" * 6 + struct.pack("<H", ad_kind)


def file_entry(location, file_type, ad_kind, info_len, ads, unique):
    """An ECMA-167 File Entry (tag 261)."""
    body = icbtag(file_type, ad_kind)
    body += struct.pack("<IIIHBBI", 0, 0, 0x1FF, 1, 0, 0, 0)
    body += struct.pack("<QQ", info_len, (info_len + SECTOR - 1) // SECTOR)
    body += b"\0" * 36  # access, modification, attribute times
    body += struct.pack("<I", 1) + b"\0" * 16  # checkpoint, EA ICB
    body += regid(b"*exav test") + struct.pack("<Q", unique)
    body += struct.pack("<II", 0, len(ads)) + ads
    return tag(261, body, location)


def extended_file_entry(location, file_type, ad_kind, info_len, ads, unique):
    """An Extended File Entry (tag 266), as UDF 2.00 and later also allow."""
    body = icbtag(file_type, ad_kind)
    body += struct.pack("<IIIHBBI", 0, 0, 0x1FF, 1, 0, 0, 0)
    body += struct.pack("<QQQ", info_len, info_len, (info_len + SECTOR - 1) // SECTOR)
    body += b"\0" * 48  # access, modification, creation, attribute times
    body += struct.pack("<II", 1, 0) + b"\0" * 32  # checkpoint, EA ICB, stream ICB
    body += regid(b"*exav test") + struct.pack("<Q", unique)
    body += struct.pack("<II", 0, len(ads)) + ads
    return tag(266, body, location)


def fid(location, name, characteristics, icb_lbn, icb_part):
    ident = (b"\x08" + name) if name else b""
    body = struct.pack("<HBB", 1, characteristics, len(ident))
    body += long_ad(SECTOR, icb_lbn, icb_part) + struct.pack("<H", 0) + ident
    # The CRC covers the padding to a four-byte boundary too.
    return tag(257, body.ljust((16 + len(body) + 3) // 4 * 4 - 16, b"\0"), location)


def directory(location, parent_lbn, children):
    out = fid(location, b"", 0x0A, parent_lbn, 1)
    for name, is_dir, lbn in children:
        out += fid(location, name, 0x02 if is_dir else 0, lbn, 1)
    return out


def main(readme_path, big_path, payload_path, out_path):
    readme = open(readme_path, "rb").read()
    big = open(big_path, "rb").read()
    payload = open(payload_path, "rb").read()

    # Metadata partition blocks.
    M_FSD, M_ROOT, M_ROOT_DATA, M_README = 0, 1, 2, 3
    M_NESTED, M_NESTED_DATA, M_BIG, M_DEEPER, M_DEEPER_DATA, M_PAYLOAD = 4, 5, 6, 7, 8, 9
    meta_blocks = 10
    meta = [b""] * meta_blocks
    meta[M_FSD] = tag(
        256,
        b"\0" * 12 + struct.pack("<HHIIII", 3, 3, 1, 1, 0, 0) + charspec()
        + dstring(b"TEST", 128) + charspec() + dstring(b"TEST", 32)
        + b"\0" * 64 + long_ad(SECTOR, M_ROOT, 1)
        + regid(b"*OSTA UDF Compliant", udf_suffix()) + b"\0" * 64,
        M_FSD,
    )

    # Physical partition blocks: the metadata file's two extents, its mirror,
    # then file data, big.bin in two pieces with a gap between them.
    P_MAIN_FE, P_MIRROR_FE = 0, 1
    P_META_A, META_A = 2, 6  # metadata blocks 0..5
    P_META_B = 12            # metadata blocks 6..9
    P_MIRROR = 20            # all ten, contiguous
    P_PAYLOAD = 32
    P_BIG_A, BIG_A = 40, 3 * SECTOR
    P_BIG_B = 50
    part_blocks = 64

    def dir_entry(location, data_block, data, unique):
        # A directory is as long as its identifiers, not its block.
        return file_entry(location, 4, 0, len(data), short_ad(len(data), data_block), unique)

    meta[M_ROOT_DATA] = directory(M_ROOT_DATA, M_ROOT, [(b"readme.txt", False, M_README), (b"nested", True, M_NESTED)])
    meta[M_ROOT] = dir_entry(M_ROOT, M_ROOT_DATA, meta[M_ROOT_DATA], 0)
    meta[M_README] = file_entry(M_README, 5, 3, len(readme), readme, 16)
    meta[M_NESTED_DATA] = directory(M_NESTED_DATA, M_ROOT, [(b"big.bin", False, M_BIG), (b"deeper", True, M_DEEPER)])
    meta[M_NESTED] = dir_entry(M_NESTED, M_NESTED_DATA, meta[M_NESTED_DATA], 17)
    meta[M_BIG] = extended_file_entry(
        M_BIG, 5, 1, len(big),
        long_ad(BIG_A, P_BIG_A, 0) + long_ad(len(big) - BIG_A, P_BIG_B, 0), 18,
    )
    meta[M_DEEPER_DATA] = directory(M_DEEPER_DATA, M_NESTED, [(b"payload.zip", False, M_PAYLOAD)])
    meta[M_DEEPER] = dir_entry(M_DEEPER, M_DEEPER_DATA, meta[M_DEEPER_DATA], 19)
    meta[M_PAYLOAD] = file_entry(M_PAYLOAD, 5, 1, len(payload), long_ad(len(payload), P_PAYLOAD, 0), 20)
    meta_bytes = b"".join(b.ljust(SECTOR, b"\0") for b in meta)

    part = bytearray(part_blocks * SECTOR)

    def put(block, data):
        part[block * SECTOR:block * SECTOR + len(data)] = data

    meta_len = meta_blocks * SECTOR
    put(P_MAIN_FE, extended_file_entry(
        P_MAIN_FE, 250, 0, meta_len,
        short_ad(META_A * SECTOR, P_META_A) + short_ad(meta_len - META_A * SECTOR, P_META_B), 0,
    ))
    put(P_MIRROR_FE, extended_file_entry(P_MIRROR_FE, 251, 0, meta_len, short_ad(meta_len, P_MIRROR), 0))
    put(P_META_A, meta_bytes[:META_A * SECTOR])
    put(P_META_B, meta_bytes[META_A * SECTOR:])
    put(P_MIRROR, meta_bytes)
    put(P_PAYLOAD, payload)
    put(P_BIG_A, big[:BIG_A])
    put(P_BIG_B, big[BIG_A:])

    total = PART_START + part_blocks + 1
    img = bytearray(total * SECTOR)

    def sector(n, data):
        img[n * SECTOR:n * SECTOR + len(data)] = data

    for i, ident in enumerate([b"BEA01", b"NSR03", b"TEA01"]):
        sector(16 + i, b"\0" + ident + b"\x01")

    MVDS, LVID = 32, 48
    sector(MVDS, tag(1, struct.pack("<II", 0, 0) + dstring(b"TEST", 32) + struct.pack("<HHHHII", 1, 1, 2, 2, 1, 1)
                     + dstring(b"TEST", 128) + charspec() + charspec() + b"\0" * 16 + regid(b"*exav test")
                     + b"\0" * 12 + regid(b"*exav test") + b"\0" * 92, MVDS))
    sector(MVDS + 1, tag(4, struct.pack("<I", 1) + regid(b"*UDF LV Info", udf_suffix()) + b"\0" * 460, MVDS + 1))
    sector(MVDS + 2, tag(5, struct.pack("<IHH", 2, 1, 0) + regid(b"+NSR03") + b"\0" * 128
                         + struct.pack("<III", 1, PART_START, part_blocks) + regid(b"*exav test") + b"\0" * 284, MVDS + 2))
    type1 = struct.pack("<BBHH", 1, 6, 1, 0)
    type2 = (struct.pack("<BBH", 2, 64, 0) + regid(b"*UDF Metadata Partition", udf_suffix())
             + struct.pack("<HHIIIIHB", 1, 0, P_MAIN_FE, P_MIRROR_FE, 0xFFFFFFFF, 1, 1, 1) + b"\0" * 5)
    maps = type1 + type2
    sector(MVDS + 3, tag(6, struct.pack("<I", 3) + charspec() + dstring(b"TEST", 128) + struct.pack("<I", SECTOR)
                         + regid(b"*OSTA UDF Compliant", udf_suffix()) + long_ad(SECTOR, M_FSD, 1)
                         + struct.pack("<II", len(maps), 2) + regid(b"*exav test") + b"\0" * 128
                         + struct.pack("<II", SECTOR, LVID) + maps, MVDS + 3))
    sector(MVDS + 4, tag(7, struct.pack("<II", 4, 0), MVDS + 4))
    sector(MVDS + 5, tag(8, b"\0" * 496, MVDS + 5))

    lvid_use = regid(b"*exav test") + struct.pack("<IIHHH", 3, 3, UDF_REV, UDF_REV, UDF_REV)
    sector(LVID, tag(9, b"\0" * 12 + struct.pack("<I", 1) + b"\0" * 8 + struct.pack("<Q", 32) + b"\0" * 24
                     + struct.pack("<II", 2, len(lvid_use)) + struct.pack("<IIII", 0, 0, part_blocks, meta_blocks)
                     + lvid_use, LVID))
    sector(LVID + 1, tag(8, b"\0" * 496, LVID + 1))

    anchor = struct.pack("<IIII", 16 * SECTOR, MVDS, 16 * SECTOR, MVDS)
    sector(256, tag(2, anchor + b"\0" * 480, 256))
    img[PART_START * SECTOR:(PART_START + part_blocks) * SECTOR] = part
    sector(total - 1, tag(2, anchor + b"\0" * 480, total - 1))
    open(out_path, "wb").write(img)


if __name__ == "__main__":
    main(*sys.argv[1:5])
