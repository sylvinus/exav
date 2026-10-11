# A minimal PE32 with one 32x32 32-bit icon (RT_ICON 1) and its group
# (RT_GROUP_ICON 1), per the PE/COFF resource layout.
import struct

side = 32
pixels = bytearray()
for y in range(side):
    for x in range(side):
        # A diagonal split: blue above, orange below, opaque.
        b, g, r = (220, 80, 20) if x > y else (20, 140, 240)
        pixels += bytes([b, g, r, 255])
and_mask = bytes(4 * side)
dib = struct.pack("<IiiHHIIiiII", 40, side, side * 2, 1, 32, 0, len(pixels) + len(and_mask), 0, 0, 0, 0)
dib += pixels + and_mask
group = struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHIH", side, side, 0, 0, 1, 32, len(dib), 1)

RSRC_RVA = 0x2000


def dir_(entries):
    return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(entries))


# Layout: root (types), two ID dirs, two language dirs, two data entries, data.
type_off = [16 + 8 * 2, 16 + 8 * 2 + 24]
lang_off = [type_off[1] + 24, type_off[1] + 48]
data_off = [lang_off[1] + 24, lang_off[1] + 24 + 16]
blob_off = data_off[1] + 16
icon_at = blob_off
group_at = (icon_at + len(dib) + 7) & ~7

r = bytearray()
r += dir_([1, 2]) + struct.pack("<II", 3, 0x80000000 | type_off[0]) + struct.pack("<II", 14, 0x80000000 | type_off[1])
for i in range(2):
    r += dir_([1]) + struct.pack("<II", 1, 0x80000000 | lang_off[i])
for i in range(2):
    r += dir_([1]) + struct.pack("<II", 0x409, data_off[i])
assert len(r) == lang_off[1] + 24
r += struct.pack("<IIII", RSRC_RVA + icon_at, len(dib), 0, 0)
r += struct.pack("<IIII", RSRC_RVA + group_at, len(group), 0, 0)
r += dib
r += bytes(group_at - len(r)) + group
rsrc = bytes(r) + bytes((-len(r)) % 0x200)

text = b"\xc3" + bytes(0x1ff)  # ret
e = 0x40
hdr = bytearray(0x200)
hdr[0:2] = b"MZ"
struct.pack_into("<I", hdr, 0x3C, e)
hdr[e:e + 4] = b"PE\0\0"
struct.pack_into("<HHIIIHH", hdr, e + 4, 0x14C, 2, 0, 0, 0, 0xE0, 0x102)
opt = e + 24
size_of_image = RSRC_RVA + ((len(rsrc) + 0xFFF) & ~0xFFF)
struct.pack_into("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", hdr, opt,
                 0x10B, 1, 0, 0x200, len(rsrc), 0, 0x1000, 0x1000, RSRC_RVA, 0x400000,
                 0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0, size_of_image, 0x200, 0, 2, 0,
                 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
dd = opt + 96
struct.pack_into("<II", hdr, dd + 2 * 8, RSRC_RVA, len(r))
sec = opt + 0xE0
struct.pack_into("<8sIIIIIIHHI", hdr, sec, b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
struct.pack_into("<8sIIIIIIHHI", hdr, sec + 40, b".rsrc", len(r), RSRC_RVA, len(rsrc), 0x400, 0, 0, 0, 0, 0x40000040)
open("icon.exe", "wb").write(bytes(hdr) + text + rsrc)
