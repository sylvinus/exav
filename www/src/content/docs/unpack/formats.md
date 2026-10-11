---
title: Supported formats
description: The archive, container, document, and executable-packer formats exav-unpack opens, their codecs and encryption schemes, and what is detected but not yet decoded.
---

exav-unpack opens archives, disk images, structured documents and packed
executables, recursively, in pure Rust and under the decompression-bomb
budget. Content it recognises but cannot fully decode comes back as a member
with `unsupported` set and the reason, through the
[crate](/unpack/rust/), the [command](/unpack/cli/) and
[`@exav/unpack-wasm`](/unpack/wasm/) alike. What the scanner does with each
format, and how it reports such content, is on the scanner's
[Supported formats](/scanner/reference/formats/) page.

Each format is a Cargo feature; see [the crate's features](/unpack/rust/#features)
to build a subset.

## Archives

| Format | Notes |
|---|---|
| ZIP | Every common method (see [codecs](#codec-level-coverage)) and [decryption](#encryption-support); orphan local headers and deferred-size members are carved too |
| gzip · bzip2 · xz · zstd · lzip · `.Z` (LZW) · LZ4 | Streaming decompressors: a member is decoded as it is read, at any size. Concatenated streams and frames are followed for all of them |
| ARC (SEA ARC / PKARC / PAK) | the pre-ZIP archiver; a member failing its CRC-16 after a full decode is still returned, as in ZIP |
| tar | POSIX/GNU |
| 7z | Every common coder (see [codecs](#codec-level-coverage)) and AES-256 [decryption](#encryption-support) |
| CAB · CHM | Microsoft cabinet / help (ITSF + LZX) |
| RAR | RAR3 and RAR5, including solid archives; a member failing its CRC after a full decode is still returned, as in ZIP (see [codecs](#codec-level-coverage)) |
| ARJ · LHA | classic archivers |
| ALZ · EGG | ESTsoft's Korean archivers: ALZ stored, deflate and bzip2 members; EGG stored, deflate, bzip2, LZMA and AZO members (a block failing its CRC after a full decode is still returned, as in ZIP) |
| InstallShield `.z` | the older installer archive (PKWARE DCL implode) |
| ISO · UDF | CD/DVD/Blu-ray images: the ISO 9660 tree (with Joliet) and the UDF tree, including UDF-only images with no ISO 9660 descriptor. A bridge image carrying both is walked once per file |
| `ar` (.deb / .a) · cpio (RPM) · xar (.pkg) | Unix and package archives |
| DMG | Apple UDIF, including [encrypted](#encryption-support), with HFS+/APFS extraction; recognised by its trailer when its data opens with a bzip2 or xz run |
| FAT12/16/32 | files inside a disk image, with their paths, reassembled from the cluster chain, so a fragmented file comes back whole |
| ext2/3/4 | files inside a Linux disk image, with their paths, reassembled from the inode's extent tree or block map. Symlinks and device nodes hold no bytes and are skipped |
| ZOO | Rahul Dhesi's 1986 archiver, both codecs (LZD, a 13-bit LZW, and LZH). A member failing its CRC-16 is still returned, as in ZIP. Deleted members are extracted too: ZOO flags them and leaves the bytes in place |
| NTFS | files inside a disk image, walked through the MFT: reassembled from their data runs (including across `$ATTRIBUTE_LIST`), read in place when resident, LZNT1-decompressed when compressed. Data runs short of the declared size are reported. The MFT walk also surfaces deleted-but-resident records a directory walk cannot see |
| WIM (`.wim`/`.esd`) | Windows imaging format: file resources with their paths, uncompressed, XPRESS or LZX. A resource failing its SHA-1 after a full decode is still returned, as in ZIP; LZMS resources are reported |
| VHD · VHDX · QCOW2 · VMDK | virtual disks, reconstructed to the guest disk, then opened in turn: VHD fixed and dynamic, VHDX through its block allocation table, QCOW2 including deflate-compressed clusters, VMDK sparse and streamOptimized (the shape inside an OVA). Delta images against a parent (differencing VHD/VHDX, QCOW2 with a backing file) are reported, not skipped |

ALZ and EGG matter for Korean-language targets, where ALZip is common, and so
does HWP3 (under [Documents](#documents--email)), the Korean government's
standard document format and a recurring spear-phishing carrier:

- **ALZ** is cross-checked field by field against `unalz` (zlib-licensed) and
  `unar`.
- **EGG** is written from ESTsoft's published *EGG Format Specification v1.0*;
  every block's CRC-32 validates the decoder. AZO, ESTsoft's own codec, is not in
  the specification: exav's decoder is a port of `EggDotNet` (MIT, credited in
  `NOTICE`), the one permissively licensed implementation.
- **HWP3** preamble offsets come from `java-hwp` (Apache-2.0, credited in
  `NOTICE`), validated against a document Hangul Word Processor wrote.

## Size: what is read as it goes, and what is read whole

The bound on what is held in memory at once is `Limits::max_buffer_bytes`
(256 MiB by default; `--max-memory` on the command, 1 GiB).

These are decoded as they are read, at any size, and their members come out as
a `Member::Stream`: ZIP, tar, CAB, ISO/UDF, LHA, `ar`, cpio, TNEF, OneNote,
SWF, SZDD, partition maps, self-extracting executables, universal Mach-O,
`.pyc`, and the single-stream compressors above. The exceptions: ZIP Shrink,
Reduce and Implode members, and encrypted ZIP members, are decoded whole under
that bound.

A DMG is walked at any size, but each file in it is held whole, under the
bound; an encrypted DMG is decrypted whole under the same bound. Only data
forks are read. A file macOS compressed (decmpfs) keeps its bytes in an
attribute or its resource fork instead: on HFS+, a file with a resource fork
is reported unsupported; on APFS, and for small HFS+ files compressed into the
attribute alone, such a file reads as empty.

Every other format is read whole: a container larger than the bound is a
`LimitHit` and its members are not reached. That includes RAR, OLE, PDF, CHM,
ARJ, xar, email, WIM, and the virtual disks and filesystems (VHD, VHDX, QCOW2,
VMDK, FAT, NTFS, ext), which are often larger than that: raise the bound where
such images are expected. 7z is read whole too, but its members stream out of
it. The scanner's own bounds for the same formats are on its
[Supported formats](/scanner/reference/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole)
page.

## The complete gap list

Every container or codec exav-unpack does not decode. If something is not
here, it opens it.

### Recognised and reported

exav-unpack opens these far enough to know what they are, then reports them
unsupported (encrypted, for the last two): the caller learns the members went
unexamined, rather than getting the compressed bytes as if they were content.

| Format / codec | Why it is open |
|---|---|
| ACE | No encoder exists to validate a decoder against, and the one sample obtainable is rejected as invalid by both `lsar` and `unace` |
| StuffIt / StuffIt X | Compression methods undocumented; the only implementations are closed-source or GPL |
| Inno Setup | The layout changes across setup-data versions; `innoextract` (zlib license) is the reference |
| InstallShield MSI | Sniffed by `"InstallShield\0"` plus a fixed record 292 bytes on; not opened yet |
| ZIP method 10 (DCL Implode) | No tool in print creates one, so a decoder could only be validated against found samples |
| ZIP methods 94 / 96 / 97 (MP3, JPEG, WavPack) | WinZip-only; no other extractor in the reference set reads them |
| WIM LZMS resources | Used by `.esd` images and `wimlib --solid` |
| RAR5 dictionaries over 64 MiB (including RAR 7's larger ones) | The decoder's window is capped at 64 MiB |
| RAR 1.5 / 2.x compression (unpack versions 15, 20, 26) | No permissively licensed decoder to port or check against; stored members of these archives are extracted |
| KWAJ LZSS, MSZIP and LZH methods | Stored and XOR-obfuscated KWAJ members are decoded |
| CHM multi-frame LZX intervals | Reported |
| 7z BCJ ARMT / PPC / SPARC / IA64 / RISC-V | Minor architectures |
| 7z Deflate64 / Zstandard coders | The Zstandard coder is a 7-Zip ZS fork extension |
| PKWARE Strong Encryption | Rare, proprietary; reported encrypted |
| CryptFF | Encrypted, which is what it is; reported encrypted |

They are listed because [an attacker picks a format by what the victim can open](/unpack/how-it-works/#the-parity-principle),
so they are gaps against 7-Zip, WinRAR and The Unarchiver. For ACE, StuffIt and
Inno the blocker is [validation](/unpack/how-it-works/#validating-a-decoder):
with no trustworthy implementation to check against, a subtly wrong decoder emits
plausible bytes rather than errors.

### Where recognition itself is the question

A format with no detection is the weaker failure: the file is passed on as
whatever it looks like and its members are never reached. Recognition is much
cheaper than decoding and removes that hole on its own:

| Format | exav-unpack | Sniff |
|---|---|---|
| InstallShield InstallScript cabinet | Recognised, reported | `ISc(` at 0 |
| InstallShield `.z` archive | **Decoded** | `13 5D 65 8C` at 0, confirmed against the header's own arithmetic (declared archive size, table-of-contents offset) |
| ext2/3/4 | **Decoded** | `0xEF53` at offset 1080; nothing at offset 0 identifies the image |
| ZOO | **Decoded** | tag `0xFDC4A7DC` at 20 plus a non-zero version byte at 32; the leading `ZOO ?.?? Archive.` text may be anything |
| AppleSingle / AppleDouble | Recognised, reported | `0x00051600` / `0x00051607` |
| lrzip | Recognised, reported | `LRZI` at 0 |

ext is walked as a filesystem rather than carved, for the same reason as FAT: a
file written into a hole lands in several extents. InstallShield `.z` is read
through the MIT `unshield` crate; the header check keeps four magic bytes alone
from reporting ordinary files as archives exav then could not open.

lrzip and the `ISc(` cabinet stay at recognition for licensing reasons. Neither
has a published specification: lrzip's long-range match stream is defined only
by its GPL source, and the only `ISc(` implementation is the LGPL `unshield` C
project (not the MIT crate of the same name). exav's clean-room rule forbids
reading either, and inferring an exact bitstream from black-box behaviour is not
something to claim. Reporting the format tells the caller there is a gap,
where a guessed decoder would produce plausible bytes and no sign of one.

Still unrecognised, each for a stated reason:

| Format | Why not |
|---|---|
| Compact Pro, DiskDoubler | No authoritative magic: `file`'s database does not carry them, and a guessed signature would report ordinary files as archives it cannot open |
| MacBinary | No magic at all, only a heuristic over header fields (a zero at 0, a length byte at 1, a CRC at 124), with a false-positive rate on arbitrary binaries |
| Wise installer | A PE carrying a marker string; the outer PE is passed on as it is |
| Brotli as a bare stream | A raw Brotli stream has no magic number; `.br` is identified by a `Content-Encoding` header a file on its own does not carry |

### Codec-level coverage

**ZIP**, reachable by every extractor in the reference set and both OS shells:

| Method | Name | exav |
|---|---|---|
| 0 | Store | yes |
| 1 | Shrink | yes |
| 2–5 | Reduce | yes |
| 6 | Implode | yes |
| 8 | Deflate | yes |
| 9 | Deflate64 | yes |
| 10 | PKWARE DCL Implode | **no** |
| 12 | bzip2 | yes |
| 14 | LZMA | yes |
| 93 | Zstandard | yes |
| 94 | MP3 | **no** |
| 95 | XZ | yes |
| 96 | JPEG | **no** |
| 97 | WavPack | **no** |
| 98 | PPMd | yes |

ZIP64, orphan local headers (dual indexing) and deferred-size members are
handled. Encryption is under [Encryption support](#encryption-support).

**7z:** Copy, LZMA, LZMA2, PPMd, BZip2, Deflate, AES-256 (including encrypted
headers), Delta, BCJ x86/ARM/ARM64 and BCJ2. BCJ2 is the only 7z coder with
several input streams, so the folder's bind-pair graph is resolved rather than
walked as a chain. Missing: the minor-architecture BCJ filters, and the Deflate64
and Zstandard coders.

**RAR:** RAR3 (LZ + PPMd) and RAR5 (LZ), including solid archives (the window,
Huffman tables and PPMd model carry across the group, and a member decoded
after one of the group that could not be is reported when its CRC disagrees),
the
standard filters RAR writes, encrypted members and headers,
and hard links and
file copies. Checked against official RAR 6.12 and 7.23 output across methods,
solid groups, filters, dictionary sizes, volumes, recovery records and
encryption. A member split across volumes is reported, since the rest of its
data is in a sibling file; the bytes of a split stored member that are present
are still returned. The command joins a volume set it is given
([`--volume`](/unpack/cli/#what-it-adds)).

**CAB / CHM:** MSZIP, LZX and Quantum; CHM is ITSF + LZX, with multi-frame LZX
intervals missing.

**Disk images:** ISO 9660 + Joliet, UDF, DMG (HFS+/APFS, LZFSE/LZVN, encrypted),
VHD, VHDX, QCOW2, VMDK, FAT12/16/32, NTFS and ext2/3/4. Images whose payload
lives in a parent file (differencing VHD/VHDX, QCOW2 with a backing file) are
reported rather than partially reconstructed.

### CAB Quantum

Quantum is an arithmetic coder over adaptive frequency models, shipped with
Office-97-era cabinets, and still reachable: 7-Zip decompresses Quantum cabinets
today. Microsoft published the cabinet container but never the Quantum
compressor, so exav's decoder was written from a functional specification and
validated against `cabextract`/libmspack as an oracle, never a source: byte-exact
on the reference cabinet, and on 107 generated streams across every window size
(10 to 21) with outputs up to 11 KB, with no disagreement. exav also rejects
matches that overshoot a frame or reach behind the start of a folder, which an
encoder cannot produce, so a corrupt stream does not turn into plausible output.

## PE packers

| State | Packers |
|---|---|
| **Unpacked, per format** | UPX, all methods: NRV2B/2D/2E (UCL), LZMA and DEFLATE, including the bare-`PackHeader` layout, decoded to the size the header records (a run matching its Adler-32 first), then rebuilt as a PE (a stripped or patched `PackHeader` falls back to running the stub); the aPLib family (Petite 2.x, FSG 2.0, NsPack), round-trip byte-exact |
| **Unpacked by running the stub** | ASPack, MEW, Upack, WWPack, PESpin, Yoda's Cryptor, and anything else that looks packed, under a bounded x86 interpreter that captures the image the stub rebuilds (the `pe-emu` feature). Measured coverage is on the [PE stub emulation](/scanner/concepts/pe-emulation/#measured-coverage) page |
| **Reported unsupported** | A file whose packer exav identified but could not unpack. A file sent to the emulator only because of its shape yields nothing if nothing comes out |
| **Reported, never unpacked** | VMProtect, Themida/WinLicense, Enigma: virtualizers, where no original code exists in memory to recover |

A per-packer decoder has to be written against a format the packer's author is
free to change; what no packer can avoid is that its stub rebuilds the original
image in memory and jumps to it. exav runs the stub in a sandbox with no syscalls
and no host memory, and takes the image at that jump. Nothing is emitted unless
it reads back as a valid PE. See [PE stub emulation](/scanner/concepts/pe-emulation/).

## Documents & email

| Format | What's extracted |
|---|---|
| OLE2 (legacy Office, MSI) | streams, VBA-macro decompression, Excel 4.0 (XLM) macros |
| OOXML | the modern Office ZIP container |
| PDF | object streams (FlateDecode, LZW, ASCII85, ASCIIHex, RunLength and filter chains), JavaScript, URI and launch-action harvesting; [decryption](#encryption-support) |
| HWP3 (Hangul Word Processor 3) | the deflate-compressed body |
| RTF | embedded hex objects |
| MIME email | decoded attachments and parts |
| TNEF (`winmail.dat`) · OneNote · Adobe XDP | embedded-file carriers |

## Executables

Packed executables are under [PE packers](#pe-packers). A Mach-O universal
("fat") binary is split per architecture.

## Other carriers

Formats that are not archives but still carry a payload:

| Carrier | What exav extracts |
|---|---|
| NSIS, SFX installers | the installer's packaged files |
| AutoIt (EA05, EA06) | the script, a compiled one as text in the form ClamAV writes it, and the files it installs |
| MS-SZDD / KWAJ | the original file from SZDD, and from KWAJ stored or XOR members (other KWAJ methods are reported) |
| BinHex, uuencode | the decoded binary |
| LNK | embedded command-line strings and target paths |
| Python `.pyc` | bytecode strings and constants |
| GPT / APM / MBR partition maps | the partitions, then each filesystem inside |
| Java `.class` | constant-pool strings |
| SWF (FWS / CWS / ZWS) | the decompressed Flash tag stream |
| HTML, Word/Excel 2003 flat XML | inline base64 assets (a `data:` URI image, a base64 element body), through `markup_embedded_payloads` rather than `walk` |
| AI models | Python pickle opcodes (surfaced, never executed) and the safetensors header |
| Microsoft Script Encoder | the plaintext of `#@~^`-encoded VBScript/JScript |
| AutoCAD DXF (ASCII and binary, R12 to 2018) | the object an OLE2FRAME embeds, which the file holds as hexadecimal (the compound file, then opened as OLE), and any other binary chunk that is a whole file of a known kind |
| AutoCAD DWG (R13, R14, 2000, 2004, 2007, 2010, 2013, 2018) | the preview images: the bitmap, which the file holds without the header of a BMP file, as a BMP file; a Windows metafile or PNG as it is. The object each OLE2FRAME embeds, as its compound file; a drawing whose objects cannot be read is reported as not fully examined, as is a drawing of a release before R13 (R12 and older) |

## Encryption support

exav-unpack decrypts these with the passwords it is given, then with the
built-in ones where the table names some:

| Container | Schemes decrypted | Tried besides the given passwords |
|---|---|---|
| ZIP | ZipCrypto, WinZip AES-128/192/256 | `infected`, `virus`, `malware`, `password`, `123456` (the malware-sharing convention) |
| 7z | AES-256 (SHA-256 KDF), including encrypted headers; the result is CRC-checked | none |
| RAR | RAR5 AES-256 and RAR 2.9-4 AES-128, including encrypted headers (`rar -hp`); the result is CRC-checked | `infected`, `virus`, `malware`, `password`, `123456` |
| PDF | standard security handler, RC4 and AES | the empty user password, first |
| DMG | encrypted UDIF | none |
| Office | legacy Excel `.xls` (RC4, RC4 CryptoAPI, XOR obfuscation); OOXML `.docx`/`.xlsx`/`.pptx` (AES, standard and agile) | `VelvetSweatshop` (Excel's no-prompt default) and the empty password |
| ARJ | garbled (`arj -g`) and GOST-40 members, checked against the member's CRC-32 | none |

Content that is still encrypted after that comes back as an unsupported
member marked encrypted, never as ciphertext passed off as content. That
covers a wrong or missing password, and the schemes exav-unpack detects but
does not decrypt: RAR 2.0's own cipher, PKWARE Strong Encryption, encrypted
ALZ and EGG members, ARJ GOST-256, encrypted legacy Word `.doc`, and CryptFF.

The passwords are `Budget::passwords` in the crate, `-P` on the command
(repeatable). The scanner's pool, built from its flags and `.pwdb` databases,
is on its [Supported formats](/scanner/reference/formats/#encryption-and-passwords)
page.

ARJ decryption comes with the `arj` feature; the rest needs the `decrypt`
feature, on by default (see [the crate's features](/unpack/rust/#features)).
Without it, that content is reported as encrypted.
