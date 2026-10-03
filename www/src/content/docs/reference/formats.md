---
title: Supported formats
description: The archive, container, document, and executable-packer formats exav unpacks, and what is detected but not yet decoded.
---

exav recursively unpacks archives, structured documents and packed executables,
in pure Rust and under the decompression-bomb budget. Anything it cannot fully
decode is reported `UNSCANNABLE` or `PASSWORD-PROTECTED` (see
[never a silent clean](/concepts/design-principles/#never-a-silent-clean)).

Each format is a Cargo feature; see [Feature flags](/reference/feature-flags/) to
build a subset.

## Archives

| Format | Notes |
|---|---|
| ZIP | Every common method (see [codecs](#codec-level-coverage)) and [decryption](#encryption-support); orphan local headers and deferred-size members are carved too |
| gzip · bzip2 · xz · zstd · lzip · `.Z` (LZW) · LZ4 | Streaming decompressors: a member is decoded as it is read. Past `--max-object-bytes` it is written to a spill file and scanned from there like any object that large; with spilling off it is reported `LIMITS-EXCEEDED`. Concatenated streams and frames are followed for all of them |
| ARC (SEA ARC / PKARC / PAK) | the pre-ZIP archiver; each member is checked against its CRC-16 |
| tar | POSIX/GNU |
| 7z | Every common coder (see [codecs](#codec-level-coverage)) and AES-256 [decryption](#encryption-support) |
| CAB · CHM | Microsoft cabinet / help (ITSF + LZX) |
| RAR | RAR3 and RAR5, including solid archives; every member is checked against its recorded CRC (see [codecs](#codec-level-coverage)) |
| ARJ · LHA | classic archivers |
| ALZ · EGG | ESTsoft's Korean archivers: ALZ stored, deflate and bzip2 members; EGG stored, deflate, bzip2, LZMA and AZO members, each block CRC-checked |
| InstallShield `.z` | the older installer archive (PKWARE DCL implode) |
| ISO · UDF | CD/DVD/Blu-ray images: the ISO 9660 tree (with Joliet) and the UDF tree, including UDF-only images with no ISO 9660 descriptor. A bridge image carrying both is walked once per file |
| `ar` (.deb / .a) · cpio (RPM) · xar (.pkg) | Unix and package archives |
| DMG | Apple UDIF, including [encrypted](#encryption-support), with HFS+/APFS extraction |
| FAT12/16/32 | files inside a disk image, with their paths, reassembled from the cluster chain, so a fragmented file comes back whole |
| ext2/3/4 | files inside a Linux disk image, with their paths, reassembled from the inode's extent tree or block map. Symlinks and device nodes hold no bytes and are skipped |
| ZOO | Rahul Dhesi's 1986 archiver, both codecs (LZD, a 13-bit LZW, and LZH). Each member is checked against its recorded CRC-16, and a mismatch is reported. Deleted members are extracted too: ZOO flags them and leaves the bytes in place |
| NTFS | files inside a disk image, walked through the MFT: reassembled from their data runs (including across `$ATTRIBUTE_LIST`), read in place when resident, LZNT1-decompressed when compressed. Data runs short of the declared size are reported. The MFT walk also surfaces deleted-but-resident records a directory walk cannot see |
| WIM (`.wim`/`.esd`) | Windows imaging format: file resources with their paths, uncompressed, XPRESS or LZX. Each resource is checked against its recorded SHA-1; LZMS resources are reported |
| VHD · VHDX · QCOW2 · VMDK | virtual disks, reconstructed to the guest disk and rescanned: VHD fixed and dynamic, VHDX through its block allocation table, QCOW2 including deflate-compressed clusters, VMDK sparse and streamOptimized (the shape inside an OVA). Delta images against a parent (differencing VHD/VHDX, QCOW2 with a backing file) are reported, not skipped |

## Size: what is read as it goes, and what is read whole

These are decoded as they are read, at any size: ZIP, tar, CAB, ISO/UDF, LHA,
`ar`, cpio, TNEF, OneNote, SWF, SZDD, partition maps, self-extracting
executables, universal Mach-O, `.pyc`, and the single-stream compressors above.
A member that decodes past `--max-object-bytes` goes to a spill file and is
scanned from there. The exceptions: ZIP Shrink, Reduce and Implode members, and
encrypted ZIP members, are decoded whole under that limit.

A DMG is walked at any size, but each file in it is held whole, under
`--max-object-bytes`; an encrypted DMG is decrypted whole under the same limit.
Only data forks are read. A file macOS compressed (decmpfs) keeps its bytes in
an attribute or its resource fork instead: on HFS+, a file with a resource fork
is reported `UNSCANNABLE`; on APFS, and for small HFS+ files compressed into
the attribute alone, such a file reads as empty.

Every other format is read whole: a container larger than `--max-object-bytes`
(256 MiB by default) is reported `LIMITS-EXCEEDED` and its members are not
scanned. That includes RAR, OLE, PDF, CHM, ARJ, xar, email, WIM, and the virtual
disks and filesystems (VHD, VHDX, QCOW2, VMDK, FAT, NTFS, ext), which are often
larger than that: raise `--max-object-bytes` where such images are expected. 7z
is read whole too, but its members stream out of it.

## The complete gap list

Every container or codec exav does not decode. If something is not here, exav
opens it.

### Recognised and reported

exav opens these far enough to know what they are, then reports `UNSCANNABLE` or
`PASSWORD-PROTECTED`: it says the members went unexamined rather than scanning
the compressed bytes, matching nothing, and calling the file clean.

The ClamAV column was measured by extracting each container with a third-party
tool, hashing its members into a signature database, and scanning the untouched
container with ClamAV 1.4.3 and 1.5.3.

| Format / codec | ClamAV | Why it is open |
|---|---|---|
| ACE | No support: 200 members of a real ACE went unextracted | No encoder exists to validate a decoder against, and the one sample obtainable is rejected as invalid by both `lsar` and `unace` |
| StuffIt / StuffIt X | No support: real `.sit` and `.sitx` unextracted | Compression methods undocumented; the only implementations are closed-source or GPL |
| Inno Setup | No support: stops at "Recognized MS-EXE/DLL", 71 members unreached | The layout changes across setup-data versions; `innoextract` (zlib license) is the reference |
| ZIP method 10 (DCL Implode) | No support: enumerates the entry, then `unsupported method (10)` | No tool in print creates one, so a decoder could only be validated against found samples |
| ZIP methods 94 / 96 / 97 (MP3, JPEG, WavPack) | No support | WinZip-only; no other extractor in the reference set reads them |
| PKWARE Strong Encryption | No support | Rare, proprietary |
| WIM LZMS resources | No support for WIM at all: no `CL_TYPE_WIM`, all four test images clean | Used by `.esd` images and `wimlib --solid` |
| RAR5 dictionaries over 64 MiB (including RAR 7's larger ones) | not measured | The decoder's window is capped at 64 MiB |
| RAR 1.5 / 2.x compression (unpack versions 15, 20, 26) | not measured; ClamAV's RAR support derives from UnRAR, which reads these | No permissively licensed decoder to port or check against; stored members of these archives are scanned |
| KWAJ LZSS, MSZIP and LZH methods | not measured | Stored and XOR-obfuscated KWAJ members are decoded |
| CHM multi-frame LZX intervals | not measured | Reported |
| 7z BCJ ARMT / PPC / SPARC / IA64 / RISC-V | not measured | Minor architectures |
| 7z Deflate64 / Zstandard coders | not measured | The Zstandard coder is a 7-Zip ZS fork extension |

None of the measured rows is a capability gap against ClamAV: they are formats
neither engine opens. RAR 1.5/2.x compression, not measured, is likely one. They
are listed because [an attacker picks a format by what the victim can open](/concepts/archive-extraction/#the-parity-principle),
so they are gaps against 7-Zip, WinRAR and The Unarchiver. For ACE, StuffIt and
Inno the blocker is [validation](/concepts/archive-extraction/#validating-a-decoder):
with no trustworthy implementation to check against, a subtly wrong decoder emits
plausible bytes rather than errors.

### Checked against ClamAV's own type list

These come from checking exav against ClamAV's own `CL_TYPE_*` enumeration rather
than a hand-assembled list. `clamscan --debug` reports dedicated submodules for
EGG, ALZ and HWP, all on by default, and its shipped magic database types all
five formats below.

| Format | ClamAV | exav | Evidence of decoding in ClamAV |
|---|---|---|---|
| **EGG** (ESTsoft, Korean) | Decodes | **Decodes** (store/deflate/bzip2/LZMA/AZO, CRC-verified) | `EGG` submodule on by default; `Heuristics.Encrypted.EGG` exists, so members are parsed deeply enough to detect encryption |
| **ALZ** (ESTsoft, Korean) | Decodes | **Decodes** (store/bzip2/deflate) | `ALZ` submodule on by default; magic added at flevel 210 |
| **HWP3** (Hangul Word Processor) | Decodes | **Decodes** (deflate body) | `HWP` submodule on by default, with its own scan-option bit, engine option `MAX_RECHWP3` and `--max-rechwp3` flag |
| **ISHIELD_MSI** (InstallShield MSI) | Types and handles | Recognised, reported `UNSCANNABLE` | dedicated `CL_TYPE_ISHIELD_MSI` |
| **CRYPTFF** | Types and handles | Recognised, reported `PASSWORD-PROTECTED` | dedicated `CL_TYPE_CRYPTFF` |

EGG and ALZ matter for Korean-language targets, where ALZip is common; HWP3 is the
Korean government's standard document format and a recurring spear-phishing
carrier.

- **ALZ** is cross-checked field by field against `unalz` (zlib-licensed) and
  `unar`.
- **EGG** is written from ESTsoft's published *EGG Format Specification v1.0*;
  every block's CRC-32 validates the decoder. AZO, ESTsoft's own codec, is not in
  the specification: exav's decoder is a port of `EggDotNet` (MIT, credited in
  `NOTICE`), the one permissively licensed implementation.
- **HWP3** preamble offsets come from `java-hwp` (Apache-2.0, credited in
  `NOTICE`), validated against a document Hangul Word Processor wrote.

InstallShield MSI (sniffed by `"InstallShield\0"` plus a fixed record 292 bytes
on) and CryptFF are recognised but not opened, so their payloads report as
unexamined. CryptFF reports as encrypted, because that is what it is.

### Where recognition itself is the question

A format with no detection is the weaker failure: the file is scanned as whatever
it types as, its members are never reached, and the scan can come back clean.
Recognition is much cheaper than decoding and removes that hole on its own:

| Format | ClamAV | exav | Sniff |
|---|---|---|---|
| InstallShield InstallScript cabinet | No support | Recognised, reported | `ISc(` at 0 |
| InstallShield `.z` archive | No support | **Decoded** | `13 5D 65 8C` at 0, confirmed against the header's own arithmetic (declared archive size, table-of-contents offset) |
| ext2/3/4 | No support | **Decoded** | `0xEF53` at offset 1080; nothing at offset 0 identifies the image |
| ZOO | No support | **Decoded** | tag `0xFDC4A7DC` at 20 plus a non-zero version byte at 32; the leading `ZOO ?.?? Archive.` text may be anything |
| AppleSingle / AppleDouble | No support | Recognised, reported | `0x00051600` / `0x00051607` |
| lrzip | No support | Recognised, reported | `LRZI` at 0 |

ext is walked as a filesystem rather than carved, for the same reason as FAT: a
file written into a hole lands in several extents. InstallShield `.z` is read
through the MIT `unshield` crate; the header check keeps four magic bytes alone
from reporting ordinary files as archives exav then could not open.

lrzip and the `ISc(` cabinet stay at recognition for licensing reasons. Neither
has a published specification: lrzip's long-range match stream is defined only
by its GPL source, and the only `ISc(` implementation is the LGPL `unshield` C
project (not the MIT crate of the same name). exav's clean-room rule forbids
reading either, and inferring an exact bitstream from black-box behaviour is not
something to claim. `UNSCANNABLE` tells the operator there is a gap, where a
guessed decoder would produce plausible bytes and a confident `OK`.

Still unrecognised, each for a stated reason:

| Format | Why not |
|---|---|
| Compact Pro, DiskDoubler | No authoritative magic: `file`'s database does not carry them, and a guessed signature would report ordinary files `UNSCANNABLE` |
| MacBinary | No magic at all, only a heuristic over header fields (a zero at 0, a length byte at 1, a CRC at 124), with a false-positive rate on arbitrary binaries |
| Wise installer | A PE carrying a marker string; the outer PE is scanned either way |
| Brotli as a bare stream | A raw Brotli stream has no magic number; `.br` is identified by a `Content-Encoding` header a scanner never sees |

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
Huffman tables and PPMd model carry across the group, and every member is
CRC-checked), the standard filters RAR writes, encrypted members and headers,
and hard links and
file copies. Checked against official RAR 6.12 and 7.23 output across methods,
solid groups, filters, dictionary sizes, volumes, recovery records and
encryption. A member split across volumes is reported, since the rest of its
data is in a sibling file; the bytes of a split stored member that are present
are still scanned. (ClamAV does not join volume sets either.)

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
| **Unpacked, per format** | UPX, all methods: NRV2B/2D/2E (UCL), LZMA and DEFLATE, including the bare-`PackHeader` layout, verified against the header's Adler-32, then rebuilt as a PE (a stripped or patched `PackHeader` falls back to running the stub); the aPLib family (Petite 2.x, FSG 2.0, NsPack), round-trip byte-exact; MPRESS, by running ClamAV's own `.cbc` unpacker on exav's bytecode interpreter, so only with `bytecode.cvd` loaded |
| **Unpacked by running the stub** | ASPack, MEW, Upack, WWPack, PESpin, Yoda's Cryptor, and anything else that looks packed, under a bounded x86 interpreter that captures the image the stub rebuilds. Measured coverage is on the [PE stub emulation](/concepts/pe-emulation/#measured-coverage) page |
| **Reported `UNSCANNABLE`** | A file whose packer exav identified but could not unpack. A file sent to the emulator only because of its shape is scanned as it is if nothing comes out |
| **Reported, never unpacked** | VMProtect, Themida/WinLicense, Enigma: virtualizers, where no original code exists in memory to recover |

A per-packer decoder has to be written against a format the packer's author is
free to change; what no packer can avoid is that its stub rebuilds the original
image in memory and jumps to it. exav runs the stub in a sandbox with no syscalls
and no host memory, and takes the image at that jump. Nothing is emitted unless
it reads back as a valid PE. See [PE stub emulation](/concepts/pe-emulation/).

ClamAV natively unpacks 10 packer families, each with a hand-written submodule.
exav unpacks four of them with dedicated decoders and the rest through the
emulator. SUE and Yoda's Protector (not Yoda's Cryptor) are detection-only in
ClamAV, covered by PUA packer signatures in the optional `.?du` databases, and
so is MPRESS outside its bytecode signature.

`--clamav-compat` keeps the PE unpackers on: it narrows archive extractors and
names, not unpacking of executables.

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

Packed executables are under [PE packers](#pe-packers).

| Format | Handling |
|---|---|
| Embedded PE / ELF / Mach-O | carved at non-zero offsets and rescanned in their own type context |
| Mach-O universal ("fat") | split per architecture |

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
| SWF (FWS / CWS / ZWS) | the decompressed Flash tag stream; all three variants are typed so `Target:11` signatures apply |
| HTML, Word/Excel 2003 flat XML | inline base64 assets (a `data:` URI image, a base64 element body), with the document as their container |
| AI models | Python pickle opcodes (surfaced, never executed) and the safetensors header |
| Microsoft Script Encoder | the plaintext of `#@~^`-encoded VBScript/JScript |
| An archive appended to another file | carved and extracted; an encrypted ZIP appended to a picture or document is reported `PASSWORD-PROTECTED` once its directory checks out |

## Encryption support

exav decrypts these with the password pool, then with the built-in passwords
where the table names some:

| Container | Schemes decrypted | Tried besides the pool |
|---|---|---|
| ZIP | ZipCrypto, WinZip AES-128/192/256 | `infected`, `virus`, `malware`, `password`, `123456` (the malware-sharing convention) |
| 7z | AES-256 (SHA-256 KDF), including encrypted headers; the result is CRC-checked | none |
| RAR | RAR5 AES-256 and RAR 2.9-4 AES-128, including encrypted headers (`rar -hp`); the result is CRC-checked | `infected`, `virus`, `malware`, `password`, `123456` |
| PDF | standard security handler, RC4 and AES | the empty user password, first |
| DMG | encrypted UDIF | none |
| Office | legacy Excel `.xls` (RC4, RC4 CryptoAPI, XOR obfuscation); OOXML `.docx`/`.xlsx`/`.pptx` (AES, standard and agile) | `VelvetSweatshop` (Excel's no-prompt default) and the empty password |
| ARJ | garbled (`arj -g`) and GOST-40 members, checked against the member's CRC-32 | none |

Content that is still encrypted after that is reported `PASSWORD-PROTECTED`,
never scanned as ciphertext and called clean. That covers a wrong or missing
password, and the schemes exav detects but does not decrypt: RAR 2.0's own
cipher, PKWARE Strong Encryption, encrypted ALZ and
EGG members, ARJ GOST-256, encrypted legacy Word `.doc`, and CryptFF.

The pool is, in order: each `--passwords` (repeatable, or comma-separated in
`EXAV_PASSWORDS`), then the lines of the `--passwords-from` file (kept verbatim,
so a password may hold commas or spaces, and stays out of process listings),
then the passwords of any ClamAV `.pwdb` database in the signature directory
(cleartext or hex-encoded entries). Duplicates are dropped.

ARJ decryption comes with the `arj` feature; the rest needs the `decrypt`
feature, on by default (see [Feature flags](/reference/feature-flags/)). Without
it, that content is reported `PASSWORD-PROTECTED`.
