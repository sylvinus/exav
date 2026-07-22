---
title: Supported formats
description: The archive, container, document, and executable-packer formats exav unpacks — and what's detected but not yet decoded.
---

exav recursively unpacks a wide set of archives, structured documents, and packed
executables — all pure-Rust, all under the decompression-bomb budget. Anything it
can't fully decode is reported `UNSCANNABLE` or `PASSWORD-PROTECTED`, never
silently dropped (the [never-silent invariant](/concepts/design-principles/#never-a-silent-clean)).

Each format is a Cargo feature; see [Feature flags](/reference/feature-flags/) to
build a subset.

## Archives

| Format | Notes |
|---|---|
| ZIP | **Deflate64 (method 9)**, Store, Deflate, bzip2, LZMA, zstd, XZ and PPMd members; WinZip AES-128/192/256 & ZipCrypto decryption; orphan local headers and deferred-size streaming members are carved too |
| gzip · bzip2 · xz · zstd · lzip · `.Z` (LZW) · LZ4 | streaming decompressors: content is scanned to its end without being held, so a payload past the per-member cap is still reached — no matter which of them a file happens to be wrapped in. Concatenated streams are followed rather than stopping at the first, for LZ4 frames and for multi-stream bzip2/xz alike |
| tar | POSIX/GNU |
| 7z | LZMA/LZMA2/PPMd/BZip2/Deflate/Delta, BCJ x86/ARM/ARM64 and **BCJ2**; AES-256 decryption (SHA-256 KDF, CRC-verified) |
| CAB · CHM | Microsoft cabinet / help (ITSF + LZX) |
| RAR | RAR3 (LZ + PPMd) and RAR5 (LZ), including **solid** archives — the whole group shares one compressed stream, so each member is decoded against the window the previous one left. Every member is checked against the CRC the archive records, so a mis-decode is reported rather than passed off as the file |
| ARJ · LHA | classic archivers |
| ISO · UDF | CD/DVD/Blu-ray images: the ISO 9660 tree (with Joliet) and the UDF tree, including UDF-only images that carry no ISO 9660 descriptor at all. A bridge image carrying both is walked once per file, not twice |
| `ar` (.deb / .a) · cpio (RPM) · xar (.pkg) | Unix/package archives |
| DMG | Apple UDIF, incl. encrypted, with HFS+/APFS extraction |
| FAT12/16/32 | files inside a disk image, with their paths, reassembled from the cluster chain — so a fragmented file comes back whole rather than as the fragments a raw carve would find |
| ext2/3/4 | files inside a Linux disk image, with their paths, reassembled from the inode's extent tree or block map — same argument as FAT, and ext4 fragments freely. Symlinks and device nodes are skipped rather than invented as files: neither holds bytes in the image |
| ZOO | Rahul Dhesi's 1986 archiver, both codecs (LZD, a 13-bit LZW; and LZH, his own). Every member is checked against the CRC-16 the archive records, and a mismatch is reported rather than passed off as the file. **Deleted members are extracted too** — ZOO flags them in the directory and leaves the bytes in place |
| NTFS | files inside a disk image, walked through the MFT: reassembled from their data runs (including across `$ATTRIBUTE_LIST` when a file is fragmented past what one record can describe), read in place when resident, and LZNT1-decompressed when compressed. Data runs that fall short of the declared size are reported rather than handed back as a complete file. An MFT walk also surfaces **deleted-but-resident** records, which a directory walk cannot |
| WIM (`.wim`/`.esd`) | Windows imaging format: file resources with their directory paths, uncompressed, XPRESS- or LZX-compressed. Each resource is checked against the SHA-1 the image records, so a mis-decode is reported rather than scanned as the file; LZMS resources are reported |
| VHD · VHDX · QCOW2 · VMDK | virtual-disk images, reconstructed to the guest disk and rescanned: VHD fixed + dynamic, VHDX via its block allocation table, QCOW2 including deflate-compressed clusters, VMDK sparse and streamOptimized (the shape inside an OVA). Images that are a delta against a parent file (differencing VHD/VHDX, QCOW2 backing file) are reported, not skipped |

## The complete gap list

Every container or codec exav does not decode, in one place. This list is
authoritative — if something is not here, exav opens it.

It splits in two, and the split is the part that matters.

### Recognised, reported — never a silent clean

exav opens these far enough to know what they are, then reports `UNSCANNABLE` or
`PASSWORD-PROTECTED`. It knows the file is a container and says its members went
unexamined, rather than scanning the compressed bytes, matching nothing, and
calling it clean.

The ClamAV column was measured by extracting each container with a third-party
tool, hashing the members into a signature database, and scanning the untouched
container with ClamAV 1.4.3 and 1.5.3 to see whether it reached them.

| Format / codec | ClamAV | Why it is open |
|---|---|---|
| ACE | No support — 200 members of a real ACE went unextracted | No encoder exists to validate a decoder against, and the one obtainable sample is rejected as invalid by both `lsar` and `unace` |
| StuffIt / StuffIt X | No support — genuine `.sit` and `.sitx` unextracted | Compression methods undocumented; the only reference implementations are closed-source or GPL |
| Inno Setup | No support — stops at "Recognized MS-EXE/DLL"; 71 members unreached | The layout changes across setup-data versions; `innoextract` works as an oracle but is GPL, so it cannot be a source |
| ZIP method 10 (DCL Implode) | No support — enumerates the entry, then `unsupported method (10)` | No tool in print creates one, so a decoder could only be validated against found samples |
| ZIP methods 94 / 96 / 97 (MP3, JPEG, WavPack) | No support | WinZip-only; no other extractor in the reference set reads them either |
| PKWARE Strong Encryption | No support | Rare, proprietary |
| RAR AES | No support | Decryptor pending |
| WIM LZMS resources | No support for WIM at all — no `CL_TYPE_WIM`, all four test images clean | Used by `.esd` images and `wimlib --solid` |
| RAR7 big dictionary | — | |
| NSIS modified-bzip2 blocks | — | |
| CHM multi-frame LZX intervals | — | |
| AutoIt EA06 | — | |
| 7z BCJ ARMT / PPC / SPARC / IA64 / RISC-V | — | Minor architectures |
| 7z Deflate64 / Zstandard coders | — | The Zstandard coder is a 7-Zip ZS fork extension |
| ASPack, MEW, Upack, WWPack, PESpin, yC | Ships a hand-written unpacker per family | Runs the stub under an x86 interpreter instead — see [PE packers](#pe-packers) |

**Nothing in this table is a capability gap against ClamAV** — the last
row is a different route to the same result. Everything above it is
a format neither engine opens, listed because
[an attacker picks a format by what the victim can open](/concepts/archive-extraction/#the-parity-principle),
not by what a scanner supports — these are gaps against 7-Zip, WinRAR and The
Unarchiver. For ACE, StuffIt and Inno the blocker is
[validation](/concepts/archive-extraction/#validating-a-decoder) rather than
effort: with no trustworthy implementation to check against, a decoder that is
subtly wrong emits plausible bytes rather than errors.

### Checked against ClamAV's own type list

The formats here come from checking exav against ClamAV's own `CL_TYPE_*`
enumeration rather than a hand-assembled format list — a hand-assembled list can
only confirm itself.

`clamscan --debug` reports **dedicated submodules for EGG, ALZ and HWP, all
enabled by default**, listed alongside its unpackers; its shipped magic database
types all five formats below.

| Format | ClamAV | exav | Evidence it is really decoded, not just typed |
|---|---|---|---|
| **EGG** (ESTsoft, Korean) | Decodes | **Decodes** (store/deflate/bzip2/LZMA, CRC-verified) | `EGG` submodule on by default; `Heuristics.Encrypted.EGG` exists, so members are parsed deeply enough to detect encryption |
| **ALZ** (ESTsoft, Korean) | Decodes | **Decodes** (store/bzip2/deflate) | `ALZ` submodule on by default; magic added at flevel 210 |
| **HWP3** (Hangul Word Processor) | Decodes | **Decodes** (deflate body) | `HWP` submodule on by default, plus its own scan-option bit, its own engine option `MAX_RECHWP3`, and its own `--max-rechwp3` flag |
| **ISHIELD_MSI** (InstallShield MSI) | Types and handles | Recognised, reported `UNSCANNABLE` | dedicated `CL_TYPE_ISHIELD_MSI` |
| **CRYPTFF** | Types and handles | Recognised, reported `PASSWORD-PROTECTED` | dedicated `CL_TYPE_CRYPTFF` |

EGG and ALZ matter for Korean-language targets, where ALZip is common; HWP3 is
the Korean government's standard document format and a recurring spear-phishing
carrier. All three are decoded, not merely recognised:

- **ALZ** — stored, bzip2 and deflate members. Structure cross-checked field by
  field against `unalz` (zlib-licensed) and `unar` as external oracles.
- **EGG** — stored, deflate, bzip2, LZMA **and AZO** members, written from
  ESTsoft's own published *EGG Format Specification v1.0*. Every EGG block
  records a CRC-32 of its decompressed bytes, so the **format validates the
  decoder**: a member is only ever handed on as content when it reproduces the
  checksum ESTsoft's compressor wrote. Encrypted members report as
  password-protected.

  AZO is ESTsoft's own algorithm and is **not in the specification** — a range
  coder driving LZ77, with two competing probability models per context and a
  running score picking which to decode from. exav's decoder is a Rust port of
  the one permissively licensed implementation, `EggDotNet` (MIT, credited in
  `NOTICE`); ESTsoft's own UnEgg library could not be used, because its licence
  forbids both commercial use without approval and using it to build a
  compression algorithm. ClamAV reached the same conclusion and wrote from the
  spec. The port is validated the same way as the rest: against the writer's
  CRC-32, not against itself.
- **HWP3** — the deflate-compressed body is decompressed and scanned, which is
  where a spear-phishing payload lives. Preamble offsets come from `java-hwp`
  (Apache-2.0, credited in `NOTICE`) and are validated against
  `testHWP_3.0.hwp` from the **Apache Tika** corpus — a document Hangul Word
  Processor wrote, not one exav wrote. Its 9 KiB container inflates to ~45 KiB
  of body, and a test samples the inflated bytes to confirm they are absent
  from the raw file, so the fixture cannot quietly stop testing
  compression.

InstallShield MSI and CryptFF are recognised but not opened: both are named, so
their payloads report as unexamined instead of scanning clean. CryptFF reports
as encrypted rather than merely undecodable, because that is what it is.

### Where recognition itself is the question

A format with **no detection** is the weaker failure mode: the file is scanned
as whatever it does type as, the members inside are never reached, and **the
scan can come back clean** — unlike the tables above, where exav at least names
what it could not open. Recognition is far cheaper than decoding and removes
that clean-verdict hole on its own. Where each format that raises this risk
stands:

| Format | ClamAV | exav | Sniff |
|---|---|---|---|
| InstallShield MSI | No support | Recognised, reported | `"InstallShield\0"` + a fixed record 292 bytes on |
| InstallShield InstallScript cabinet | No support | Recognised, reported | `ISc(` at 0 |
| InstallShield `.z` archive | No support | **Decoded** | `13 5D 65 8C` at 0, confirmed against the header's own arithmetic (declared archive size, table-of-contents offset inside it) rather than a version constant |
| ext2/3/4 | No support | **Decoded** | `0xEF53` at **1080** — nothing at offset 0 identifies the image |
| ZOO | No support | **Decoded** | tag `0xFDC4A7DC` at **20** plus a non-zero version byte at 32; the leading `ZOO ?.?? Archive.` text is conventional and may be anything |
| AppleSingle / AppleDouble | No support | Recognised, reported | `0x00051600` / `0x00051607` |
| lrzip | No support | Recognised, reported | `LRZI` at 0 |

**ext2/3/4 and ZOO are decoded in full**, not merely recognised:

- **ext** is walked as a filesystem, not carved, for the same reason as FAT: a
  file written into a hole left by a deleted one lands in several extents, and
  the first fragment on its own will not decompress. The regression fixture is
  built with `mke2fs` + `debugfs` and its payload inode really does span two
  non-adjacent extents (`(0-62):371-433, (63-96):498-531`), with the EICAR
  string deflated so it appears nowhere in the raw image. Reading is delegated
  to `ext4-view` (MIT/Apache, read-only by construction, no dependencies).
- **ZOO** carries two codecs of its own: LZD (a 13-bit LZW) and LZH (Dhesi's
  own, which is `lh5` on the wire). The oracle is the format itself — the
  fixtures hold one identical member stored, LZD-compressed and LZH-compressed,
  and the test asserts the compressed ones reproduce the stored bytes exactly.
  A subtly wrong codec emits plausible bytes rather than an error, which is the
  failure that check exists to catch. Each member's recorded CRC-16 is verified
  too; a mismatch is *reported*, not dropped, since a tampered member is the
  interesting one.

- **InstallShield `.z`** — the *older* installer archive. Members use
  PKWARE's DCL "implode", read
  through the MIT `unshield` crate. The oracle is the plaintext: the upstream
  project ships `undhr.z` next to `undhr.md`, the original, and the test asserts
  a byte-for-byte match. Recognition is confirmed against the header's own
  arithmetic rather than a guessed version word — four magic bytes alone would
  report ordinary files as archives exav then could not open, a lie in the other
  direction.

**lrzip and the `ISc(` cabinet stay at recognition, and the blocker is
licensing rather than effort.** Neither has a published specification. lrzip's
rzip long-range match stream is defined only by its own GPL source, and the only
`ISc(` implementation is the LGPL `unshield` — both of which exav must not read
under its clean-room rule, and neither has a permissively-licensed
implementation in any language. Running such a tool as an *oracle* is fine;
inferring an exact bitstream from black-box behaviour is not something to
attempt and then claim. `UNSCANNABLE` tells an operator there is a gap, where a
guessed decoder would produce plausible bytes and a confident `OK`.

(The MIT `unshield` *crate* on crates.io covers the `.z` archive above — a
different format from the `ISc(` cabinet, whose only implementation is the LGPL
`unshield` **C project**. Same name, same author lineage, different code and
different licence.)

Still unrecognised, each for a stated reason rather than by omission:

| Format | Why not |
|---|---|
| Compact Pro, DiskDoubler | No magic that could be sourced authoritatively. `file`'s magic database does not carry them, and guessing a signature buys a false positive — an ordinary file reported `UNSCANNABLE` — which is its own kind of lie |
| MacBinary | No magic at all: it is identified by a *heuristic* over header fields (a zero at 0, a length byte at 1, a CRC at 124). Recognising it means accepting a false-positive rate on arbitrary binaries |
| Wise installer | A PE carrying a marker string; the outer file is a PE and is scanned as one either way |
| Brotli as a bare stream | Deliberate. A raw Brotli stream has **no magic number** — nothing in the bytes distinguishes it from arbitrary data. `.br` is served with a `Content-Encoding` header, metadata a scanner never sees. Detection, not decoding, is the blocker |

The pattern in the "why not" column is the same one throughout this page:
**where the choice is between a silent miss and a false positive, exav takes
neither on a guess.** A format is recognised when the bytes say so, and listed
here when they do not.

### Codec-level coverage

What the entries above look like in detail, for the formats where "supported" is
a per-codec question rather than a yes.

**ZIP** — reachable by every extractor in the reference set and both OS shells,
so the highest-value format to be complete on.

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

ZIP64, orphan local headers (dual indexing), deferred-size members, ZipCrypto and
WinZip AES-128/192/256 are all handled; PKWARE Strong Encryption is not.

**7z** — Copy, LZMA, LZMA2, PPMd, BZip2, Deflate, AES-256 (including encrypted
headers), Delta and BCJ x86/ARM/ARM64 all decode, as does **BCJ2**. BCJ2 needed
more than a decoder: it is the only 7z coder with several input streams, so the
folder's bind-pair graph has to be resolved rather than walked as a linear chain.
Missing: the minor-architecture BCJ filters, and the Deflate64 and Zstandard
coders.

**RAR** — RAR3 (LZ + PPMd) and RAR5 (LZ) decode, including **solid** archives:
the window, Huffman tables and PPMd model carry across the group, and every
member is CRC-checked so a mis-decoded solid member is reported rather than
handed over. A member split across volumes is reported, since the rest of its
data is in a sibling file; a split *stored* member's present bytes are still
emitted. (ClamAV does not join volume sets either.)

**CAB / CHM** — MSZIP, LZX and **Quantum** all decode; CHM is ITSF + LZX, with
multi-frame LZX intervals still missing.

**Disk images** — ISO 9660 + Joliet, UDF, DMG (HFS+/APFS, LZFSE/LZVN,
encrypted), VHD, VHDX, QCOW2, VMDK, FAT12/16/32, NTFS and ext2/3/4 are all
walked. Images whose payload lives in a *parent* file — differencing VHD/VHDX,
QCOW2 with a backing file — are reported rather than partially reconstructed.

### CAB Quantum

Implemented. Quantum is an arithmetic coder over adaptive frequency models,
shipped with Office-97-era cabinets — and still reachable, because **7-Zip
decompresses Quantum cabinets byte-exactly today**. A victim opens the archive;
a scanner that skips the codec sees nothing. That a format is old, or absent
from a corpus, is an argument for an attacker reaching for it.

Microsoft published the cabinet *container* but never the Quantum *compressor*,
so exav's decoder was written from a functional specification of the format and
validated against `cabextract`/libmspack as an oracle — the same relationship the
project has with `clamscan` and `innoextract`, never a source.

Validation: byte-exact on the reference cabinet, plus **107 generated streams
across every window size (10–21) with outputs up to 11 KB, decoded by both
engines with zero disagreements** — enough to exercise hundreds of frequency
rescales, the periodic model reordering, and repeated window wrapping, none of
which the tiny reference vector reaches. exav additionally rejects matches that
overshoot a frame or reach behind the start of a folder; neither can occur in
data an encoder produced, and refusing them stops a corrupt stream from turning
into plausible output.

## PE packers

| State | Packers |
|---|---|
| **Unpacked, per format** | UPX (including the bare-`PackHeader` layout, verified against the header's Adler-32, then rebuilt as a PE); the aPLib family (Petite, FSG, NsPack); **MPRESS**, by running ClamAV's own `.cbc` unpacker on exav's bytecode interpreter |
| **Unpacked, by running the stub** | Anything else that looks packed, under a bounded x86 interpreter that captures the image the stub rebuilds. Measured against 276 samples from 23 real packers, 218 (79%) give back a complete image, and 15 packers do so on every sample (ASPack, BeRoEXEPacker, EXpressor, FSG, MEW, MPRESS, Molebox, NSPack, Neolite, PECompact, Packman, RLPack, UPX, WinUpack, Yoda-Crypter); Exe32pack, PEtite, JDPack and Eronana unpack most but not all of theirs; Alienyze, TELock and Yoda-Protector defeat it entirely and are reported rather than passed over |
| **Reported `UNSCANNABLE`** | A packed file whose stub defended itself successfully, so no verified image came out |
| **Reported, never unpacked** | VMProtect, Themida/WinLicense, Enigma — virtualizers, where no original code exists in memory at any point to recover |

The second row is the general case. A per-packer decoder has to be written,
version by version, against a format the packer's author is free to change; the
one thing no packer can avoid is that its stub must rebuild the original image
in memory and jump to it. exav runs the stub — in a sandbox with no syscalls, no
host memory and no way out — and takes the image at that jump. Nothing is
emitted unless it reads back as a valid PE, so a stub that outruns the emulator
costs a report, never a fabricated one. See
[PE stub emulation](/concepts/pe-emulation/).

Measured against ClamAV: ClamAV natively unpacks **10 packer families**, each
with a hand-written submodule. exav unpacks 4 of them with dedicated decoders,
**MPRESS** (which ClamAV does not unpack at all) through ClamAV's own bytecode
program, and the rest through the emulator, which is not limited to a list.

MPRESS, SUE and Yoda's *Protector* (a different product from Yoda's Cryptor) are
detection-only for ClamAV, covered by 964 PUA packer signatures in the optional
`.?du` databases rather than by an unpacker.

This runs under `--clamav-compat` too: compat matches ClamAV's alert *names* and
rough feature scope, and does not switch unpackers off.

## Documents & email

| Format | What's extracted |
|---|---|
| OLE2 (legacy Office, MSI) | streams, VBA-macro decompression, Excel 4.0 (XLM) macro surfacing |
| OOXML | the modern Office ZIP container |
| PDF | object streams (FlateDecode + LZW/ASCII85/ASCIIHex/RunLength + filter chains), plus JavaScript / URI / launch-action harvesting; RC4/AES decryption |
| RTF | embedded hex objects |
| MIME email | decoded attachments and parts |
| TNEF (`winmail.dat`) · OneNote · Adobe XDP | embedded-file carriers |

## Executables & packers

| Format | Handling |
|---|---|
| UPX | walked with all UCL methods + LZMA + DEFLATE (NRV2B/D/E). A stripped or patched `PackHeader` defeats the static reader — it needs the header to find the compressed blocks — so those images fall back to running the stub, which has to decompress them regardless |
| aPLib families (Petite 2.x / FSG 2.0 / NsPack) | **decompressed** back to the original PE (round-trip byte-exact) |
| Aspack · MEW · Upack · wwpack32 · PeSpin · Yoda's Cryptor, and unnamed packers | **stub run under a bounded x86 interpreter**; the rebuilt image is dumped when it reads back as a PE, and the file is reported `UNSCANNABLE` when it does not |
| VMProtect · Themida/WinLicense · Enigma | **reported** — a virtualizer destroys the original code at build time, so there is nothing to recover |
| Embedded PE / ELF / Mach-O | carved at non-zero offsets and re-scanned in their own type context |
| Mach-O universal ("fat") | split per-architecture |

## Other carriers

Formats that aren't archives but still carry a payload exav has to reach:

| Carrier | What exav extracts |
|---|---|
| NSIS, SFX installers | The installer's packaged files |
| AutoIt (EA05) | The compiled script body |
| MS-SZDD / KWAJ | The original file from the legacy compression wrappers |
| BinHex, uuencode | The decoded binary from the text encoding |
| LNK | Embedded command-line strings and target paths |
| Python `.pyc` | Bytecode strings and constants |
| GPT / APM / MBR partition maps | The partitions, then each filesystem inside |
| Java `.class` | Constant-pool strings |
| SWF (FWS / CWS / ZWS) | The decompressed Flash tag stream; all three variants are typed so `Target:11` signatures apply |
| HTML, Word/Excel 2003 flat XML | Inline base64 assets — a `data:` URI image, a base64 element body — extracted with the document as their container |
| AI models | Python pickle opcodes (surfaced, never executed) + safetensors header |
| Microsoft Script Encoder | The plaintext of `#@~^`-encoded VBScript/JScript |

## Encryption support

| Container | Status |
|---|---|
| ZIP (ZipCrypto, WinZip AES-128/192/256) | decrypted with a password |
| 7z (AES-256) | decrypted with a password (CRC-verified) |
| PDF (RC4 / AES standard security handler) | decrypted with a password |
| DMG | decrypted with a password |
| Office: legacy XLS (RC4-basic, RC4-CryptoAPI, XOR) and OOXML (AES standard + agile) | decrypted; `VelvetSweatshop` and the empty password are tried automatically |
| RAR AES, PKWARE Strong Encryption | detected only — decryptors pending |

Passwords come from `--passwords` (repeatable) or a ClamAV `.pwdb` database.
