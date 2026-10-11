---
title: Supported formats
description: What the scanner recognises, which signatures apply to each file type, the containers and encodings it opens, how it handles encrypted content, and how that compares with ClamAV.
---

exav types each object by its content, never by its name, and runs the
signatures scoped to that type. If the object is a container, it opens it and
scans every member the same way, to any depth, under the
[limits](/scanner/reference/limits/). Anything it cannot fully examine is
reported `UNSCANNABLE`, `PASSWORD-PROTECTED` or `LIMITS-EXCEEDED`, never
`OK` (see [Never a silent clean](/scanner/concepts/design-principles/#never-a-silent-clean)).

Containers are opened by the extractor, [exav-unpack](/unpack/). Its
[Supported formats](/unpack/formats/) page has the codec-level detail; this
page is what the scanner does with each kind of file.

## File types

Every object, whatever its type, is matched against the body signatures with
no target (`Target:0`), the file hash signatures (`.hdb`, `.hsb`) and the YARA
rules. On top of that:

| Type | What the scanner does with it | Signatures that apply to it alone |
|---|---|---|
| PE (Windows executables and DLLs) | Reads the entry point, sections, imports, icons, version information and Authenticode signer; unpacks a packed file ([below](#packed-executables)) | `Target:1`; `EP`, section and `VI` offsets; section hashes (`.mdb`, `.msb`), import hashes (`.imp`), icons (`.idb`), signer block list (`.crb`); YARA `pe` and `dotnet` |
| ELF | Scanned as it is; a UPX-packed one is unpacked | `Target:6`; YARA `elf`. `EP` and section offsets do not resolve ([gap](/scanner/reference/comparison-with-clamav/#targets)) |
| Mach-O | A universal binary is split per architecture; each is scanned as it is, and a UPX-packed one unpacked | `Target:9`, with the same offset gap |
| OLE2 (legacy Office, MSI) | Every stream; VBA macros decompressed, Excel 4.0 (XLM) macros, `Ole10Native` payloads; encrypted Excel decrypted | `Target:2` |
| OOXML (`.docx`, `.xlsx`, `.pptx`) | Opened as the ZIP it is; told apart as Word, Excel or PowerPoint for `Container:`; encrypted documents decrypted | as for its members |
| PDF | Streams decoded through their filters (Flate, LZW, ASCII85, ASCIIHex, RunLength), JavaScript and URI and launch targets collected, the document decrypted. Image streams (DCT, JBIG2, JPX, CCITT) are matched as stored | `Target:10` |
| HTML | A normalised view (entities decoded, lowercased, whitespace collapsed) and, for script, a normalised and a deobfuscated JavaScript view; inline base64 assets extracted | `Target:3`, on the normalised view |
| RTF | Both an HTML and a text view; embedded objects extracted | `Target:3` and `Target:7` |
| Email (MIME), MHTML | Every part decoded and scanned; a MIME document with no mail envelope is a saved web page (MHTML) | `Target:4`, on the raw message |
| Text, scripts | A normalised text view, and JavaScript views when the content looks like script; Script Encoder (`#@~^`) decoded; base64-encoded executables decoded ([below](#found-inside-other-files)) | `Target:7`, on the normalised view |
| Images | PNG, GIF, JPEG, TIFF, BMP; with the `image-hash` feature (on by default) also WebP, ICO, PNM, QOI, DDS, farbfeld, HDR, JPEG 2000 and JBIG2. Each is hashed as ClamAV's `sigtool --fuzzy-img` hashes it | `Target:5`; `fuzzy_img#` |
| SWF | Compressed movies (`CWS`, `ZWS`) decompressed and rescanned | `Target:11` |
| Java class | The constant pool's strings | `Target:12` |

`Target:8`, `13` and `14` are not implemented; signatures scoped to them do
not run. `HandlerType:` re-types an object and scans it again as the new
type, as in ClamAV. [Comparison with ClamAV](/scanner/reference/comparison-with-clamav/#targets)
covers the targets in detail.

## Containers

Every format exav-unpack opens is opened when scanning, and its members
scanned in turn:

- **Archives:** ZIP (every common method), 7z, RAR3 and RAR5, tar, CAB, CHM,
  ARJ, LHA, ZOO, ARC, ALZ, EGG, InstallShield `.z`, `ar`, cpio, xar.
- **Compressed streams:** gzip, bzip2, xz, zstd, lzip, LZ4, Unix `compress`
  (`.Z`), SZDD, KWAJ.
- **Disk images:** ISO 9660 and UDF, Apple DMG, the virtual disks VHD, VHDX,
  QCOW2 and VMDK reconstructed to the guest disk, GPT, APM and MBR partition
  maps, and the FAT, NTFS and ext2/3/4 filesystems inside them, WIM.
- **Documents:** OLE2, OOXML, PDF, RTF, HWP3, OneNote, Adobe XDP, Word and
  Excel 2003 flat XML.
- **Mail:** MIME, TNEF (`winmail.dat`), BinHex, uuencode.
- **Installers and self-extractors:** NSIS, SFX archives, AutoIt scripts
  (compiled ones too), Inno Setup recognised and reported.
- **Other carriers:** shortcuts (LNK), Python `.pyc`, AI model files (pickle
  opcodes, never executed, and safetensors headers), DXF and DWG drawings
  (their embedded objects and preview images; a drawing is not rendered).

A set split into byte-numbered parts (`x.7z.001`, `x.7z.002`, ...) and met
inside one container is joined and scanned whole. RAR and ZIP volume sets are
not joined; a member continued in another volume is reported.

### Found inside other files

Some payloads are not announced by the file that carries them. exav looks for
them in every object:

- **Executables and archives at an offset.** A PE, ELF or Mach-O image, or a
  ZIP, gzip, bzip2, xz, 7z, RAR or CAB archive, found inside another file
  (appended to an image, embedded in a document) is carved and scanned in its
  own type: up to 16 images of each kind and 32 archives per object. An
  object holding more is reported `LIMITS-EXCEEDED` unless something is
  found, and the other members of its container are still scanned.
- **Base64.** A base64-encoded executable in a text file (a PE in a PowerShell
  one-liner) is decoded and scanned, and so are the `data:` URIs and base64
  assets of HTML and flat-XML Office documents. `--no-decode base64` turns it
  off (see [Detection](/scanner/reference/cli/#detection)).

### Packed executables

| State | Packers |
|---|---|
| **Unpacked, per format** | UPX, every method, on PE, ELF and Mach-O; the aPLib family (Petite 2.x, FSG 2.0, NsPack); MPRESS, by running ClamAV's own `.cbc` unpacker on exav's bytecode interpreter, so only with `bytecode.cvd` loaded |
| **Unpacked by running the stub** | ASPack, MEW, Upack, WWPack, PESpin, Yoda's Cryptor, and anything else that looks packed, under a bounded x86 interpreter that captures the image the stub rebuilds ([PE stub emulation](/scanner/concepts/pe-emulation/)) |
| **Reported `UNSCANNABLE`** | A file whose packer exav identified but could not unpack. A file sent to the emulator only because of its shape is scanned as it is if nothing comes out |
| **Reported, never unpacked** | VMProtect, Themida/WinLicense, Enigma: virtualizers, where no original code exists in memory to recover |

The unpacked image is scanned as a PE of its own, and what the bytecode
signatures unpack is scanned too.

## Size: what is read as it goes, and what is read whole

These are decoded as they are read, at any size: ZIP, tar, CAB, ISO/UDF, LHA,
`ar`, cpio, TNEF, OneNote, SWF, SZDD, partition maps, self-extracting
executables, universal Mach-O, `.pyc`, and the single-stream compressors. A
member that decodes past `--max-object-bytes` goes to a
[spill file](/scanner/reference/cli/#buffering-a-stream-spill) and is scanned
from there, or is reported `LIMITS-EXCEEDED` with spilling off. The
exceptions: ZIP Shrink, Reduce and Implode members, and encrypted ZIP
members, are decoded whole under that limit.

A DMG is walked at any size, but each file in it is held whole, under
`--max-object-bytes`; an encrypted DMG is decrypted whole under the same limit.

Every other container is read whole: one larger than `--max-object-bytes`
(256 MiB by default) is reported `LIMITS-EXCEEDED` and its members are not
scanned. That includes RAR, OLE, PDF, CHM, ARJ, xar, email, WIM, and the
virtual disks and filesystems (VHD, VHDX, QCOW2, VMDK, FAT, NTFS, ext), which
are often larger than that: raise `--max-object-bytes` where such images are
expected. 7z is read whole too, but its members stream out of it.

A file of any size is scanned through a block cache rather than loaded. The
checks that parse an object whole (a PE's structure, YARA's `pe`, `elf` and
`dotnet` modules) apply up to `--max-object-bytes`; past it, an object one of
them applied to is reported `LIMITS-EXCEEDED` unless something is found. See
[Limits and tuning](/scanner/reference/limits/).

## Encryption and passwords

exav decrypts ZIP (ZipCrypto, WinZip AES), 7z, RAR3 and RAR5, PDF, encrypted
DMG, legacy Excel and OOXML Office documents, and ARJ's garbled and GOST-40
members. The
[schemes](/unpack/formats/#encryption-support) are listed with the extractor.

It tries, in order (a PDF's empty user password goes first):

1. each `--passwords` (repeatable, or comma-separated in `EXAV_PASSWORDS`);
2. the lines of the `--passwords-from` file, kept verbatim, so a password may
   hold commas or spaces, and stays out of process listings;
3. the passwords of any ClamAV `.pwdb` database in the signature directory
   (cleartext or hex-encoded entries);
4. the built-in ones: `infected`, `virus`, `malware`, `password` and `123456`
   for ZIP and RAR (the malware-sharing convention), and `VelvetSweatshop`
   (Excel's no-prompt default) and the empty password for Office.

Duplicates are dropped. Content still encrypted after that is reported
`PASSWORD-PROTECTED`, never scanned as ciphertext and called clean. That
covers a wrong or missing password, and the schemes exav detects but does not
decrypt: RAR 2.0's own cipher, PKWARE Strong Encryption, encrypted ALZ and EGG
members, ARJ GOST-256, encrypted legacy Word `.doc`, and CryptFF.

Decryption needs the `decrypt` feature, on by default, and ARJ's the `arj`
feature (see [Feature flags](/scanner/reference/feature-flags/)). Without them,
that content is reported `PASSWORD-PROTECTED`.

## What is reported instead of scanned

A container or codec exav recognises but does not decode is reported
`UNSCANNABLE` rather than scanned as opaque bytes: ACE, StuffIt, Inno Setup,
InstallShield MSI and InstallScript cabinets, AppleSingle and AppleDouble,
lrzip, and a few codecs inside formats exav otherwise opens (ZIP methods 10,
94, 96 and 97, RAR 1.5 and 2.x compression, WIM LZMS, and others). The
extractor's [complete gap list](/unpack/formats/#the-complete-gap-list) has
every one and why it is open.

A format left out of a custom build is reported the same way.

## Under `--clamav-compat`

[`--clamav-compat`](/scanner/reference/cli/#clamav-compatibility) holds the
scanner to what stock ClamAV opens, so a differential run compares like with
like. It leaves these unopened, scanning the file as it is:

- `ar` and lzip archives, Inno Setup installers;
- the formats ClamAV has no type for: DMG, the virtual disks (VHD, VHDX,
  QCOW2, VMDK), Unix `compress` (`.Z`), DXF and DWG;
- UPX on ELF and Mach-O (UPX on PE stays on);
- base64 payloads;
- the image formats beyond PNG, GIF, JPEG, TIFF and BMP.

The PE unpackers stay on: compat narrows what is opened to compare with
ClamAV, not the unpacking of executables.

## Compared with ClamAV

The measurements below come from ClamAV 1.4.3 and 1.5.3. Where a container
could hold the EICAR test file, it was scanned with it inside; otherwise its
members were extracted with a third-party tool, hashed into a signature
database, and the untouched container scanned.

### Formats neither opens

| Format / codec | ClamAV | exav |
|---|---|---|
| ACE | No support: 200 members of a real ACE went unextracted | `UNSCANNABLE` |
| StuffIt / StuffIt X | No support: real `.sit` and `.sitx` unextracted | `UNSCANNABLE` |
| Inno Setup | No support: stops at "Recognized MS-EXE/DLL", 71 members unreached | `UNSCANNABLE` |
| ZIP method 10 (DCL Implode) | No support: enumerates the entry, then `unsupported method (10)` | `UNSCANNABLE` |
| ZIP methods 94 / 96 / 97 (MP3, JPEG, WavPack) | No support | `UNSCANNABLE` |
| PKWARE Strong Encryption | No support | `PASSWORD-PROTECTED` |
| WIM LZMS resources | No support for WIM at all: no `CL_TYPE_WIM`, all four test images clean | `UNSCANNABLE`; other WIM resources are decoded |

None of these is a capability gap against ClamAV, but ClamAV answers `OK`
for each, and exav says the members went unexamined. Not measured, and
likely a gap: RAR 1.5 and 2.x compression, which ClamAV's UnRAR-derived RAR
support reads.

### Checked against ClamAV's own type list

These come from checking exav against ClamAV's own `CL_TYPE_*` enumeration
rather than a hand-assembled list. `clamscan --debug` reports dedicated
submodules for EGG, ALZ and HWP, all on by default, and its shipped magic
database types all five formats below.

| Format | ClamAV | exav | Evidence of decoding in ClamAV |
|---|---|---|---|
| **EGG** (ESTsoft, Korean) | Decodes | **Decodes** (store/deflate/bzip2/LZMA/AZO) | `EGG` submodule on by default; `Heuristics.Encrypted.EGG` exists, so members are parsed deeply enough to detect encryption |
| **ALZ** (ESTsoft, Korean) | Decodes | **Decodes** (store/bzip2/deflate) | `ALZ` submodule on by default; magic added at flevel 210 |
| **HWP3** (Hangul Word Processor) | Decodes | **Decodes** (deflate body) | `HWP` submodule on by default, with its own scan-option bit, engine option `MAX_RECHWP3` and `--max-rechwp3` flag |
| **ISHIELD_MSI** (InstallShield MSI) | Types and handles | Recognised, reported `UNSCANNABLE` | dedicated `CL_TYPE_ISHIELD_MSI` |
| **CRYPTFF** | Types and handles | Recognised, reported `PASSWORD-PROTECTED` | dedicated `CL_TYPE_CRYPTFF` |

EGG and ALZ matter for Korean-language targets, where ALZip is common; HWP3 is
the Korean government's standard document format and a recurring
spear-phishing carrier.

### Formats ClamAV does not recognise

A format with no detection is the weaker failure: the file is scanned as
whatever it types as, its members are never reached, and the scan can come
back clean.

| Format | ClamAV | exav |
|---|---|---|
| InstallShield `.z` archive | No support | Decoded |
| ext2/3/4 | No support | Decoded |
| ZOO | No support | Decoded |
| VHD, VHDX, QCOW2, VMDK, NTFS, FAT | No support | Decoded |
| InstallShield InstallScript cabinet | No support | Recognised, reported `UNSCANNABLE` |
| AppleSingle / AppleDouble | No support | Recognised, reported `UNSCANNABLE` |
| lrzip | No support | Recognised, reported `UNSCANNABLE` |

[Evidence for what ClamAV does not open](/scanner/reference/comparison-with-clamav/#evidence-for-what-clamav-does-not-open)
has the disk image measurements.

### Packers

ClamAV natively unpacks 10 packer families, each with a hand-written
submodule. exav unpacks four of them with dedicated decoders and the rest
through the emulator. SUE and Yoda's Protector (not Yoda's Cryptor) are
detection-only in ClamAV, covered by PUA packer signatures in the optional
`.?du` databases, and so is MPRESS outside its bytecode signature.
