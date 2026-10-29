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
page is what the scanner does with each kind of file, and the
[format matrix](/project/formats/) has every format, with what the extractor
and the viewer do with it.

## File types

Every object, whatever its type, is matched against the body signatures with
no target (`Target:0`), the file hash signatures (`.hdb`, `.hsb`) and the YARA
rules. On top of that:

| Type | What the scanner does with it | Signatures that apply to it alone |
|---|---|---|
| PE (Windows executables and DLLs) | Reads the entry point, sections, imports, icons, version information and Authenticode signer; unpacks a packed file ([below](#packed-executables)) | `Target:1`; `EP`, section and `VI` offsets; section hashes (`.mdb`, `.msb`), import hashes (`.imp`), icons (`.idb`), signer block list (`.crb`); YARA `pe` and `dotnet` |
| ELF | Scanned as it is; a UPX-packed one is unpacked | `Target:6`, with `EP` and section offsets ([how](/scanner/reference/comparison-with-clamav/#targets)); YARA `elf` |
| Mach-O | A universal binary is split per architecture; each is scanned as it is, and a UPX-packed one unpacked | `Target:9`, with section offsets (`EP` does not resolve, as in clamscan) |
| OLE2 (legacy Office, MSI) | Every stream; VBA macros decompressed, Excel 4.0 (XLM) macros, `Ole10Native` payloads; encrypted Excel decrypted | `Target:2` |
| OOXML (`.docx`, `.xlsx`, `.pptx`) | Opened as the ZIP it is; told apart as Word, Excel or PowerPoint for `Container:`; encrypted documents decrypted | as for its members |
| PDF | Streams decoded through their filters (Flate, LZW, ASCII85, ASCIIHex, RunLength; a filter given as a reference is followed, and the identity `/Crypt` is passed over), JavaScript and URI and launch targets collected, the document decrypted. Image streams (DCT, JBIG2, JPX, CCITT) are matched as stored; a stream with any other filter is reported. The header may follow up to a kilobyte of other bytes, and an object that does not end does not hide the ones after it | `Target:10` |
| HTML | A normalised view (entities decoded, lowercased, whitespace collapsed) and, for script, a normalised and a deobfuscated JavaScript view; inline base64 assets extracted | `Target:3`, on the normalised view |
| RTF | Both an HTML and a text view; embedded objects extracted | `Target:3` and `Target:7` |
| Email (MIME), MHTML | Every part decoded and scanned, the last part of a multipart nothing closed included, a base64 part read as far as it decodes, and a file uuencoded into a text part; a message is known by its header block (any first field, in any case), and a MIME document with no mail envelope is a saved web page (MHTML) | `Target:4`, on the raw message |
| Text, scripts | A normalised text view, and JavaScript views when the content looks like script; Script Encoder (`#@~^`) decoded; base64-encoded executables decoded ([below](#found-inside-other-files)) | `Target:7`, on the normalised view |
| Images | PNG, GIF, JPEG, TIFF, BMP; with the `image-hash` feature (on by default) also WebP, ICO, PNM, QOI, DDS, farbfeld, HDR, JPEG 2000 and JBIG2. Each is hashed as ClamAV's `sigtool --fuzzy-img` hashes it | `Target:5`; `fuzzy_img#` |
| SWF | Compressed movies (`CWS`, `ZWS`) decompressed and rescanned | `Target:11` |
| Java class | The constant pool's strings | `Target:12` |

`Target:8`, `13` and `14` are not implemented; signatures scoped to them do
not run. `HandlerType:` re-types an object and scans it again as the new
type, as in ClamAV. [Comparison with ClamAV](/scanner/reference/comparison-with-clamav/#targets)
covers the targets in detail.

### The text a reader sees

Beside its bytes, a document is matched through its visible text: the words
without the marks, tags, escapes or run boundaries, entities decoded, and each
link followed by where it goes (`label (target)`). That text is one more view,
which `Target:0` and `Target:7` signatures see, and `--detect phishing` judges
its links. It is the `visible-text` [feature](/scanner/reference/feature-flags/),
off under `--clamav-compat`.

| Read in the default build | Read with an opt-in feature |
|---|---|
| Markdown (`.md`, `.markdown`), HTML, the XML parts of Word, PowerPoint, Excel and OpenDocument files, DXF and DWG drawings | PDF (`visible-text-pdf`); DOC, XLS, PPT, RTF, Word 2003 XML, SpreadsheetML 2003, SYLK, flat OpenDocument (FODT, FODS, FODP, FODG), Numbers, Pages and Keynote (`visible-text-office`) |

A document of a kind that has such a text, whose text cannot be taken out
(encrypted, past a limit, damaged), is still scanned as bytes, and the scan is
`PARTIAL`, never `OK`. A compound file (`.doc`, `.xls`, `.ppt` and their
templates) is read as an office document by its extension only, so that an
installer is not read whole to find out.

## Containers

Every format exav-unpack opens is opened when scanning, and its members
scanned in turn:

- **Archives:** ZIP (every common method), 7z, RAR3 and RAR5, tar, CAB, CHM,
  ARJ, LHA, ZOO, ARC, ALZ, EGG, InstallShield `.z`, `ar`, cpio, xar.
- **Compressed streams:** gzip, bzip2, xz, zstd, lzip, `.lzma`, LZ4, Unix
  `compress` (`.Z`), SZDD, KWAJ.
- **Packages:** RPM (scripts and payload). A ZIP behind other bytes (a stub, a
  header, padding) is opened when its end record agrees with where it starts.
- **Disk images:** ISO 9660 and UDF, Apple DMG, the virtual disks VHD, VHDX,
  QCOW2 and VMDK reconstructed to the guest disk, GPT, APM and MBR partition
  maps, and the filesystems inside them (FAT, exFAT, NTFS, ext2/3/4, HFS+,
  APFS), SquashFS, cramfs, romfs and EROFS images, WIM.
- **Documents:** OLE2, OOXML, PDF, RTF, HWP3, OneNote, Adobe XDP, Word and
  Excel 2003 flat XML.
- **Mail:** MIME, TNEF (`winmail.dat`), BinHex, uuencode.
- **Installers and self-extractors:** NSIS, SFX archives, AutoIt scripts
  (compiled ones too), Inno Setup recognised and reported.
- **Other carriers:** shortcuts (LNK), Python `.pyc`, AI model files (pickle
  opcodes, never executed, and safetensors headers), DXF and DWG drawings
  (their embedded objects and preview images; a drawing is not rendered).

A set split into byte-numbered parts (`x.7z.001`, `x.7z.002`, ...) and met
inside one container is joined and scanned whole. RAR, ZIP and CAB volume sets
met there are not joined; a member continued in another volume is reported.
Next to each other on disk, or sent together to the daemon, they are: a RAR set
(`x.part1.rar`, `x.r00`), a ZIP set (`x.z01`, ..., `x.zip`) and a CAB set (each
cabinet's header names the next). Scanning one volume of such a set by name
scans the archive its siblings make as well, looked for in the same directory
among regular files (a symbolic link is not a sibling).

### Found inside other files

Some payloads are not announced by the file that carries them. exav looks for
them in every object:

- **Executables and archives at an offset.** A PE, ELF or Mach-O image, or a
  ZIP, gzip, bzip2, xz, 7z, RAR or CAB archive, found inside another file
  (appended to an image, embedded in a document) is carved and scanned in its
  own type: up to 16 images of each kind and 32 archives per object. An
  object holding more is reported `LIMITS-EXCEEDED` unless something is
  found, and the other members of its container are still scanned.
- **Base64.** A base64-encoded executable or archive (ZIP, gzip, 7z, RAR, xz)
  in a text file (a PE in a PowerShell one-liner, a ZIP in an `atob` string) is
  decoded and scanned, and so are the `data:` URIs and base64 assets of HTML
  and flat-XML Office documents. A text file is one with a stretch that is
  mostly text, sampled from its start to its end. Up to 8 executables or
  archives, from 64 runs that start like one, are decoded in a text file, and 16
  assets in a page; a file with more is reported `LIMITS-EXCEEDED` unless
  something is found. `--no-decode base64` turns it off (see
  [Detection](/scanner/reference/cli/#detection)).

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

[Which formats the extractor reads as it goes](/unpack/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole)
(ZIP, tar, 7z, WIM, xar, disk images and the filesystems in them, and more) is
on its page. In the scanner, a member or a file in a filesystem that is past
`--max-object-bytes` goes to a
[spill file](/scanner/reference/cli/#buffering-a-stream-spill) and is scanned
from there, or is reported `LIMITS-EXCEEDED` with spilling off. A file a
filesystem stores compressed (HFS+ and APFS decmpfs, NTFS LZNT1) is decoded
whole under that limit and reported `UNSCANNABLE` past it, and the walk goes on.

Every format the extractor reads whole (RAR, OLE, PDF, CHM, ARJ and email, among
others) is reported `LIMITS-EXCEEDED` when larger than `--max-object-bytes`
(256 MiB by default), and its members are not scanned. Raise the limit where
such files are expected.

For what a scan holds, and what needs disk, by kind of input, see
[Streaming & memory](/scanner/concepts/streaming-memory/#can-a-file-be-larger-than-the-ram).

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

Which formats ClamAV opens and exav does not, and the reverse, is in
[Comparison with ClamAV](/scanner/reference/comparison-with-clamav/#formats-and-unpacking).
