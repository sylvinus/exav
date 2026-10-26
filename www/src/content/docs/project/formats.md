---
title: Format matrix
description: Which of exav's tools reads each file format, the scanner, the extractor or the viewer, and whether the extractor streams it or reads it whole.
---

<!-- Generated from formats/registry.json by scripts/formats.mjs: edit the registry. -->

One table for "can exav handle my file": for each format, what the
[scanner](/scanner/reference/formats/) does with it, whether the
[extractor](/unpack/formats/) streams it or reads it whole (a format read
whole is held in memory up to the buffer limit), and which plugin of the
[viewer](/viewer/) opens it. The pages of each tool have the detail:
codecs, encryption, limits.

- **Scanner.** opened, and every member scanned; recognised and reported UNSCANNABLE or PASSWORD-PROTECTED, not opened; scanned through a text view as well as its bytes; typed by its content, its signatures applied; no type of its own.
- **Extractor.** *Streamed*: the members are decoded as they are read, at any size. *Read whole*: the container is read into memory first; *members streamed* says the members then come out one at a time. *Recognised, reported*: the format is told apart and the file is reported as not examined, never clean.
- **Viewer.** The plugin, as `@exav/viewer` names it. *No*: the viewer does not open it.

## Archives and compressed streams

| Format | Extensions | Scanner | Extractor | Viewer |
|---|---|---|---|---|
| ZIP | `.zip` | Opened, members scanned | Streamed | `archive` |
| Packages that are ZIP files (JAR, APK, IPA, wheel, NuGet, VSIX, MSIX...) | `.jar` `.war` `.ear` `.apk` `.apks` `.xapk` `.aab` `.ipa` `.xpi` `.whl` `.nupkg` `.vsix` `.kmz` `.appx` `.appxbundle` `.msix` `.msixbundle` | Opened, members scanned | Streamed | `archive` |
| First part of a split archive (.7z.001, .zip.001, .rar.001, .tar.001, .z01) | `.7z.001` `.zip.001` `.rar.001` `.tar.001` `.z01` | Opened, members scanned | Streamed | `archive` |
| Comic book archives (CBZ, CBR, CB7, CBT) | `.cbz` `.cbr` `.cb7` `.cbt` | Opened, members scanned | Streamed | `archive` |
| gzip | `.gz` `.tgz` | Opened, members scanned | Streamed | `archive` |
| bzip2 | `.bz2` `.tbz` `.tbz2` | Opened, members scanned | Streamed | `archive` |
| xz | `.xz` `.txz` | Opened, members scanned | Streamed | `archive` |
| Zstandard | `.zst` `.tzst` | Opened, members scanned | Streamed | `archive` |
| LZ4 | `.lz4` | Opened, members scanned | Streamed | `archive` |
| LZMA (.lzma) | `.lzma` | Opened, members scanned | Streamed | `archive` |
| RPM package | `.rpm` | Opened, members scanned | Streamed | `archive` |
| lzip | `.lz` `.tlz` | Opened, members scanned | Streamed | `archive` |
| Unix compress (.Z) | `.z` `.taz` | Opened, members scanned | Streamed | `archive` |
| tar | `.tar` | Opened, members scanned | Streamed | `archive` |
| 7z | `.7z` | Opened, members scanned | Read whole, members streamed | `archive` |
| RAR (RAR3 and RAR5) | `.rar` | Opened, members scanned | Read whole | `archive` |
| Cabinet (CAB) | `.cab` | Opened, members scanned | Streamed | `archive` |
| Compiled HTML Help (CHM) | `.chm` | Opened, members scanned | Read whole | `archive` |
| LHA / LZH | `.lzh` `.lha` | Opened, members scanned | Streamed | `archive` |
| ARJ | `.arj` | Opened, members scanned | Read whole | `archive` |
| ar (static libraries, Debian packages) | `.ar` `.a` `.deb` `.udeb` | Opened, members scanned | Streamed | `archive` |
| cpio (RPM payloads, initramfs) | `.cpio` | Opened, members scanned | Streamed | `archive` |
| xar (macOS packages) | `.xar` `.pkg` `.xip` | Opened, members scanned | Read whole | `archive` |
| ZOO | `.zoo` | Opened, members scanned | Read whole | `archive` |
| ARC / PKARC / PAK | `.arc` | Opened, members scanned | Read whole | `archive` |
| ALZ | `.alz` | Opened, members scanned | Read whole | `archive` |
| EGG | `.egg` | Opened, members scanned | Read whole | `archive` |
| InstallShield .z |  | Opened, members scanned | Read whole | No |
| MS-Compress (SZDD, KWAJ) |  | Opened, members scanned | Streamed | No |
| ACE | `.ace` | Reported, not opened | Recognised, reported | No |
| StuffIt and StuffIt X | `.sit` `.sitx` | Reported, not opened | Recognised, reported | No |
| InstallShield InstallScript cabinet |  | Reported, not opened | Recognised, reported | No |
| CryptFF |  | Reported, not opened | Recognised, reported | No |
| lrzip | `.lrz` | Reported, not opened | Recognised, reported | No |
| AppleSingle and AppleDouble |  | Reported, not opened | Recognised, reported | No |

## Disk images and filesystems

| Format | Extensions | Scanner | Extractor | Viewer |
|---|---|---|---|---|
| ISO 9660 and UDF | `.iso` | Opened, members scanned | Streamed | `archive` |
| Apple disk image (DMG) | `.dmg` | Opened, members scanned | Streamed | `archive` |
| VHD | `.vhd` | Opened, members scanned | Streamed | `archive` |
| VHDX | `.vhdx` | Opened, members scanned | Streamed | `archive` |
| VMDK (and OVA) | `.vmdk` `.ova` | Opened, members scanned | Streamed | `archive` |
| QCOW2 | `.qcow2` | Opened, members scanned | Streamed | `archive` |
| Windows imaging (WIM, ESD) | `.wim` `.esd` | Opened, members scanned | Read whole | `archive` |
| Partition maps (GPT, APM, MBR) and raw disk images | `.img` | Opened, members scanned | Streamed | `archive` |
| FAT12, FAT16, FAT32 |  | Opened, members scanned | Streamed | No |
| NTFS |  | Opened, members scanned | Streamed | No |
| ext2, ext3, ext4 |  | Opened, members scanned | Read whole | No |

## Installers, self-extractors and packers

| Format | Extensions | Scanner | Extractor | Viewer |
|---|---|---|---|---|
| InstallShield MSI |  | Reported, not opened | Recognised, reported | No |
| NSIS installer |  | Opened, members scanned | Read whole | No |
| Inno Setup installer |  | Reported, not opened | Recognised, reported | No |
| Self-extracting archives |  | Opened, members scanned | Streamed | No |
| AutoIt compiled scripts |  | Opened, members scanned | Read whole | No |
| UPX-packed executables |  | Opened, members scanned | Read whole | No |
| Other packed PE executables |  | Opened, members scanned | Read whole | No |
| Mach-O universal binaries |  | Opened, members scanned | Streamed | No |

## Documents

| Format | Extensions | Scanner | Extractor | Viewer |
|---|---|---|---|---|
| OLE2 compound files (legacy Office, MSI) |  | Opened, members scanned | Read whole | No |
| PDF | `.pdf` | Opened, members scanned | Read whole | `pdf` |
| Word (DOCX) | `.docx` `.docm` `.dotx` | Opened, members scanned | Streamed | `docx` |
| Excel (XLSX) | `.xlsx` `.xlsm` | Opened, members scanned | Streamed | `xlsx` |
| PowerPoint (PPTX) | `.pptx` `.pptm` `.ppsx` `.potx` | Opened, members scanned | Streamed | `pptx` |
| Word 6 to 2003 (DOC) | `.doc` `.dot` | Scanned with its text | Read whole | `doc` |
| Excel 4 to 2003 (XLS) | `.xls` `.xlt` | Scanned with its text | Read whole | `xls` |
| PowerPoint 95 to 2003 (PPT) | `.ppt` `.pps` `.pot` | Scanned with its text | Read whole | `ppt` |
| RTF | `.rtf` | Scanned with its text | Read whole | `rtf` |
| OpenDocument text (ODT) | `.odt` `.ott` `.fodt` | Scanned with its text | Streamed | `odt` |
| OpenDocument spreadsheet (ODS) | `.ods` `.ots` `.fods` | Scanned with its text | Streamed | `ods` |
| OpenDocument presentation (ODP) | `.odp` `.otp` `.fodp` | Scanned with its text | Streamed | `odp` |
| Keynote | `.key` | Scanned with its text | Streamed | `keynote` |
| Numbers | `.numbers` | Scanned with its text | Streamed | `numbers` |
| Pages | `.pages` | Scanned with its text | Streamed | No |
| CSV and TSV | `.csv` `.tsv` | Scanned with its text | No | `csv` |
| Visio | `.vsd` `.vst` `.vdx` `.vtx` `.vsdx` `.vsdm` `.vstx` `.vstm` | Bytes only | No | `visio` |
| CorelDRAW | `.cdr` `.cmx` | Bytes only | No | `coreldraw` |
| Publisher | `.pub` | Opened, members scanned | Read whole | `publisher` |
| PageMaker 6 to 7 | `.pmd` `.pm6` `.p65` | Bytes only | No | `pagemaker` |
| FreeHand 3 to 11 | `.fh` `.fh3` `.fh4` `.fh5` `.fh7` `.fh8` `.fh9` `.fh10` `.fh11` | Bytes only | No | `freehand` |
| QuarkXPress 3.1 to 4.1 | `.qxd` `.qxt` | Bytes only | No | `quarkxpress` |
| Zoner Draw 4 and 5 | `.zmf` | Bytes only | No | `zonerdraw` |
| WordPerfect Graphics 1 and 2 | `.wpg` | Bytes only | No | `wpg` |
| Hangul Word Processor 3 (HWP3) | `.hwp` | Opened, members scanned | Read whole | No |
| OneNote | `.one` | Opened, members scanned | Streamed | No |
| Adobe XDP | `.xdp` | Opened, members scanned | Read whole | No |

## Mail and encodings

| Format | Extensions | Scanner | Extractor | Viewer |
|---|---|---|---|---|
| TNEF (winmail.dat) | `winmail.dat` `.tnef` | Opened, members scanned | Streamed | `archive` |
| Email (MIME) and MHTML | `.eml` `.mht` `.mhtml` | Opened, members scanned | Read whole | No |
| BinHex | `.hqx` | Opened, members scanned | Read whole | No |
| uuencode | `.uu` | Opened, members scanned | Read whole | No |

## Images

| Format | Extensions | Scanner | Extractor | Viewer |
|---|---|---|---|---|
| PNG, JPEG, GIF, WebP and SVG | `.png` `.jpg` `.jpeg` `.webp` `.gif` `.svg` | Typed, signatures applied | No | `image` |
| TIFF | `.tif` `.tiff` | Typed, signatures applied | No | `image` |
| BMP | `.bmp` | Typed, signatures applied | No | `image` |
| ICO, PNM, QOI, DDS, farbfeld, Radiance HDR | `.ico` `.cur` `.pbm` `.pgm` `.ppm` `.pnm` `.pam` `.qoi` `.dds` `.ff` `.hdr` | Typed, signatures applied | No | `image` |
| Targa (TGA) | `.tga` `.icb` | Bytes only | No | `image` |
| JPEG 2000 | `.jp2` `.jpf` `.jpx` `.j2k` `.j2c` | Typed, signatures applied | No | `image` |
| JBIG2 | `.jb2` `.jbig2` | Typed, signatures applied | No | `image` |
| JPEG XL | `.jxl` | Typed, signatures applied | No | `image` |
| Camera RAW (DNG, CR2, CR3, NEF, ARW, ORF, RW2, RAF, PEF...) | `.dng` `.gpr` `.cr2` `.cr3` `.crw` `.nef` `.nrw` `.arw` `.sr2` `.srf` `.orf` `.ori` `.rw2` `.rwl` `.raw` `.raf` `.pef` `.srw` `.3fr` `.fff` `.iiq` `.x3f` `.mrw` `.dcr` `.kdc` `.erf` `.mef` `.mos` | Typed, signatures applied | No | `image` |
| HEIC and HEIF | `.heic` `.heif` | Typed, signatures applied | No | No |

## Drawings and 3D models

| Format | Extensions | Scanner | Extractor | Viewer |
|---|---|---|---|---|
| OpenDocument drawing (ODG) | `.odg` `.otg` `.fodg` | Scanned with its text | Streamed | `odg` |
| AutoCAD DWG | `.dwg` | Opened, members scanned | Read whole | `dwg` |
| AutoCAD DXF | `.dxf` | Opened, members scanned | Read whole | `dxf` |
| IFC | `.ifc` | Bytes only | No | `ifc` |
| STL | `.stl` | Bytes only | No | `stl` |
| Wavefront OBJ | `.obj` | Bytes only | No | `obj` |
| Stanford PLY | `.ply` | Bytes only | No | `ply` |
| glTF 2.0 (GLTF, GLB) | `.gltf` `.glb` | Bytes only | No | `gltf` |

## Video and audio

| Format | Extensions | Scanner | Extractor | Viewer |
|---|---|---|---|---|
| Video (MP4, MOV, WebM, Ogg) | `.mp4` `.m4v` `.mov` `.webm` `.ogv` | Bytes only | No | `video` |
| Audio (MP3, M4A, AAC, WAV, Ogg, Opus, FLAC) | `.mp3` `.m4a` `.aac` `.wav` `.ogg` `.oga` `.opus` `.flac` | Bytes only | No | `audio` |

## Text and code

| Format | Extensions | Scanner | Extractor | Viewer |
|---|---|---|---|---|
| Markdown | `.md` `.markdown` | Scanned with its text | No | `text` |
| JSON | `.json` `.geojson` | Typed, signatures applied | No | `text` |
| XML (and RSS, KML, GPX, plist...) | `.xml` `.xsd` `.xsl` `.xslt` `.rss` `.atom` `.kml` `.gpx` `.rdf` `.wsdl` `.plist` | Typed, signatures applied | No | `text` |
| HTML | `.html` `.htm` `.xhtml` | Scanned with its text | No | `text` |
| Diffs and patches | `.diff` `.patch` | Typed, signatures applied | No | `text` |
| Plain text, logs, configuration, subtitles | `.txt` `.text` `.log` `.jsonl` `.ndjson` `.srt` `.vtt` `.yaml` `.yml` `.toml` `.ini` `.cfg` `.conf` `.properties` | Typed, signatures applied | No | `text` |
| Source code | `.js` `.mjs` `.cjs` `.jsx` `.ts` `.tsx` `.mts` `.cts` `.css` `.scss` `.py` `.sh` `.bash` `.zsh` `.bat` `.ps1` `.c` `.h` `.cc` `.cpp` `.hpp` `.cs` `.rs` `.go` `.java` `.kt` `.swift` `.rb` `.php` `.pl` `.lua` `.sql` | Typed, signatures applied | No | `text` |

## Executables and other carriers

| Format | Extensions | Scanner | Extractor | Viewer |
|---|---|---|---|---|
| Windows executables (PE) | `.exe` `.dll` `.sys` | Typed, signatures applied | No | No |
| ELF |  | Typed, signatures applied | No | No |
| Mach-O |  | Typed, signatures applied | No | No |
| Windows shortcuts (LNK) | `.lnk` | Opened, members scanned | Read whole | No |
| Python bytecode (.pyc) | `.pyc` | Opened, members scanned | Streamed | No |
| Java class files | `.class` | Opened, members scanned | Read whole | No |
| SWF (Flash) | `.swf` | Opened, members scanned | Streamed | No |
| AI models (pickle, safetensors) | `.pkl` `.safetensors` | Opened, members scanned | Read whole | No |
| Microsoft Script Encoder | `.vbe` `.jse` | Opened, members scanned | Read whole | No |
