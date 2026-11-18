# Streaming the last container formats

exav optimises for memory, not bandwidth. `walk` hands a format's members over
straight off the seekable source, each decoded as it is read, so peak memory is
one member's window rather than the whole decoded object. Most containers
already work that way (every arm of `dispatch` in `stream.rs` but the last),
including tar, zip, 7z, WIM, xar, cab, CHM, RAR (volume sets too), lz4, `.Z`,
DMG, compound files (OLE and MSI), email, the virtual disks and the filesystem
and partition readers; the
rest are read whole (`read_whole`). What is left of those is in
[BACKLOG.md](BACKLOG.md), with the reason for each.

**Compound files and email.** A compound file past the buffer limit is read
through `cfb::Compound::open_source`: what is held is the list of the sectors of
the FAT, the miniFAT and the mini stream, and the directory (up to the limit,
and reported when it is longer); each stream is read from its sectors, and one
past the limit (the cabinet of an MSI) is a `Read` handed over as a streamed
member. The streams the passes after the walk need (embedded objects, a
presentation's records, a workbook, a VBA project) are held until those have
run, and one past the limit is reported as not examined by them. An
`EncryptedPackage` past the limit is reported, not decrypted. A mailbox past the
limit is split at its `From ` lines, a message within the limit is read as one
in memory is, and a larger one is read part by part with the header block of
one part held, each leaf's base64 or quoted-printable body decoded as it is
read.

**7z, WIM and xar** read their header, their directory tree or their table of
contents from where it is in the source, and each member from its place in it,
through `source::Reader`. A 7z folder's packed bytes are a `Read` under its
coder chain, and its members are read in order, the ones before the one wanted
decoded and dropped, which is charged to the scan budget before it is done. A
WIM resource is a `ResourceReader` that decodes a chunk at a time; an xar
member is a zlib reader over its range of the heap. What is still held is
named in each: a 7z's header and a WIM's directory tree are held under the
buffer limit, and an xar's table of contents under 64 MiB. An encrypted 7z
folder (AES, on a chain or on each stream of a BCJ2 graph) is decrypted a
64 KiB chunk at a time; its password is found by decoding its first CRC'd
member once before it is scanned; a folder with no CRC is read with the first
password that decodes it and its members are reported. Each member is checked
against its CRC as it ends.

**Disks: done.** A disk is read as a `Read + Seek`, and the filesystem and
partition readers take one, so a file comes out of a disk without the disk being
held.

- *DMG.* The HFS+/APFS readers get the disk over `DmgReader`, which
  decompresses a BLKX run when the filesystem first reaches it and keeps the
  last 32 MiB of decoded runs. An encrypted image is decrypted whole, under the
  buffer limit.
- *VHD (fixed and dynamic), VHDX, QCOW2, VMDK (sparse and streamOptimized).*
  `formats/vdisk.rs` gives each as a `VDisk`, a `Read + Seek` over a layout that
  says where a unit (cluster, block, grain) is. The tables are read from the
  source when a read reaches a unit, never held: a hostile L1 table, BAT or grain
  directory costs reads, not memory. A stored unit is read straight from the
  source, an unallocated one reads as zeros and costs nothing, and a compressed
  one (QCOW2 deflate or zstd, a VMDK grain) is decoded into a cache of at most
  32 MiB and decoded again if it was evicted. The one structure that is held is
  a streamOptimized VMDK's index of grains, one entry per grain found by one
  pass over its markers, counted against the buffer limit. What a disk decodes
  is charged to the scan budget, and a read that would pass what is left of it
  fails: an image that lands the filesystem walker on a different compressed unit
  for every small read stops there.
- *The filesystems.* Read in place over a `Read + Seek`: `ntfs.rs` follows the
  MFT record by record through `$MFT`'s own runs; `fat.rs`, `exfat.rs`,
  `ext.rs`, `hfsplus.rs`, `apfs.rs`, `squashfs.rs`, `cramfs.rs`, `romfs.rs` and
  `erofs.rs` read the directories and then each file by its clusters, extents
  or blocks (`vol.rs` is what they read through). A raw image over the buffer
  limit is walked, not refused. A file within the buffer limit is read into
  memory; a longer one is a `Got::Stream`, a `Read` over the file's stretches
  (`Pieces`, a list of where on the volume each is, or a block reader for the
  compressed ones) that the walk hands over as a streamed member, so the scan
  puts it in a spill file as it does a ZIP member. A stretch the volume does not
  give ends the stream with an error after the bytes before it; a hole reads as
  zeros, and is charged to the hole limit (`max_hole_bytes`) instead of the scan
  budget. A file stored compressed by NTFS (LZNT1) is read a compression unit at
  a time, by the clusters each has allocated, and handed over as it goes when it
  is long; one stored compressed by HFS+ or APFS (decmpfs, in the resource
  fork) or by EROFS is read a block or an extent at a time (a window of the
  table or index, one coded cluster, one decoder).
- *Partitions.* `partition::stream_offsets` already took a `Read + Seek`.

A disk that fits the buffer limit is still handed over as one member, so its raw
bytes are scanned and typed one level down. A larger one is walked in place
(`formats/volumes.rs`): the filesystem that starts it, or the volumes of its
partition table. A volume that fits the limit is streamed whole, as a partition
of a raw disk always was; a larger one that holds a filesystem exav reads is
walked in place, and each file comes out under the partition's name. A larger
one that is not is streamed from a raw file, where those bytes are the input,
and reported from a virtual disk, where the size is only what a header declares
and reading it could be a long walk through zeros. The bytes before the first
partition (the boot code) come out as `<boot-area>`, up to 1 MiB.

Not covered: a partition table inside a partition; differencing VHD and VHDX and QCOW2 with a
backing file, which are reported because the parent is not in the file.

**RAR: done.** `rar.rs` reads RAR4 and RAR5 where they lie: each header
through a window of the source, each member's packed bytes through a reader
over its range, and a compressed member decoded as it is read, so what is held
is the LZ window and a bounded stretch of input (a solid group shares one
window). A volume set is a `RarSpan` over its volumes. An archive with
encrypted headers, encrypted members or RAR5 links still goes to the
whole-archive reader when it fits the buffer limit.

**PDF: measured, and not worth doing.** `extract_pdf` already decompresses
stream objects one at a time into a budget-bounded buffer, and the file itself
has to be buffered regardless because the xref table lives at the end and the
recovery path scans the whole file. Peak is therefore already input plus one
bounded object; streaming would save a single bounded body.
