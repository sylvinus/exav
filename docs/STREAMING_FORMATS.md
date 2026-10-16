# Streaming the last container formats

exav optimises for memory, not bandwidth. `walk` hands a format's members over
straight off the seekable source, each decoded as it is read, so peak memory is
one member's window rather than the whole decoded object. Most containers
already work that way (every arm of `dispatch` in `stream.rs` but the last),
including tar, zip, 7z, cab, lz4, `.Z`, DMG, the virtual disks and the NTFS,
FAT and partition readers; the rest are read whole (`read_whole`). Two of those
matter, for different reasons, and only one of them is worth changing.

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
- *NTFS, FAT.* Read in place over a `Read + Seek` (`ntfs.rs` follows the MFT
  record by record through `$MFT`'s own runs; `fat.rs` lets `fatfs` seek). A
  raw image over the buffer limit is walked, not refused.
- *Partitions.* `partition::stream_offsets` already took a `Read + Seek`.

A disk that fits the buffer limit is still handed over as one member, so its raw
bytes are scanned and typed one level down. A larger one is walked in place
(`formats/volumes.rs`): the filesystem that starts it, or the volumes of its
partition table. A volume that fits the limit is streamed whole, as a partition
of a raw disk always was; a larger one that holds an NTFS or FAT filesystem is
walked in place, and each file comes out under the partition's name. A larger
one that is neither is streamed from a raw file, where those bytes are the input,
and reported from a virtual disk, where the size is only what a header declares
and reading it could be a long walk through zeros. The bytes before the first
partition (the boot code) come out as `<boot-area>`, up to 1 MiB. Each file is
still returned whole, so a file is bounded by the peak-buffer limit.

**ext is the exception.** `ext4-view` takes a `Box<dyn Ext4Read>`, which is
`'static`: the reader cannot borrow the disk it reads, so the volume is copied
into memory once. The copy is the volume, not the disk around it, and a volume
over the buffer limit is reported. Reading it in place would take a copy of the
crate with a lifetime added to every type that holds the reader.

Not covered: HFS+ and APFS inside a VHD, VHDX, QCOW2 or VMDK (the volume is
streamed or reported, as any filesystem exav does not read in place); a
partition table inside a partition; differencing VHD and VHDX and QCOW2 with a
backing file, which are reported because the parent is not in the file.

**RAR: real work, deliberately not rushed.** `rar3_unpack.rs` and
`rar5_unpack.rs` are vendored decoders that build the complete output `Vec`.
Streaming them means turning both into resumable `Read` state machines that
retain only the already-capped LZ window: major surgery on fuzzed,
differential-tested code, where a subtle break costs correctness on a format
attackers actively use. It is a focused effort of its own, not a change to slip
in alongside others.

**PDF: measured, and not worth doing.** `extract_pdf` already decompresses
stream objects one at a time into a budget-bounded buffer, and the file itself
has to be buffered regardless because the xref table lives at the end and the
recovery path scans the whole file. Peak is therefore already input plus one
bounded object; streaming would save a single bounded body.
