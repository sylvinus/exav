//! Virtual disks and filesystems too big to hold, walked where they lie.
//!
//! A QCOW2, VMDK, VHD or VHDX declares a disk size that is not the file's, and
//! a raw disk image can be larger than the buffer limit. Whichever it is, a file
//! near the end of a disk of many GiB has to come out without the disk being
//! built: the image is read where the filesystem walk goes, and an unallocated
//! range costs nothing.
//!
//! Two kinds of image are used. The `fat4g.*` fixtures are what `qemu-img`
//! writes for a 4 GiB disk holding an MBR and a FAT volume at 3 GiB, so the
//! container layouts are those of the tools that make them:
//!
//! ```sh
//! # disk.raw: 4 GiB sparse, the MBR at 0, fat/fragmented.img at 3 GiB
//! qemu-img convert -f raw -O qcow2 -o cluster_size=4096 disk.raw plain.qcow2
//! qemu-img convert -f raw -O qcow2 -c -o cluster_size=4096 disk.raw deflate.qcow2
//! qemu-img convert -f raw -O qcow2 -c -o cluster_size=4096,compression_type=zstd disk.raw zstd.qcow2
//! qemu-img convert -f raw -O vmdk -o subformat=monolithicSparse disk.raw sparse.vmdk
//! qemu-img convert -f raw -O vmdk -o subformat=streamOptimized disk.raw stream.vmdk
//! qemu-img convert -f raw -O vpc -o subformat=dynamic,force_size=on disk.raw dynamic.vhd
//! qemu-img convert -f raw -O vhdx -o block_size=1M disk.raw dynamic.vhdx
//! ```
//!
//! Each is stored gzipped. The others are written here, so a disk can be a
//! terabyte, an NTFS volume can lie in it, and a table can be made hostile.

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, LimitHit, Limits};
use std::collections::BTreeMap;

const SECTOR: u64 = 512;
const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// `sha256sum` of the ZIP in `fat/fragmented.img`, which the walk of the FAT
/// volume has to reproduce.
const FAT_PAYLOAD: &str = "aa3029a89a5e657f2d4fa85d3c352d348c08d30b04b924417d7e8b2c3a6bb342";
/// `sha256sum` of what `ntfscat` returns for `payload.zip` of the NTFS fixture.
const NTFS_PAYLOAD: &str = "49c7e4f4b184954a212c78c87c17705cd4c16f0b8c83a5cd6a750369c47957c5";

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn gunzipped(name: &str) -> Vec<u8> {
    super::diskimage::fixture(&format!("{name}.gz"))
}

// ─── Images ──────────────────────────────────────────────────────────────────

/// Pieces of a disk: `(offset, bytes)`, the rest of it zeros.
type Pieces = Vec<(u64, Vec<u8>)>;

/// A disk with an MBR listing one partition of type `ptype` holding `volume`
/// at `at`.
fn mbr_disk(at: u64, volume: Vec<u8>, ptype: u8) -> Pieces {
    let mut mbr = vec![0u8; 512];
    mbr[0x1BE] = 0x80;
    mbr[0x1BE + 4] = ptype;
    mbr[0x1BE + 8..0x1BE + 12].copy_from_slice(&u32::try_from(at / SECTOR).unwrap().to_le_bytes());
    mbr[0x1BE + 12..0x1BE + 16].copy_from_slice(
        &u32::try_from(volume.len() as u64 / SECTOR)
            .unwrap()
            .to_le_bytes(),
    );
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    vec![(0, mbr), (at, volume)]
}

/// The units of `unit` bytes of a disk that hold anything but zeros.
fn units(pieces: &Pieces, unit: u64) -> BTreeMap<u64, Vec<u8>> {
    let mut m: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    for (off, bytes) in pieces {
        let mut pos = 0usize;
        while pos < bytes.len() {
            let abs = off + pos as u64;
            let (idx, into) = (abs / unit, (abs % unit) as usize);
            let n = (unit as usize - into).min(bytes.len() - pos);
            let u = m.entry(idx).or_insert_with(|| vec![0; unit as usize]);
            u[into..into + n].copy_from_slice(&bytes[pos..pos + n]);
            pos += n;
        }
    }
    m.retain(|_, u| u.iter().any(|&b| b != 0));
    m
}

#[derive(Clone, Copy, PartialEq)]
enum Packing {
    Stored,
    Deflate,
    #[cfg(feature = "zstd")]
    Zstd,
}

fn deflate(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut w = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    w.write_all(data).unwrap();
    w.finish().unwrap()
}

fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut w = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    w.write_all(data).unwrap();
    w.finish().unwrap()
}

/// A QCOW2 of `size` bytes holding `pieces`, its clusters stored or compressed.
fn qcow2(size: u64, cluster_bits: u32, pieces: &Pieces, packing: Packing) -> Vec<u8> {
    let cluster = 1u64 << cluster_bits;
    let l2n = cluster / 8;
    let l1_size = size.div_ceil(l2n * cluster);
    let l1_clusters = (l1_size * 8).div_ceil(cluster);
    let mut file = vec![0u8; ((1 + l1_clusters) * cluster) as usize];
    let csize_shift = 62 - (cluster_bits - 8);
    let mut l2: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (idx, data) in units(pieces, cluster) {
        let packed = match packing {
            Packing::Stored => None,
            Packing::Deflate => Some(deflate(&data)),
            #[cfg(feature = "zstd")]
            Packing::Zstd => Some(ruzstd::encoding::compress_to_vec(
                &data[..],
                ruzstd::encoding::CompressionLevel::Fastest,
            )),
        }
        .filter(|p| (p.len() as u64) < cluster);
        let entry = match packed {
            Some(p) => {
                // Packed end to end, whatever the offset.
                let at = file.len() as u64;
                file.extend_from_slice(&p);
                let sectors = ((at % SECTOR) + p.len() as u64).div_ceil(SECTOR);
                (1 << 62) | at | ((sectors - 1) << csize_shift)
            }
            None => {
                file.resize(file.len().next_multiple_of(cluster as usize), 0);
                let at = file.len() as u64;
                file.extend_from_slice(&data);
                (1 << 63) | at
            }
        };
        l2.entry(idx / l2n).or_insert_with(|| vec![0; l2n as usize])[(idx % l2n) as usize] = entry;
    }
    let mut l1 = vec![0u64; l1_size as usize];
    for (i, table) in l2 {
        file.resize(file.len().next_multiple_of(cluster as usize), 0);
        l1[i as usize] = (1 << 63) | file.len() as u64;
        for e in table {
            file.extend_from_slice(&e.to_be_bytes());
        }
    }
    for (i, e) in l1.iter().enumerate() {
        let at = cluster as usize + i * 8;
        file[at..at + 8].copy_from_slice(&e.to_be_bytes());
    }
    file[..4].copy_from_slice(b"QFI\xfb");
    file[4..8].copy_from_slice(&2u32.to_be_bytes());
    file[20..24].copy_from_slice(&cluster_bits.to_be_bytes());
    file[24..32].copy_from_slice(&size.to_be_bytes());
    file[36..40].copy_from_slice(&(l1_size as u32).to_be_bytes());
    file[40..48].copy_from_slice(&cluster.to_be_bytes());
    #[cfg(feature = "zstd")]
    if packing == Packing::Zstd {
        // Version 3 with the compression-type feature, type 1 (zstd).
        file[4..8].copy_from_slice(&3u32.to_be_bytes());
        file[72..80].copy_from_slice(&(1u64 << 3).to_be_bytes());
        file[100..104].copy_from_slice(&112u32.to_be_bytes());
        file[104] = 1;
    }
    file
}

/// A dynamic VHD of `size` bytes holding `pieces`.
fn vhd(size: u64, block: u32, pieces: &Pieces) -> Vec<u8> {
    use super::vhd::{dyn_header, footer};
    let blocks = units(pieces, u64::from(block));
    let max_entries = size.div_ceil(u64::from(block)) as u32;
    let bat_off = 512 + 1024;
    let bat_len = (max_entries as usize * 4).next_multiple_of(512);
    let mut file = footer(3, 512, size);
    file.extend(dyn_header(bat_off as u64, max_entries, block));
    file.resize(bat_off + bat_len, 0);
    let mut bat = vec![0xFFu8; max_entries as usize * 4];
    let bitmap = (block as usize / 512).div_ceil(8).next_multiple_of(512);
    for (idx, data) in blocks {
        let start = file.len();
        bat[idx as usize * 4..idx as usize * 4 + 4]
            .copy_from_slice(&((start / 512) as u32).to_be_bytes());
        file.resize(start + bitmap, 0);
        file.extend_from_slice(&data);
    }
    file[bat_off..bat_off + bat.len()].copy_from_slice(&bat);
    file.extend(footer(3, 512, size));
    file
}

/// A dynamic VHDX of `size` bytes holding `pieces`, in blocks of `block`.
fn vhdx(size: u64, block: u32, pieces: &Pieces) -> Vec<u8> {
    const BAT: [u8; 16] = [
        0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a,
        0x08,
    ];
    const META: [u8; 16] = [
        0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88,
        0x6e,
    ];
    const FILE_PARAMS: [u8; 16] = [
        0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7,
        0x6b,
    ];
    const DISK_SIZE: [u8; 16] = [
        0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4,
        0xb8,
    ];
    const SECTOR_SIZE: [u8; 16] = [
        0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab,
        0x5f,
    ];
    let blocks = units(pieces, u64::from(block));
    let total = size.div_ceil(u64::from(block));
    let ratio = (1u64 << 23) * 512 / u64::from(block);
    let bat_entries = total + total / ratio + 1;
    let bat_off = MIB as usize;
    let bat_len = (bat_entries as usize * 8).next_multiple_of(MIB as usize);
    let meta_off = bat_off + bat_len;
    let data_start = meta_off + MIB as usize;
    let mut file = vec![0u8; data_start];
    file[..8].copy_from_slice(b"vhdxfile");
    let table = 192 * KIB as usize;
    file[table..table + 4].copy_from_slice(b"regi");
    file[table + 8..table + 12].copy_from_slice(&2u32.to_le_bytes());
    for (i, (guid, off, len)) in [(BAT, bat_off, bat_len), (META, meta_off, MIB as usize)]
        .into_iter()
        .enumerate()
    {
        let e = table + 16 + i * 32;
        file[e..e + 16].copy_from_slice(&guid);
        file[e + 16..e + 24].copy_from_slice(&(off as u64).to_le_bytes());
        file[e + 24..e + 28].copy_from_slice(&(len as u32).to_le_bytes());
    }
    file[meta_off..meta_off + 8].copy_from_slice(b"metadata");
    file[meta_off + 10..meta_off + 12].copy_from_slice(&3u16.to_le_bytes());
    let items = 64 * KIB as usize;
    for (i, (guid, at, len)) in [(FILE_PARAMS, 0, 8), (DISK_SIZE, 8, 8), (SECTOR_SIZE, 16, 4)]
        .into_iter()
        .enumerate()
    {
        let e = meta_off + 32 + i * 32;
        file[e..e + 16].copy_from_slice(&guid);
        file[e + 16..e + 20].copy_from_slice(&((items + at) as u32).to_le_bytes());
        file[e + 20..e + 24].copy_from_slice(&(len as u32).to_le_bytes());
    }
    file[meta_off + items..meta_off + items + 4].copy_from_slice(&block.to_le_bytes());
    file[meta_off + items + 8..meta_off + items + 16].copy_from_slice(&size.to_le_bytes());
    file[meta_off + items + 16..meta_off + items + 20].copy_from_slice(&512u32.to_le_bytes());
    for (idx, data) in blocks {
        let at = file.len();
        file.extend_from_slice(&data);
        let entry = 6 | (((at as u64) >> 20) << 20);
        let b = bat_off + ((idx + idx / ratio) as usize) * 8;
        file[b..b + 8].copy_from_slice(&entry.to_le_bytes());
    }
    file
}

/// A sparse VMDK of `size` bytes holding `pieces`, in grains of 64 KiB.
fn vmdk_sparse(size: u64, pieces: &Pieces) -> Vec<u8> {
    vmdk_sparse_grains(size, pieces, 64 * KIB)
}

/// [`vmdk_sparse`] in grains of `grain` bytes.
fn vmdk_sparse_grains(size: u64, pieces: &Pieces, grain: u64) -> Vec<u8> {
    let grains = units(pieces, grain);
    let per_gde = 512 * grain;
    let num_gde = size.div_ceil(per_gde);
    let gd_sectors = (num_gde * 4).div_ceil(SECTOR);
    let mut file = vec![0u8; ((1 + gd_sectors) * SECTOR) as usize];
    let mut gts: BTreeMap<u64, usize> = BTreeMap::new();
    for idx in grains.keys() {
        let g = idx / 512;
        gts.entry(g).or_insert_with(|| {
            let at = file.len();
            file.resize(at + 2048, 0);
            let sector = (at / 512) as u32;
            file[512 + g as usize * 4..512 + g as usize * 4 + 4]
                .copy_from_slice(&sector.to_le_bytes());
            at
        });
    }
    for (idx, data) in grains {
        let sector = (file.len() / 512) as u32;
        file.extend_from_slice(&data);
        let at = gts[&(idx / 512)] + (idx % 512) as usize * 4;
        file[at..at + 4].copy_from_slice(&sector.to_le_bytes());
    }
    file[..4].copy_from_slice(b"KDMV");
    file[4..8].copy_from_slice(&1u32.to_le_bytes());
    file[12..20].copy_from_slice(&(size / SECTOR).to_le_bytes());
    file[20..28].copy_from_slice(&(grain / SECTOR).to_le_bytes());
    file[44..48].copy_from_slice(&512u32.to_le_bytes());
    file[56..64].copy_from_slice(&1u64.to_le_bytes());
    file[64..72].copy_from_slice(&(1 + gd_sectors).to_le_bytes());
    file
}

/// A streamOptimized VMDK of `size` bytes holding `pieces`.
fn vmdk_stream(size: u64, pieces: &Pieces) -> Vec<u8> {
    vmdk_stream_grains(size, pieces, 64 * KIB)
}

/// [`vmdk_stream`] in grains of `grain` bytes.
fn vmdk_stream_grains(size: u64, pieces: &Pieces, grain: u64) -> Vec<u8> {
    let mut file = vec![0u8; 512];
    file[..4].copy_from_slice(b"KDMV");
    file[4..8].copy_from_slice(&3u32.to_le_bytes());
    file[8..12].copy_from_slice(&(1u32 << 16).to_le_bytes());
    file[12..20].copy_from_slice(&(size / SECTOR).to_le_bytes());
    file[20..28].copy_from_slice(&(grain / SECTOR).to_le_bytes());
    file[44..48].copy_from_slice(&512u32.to_le_bytes());
    file[56..64].copy_from_slice(&u64::MAX.to_le_bytes());
    file[64..72].copy_from_slice(&1u64.to_le_bytes());
    file[77..79].copy_from_slice(&1u16.to_le_bytes());
    for (idx, data) in units(pieces, grain) {
        let z = zlib(&data);
        file.extend_from_slice(&(idx * grain / SECTOR).to_le_bytes());
        file.extend_from_slice(&(z.len() as u32).to_le_bytes());
        file.extend_from_slice(&z);
        file.resize(file.len().next_multiple_of(512), 0);
    }
    file.extend_from_slice(&[0u8; 512]);
    file
}

// ─── Walking ─────────────────────────────────────────────────────────────────

/// Limits under which a volume of `cap` bytes or more is read in place and a
/// disk of a few MiB is not held.
fn limits(cap: u64) -> Limits {
    let mut l = Limits::default();
    l.max_buffer_bytes = cap;
    l.max_extracted_bytes = 256 * MIB;
    l
}

/// What a walk of `blob` gave: every member, and how the walk ended.
fn walked(fmt: Format, blob: &[u8], limits: Limits) -> (Vec<Entry>, Result<(), LimitHit>) {
    let mut out = Vec::new();
    let mut budget = Budget::new(limits);
    let end = extract_each(fmt, blob, &mut budget, &mut |e: Entry, _: &mut Budget| {
        out.push(e);
        None::<()>
    });
    (out, end.map(|_| ()))
}

fn named<'a>(e: &'a [Entry], name: &str) -> &'a Entry {
    e.iter().find(|x| x.name == name).unwrap_or_else(|| {
        panic!(
            "no member {name}; got {:?}",
            e.iter()
                .map(|x| (&x.name, x.data.len(), x.unsupported))
                .collect::<Vec<_>>()
        )
    })
}

fn unreported(e: &[Entry]) {
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "nothing should be reported, got {:?}",
        e.iter()
            .filter(|x| x.unsupported.is_some())
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

// ─── The images qemu-img writes ──────────────────────────────────────────────

const REAL: &[(Format, &str)] = &[
    (Format::Qcow2, "fat4g.plain.qcow2"),
    (Format::Qcow2, "fat4g.deflate.qcow2"),
    #[cfg(feature = "zstd")]
    (Format::Qcow2, "fat4g.zstd.qcow2"),
    (Format::Vmdk, "fat4g.sparse.vmdk"),
    (Format::Vmdk, "fat4g.stream.vmdk"),
    (Format::Vhd, "fat4g.dynamic.vhd"),
    (Format::Vhdx, "fat4g.dynamic.vhdx"),
];

/// A file of a FAT volume at 3 GiB of a 4 GiB disk comes out under its
/// partition, whichever container the disk is in.
#[test]
fn a_file_at_the_end_of_a_four_gib_disk_comes_out_of_every_container() {
    for &(fmt, name) in REAL {
        let blob = gunzipped(name);
        assert_eq!(exav_unpack::detect(&blob), Some(fmt), "{name}");
        // Over the volume (128 KiB), so it is read in place, and under the disk.
        let (e, end) = walked(fmt, &blob, limits(64 * KIB));
        end.unwrap_or_else(|h| panic!("{name}: {h:?}"));
        unreported(&e);
        let p = named(&e, "mbr-part-1/sub/p.zip");
        assert_eq!(sha256_hex(&p.data), FAT_PAYLOAD, "{name}");
        assert!(
            e.iter().all(|x| x.data.len() as u64 <= 64 * KIB),
            "{name}: no member may pass the buffer limit"
        );
        assert!(
            !e.iter().any(|x| x.name.ends_with("-disk")),
            "{name}: the disk was held whole"
        );
    }
}

/// A disk that fits the limit is still handed over as one member, whose bytes
/// are the disk's: what `qemu-img convert -O raw` gives, which the image was
/// made from.
#[test]
fn a_disk_that_fits_the_limit_is_still_one_member() {
    // A small disk: the raw image of the existing fixtures.
    let d = super::diskimage::fixture("compressed.qcow2");
    let (e, end) = walked(Format::Qcow2, &d, limits(8 * MIB));
    end.unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].name, "qcow2-disk");
    assert_eq!(e[0].data.len(), 256 * KIB as usize);
}

// ─── Disks of any size ───────────────────────────────────────────────────────

/// Every container with the NTFS fixture (20 MiB, mostly zeros) at the end of a
/// disk of `size`, and the name each is walked under.
fn ntfs_images(size: u64, at: u64) -> Vec<(Format, &'static str, Vec<u8>)> {
    let ntfs = super::ntfs::fixture();
    let disk = mbr_disk(at, ntfs, 0x07);
    let mut v = vec![
        (
            Format::Qcow2,
            "qcow2",
            qcow2(size, 16, &disk, Packing::Stored),
        ),
        (
            Format::Qcow2,
            "qcow2 deflate",
            qcow2(size, 16, &disk, Packing::Deflate),
        ),
        (Format::Vmdk, "vmdk sparse", vmdk_sparse(size, &disk)),
        (Format::Vmdk, "vmdk stream", vmdk_stream(size, &disk)),
        (Format::Vhdx, "vhdx", vhdx(size, MIB as u32, &disk)),
    ];
    #[cfg(feature = "zstd")]
    v.push((
        Format::Qcow2,
        "qcow2 zstd",
        qcow2(size, 16, &disk, Packing::Zstd),
    ));
    v.push((Format::Vhd, "vhd", vhd(size, 2 * MIB as u32, &disk)));
    v
}

/// The NTFS volume of 20 MiB, near the end of a 256 GiB disk, is walked: its
/// files come out under the partition, none larger than the limit, and nothing
/// the size of the disk is built (that would be 256 GiB).
#[test]
fn an_ntfs_volume_deep_in_a_256_gib_disk_is_walked() {
    for (fmt, what, blob) in ntfs_images(256 * GIB, 250 * GIB) {
        let (e, end) = walked(fmt, &blob, limits(8 * MIB));
        end.unwrap_or_else(|h| panic!("{what}: {h:?}"));
        unreported(&e);
        let p = named(&e, "mbr-part-1/payload.zip");
        assert_eq!(sha256_hex(&p.data), NTFS_PAYLOAD, "{what}");
        named(&e, "mbr-part-1/small.txt");
        named(&e, "mbr-part-1/eicar.com");
        assert!(
            e.iter().map(|x| x.data.len() as u64).sum::<u64>() < 3 * MIB,
            "{what}: only the files and the boot area come out"
        );
    }
}

/// The same at a terabyte, where anything proportional to the disk is out of
/// reach of the machine.
#[test]
fn a_terabyte_disk_costs_what_it_holds() {
    let disk = mbr_disk(1000 * GIB, gunzipped_fat(), 0x01);
    let size = 1024 * GIB;
    let images = [
        (Format::Qcow2, qcow2(size, 16, &disk, Packing::Deflate)),
        (Format::Vmdk, vmdk_sparse(size, &disk)),
        (Format::Vmdk, vmdk_stream(size, &disk)),
    ];
    for (fmt, blob) in images {
        let (e, end) = walked(fmt, &blob, limits(64 * KIB));
        end.unwrap_or_else(|h| panic!("{fmt:?}: {h:?}"));
        let p = named(&e, "mbr-part-1/sub/p.zip");
        assert_eq!(sha256_hex(&p.data), FAT_PAYLOAD, "{fmt:?}");
    }
}

fn gunzipped_fat() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/fat/fragmented.img.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = exav_unpack::read_fixture(&p).unwrap();
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&raw[..]), &mut out).unwrap();
    out
}

// ─── Volumes written here ────────────────────────────────────────────────────

/// A FAT12 or FAT16 volume of `size` bytes holding `files` (names of 8.3 in
/// lower case, which the entry says with its case flags), each in a run of
/// clusters.
fn fat_volume(size: usize, files: &[(&str, &[u8])]) -> Vec<u8> {
    let sectors = size / 512;
    let root_sectors = 32;
    // The smallest cluster that keeps the volume within FAT16.
    let spc = [1usize, 2, 4, 8, 16, 32, 64]
        .into_iter()
        .find(|&s| (sectors - 1 - root_sectors) / s < 60000)
        .unwrap();
    let guess = (sectors - 1 - root_sectors) / spc;
    let bits = if guess < 4085 { 12 } else { 16 };
    let fat_sectors = ((guess + 2) * bits / 8).div_ceil(512);
    let first_data = 1 + 2 * fat_sectors + root_sectors;
    let clusters = (sectors - first_data) / spc;
    let mut d = vec![0u8; size];
    d[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    d[3..11].copy_from_slice(b"MSDOS5.0");
    d[11..13].copy_from_slice(&512u16.to_le_bytes());
    d[13] = spc as u8;
    d[14..16].copy_from_slice(&1u16.to_le_bytes());
    d[16] = 2;
    d[17..19].copy_from_slice(&512u16.to_le_bytes());
    // The sector count is in a 16-bit field, or in a 32-bit one when it is more.
    match u16::try_from(sectors) {
        Ok(n) => d[19..21].copy_from_slice(&n.to_le_bytes()),
        Err(_) => d[32..36].copy_from_slice(&(sectors as u32).to_le_bytes()),
    }
    d[21] = 0xF8;
    d[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
    d[38] = 0x29;
    d[54..62].copy_from_slice(if bits == 12 { b"FAT12   " } else { b"FAT16   " });
    d[510..512].copy_from_slice(&[0x55, 0xAA]);
    let fat = 512;
    let set = |d: &mut Vec<u8>, c: usize, v: usize| {
        for copy in 0..2 {
            let t = fat + copy * fat_sectors * 512;
            if bits == 16 {
                d[t + c * 2..t + c * 2 + 2].copy_from_slice(&(v as u16).to_le_bytes());
            } else {
                let at = t + c + c / 2;
                let pair = u16::from_le_bytes([d[at], d[at + 1]]);
                let pair = if c % 2 == 1 {
                    (pair & 0x000F) | ((v as u16) << 4)
                } else {
                    (pair & 0xF000) | v as u16
                };
                d[at..at + 2].copy_from_slice(&pair.to_le_bytes());
            }
        }
    };
    let end = if bits == 16 { 0xFFFF } else { 0xFFF };
    set(&mut d, 0, if bits == 16 { 0xFFF8 } else { 0xFF8 });
    set(&mut d, 1, end);
    let (mut next, root) = (2usize, fat + 2 * fat_sectors * 512);
    for (i, (name, data)) in files.iter().enumerate() {
        let n = data.len().div_ceil(spc * 512);
        assert!(next + n <= clusters + 2, "the volume is full");
        for c in next..next + n {
            set(&mut d, c, if c + 1 == next + n { end } else { c + 1 });
        }
        let at = first_data * 512 + (next - 2) * spc * 512;
        d[at..at + data.len()].copy_from_slice(data);
        let (base, ext) = name.split_once('.').unwrap_or((name, ""));
        let e = root + i * 32;
        d[e..e + 11].fill(b' ');
        d[e..e + base.len()].copy_from_slice(base.to_ascii_uppercase().as_bytes());
        d[e + 8..e + 8 + ext.len()].copy_from_slice(ext.to_ascii_uppercase().as_bytes());
        d[e + 11] = 0x20;
        d[e + 12] = 0x18;
        d[e + 26..e + 28].copy_from_slice(&(next as u16).to_le_bytes());
        d[e + 28..e + 32].copy_from_slice(&(data.len() as u32).to_le_bytes());
        next += n;
    }
    d
}

/// `n` bytes that compress, and differ from those of another `seed`.
fn patterned(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2654435761) | 1;
    let block: Vec<u8> = (0..4096)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    (0..n).map(|i| block[i % 4096] ^ (i >> 20) as u8).collect()
}

// ─── Reading back after eviction ─────────────────────────────────────────────

/// A 40 MiB file between two small ones, in 2 MiB compressed clusters: the walk
/// goes through more decoded clusters than the cache holds, so the first ones
/// are evicted while it goes on to the next file.
#[test]
fn a_walk_that_returns_to_evicted_clusters_reads_the_same_files() {
    let (a, big, z) = (
        patterned(3000, 1),
        patterned(40 << 20, 2),
        patterned(5000, 3),
    );
    let vol = fat_volume(64 << 20, &[("a.txt", &a), ("big.bin", &big), ("z.txt", &z)]);
    let blob = qcow2(2 * GIB, 21, &mbr_disk(GIB, vol, 0x06), Packing::Deflate);
    let (e, end) = walked(Format::Qcow2, &blob, limits(48 * MIB));
    end.unwrap();
    unreported(&e);
    for (name, want) in [("a.txt", &a), ("big.bin", &big), ("z.txt", &z)] {
        let got = named(&e, &format!("mbr-part-1/{name}"));
        assert!(got.data == *want, "{name} differs");
    }
}

// ─── What is read ────────────────────────────────────────────────────────────

/// A source in memory that counts the bytes it hands out and does not let a
/// caller borrow it whole.
struct Counting {
    data: Vec<u8>,
    read: std::cell::Cell<usize>,
}

impl Counting {
    fn new(data: Vec<u8>) -> Self {
        Counting {
            data,
            read: std::cell::Cell::new(0),
        }
    }
}

impl exav_unpack::ByteSource for Counting {
    fn len(&self) -> usize {
        self.data.len()
    }

    fn window(&self, off: usize, len: usize) -> std::borrow::Cow<'_, [u8]> {
        let start = off.min(self.data.len());
        let end = start.saturating_add(len).min(self.data.len());
        self.read.set(self.read.get() + (end - start));
        std::borrow::Cow::Borrowed(&self.data[start..end])
    }

    fn identity(&self) -> (usize, usize) {
        (self as *const Self as usize, self.data.len())
    }
}

fn walked_src(
    fmt: Format,
    src: &dyn exav_unpack::ByteSource,
    limits: Limits,
) -> (Vec<Entry>, Result<(), LimitHit>) {
    let mut out = Vec::new();
    let mut budget = Budget::new(limits);
    let end = exav_unpack::walk(fmt, src, &mut budget, &mut |meta, content, _| {
        // A stream is read as the engine reads it, which holds it up to its own
        // limit; the buffer limit is for members held whole.
        let data = match content {
            None => Vec::new(),
            Some(exav_unpack::Member::Bytes(d)) => d,
            Some(exav_unpack::Member::Stream(r)) => {
                let mut d = Vec::new();
                let _ = std::io::Read::read_to_end(r, &mut d);
                d
            }
        };
        out.push(Entry {
            name: meta.name.clone(),
            data,
            unsupported: meta.unsupported,
            ..Entry::default()
        });
        None::<()>
    });
    (out, end.map(|_| ()))
}

/// The files of an NTFS volume come out of a disk image without reading the
/// image: the walk reads the boot sector, the records it goes through and the
/// files, a small part of a volume that is mostly its own bookkeeping.
#[test]
fn a_walk_reads_a_small_part_of_the_image() {
    let disk = mbr_disk(250 * GIB, super::ntfs::fixture(), 0x07);
    let blob = qcow2(256 * GIB, 16, &disk, Packing::Stored);
    let src = Counting::new(blob);
    let (e, end) = walked_src(Format::Qcow2, &src, limits(8 * MIB));
    end.unwrap();
    named(&e, "mbr-part-1/payload.zip");
    let (read, size) = (src.read.get(), src.data.len());
    assert!(
        read < size / 2,
        "{read} of the image's {size} bytes were read: more than the metadata and the files"
    );
}

/// A raw NTFS image over the buffer limit used to be refused for being read
/// whole; it is walked, reading the volume where the walk goes.
#[test]
fn a_raw_ntfs_image_over_the_limit_is_walked_not_read_whole() {
    let src = Counting::new(super::ntfs::fixture());
    let (e, end) = walked_src(Format::Ntfs, &src, limits(8 * MIB));
    end.unwrap();
    unreported(&e);
    assert_eq!(sha256_hex(&named(&e, "payload.zip").data), NTFS_PAYLOAD);
    assert!(
        src.read.get() < src.data.len() / 4,
        "read {}",
        src.read.get()
    );
}

#[test]
fn a_raw_fat_image_over_the_limit_is_walked_not_read_whole() {
    let src = Counting::new(gunzipped_fat());
    let (e, end) = walked_src(Format::Fat, &src, limits(32 * KIB));
    end.unwrap();
    unreported(&e);
    assert_eq!(sha256_hex(&named(&e, "sub/p.zip").data), FAT_PAYLOAD);
}

/// A raw disk of 64 GiB, held as pieces: the walk asks for bytes by offset and
/// gets zeros for the rest.
#[cfg(target_pointer_width = "64")]
struct SparseDisk {
    len: usize,
    pieces: Pieces,
}

#[cfg(target_pointer_width = "64")]
impl exav_unpack::ByteSource for SparseDisk {
    fn len(&self) -> usize {
        self.len
    }

    fn window(&self, off: usize, len: usize) -> std::borrow::Cow<'_, [u8]> {
        let start = off.min(self.len);
        let n = len.min(self.len - start);
        let mut out = vec![0u8; n];
        for (at, bytes) in &self.pieces {
            let (from, to) = (*at as usize, *at as usize + bytes.len());
            let (lo, hi) = (from.max(start), to.min(start + n));
            if lo < hi {
                out[lo - start..hi - start].copy_from_slice(&bytes[lo - from..hi - from]);
            }
        }
        std::borrow::Cow::Owned(out)
    }

    fn identity(&self) -> (usize, usize) {
        (self as *const Self as usize, self.len)
    }
}

/// A raw partitioned disk of 64 GiB whose NTFS volume (20 MiB) is over the
/// limit: its files come out of the partition, which is not streamed.
#[cfg(target_pointer_width = "64")]
#[test]
fn a_raw_disk_larger_than_the_limit_is_walked_through_its_partitions() {
    let disk = SparseDisk {
        len: (64 * GIB) as usize,
        pieces: mbr_disk(60 * GIB, super::ntfs::fixture(), 0x07),
    };
    let (e, end) = walked_src(Format::Partition, &disk, limits(8 * MIB));
    end.unwrap();
    unreported(&e);
    assert_eq!(
        sha256_hex(&named(&e, "mbr-part-1/payload.zip").data),
        NTFS_PAYLOAD
    );
    assert!(!e.iter().any(|x| x.name == "mbr-part-1"));
}

/// A partition that fits the limit is still handed over as a stream of its
/// bytes, for the engine to type and scan as it always did.
#[cfg(target_pointer_width = "64")]
#[test]
fn a_partition_that_fits_the_limit_is_still_streamed() {
    let fat = gunzipped_fat();
    let disk = SparseDisk {
        len: (64 * GIB) as usize,
        pieces: mbr_disk(60 * GIB, fat.clone(), 0x01),
    };
    let (e, end) = walked_src(Format::Partition, &disk, limits(8 * MIB));
    end.unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].name, "mbr-part-1");
    assert!(e[0].data == fat);
}

/// Over the limit, a volume of a kind not read in place is still streamed from a
/// raw file: those bytes are the input, and the engine types and scans them.
#[cfg(target_pointer_width = "64")]
#[test]
fn a_raw_partition_over_the_limit_that_is_no_filesystem_is_still_streamed() {
    let blob = patterned(9 << 20, 7);
    let disk = SparseDisk {
        len: (64 * GIB) as usize,
        pieces: mbr_disk(60 * GIB, blob.clone(), 0x83),
    };
    let (e, end) = walked_src(Format::Partition, &disk, limits(8 * MIB));
    end.unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].name, "mbr-part-1");
    assert!(e[0].data == blob);
}

/// The same inside a virtual disk is reported: its size is what a header
/// declares, not bytes that were scanned already, and reading them could be a
/// walk through zeros.
#[test]
fn a_virtual_volume_over_the_limit_that_is_no_filesystem_is_reported() {
    let disk = mbr_disk(200 * GIB, patterned(9 << 20, 7), 0x83);
    let blob = qcow2(256 * GIB, 16, &disk, Packing::Deflate);
    let (e, end) = walked(Format::Qcow2, &blob, limits(8 * MIB));
    end.unwrap();
    let r = named(&e, "mbr-part-1");
    assert!(r.unsupported.is_some() && r.data.is_empty(), "{r:?}");
}

/// A partition table with no partition in it holds nothing, which is not a
/// disk that could not be read.
#[test]
fn a_table_with_no_partition_holds_nothing() {
    let mut gpt = vec![0u8; 512];
    gpt[..8].copy_from_slice(b"EFI PART");
    gpt[72..80].copy_from_slice(&2u64.to_le_bytes());
    gpt[84..88].copy_from_slice(&128u32.to_le_bytes());
    let blob = qcow2(256 * GIB, 16, &vec![(512, gpt)], Packing::Stored);
    let (e, end) = walked(Format::Qcow2, &blob, limits(8 * MIB));
    end.unwrap();
    assert!(
        e.is_empty(),
        "{:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
}

/// What lies before the first partition (the boot code) is scanned, within the
/// limit, since no filesystem walk reaches it.
#[test]
fn the_boot_area_of_a_walked_disk_comes_out() {
    let disk = mbr_disk(200 * GIB, gunzipped_fat(), 0x01);
    let blob = qcow2(256 * GIB, 16, &disk, Packing::Stored);
    let (e, end) = walked(Format::Qcow2, &blob, limits(64 * KIB));
    end.unwrap();
    let boot = named(&e, "<boot-area>");
    assert_eq!(boot.data.len(), 64 * KIB as usize);
    assert_eq!(boot.data[510..512], [0x55, 0xAA]);
}

/// An ext volume under the limit is streamed for the engine to walk, and one
/// over it is walked in place, from its own range of the disk.
#[test]
fn an_ext_volume_in_a_big_disk_is_read_from_its_own_range() {
    let ext = super::ext::fixture();
    let disk = mbr_disk(100 * GIB, ext.clone(), 0x83);
    let blob = qcow2(128 * GIB, 16, &disk, Packing::Deflate);
    let (e, end) = walked(Format::Qcow2, &blob, limits(8 * MIB));
    end.unwrap();
    assert!(named(&e, "mbr-part-1").data == ext);
    let (e, end) = walked(Format::Qcow2, &blob, limits(MIB));
    end.unwrap();
    unreported(&e);
    let p = named(&e, "mbr-part-1/sub/p.zip");
    assert_eq!(
        sha256_hex(&p.data),
        "d61da8b0c3cd1d5ffa812601aae787c81a7424850c4dca15c27e593f8f92fcc8"
    );
}

/// The raw volume of an Apple image: the disk of a UDRW image, which is its
/// bytes before the trailer, from where the filesystem's header says it starts.
#[cfg(feature = "dmg")]
fn apple_volume(dmg: &str, magic: &[u8], header_at: usize) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/dmg/{dmg}", env!("CARGO_MANIFEST_DIR"));
    let image = exav_unpack::read_fixture(&p).unwrap();
    let disk = &image[..image.len() - 512];
    let at = disk
        .windows(magic.len())
        .position(|w| w == magic)
        .unwrap_or_else(|| panic!("no filesystem in {dmg}"))
        - header_at;
    disk[at..].to_vec()
}

/// An HFS+ or an APFS volume in a disk is walked where it lies, as the others
/// are, and one that fits the limit is streamed as it was.
#[cfg(feature = "dmg")]
#[test]
fn an_hfs_plus_or_apfs_volume_in_a_big_disk_is_walked_from_its_own_range() {
    for (dmg, magic, header_at, ptype) in [
        ("hfs_plus_udrw.dmg", &[0x48u8, 0x2B, 0, 4][..], 1024, 0xAF),
        ("apfs_udrw.dmg", b"NXSB", 32, 0xAB),
    ] {
        let volume = apple_volume(dmg, magic, header_at);
        let disk = mbr_disk(100 * GIB, volume.clone(), ptype);
        let blob = qcow2(128 * GIB, 16, &disk, Packing::Deflate);
        let (e, end) = walked(Format::Qcow2, &blob, limits(volume.len() as u64 + 1));
        end.unwrap();
        assert!(named(&e, "mbr-part-1").data == volume, "{dmg}");
        let (e, end) = walked(Format::Qcow2, &blob, limits(volume.len() as u64 / 2));
        end.unwrap_or_else(|h| panic!("{dmg}: {h:?}"));
        unreported(&e);
        let hello = e
            .iter()
            .find(|x| x.name.starts_with("mbr-part-1/") && x.data.starts_with(b"hello hfs+"))
            .unwrap_or_else(|| {
                panic!("{dmg}: {:?}", e.iter().map(|x| &x.name).collect::<Vec<_>>())
            });
        assert!(hello.name.ends_with("test.txt"), "{dmg}: {}", hello.name);
    }
}

// ─── Bounds ──────────────────────────────────────────────────────────────────

/// The bytes a disk decodes are counted against the scan budget: an image of
/// 2 MiB compressed clusters cannot be walked on a budget of 1 MiB, and says
/// that is why.
#[test]
fn decoding_more_than_the_scan_budget_allows_is_a_limit_not_a_silent_stop() {
    let vol = fat_volume(9 << 20, &[("a.txt", &patterned(5000, 1))]);
    let blob = qcow2(GIB, 21, &mbr_disk(512 * MIB, vol, 0x06), Packing::Deflate);
    let (e, end) = walked(Format::Qcow2, &blob, limits(8 * MIB));
    end.unwrap();
    named(&e, "mbr-part-1/a.txt");

    let mut tight = limits(8 * MIB);
    // Room for the boot area and the file, not for the clusters decoded to get
    // to them.
    tight.max_scanned_bytes = 3 * MIB;
    let (_, end) = walked(Format::Qcow2, &blob, tight);
    let hit = end.expect_err("a walk that decodes past its budget must not end as clean");
    assert_eq!(hit.kind, exav_unpack::LimitKind::MaxScanSize, "{hit:?}");
}

// ─── Hostile images ──────────────────────────────────────────────────────────

/// A 64 MiB disk with a 9 MiB FAT volume in the middle: over a limit of 8 MiB,
/// so read in place, in every container.
fn small_images() -> Vec<(Format, &'static str, Vec<u8>)> {
    let vol = fat_volume(
        9 << 20,
        &[
            ("a.txt", &patterned(3000, 1)),
            ("b.bin", &patterned(70_000, 2)),
        ],
    );
    let disk = mbr_disk(32 * MIB, vol, 0x06);
    let size = 64 * MIB;
    vec![
        (
            Format::Qcow2,
            "qcow2",
            qcow2(size, 16, &disk, Packing::Stored),
        ),
        (
            Format::Qcow2,
            "qcow2 deflate",
            qcow2(size, 16, &disk, Packing::Deflate),
        ),
        (Format::Vmdk, "vmdk sparse", vmdk_sparse(size, &disk)),
        (Format::Vmdk, "vmdk stream", vmdk_stream(size, &disk)),
        (Format::Vhd, "vhd", vhd(size, 2 * MIB as u32, &disk)),
        (Format::Vhdx, "vhdx", vhdx(size, MIB as u32, &disk)),
    ]
}

#[test]
fn the_small_images_are_walked_in_place() {
    for (fmt, what, blob) in small_images() {
        let (e, end) = walked(fmt, &blob, limits(8 * MIB));
        end.unwrap_or_else(|h| panic!("{what}: {h:?}"));
        unreported(&e);
        assert_eq!(
            named(&e, "mbr-part-1/a.txt").data,
            patterned(3000, 1),
            "{what}"
        );
        assert_eq!(
            named(&e, "mbr-part-1/b.bin").data,
            patterned(70_000, 2),
            "{what}"
        );
    }
}

/// Each header and table field at the top of its range, one at a time: no
/// panic, and no walk that fails to end. The disk is read in place, so a
/// field that moves a table, a size or a count is followed into the
/// filesystem walk.
#[test]
fn container_fields_at_their_extremes() {
    use super::extreme::{none, sectors, sweep};
    let mut bad = Vec::new();
    for (fmt, what, blob) in small_images() {
        let regions: Vec<std::ops::Range<usize>> = match what {
            "vhd" => vec![0..512, 512..1536, 1536..1700],
            // The region table, the metadata table and its items, the start of
            // the block allocation table.
            "vhdx" => vec![
                0..16,
                192 * 1024..192 * 1024 + 96,
                256 * 1024..256 * 1024 + 96,
                (MIB as usize)..(MIB as usize) + 64,
                2 * MIB as usize..2 * MIB as usize + 160,
                2 * MIB as usize + 64 * 1024..2 * MIB as usize + 64 * 1024 + 24,
            ],
            _ => sectors(&blob, 24, 128),
        };
        bad.extend(
            sweep(fmt, &blob, &regions)
                .into_iter()
                .map(|w| format!("{what} {w}")),
        );
    }
    none(bad);
}

/// An image cut anywhere: no panic, and what comes out of a file is its bytes
/// or zeros where the cut took them. A cluster that is not all there is absent,
/// not read as something else.
#[test]
fn an_image_cut_anywhere_never_gives_content_it_did_not_have() {
    let (a, b) = (patterned(3000, 1), patterned(70_000, 2));
    for (fmt, what, blob) in small_images() {
        let step = blob.len() / 50 + 1;
        let cuts = (0..blob.len())
            .step_by(step)
            .chain((0..4096).step_by(53))
            .chain([blob.len() - 1, blob.len() - 512]);
        for cut in cuts {
            let (e, end) = walked(fmt, &blob[..cut], limits(8 * MIB));
            if let Err(h) = &end {
                assert!(!h.reason.contains("panicked"), "{what} cut at {cut}: {h:?}");
            }
            for (name, want) in [("a.txt", &a), ("b.bin", &b)] {
                let found = e
                    .iter()
                    .find(|x| x.name == format!("mbr-part-1/{name}") && x.unsupported.is_none());
                if let Some(f) = found {
                    // A file whose chain is in the part that was cut ends where
                    // the filesystem's own table does, so it can be short.
                    assert!(
                        f.data.len() <= want.len(),
                        "{what} cut at {cut}: {name} is longer than the file"
                    );
                    assert!(
                        f.data
                            .iter()
                            .zip(want.iter())
                            .all(|(g, w)| g == w || *g == 0),
                        "{what} cut at {cut}: {name} holds bytes the image does not"
                    );
                }
            }
        }
    }
}

/// A cut inside the table that says where everything is leaves nothing to
/// follow, which is said.
#[test]
fn a_cut_inside_a_table_is_reported() {
    let images = small_images();
    let image = |what: &str| images.iter().find(|i| i.1 == what).unwrap();
    for (what, at) in [
        ("qcow2", 64 * KIB as usize + 4),
        ("vmdk sparse", 514),
        ("vhd", 1540),
        ("vhdx", MIB as usize + 100),
    ] {
        let (fmt, _, blob) = image(what);
        let (e, end) = walked(*fmt, &blob[..at], limits(8 * MIB));
        end.unwrap_or_else(|h| panic!("{what}: {h:?}"));
        assert!(
            e.iter().any(|x| x.unsupported.is_some()),
            "{what}: a table that is not there must be reported, got {:?}",
            e.iter()
                .map(|x| (&x.name, x.unsupported))
                .collect::<Vec<_>>()
        );
        assert!(e.iter().all(|x| x.data.is_empty()), "{what}");
    }
}

/// Tables that point where nothing is, claim sizes nothing could have, or name
/// units that do not decode: the walk ends, and it does not end quietly with
/// less than the image holds.
#[test]
fn hostile_tables_do_not_end_clean_or_in_a_panic() {
    let images = small_images();
    let image = |what: &str| images.iter().find(|i| i.1 == what).unwrap();
    let top = u64::MAX.to_le_bytes();
    let mib = MIB as usize;
    // (image, what is changed, where, to what)
    let cases: Vec<(&str, &str, usize, Vec<u8>)> = vec![
        (
            "qcow2",
            "L1 entry beyond the file",
            64 * 1024,
            (u64::MAX >> 1 & !511).to_be_bytes().to_vec(),
        ),
        (
            "qcow2",
            "L1 table of 2^32 entries",
            36,
            u32::MAX.to_be_bytes().to_vec(),
        ),
        ("qcow2", "cluster bits", 20, 21u32.to_be_bytes().to_vec()),
        (
            "qcow2 deflate",
            "L1 entry beyond the file",
            64 * 1024,
            (u64::MAX >> 1 & !511).to_be_bytes().to_vec(),
        ),
        (
            "vmdk sparse",
            "directory entry beyond the file",
            512,
            u32::MAX.to_le_bytes().to_vec(),
        ),
        (
            "vmdk sparse",
            "grain table size",
            44,
            (1u32 << 20).to_le_bytes().to_vec(),
        ),
        ("vmdk sparse", "capacity", 12, top.to_vec()),
        (
            "vmdk stream",
            "grain longer than the file",
            512 + 8,
            u32::MAX.to_le_bytes().to_vec(),
        ),
        (
            "vmdk stream",
            "grain at the top of the disk",
            512,
            top.to_vec(),
        ),
        (
            "vhd",
            "table entry beyond the file",
            1536,
            (u32::MAX - 1).to_be_bytes().to_vec(),
        ),
        (
            "vhd",
            "table of 2^32 entries",
            512 + 28,
            u32::MAX.to_be_bytes().to_vec(),
        ),
        (
            "vhdx",
            "table entry beyond the file",
            mib,
            (6 | (u64::MAX >> 20 << 20)).to_le_bytes().to_vec(),
        ),
        (
            "vhdx",
            "disk of 2^64 bytes",
            2 * mib + 64 * 1024 + 8,
            top.to_vec(),
        ),
        (
            "vhdx",
            "block of 256 MiB",
            2 * mib + 64 * 1024,
            (1u32 << 28).to_le_bytes().to_vec(),
        ),
    ];
    let a = patterned(3000, 1);
    for (what, change, at, to) in cases {
        let (fmt, _, blob) = image(what);
        let mut blob = blob.clone();
        blob[at..at + to.len()].copy_from_slice(&to);
        let (e, end) = walked(*fmt, &blob, limits(8 * MIB));
        if let Err(h) = &end {
            assert!(!h.reason.contains("panicked"), "{what}, {change}: {h:?}");
            continue;
        }
        let kept = e
            .iter()
            .any(|x| x.name == "mbr-part-1/a.txt" && x.data == a);
        assert!(
            kept || e.iter().any(|x| x.unsupported.is_some()),
            "{what}, {change}: neither the files nor a report, got {:?}",
            e.iter()
                .map(|x| (&x.name, x.unsupported))
                .collect::<Vec<_>>()
        );
    }
}

/// The seeds of `fuzz/seeds/vdisk`: a 1 MiB disk holding an MBR and a FAT
/// volume of 70 KiB (over the fuzz target's buffer limit, so walked in place),
/// small enough to fit the fuzzer's inputs, each behind the byte that picks the
/// format the target tries. Written with
/// `EXAV_DEBUG_WRITE_SEEDS=fuzz/seeds/vdisk cargo test -p exav-unpack --test all write_the_fuzz_seeds -- --ignored`.
#[test]
#[ignore = "writes the committed fuzz seeds"]
fn write_the_fuzz_seeds() {
    let dir = std::env::var("EXAV_DEBUG_WRITE_SEEDS")
        .expect("EXAV_DEBUG_WRITE_SEEDS names the directory");
    let vol = fat_volume(70 * 1024, &[("a.txt", &patterned(300, 1))]);
    let disk = mbr_disk(128 * KIB, vol, 0x01);
    let size = MIB;
    let images: Vec<(&str, u8, Vec<u8>)> = vec![
        ("qcow2.bin", 0, qcow2(size, 9, &disk, Packing::Stored)),
        (
            "qcow2_deflate.bin",
            0,
            qcow2(size, 9, &disk, Packing::Deflate),
        ),
        #[cfg(feature = "zstd")]
        ("qcow2_zstd.bin", 0, qcow2(size, 9, &disk, Packing::Zstd)),
        (
            "vmdk_sparse.bin",
            1,
            vmdk_sparse_grains(size, &disk, 4 * KIB),
        ),
        (
            "vmdk_stream.bin",
            1,
            vmdk_stream_grains(size, &disk, 4 * KIB),
        ),
        ("vhd.bin", 2, vhd(size, 4096, &disk)),
    ];
    for (name, pick, image) in images {
        assert!(image.len() < 24 * 1024, "{name}: {} bytes", image.len());
        // Each is a seed because the walk reaches the file in the volume.
        let fmt = [Format::Qcow2, Format::Vmdk, Format::Vhd][usize::from(pick)];
        let (e, end) = walked(fmt, &image, limits(64 * KIB));
        end.unwrap();
        named(&e, "mbr-part-1/a.txt");
        let mut seed = vec![pick];
        seed.extend_from_slice(&image);
        std::fs::write(std::path::Path::new(&dir).join(name), seed).unwrap();
    }
}
