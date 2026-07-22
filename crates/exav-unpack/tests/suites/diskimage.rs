//! Virtual disk images — QCOW2, VMDK and VHDX.
//!
//! These matter to a scanner rather than merely to a hypervisor: `qemu-img
//! convert -c` deflates each QCOW2 cluster, and a streamOptimized VMDK (the
//! shape found inside an OVA appliance) deflates each grain. A payload in
//! either appears nowhere in the file's bytes, so a raw pattern scan sees
//! nothing and only real reconstruction reaches it.
//!
//! VHDX stores its blocks uncompressed, so the stake there is different: blocks
//! sit in arbitrary file order, and Windows mounts the format on double-click.
//!
//! The fixtures come from **qemu-img** and the expected digest is the digest of
//! the raw image qemu-img itself produces — not this crate's output. A decoder
//! checked against a matching encoder can agree on a shared misreading; a
//! mismatch here is exav's.
//!
//! Regenerate with:
//! ```sh
//! qemu-img convert -f raw -O qcow2 -c -o cluster_size=512 small.img compressed.qcow2
//! qemu-img convert -f raw -O vmdk -o subformat=streamOptimized small.img streamoptimized.vmdk
//! qemu-img convert -f raw -O vmdk small.img sparse.vmdk
//! qemu-img convert -f raw -O vhdx -o block_size=1M small.img dynamic.vhdx && gzip -9 dynamic.vhdx
//! qemu-img convert -f raw -O qcow2 -c -o cluster_size=512 odd.img compressed_odd_offset.qcow2
//! ```
//!
//! The VHDX is stored gzipped only because its 1 MiB-aligned regions make even a
//! 256 KiB disk a 9 MiB file; the bytes inside are qemu-img's, unmodified.

use exav_unpack::{extract_each, Budget, Entry, Format, Limits};

/// `sha256sum` of the 256 KiB raw image the fixtures were built from, which is
/// also what `qemu-img convert -O raw` returns for each of them.
const RAW_SHA256: &str = "f456367a5c6caff15823c0c77b4711d2b1d01b85dfe32de783077d597f7c67a7";

/// A deflated ZIP sits at offset 4096 of that image, so the EICAR string is
/// absent from the fixtures' bytes and cannot be found without reconstruction.
const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/diskimage/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    if !name.ends_with(".gz") {
        return raw;
    }
    let mut out = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(std::io::Cursor::new(raw)),
        &mut out,
    )
    .unwrap_or_else(|e| panic!("gunzip {p}: {e}"));
    out
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn members(fmt: Format, blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits {
        max_buffer_bytes: 8 * 1024 * 1024,
        max_extracted_bytes: 16 * 1024 * 1024,
        ..Limits::default()
    });
    let _ = extract_each(fmt, blob, &mut b, &mut |e: Entry, _: &mut Budget| {
        out.push(e);
        None::<()>
    });
    out
}

/// The single reconstructed-disk member, which must have decoded cleanly.
fn disk(fmt: Format, name: &str) -> Vec<u8> {
    let e = members(fmt, &fixture(name));
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "{name} must decode, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    let d = e.into_iter().next().unwrap_or_else(|| {
        panic!("{name} produced no member at all — its contents would go unscanned")
    });
    d.data
}

#[test]
fn a_compressed_qcow2_reconstructs_byte_for_byte() {
    let d = disk(Format::Qcow2, "compressed.qcow2");
    assert_eq!(
        sha256_hex(&d),
        RAW_SHA256,
        "the guest disk must match `qemu-img convert -O raw` — a cluster \
         descriptor read subtly wrong still yields plausible-looking output"
    );
}

#[test]
fn a_streamoptimized_vmdk_reconstructs_byte_for_byte() {
    let d = disk(Format::Vmdk, "streamoptimized.vmdk");
    assert_eq!(sha256_hex(&d), RAW_SHA256);
}

#[test]
fn a_sparse_vmdk_reconstructs_byte_for_byte() {
    let d = disk(Format::Vmdk, "sparse.vmdk");
    assert_eq!(sha256_hex(&d), RAW_SHA256);
}

#[test]
fn a_dynamic_vhdx_reconstructs_byte_for_byte() {
    let d = disk(Format::Vhdx, "dynamic.vhdx.gz");
    assert_eq!(
        sha256_hex(&d),
        RAW_SHA256,
        "the guest disk must match `qemu-img convert -O raw` — a block \
         allocation table misread as empty yields a full-size disk of zeroes, \
         which scans clean"
    );
}

#[test]
fn a_vhdx_whose_block_table_is_short_says_so() {
    // Truncating the BAT region's declared length leaves the payload blocks
    // unlocatable. The reconstructed disk is then a plausible-looking expanse of
    // zeroes, so staying quiet about it would be a silent clean.
    let mut raw = fixture("dynamic.vhdx.gz");
    // Region table 1 at 192 KiB: entries are GUID(16) + offset(8) + length(4).
    // The BAT is the first entry in qemu-img's output.
    let len_at = 192 * 1024 + 16 + 16 + 8;
    raw[len_at..len_at + 4].copy_from_slice(&0u32.to_le_bytes());

    let e = members(Format::Vhdx, &raw);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "an unusable block allocation table must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_qcow2_cluster_that_will_not_inflate_says_so() {
    // Corrupting the compressed cluster's deflate stream leaves a cluster-sized
    // hole of zeroes in the reconstructed disk. Nothing about that hole looks
    // wrong to a pattern scanner, so the extractor has to say it is there.
    //
    // The fixture holds exactly one compressed cluster, in the file's final
    // 512-byte cluster (`a_compressed_qcow2_reconstructs_byte_for_byte` covers
    // the pristine case, so a fixture that stopped matching this layout would
    // not fail silently).
    let mut raw = fixture("compressed.qcow2");
    let cluster = raw.len() - 512;
    for b in &mut raw[cluster..cluster + 16] {
        *b ^= 0xFF;
    }

    let e = members(Format::Qcow2, &raw);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "a cluster that could not be decompressed must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    assert!(
        e.iter().any(|x| !x.data.is_empty()),
        "the rest of the disk must still be handed over for scanning"
    );
}

#[test]
fn a_streamoptimized_grain_that_will_not_inflate_says_so() {
    let mut raw = fixture("streamoptimized.vmdk");
    // The first grain marker sits at `overhead * 512`; its deflate stream starts
    // 12 bytes in. Corrupting that leaves the grain's guest range zero-filled.
    let overhead = u64::from_le_bytes(raw[64..72].try_into().unwrap()) as usize * 512;
    let start = overhead + 12;
    for b in &mut raw[start..start + 32] {
        *b ^= 0xFF;
    }

    let e = members(Format::Vmdk, &raw);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "a grain that could not be decompressed must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_compressed_cluster_at_an_odd_host_offset_is_not_dropped() {
    // Bit 0 of an L2 entry means "this cluster reads as zeroes" — but only for a
    // *plain* entry. In a compressed descriptor it is part of the host offset,
    // so testing it unconditionally drops every compressed cluster that happens
    // to start at an odd byte. The cluster does not error: it becomes a hole of
    // zeroes, which scans perfectly clean.
    //
    // This image has two compressed clusters, the second at an odd offset, so a
    // decoder with that bug returns a disk that is byte-perfect except for the
    // one cluster holding the payload.
    let d = disk(Format::Qcow2, "compressed_odd_offset.qcow2");
    assert!(
        d.windows(4).any(|w| w == b"PK\x03\x04"),
        "the cluster at an odd host offset must be decoded, not zero-filled"
    );
}

#[test]
fn the_payload_is_absent_from_the_compressed_fixtures() {
    // Guards the premise of the tests above: if the EICAR string were visible in
    // the raw bytes, a scanner would find it without decoding anything and these
    // fixtures would prove nothing about the decoders.
    for name in ["compressed.qcow2", "streamoptimized.vmdk"] {
        let raw = fixture(name);
        assert!(
            !raw.windows(EICAR.len()).any(|w| w == EICAR),
            "{name} must not expose the payload in its own bytes"
        );
    }
}

#[test]
fn the_payload_is_reachable_after_reconstruction() {
    for (fmt, name) in [
        (Format::Qcow2, "compressed.qcow2"),
        (Format::Vmdk, "streamoptimized.vmdk"),
        (Format::Vmdk, "sparse.vmdk"),
        (Format::Vhdx, "dynamic.vhdx.gz"),
    ] {
        let d = disk(fmt, name);
        assert!(
            d.windows(4).any(|w| w == b"PK\x03\x04"),
            "{name}: the embedded archive must survive reconstruction"
        );
    }
}
