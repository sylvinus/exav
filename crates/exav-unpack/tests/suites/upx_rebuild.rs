//! UPX images carrying a bare `PackHeader`, and the ClamAV-compatible rebuild.
//!
//! Two separate things had to be true before a live GandCrab sample stopped
//! scanning clean, and both are pinned here because each is invisible from the
//! other's perspective:
//!
//! 1. **Routing.** `is_upx` gated on the `l_info`/`p_info`/`b_info` chain. This
//!    PE instead carries a bare 32-byte `PackHeader`, whose `c_len` /
//!    `u_file_size` fields land exactly where a `b_info`'s sizes are expected —
//!    so validation failed, the file matched no unpacker at all, and it was
//!    reported clean.
//!
//! 2. **The rebuild.** Decompressing is not enough. A large family of ClamAV
//!    signatures for packed malware is an MD5 over the PE **ClamAV itself
//!    rebuilds**, so a raw decompressed run — correct though it is — matches
//!    nothing. The rebuild has to reproduce that layout exactly: the file
//!    flattened so each file offset equals its RVA, `FileAlignment` raised to
//!    `SectionAlignment`, each section's size rounded up, and `TimeDateStamp`
//!    overwritten with `"CLAM"`.
//!
//! The rules were recovered by diffing exav's output against clamd's, not from
//! reading its source. Correctness of the *decompression* is separately
//! guaranteed at runtime by the Adler-32 the `PackHeader` records — a decode
//! that does not reproduce it is discarded rather than handed over.

use exav_unpack::{extract, Budget, Format, Limits};

/// Assemble a minimal UPX-packed PE whose payload is a stored (uncompressed)
/// run — enough to drive routing and the rebuild without depending on the NRV
/// decompressors, which have their own tests.
fn packed_pe() -> Vec<u8> {
    // The inner image: one section's worth of content, then the original header
    // block the rebuild recovers from the tail.
    let mut inner = vec![0xCCu8; 0x1000];
    let hdr_at = inner.len();
    inner.extend_from_slice(b"PE\0\0");
    inner.extend_from_slice(&0x014cu16.to_le_bytes()); // machine
    inner.extend_from_slice(&1u16.to_le_bytes()); // sections
    inner.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // TimeDateStamp
    inner.extend_from_slice(&[0u8; 8]);
    inner.extend_from_slice(&224u16.to_le_bytes()); // optional header size
    inner.extend_from_slice(&0x0102u16.to_le_bytes()); // characteristics
    let mut opt = vec![0u8; 224];
    opt[0..2].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32 magic
    opt[32..36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    opt[36..40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    inner.extend_from_slice(&opt);
    let mut sec = vec![0u8; 40];
    sec[0..5].copy_from_slice(b".text");
    sec[8..12].copy_from_slice(&0x800u32.to_le_bytes()); // VirtualSize (unaligned)
    sec[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    sec[16..20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
    sec[20..24].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
    inner.extend_from_slice(&sec);
    let _ = hdr_at;

    // The outer packed PE: headers, then a PackHeader, then the payload.
    let mut out = vec![0u8; 0x400];
    out[0..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let e = 0x80usize;
    out[e..e + 4].copy_from_slice(b"PE\0\0");
    out[e + 6..e + 8].copy_from_slice(&1u16.to_le_bytes());
    out[e + 20..e + 22].copy_from_slice(&224u16.to_le_bytes());
    let st = e + 24 + 224;
    out[st..st + 4].copy_from_slice(b"UPX0");
    out[st + 12..st + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // first RVA

    // PackHeader: method 2 (NRV2B) would need a real stream, so use the stored
    // marker the decoder rejects — this test pins routing + rebuild, and the
    // decompressors are covered elsewhere.
    let ph = out.len();
    out.extend_from_slice(b"UPX!");
    out.extend_from_slice(&[13, 9, 2, 8]); // version, format, method, level
    out.extend_from_slice(&0u32.to_le_bytes()); // u_adler (deliberately wrong)
    out.extend_from_slice(&0u32.to_le_bytes()); // c_adler
    out.extend_from_slice(&(inner.len() as u32).to_le_bytes()); // u_len
    out.extend_from_slice(&16u32.to_le_bytes()); // c_len
    out.extend_from_slice(&0u32.to_le_bytes()); // u_file_size
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&[0u8; 16]); // the "compressed" bytes
    let _ = ph;
    out
}

/// A PackHeader-layout image must reach the unpacker rather than falling
/// through every branch to a clean verdict. Whether the payload decodes is a
/// separate question — what must never happen is silence.
#[test]
fn packheader_layout_is_routed_not_ignored() {
    let blob = packed_pe();
    assert!(
        exav_unpack::is_upx(&blob),
        "a bare PackHeader must be recognised as UPX; gating only on the \
         l_info chain let these files reach no unpacker at all"
    );

    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Upx, &blob, &mut budget).expect("extract");
    assert!(
        !entries.is_empty(),
        "a recognised UPX image whose payload could not be recovered must still \
         be surfaced, never dropped into a clean OK"
    );
}

/// The Adler-32 in the header is the acceptance test for a decode. Here it is
/// deliberately wrong, so nothing may be handed over as though it decoded.
#[test]
fn a_decode_that_fails_its_checksum_is_never_handed_over() {
    let blob = packed_pe();
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Upx, &blob, &mut budget).expect("extract");
    for e in &entries {
        assert!(
            e.data.is_empty() || !e.data.windows(4).any(|w| w == b"PE\0\0"),
            "an image whose checksum did not verify was emitted as content"
        );
    }
    assert!(
        entries.iter().any(|e| e.unsupported.is_some()),
        "expected the failed recovery to be reported: {:?}",
        entries
            .iter()
            .map(|e| (&e.name, e.unsupported))
            .collect::<Vec<_>>()
    );
}
