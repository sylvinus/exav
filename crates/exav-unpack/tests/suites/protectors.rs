//! Virtualizing protectors must be recognised and reported, never passed over.
//!
//! VMProtect, Themida/WinLicense and Enigma are the three most common packers in
//! current sample sets — more common than every packer any engine unpacks, by an
//! order of magnitude. None of them can be unpacked: the protected functions are
//! translated into a private bytecode when the file is *built*, so unlike a
//! compressor there is no original code sitting in memory at runtime to recover.
//! No engine unpacks them, and a better emulator would not change that.
//!
//! What exav can do is say so. Silence on the most prevalent packers in the wild
//! is the one outcome worse than not unpacking them — it reads identically to
//! "we looked and found nothing".

use exav_unpack::{extract, Budget, Format, Limits};

/// Build a minimal but structurally valid PE with the given section names.
fn pe_with_sections(names: &[&[u8]]) -> Vec<u8> {
    const FA: u32 = 0x200;
    const SA: u32 = 0x1000;
    let mut opt = Vec::new();
    opt.extend_from_slice(&0x10bu16.to_le_bytes()); // PE32 magic
    opt.extend_from_slice(&[1, 0]); // linker version
    for v in [FA, 0, 0, 0x1000, 0x1000, 0x1000, 0x0040_0000u32] {
        opt.extend_from_slice(&v.to_le_bytes());
    }
    for v in [SA, FA] {
        opt.extend_from_slice(&v.to_le_bytes());
    }
    for v in [4u16, 0, 0, 0, 4, 0] {
        opt.extend_from_slice(&v.to_le_bytes());
    }
    for v in [0x3000u32, 0x400, 0, 2] {
        opt.extend_from_slice(&v.to_le_bytes());
    }
    for v in [0u16, 0] {
        opt.extend_from_slice(&v.to_le_bytes());
    }
    for v in [0x10_0000u32, 0x1000, 0x10_0000, 0x1000, 0, 16] {
        opt.extend_from_slice(&v.to_le_bytes());
    }
    opt.extend_from_slice(&[0u8; 16 * 8]); // data directories

    let mut nt = b"PE\0\0".to_vec();
    nt.extend_from_slice(&0x14cu16.to_le_bytes()); // i386
    nt.extend_from_slice(&(names.len() as u16).to_le_bytes());
    nt.extend_from_slice(&[0u8; 12]); // timestamp, symbols
    nt.extend_from_slice(&(opt.len() as u16).to_le_bytes());
    nt.extend_from_slice(&0x102u16.to_le_bytes());
    nt.extend_from_slice(&opt);

    let mut secs = Vec::new();
    for (i, n) in names.iter().enumerate() {
        let mut name = [0u8; 8];
        name[..n.len().min(8)].copy_from_slice(&n[..n.len().min(8)]);
        secs.extend_from_slice(&name);
        for v in [FA, 0x1000 * (i as u32 + 1), FA, 0x400 + FA * i as u32, 0, 0] {
            secs.extend_from_slice(&v.to_le_bytes());
        }
        secs.extend_from_slice(&[0u8; 4]); // reloc/line counts
        secs.extend_from_slice(&0x6000_0020u32.to_le_bytes());
    }

    let mut out = b"MZ".to_vec();
    out.resize(0x3c, 0);
    out.extend_from_slice(&0x40u32.to_le_bytes());
    out.extend_from_slice(&nt);
    out.extend_from_slice(&secs);
    out.resize(0x400, 0);
    out.resize(0x400 + FA as usize * names.len(), 0x90);
    out
}

/// Ask the PE-packer extractor directly. `detect()` does not route a bare PE
/// here — a PE is not a container by magic — so the scanner reaches this path
/// through its own content-aware routing. A library caller has to name it.
fn reported_reason(pe: &[u8]) -> Option<&'static str> {
    let mut b = Budget::new(Limits::default());
    let entries = extract(Format::PePacked, pe, &mut b).ok()?;
    entries.into_iter().find_map(|e| e.unsupported)
}

#[test]
fn every_virtualizing_protector_is_recognised() {
    for (name, sections) in [
        ("VMProtect", vec![&b".vmp0"[..], &b".vmp1"[..]]),
        (
            "Themida (capitalised)",
            vec![&b"Themida"[..], &b".rsrc"[..]],
        ),
        ("Themida (lowercase)", vec![&b".themida"[..], &b".rsrc"[..]]),
        ("WinLicense", vec![&b".winlice"[..], &b".rsrc"[..]]),
        ("Enigma", vec![&b".enigma1"[..], &b".enigma2"[..]]),
    ] {
        let pe = pe_with_sections(&sections);
        let reason = reported_reason(&pe).unwrap_or_else(|| {
            panic!(
                "{name}: went unreported — a silent pass on the \
                                       most prevalent packers in the wild"
            )
        });
        assert!(
            reason.contains("virtualizer"),
            "{name}: reported, but with the compressor wording. A virtualizer has \
             no original image to recover, and saying otherwise sends the reader \
             looking for an unpacker that cannot exist. Got: {reason}"
        );
    }
}

#[test]
fn an_ordinary_pe_is_not_flagged() {
    // The markers must be specific. Flagging every PE as protected would make
    // the verdict meaningless.
    let pe = pe_with_sections(&[&b".text"[..], &b".rdata"[..], &b".data"[..]]);
    assert!(
        reported_reason(&pe).is_none(),
        "an ordinary PE must not be reported as protected"
    );
}
