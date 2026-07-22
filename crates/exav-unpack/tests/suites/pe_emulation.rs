//! Emulation-based unpacking of PE runtime packers, through the public API.
//!
//! A runtime packer's format is whatever its author chose; what every one of
//! them has in common is that the stub must rebuild the original image in
//! memory and jump to it. exav runs the stub in a sandboxed x86 interpreter and
//! captures that moment, which is why it does not need a decoder per packer —
//! and why a packer nobody has written a decoder for still gets unpacked.
//!
//! These tests drive the public `extract(Format::PePacked, …)` entry point with
//! hand-assembled stubs, so what is covered is the contract a caller sees: a
//! recovered image, a bounded run, and nothing invented when there is nothing
//! to recover.

use exav_unpack::{extract, is_pepack, Budget, Format, Limits};

const IMAGE_BASE: u32 = 0x0040_0000;
const DEST_RVA: u32 = 0x1000;
const DEST_VSIZE: u32 = 0xd000;
const STUB_RVA: u32 = 0xe000;
/// Where the payload sits inside the stub section.
const PAYLOAD_OFF: usize = 0x1000;

/// Build a PE with the shape a packed file has: a destination section that
/// exists only in memory, and a writable section holding the stub, the packed
/// payload and the entry point.
fn packed_pe(stub: &[u8], payload: &[u8]) -> Vec<u8> {
    let pe_off = 0x80usize;
    let opt_size = 0xe0usize;
    let sec_table = pe_off + 24 + opt_size;
    let stub_raw = 0x400usize;
    let sec1_len = PAYLOAD_OFF + payload.len();
    let mut d = vec![0u8; stub_raw + sec1_len];
    d[..2].copy_from_slice(b"MZ");
    d[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let coff = pe_off + 4;
    d[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes()); // i386
    d[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    d[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    let opt = coff + 20;
    d[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32
    d[opt + 16..opt + 20].copy_from_slice(&STUB_RVA.to_le_bytes()); // entry
    d[opt + 28..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    d[opt + 56..opt + 60].copy_from_slice(&0x2_0000u32.to_le_bytes()); // SizeOfImage
    d[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders

    let s0 = sec_table;
    d[s0..s0 + 5].copy_from_slice(b".text");
    d[s0 + 8..s0 + 12].copy_from_slice(&DEST_VSIZE.to_le_bytes());
    d[s0 + 12..s0 + 16].copy_from_slice(&DEST_RVA.to_le_bytes());
    d[s0 + 36..s0 + 40].copy_from_slice(&0xe000_0020u32.to_le_bytes());

    let s1 = sec_table + 40;
    d[s1..s1 + 5].copy_from_slice(b".data");
    d[s1 + 8..s1 + 12].copy_from_slice(&(sec1_len as u32).to_le_bytes());
    d[s1 + 12..s1 + 16].copy_from_slice(&STUB_RVA.to_le_bytes());
    d[s1 + 16..s1 + 20].copy_from_slice(&(sec1_len as u32).to_le_bytes());
    d[s1 + 20..s1 + 24].copy_from_slice(&(stub_raw as u32).to_le_bytes());
    d[s1 + 36..s1 + 40].copy_from_slice(&0xe000_0060u32.to_le_bytes()); // rwx

    d[stub_raw..stub_raw + stub.len()].copy_from_slice(stub);
    d[stub_raw + PAYLOAD_OFF..stub_raw + PAYLOAD_OFF + payload.len()].copy_from_slice(payload);
    d
}

/// The archetypal stub: copy `len` bytes from the payload to the destination,
/// transforming each one, then jump to what it wrote.
///
/// ```text
///   mov esi, payload ; mov edi, dest ; mov ecx, len
///   lodsb ; xor al, key ; stosb ; loop -6
///   jmp dest
/// ```
fn decrypt_stub(len: u32, key: u8) -> Vec<u8> {
    let payload_va = IMAGE_BASE + STUB_RVA + PAYLOAD_OFF as u32;
    let dest_va = IMAGE_BASE + DEST_RVA;
    let mut stub: Vec<u8> = vec![0xbe];
    stub.extend_from_slice(&payload_va.to_le_bytes());
    stub.push(0xbf);
    stub.extend_from_slice(&dest_va.to_le_bytes());
    stub.push(0xb9);
    stub.extend_from_slice(&len.to_le_bytes());
    stub.extend_from_slice(&[0xac, 0x34, key, 0xaa, 0xe2, 0xfa]);
    let jmp_at = IMAGE_BASE + STUB_RVA + stub.len() as u32;
    let rel = dest_va.wrapping_sub(jmp_at + 5) as i32;
    stub.push(0xe9);
    stub.extend_from_slice(&rel.to_le_bytes());
    stub
}

fn payload_of(marker: &[u8], len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len + marker.len());
    while v.len() < len {
        v.extend_from_slice(marker);
    }
    v
}

fn unpack(file: &[u8]) -> Vec<exav_unpack::Entry> {
    let mut b = Budget::new(Limits {
        max_extracted_bytes: 1 << 30,
        max_buffer_bytes: 1 << 30,
        ..Default::default()
    });
    extract(Format::PePacked, file, &mut b).expect("extraction stays within budget")
}

#[test]
fn a_packed_image_is_recovered_by_running_its_stub() {
    const MARKER: &[u8] = b"EXAV_PE_EMULATION_PAYLOAD";
    let plain = payload_of(MARKER, 0xc000);
    let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x5a).collect();
    let file = packed_pe(&decrypt_stub(cipher.len() as u32, 0x5a), &cipher);

    assert!(
        is_pepack(&file),
        "the shape of a packed image must route it to the unpacker even though \
         no packer signature matches it"
    );
    let entries = unpack(&file);
    assert_eq!(entries.len(), 1, "one recovered image");
    assert_eq!(
        entries[0].name, "runtime-emulated",
        "an unpack that reached the original entry point says so in the name"
    );
    assert!(
        entries[0].data.windows(MARKER.len()).any(|w| w == MARKER),
        "the recovered image carries the decrypted payload"
    );
    assert!(
        !file.windows(MARKER.len()).any(|w| w == MARKER),
        "which is present nowhere in the packed file — only running it finds it"
    );
}

#[test]
fn the_recovered_image_is_a_pe_the_scanner_can_walk() {
    // The dump has to be a valid PE, not a memory blob: the scanner parses it
    // again to find resources, overlays and nested content.
    const MARKER: &[u8] = b"EXAV_DUMP_IS_A_PE";
    let plain = payload_of(MARKER, 0xc000);
    let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x33).collect();
    let file = packed_pe(&decrypt_stub(cipher.len() as u32, 0x33), &cipher);
    let entries = unpack(&file);
    let dump = &entries[0].data;

    assert_eq!(&dump[..2], b"MZ");
    let e_lfanew = u32::from_le_bytes(dump[0x3c..0x40].try_into().unwrap()) as usize;
    assert_eq!(&dump[e_lfanew..e_lfanew + 4], b"PE\0\0");
    let opt = e_lfanew + 24;
    let entry = u32::from_le_bytes(dump[opt + 16..opt + 20].try_into().unwrap());
    assert_eq!(
        entry, DEST_RVA,
        "the dump's entry point is where the stub transferred control, not the \
         packer's"
    );
}

#[test]
fn a_stub_that_loops_forever_is_bounded_and_yields_nothing() {
    // `jmp $`: the file never unpacks. The run must end on its own budget and
    // report nothing rather than hanging or inventing an image.
    let file = packed_pe(&[0xeb, 0xfe], b"payload");
    let started = std::time::Instant::now();
    let entries = unpack(&file);
    assert!(
        entries.is_empty(),
        "nothing was rebuilt, so nothing is claimed"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(120),
        "the instruction budget bounds the run"
    );
}

#[test]
fn an_ordinary_program_is_not_routed_to_the_emulator() {
    // A normal PE — entry point at the start of a read-only code section — is
    // not emulated at all. The cost of the emulator has to fall on files that
    // look packed, not on every executable that gets scanned.
    let mut file = packed_pe(&decrypt_stub(0x100, 0x5a), b"payload");
    let sec_table = 0x80 + 24 + 0xe0;
    // Entry point into section 0, and make both sections read-only code.
    let opt = 0x80 + 24;
    file[opt + 16..opt + 20].copy_from_slice(&DEST_RVA.to_le_bytes());
    file[sec_table + 36..sec_table + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    file[sec_table + 40 + 36..sec_table + 40 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    // ...and give section 0 raw data, so nothing reserves memory to unfold into.
    file[sec_table + 16..sec_table + 20].copy_from_slice(&0x200u32.to_le_bytes());
    file[sec_table + 20..sec_table + 24].copy_from_slice(&0x400u32.to_le_bytes());
    file[sec_table + 8..sec_table + 12].copy_from_slice(&0x200u32.to_le_bytes());
    // An ordinary function prologue at the entry point rather than the stub's
    // `mov esi, imm32`, which is a packer signature in its own right.
    file[0x400..0x404].copy_from_slice(&[0x55, 0x8b, 0xec, 0xc3]);

    assert!(
        !is_pepack(&file),
        "an ordinary executable must not be routed to the unpacker"
    );
}

#[test]
fn emulation_respects_the_extraction_budget() {
    // A tight per-member cap must be honoured: the emulator may not hand back a
    // buffer larger than the budget allows.
    const MARKER: &[u8] = b"EXAV_BUDGETED";
    let plain = payload_of(MARKER, 0xc000);
    let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x11).collect();
    let file = packed_pe(&decrypt_stub(cipher.len() as u32, 0x11), &cipher);

    let mut b = Budget::new(Limits {
        max_buffer_bytes: 0x2000,
        max_extracted_bytes: 0x2000,
        ..Default::default()
    });
    let entries = extract(Format::PePacked, &file, &mut b).expect("budget stop is not an error");
    for e in &entries {
        assert!(
            e.data.len() <= 0x2000,
            "a member larger than the per-member cap was emitted ({} bytes)",
            e.data.len()
        );
    }
}
