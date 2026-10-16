//! End-to-end tests a consumer of the crate can run: build a PE in memory, run
//! its stub through [`exav_pe_emu::unpack`], and check the image that comes out.
//!
//! The fixtures are assembled here rather than committed as binaries, so nothing
//! third-party or packed is checked in. [`pe`] is the generator: a minimal but
//! real PE32 with the sections, entry point and (optionally) TLS directory each
//! test needs.

use exav_pe_emu::{unpack, EmuLimits};

/// A minimal PE32 builder. The image has two sections, `.text` (the empty
/// destination a stub fills) at RVA 0x1000 and `.pack` (the stub's own bytes)
/// at RVA 0x2000, mapped at base 0x400000. The caller supplies `.pack`'s raw
/// bytes, the entry RVA, and an optional TLS directory RVA.
mod pe {
    pub const BASE: u32 = 0x0040_0000;
    pub const TEXT_RVA: u32 = 0x1000;
    pub const PACK_RVA: u32 = 0x2000;

    pub struct Pe {
        pub entry_rva: u32,
        pub pack: Vec<u8>,
        pub tls_dir_rva: Option<u32>,
    }

    impl Pe {
        pub fn build(&self) -> Vec<u8> {
            let pe_off = 0x80usize;
            let opt_size = 0xe0usize;
            let sec_table = pe_off + 24 + opt_size;
            let num = 2usize;
            let headers = 0x400usize;
            let pack_raw = headers;
            let pack_len = self.pack.len().max(0x200);
            let mut d = vec![0u8; pack_raw + pack_len];

            d[..2].copy_from_slice(b"MZ");
            d[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
            d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
            let coff = pe_off + 4;
            d[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes()); // i386
            d[coff + 2..coff + 4].copy_from_slice(&(num as u16).to_le_bytes());
            d[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());

            let opt = coff + 20;
            d[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32
            d[opt + 16..opt + 20].copy_from_slice(&self.entry_rva.to_le_bytes());
            d[opt + 28..opt + 32].copy_from_slice(&BASE.to_le_bytes());
            d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
            d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
            d[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
            d[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
                                                                            // 16 data directories, so the TLS slot (9) is present.
            d[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
            if let Some(tls_rva) = self.tls_dir_rva {
                let dd = opt + 96 + 9 * 8; // data directory 9
                d[dd..dd + 4].copy_from_slice(&tls_rva.to_le_bytes());
                d[dd + 4..dd + 8].copy_from_slice(&0x18u32.to_le_bytes());
            }

            // Section 0: `.text`, the empty destination (no raw data).
            let s0 = sec_table;
            d[s0..s0 + 5].copy_from_slice(b".text");
            d[s0 + 8..s0 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
            d[s0 + 12..s0 + 16].copy_from_slice(&TEXT_RVA.to_le_bytes());
            d[s0 + 36..s0 + 40].copy_from_slice(&0xe000_0020u32.to_le_bytes());

            // Section 1: `.pack`, holding the stub.
            let s1 = sec_table + 40;
            d[s1..s1 + 5].copy_from_slice(b".pack");
            d[s1 + 8..s1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
            d[s1 + 12..s1 + 16].copy_from_slice(&PACK_RVA.to_le_bytes());
            d[s1 + 16..s1 + 20].copy_from_slice(&(self.pack.len() as u32).to_le_bytes());
            d[s1 + 20..s1 + 24].copy_from_slice(&(pack_raw as u32).to_le_bytes());
            d[s1 + 36..s1 + 40].copy_from_slice(&0xe000_0020u32.to_le_bytes());

            d[pack_raw..pack_raw + self.pack.len()].copy_from_slice(&self.pack);
            d
        }
    }

    /// `.text`'s raw offset inside a dump, so a test can read the bytes a stub
    /// wrote there. A memory-layout dump puts `PointerToRawData == VirtualAddress`.
    pub fn text_offset_in_dump(dump: &[u8]) -> usize {
        let pe = u32::from_le_bytes(dump[0x3c..0x40].try_into().unwrap()) as usize;
        let opt = pe + 24;
        let sec = opt + u16::from_le_bytes(dump[pe + 20..pe + 22].try_into().unwrap()) as usize;
        u32::from_le_bytes(dump[sec + 20..sec + 24].try_into().unwrap()) as usize
    }
}

/// Limits with the dirty-byte floors dropped, because these hand-written stubs
/// rebuild a page, not the tens of kilobytes a real unpack produces.
fn limits() -> EmuLimits {
    EmuLimits {
        min_unpack_dirty: 0,
        min_partial_dirty: 0,
        ..Default::default()
    }
}

#[test]
fn a_decrypt_and_jump_stub_unpacks() {
    // The archetype: XOR-decrypt a body from `.pack` into `.text`, then jump to
    // it. Mirrors a runtime packer's tail transfer.
    let plain: &[u8] = b"ORIGINAL PROGRAM";
    let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x5a).collect();

    // src = PACK_RVA + 0x40 (the cipher text, below the stub).
    let src = pe::BASE + pe::PACK_RVA + 0x40;
    let dst = pe::BASE + pe::TEXT_RVA;
    let mut stub = vec![
        0xbe, 0, 0, 0, 0, // mov esi, src
        0xbf, 0, 0, 0, 0, // mov edi, dst
        0xb9, 0, 0, 0, 0, // mov ecx, len
        0xac, 0x34, 0x5a, 0xaa, 0xe2, 0xfa, // lodsb; xor al,0x5a; stosb; loop -6
    ];
    stub[1..5].copy_from_slice(&src.to_le_bytes());
    stub[6..10].copy_from_slice(&dst.to_le_bytes());
    stub[11..15].copy_from_slice(&(plain.len() as u32).to_le_bytes());
    // jmp dst (rel32 from the end of this instruction).
    let jmp_at = pe::BASE + pe::PACK_RVA + stub.len() as u32;
    let rel = dst.wrapping_sub(jmp_at + 5) as i32;
    stub.push(0xe9);
    stub.extend_from_slice(&rel.to_le_bytes());

    let mut pack = vec![0u8; 0x40];
    pack[..stub.len()].copy_from_slice(&stub);
    pack.extend_from_slice(&cipher);

    let file = pe::Pe {
        entry_rva: pe::PACK_RVA,
        pack,
        tls_dir_rva: None,
    }
    .build();

    let r = unpack(&file, &limits());
    let u = r.unpacked.expect("an image was reconstructed");
    assert!(u.reached_oep, "stopped at the tail jump: {}", r.stop);
    assert_eq!(u.oep_rva, pe::TEXT_RVA);
    let at = pe::text_offset_in_dump(&u.data);
    assert_eq!(&u.data[at..at + plain.len()], plain);
}

#[test]
fn a_stub_that_writes_nothing_yields_no_image() {
    // `ret`: a stub that does nothing produces no reconstruction, and the crate
    // reports that rather than handing back the input under an "unpacked" name.
    let file = pe::Pe {
        entry_rva: pe::PACK_RVA,
        pack: vec![0xc3],
        tls_dir_rva: None,
    }
    .build();
    let r = unpack(&file, &limits());
    assert!(r.unpacked.is_none(), "{}", r.stop);
    assert_eq!(r.dirty_bytes, 0);
}

/// Build the TLS fixture: a file whose entry point only jumps into `.text`,
/// which is empty until a TLS callback copies the payload there. Reaching the
/// original entry point therefore proves the callback ran before the entry
/// point, as the Windows loader runs it.
fn tls_fixture() -> Vec<u8> {
    let payload: &[u8] = b"OEP-CODE-PLACED-BY-TLS-CALLBACK";

    // Layout inside `.pack` (RVA 0x2000):
    //   0x00  entry: jmp .text            (nothing of its own to unpack)
    //   0x10  callback: rep movsb payload -> .text; ret
    //   0x60  payload bytes
    //   0xA0  callback array: [callback_va, 0]
    //   0xC0  TLS directory (IMAGE_TLS_DIRECTORY32)
    //   0xE0  AddressOfIndex storage
    let entry_off = 0x00u32;
    let cb_off = 0x10u32;
    let payload_off = 0x60u32;
    let cb_array_off = 0xa0u32;
    let tls_dir_off = 0xc0u32;
    let index_off = 0xe0u32;
    let va = |off: u32| pe::BASE + pe::PACK_RVA + off;
    let dst = pe::BASE + pe::TEXT_RVA;

    let mut pack = vec![0u8; 0x100];

    // entry: jmp .text
    let rel = dst.wrapping_sub(va(entry_off) + 5) as i32;
    pack[entry_off as usize] = 0xe9;
    pack[entry_off as usize + 1..entry_off as usize + 5].copy_from_slice(&rel.to_le_bytes());

    // callback(image_base, reason, reserved): copy the payload into .text, ret.
    let cb = [
        vec![0xbf],
        dst.to_le_bytes().to_vec(), // mov edi, .text
        vec![0xbe],
        va(payload_off).to_le_bytes().to_vec(), // mov esi, payload
        vec![0xb9],
        (payload.len() as u32).to_le_bytes().to_vec(), // mov ecx, len
        vec![0xf3, 0xa4],                              // rep movsb
        vec![0xc3],                                    // ret
    ]
    .concat();
    pack[cb_off as usize..cb_off as usize + cb.len()].copy_from_slice(&cb);

    pack[payload_off as usize..payload_off as usize + payload.len()].copy_from_slice(payload);

    // Callback array: one callback, null-terminated.
    pack[cb_array_off as usize..cb_array_off as usize + 4]
        .copy_from_slice(&va(cb_off).to_le_bytes());

    // IMAGE_TLS_DIRECTORY32: no raw data, AddressOfIndex -> our storage,
    // AddressOfCallBacks -> the array.
    let td = tls_dir_off as usize;
    pack[td + 8..td + 12].copy_from_slice(&va(index_off).to_le_bytes()); // AddressOfIndex
    pack[td + 12..td + 16].copy_from_slice(&va(cb_array_off).to_le_bytes()); // AddressOfCallBacks

    let _ = index_off;
    pe::Pe {
        entry_rva: pe::PACK_RVA,
        pack,
        tls_dir_rva: Some(pe::PACK_RVA + tls_dir_off),
    }
    .build()
}

#[test]
fn a_tls_callback_runs_before_the_entry_point() {
    // PE-1 coverage. The entry point only jumps into `.text`; `.text` holds the
    // original code only because the TLS callback put it there first. If the
    // callback did not run, `.text` is empty and nothing is recovered.
    let payload: &[u8] = b"OEP-CODE-PLACED-BY-TLS-CALLBACK";
    let file = tls_fixture();
    let r = unpack(&file, &limits());
    let u = r
        .unpacked
        .expect("the TLS callback filled .text and the entry point reached it");
    assert!(
        u.reached_oep,
        "did not reach the original entry point: {}",
        r.stop
    );
    assert_eq!(u.oep_rva, pe::TEXT_RVA);
    let at = pe::text_offset_in_dump(&u.data);
    assert_eq!(
        &u.data[at..at + payload.len()],
        payload,
        "the dump holds the code the TLS callback wrote"
    );
}
