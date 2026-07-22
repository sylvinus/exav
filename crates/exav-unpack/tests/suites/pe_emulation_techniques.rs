//! What the PE stub emulator has to survive, one technique per test.
//!
//! Real packers are the reason this code exists, but they are a poor *unit*
//! test: they are third-party binaries with unclear redistribution terms, each
//! exercises a dozen mechanisms at once, and when one breaks the failure says
//! "ASPack no longer unpacks" rather than which mechanism regressed.
//!
//! So the mechanisms are tested directly. Each test here builds a PE whose stub
//! is hand-assembled machine code using exactly one technique that real packers
//! use — resolving imports through the IAT the loader filled in, reading its own
//! file, single-stepping itself through the trap flag, unfolding into memory it
//! allocated, wiping its own headers — and asserts the payload comes back. The
//! packed corpus then measures *coverage*; these tests pin *behaviour*.
//!
//! Every stub is written to be readable: the assembly is in a comment above the
//! bytes, and addresses are computed from the layout constants rather than
//! hard-coded.

use exav_unpack::{extract, Budget, Entry, Format, Limits};

const BASE: u32 = 0x0040_0000;
/// Destination section: reserved in memory, empty on disk.
const DEST_RVA: u32 = 0x1000;
const DEST_VSIZE: u32 = 0xd000;
/// Stub section: code, strings, import table and payload.
const STUB_RVA: u32 = 0xe000;
const STRINGS_OFF: u32 = 0x800; // within the stub section
const IMPORTS_OFF: u32 = 0x880;
const IAT_OFF: u32 = 0x900;
const PAYLOAD_OFF: u32 = 0x1000;
const MARKER: &[u8] = b"EXAV_TECHNIQUE_PAYLOAD_MARKER";

fn dest_va() -> u32 {
    BASE + DEST_RVA
}
fn stub_va() -> u32 {
    BASE + STUB_RVA
}
fn iat_va(i: u32) -> u32 {
    BASE + STUB_RVA + IAT_OFF + i * 4
}

/// A payload the tests can recognise, and its XOR-encrypted form.
fn payload(len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut plain = Vec::new();
    while plain.len() < len {
        plain.extend_from_slice(MARKER);
    }
    let cipher = plain.iter().map(|b| b ^ 0x5a).collect();
    (plain, cipher)
}

/// Assemble the pieces of a packed PE.
#[derive(Default)]
struct Packed {
    stub: Vec<u8>,
    /// Bytes placed at `PAYLOAD_OFF` inside the stub section.
    section_payload: Vec<u8>,
    /// Bytes appended after the last section — the overlay a self-reading stub
    /// goes to the file for.
    overlay: Vec<u8>,
    /// Names imported from `kernel32`, in IAT order.
    imports: Vec<&'static str>,
    /// Extra NUL-terminated strings laid out at `STRINGS_OFF`.
    strings: Vec<&'static str>,
    /// Raw pointer of the stub section, before the loader rounds it down.
    unaligned_raw_ptr: bool,
}

impl Packed {
    /// File offset of the string at index `i`, as a virtual address.
    fn string_va(&self, i: usize) -> u32 {
        let mut off = BASE + STUB_RVA + STRINGS_OFF;
        for s in self.strings.iter().take(i) {
            off += s.len() as u32 + 1;
        }
        off
    }

    fn build(&self) -> Vec<u8> {
        const PE_OFF: usize = 0x80;
        const OPT_SIZE: usize = 0xe0;
        let sec_table = PE_OFF + 24 + OPT_SIZE;
        let stub_raw = 0x400usize;
        let sec_len = (PAYLOAD_OFF as usize + self.section_payload.len()).max(0x2000);
        let mut d = vec![0u8; stub_raw + sec_len];

        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&(PE_OFF as u32).to_le_bytes());
        d[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");
        let coff = PE_OFF + 4;
        d[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes());
        d[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        d[coff + 16..coff + 18].copy_from_slice(&(OPT_SIZE as u16).to_le_bytes());
        let opt = coff + 20;
        d[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        d[opt + 16..opt + 20].copy_from_slice(&STUB_RVA.to_le_bytes());
        d[opt + 28..opt + 32].copy_from_slice(&BASE.to_le_bytes());
        d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        d[opt + 56..opt + 60].copy_from_slice(&0x2_0000u32.to_le_bytes()); // SizeOfImage
        d[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        d[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        if !self.imports.is_empty() {
            let dd = opt + 96 + 8; // data directory 1: imports
            d[dd..dd + 4].copy_from_slice(&(STUB_RVA + IMPORTS_OFF).to_le_bytes());
            d[dd + 4..dd + 8].copy_from_slice(&40u32.to_le_bytes());
        }

        let s0 = sec_table;
        d[s0..s0 + 5].copy_from_slice(b".text");
        d[s0 + 8..s0 + 12].copy_from_slice(&DEST_VSIZE.to_le_bytes());
        d[s0 + 12..s0 + 16].copy_from_slice(&DEST_RVA.to_le_bytes());
        d[s0 + 36..s0 + 40].copy_from_slice(&0xe000_0020u32.to_le_bytes());

        let s1 = sec_table + 40;
        d[s1..s1 + 5].copy_from_slice(b".pack");
        d[s1 + 8..s1 + 12].copy_from_slice(&(sec_len as u32).to_le_bytes());
        d[s1 + 12..s1 + 16].copy_from_slice(&STUB_RVA.to_le_bytes());
        d[s1 + 16..s1 + 20].copy_from_slice(&(sec_len as u32).to_le_bytes());
        // The loader rounds this down to a 512-byte boundary, so a stub can
        // point it a little past the real start and still be loaded correctly.
        let declared = if self.unaligned_raw_ptr {
            stub_raw as u32 + 0x88
        } else {
            stub_raw as u32
        };
        d[s1 + 20..s1 + 24].copy_from_slice(&declared.to_le_bytes());
        d[s1 + 36..s1 + 40].copy_from_slice(&0xe000_0060u32.to_le_bytes());

        d[stub_raw..stub_raw + self.stub.len()].copy_from_slice(&self.stub);

        // Strings.
        let mut off = stub_raw + STRINGS_OFF as usize;
        for s in &self.strings {
            d[off..off + s.len()].copy_from_slice(s.as_bytes());
            off += s.len() + 1;
        }

        // Import directory: one descriptor for kernel32, name table and IAT.
        if !self.imports.is_empty() {
            let names_rva = STUB_RVA + IMPORTS_OFF + 0x40;
            let dll_rva = STUB_RVA + IMPORTS_OFF + 0x20;
            let desc = stub_raw + IMPORTS_OFF as usize;
            d[desc..desc + 4].copy_from_slice(&(STUB_RVA + IAT_OFF).to_le_bytes()); // OFT
            d[desc + 12..desc + 16].copy_from_slice(&dll_rva.to_le_bytes()); // Name
            d[desc + 16..desc + 20].copy_from_slice(&(STUB_RVA + IAT_OFF).to_le_bytes()); // FT
            let dll = stub_raw + (dll_rva - STUB_RVA) as usize;
            d[dll..dll + 12].copy_from_slice(b"KERNEL32.dll");

            let mut name_rva = names_rva;
            for (i, name) in self.imports.iter().enumerate() {
                let slot = stub_raw + IAT_OFF as usize + i * 4;
                d[slot..slot + 4].copy_from_slice(&name_rva.to_le_bytes());
                let at = stub_raw + (name_rva - STUB_RVA) as usize;
                // IMAGE_IMPORT_BY_NAME: hint, then the NUL-terminated name.
                d[at + 2..at + 2 + name.len()].copy_from_slice(name.as_bytes());
                name_rva += 2 + name.len() as u32 + 1;
            }
        }

        let at = stub_raw + PAYLOAD_OFF as usize;
        d[at..at + self.section_payload.len()].copy_from_slice(&self.section_payload);
        d.extend_from_slice(&self.overlay);
        d
    }
}

fn unpack(file: &[u8]) -> Vec<Entry> {
    let mut b = Budget::new(Limits {
        max_extracted_bytes: 1 << 30,
        max_buffer_bytes: 1 << 30,
        ..Default::default()
    });
    extract(Format::PePacked, file, &mut b).expect("extraction stays within budget")
}

fn recovered(entries: &[Entry]) -> bool {
    entries
        .iter()
        .any(|e| e.data.windows(MARKER.len()).any(|w| w == MARKER))
}

/// `mov esi, src ; mov edi, dst ; mov ecx, len ; lodsb ; xor al,0x5a ; stosb ;
/// loop ; jmp dst` — the decrypt-and-transfer tail every test ends with.
fn decrypt_tail(at_va: u32, src: u32, dst: u32, len: u32) -> Vec<u8> {
    let mut c: Vec<u8> = vec![0xbe];
    c.extend_from_slice(&src.to_le_bytes());
    c.push(0xbf);
    c.extend_from_slice(&dst.to_le_bytes());
    c.push(0xb9);
    c.extend_from_slice(&len.to_le_bytes());
    c.extend_from_slice(&[0xac, 0x34, 0x5a, 0xaa, 0xe2, 0xfa]);
    let jmp_at = at_va + c.len() as u32;
    let rel = dst.wrapping_sub(jmp_at + 5) as i32;
    c.push(0xe9);
    c.extend_from_slice(&rel.to_le_bytes());
    c
}

#[test]
fn a_stub_calling_through_the_import_table_the_loader_filled_in() {
    // The loader binds imports before the entry point runs, and a stub calls
    // straight through those slots. Here: VirtualProtect on the destination
    // (which every in-place unpacker does), then decrypt and transfer.
    //
    //   push 0x419000 ; push 0x40 ; push 0xc000 ; push dest
    //   call [iat+0]              ; VirtualProtect(dest, 0xc000, RWX, &old)
    //   <decrypt tail>
    let (_, cipher) = payload(0xc000);
    let mut stub: Vec<u8> = Vec::new();
    for imm in [BASE + STUB_RVA + 0x40, 0x40, 0xc000, dest_va()] {
        stub.push(0x68);
        stub.extend_from_slice(&imm.to_le_bytes());
    }
    stub.extend_from_slice(&[0xff, 0x15]);
    stub.extend_from_slice(&iat_va(0).to_le_bytes());
    let tail_at = stub_va() + stub.len() as u32;
    stub.extend_from_slice(&decrypt_tail(
        tail_at,
        stub_va() + PAYLOAD_OFF,
        dest_va(),
        cipher.len() as u32,
    ));

    let file = Packed {
        stub,
        section_payload: cipher,
        imports: vec!["VirtualProtect"],
        ..Default::default()
    }
    .build();
    let entries = unpack(&file);
    assert!(
        recovered(&entries),
        "the payload came back only if the import slot held a callable address"
    );
}

#[test]
fn a_stub_reading_its_payload_from_its_own_file() {
    // Installers and self-extractors keep the payload as an *overlay* past the
    // last section, where the loaded image does not reach, and read it back
    // with CreateFile/SetFilePointer/ReadFile on their own path.
    //
    //   push 0;push 0x80;push 3;push 0;push 1;push 0x80000000;push path
    //   call [iat+0]                    ; CreateFileA
    //   mov ebx, eax
    //   push 0 ; push 0 ; push overlay ; push ebx
    //   call [iat+1]                    ; SetFilePointer(h, overlay, 0, BEGIN)
    //   push 0 ; push scratch ; push len ; push dest ; push ebx
    //   call [iat+2]                    ; ReadFile(h, dest, len, &read, 0)
    //   <decrypt tail, in place at dest>
    let (_, cipher) = payload(0xc000);
    let len = cipher.len() as u32;
    let overlay_off = 0x400u32 + 0x2000; // stub_raw + section length

    let mut p = Packed {
        imports: vec!["CreateFileA", "SetFilePointer", "ReadFile"],
        strings: vec!["C:\\sample.exe"],
        overlay: cipher,
        ..Default::default()
    };
    let path = p.string_va(0);
    let mut stub: Vec<u8> = Vec::new();
    for imm in [0u32, 0x80, 3, 0, 1, 0x8000_0000, path] {
        stub.push(0x68);
        stub.extend_from_slice(&imm.to_le_bytes());
    }
    stub.extend_from_slice(&[0xff, 0x15]);
    stub.extend_from_slice(&iat_va(0).to_le_bytes());
    stub.extend_from_slice(&[0x89, 0xc3]); // mov ebx, eax
    for imm in [0u32, 0, overlay_off] {
        stub.push(0x68);
        stub.extend_from_slice(&imm.to_le_bytes());
    }
    stub.extend_from_slice(&[0x53]); // push ebx
    stub.extend_from_slice(&[0xff, 0x15]);
    stub.extend_from_slice(&iat_va(1).to_le_bytes());
    for imm in [0u32, stub_va() + 0x40, len, dest_va()] {
        stub.push(0x68);
        stub.extend_from_slice(&imm.to_le_bytes());
    }
    stub.extend_from_slice(&[0x53]); // push ebx
    stub.extend_from_slice(&[0xff, 0x15]);
    stub.extend_from_slice(&iat_va(2).to_le_bytes());
    let tail_at = stub_va() + stub.len() as u32;
    stub.extend_from_slice(&decrypt_tail(tail_at, dest_va(), dest_va(), len));
    p.stub = stub;

    let file = p.build();
    assert!(
        !file[..0x2400].windows(MARKER.len()).any(|w| w == MARKER),
        "the payload is in the overlay, outside every section"
    );
    let entries = unpack(&file);
    assert!(
        recovered(&entries),
        "an overlay payload is only reachable if the stub can read its own file"
    );
}

#[test]
fn a_stub_single_stepping_itself_through_the_trap_flag() {
    // Anti-debug: install a handler, set TF, and let the single-step exception
    // drive the loop. A trap flag nobody emulates means the exception never
    // arrives and the stub spins until the budget runs out.
    //
    //   push handler ; push fs:[0] ; mov fs:[0], esp
    //   pushfd ; or dword [esp], 0x100 ; popfd     ; TF on
    //   nop                                        ; #DB after this one
    //   <decrypt tail>                             ; reached via the handler
    // handler:
    //   mov eax, [esp+0xc] ; mov [eax+0xb8], resume ; and [eax+0xc0], ~0x100
    //   xor eax, eax ; ret                          ; ExceptionContinueExecution
    let (_, cipher) = payload(0xc000);
    let len = cipher.len() as u32;
    let mut stub: Vec<u8> = Vec::new();
    let handler_patch = stub.len() + 1;
    stub.extend_from_slice(&[0x68, 0, 0, 0, 0]); // push handler (patched)
    stub.extend_from_slice(&[0x64, 0xff, 0x35, 0, 0, 0, 0]); // push fs:[0]
    stub.extend_from_slice(&[0x64, 0x89, 0x25, 0, 0, 0, 0]); // mov fs:[0], esp
    stub.extend_from_slice(&[0x9c]); // pushfd
    stub.extend_from_slice(&[0x81, 0x0c, 0x24, 0x00, 0x01, 0x00, 0x00]); // or [esp],0x100
    stub.extend_from_slice(&[0x9d]); // popfd
    stub.extend_from_slice(&[0x90]); // nop  <- the trap fires after this
    stub.extend_from_slice(&[0xeb, 0xfe]); // jmp $   (only reached if no trap)
    let resume_off = stub.len();
    let tail_at = stub_va() + resume_off as u32;
    stub.extend_from_slice(&decrypt_tail(
        tail_at,
        stub_va() + PAYLOAD_OFF,
        dest_va(),
        len,
    ));

    let handler_off = stub.len();
    stub.extend_from_slice(&[0x8b, 0x44, 0x24, 0x0c]); // mov eax,[esp+0xc]  (CONTEXT*)
    stub.extend_from_slice(&[0xc7, 0x80, 0xb8, 0x00, 0x00, 0x00]); // mov [eax+0xb8], imm32
    stub.extend_from_slice(&(stub_va() + resume_off as u32).to_le_bytes());
    // Clear TF in the saved EFLAGS so the resumed code runs at full speed.
    stub.extend_from_slice(&[0x81, 0xa0, 0xc0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0xff, 0xff]);
    stub.extend_from_slice(&[0x31, 0xc0, 0xc3]); // xor eax,eax ; ret
    let handler_va = stub_va() + handler_off as u32;
    stub[handler_patch..handler_patch + 4].copy_from_slice(&handler_va.to_le_bytes());

    let file = Packed {
        stub,
        section_payload: cipher,
        ..Default::default()
    }
    .build();
    let entries = unpack(&file);
    assert!(
        recovered(&entries),
        "the payload is only reached through the single-step exception"
    );
}

#[test]
fn a_loader_that_unfolds_into_memory_it_allocated() {
    // The dropper shape: nothing is written to the image at all. The stub
    // allocates, builds a whole PE there, and runs it — so the only place the
    // payload ever exists is memory the emulator handed out.
    //
    //   push 0x40 ; push 0x1000 ; push 0x20000 ; push 0
    //   call [iat+0]                 ; VirtualAlloc(NULL, 0x20000, COMMIT, RWX)
    //   mov edi, eax ; mov esi, payload ; mov ecx, len
    //   lodsb ; xor al,0x5a ; stosb ; loop
    //   ret                          ; back to the loader: nothing more to see
    let (plain, cipher) = payload(0x4000);
    // The payload is itself a PE image, which is what makes it worth emitting.
    let mut inner = Packed {
        stub: vec![0xc3],
        section_payload: plain,
        ..Default::default()
    }
    .build();
    inner.truncate(0x2400);
    let inner_cipher: Vec<u8> = inner.iter().map(|b| b ^ 0x5a).collect();
    let _ = cipher;

    let mut stub: Vec<u8> = Vec::new();
    for imm in [0x40u32, 0x1000, 0x2_0000, 0] {
        stub.push(0x68);
        stub.extend_from_slice(&imm.to_le_bytes());
    }
    stub.extend_from_slice(&[0xff, 0x15]);
    stub.extend_from_slice(&iat_va(0).to_le_bytes());
    stub.extend_from_slice(&[0x89, 0xc7]); // mov edi, eax
    stub.push(0xbe);
    stub.extend_from_slice(&(stub_va() + PAYLOAD_OFF).to_le_bytes());
    stub.push(0xb9);
    stub.extend_from_slice(&(inner_cipher.len() as u32).to_le_bytes());
    stub.extend_from_slice(&[0xac, 0x34, 0x5a, 0xaa, 0xe2, 0xfa]);
    stub.push(0xc3); // ret

    let file = Packed {
        stub,
        section_payload: inner_cipher,
        imports: vec!["VirtualAlloc"],
        ..Default::default()
    }
    .build();
    let entries = unpack(&file);
    assert!(
        entries.iter().any(|e| e.name.contains("allocation")),
        "a payload built in allocated memory is emitted under its own name: {:?}",
        entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
    assert!(recovered(&entries));
}

#[test]
fn a_stub_that_wipes_its_own_headers_before_transferring() {
    // An anti-dump move: overwrite `MZ`/`PE` in memory once the loader is done
    // with them, so a memory dump is not a valid image. The bytes are still in
    // the file, and the dump has to fall back to them.
    //
    //   mov edi, base ; xor eax, eax ; mov ecx, 0x40 ; rep stosb
    //   <decrypt tail>
    let (_, cipher) = payload(0xc000);
    let mut stub: Vec<u8> = vec![0xbf];
    stub.extend_from_slice(&BASE.to_le_bytes());
    stub.extend_from_slice(&[0x31, 0xc0]); // xor eax, eax
    stub.push(0xb9);
    stub.extend_from_slice(&0x40u32.to_le_bytes());
    stub.extend_from_slice(&[0xf3, 0xaa]); // rep stosb
    let tail_at = stub_va() + stub.len() as u32;
    stub.extend_from_slice(&decrypt_tail(
        tail_at,
        stub_va() + PAYLOAD_OFF,
        dest_va(),
        cipher.len() as u32,
    ));

    let file = Packed {
        stub,
        section_payload: cipher,
        ..Default::default()
    }
    .build();
    let entries = unpack(&file);
    assert!(recovered(&entries), "the payload survives a wiped header");
    let dump = entries
        .iter()
        .find(|e| e.data.windows(MARKER.len()).any(|w| w == MARKER))
        .expect("a dump");
    assert_eq!(
        &dump.data[..2],
        b"MZ",
        "and the dump is still a PE the scanner can parse"
    );
}

#[test]
fn a_section_whose_raw_pointer_the_loader_rounds_down() {
    // NSPack declares `PointerToRawData` a little past the real start; the
    // loader masks it to a 512-byte boundary, so the bytes that execute are the
    // ones at the rounded-down offset. Taking the field literally loads zeros.
    let (_, cipher) = payload(0xc000);
    let mut stub: Vec<u8> = Vec::new();
    let tail_at = stub_va();
    stub.extend_from_slice(&decrypt_tail(
        tail_at,
        stub_va() + PAYLOAD_OFF,
        dest_va(),
        cipher.len() as u32,
    ));
    let file = Packed {
        stub,
        section_payload: cipher,
        unaligned_raw_ptr: true,
        ..Default::default()
    }
    .build();
    let entries = unpack(&file);
    assert!(
        recovered(&entries),
        "the stub only runs if the raw pointer was rounded down like the loader does"
    );
}

#[test]
fn a_stub_that_uses_more_stack_than_the_initial_mapping() {
    // Windows commits stack pages on demand as the guard page is touched. A
    // stub with a large frame — or a decompressor that keeps its window on the
    // stack — walks past a fixed mapping and faults on an ordinary access.
    //
    //   sub esp, 0x110000 ; mov [esp], eax ; add esp, 0x110000
    //
    // The frame has to cross *below* the initially mapped stack for this to
    // test anything: the mapping starts a megabyte under the initial `esp`.
    //   <decrypt tail>
    let (_, cipher) = payload(0xc000);
    let mut stub: Vec<u8> = Vec::new();
    stub.extend_from_slice(&[0x81, 0xec]); // sub esp, imm32
    stub.extend_from_slice(&0x11_0000u32.to_le_bytes());
    stub.extend_from_slice(&[0x89, 0x04, 0x24]); // mov [esp], eax
    stub.extend_from_slice(&[0x81, 0xc4]); // add esp, imm32
    stub.extend_from_slice(&0x11_0000u32.to_le_bytes());
    let tail_at = stub_va() + stub.len() as u32;
    stub.extend_from_slice(&decrypt_tail(
        tail_at,
        stub_va() + PAYLOAD_OFF,
        dest_va(),
        cipher.len() as u32,
    ));
    let file = Packed {
        stub,
        section_payload: cipher,
        ..Default::default()
    }
    .build();
    assert!(
        recovered(&unpack(&file)),
        "the stack grew instead of faulting"
    );
}

#[test]
fn a_stub_that_resolves_kernel32_by_walking_the_loader_list() {
    // No import table at all: find kernel32 through fs:[0x30] -> PEB -> Ldr,
    // then call GetProcAddress found by hand. Shellcode-style, and common in
    // stubs that want no static evidence of what they call.
    //
    //   mov eax, fs:[0x30] ; mov eax,[eax+0xc] ; mov eax,[eax+0x1c]
    //   mov eax,[eax] ; mov ebx,[eax+8]     ; kernel32 base
    //   mov [dest], ebx                     ; prove it, in the destination
    //   <decrypt tail>
    let (_, cipher) = payload(0xc000);
    let mut stub: Vec<u8> = vec![
        0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, // mov eax, fs:[0x30]
        0x8b, 0x40, 0x0c, // mov eax, [eax+0xc]
        0x8b, 0x40, 0x1c, // mov eax, [eax+0x1c]
        0x8b, 0x00, // mov eax, [eax]
        0x8b, 0x58, 0x08, // mov ebx, [eax+8]
    ];
    stub.extend_from_slice(&[0x89, 0x1d]); // mov [imm32], ebx
    stub.extend_from_slice(&(dest_va() + 0xc000).to_le_bytes());
    let tail_at = stub_va() + stub.len() as u32;
    stub.extend_from_slice(&decrypt_tail(
        tail_at,
        stub_va() + PAYLOAD_OFF,
        dest_va(),
        cipher.len() as u32,
    ));
    let file = Packed {
        stub,
        section_payload: cipher,
        ..Default::default()
    }
    .build();
    assert!(recovered(&unpack(&file)));
}
