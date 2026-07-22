//! Differential fuzzing of `exav-x86` against `iced-x86`.
//!
//! WHY A FUZZER AND NOT JUST THE TESTS: the differential tests in
//! `crates/exav-x86/tests/differential.rs` sweep the opcode maps exhaustively,
//! but they hold the *body* of each instruction fixed — one ModRM byte, then a
//! constant tail. A decoder's subtler mistakes live in the body: a SIB byte that
//! changes whether a displacement is present, a `mod` that changes its width, a
//! prefix run that pushes the instruction past fifteen bytes. Coverage-guided
//! mutation reaches those combinations; a hand-written sweep does not.
//!
//! WHAT IS ASSERTED, and why each one matters:
//!
//! 1. **Never claim an encoding the oracle rejects.** Inventing an instruction
//!    from bytes that are not one is the failure that lets an emulator run
//!    fabricated code.
//! 2. **Agree on length.** A length that is off by one desynchronises every
//!    instruction after it, so this is not a local error but a cascading one.
//! 3. **Agree on the mnemonic**, which decides which semantics run.
//! 4. **Agree on the memory operand** — base, index, scale, displacement —
//!    which is where an emulated read or write lands, and on every register
//!    operand: its register file, its number, and the order the two ModRM
//!    fields appear in. `movdqa xmm1, xmm2` decoded backwards runs and produces
//!    the wrong bytes, which a length check would never notice.
//! 5. **Length is self-consistent**: re-decoding the instruction from exactly
//!    its own reported length gives the same answer. A decoder that consumes
//!    more than it reports passes 2 and still corrupts the stream.
//! 6. **Truncation is never completed**: no proper prefix of an instruction
//!    decodes. This is the read-past-the-buffer check.
//!
//! Declining is not a failure. `exav-x86` returns `None` both for bytes that
//! are not an instruction and for encodings outside its scope, and the caller
//! is required to treat that as unsupported rather than as a fault.

#![no_main]

use exav_x86::{decode, Insn, Op, Size};
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};
use libfuzzer_sys::fuzz_target;

/// Each register file in the encoding's own numbering, so a decoded number
/// indexes straight into it.
const GPR32: [Register; 8] = [
    Register::EAX,
    Register::ECX,
    Register::EDX,
    Register::EBX,
    Register::ESP,
    Register::EBP,
    Register::ESI,
    Register::EDI,
];
const GPR16: [Register; 8] = [
    Register::AX,
    Register::CX,
    Register::DX,
    Register::BX,
    Register::SP,
    Register::BP,
    Register::SI,
    Register::DI,
];
const GPR8: [Register; 8] = [
    Register::AL,
    Register::CL,
    Register::DL,
    Register::BL,
    Register::AH,
    Register::CH,
    Register::DH,
    Register::BH,
];
const XMM: [Register; 8] = [
    Register::XMM0,
    Register::XMM1,
    Register::XMM2,
    Register::XMM3,
    Register::XMM4,
    Register::XMM5,
    Register::XMM6,
    Register::XMM7,
];
const MMX: [Register; 8] = [
    Register::MM0,
    Register::MM1,
    Register::MM2,
    Register::MM3,
    Register::MM4,
    Register::MM5,
    Register::MM6,
    Register::MM7,
];

/// iced's 32-bit GPR numbering, back to the encoding's own — used for the base
/// and index of a memory operand, which are always 32-bit registers.
fn reg_num(r: Register) -> Option<u8> {
    GPR32.iter().position(|x| *x == r).map(|i| i as u8)
}

/// Compare register operands position by position.
///
/// Only encodings where both decoders report the same number of operands are
/// compared: where this crate models no operand shape it reports the `r/m`
/// operand alone, which is a narrower claim rather than a contradictory one.
fn check_registers(ours: &Insn, iced: &Instruction, bytes: &[u8]) {
    if ours.op_count() != iced.op_count() as usize {
        return;
    }
    for i in 0..ours.op_count() {
        let (file, num) = match ours.ops[i] {
            Op::Reg(n, Size::B1) => (GPR8, n),
            Op::Reg(n, Size::B2) => (GPR16, n),
            Op::Reg(n, Size::B4) => (GPR32, n),
            Op::Xmm(n) => (XMM, n),
            Op::Mmx(n) => (MMX, n),
            _ => continue,
        };
        assert_eq!(
            iced.op_kind(i as u32),
            OpKind::Register,
            "operand {i} of {bytes:02x?}: claimed a register"
        );
        assert_eq!(
            file.get(num as usize),
            Some(&iced.op_register(i as u32)),
            "operand {i} of {bytes:02x?}: {:?}",
            ours.ops[i]
        );
    }
}

/// Compare the memory operand, when we produced one. 16-bit addressing pairs a
/// base and index that iced reports in a different numbering, so those are left
/// to the crate's own tests.
fn check_memory(ours: &[Op; 3], iced: &Instruction, bytes: &[u8]) {
    let Some((base, index, scale, disp, addr16)) = ours.iter().find_map(|o| match o {
        Op::Mem {
            base,
            index,
            scale,
            disp,
            addr16,
            ..
        } => Some((*base, *index, *scale, *disp, *addr16)),
        _ => None,
    }) else {
        return;
    };
    if addr16 {
        return;
    }
    assert_eq!(
        reg_num(iced.memory_base()),
        base,
        "memory base disagrees on {bytes:02x?}"
    );
    assert_eq!(
        reg_num(iced.memory_index()),
        index,
        "memory index disagrees on {bytes:02x?}"
    );
    if index.is_some() {
        assert_eq!(
            iced.memory_index_scale(),
            u32::from(scale),
            "memory scale disagrees on {bytes:02x?}"
        );
    }
    // `ours` has to come from the decoder under test. Deriving both sides from
    // `iced` makes this `iced == iced`, which is true of any decoder at all —
    // and it is the check that decides whether an emulated read or write lands
    // where the hardware would put it, so a vacuous one is worse than none.
    let iced_disp = iced.memory_displacement32();
    let (ours, theirs) = if base.is_none() && index.is_none() {
        // A bare absolute address: iced reports it unsigned.
        (disp & 0xffff_ffff, i64::from(iced_disp))
    } else {
        (disp, iced_disp as i32 as i64)
    };
    assert_eq!(
        ours, theirs,
        "memory displacement disagrees on {bytes:02x?}"
    );
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Decode at a plausible code address rather than zero, so a relative branch
    // resolves through real arithmetic instead of trivially.
    let ip = 0x0040_1000u64;
    let window = &data[..data.len().min(exav_x86::MAX_INSN_LEN)];

    let mut dec = Decoder::with_ip(32, window, ip, DecoderOptions::NONE);
    let iced = dec.decode();
    let ours = decode(window, ip);

    // iced pads a truncated instruction out past the end of the buffer; that is
    // not a fair comparison, so skip those.
    if iced.len() > window.len() {
        return;
    }

    match (iced.is_invalid(), ours) {
        (true, None) => {}
        (true, Some(o)) => panic!(
            "claimed {:?} (len {}) on {window:02x?}, which iced rejects",
            o.mn, o.len
        ),
        // Out of scope. The caller reports it; it is not a defect here.
        (false, None) => {}
        (false, Some(o)) => {
            assert_eq!(
                o.len,
                iced.len(),
                "length disagrees on {window:02x?}: {:?} vs iced {:?}",
                o.mn,
                iced.mnemonic()
            );
            assert_eq!(
                o.mn.name(),
                format!("{:?}", iced.mnemonic()),
                "mnemonic disagrees on {window:02x?}"
            );
            check_memory(&o.ops, &iced, window);
            check_registers(&o, &iced, window);

            // Re-decoding from exactly the reported length must agree: a
            // decoder that reads further than it reports would still have
            // passed every check above.
            let exact = decode(&window[..o.len], ip)
                .unwrap_or_else(|| panic!("{window:02x?} does not decode from its own {} bytes", o.len));
            assert_eq!(exact.len, o.len, "length not self-consistent");
            assert_eq!(exact.mn, o.mn, "mnemonic not self-consistent");

            // No proper prefix of an instruction may decode.
            for cut in 1..o.len {
                assert!(
                    decode(&window[..cut], ip).is_none(),
                    "{window:02x?} decoded from a truncated {cut} of {} bytes",
                    o.len
                );
            }
        }
    }
});
