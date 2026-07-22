//! Emit `crates/exav-x86/src/generated.rs`: the opcode maps this crate cannot
//! reasonably hand-write, read off what `iced-x86` decodes rather than
//! transcribed from a manual.
//!
//! Run it through `scripts/gen-x86-tables.sh`, which writes the result into
//! place and formats it. It is its own workspace so that it stays runnable
//! while `exav-x86` does not compile — the state any change to the cell layout
//! leaves the crate in until this has run.
//!
//! Only a few facts per cell are needed, and each one is a fact a decoder
//! cannot infer from the bytes:
//!
//! * which instruction an encoding names;
//! * how many immediate bytes follow the ModRM/SIB/displacement — the
//!   displacement itself is computed by the decoder's own ModRM logic, so it
//!   must not be baked in here;
//! * for VEX, whether the encoding rejects a `vvvv` field other than `1111`.
//!
//! `iced-x86` is MIT-licensed; the attribution is in `NOTICE`.

use iced_x86::{Decoder, DecoderOptions, Register};
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// The eight 32-bit general-purpose registers, in encoding order. A memory
/// operand whose index is outside this set is a VSIB one.
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

/// The mandatory-prefix combinations a `0F` encoding can carry. `66` together
/// with `F3` or `F2` is not the same column as either alone — several
/// encodings that are valid under one are rejected under both — so the pair
/// gets its own column rather than being folded into the winner.
const PFX: [&[u8]; 6] = [&[], &[0x66], &[0xf3], &[0xf2], &[0x66, 0xf3], &[0x66, 0xf2]];

/// The tail appended to every probe, long enough that no encoding runs out of
/// bytes and distinctive enough that a misread immediate shows up as a wrong
/// length rather than a plausible one.
const TAIL: [u8; 10] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa];

/// A ModRM byte selecting `[ecx]`: `mod=00 rm=001`, which has neither a SIB
/// byte nor a displacement, so everything past it is immediate.
fn modrm_mem(digit: u8) -> u8 {
    (digit << 3) | 1
}

/// A ModRM byte selecting `ecx`: `mod=11 rm=001`.
fn modrm_reg(digit: u8) -> u8 {
    0xc0 | (digit << 3) | 1
}

fn decode(b: &[u8]) -> Option<iced_x86::Instruction> {
    let mut d = Decoder::with_ip(32, b, 0x1000, DecoderOptions::NONE);
    let i = d.decode();
    (!i.is_invalid()).then_some(i)
}

/// A table cell: the mnemonic's name and the number of immediate bytes.
type Cell = Option<(String, u8)>;

/// Decode `head ++ tail` and read back the mnemonic and the immediate size,
/// where `head` is everything up to and including the ModRM byte.
///
/// Anything past four immediate bytes means the probe picked a form with a
/// displacement after all; that is reported as unrepresentable rather than
/// guessed at.
fn probe(head: &[u8]) -> Cell {
    probe_counting(head, head.len())
}

/// The same, where the bytes the opcode actually consumes are fewer than the
/// bytes placed. An opcode that reads no ModRM byte still has to be probed with
/// one present — otherwise the tail's first byte lands where the ModRM would
/// be, and `0F 20`, which ignores `mod` but not `reg`, is probed at the wrong
/// register — but that byte must not be counted as consumed.
fn probe_counting(head: &[u8], consumed: usize) -> Cell {
    let mut b = head.to_vec();
    b.extend_from_slice(&TAIL);
    let i = decode(&b)?;
    let imm = i.len().checked_sub(consumed)?;
    (imm <= 4).then(|| (format!("{:?}", i.mnemonic()), imm as u8))
}

// ---------------------------------------------------------------------------
// The `0F` map
// ---------------------------------------------------------------------------

/// Decode `prefix 0F op modrm <tail>` and return `(mnemonic, immediate bytes)`.
fn probe_0f(pfx: &[u8], op: u8, modrm: u8, has_modrm: bool) -> Cell {
    let mut head = pfx.to_vec();
    head.extend_from_slice(&[0x0f, op, modrm]);
    // An opcode with no ModRM byte is shorter than one with; subtracting a byte
    // that was never consumed is what makes a valid instruction look invalid.
    probe_counting(&head, pfx.len() + 2 + usize::from(has_modrm))
}

/// Does this opcode take a ModRM byte?
///
/// Probed behaviourally rather than assumed: `mod=00 rm=101` encodes a bare
/// `disp32` and `mod=11` encodes a register, so an opcode that reads a ModRM
/// byte decodes four bytes longer for the first than the second. One that does
/// not read one decodes the same length either way.
fn has_modrm(pfx: &[u8], op: u8) -> bool {
    let len = |second: u8| -> Option<usize> {
        let mut b = pfx.to_vec();
        b.extend_from_slice(&[0x0f, op, second]);
        b.extend_from_slice(&TAIL);
        decode(&b).map(|i| i.len())
    };
    match (len(0x05), len(0xc0)) {
        (Some(a), Some(b)) => a != b,
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// VEX and XOP
// ---------------------------------------------------------------------------
//
// The two share a shape: a three-byte prefix carrying an opcode-map selector,
// `W`, an inverted `vvvv`, `L` and a mandatory-prefix field, then the opcode
// and a ModRM byte. Only the prefix byte and the map numbering differ — `C4`
// selects maps 1-3 (`0F`, `0F 38`, `0F 3A`), `8F` selects 8-10 — so the probing
// is written once and run twice.

/// `C4`: the VEX prefix, and the maps it selects.
const VEX: (u8, u8) = (0xc4, 1);
/// `8F`: AMD's XOP prefix, and the maps it selects.
const XOP: (u8, u8) = (0x8f, 8);

/// Build a three-byte VEX or XOP instruction head, up to and including the
/// ModRM byte.
///
/// `RXB` is set to all-ones: 32-bit mode ignores those bits, but the byte has
/// to look like `mod == 3` (for `C4`) or like a non-zero `/digit` (for `8F`) or
/// the prefix decodes as `les` or `pop` instead. `vvvv` is written as the
/// encoding's own inverted field, so `0b1111` is the "no register" value that
/// the encodings which forbid a `vvvv` operand require.
fn vex_head(pfx: u8, map: u8, w: u8, vvvv: u8, l: u8, pp: u8, op: u8, modrm: u8) -> Vec<u8> {
    vec![
        pfx,
        0xe0 | map,
        (w << 7) | ((vvvv & 0xf) << 3) | (l << 2) | pp,
        op,
        modrm,
    ]
}

/// `[map][pp][L][W][opcode]`, flattened, relative to the family's first map.
fn vex_index(base: u8, map: u8, pp: u8, l: u8, w: u8, op: u8) -> usize {
    ((((map - base) as usize * 4 + pp as usize) * 2 + l as usize) * 2 + w as usize) * 256
        + op as usize
}

const VEX_CELLS: usize = 3 * 4 * 2 * 2 * 256;

/// One family's tables: the dense `[map][pp][L][W][opcode]` grid, a flag per
/// cell saying whether it spilled into a block, and the blocks themselves.
#[derive(Default)]
struct VexTables {
    direct: Vec<Option<VexCell>>,
    is_sub: Vec<bool>,
    sub: Vec<Option<VexCell>>,
}

/// A VEX cell: mnemonic, immediate bytes, whether a `vvvv` field other than
/// `1111` is rejected, whether the opcode reads a ModRM byte at all, and
/// whether its SIB index names a vector register.
struct VexCell {
    name: String,
    imm: u8,
    strict_vvvv: bool,
    no_modrm: bool,
    vsib: bool,
}

/// Does this encoding index memory with a vector register rather than a
/// general-purpose one? The gathers and scatters do, and a decoder that
/// reports their index as a GPR number is naming the wrong register file.
///
/// Probed with `mod=00 rm=100`, which forces a SIB byte, with `index=001` and
/// `base=000`. The destination is register 2 and the mask register `vvvv`
/// reads as 0, so no two of the three registers a gather names collide — a
/// collision is itself invalid, and would hide the VSIB.
fn vex_vsib(pfx: u8, map: u8, w: u8, l: u8, pp: u8, op: u8) -> bool {
    let mut b = vex_head(pfx, map, w, 0b1111, l, pp, op, 0x14);
    b.push(0x08);
    b.extend_from_slice(&TAIL);
    match decode(&b) {
        Some(i) => {
            let idx = i.memory_index();
            idx != Register::None && !GPR32.contains(&idx)
        }
        None => false,
    }
}

/// Does this VEX opcode read a ModRM byte? Almost all do; `vzeroupper` and
/// `vzeroall` are the encodings that do not, and treating their next byte as a
/// ModRM gets both the length and the operand wrong.
///
/// Probed the same way as the `0F` map: `mod=00 rm=101` is a bare `disp32` and
/// `mod=11` is a register, so an opcode that reads the byte decodes four bytes
/// longer for the first than for the second.
fn vex_has_modrm(pfx: u8, map: u8, w: u8, l: u8, pp: u8, op: u8) -> bool {
    let len = |second: u8| -> Option<usize> {
        let mut b = vex_head(pfx, map, w, 0b1111, l, pp, op, second);
        b.extend_from_slice(&TAIL);
        decode(&b).map(|i| i.len())
    };
    match (len(0x05), len(0xc0)) {
        (Some(a), Some(b)) => a != b,
        _ => true,
    }
}

#[allow(clippy::too_many_arguments)]
fn probe_vex(
    pfx: u8,
    map: u8,
    pp: u8,
    l: u8,
    w: u8,
    op: u8,
    modrm: u8,
    has_modrm: bool,
    vsib: bool,
) -> Option<VexCell> {
    // A gather or scatter indexes memory with a vector register, which is only
    // expressible through a SIB byte — `mod=00 rm=001` is not an encoding of
    // one at all, so probing these with the usual memory ModRM decodes nothing
    // and the whole family would be missing from the map.
    //
    // The three vector registers such an encoding names — destination, index
    // and mask — must all differ, or it is invalid for a reason that has
    // nothing to do with the opcode. Fixing the mask at `vvvv = 0` would
    // decline the destination-`xmm0` form for every gather, so the registers
    // are chosen per digit instead.
    let mod3 = modrm >= 0xc0;
    let free = |used: [u8; 3]| (0u8..8).find(|r| !used.contains(r)).expect("8 registers, 3 used");
    let (modrm, sib, vvvv_a, vvvv_b) = if vsib && !mod3 {
        let digit = (modrm >> 3) & 7;
        let index = if digit == 1 { 2 } else { 1 };
        let m1 = free([digit, index, 8]);
        let m2 = free([digit, index, m1]);
        // `mod=00 rm=100` is a SIB byte; `scale=0 base=000` with the chosen
        // index, and no displacement.
        ((modrm & 0xf8) | 4, Some(index << 3), !m1 & 0xf, !m2 & 0xf)
    } else {
        (modrm, None, 0b1111, 0b1110)
    };

    let mut head = vex_head(pfx, map, w, vvvv_a, l, pp, op, modrm);
    head.extend(sib);
    let (name, imm) = probe_counting(&head, head.len() - usize::from(!has_modrm))?;
    // `1110` is `vvvv = 1`: a legal register for the encodings that take one,
    // and a rejected field for the encodings that do not. For a VSIB encoding
    // `vvvv` is the mask, so the alternative is a second non-colliding register
    // rather than a fixed one — a collision would decode as invalid and be read
    // as "this opcode rejects the field", which would then reject every legal
    // mask a caller might pass.
    let mut b = vex_head(pfx, map, w, vvvv_b, l, pp, op, modrm);
    b.extend(sib);
    b.extend_from_slice(&TAIL);
    let strict_vvvv = decode(&b).map_or(true, |i| format!("{:?}", i.mnemonic()) != name);
    Some(VexCell {
        name,
        imm,
        strict_vvvv,
        no_modrm: !has_modrm,
        vsib,
    })
}

// ---------------------------------------------------------------------------
// Operand shapes for the `0F` map
// ---------------------------------------------------------------------------
//
// The generated cells above give an encoding its identity and its length,
// which is all a linear disassembly needs. An *emulator* needs more: which
// register file each operand names, which way round the two are, and how wide
// a memory operand is.
//
// Nearly every SSE and MMX encoding fits one shape — a `reg`-field operand and
// an `rm`-field operand, in one order or the other, optionally followed by an
// `imm8`. That shape is what is recorded here. An encoding that does not fit
// is marked as having no modelled operands, which is exactly what the decoder
// already reports for it, so nothing regresses by being left out.

/// The register file an operand names, at the width it names it.
///
/// The width has to be recorded rather than taken from the operand-size
/// prefix: in a SIMD encoding a `66` is a *mandatory* prefix selecting the
/// opcode, not an operand-size override, so `66 0F 6E` moves a full 32-bit
/// register into an XMM one despite the `66`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    Gpr32,
    Xmm,
    Mmx,
    Gpr16,
    Gpr8,
}

fn class_of(r: Register) -> Option<Class> {
    if GPR32.contains(&r) {
        Some(Class::Gpr32)
    } else if XMM.contains(&r) {
        Some(Class::Xmm)
    } else if MMX.contains(&r) {
        Some(Class::Mmx)
    } else if GPR16.contains(&r) {
        Some(Class::Gpr16)
    } else if GPR8.contains(&r) {
        Some(Class::Gpr8)
    } else {
        None
    }
}

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

/// What the decoder needs to build an encoding's operands.
struct Shape {
    /// The `reg`-field operand comes first.
    reg_first: bool,
    /// There is no `reg`-field operand: those bits are a group digit. This is
    /// the shift groups — `psrlw mm, imm8` and its relatives.
    rm_only: bool,
    reg_class: Class,
    rm_class: Class,
    /// Width of the `rm` operand when it addresses memory, in bytes. Zero when
    /// the encoding has no memory form at all.
    mem_bytes: u8,
    has_imm8: bool,
}

/// Read an encoding's operand shape off two decodes: one with `mod == 3`, which
/// shows which register file each side names and which way round they are, and
/// one addressing memory, which shows how wide the memory operand is.
///
/// `reg = 1` and `rm = 2` are chosen so the two register numbers differ — that
/// difference is the only thing that says which operand came from which field.
fn probe_shape(pfx: &[u8], op: u8) -> Option<Shape> {
    probe_shape_in(pfx, &[], op)
}

/// The same for a three-byte escape: `escape` is the byte between `0F` and the
/// opcode, empty for the two-byte map.
fn probe_shape_in(pfx: &[u8], escape: &[u8], op: u8) -> Option<Shape> {
    // Each `/digit` is its own encoding, so a probe pinned to one digit sees
    // nothing when that digit is not defined. The shift groups (`0F 71/72/73`)
    // define no `/1`, which is exactly the family the `rm_only` shape exists
    // for — so pinning digit 1 dropped every shape the branch was written to
    // describe, and the branch never ran.
    //
    // Before taking a shape from any digit, rule out the opcode entirely if ANY
    // digit shows a memory form with fewer operands than its register form.
    // That is what a GROUP opcode looks like — `0F 18`'s `/0../3` are prefetch
    // hints taking one memory operand, while its register forms render as
    // two-operand aliases — and the digits where the memory form is undefined
    // would otherwise slip a second operand into the table for an instruction
    // that has one.
    if (0..8).any(|digit| group_digit_evidence(pfx, escape, op, digit)) {
        return None;
    }
    (0..8).find_map(|digit| probe_shape_at(pfx, escape, op, digit))
}

/// Whether this `(opcode, digit)` shows the `reg` field acting as a group digit
/// rather than naming an operand.
/// The memory access width for `(pfx, escape, op)`, from whichever digit has a
/// memory form. Zero when none does or the width is one this crate cannot carry.
fn probe_mem_width(pfx: &[u8], escape: &[u8], op: u8) -> u8 {
    (0..8)
        .find_map(|digit| {
            let mut b = pfx.to_vec();
            b.push(0x0f);
            b.extend_from_slice(escape);
            b.extend_from_slice(&[op, (digit << 3) | 1]);
            b.extend_from_slice(&TAIL);
            decode(&b).map(|m| m.memory_size().size())
        })
        .filter(|n| *n > 0 && *n <= 63)
        .map_or(0, |n| n as u8)
}

fn group_digit_evidence(pfx: &[u8], escape: &[u8], op: u8, digit: u8) -> bool {
    let head = |modrm: u8| -> Vec<u8> {
        let mut b = pfx.to_vec();
        b.push(0x0f);
        b.extend_from_slice(escape);
        b.extend_from_slice(&[op, modrm]);
        b.extend_from_slice(&TAIL);
        b
    };
    let reg_form = decode(&head(0xc0 | (digit << 3) | 2));
    let mem_form = decode(&head((digit << 3) | 1));
    match (reg_form, mem_form) {
        (Some(r), Some(m)) => m.op_count() < r.op_count(),
        _ => false,
    }
}

fn probe_shape_at(pfx: &[u8], escape: &[u8], op: u8, digit: u8) -> Option<Shape> {
    let head = |modrm: u8| -> Vec<u8> {
        let mut b = pfx.to_vec();
        b.push(0x0f);
        b.extend_from_slice(escape);
        b.extend_from_slice(&[op, modrm]);
        b
    };
    let mut b = head(0xc0 | (digit << 3) | 2);
    b.extend_from_slice(&TAIL);
    let i = decode(&b)?;
    let imm8_at = |n: u32| i.op_count() == n + 1 && i.op_kind(n) == iced_x86::OpKind::Immediate8;
    let reg_at = |n: u32| i.op_kind(n) == iced_x86::OpKind::Register;

    // The memory form, for the width. `mod=00 rm=001` is `[ecx]`. An encoding
    // with no memory form — the shift groups have none — reports zero, which is
    // never read because the operand can only be a register.
    // The memory form, both for its width and as a cross-check. An encoding
    // whose memory form reports FEWER operands than its register form does not
    // name the `reg` field at all — it is a group digit selecting the variant,
    // as in `0F 0D` prefetch and `0F 18` hint-nop, whose register forms iced
    // renders as two-operand aliases. Recording a shape from the register probe
    // alone made the decoder report an operand the instruction does not have.
    let mem_probe = {
        let mut b = head((digit << 3) | 1);
        b.extend_from_slice(&TAIL);
        decode(&b)
    };
    if let Some(m) = &mem_probe {
        if m.op_count() < i.op_count() {
            return None;
        }
    }
    let mem_bytes = match mem_probe.map(|m| m.memory_size().size()) {
        Some(n) if n > 0 && n <= 16 => n as u8,
        Some(_) => return None,
        None => 0,
    };

    // One register operand and an `imm8`: the `reg` bits are a group digit, not
    // an operand. `psrlw mm, imm8` and the rest of the shift groups.
    if reg_at(0) && imm8_at(1) {
        let c = class_of(i.op_register(0))?;
        // `rm = 2` above, so the operand must read as register 2 — otherwise
        // the probe is looking at something whose operand is not the `rm` field.
        if reg_num(i.op_register(0))? != 2 {
            return None;
        }
        return Some(Shape {
            reg_first: false,
            rm_only: true,
            reg_class: c,
            rm_class: c,
            mem_bytes,
            has_imm8: true,
        });
    }

    // The same shape without an immediate: ONE operand, and it is the `r/m`
    // field. `0F 1F` — the multi-byte NOP — is the family here, and without this
    // the decoder falls back to emitting `reg` and `rm` both, reporting a second
    // operand the instruction does not have.
    if i.op_count() == 1 && reg_at(0) {
        let c = class_of(i.op_register(0))?;
        if reg_num(i.op_register(0))? != 2 {
            return None;
        }
        return Some(Shape {
            reg_first: false,
            rm_only: true,
            reg_class: c,
            rm_class: c,
            mem_bytes,
            has_imm8: false,
        });
    }

    // Two register operands, optionally an `imm8`. Anything else — an implicit
    // operand, a third register, a wider immediate — is not this shape.
    let has_imm8 = imm8_at(2);
    if (i.op_count() != 2 && !has_imm8) || !reg_at(0) || !reg_at(1) {
        return None;
    }
    let (c0, c1) = (class_of(i.op_register(0))?, class_of(i.op_register(1))?);
    let (n0, n1) = (reg_num(i.op_register(0))?, reg_num(i.op_register(1))?);
    // One side must read as the probed digit (the `reg` field) and the other as
    // register 2 (the `rm` field); if both read the same, the probe cannot tell
    // them apart. Comparing against `digit` rather than a fixed 1 is what keeps
    // a GROUP opcode out: where `reg` is a digit selecting the variant rather
    // than naming a register — `0F 0D` prefetch, `0F 18` hint-nop — the operand
    // iced reports does not track the digit, so no shape is recorded and the
    // decoder does not invent a second operand the instruction does not have.
    if digit == 2 {
        return None;
    }
    let reg_first = match (n0, n1) {
        (a, 2) if a == digit => true,
        (2, b) if b == digit => false,
        _ => return None,
    };
    let (reg_class, rm_class) = if reg_first { (c0, c1) } else { (c1, c0) };
    // `mem_bytes == 0` means "no memory form", which the comment above already
    // promises is a legitimate answer — the register-only encodings say exactly
    // that. Discarding the shape here threw away `movmskps`, `pmovmskb`,
    // `pextrw` and `movbe` among others, so they decoded with no operands at
    // all; `pmovmskb` appears in real unpacker loops. `sized_mem` passes a
    // register operand through untouched, so a zero width is never read.
    Some(Shape {
        reg_first,
        rm_only: false,
        reg_class,
        rm_class,
        mem_bytes,
        has_imm8,
    })
}

/// The register's number within its file, whichever file that is.
fn reg_num(r: Register) -> Option<u8> {
    for set in [&GPR32, &XMM, &MMX, &GPR16, &GPR8] {
        if let Some(i) = set.iter().position(|x| *x == r) {
            return Some(i as u8);
        }
    }
    None
}

/// Pack a shape, or — when the register shape is not modelled — just the memory
/// ACCESS WIDTH, with bit 0 left clear.
///
/// The width is a separate fact from which register file each side names, and it
/// is the one an emulator sizes its read or write from. Emitting it only
/// alongside a full shape left every unmodelled encoding reporting the operand
/// size instead: four bytes for `lgdt`'s six, for `prefetch`'s one, for
/// `movlps`'s eight. Bit 0 still means "the register shape is modelled", so a
/// width-only word reports operands exactly as before and only sizes them.
fn shape_word_or_width(s: &Option<Shape>, width: u8) -> u16 {
    match s {
        Some(_) => shape_word(s),
        None => u16::from(width) << 10,
    }
}

fn shape_word(s: &Option<Shape>) -> u16 {
    let Some(s) = s else { return 0 };
    let c = |x: Class| -> u16 {
        match x {
            Class::Gpr32 => 0,
            Class::Xmm => 1,
            Class::Mmx => 2,
            Class::Gpr16 => 3,
            Class::Gpr8 => 4,
        }
    };
    // Bit 0 marks the word as populated at all, so a shape whose every other
    // field is zero is still distinguishable from "not modelled".
    1 | (u16::from(s.reg_first) << 1)
        | (c(s.reg_class) << 2)
        | (c(s.rm_class) << 5)
        | (u16::from(s.has_imm8) << 8)
        | (u16::from(s.rm_only) << 9)
        | (u16::from(s.mem_bytes) << 10)
}

// ---------------------------------------------------------------------------
// EVEX
// ---------------------------------------------------------------------------

/// Build an EVEX instruction head, up to and including the ModRM byte.
///
/// `RXB` and `R'` extend register numbers that do not exist in 32-bit mode, so
/// they are set to all-ones: the processor ignores them, but the byte still has
/// to look like `mod == 3` or `62` is `bound`. `V'` and `P1` bit 2 are not
/// ignored — 32-bit mode requires both set — and `P0` bits 3-2 are reserved.
#[allow(clippy::too_many_arguments)]
fn evex_head(
    mm: u8,
    w: u8,
    vvvv: u8,
    pp: u8,
    z: u8,
    ll: u8,
    b: u8,
    aaa: u8,
    op: u8,
    modrm: u8,
) -> Vec<u8> {
    vec![
        0x62,
        0b1111_0000 | mm,
        (w << 7) | ((vvvv & 0xf) << 3) | 0b100 | pp,
        (z << 7) | (ll << 5) | (b << 4) | 0b1000 | aaa,
        op,
        modrm,
    ]
}

/// `[mm][pp][W][L'L][b][opcode]`, flattened. Sparse on emission: most of this
/// space is not an encoding.
fn evex_key(mm: u8, pp: u8, w: u8, ll: u8, b: u8, op: u8) -> u32 {
    ((((mm as u32 * 4 + pp as u32) * 2 + w as u32) * 4 + ll as u32) * 2 + b as u32) * 256
        + op as u32
}

const EVEX_KEYS: u32 = 8 * 4 * 2 * 4 * 2 * 256;

/// An EVEX cell. Beyond a VEX cell it carries `N`, the factor an EVEX `disp8`
/// is multiplied by — which is why a compressed displacement cannot be computed
/// from the ModRM byte alone — and which mask-field values the encoding rejects.
struct EvexCell {
    name: String,
    imm: u8,
    /// `log2` of the `disp8` scale factor, 0..=6.
    disp8_shift: u8,
    strict_vvvv: bool,
    /// The encoding requires a non-zero mask register.
    needs_mask: bool,
    /// The encoding forbids one — it writes a mask rather than reading one.
    forbids_mask: bool,
    /// The encoding forbids zeroing-merge.
    forbids_z: bool,
    /// The encoding indexes memory with a vector register.
    vsib: bool,
}

/// Does this EVEX encoding index memory with a vector register? The gathers do,
/// and the scatters — which EVEX encodes and nothing else does — are the reason
/// this cannot be skipped: leave it out and `vscatterdps` is not in the map at
/// all, so the decoder declines a real instruction rather than reporting it.
///
/// Probed with `mod=00 rm=100`, which forces a SIB byte, with `index=001` and
/// `base=000`. The destination is register 2, so it does not collide with the
/// index — a gather rejects that, for a reason that has nothing to do with the
/// opcode. The mask is `aaa = 1`, which the gathers require.
#[allow(clippy::too_many_arguments)]
fn evex_vsib(mm: u8, w: u8, pp: u8, ll: u8, b: u8, op: u8) -> bool {
    let mut v = evex_head(mm, w, 0b1111, pp, 0, ll, b, 1, op, 0x14);
    v.push(0x08);
    v.extend_from_slice(&TAIL);
    match decode(&v) {
        Some(i) => {
            let idx = i.memory_index();
            idx != Register::None && !GPR32.contains(&idx)
        }
        None => false,
    }
}

/// A memory ModRM and its SIB byte for one `/digit`, VSIB or not.
///
/// For a VSIB encoding `mod=00 rm=001` is not a smaller form of the
/// instruction — it is not an encoding, so probing with it finds nothing and
/// the family goes missing from the map. `rm=100` names a SIB byte, whose index
/// must be a different register from the destination.
fn vsib_mem(digit: u8, vsib: bool) -> (u8, Option<u8>) {
    if !vsib {
        return (modrm_mem(digit), None);
    }
    let index = if digit == 1 { 2 } else { 1 };
    ((digit << 3) | 4, Some(index << 3))
}

/// The `disp8` scale factor, read off a decode rather than derived from the
/// instruction's tuple type: probing with `mod=01` and a displacement byte of
/// one makes iced report exactly `N`.
///
/// The probe carries the caller's `digit`, because the scale belongs to the
/// encoding and each `/digit` in a sub-block is a different one. Probing a fixed
/// digit gives every cell in the block digit 0's answer — and where digit 0 is
/// not an encoding at all the probe fails and yields 0, which reads as "do not
/// scale". An unscaled displacement addresses the wrong memory by up to 64x.
#[allow(clippy::too_many_arguments)]
fn evex_disp8_n(mm: u8, w: u8, pp: u8, ll: u8, b: u8, aaa: u8, op: u8, digit: u8, vsib: bool) -> u8 {
    // `mod=01`, so the byte after the addressing bytes is the displacement.
    let (modrm, sib) = vsib_mem(digit, vsib);
    let modrm = 0x40 | (modrm & 0x3f);
    let mut v = evex_head(mm, w, 0b1111, pp, 0, ll, b, aaa, op, modrm);
    v.extend(sib);
    v.push(0x01);
    v.extend_from_slice(&TAIL);
    match decode(&v) {
        Some(i) => {
            let n = i.memory_displacement32();
            // A scale is always a power of two from 1 to 64.
            if n.is_power_of_two() && n <= 64 {
                n.trailing_zeros() as u8
            } else {
                0
            }
        }
        None => 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn probe_evex(
    mm: u8,
    pp: u8,
    w: u8,
    ll: u8,
    b: u8,
    op: u8,
    modrm: u8,
    sib: Option<u8>,
    vsib: bool,
) -> Option<EvexCell> {
    let probe_at = |z: u8, aaa: u8| -> Cell {
        let mut head = evex_head(mm, w, 0b1111, pp, z, ll, b, aaa, op, modrm);
        head.extend(sib);
        probe_counting(&head, head.len())
    };
    // A non-zero mask register is the canonical probe: the encodings that
    // require one reject `aaa = 0`, and the few that write a mask rather than
    // reading one reject everything else.
    let (name, imm, aaa, needs_mask, forbids_mask) = match (probe_at(0, 1), probe_at(0, 0)) {
        (Some((n, i)), other) => (n, i, 1, other.is_none(), false),
        (None, Some((n, i))) => (n, i, 0, false, true),
        (None, None) => return None,
    };
    let strict_vvvv = {
        let mut head = evex_head(mm, w, 0b1110, pp, 0, ll, b, aaa, op, modrm);
        head.extend(sib);
        probe_counting(&head, head.len()).map_or(true, |(n, _)| n != name)
    };
    Some(EvexCell {
        name,
        imm,
        disp8_shift: evex_disp8_n(mm, w, pp, ll, b, aaa, op, (modrm >> 3) & 7, vsib),
        strict_vvvv,
        needs_mask,
        forbids_mask,
        // Zeroing-merge needs a mask to zero against, so `z` without one is
        // never an encoding; beyond that, a store has no destination register
        // to zero and rejects it too.
        forbids_z: aaa == 0 || probe_at(1, aaa).is_none(),
        vsib,
    })
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

fn imm_code(n: u8) -> u16 {
    match n {
        1 => 1,
        2 => 2,
        4 => 3,
        _ => 0,
    }
}

/// Format one flat table of integers.
fn emit_table<T: std::fmt::Display>(out: &mut String, doc: &str, name: &str, ty: &str, values: &[T]) {
    writeln!(out, "\n{doc}").unwrap();
    writeln!(
        out,
        // `static`, not `const`: a `const` array is a value that gets copied
        // into every use site, and these run to tens of thousands of entries.
        "pub(crate) static {name}: [{ty}; {}] = [",
        values.len()
    )
    .unwrap();
    for chunk in values.chunks(16) {
        out.push_str("    ");
        for v in chunk {
            write!(out, "{v},").unwrap();
        }
        out.push('\n');
    }
    out.push_str("];\n");
}

fn main() {
    let mut names: BTreeSet<String> = BTreeSet::new();
    let note = |c: &Cell, names: &mut BTreeSet<String>| {
        if let Some((n, _)) = c {
            names.insert(n.clone());
        }
    };

    // ---- the `0F` map -----------------------------------------------------
    let mut cells: Vec<Cell> = Vec::with_capacity(PFX.len() * 256 * 16);
    let mut modrm_bits: Vec<bool> = Vec::with_capacity(PFX.len() * 256);
    for pfx in PFX {
        for op in 0u16..=0xff {
            let hm = has_modrm(pfx, op as u8);
            modrm_bits.push(hm);
            for digit in 0u8..8 {
                for mod3 in [false, true] {
                    let modrm = if mod3 {
                        modrm_reg(digit)
                    } else {
                        modrm_mem(digit)
                    };
                    let c = probe_0f(pfx, op as u8, modrm, hm);
                    note(&c, &mut names);
                    cells.push(c);
                }
            }
        }
    }

    // Operand shapes, one per (prefix, opcode) of the `0F` map. Not per digit:
    // an encoding whose meaning varies by `/digit` is a group, and no group in
    // the SIMD region has a shape that varies with it.
    let mut shapes: Vec<u16> = Vec::with_capacity(PFX.len() * 256);
    for pfx in PFX {
        for op in 0u16..=0xff {
            shapes.push(shape_word(&probe_shape(pfx, op as u8)));
        }
    }

    // A few opcodes name a different instruction for every ModRM byte in the
    // register range rather than for every `/digit` — `0F 01` holds `vmcall`,
    // `monitor`, `swapgs` and friends there. Those get an exact list.
    let mut special: Vec<(usize, u8, u8, String, u8)> = Vec::new();
    for (pi, pfx) in PFX.iter().enumerate() {
        for op in 0u16..=0xff {
            let op = op as u8;
            let hm = has_modrm(pfx, op);
            let varies = (0u8..8).any(|digit| {
                let base = probe_0f(pfx, op, modrm_reg(digit), hm).map(|x| x.0);
                (0u8..8)
                    .any(|rm| probe_0f(pfx, op, 0xc0 | (digit << 3) | rm, hm).map(|x| x.0) != base)
            });
            if !varies {
                continue;
            }
            for modrm in 0xc0u16..=0xff {
                if let Some((n, imm)) = probe_0f(pfx, op, modrm as u8, hm) {
                    names.insert(n.clone());
                    special.push((pi, op, modrm as u8, n, imm));
                }
            }
        }
    }

    // ---- the three-byte escapes -------------------------------------------
    // The byte after `0F 38` / `0F 3A` is the real opcode and the ModRM comes
    // after that, so these get their own prefix x opcode tables.
    let mut escapes: Vec<(&str, Vec<Cell>)> = Vec::new();
    for (esc, label) in [(0x38u8, "OF38"), (0x3a, "OF3A")] {
        let mut esc_cells: Vec<Cell> = Vec::new();
        for pfx in PFX {
            for op in 0u16..=0xff {
                for digit in 0u8..8 {
                    for mod3 in [false, true] {
                        let modrm = if mod3 {
                            modrm_reg(digit)
                        } else {
                            modrm_mem(digit)
                        };
                        let mut head = pfx.to_vec();
                        head.extend_from_slice(&[0x0f, esc, op as u8, modrm]);
                        let c = probe(&head);
                        note(&c, &mut names);
                        esc_cells.push(c);
                    }
                }
            }
        }
        escapes.push((label, esc_cells));
    }

    // ---- 3DNow! -----------------------------------------------------------
    // `0F 0F` puts the opcode byte *after* the ModRM, SIB and displacement:
    // the instruction's identity is its last byte. Mandatory prefixes do not
    // select anything here, which is asserted rather than assumed.
    let mut now3d: Vec<Cell> = Vec::with_capacity(256);
    for suffix in 0u16..=0xff {
        let bytes = [0x0f, 0x0f, 0xc1, suffix as u8];
        let c = decode(&bytes).map(|i| {
            assert_eq!(i.len(), 4, "3DNow! suffix {suffix:02x} is not four bytes");
            (format!("{:?}", i.mnemonic()), 0u8)
        });
        for pfx in PFX {
            let mut b = pfx.to_vec();
            b.extend_from_slice(&bytes);
            let other = decode(&b).map(|i| format!("{:?}", i.mnemonic()));
            assert_eq!(
                other,
                c.clone().map(|x| x.0),
                "3DNow! suffix {suffix:02x} is not prefix-independent"
            );
        }
        note(&c, &mut names);
        now3d.push(c);
    }

    // ---- VEX and XOP ------------------------------------------------------
    // One cell per (map, pp, L, W, opcode). Most opcodes name the same
    // instruction for every ModRM byte, so those collapse to a single cell and
    // only the ones that do not — the shift groups, and the handful whose
    // register form is a different instruction — spill into a 16-entry block.
    let mut families: Vec<(&str, VexTables)> = Vec::new();
    for (label, (pfx, base)) in [("VEX", VEX), ("XOP", XOP)] {
        let mut t = VexTables::default();
        for map in base..base + 3 {
            for pp in 0u8..4 {
                for l in 0u8..2 {
                    for w in 0u8..2 {
                        for op in 0u16..=0xff {
                            let hm = vex_has_modrm(pfx, map, w, l, pp, op as u8);
                            let vs = vex_vsib(pfx, map, w, l, pp, op as u8);
                            let mut block: Vec<Option<VexCell>> = Vec::with_capacity(16);
                            for digit in 0u8..8 {
                                for mod3 in [false, true] {
                                    let modrm = if mod3 {
                                        modrm_reg(digit)
                                    } else {
                                        modrm_mem(digit)
                                    };
                                    block.push(probe_vex(
                                        pfx, map, pp, l, w, op as u8, modrm, hm, vs,
                                    ));
                                }
                            }
                            for c in block.iter().flatten() {
                                names.insert(c.name.clone());
                            }
                            let uniform = block.iter().all(|c| match (c, &block[0]) {
                                (None, None) => true,
                                (Some(a), Some(b)) => {
                                    a.name == b.name
                                        && a.imm == b.imm
                                        && a.strict_vvvv == b.strict_vvvv
                                        && a.no_modrm == b.no_modrm
                                        && a.vsib == b.vsib
                                }
                                _ => false,
                            });
                            assert_eq!(t.direct.len(), vex_index(base, map, pp, l, w, op as u8));
                            if uniform {
                                t.direct.push(block.into_iter().next().unwrap());
                                t.is_sub.push(false);
                            } else {
                                t.direct.push(None);
                                t.is_sub.push(true);
                                t.sub.extend(block);
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(t.direct.len(), VEX_CELLS);
        families.push((label, t));
    }

    // ---- EVEX -------------------------------------------------------------
    // Sparse, unlike VEX and XOP: the axis product is 131,072 cells and almost
    // all of them are not an encoding, so a dense grid would be mostly zeroes.
    // Keys are emitted sorted and binary-searched.
    let mut evex: Vec<(u32, Option<EvexCell>)> = Vec::new();
    let mut evex_sub: Vec<Option<EvexCell>> = Vec::new();
    let mut evex_is_sub: Vec<bool> = Vec::new();
    for mm in 0u8..8 {
        for pp in 0u8..4 {
            for w in 0u8..2 {
                for ll in 0u8..4 {
                    for b in 0u8..2 {
                        for op in 0u16..=0xff {
                            let vs = evex_vsib(mm, w, pp, ll, b, op as u8);
                            let mut block: Vec<Option<EvexCell>> = Vec::with_capacity(16);
                            for digit in 0u8..8 {
                                for mod3 in [false, true] {
                                    let (modrm, sib) = if mod3 {
                                        (modrm_reg(digit), None)
                                    } else {
                                        vsib_mem(digit, vs)
                                    };
                                    block.push(probe_evex(
                                        mm, pp, w, ll, b, op as u8, modrm, sib, vs,
                                    ));
                                }
                            }
                            if block.iter().all(|c| c.is_none()) {
                                continue;
                            }
                            for c in block.iter().flatten() {
                                names.insert(c.name.clone());
                            }
                            let uniform = block.iter().all(|c| match (c, &block[0]) {
                                (None, None) => true,
                                (Some(a), Some(b)) => {
                                    a.name == b.name
                                        && a.imm == b.imm
                                        && a.disp8_shift == b.disp8_shift
                                        && a.strict_vvvv == b.strict_vvvv
                                        && a.needs_mask == b.needs_mask
                                        && a.forbids_mask == b.forbids_mask
                                        && a.forbids_z == b.forbids_z
                                        && a.vsib == b.vsib
                                }
                                _ => false,
                            });
                            let key = evex_key(mm, pp, w, ll, b, op as u8);
                            if uniform {
                                evex.push((key, block.into_iter().next().unwrap()));
                                evex_is_sub.push(false);
                            } else {
                                evex.push((key, None));
                                evex_is_sub.push(true);
                                evex_sub.extend(block);
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(evex.windows(2).all(|w| w[0].0 < w[1].0), "keys must sort");
    assert!(evex.last().is_none_or(|(k, _)| *k < EVEX_KEYS));

    // ---- emit -------------------------------------------------------------
    let names: Vec<String> = names.into_iter().collect();
    let index = |n: &str| names.iter().position(|x| x == n).unwrap() as u16;
    let cell_word = |c: &Cell| -> u16 {
        match c {
            None => 0,
            Some((n, imm)) => ((index(n) + 1) << 2) | imm_code(*imm),
        }
    };

    let mut out = String::new();
    out.push_str(
        "//! The opcode maps, generated from the `iced-x86` decoder (MIT; see\n\
         //! `NOTICE`). Do not edit by hand — regenerate with\n\
         //! `scripts/gen-x86-tables.sh`.\n\
         //!\n\
         //! Each cell records the facts a decoder cannot infer: which instruction\n\
         //! an encoding names, how many immediate bytes follow the\n\
         //! ModRM/SIB/displacement, and for VEX whether the encoding rejects a\n\
         //! `vvvv` field other than `1111`. The displacement itself is *not* here —\n\
         //! that is computed by `modrm()`, so a change to addressing rules cannot be\n\
         //! contradicted by a stale table.\n",
    );

    writeln!(
        out,
        "\n/// Every mnemonic reachable through a generated map.\n\
         pub(crate) static OF_NAMES: [&str; {}] = [",
        names.len()
    )
    .unwrap();
    for n in &names {
        writeln!(out, "    \"{n}\",").unwrap();
    }
    out.push_str("];\n");

    emit_table(
        &mut out,
        "/// `[prefix][opcode][digit][mod==3]`, flattened. `0` is \"not an\n\
         /// encoding\"; otherwise bits 0-1 are the immediate size (0, 1, 2 or 4\n\
         /// bytes) and bits 2.. are `OF_NAMES` index + 1.\n\
         ///\n\
         /// Prefix order is none, `66`, `F3`, `F2`, `66 F3`, `66 F2`.",
        "OF_MAP",
        "u16",
        &cells.iter().map(cell_word).collect::<Vec<_>>(),
    );

    writeln!(
        out,
        "\n/// Opcodes whose register-range encodings vary by the whole ModRM byte\n\
         /// rather than by `/digit`. Sorted by `(prefix, opcode, modrm)` and\n\
         /// binary-searched; consulted before [`OF_MAP`] when `mod == 3`.\n\
         pub(crate) static OF_MOD3: [(u8, u8, u8, u16, u8); {}] = [",
        special.len()
    )
    .unwrap();
    for (pi, op, modrm, n, imm) in &special {
        writeln!(out, "    ({pi}, {op}, {modrm}, {}, {imm}),", index(n)).unwrap();
    }
    out.push_str("];\n");

    writeln!(
        out,
        "\n/// `[prefix][opcode]`: whether the opcode reads a ModRM byte. Probed by\n\
         /// decoding the same opcode with `mod=00 rm=101` and with `mod=11` and\n\
         /// comparing lengths, not assumed from the opcode's range.\n\
         pub(crate) static OF_HAS_MODRM: [bool; {}] = [",
        modrm_bits.len()
    )
    .unwrap();
    for chunk in modrm_bits.chunks(16) {
        out.push_str("    ");
        for b in chunk {
            write!(out, "{b},").unwrap();
        }
        out.push('\n');
    }
    out.push_str("];\n");

    emit_table(
        &mut out,
        "/// `[prefix][opcode]` operand shapes for the `0F` map. `0` means the\n\
         /// encoding's operands are not modelled — the decoder reports its\n\
         /// identity and length and nothing else, which is what an emulator\n\
         /// needs in order to decline it rather than misread it.\n\
         ///\n\
         /// Otherwise bit 0 marks the word populated, bit 1 says the `reg`-field\n\
         /// operand comes first, bits 2-4 and 5-7 are the register file of the\n\
         /// `reg` and `rm` operands (0 32-bit general-purpose, 1 XMM, 2 MMX,\n\
         /// 3 16-bit, 4 8-bit), bit 8 marks a trailing `imm8` operand, bit 9\n\
         /// says there is no `reg`-field operand at all because those bits are\n\
         /// a group digit, and bits 10.. are the width in bytes of the `rm`\n\
         /// operand when it addresses memory (zero when there is no memory\n\
         /// form).\n\
         ///\n\
         /// The register width is recorded rather than taken from the\n\
         /// operand-size prefix: in this region a `66` selects the opcode, so\n\
         /// `66 0F 6E` moves a full 32-bit register into an XMM one.",
        "OF_SHAPE",
        "u16",
        &shapes,
    );

    for (label, esc) in [("OF38", 0x38u8), ("OF3A", 0x3a)] {
        let mut sh: Vec<u16> = Vec::with_capacity(PFX.len() * 256);
        for pfx in PFX {
            for op in 0u16..=0xff {
                sh.push(shape_word(&probe_shape_in(pfx, &[esc], op as u8)));
            }
        }
        emit_table(
            &mut out,
            &format!(
                "/// `[prefix][opcode]` operand shapes for the `{label}` escape,\n\
                 /// encoded like [`OF_SHAPE`]."
            ),
            &format!("{label}_SHAPE"),
            "u16",
            &sh,
        );
    }

    for (label, esc_cells) in &escapes {
        emit_table(
            &mut out,
            &format!(
                "/// `[prefix][opcode][digit][mod==3]` for the `{label}` three-byte\n\
                 /// escape, encoded like [`OF_MAP`]."
            ),
            &format!("{label}_MAP"),
            "u16",
            &esc_cells.iter().map(cell_word).collect::<Vec<_>>(),
        );
    }

    emit_table(
        &mut out,
        "/// 3DNow!, indexed by the suffix byte that follows the operands. `0` is\n\
         /// \"not an encoding\"; otherwise bits 2.. are `OF_NAMES` index + 1. The\n\
         /// immediate field is unused: the suffix *is* the opcode, and nothing\n\
         /// follows it.",
        "NOW3D_MAP",
        "u16",
        &now3d.iter().map(cell_word).collect::<Vec<_>>(),
    );

    // A VEX cell carries three flags the `0F` cells do not, so it gets a wider
    // word rather than a tighter packing: an opcode index squeezed against a
    // flag bit is one new mnemonic away from silently aliasing.
    let vex_word = |c: &Option<VexCell>| -> u32 {
        match c {
            None => 0,
            Some(c) => {
                (u32::from(index(&c.name) + 1) << 6)
                    | u32::from(imm_code(c.imm))
                    | (u32::from(c.no_modrm) << 2)
                    | (u32::from(c.strict_vvvv) << 3)
                    | (u32::from(c.vsib) << 4)
            }
        }
    };
    let mut sizes = Vec::new();
    for (label, t) in &families {
        let mut words = Vec::with_capacity(VEX_CELLS);
        let mut block = 0u32;
        for (i, c) in t.direct.iter().enumerate() {
            if t.is_sub[i] {
                words.push((block << 6) | (1 << 5));
                block += 1;
            } else {
                words.push(vex_word(c));
            }
        }
        let maps = if *label == "VEX" {
            "`0F`, `0F 38`, `0F 3A`"
        } else {
            "XOP 8, 9 and 10"
        };
        emit_table(
            &mut out,
            &format!(
                "/// `[map][pp][L][W][opcode]`, flattened, where map is {maps} and\n\
                 /// `pp` is none, `66`, `F3`, `F2`.\n\
                 ///\n\
                 /// `0` is \"not an encoding\". Otherwise bits 0-1 are the immediate\n\
                 /// size, bit 2 marks an opcode that reads no ModRM byte, bit 3 one\n\
                 /// that rejects a `vvvv` field other than `1111`, bit 4 one whose\n\
                 /// SIB index is a vector register, and bit 5 says the rest is a\n\
                 /// block index into [`{label}_SUB`] rather than a mnemonic. Bits 6..\n\
                 /// are that block index, or `OF_NAMES` index + 1."
            ),
            &format!("{label}_MAP"),
            "u32",
            &words,
        );
        emit_table(
            &mut out,
            &format!(
                "/// Sixteen cells per [`{label}_MAP`] block, indexed `[digit][mod==3]`\n\
                 /// and encoded like a direct `{label}_MAP` cell. A block is emitted\n\
                 /// for the opcodes whose meaning varies across those sixteen."
            ),
            &format!("{label}_SUB"),
            "u32",
            &t.sub.iter().map(vex_word).collect::<Vec<_>>(),
        );
        sizes.push(format!("{label} {} + {}", words.len(), t.sub.len()));
    }

    let evex_word = |c: &Option<EvexCell>| -> u32 {
        match c {
            None => 0,
            Some(c) => {
                (u32::from(index(&c.name) + 1) << 11)
                    | u32::from(imm_code(c.imm))
                    | (u32::from(c.disp8_shift) << 3)
                    | (u32::from(c.strict_vvvv) << 6)
                    | (u32::from(c.needs_mask) << 7)
                    | (u32::from(c.forbids_mask) << 8)
                    | (u32::from(c.forbids_z) << 9)
                    | (u32::from(c.vsib) << 10)
            }
        }
    };
    let mut evex_keys = Vec::with_capacity(evex.len());
    let mut evex_words = Vec::with_capacity(evex.len());
    let mut block = 0u32;
    for (i, (key, c)) in evex.iter().enumerate() {
        evex_keys.push(*key);
        if evex_is_sub[i] {
            evex_words.push((block << 11) | (1 << 2));
            block += 1;
        } else {
            evex_words.push(evex_word(c));
        }
    }
    emit_table(
        &mut out,
        "/// The keys of [`EVEX_CELLS`], sorted and binary-searched. A key is\n\
         /// `[mm][pp][W][L'L][b][opcode]` flattened; the space is 131,072 wide and\n\
         /// almost all of it is not an encoding, so it is stored sparsely rather\n\
         /// than as a grid of zeroes.",
        "EVEX_KEYS",
        "u32",
        &evex_keys,
    );
    emit_table(
        &mut out,
        "/// One cell per [`EVEX_KEYS`] entry, at the same index.\n\
         ///\n\
         /// Bits 0-1 are the immediate size; bit 2 says bits 11.. are a block\n\
         /// index into [`EVEX_SUB`] rather than a mnemonic; bits 3-5 are `log2`\n\
         /// of the `disp8` scale factor, which is why a compressed displacement\n\
         /// cannot be computed from the ModRM byte alone; bit 6 rejects a `vvvv`\n\
         /// other than `1111`; bit 7 requires a non-zero mask register and bit 8\n\
         /// forbids one; bit 9 forbids zeroing-merge; bit 10 indexes memory with\n\
         /// a vector register, which only a SIB byte encodes. Bits 11.. are the\n\
         /// block index or `OF_NAMES` index + 1.",
        "EVEX_CELLS",
        "u32",
        &evex_words,
    );
    emit_table(
        &mut out,
        "/// Sixteen cells per [`EVEX_CELLS`] block, indexed `[digit][mod==3]` and\n\
         /// encoded like a direct cell.",
        "EVEX_SUB",
        "u32",
        &evex_sub.iter().map(evex_word).collect::<Vec<_>>(),
    );
    sizes.push(format!(
        "EVEX {} of {EVEX_KEYS} keys + {}",
        evex_keys.len(),
        evex_sub.len()
    ));

    print!("{out}");
    eprintln!(
        "{} distinct mnemonics; 0F {} cells, escapes {} each, 3DNow! {}, {}",
        names.len(),
        cells.len(),
        escapes[0].1.len(),
        now3d.len(),
        sizes.join(", "),
    );
}
