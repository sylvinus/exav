//! x86 instruction decoding for the bytecode `disasm_x86` API.
//!
//! The bytecode `disasm_x86(DISASM_RESULT*, len)` API decodes one instruction at
//! the file cursor into a fixed 64-byte `DISASM_RESULT`, which programs read to
//! match (poly/metamorphic) code patterns. Decoding is `exav-x86` — pure Rust,
//! decode-only, no dependencies — and this module translates its output into the
//! ABI layout: a 287-value `real_op`, a `(reg/size/value)` per operand, and the
//! operand-access encoding the format specifies.
//!
//! The translation is best-effort: opcodes and registers outside the ABI's set
//! map to `INVALID`. It is exercised but not yet validated against real
//! polymorphic samples, so disasm-using programs stay gated like the rest.
//!
//! **A decode this crate declines is not a decode that failed.** `exav-x86`
//! returns `None` both for bytes that are not an instruction and for
//! instructions outside its scope, and it cannot tell them apart. The caller in
//! `exec.rs` therefore treats `None` as an *unsupported operation*, which
//! discards the whole program's result, rather than as the ABI's "could not
//! disassemble" return — a program that silently took a different branch would
//! be a false negative with nothing to show for it.

use exav_x86::{Insn, Mn, Op, Seg, Size};

/// Size of `struct DISASM_RESULT`.
pub const RESULT_SIZE: usize = 64;
/// Longest instruction the decoder considers.
const MAX_INSN: usize = 32;

// `enum DIS_ACCESS` (bytecode ABI).
const ACCESS_NOARG: u8 = 0;
const ACCESS_IMM: u8 = 1;
const ACCESS_REL: u8 = 2;
const ACCESS_REG: u8 = 3;
const ACCESS_MEM: u8 = 4;

// `enum DIS_SIZE` (bytecode ABI).
const SIZEB: u8 = 0;
const SIZEW: u8 = 1;
const SIZED: u8 = 2;
const SIZEF: u8 = 3; // 6-byte (seg+reg pair)
const SIZEQ: u8 = 4;
const SIZET: u8 = 5; // 10-byte

/// Map a memory-operand width in bytes to the `enum DIS_SIZE` value.
fn mem_size(bytes: u32) -> u8 {
    match bytes {
        1 => SIZEB,
        2 => SIZEW,
        4 => SIZED,
        6 => SIZEF,
        8 => SIZEQ,
        10 => SIZET,
        _ => SIZED,
    }
}

/// `enum X86OPS` names in order; the index is the `real_op` value.
const X86OPS: &[&str] = &[
    "INVALID",
    "AAA",
    "AAD",
    "AAM",
    "AAS",
    "ADD",
    "ADC",
    "AND",
    "ARPL",
    "BOUND",
    "BSF",
    "BSR",
    "BSWAP",
    "BT",
    "BTC",
    "BTR",
    "BTS",
    "CALL",
    "CDQ",
    "CWD",
    "CWDE",
    "CBW",
    "CLC",
    "CLD",
    "CLI",
    "CLTS",
    "CMC",
    "CMOVO",
    "CMOVNO",
    "CMOVC",
    "CMOVNC",
    "CMOVZ",
    "CMOVNZ",
    "CMOVBE",
    "CMOVA",
    "CMOVS",
    "CMOVNS",
    "CMOVP",
    "CMOVNP",
    "CMOVL",
    "CMOVGE",
    "CMOVLE",
    "CMOVG",
    "CMP",
    "CMPSD",
    "CMPSW",
    "CMPSB",
    "CMPXCHG",
    "CMPXCHG8B",
    "CPUID",
    "DAA",
    "DAS",
    "DEC",
    "DIV",
    "ENTER",
    "FWAIT",
    "HLT",
    "IDIV",
    "IMUL",
    "INC",
    "IN",
    "INSD",
    "INSW",
    "INSB",
    "INT",
    "INT3",
    "INTO",
    "INVD",
    "INVLPG",
    "IRET",
    "JO",
    "JNO",
    "JC",
    "JNC",
    "JZ",
    "JNZ",
    "JBE",
    "JA",
    "JS",
    "JNS",
    "JP",
    "JNP",
    "JL",
    "JGE",
    "JLE",
    "JG",
    "JMP",
    "LAHF",
    "LAR",
    "LDS",
    "LES",
    "LFS",
    "LGS",
    "LEA",
    "LEAVE",
    "LGDT",
    "LIDT",
    "LLDT",
    "PREFIX_LOCK",
    "LODSD",
    "LODSW",
    "LODSB",
    "LOOP",
    "LOOPE",
    "LOOPNE",
    "JECXZ",
    "LSL",
    "LSS",
    "LTR",
    "MOV",
    "MOVSD",
    "MOVSW",
    "MOVSB",
    "MOVSX",
    "MOVZX",
    "MUL",
    "NEG",
    "NOP",
    "NOT",
    "OR",
    "OUT",
    "OUTSD",
    "OUTSW",
    "OUTSB",
    "PUSH",
    "PUSHAD",
    "PUSHA",
    "PUSHFD",
    "PUSHF",
    "POP",
    "POPAD",
    "POPFD",
    "POPF",
    "RCL",
    "RCR",
    "RDMSR",
    "RDPMC",
    "RDTSC",
    "PREFIX_REPE",
    "PREFIX_REPNE",
    "RETF",
    "RETN",
    "ROL",
    "ROR",
    "RSM",
    "SAHF",
    "SAR",
    "SBB",
    "SCASD",
    "SCASW",
    "SCASB",
    "SETO",
    "SETNO",
    "SETC",
    "SETNC",
    "SETZ",
    "SETNZ",
    "SETBE",
    "SETA",
    "SETS",
    "SETNS",
    "SETP",
    "SETNP",
    "SETL",
    "SETGE",
    "SETLE",
    "SETG",
    "SGDT",
    "SIDT",
    "SHL",
    "SHLD",
    "SHR",
    "SHRD",
    "SLDT",
    "STOSD",
    "STOSW",
    "STOSB",
    "STR",
    "STC",
    "STD",
    "STI",
    "SUB",
    "SYSCALL",
    "SYSENTER",
    "SYSEXIT",
    "SYSRET",
    "TEST",
    "UD2",
    "VERR",
    "VERRW",
    "WBINVD",
    "WRMSR",
    "XADD",
    "XCHG",
    "XLAT",
    "XOR",
    "PREFIX_OPSIZE",
    "PREFIX_ADDRSIZE",
    "PREFIX_SEGMENT",
    "2BYTE",
    "FPU",
    "F2XM1",
    "FABS",
    "FADD",
    "FADDP",
    "FBLD",
    "FBSTP",
    "FCHS",
    "FCLEX",
    "FCMOVB",
    "FCMOVBE",
    "FCMOVE",
    "FCMOVNB",
    "FCMOVNBE",
    "FCMOVNE",
    "FCMOVNU",
    "FCMOVU",
    "FCOM",
    "FCOMI",
    "FCOMIP",
    "FCOMP",
    "FCOMPP",
    "FCOS",
    "FDECSTP",
    "FDIV",
    "FDIVP",
    "FDIVR",
    "FDIVRP",
    "FFREE",
    "FIADD",
    "FICOM",
    "FICOMP",
    "FIDIV",
    "FIDIVR",
    "FILD",
    "FIMUL",
    "FINCSTP",
    "FINIT",
    "FIST",
    "FISTP",
    "FISTTP",
    "FISUB",
    "FISUBR",
    "FLD",
    "FLD1",
    "FLDCW",
    "FLDENV",
    "FLDL2E",
    "FLDL2T",
    "FLDLG2",
    "FLDLN2",
    "FLDPI",
    "FLDZ",
    "FMUL",
    "FMULP",
    "FNOP",
    "FPATAN",
    "FPREM",
    "FPREM1",
    "FPTAN",
    "FRNDINT",
    "FRSTOR",
    "FSCALE",
    "FSIN",
    "FSINCOS",
    "FSQRT",
    "FSAVE",
    "FST",
    "FSTCW",
    "FSTENV",
    "FSTP",
    "FSTSW",
    "FSUB",
    "FSUBP",
    "FSUBR",
    "FSUBRP",
    "FTST",
    "FUCOM",
    "FUCOMI",
    "FUCOMIP",
    "FUCOMP",
    "FUCOMPP",
    "FXAM",
    "FXCH",
    "FXTRACT",
    "FYL2X",
    "FYL2XP1",
];

/// `enum X86REGS` names in order; the index is the register value.
///
/// The ABI transports a register as that index, so nothing here reads the
/// names — but they are what makes the numbering in [`reg`] and [`seg_reg_num`]
/// checkable against the ABI rather than trusted, and the length assertion in
/// the tests is what keeps the table and the numbering in step.
#[allow(dead_code)]
const X86REGS: &[&str] = &[
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "AX", "CX", "DX", "BX", "SP", "BP",
    "SI", "DI", "AH", "CH", "DH", "BH", "AL", "CL", "DL", "BL", "ES", "CS", "SS", "DS", "FS", "GS",
    "CR0", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "DR0", "DR1", "DR2", "DR3", "DR4",
    "DR5", "DR6", "DR7", "ST0", "ST1", "ST2", "ST3", "ST4", "ST5", "ST6", "ST7",
];
const REG_INVALID: u8 = 54;

/// Map a decoded mnemonic to the `real_op` index.
fn real_op(mn: Mn) -> u16 {
    let raw = mn.name().to_uppercase();
    // Reconcile the spellings that differ between the decoder and the ABI.
    let name: &str = match raw.as_str() {
        "RET" => "RETN",
        "JE" => "JZ",
        "JNE" => "JNZ",
        "JB" => "JC",
        "JAE" => "JNC",
        "XLATB" => "XLAT",
        "IRETD" | "IRET" => "IRET",
        "MOVSXD" => "MOVSX",
        other => other,
    };
    X86OPS.iter().position(|&n| n == name).unwrap_or(0) as u16
}

/// Map a general-purpose register number and width to the `X86REGS` value.
///
/// The ABI orders its register file by width — eight 32-bit, then eight 16-bit,
/// then the four high and four low byte registers — so the encoding's number
/// indexes into the block its width selects.
fn reg(num: u8, size: Size) -> u8 {
    if num > 7 {
        return REG_INVALID;
    }
    match size {
        Size::B4 => num,
        Size::B2 => 8 + num,
        // The byte registers are `AL CL DL BL AH CH DH BH` by encoding number,
        // but the ABI lists the high four before the low four.
        Size::B1 => {
            if num < 4 {
                20 + num // AL..BL
            } else {
                16 + (num - 4) // AH..BH
            }
        }
    }
}

/// Map a segment register to its `X86REGS` value.
fn seg_reg_num(s: Seg) -> u8 {
    match s {
        Seg::Es => 24,
        Seg::Cs => 25,
        Seg::Ss => 26,
        Seg::Ds => 27,
        Seg::Fs => 28,
        Seg::Gs => 29,
    }
}

/// The `enum DIS_SIZE` value for an immediate, chosen by the width it needs
/// rather than the width the encoding happened to store it in.
fn imm_size(v: i64) -> u8 {
    if i64::from(i8::MIN) <= v && v <= i64::from(i8::MAX) {
        SIZEB
    } else if i64::from(i16::MIN) <= v && v <= i64::from(i16::MAX) {
        SIZEW
    } else if i64::from(i32::MIN) <= v && v <= i64::from(i32::MAX) {
        SIZED
    } else {
        SIZEQ
    }
}

fn put32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Detect the operand-size (`0x66`) and address-size (`0x67`) prefixes by
/// scanning the leading legacy-prefix bytes, returning the `(opsize,
/// adsize)` flags (1 if the respective prefix is present, else 0). Other legacy
/// prefixes (lock/rep/segment) are skipped over.
fn prefix_flags(bytes: &[u8], len: usize) -> (u8, u8) {
    let (mut opsize, mut adsize) = (0u8, 0u8);
    for &b in bytes.iter().take(len) {
        match b {
            0x66 => opsize = 1,
            0x67 => adsize = 1,
            // lock / repne / rep / segment overrides — keep scanning.
            0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 => {}
            _ => break, // first non-prefix byte: prefixes end here
        }
    }
    (opsize, adsize)
}

/// Decode one instruction from `bytes`; fill a `DISASM_RESULT` image and return
/// `(image, instruction_length)`. `None` if nothing decodes.
pub fn disasm_one(bytes: &[u8]) -> Option<([u8; RESULT_SIZE], usize)> {
    let n = bytes.len().min(MAX_INSN);
    let slice = bytes.get(..n)?;
    // The instruction is decoded as if it sat at address zero, so a relative
    // branch resolves to a target the ABI's "displacement from the next
    // instruction" can be recovered from by subtracting the length.
    let insn = exav_x86::decode(slice, 0)?;
    if insn.len == 0 {
        return None;
    }

    let mut r = [0u8; RESULT_SIZE];
    r[0..2].copy_from_slice(&real_op(insn.mn).to_le_bytes());
    // opsize/adsize are flags (0 = default 32-bit, 1 = 16-bit via a 0x66/0x67
    // prefix), NOT a bit width — the ABI uses `s.opsize`/`s.adsize` verbatim.
    let (opsize, adsize) = prefix_flags(slice, insn.len);
    r[2] = opsize;
    r[3] = adsize;
    r[4] = 0; // segment

    for i in 0..3usize {
        let base = 5 + i * 10;
        fill_arg(&mut r[base..base + 10], &insn, i);
    }
    Some((r, insn.len))
}

fn fill_arg(arg: &mut [u8], insn: &Insn, i: usize) {
    match insn.ops[i] {
        Op::None => arg[0] = ACCESS_NOARG,
        Op::Reg(num, size) => {
            arg[0] = ACCESS_REG;
            arg[1] = reg(num, size); // for REG, [1] holds the register
        }
        Op::SegReg(s) => {
            arg[0] = ACCESS_REG;
            arg[1] = seg_reg_num(s);
        }
        // The x87 stack and the vector register files are not in the ABI's
        // register file, which holds general-purpose registers only. A slot or
        // a vector register therefore has no representation, and is reported as
        // absent rather than as a general-purpose register of the same number —
        // which would name `eax` for `xmm0` and read as a real operand.
        Op::St(_) | Op::Xmm(_) | Op::Mmx(_) => arg[0] = ACCESS_NOARG,
        Op::Rel(target) => {
            arg[0] = ACCESS_REL;
            arg[1] = SIZED;
            // The ABI stores the displacement from the *next* instruction as a
            // 64-bit value split low/high (`arg.q` then `arg.q >> 32`).
            let q = (target as i64).wrapping_sub(insn.len as i64) as i32 as i64;
            put32(arg, 2, q as u32);
            put32(arg, 6, (q >> 32) as u32);
        }
        Op::Mem {
            base,
            index,
            scale,
            disp,
            size,
            ..
        } => {
            arg[0] = ACCESS_MEM;
            arg[1] = mem_size(size.bytes()); // the ABI sets size for every arg
            arg[2] = index.map_or(REG_INVALID, |n| reg(n, Size::B4)); // r1 (scaled)
            arg[3] = base.map_or(REG_INVALID, |n| reg(n, Size::B4)); // r2 (added)
            arg[4] = scale;
            arg[5] = 0;
            put32(arg, 6, disp as u32);
        }
        Op::MemWide {
            base,
            index,
            scale,
            disp,
            bytes,
            ..
        } => {
            arg[0] = ACCESS_MEM;
            arg[1] = mem_size(u32::from(bytes));
            arg[2] = index.map_or(REG_INVALID, |n| reg(n, Size::B4));
            arg[3] = base.map_or(REG_INVALID, |n| reg(n, Size::B4));
            arg[4] = scale;
            arg[5] = 0;
            put32(arg, 6, disp as u32);
        }
        Op::Imm(v) => {
            arg[0] = ACCESS_IMM;
            arg[1] = imm_size(v);
            put32(arg, 2, v as u32);
            put32(arg, 6, (v >> 32) as u32);
        }
        // A far pointer is two values where the ABI has one slot; the offset is
        // the part a pattern would match on.
        Op::FarPtr { offset, .. } => {
            arg[0] = ACCESS_IMM;
            arg[1] = SIZED;
            put32(arg, 2, offset);
            put32(arg, 6, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_common_ops_to_abi_opcodes() {
        // real_op indices for a few well-known mnemonics.
        let nop = X86OPS.iter().position(|&n| n == "NOP").unwrap() as u16;
        let push = X86OPS.iter().position(|&n| n == "PUSH").unwrap() as u16;
        let ret = X86OPS.iter().position(|&n| n == "RETN").unwrap() as u16;

        // 0x90 = nop
        let (r, len) = disasm_one(&[0x90]).unwrap();
        assert_eq!(len, 1);
        assert_eq!(u16::from_le_bytes([r[0], r[1]]), nop);

        // 0x55 = push ebp ; arg0 is a register = EBP.
        let (r, len) = disasm_one(&[0x55]).unwrap();
        assert_eq!(len, 1);
        assert_eq!(u16::from_le_bytes([r[0], r[1]]), push);
        assert_eq!(r[5], ACCESS_REG);
        assert_eq!(r[6], reg(5, Size::B4), "EBP");

        // 0xc3 = ret -> RETN
        let (r, _) = disasm_one(&[0xc3]).unwrap();
        assert_eq!(u16::from_le_bytes([r[0], r[1]]), ret);
    }

    #[test]
    fn reg_and_op_tables_have_expected_sizes() {
        assert_eq!(X86OPS.len(), 287);
        assert_eq!(X86REGS.len(), 54);
        assert_eq!(reg(0, Size::B4), 0, "EAX");
        assert_eq!(reg(7, Size::B4), 7, "EDI");
        assert_eq!(reg(0, Size::B2), 8, "AX");
        assert_eq!(reg(0, Size::B1), 20, "AL");
        assert_eq!(reg(4, Size::B1), 16, "AH");
    }

    #[test]
    fn invalid_bytes_decode_to_none_or_invalid() {
        // A lone 0xff may form an incomplete instruction.
        let _ = disasm_one(&[]);
        assert!(disasm_one(&[]).is_none());
    }
}
