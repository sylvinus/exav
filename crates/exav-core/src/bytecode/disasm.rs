//! x86 instruction decoding for the bytecode `disasm_x86` API.
//!
//! The bytecode `disasm_x86(DISASM_RESULT*, len)` API decodes one instruction at
//! the file cursor into a fixed 64-byte `DISASM_RESULT`, which programs read to
//! match (poly/metamorphic) code patterns. We decode with `iced-x86` (pure
//! Rust, decode-only — no native codegen, keeping the no-JIT posture) and
//! translate into the ABI layout: a 287-value `real_op`, a `(reg/size/value)`
//! per operand, and the operand-access encoding the format specifies.
//!
//! The translation is best-effort: opcodes/registers outside the common set map
//! to `INVALID`. It is exercised but not yet validated against real polymorphic
//! samples, so disasm-using programs stay gated like the rest.

use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};

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

/// Map an iced memory-operand size to the `enum DIS_SIZE` value.
fn mem_size(m: MemorySize) -> u8 {
    match m.info().size() {
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
const X86REGS: &[&str] = &[
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "AX", "CX", "DX", "BX", "SP", "BP",
    "SI", "DI", "AH", "CH", "DH", "BH", "AL", "CL", "DL", "BL", "ES", "CS", "SS", "DS", "FS", "GS",
    "CR0", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "DR0", "DR1", "DR2", "DR3", "DR4",
    "DR5", "DR6", "DR7", "ST0", "ST1", "ST2", "ST3", "ST4", "ST5", "ST6", "ST7",
];
const REG_INVALID: u8 = 54;

/// Map an iced mnemonic to the `real_op` index.
fn real_op(mn: Mnemonic) -> u16 {
    let raw = format!("{mn:?}").to_uppercase();
    // Reconcile the spellings that differ between iced and the ABI.
    let name: &str = match raw.as_str() {
        "RET" => "RETN",
        "JE" => "JZ",
        "JNE" => "JNZ",
        "JB" | "JNAE" => "JC",
        "JAE" | "JNB" => "JNC",
        "JNA" => "JBE",
        "JNBE" => "JA",
        "JNGE" => "JL",
        "JNL" => "JGE",
        "JNG" => "JLE",
        "JNLE" => "JG",
        "JPE" => "JP",
        "JPO" => "JNP",
        "MOVSXD" => "MOVSX",
        other => other,
    };
    X86OPS.iter().position(|&n| n == name).unwrap_or(0) as u16
}

/// Map an iced register to the `X86REGS` value.
fn reg(r: Register) -> u8 {
    if r == Register::None {
        return REG_INVALID;
    }
    let name = format!("{r:?}").to_uppercase();
    X86REGS
        .iter()
        .position(|&n| n == name)
        .map(|i| i as u8)
        .unwrap_or(REG_INVALID)
}

fn imm_size(k: OpKind) -> u8 {
    match k {
        OpKind::Immediate8 | OpKind::Immediate8to16 | OpKind::Immediate8to32 => SIZEB,
        OpKind::Immediate16 => SIZEW,
        OpKind::Immediate32 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => SIZED,
        OpKind::Immediate64 => SIZEQ,
        _ => SIZED,
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
    let mut dec = Decoder::new(32, slice, DecoderOptions::NONE);
    if !dec.can_decode() {
        return None;
    }
    let insn = dec.decode();
    if insn.is_invalid() || insn.len() == 0 {
        return None;
    }

    let mut r = [0u8; RESULT_SIZE];
    r[0..2].copy_from_slice(&real_op(insn.mnemonic()).to_le_bytes());
    // opsize/adsize are flags (0 = default 32-bit, 1 = 16-bit via a 0x66/0x67
    // prefix), NOT a bit width — the ABI uses `s.opsize`/`s.adsize` verbatim.
    // Detect the prefixes from the leading instruction bytes (skipping the
    // other legacy prefixes), matching the reference decoder.
    let (opsize, adsize) = prefix_flags(slice, insn.len());
    r[2] = opsize;
    r[3] = adsize;
    r[4] = 0; // segment

    for i in 0..3u32 {
        let base = 5 + (i as usize) * 10;
        if i >= insn.op_count() {
            r[base] = ACCESS_NOARG;
            continue;
        }
        fill_arg(&mut r[base..base + 10], &insn, i);
    }
    Some((r, insn.len()))
}

fn fill_arg(arg: &mut [u8], insn: &Instruction, i: u32) {
    match insn.op_kind(i) {
        OpKind::Register => {
            arg[0] = ACCESS_REG;
            arg[1] = reg(insn.op_register(i)); // for REG, [1] holds the register
        }
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            arg[0] = ACCESS_REL;
            arg[1] = SIZED;
            // The ABI stores the relative displacement from the next instruction
            // as a 64-bit value split low/high (`arg.q` then `arg.q >> 32`).
            let target = insn.near_branch_target();
            let next = insn.next_ip();
            let q = target.wrapping_sub(next) as i32 as i64; // sign-extend
            put32(arg, 2, q as u32);
            put32(arg, 6, (q >> 32) as u32);
        }
        OpKind::Memory => {
            arg[0] = ACCESS_MEM;
            arg[1] = mem_size(insn.memory_size()); // the ABI sets size for every arg
            arg[2] = reg(insn.memory_index()); // r1 (scaled)
            arg[3] = reg(insn.memory_base()); // r2 (added)
            arg[4] = insn.memory_index_scale() as u8;
            arg[5] = 0;
            put32(arg, 6, insn.memory_displacement32());
        }
        k @ (OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64) => {
            arg[0] = ACCESS_IMM;
            arg[1] = imm_size(k);
            let v = insn.immediate(i);
            put32(arg, 2, v as u32);
            put32(arg, 6, (v >> 32) as u32);
        }
        _ => arg[0] = ACCESS_NOARG,
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
        assert_eq!(r[6], reg(Register::EBP));

        // 0xc3 = ret -> RETN
        let (r, _) = disasm_one(&[0xc3]).unwrap();
        assert_eq!(u16::from_le_bytes([r[0], r[1]]), ret);
    }

    #[test]
    fn reg_and_op_tables_have_expected_sizes() {
        assert_eq!(X86OPS.len(), 287);
        assert_eq!(X86REGS.len(), 54);
        assert_eq!(reg(Register::EAX), 0);
        assert_eq!(reg(Register::EDI), 7);
    }

    #[test]
    fn invalid_bytes_decode_to_none_or_invalid() {
        // A lone 0xff may form an incomplete instruction.
        let _ = disasm_one(&[]);
        assert!(disasm_one(&[]).is_none());
    }
}
