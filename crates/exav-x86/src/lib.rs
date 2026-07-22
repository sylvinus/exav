//! A decode-only x86-32 instruction decoder, with no dependencies.
//!
//! # What it claims, and what it refuses
//!
//! [`decode`] returns `None` for two different situations that a caller **must
//! not** try to tell apart:
//!
//! * the bytes are not a valid instruction, and
//! * the bytes are a valid instruction this decoder does not implement.
//!
//! Nothing here can distinguish them, so a caller that treats `None` as
//! "illegal instruction" would fabricate a CPU fault for code a real processor
//! runs. The emulator's rule is the safe one: `None` is *unsupported*, reported
//! and never delivered to the program being emulated as an exception.
//!
//! # Scope
//!
//! 32-bit protected mode: no REX, no RIP-relative addressing, no 64-bit forms.
//! Everything else — the integer and control-flow instruction set, port I/O,
//! far transfers and segment-register loads, both address sizes, the whole x87
//! escape map, the system-instruction space, SSE/MMX with the `0F 38` and
//! `0F 3A` escapes, 3DNow!, VEX, EVEX and AMD's XOP.
//!
//! Operands are modelled for the general-purpose and x87 encodings. For the
//! SIMD maps the register *file* an operand names — MMX, XMM/YMM, mask — is
//! not: a register number is reported as the encoding's own, and a vector index
//! register is not reported at all. Nothing in exav interprets those operands,
//! and reporting one as a general-purpose register would be a plausible-looking
//! lie. What those encodings are asked for is their identity and their length.
//!
//! The scope was measured, not guessed: instrumenting the emulator across the
//! packed-sample corpus records which encodings real stubs actually execute,
//! and this decoder covers all of them. The set is far smaller than the ISA —
//! a packer's stub is a decompressor, not a compiler's output.
//!
//! # Verification
//!
//! Correctness here means agreeing with a decoder that has seen far more code
//! than this one, so the tests are differential: `tests/differential.rs` decodes
//! the same bytes with `iced-x86` and compares length and mnemonic — over
//! exhaustive opcode sweeps under every prefix combination, pseudo-random bytes,
//! and (behind `--ignored`) every byte offset of the sample corpus. It agrees
//! at every corpus decode site, with no disagreements and no declines — which
//! the sweep asserts rather than merely reports, and prints the counts for.
//!
//! Corpus agreement is agreement on bytes that OCCUR, which is narrower than it
//! sounds: the fuzz target reaches encodings no real stub contains, and has
//! found genuine defects there. Both checks are needed.
//!
//! Length is the property to watch: an instruction decoded one byte short or
//! long desynchronises every instruction after it, so a length error is not a
//! local mistake but a cascading one.
//!
//! # Tables
//!
//! The SIMD and system regions come from `generated.rs`, which is checked in
//! and produced by `scripts/gen-x86-tables.sh` from `iced-x86` (MIT; attributed
//! in `NOTICE`). It records only what a decoder cannot infer from the bytes —
//! which instruction an encoding names, and how many immediate bytes follow —
//! and never a displacement, so a change to the addressing rules cannot be
//! contradicted by a stale table.

#![forbid(unsafe_code)]

mod generated;

// ---------------------------------------------------------------------------
// Mnemonics
// ---------------------------------------------------------------------------

/// A mnemonic, identified by its name.
///
/// A name rather than a discriminant because the `0F` map is generated: every
/// mnemonic in it would otherwise have to be mirrored into an enum and kept in
/// step with the table by hand, which is exactly the transcription step this
/// crate avoids. Names match the spelling used by common x86 tooling, so a decode can
/// be compared against another decoder's output directly.
///
/// The name is INTERNED — the value held is an index into the two name tables,
/// so `mn == Mn::Lea` is an integer comparison. Holding the `&'static str`
/// itself would make every such test a string comparison, and a decoder tests
/// its mnemonic several times per instruction while an emulator runs millions
/// of them.
///
/// The named constants below are usable in patterns, so
/// `matches!(insn.mn, Mn::Lea | Mn::Bound)` works as it would for an enum.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Mn(u16);

impl Mn {
    /// The mnemonic's name, e.g. `Mn::Mov.name() == "Mov"`.
    pub fn name(self) -> &'static str {
        let i = self.0 as usize;
        match generated::OF_NAMES.get(i) {
            Some(n) => n,
            None => HAND_NAMES[i - generated::OF_NAMES.len()],
        }
    }

    /// The mnemonic a generated map's name index names.
    fn from_generated(i: usize) -> Mn {
        debug_assert!(i < generated::OF_NAMES.len(), "name index {i} out of range");
        Mn(i as u16)
    }

    /// The index for a name, resolved at compile time.
    ///
    /// [`generated::OF_NAMES`] is searched first, so a name in both tables gets
    /// the generated maps' index and the constant below compares equal to what
    /// a decode of those maps produces. `OF_NAMES` holds no duplicates —
    /// `name_indices_are_unique` is what keeps that true.
    const fn intern(name: &'static str) -> Mn {
        let mut i = 0;
        while i < generated::OF_NAMES.len() {
            if str_eq(generated::OF_NAMES[i], name) {
                return Mn(i as u16);
            }
            i += 1;
        }
        let mut i = 0;
        while i < HAND_NAMES.len() {
            if str_eq(HAND_NAMES[i], name) {
                return Mn((generated::OF_NAMES.len() + i) as u16);
            }
            i += 1;
        }
        panic!("mnemonic is in neither name table")
    }
}

/// `str`'s own `==` is not callable in a `const fn`.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

impl core::fmt::Debug for Mn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

macro_rules! mnemonics {
    ($($v:ident),* $(,)?) => {
        /// The mnemonics the hand-written maps name directly. Those the
        /// generated maps also reach resolve to the generated index; the rest —
        /// the one-byte map's own, the x87 stack — are indexed from here.
        const HAND_NAMES: &[&str] = &[$(stringify!($v)),*];

        #[allow(non_upper_case_globals)]
        impl Mn {
            $(pub const $v: Mn = Mn::intern(stringify!($v));)*
        }
    };
}

mnemonics![
    // Arithmetic and logic.
    Add,
    Or,
    Adc,
    Sbb,
    And,
    Sub,
    Xor,
    Cmp,
    Inc,
    Dec,
    Neg,
    Not,
    Mul,
    Imul,
    Div,
    Idiv,
    Test,
    // Shifts and rotates. `Sal` is the undocumented `/6` alias of `Shl`.
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shl,
    Shr,
    Sal,
    Sar,
    Shld,
    Shrd,
    // Bit operations.
    Bt,
    Bts,
    Btr,
    Btc,
    Bsf,
    Bsr,
    Bswap,
    Tzcnt,
    Lzcnt,
    // Moves.
    Mov,
    Movzx,
    Movsx,
    Lea,
    Xchg,
    Xadd,
    Cmpxchg,
    Cmpxchg8b,
    Montmul,
    Push,
    Pop,
    Pushad,
    Popad,
    Pusha,
    Popa,
    // Control flow.
    Call,
    Jmp,
    Ret,
    Enter,
    Leave,
    Loop,
    Loope,
    Loopne,
    Jecxz,
    Jcxz,
    Jo,
    Jno,
    Jb,
    Jae,
    Je,
    Jne,
    Jbe,
    Ja,
    Js,
    Jns,
    Jp,
    Jnp,
    Jl,
    Jge,
    Jle,
    Jg,
    // Conditional set and move.
    Seto,
    Setno,
    Setb,
    Setae,
    Sete,
    Setne,
    Setbe,
    Seta,
    Sets,
    Setns,
    Setp,
    Setnp,
    Setl,
    Setge,
    Setle,
    Setg,
    Cmovo,
    Cmovno,
    Cmovb,
    Cmovae,
    Cmove,
    Cmovne,
    Cmovbe,
    Cmova,
    Cmovs,
    Cmovns,
    Cmovp,
    Cmovnp,
    Cmovl,
    Cmovge,
    Cmovle,
    Cmovg,
    // String operations.
    Movsb,
    Movsw,
    Movsd,
    Cmpsb,
    Cmpsw,
    Cmpsd,
    Stosb,
    Stosw,
    Stosd,
    Lodsb,
    Lodsw,
    Lodsd,
    Scasb,
    Scasw,
    Scasd,
    // Flags, conversions and the rest.
    Clc,
    Stc,
    Cmc,
    Cld,
    Std,
    Cli,
    Sti,
    Sahf,
    Lahf,
    Pushfd,
    Popfd,
    Pushf,
    Popf,
    Cwde,
    Cdq,
    Cbw,
    Cwd,
    Nop,
    Pause,
    Wait,
    Hlt,
    Int,
    Int1,
    Int3,
    Into,
    Aam,
    Aad,
    Cpuid,
    Rdtsc,
    // Packed BCD adjustments, and the two undocumented-but-real one-byte ops.
    Daa,
    Das,
    Aaa,
    Aas,
    Salc,
    Xlatb,
    // Segmented memory: far transfers, segment-register moves, far pointer loads.
    Retf,
    Iretd,
    Iret,
    Bound,
    Arpl,
    Lds,
    Les,
    Lfs,
    Lgs,
    Lss,
    // Port I/O. The emulator does not execute these, but a decoder that cannot
    // name them cannot give their length either.
    In,
    Out,
    Insb,
    Insw,
    Insd,
    Outsb,
    Outsw,
    Outsd,
    // x87. `Fnstenv`/`Fnstcw` are the GetPC-trick companions: a stub reads its
    // own address back out of the saved FPU environment.
    Fadd,
    Faddp,
    Fiadd,
    Fmul,
    Fmulp,
    Fimul,
    Fcom,
    Fcomp,
    Fcompp,
    Ficom,
    Ficomp,
    Fsub,
    Fsubp,
    Fsubr,
    Fsubrp,
    Fisub,
    Fisubr,
    Fdiv,
    Fdivp,
    Fdivr,
    Fdivrp,
    Fidiv,
    Fidivr,
    Fld,
    Fst,
    Fstp,
    Fild,
    Fist,
    Fistp,
    Fisttp,
    Fbld,
    Fbstp,
    Fxch,
    Ffree,
    Ffreep,
    Fldenv,
    Fldcw,
    Fnstenv,
    Fnstcw,
    Fnsave,
    Frstor,
    Fnstsw,
    Fnclex,
    Fninit,
    Fchs,
    Fabs,
    Ftst,
    Fxam,
    Fld1,
    Fldl2t,
    Fldl2e,
    Fldpi,
    Fldlg2,
    Fldln2,
    Fldz,
    F2xm1,
    Fyl2x,
    Fptan,
    Fpatan,
    Fxtract,
    Fprem,
    Fprem1,
    Fdecstp,
    Fincstp,
    Fyl2xp1,
    Fsqrt,
    Fsincos,
    Frndint,
    Fscale,
    Fsin,
    Fcos,
    Fnop,
    Fucom,
    Fucomp,
    Fucompp,
    Fucomi,
    Fucomip,
    Fcomi,
    Fcomip,
    Fcmovb,
    Fcmove,
    Fcmovbe,
    Fcmovu,
    Fcmovnb,
    Fcmovne,
    Fcmovnbe,
    Fcmovnu,
    // `Fstpnce` is the undocumented `fstp` that skips the stack-fault check.
    // `Reservednop` covers `0F 0D` and `0F 18`–`0F 1F`: encodings that do
    // nothing but still have a length.
    Fstpnce,
    Reservednop,
    Xabort,
    Xbegin,
    // Cache hints: no architectural effect, but real encodings with a length.
    Prefetch,
    Prefetchnta,
    Prefetcht0,
    Prefetcht1,
    Prefetcht2,
    Prefetchit0,
    Prefetchit1,
    Prefetchw,
    Prefetchwt1,
    Cldemote,
    // Control-flow-enforcement encodings that live inside the `0F 1E` no-op
    // space behind an `F3`, so a decoder that treats the space as uniform gets
    // both their name and their operand wrong.
    Endbr32,
    Endbr64,
    Rdsspd,
    // Privileged and system instructions. None of them run under emulation, but
    // each is an encoding, and an encoding without a length stalls a decode.
    Sldt,
    Str,
    Lldt,
    Ltr,
    Verr,
    Verw,
    Sgdt,
    Sidt,
    Lgdt,
    Lidt,
    Smsw,
    Lmsw,
    Invlpg,
    Lar,
    Lsl,
    Clts,
    Invd,
    Wbinvd,
    Wbnoinvd,
    Rsm,
    Ud0,
    Ud1,
    Ud2,
    Getsec,
    Syscall,
    Sysret,
    Sysenter,
    Sysexit,
    Wrmsr,
    Rdmsr,
    Rdpmc,
    // The x87 encodings that were reserved when the 387 absorbed the 287's
    // coprocessor-control instructions.
    Fneni,
    Fndisi,
    Fnsetpm,
    // SSE and MMX. Every mnemonic the generated map can produce is already a
    // valid `Mn` — one is built from a name — but only the ones listed here
    // have a constant a caller can write in a `match` pattern. These are the
    // ones a packer stub uses: vector moves as a wide `memcpy`, the lane
    // shuffles and whole-register shifts that move the bytes around
    // afterwards, and the bitwise and add/subtract lanes a decryptor uses.
    Movd,
    Movq,
    Movaps,
    Movups,
    Movapd,
    Movupd,
    Movdqa,
    Movdqu,
    Movss,
    Movntdq,
    Movntq,
    Movntps,
    Lddqu,
    Pshufd,
    Pshufw,
    Pshuflw,
    Pshufhw,
    Pslldq,
    Psrldq,
    Punpcklbw,
    Punpcklwd,
    Punpckldq,
    Punpcklqdq,
    Pand,
    Pandn,
    Por,
    Pxor,
    Paddb,
    Paddw,
    Paddd,
    Paddq,
    Psubb,
    Psubw,
    Psubd,
    Psubq,
    Pcmpeqb,
    Pcmpeqw,
    Pcmpeqd,
    // Fences and the MMX state clear: no data movement, but a stub that uses
    // them expects a no-op rather than a stop.
    Emms,
    Femms,
    Sfence,
    Lfence,
    Mfence,
    // The CRC-32C accumulator, which packers use as a cheap integrity check
    // over what they have just unpacked.
    Crc32,
    // The FP16 complex-multiply family. Named here only because it carries a
    // restriction the opcode tables cannot express: see `overlaps_a_source`.
    Vfmulcph,
    Vfmulcsh,
    Vfcmulcph,
    Vfcmulcsh,
    Vfmaddcph,
    Vfmaddcsh,
    Vfcmaddcph,
    Vfcmaddcsh,
];

// ---------------------------------------------------------------------------
// Output model
// ---------------------------------------------------------------------------

/// Operand width in bytes, after any `66` prefix has been applied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Size {
    B1 = 1,
    B2 = 2,
    B4 = 4,
}

impl Size {
    pub fn bytes(self) -> u32 {
        self as u32
    }
}

/// A segment register, when an override prefix names one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Seg {
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
}

/// One decoded operand.
///
/// Register numbers are the encoding's own: `0`–`7` meaning
/// `(e)ax, (e)cx, (e)dx, (e)bx, (e)sp, (e)bp, (e)si, (e)di`, or
/// `al, cl, dl, bl, ah, ch, dh, bh` at [`Size::B1`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    None,
    Reg(u8, Size),
    Mem {
        base: Option<u8>,
        index: Option<u8>,
        scale: u8,
        disp: i64,
        seg: Option<Seg>,
        size: Size,
        /// True when the address is computed 16-bit (a `67` prefix), which
        /// truncates the effective address rather than widening it.
        addr16: bool,
    },
    Imm(i64),
    /// A branch target, already resolved against the instruction's end address.
    Rel(u64),
    /// A segment register, named directly by the encoding.
    SegReg(Seg),
    /// An x87 stack slot, `ST(0)`–`ST(7)`.
    St(u8),
    /// An SSE register, `xmm0`–`xmm7`.
    Xmm(u8),
    /// An MMX register, `mm0`–`mm7`.
    Mmx(u8),
    /// A memory operand whose width is not one of [`Size`]'s three — the x87
    /// operand sizes (8, 10, 28 and 108 bytes) and nothing else.
    MemWide {
        base: Option<u8>,
        index: Option<u8>,
        scale: u8,
        disp: i64,
        seg: Option<Seg>,
        bytes: u8,
        addr16: bool,
    },
    /// An absolute `seg:offset` far pointer, as `9A`/`EA` encode one.
    FarPtr {
        seg: u16,
        offset: u32,
    },
}

/// A decoded instruction.
#[derive(Clone, Debug)]
pub struct Insn {
    pub len: usize,
    pub mn: Mn,
    pub ops: [Op; 3],
    /// `F3`, when it is a repeat prefix rather than part of the opcode.
    pub rep: bool,
    /// `F2`, likewise.
    pub repne: bool,
    pub lock: bool,
    /// The operand size in effect, which string operations need and which is
    /// not otherwise recoverable from operands they do not encode.
    pub osize: Size,
    /// True when a `67` prefix selected 16-bit addressing.
    pub addr16: bool,
}

impl Insn {
    /// How many operands this instruction reports.
    ///
    /// Counts the slots that hold one rather than stopping at the first empty
    /// slot: an encoding whose shape is unmodelled can report nothing for the
    /// `r/m` operand and still carry an immediate, and `take_while` called that
    /// zero operands. Both differential harnesses gate their register
    /// comparison on this value, so a wrong zero silently skipped the check.
    pub fn op_count(&self) -> usize {
        self.ops.iter().filter(|o| **o != Op::None).count()
    }

    /// The address just past this instruction.
    pub fn next_ip(&self, ip: u64) -> u64 {
        ip.wrapping_add(self.len as u64)
    }
}

// ---------------------------------------------------------------------------
// Operand forms
// ---------------------------------------------------------------------------

/// How an opcode lays out its operands. `decode_form` turns each into concrete
/// [`Op`] values; every encoding in the supported set maps to one of these.
#[derive(Clone, Copy, PartialEq, Eq)]
enum F {
    Nil,
    /// ModRM, r/m first then reg.
    RmReg,
    /// ModRM, reg first then r/m.
    RegRm,
    /// ModRM r/m only — the `reg` field is a group digit, not an operand.
    Rm,
    /// r/m, then an immediate of the operand size.
    RmImmZ,
    /// r/m, then a sign-extended imm8.
    RmImm8Sex,
    /// r/m, then a literal imm8 (a shift count is not sign-extended).
    RmImm8,
    /// r/m, then the constant 1 (`D0`/`D1`).
    RmOne,
    /// r/m, then CL (`D2`/`D3`).
    RmCl,
    /// reg, r/m, CL — the double-shift register form.
    RegRmCl,
    /// reg, r/m, imm8 — the double-shift immediate form.
    RegRmImm8,
    /// reg, r/m, immediate of the operand size (three-operand `imul`).
    RegRmImmZ,
    /// reg, r/m, sign-extended imm8 (three-operand `imul`).
    RegRmImm8Sex,
    /// reg at the operand size, r/m at a fixed narrower width.
    RegRmNarrow(Size),
    /// A register in the low three opcode bits.
    OpReg,
    /// A register in the opcode, then an immediate of that size.
    OpRegImm,
    /// A register in the opcode, then the accumulator.
    OpRegAcc,
    /// The accumulator, then an immediate of the operand size.
    AccImmZ,
    /// AL, then imm8.
    AlImm8,
    ImmZ,
    Imm8Sex,
    Imm8,
    Imm16,
    /// imm16 then imm8 (`enter`).
    Imm16Imm8,
    Rel8,
    /// A relative branch as wide as the operand size — `imm16` under a `66`
    /// prefix. Getting this wrong is a length error.
    RelZ,
    /// The accumulator, then an absolute `moffs` address.
    AccMoffs,
    /// An absolute `moffs` address, then the accumulator.
    MoffsAcc,
    /// A string operation: its operands are implicit.
    Str,
    /// A segment register named by the opcode itself (`push es`).
    SegOp(Seg),
    /// ModRM with the `reg` field naming a segment register (`mov ds, eax`),
    /// r/m first.
    RmSeg,
    /// The same, segment register first (`mov eax, ds`).
    SegRm,
    /// reg, then a ModRM memory operand holding a far pointer (`lds`, `les`).
    RegFarMem,
    /// A lone ModRM operand that must be memory — the indirect far transfers,
    /// which read their `m16:32` target rather than taking it in a register.
    RegFarMemOnly,
    /// An absolute `ptr16:32` operand (`9A`, `EA`).
    FarPtrForm,
    /// The accumulator, then an immediate port number (`in al, 0x60`).
    AccPort,
    /// An immediate port number, then the accumulator (`out 0x60, al`).
    PortAcc,
    /// The accumulator, then DX as a port (`in al, dx`).
    AccDx,
    /// DX as a port, then the accumulator (`out dx, al`).
    DxAcc,
}

// ---------------------------------------------------------------------------
// Opcode tables
// ---------------------------------------------------------------------------

/// An opcode-map slot.
#[derive(Clone, Copy)]
enum Slot {
    /// Not an encoding this decoder claims.
    Bad,
    /// A mnemonic and form at the current operand size.
    I(Mn, F),
    /// The same, forced to byte width — the low opcode bit selects it.
    B(Mn, F),
    /// A `/digit` group, indexed by the ModRM `reg` field.
    G(&'static [Grp; 8]),
}

/// One `/digit` entry. `None` is a digit the group does not define.
type Grp = Option<(Mn, F)>;

use Slot::{Bad as X, B, G, I};
use F::*;

const NIL: Grp = None;

const GRP1: [Grp; 8] = [
    Some((Mn::Add, Rm)),
    Some((Mn::Or, Rm)),
    Some((Mn::Adc, Rm)),
    Some((Mn::Sbb, Rm)),
    Some((Mn::And, Rm)),
    Some((Mn::Sub, Rm)),
    Some((Mn::Xor, Rm)),
    Some((Mn::Cmp, Rm)),
];

const GRP2: [Grp; 8] = [
    Some((Mn::Rol, Rm)),
    Some((Mn::Ror, Rm)),
    Some((Mn::Rcl, Rm)),
    Some((Mn::Rcr, Rm)),
    Some((Mn::Shl, Rm)),
    Some((Mn::Shr, Rm)),
    // `/6` shifts exactly as `/4` does but carries its own name.
    Some((Mn::Sal, Rm)),
    Some((Mn::Sar, Rm)),
];

const GRP3: [Grp; 8] = [
    Some((Mn::Test, RmImmZ)),
    Some((Mn::Test, RmImmZ)),
    Some((Mn::Not, Rm)),
    Some((Mn::Neg, Rm)),
    Some((Mn::Mul, Rm)),
    Some((Mn::Imul, Rm)),
    Some((Mn::Div, Rm)),
    Some((Mn::Idiv, Rm)),
];

const GRP4: [Grp; 8] = [
    Some((Mn::Inc, Rm)),
    Some((Mn::Dec, Rm)),
    NIL,
    NIL,
    NIL,
    NIL,
    NIL,
    NIL,
];

const GRP5: [Grp; 8] = [
    Some((Mn::Inc, Rm)),
    Some((Mn::Dec, Rm)),
    Some((Mn::Call, Rm)),
    // The far forms read a `m16:32` pointer, so their operand must be memory.
    Some((Mn::Call, RegFarMemOnly)),
    Some((Mn::Jmp, Rm)),
    Some((Mn::Jmp, RegFarMemOnly)),
    Some((Mn::Push, Rm)),
    NIL,
];

const GRP8: [Grp; 8] = [
    NIL,
    NIL,
    NIL,
    NIL,
    Some((Mn::Bt, RmImm8)),
    Some((Mn::Bts, RmImm8)),
    Some((Mn::Btr, RmImm8)),
    Some((Mn::Btc, RmImm8)),
];

const GRP_POP: [Grp; 8] = [Some((Mn::Pop, Rm)), NIL, NIL, NIL, NIL, NIL, NIL, NIL];
const GRP_MOV: [Grp; 8] = [Some((Mn::Mov, RmImmZ)), NIL, NIL, NIL, NIL, NIL, NIL, NIL];

/// The eight arithmetic operations filling `00`–`3F`, in encoding order.
const ARITH: [Mn; 8] = [
    Mn::Add,
    Mn::Or,
    Mn::Adc,
    Mn::Sbb,
    Mn::And,
    Mn::Sub,
    Mn::Xor,
    Mn::Cmp,
];

/// Condition codes in encoding order, once per family. `jcc` (`70`/`0F 80`),
/// `setcc` (`0F 90`) and `cmovcc` (`0F 40`) share the ordering, so the low
/// nibble of the opcode indexes all three.
const JCC: [Mn; 16] = [
    Mn::Jo,
    Mn::Jno,
    Mn::Jb,
    Mn::Jae,
    Mn::Je,
    Mn::Jne,
    Mn::Jbe,
    Mn::Ja,
    Mn::Js,
    Mn::Jns,
    Mn::Jp,
    Mn::Jnp,
    Mn::Jl,
    Mn::Jge,
    Mn::Jle,
    Mn::Jg,
];

const SETCC: [Mn; 16] = [
    Mn::Seto,
    Mn::Setno,
    Mn::Setb,
    Mn::Setae,
    Mn::Sete,
    Mn::Setne,
    Mn::Setbe,
    Mn::Seta,
    Mn::Sets,
    Mn::Setns,
    Mn::Setp,
    Mn::Setnp,
    Mn::Setl,
    Mn::Setge,
    Mn::Setle,
    Mn::Setg,
];

const CMOVCC: [Mn; 16] = [
    Mn::Cmovo,
    Mn::Cmovno,
    Mn::Cmovb,
    Mn::Cmovae,
    Mn::Cmove,
    Mn::Cmovne,
    Mn::Cmovbe,
    Mn::Cmova,
    Mn::Cmovs,
    Mn::Cmovns,
    Mn::Cmovp,
    Mn::Cmovnp,
    Mn::Cmovl,
    Mn::Cmovge,
    Mn::Cmovle,
    Mn::Cmovg,
];

fn one_byte(op: u8) -> Slot {
    // `00`–`3F` is eight operations x six encodings: `op >> 3` selects the
    // operation and `op & 7` the encoding. The `x6`/`x7` slots are segment
    // pushes and BCD, which fall through to the match below.
    if op < 0x40 && (op & 7) < 6 {
        let m = ARITH[(op >> 3) as usize];
        return match op & 7 {
            0 => B(m, RmReg),
            1 => I(m, RmReg),
            2 => B(m, RegRm),
            3 => I(m, RegRm),
            4 => I(m, AlImm8),
            _ => I(m, AccImmZ),
        };
    }
    match op {
        // The `x6`/`x7` slots the arithmetic family leaves free: segment
        // pushes and pops, and the packed-BCD adjustments.
        0x06 => I(Mn::Push, SegOp(Seg::Es)),
        0x07 => I(Mn::Pop, SegOp(Seg::Es)),
        0x0e => I(Mn::Push, SegOp(Seg::Cs)),
        0x16 => I(Mn::Push, SegOp(Seg::Ss)),
        0x17 => I(Mn::Pop, SegOp(Seg::Ss)),
        0x1e => I(Mn::Push, SegOp(Seg::Ds)),
        0x1f => I(Mn::Pop, SegOp(Seg::Ds)),
        0x27 => I(Mn::Daa, Nil),
        0x2f => I(Mn::Das, Nil),
        0x37 => I(Mn::Aaa, Nil),
        0x3f => I(Mn::Aas, Nil),
        0x40..=0x47 => I(Mn::Inc, OpReg),
        0x48..=0x4f => I(Mn::Dec, OpReg),
        0x50..=0x57 => I(Mn::Push, OpReg),
        0x58..=0x5f => I(Mn::Pop, OpReg),
        0x60 => I(Mn::Pushad, Nil),
        0x61 => I(Mn::Popad, Nil),
        0x62 => I(Mn::Bound, RegRm),
        0x63 => I(Mn::Arpl, RmReg),
        0x6c => B(Mn::Insb, Str),
        0x6d => I(Mn::Insd, Str),
        0x6e => B(Mn::Outsb, Str),
        0x6f => I(Mn::Outsd, Str),
        0x68 => I(Mn::Push, ImmZ),
        0x69 => I(Mn::Imul, RegRmImmZ),
        0x6a => I(Mn::Push, Imm8Sex),
        0x6b => I(Mn::Imul, RegRmImm8Sex),
        0x70..=0x7f => I(JCC[(op & 0xf) as usize], Rel8),
        // `82` is an undocumented alias of `80` — same group, same byte-wide
        // immediate — and real code does use it.
        0x80..=0x83 => G(&GRP1),
        0x84 => B(Mn::Test, RmReg),
        0x85 => I(Mn::Test, RmReg),
        0x86 => B(Mn::Xchg, RmReg),
        0x87 => I(Mn::Xchg, RmReg),
        0x88 => B(Mn::Mov, RmReg),
        0x89 => I(Mn::Mov, RmReg),
        0x8a => B(Mn::Mov, RegRm),
        0x8b => I(Mn::Mov, RegRm),
        0x8c => I(Mn::Mov, RmSeg),
        0x8d => I(Mn::Lea, RegRm),
        0x8e => I(Mn::Mov, SegRm),
        0x8f => G(&GRP_POP),
        0x90 => I(Mn::Nop, Nil),
        0x91..=0x97 => I(Mn::Xchg, OpRegAcc),
        0x98 => I(Mn::Cwde, Nil),
        0x99 => I(Mn::Cdq, Nil),
        0x9a => I(Mn::Call, FarPtrForm),
        0x9b => I(Mn::Wait, Nil),
        0x9c => I(Mn::Pushfd, Nil),
        0x9d => I(Mn::Popfd, Nil),
        0x9e => I(Mn::Sahf, Nil),
        0x9f => I(Mn::Lahf, Nil),
        0xa0 => B(Mn::Mov, AccMoffs),
        0xa1 => I(Mn::Mov, AccMoffs),
        0xa2 => B(Mn::Mov, MoffsAcc),
        0xa3 => I(Mn::Mov, MoffsAcc),
        0xa4 => B(Mn::Movsb, Str),
        0xa5 => I(Mn::Movsd, Str),
        0xa6 => B(Mn::Cmpsb, Str),
        0xa7 => I(Mn::Cmpsd, Str),
        0xa8 => I(Mn::Test, AlImm8),
        0xa9 => I(Mn::Test, AccImmZ),
        0xaa => B(Mn::Stosb, Str),
        0xab => I(Mn::Stosd, Str),
        0xac => B(Mn::Lodsb, Str),
        0xad => I(Mn::Lodsd, Str),
        0xae => B(Mn::Scasb, Str),
        0xaf => I(Mn::Scasd, Str),
        0xb0..=0xb7 => B(Mn::Mov, OpRegImm),
        0xb8..=0xbf => I(Mn::Mov, OpRegImm),
        0xc0 | 0xc1 => G(&GRP2),
        0xc2 => I(Mn::Ret, Imm16),
        0xc3 => I(Mn::Ret, Nil),
        0xc4 => I(Mn::Les, RegFarMem),
        0xc5 => I(Mn::Lds, RegFarMem),
        0xc6 | 0xc7 => G(&GRP_MOV),
        0xc8 => I(Mn::Enter, Imm16Imm8),
        0xc9 => I(Mn::Leave, Nil),
        0xca => I(Mn::Retf, Imm16),
        0xcb => I(Mn::Retf, Nil),
        0xcc => I(Mn::Int3, Nil),
        0xcd => I(Mn::Int, Imm8),
        0xce => I(Mn::Into, Nil),
        0xcf => I(Mn::Iretd, Nil),
        0xd0..=0xd3 => G(&GRP2),
        0xd4 => I(Mn::Aam, Imm8),
        0xd5 => I(Mn::Aad, Imm8),
        0xd6 => I(Mn::Salc, Nil),
        0xd7 => I(Mn::Xlatb, Nil),
        0xe0 => I(Mn::Loopne, Rel8),
        0xe1 => I(Mn::Loope, Rel8),
        0xe2 => I(Mn::Loop, Rel8),
        0xe3 => I(Mn::Jecxz, Rel8),
        0xe4 => B(Mn::In, AccPort),
        0xe5 => I(Mn::In, AccPort),
        0xe6 => B(Mn::Out, PortAcc),
        0xe7 => I(Mn::Out, PortAcc),
        0xe8 => I(Mn::Call, RelZ),
        0xe9 => I(Mn::Jmp, RelZ),
        0xea => I(Mn::Jmp, FarPtrForm),
        0xeb => I(Mn::Jmp, Rel8),
        0xec => B(Mn::In, AccDx),
        0xed => I(Mn::In, AccDx),
        0xee => B(Mn::Out, DxAcc),
        0xef => I(Mn::Out, DxAcc),
        0xf1 => I(Mn::Int1, Nil),
        0xf4 => I(Mn::Hlt, Nil),
        0xf5 => I(Mn::Cmc, Nil),
        0xf6 | 0xf7 => G(&GRP3),
        0xf8 => I(Mn::Clc, Nil),
        0xf9 => I(Mn::Stc, Nil),
        0xfa => I(Mn::Cli, Nil),
        0xfb => I(Mn::Sti, Nil),
        0xfc => I(Mn::Cld, Nil),
        0xfd => I(Mn::Std, Nil),
        0xfe => G(&GRP4),
        0xff => G(&GRP5),
        _ => X,
    }
}

/// The `0F` encodings written by hand rather than taken from the generated
/// table, because the rest of exav acts on their operands: branches need a
/// resolved target, `setcc`/`cmovcc` a condition, `movzx`/`movsx` a source
/// width. Everything else in the map — the SIMD region, the system and
/// virtualisation space, the reserved no-ops — is generated, and `Bad` here
/// routes to it.
fn two_byte(op: u8) -> Slot {
    match op {
        0x31 => I(Mn::Rdtsc, Nil),
        0x40..=0x4f => I(CMOVCC[(op & 0xf) as usize], RegRm),
        0x80..=0x8f => I(JCC[(op & 0xf) as usize], RelZ),
        0x90..=0x9f => B(SETCC[(op & 0xf) as usize], Rm),
        0xa0 => I(Mn::Push, SegOp(Seg::Fs)),
        0xa1 => I(Mn::Pop, SegOp(Seg::Fs)),
        0xa2 => I(Mn::Cpuid, Nil),
        0xa3 => I(Mn::Bt, RmReg),
        0xa8 => I(Mn::Push, SegOp(Seg::Gs)),
        0xa9 => I(Mn::Pop, SegOp(Seg::Gs)),
        0xa4 => I(Mn::Shld, RegRmImm8),
        0xa5 => I(Mn::Shld, RegRmCl),
        0xab => I(Mn::Bts, RmReg),
        0xac => I(Mn::Shrd, RegRmImm8),
        0xad => I(Mn::Shrd, RegRmCl),
        0xaf => I(Mn::Imul, RegRm),
        0xb0 => B(Mn::Cmpxchg, RmReg),
        0xb1 => I(Mn::Cmpxchg, RmReg),
        0xb2 => I(Mn::Lss, RegFarMem),
        0xb3 => I(Mn::Btr, RmReg),
        0xb4 => I(Mn::Lfs, RegFarMem),
        0xb5 => I(Mn::Lgs, RegFarMem),
        0xb6 => I(Mn::Movzx, RegRmNarrow(Size::B1)),
        0xb7 => I(Mn::Movzx, RegRmNarrow(Size::B2)),
        0xba => G(&GRP8),
        0xbb => I(Mn::Btc, RmReg),
        0xbc => I(Mn::Bsf, RegRm),
        0xbd => I(Mn::Bsr, RegRm),
        0xbe => I(Mn::Movsx, RegRmNarrow(Size::B1)),
        0xbf => I(Mn::Movsx, RegRmNarrow(Size::B2)),
        0xc0 => B(Mn::Xadd, RmReg),
        0xc1 => I(Mn::Xadd, RmReg),
        0xc8..=0xcf => I(Mn::Bswap, OpReg),
        _ => X,
    }
}

// ---------------------------------------------------------------------------
// x87
// ---------------------------------------------------------------------------

/// The memory forms of `D8`–`DF`, indexed by escape then ModRM `/digit`, with
/// the width of the memory operand each one addresses. `None` is a digit that
/// escape does not define.
///
/// The widths matter: `fld m32fp`, `fld m64fp` and `fld m80fp` are three
/// different encodings of one mnemonic, and a caller sizing a read from the
/// operand needs the right one.
const X87_MEM: [[Option<(Mn, u8)>; 8]; 8] = [
    // D8 — single-precision.
    [
        Some((Mn::Fadd, 4)),
        Some((Mn::Fmul, 4)),
        Some((Mn::Fcom, 4)),
        Some((Mn::Fcomp, 4)),
        Some((Mn::Fsub, 4)),
        Some((Mn::Fsubr, 4)),
        Some((Mn::Fdiv, 4)),
        Some((Mn::Fdivr, 4)),
    ],
    // D9 — load/store single, and the control-word / environment transfers.
    [
        Some((Mn::Fld, 4)),
        None,
        Some((Mn::Fst, 4)),
        Some((Mn::Fstp, 4)),
        Some((Mn::Fldenv, 28)),
        Some((Mn::Fldcw, 2)),
        Some((Mn::Fnstenv, 28)),
        Some((Mn::Fnstcw, 2)),
    ],
    // DA — 32-bit integer.
    [
        Some((Mn::Fiadd, 4)),
        Some((Mn::Fimul, 4)),
        Some((Mn::Ficom, 4)),
        Some((Mn::Ficomp, 4)),
        Some((Mn::Fisub, 4)),
        Some((Mn::Fisubr, 4)),
        Some((Mn::Fidiv, 4)),
        Some((Mn::Fidivr, 4)),
    ],
    // DB — 32-bit integer load/store, and extended-precision.
    [
        Some((Mn::Fild, 4)),
        Some((Mn::Fisttp, 4)),
        Some((Mn::Fist, 4)),
        Some((Mn::Fistp, 4)),
        None,
        Some((Mn::Fld, 10)),
        None,
        Some((Mn::Fstp, 10)),
    ],
    // DC — double-precision.
    [
        Some((Mn::Fadd, 8)),
        Some((Mn::Fmul, 8)),
        Some((Mn::Fcom, 8)),
        Some((Mn::Fcomp, 8)),
        Some((Mn::Fsub, 8)),
        Some((Mn::Fsubr, 8)),
        Some((Mn::Fdiv, 8)),
        Some((Mn::Fdivr, 8)),
    ],
    // DD — double load/store, and the full-state transfers.
    [
        Some((Mn::Fld, 8)),
        Some((Mn::Fisttp, 8)),
        Some((Mn::Fst, 8)),
        Some((Mn::Fstp, 8)),
        Some((Mn::Frstor, 108)),
        None,
        Some((Mn::Fnsave, 108)),
        Some((Mn::Fnstsw, 2)),
    ],
    // DE — 16-bit integer.
    [
        Some((Mn::Fiadd, 2)),
        Some((Mn::Fimul, 2)),
        Some((Mn::Ficom, 2)),
        Some((Mn::Ficomp, 2)),
        Some((Mn::Fisub, 2)),
        Some((Mn::Fisubr, 2)),
        Some((Mn::Fidiv, 2)),
        Some((Mn::Fidivr, 2)),
    ],
    // DF — 16-bit integer load/store, packed BCD, and 64-bit integer.
    [
        Some((Mn::Fild, 2)),
        Some((Mn::Fisttp, 2)),
        Some((Mn::Fist, 2)),
        Some((Mn::Fistp, 2)),
        Some((Mn::Fbld, 10)),
        Some((Mn::Fild, 8)),
        Some((Mn::Fbstp, 10)),
        Some((Mn::Fistp, 8)),
    ],
];

/// The register forms of `D8`–`DF` (`mod=3`). Most escapes divide the `C0`–`FF`
/// range into eight blocks of eight, each block one mnemonic operating on
/// `ST(i)`; `D9` and parts of `DA`/`DB`/`DE`/`DF` instead name a specific
/// instruction per byte, with no operand.
fn x87_reg(esc: u8, modrm: u8) -> Option<(Mn, bool)> {
    let block = (modrm >> 3) & 7;
    // `true` here means the instruction takes `ST(i)` from the low three bits.
    let blk = |m: Mn| Some((m, true));
    let one = |m: Mn| Some((m, false));
    match esc {
        0xd8 => blk([
            Mn::Fadd,
            Mn::Fmul,
            Mn::Fcom,
            Mn::Fcomp,
            Mn::Fsub,
            Mn::Fsubr,
            Mn::Fdiv,
            Mn::Fdivr,
        ][block as usize]),
        0xd9 => match modrm {
            0xc0..=0xc7 => blk(Mn::Fld),
            0xc8..=0xcf => blk(Mn::Fxch),
            0xd0 => one(Mn::Fnop),
            // `D9 D8`–`DF` is the undocumented `fstp` that skips the stack-fault
            // check. Packers reach for it precisely because disassemblers miss it.
            0xd8..=0xdf => blk(Mn::Fstpnce),
            0xe0 => one(Mn::Fchs),
            0xe1 => one(Mn::Fabs),
            0xe4 => one(Mn::Ftst),
            0xe5 => one(Mn::Fxam),
            0xe8 => one(Mn::Fld1),
            0xe9 => one(Mn::Fldl2t),
            0xea => one(Mn::Fldl2e),
            0xeb => one(Mn::Fldpi),
            0xec => one(Mn::Fldlg2),
            0xed => one(Mn::Fldln2),
            0xee => one(Mn::Fldz),
            0xf0 => one(Mn::F2xm1),
            0xf1 => one(Mn::Fyl2x),
            0xf2 => one(Mn::Fptan),
            0xf3 => one(Mn::Fpatan),
            0xf4 => one(Mn::Fxtract),
            0xf5 => one(Mn::Fprem1),
            0xf6 => one(Mn::Fdecstp),
            0xf7 => one(Mn::Fincstp),
            0xf8 => one(Mn::Fprem),
            0xf9 => one(Mn::Fyl2xp1),
            0xfa => one(Mn::Fsqrt),
            0xfb => one(Mn::Fsincos),
            0xfc => one(Mn::Frndint),
            0xfd => one(Mn::Fscale),
            0xfe => one(Mn::Fsin),
            0xff => one(Mn::Fcos),
            _ => None,
        },
        0xda => match modrm {
            0xc0..=0xc7 => blk(Mn::Fcmovb),
            0xc8..=0xcf => blk(Mn::Fcmove),
            0xd0..=0xd7 => blk(Mn::Fcmovbe),
            0xd8..=0xdf => blk(Mn::Fcmovu),
            0xe9 => one(Mn::Fucompp),
            _ => None,
        },
        0xdb => match modrm {
            0xc0..=0xc7 => blk(Mn::Fcmovnb),
            0xc8..=0xcf => blk(Mn::Fcmovne),
            0xd0..=0xd7 => blk(Mn::Fcmovnbe),
            0xd8..=0xdf => blk(Mn::Fcmovnu),
            0xe0 => one(Mn::Fneni),
            0xe1 => one(Mn::Fndisi),
            0xe2 => one(Mn::Fnclex),
            0xe3 => one(Mn::Fninit),
            0xe4 => one(Mn::Fnsetpm),
            0xe8..=0xef => blk(Mn::Fucomi),
            0xf0..=0xf7 => blk(Mn::Fcomi),
            _ => None,
        },
        0xdc => match modrm {
            0xc0..=0xc7 => blk(Mn::Fadd),
            0xc8..=0xcf => blk(Mn::Fmul),
            // Undocumented aliases of the `D8` comparison forms.
            0xd0..=0xd7 => blk(Mn::Fcom),
            0xd8..=0xdf => blk(Mn::Fcomp),
            0xe0..=0xe7 => blk(Mn::Fsubr),
            0xe8..=0xef => blk(Mn::Fsub),
            0xf0..=0xf7 => blk(Mn::Fdivr),
            0xf8..=0xff => blk(Mn::Fdiv),
            _ => None,
        },
        0xdd => match modrm {
            0xc0..=0xc7 => blk(Mn::Ffree),
            0xc8..=0xcf => blk(Mn::Fxch),
            0xd0..=0xd7 => blk(Mn::Fst),
            0xd8..=0xdf => blk(Mn::Fstp),
            0xe0..=0xe7 => blk(Mn::Fucom),
            0xe8..=0xef => blk(Mn::Fucomp),
            _ => None,
        },
        0xde => match modrm {
            0xc0..=0xc7 => blk(Mn::Faddp),
            0xc8..=0xcf => blk(Mn::Fmulp),
            0xd0..=0xd7 => blk(Mn::Fcomp),
            0xd9 => one(Mn::Fcompp),
            0xe0..=0xe7 => blk(Mn::Fsubrp),
            0xe8..=0xef => blk(Mn::Fsubp),
            0xf0..=0xf7 => blk(Mn::Fdivrp),
            0xf8..=0xff => blk(Mn::Fdivp),
            _ => None,
        },
        0xdf => match modrm {
            0xc0..=0xc7 => blk(Mn::Ffreep),
            0xc8..=0xcf => blk(Mn::Fxch),
            0xd0..=0xdf => blk(Mn::Fstp),
            0xe0 => one(Mn::Fnstsw),
            0xe8..=0xef => blk(Mn::Fucomip),
            0xf0..=0xf7 => blk(Mn::Fcomip),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// The longest instruction a 32-bit processor will decode.
pub const MAX_INSN_LEN: usize = 15;

/// Flatten a `0F`-map coordinate into an index of [`generated::OF_MAP`], whose
/// axes are prefix, opcode, ModRM digit, then `mod == 3`.
fn of_index(pfx: usize, op: u8, digit: u8, mod3: bool) -> usize {
    ((pfx * 256 + op as usize) * 8 + digit as usize) * 2 + usize::from(mod3)
}

/// The same for [`generated::VEX_MAP`] and [`generated::XOP_MAP`], whose axes
/// are the opcode map (numbered from the family's first), the mandatory-prefix
/// field, `L`, `W`, then the opcode.
fn vex_index(map: u8, pp: u8, l: u8, w: u8, op: u8) -> usize {
    (((map as usize * 4 + pp as usize) * 2 + l as usize) * 2 + w as usize) * 256 + op as usize
}

/// Everything a VEX or XOP encoding does after its prefix has been read: look
/// up the cell, honour its flags, then consume the ModRM and any immediate.
///
/// Shared because the two prefixes differ only in which byte introduces them
/// and which maps they select — a second copy of this would be a second place
/// for an immediate width to go stale.
#[allow(clippy::too_many_arguments)]
fn vex_tail(
    r: &mut Reader,
    map: &[u32],
    sub: &[u32],
    index: usize,
    vvvv: u8,
    seg: Option<Seg>,
    asz16: bool,
    osize: Size,
) -> Option<Insn> {
    let mut cell = map[index];
    // An opcode whose meaning varies by `/digit` or by `mod` — the shift
    // groups, and the few whose register form is a different instruction —
    // stores a block of sixteen cells instead of one.
    if cell & VEX_SUB_BIT != 0 {
        let m = r.peek().unwrap_or(0);
        let block = (cell >> VEX_NAME_SHIFT) as usize;
        cell = sub[block * 16 + (((m >> 3) & 7) as usize) * 2 + usize::from(m >= 0xc0)];
    }
    if cell == 0 {
        return None;
    }
    // Encodings with no third source operand require the `vvvv` field to be all
    // ones; anything else there is a malformed encoding, not the same
    // instruction with a spare register number.
    if cell & VEX_STRICT_VVVV != 0 && vvvv != 0xf {
        return None;
    }
    let mn = Mn::from_generated(((cell >> VEX_NAME_SHIFT) - 1) as usize);
    // Nearly every such encoding reads a ModRM byte; `vzeroupper` and
    // `vzeroall` are the exceptions, and consuming a byte they do not read
    // would report them two to six bytes too long.
    let rm = if cell & VEX_NO_MODRM != 0 {
        Op::None
    } else {
        // A gather addresses memory through a vector index, and the only
        // encoding of one is a SIB byte. `rm != 100` names no SIB, so it is not
        // a smaller form of the instruction — it is not the instruction, and
        // claiming it would put a length on bytes the CPU faults.
        if cell & VEX_VSIB != 0 && r.peek().is_some_and(|b| b & 7 != 4) {
            return None;
        }
        let (_, rm) = modrm(r, Size::B4, seg, asz16)?;
        // A vector index is consumed but not reported: naming it as a
        // general-purpose register would be a plausible-looking lie, and
        // nothing in exav reads a vector operand.
        if cell & VEX_VSIB != 0 {
            Op::None
        } else {
            // Same reason, one step further: for `mod == 3` the operand names a
            // vector register, and `modrm` can only describe it as `Op::Reg` —
            // which says `ecx` for `xmm1`. The `0F` map already collapses this
            // to nothing; consumers rely on that (exav-core's bytecode disasm
            // maps vector operands to no-arg precisely so a signature cannot
            // match `eax` when the instruction named `xmm0`), and a `Op::Reg`
            // arriving from here walks straight past that guard.
            match rm {
                Op::Reg(..) => Op::None,
                other => other,
            }
        }
    };
    let imm_op = match cell & 3 {
        0 => Op::None,
        1 => Op::Imm(r.u8()? as i64),
        2 => Op::Imm(r.u16()? as i64),
        _ => Op::Imm(r.u32()? as i32 as i64),
    };
    if r.i > MAX_INSN_LEN {
        return None;
    }
    // No `rep`, `repne` or `lock`: a legacy prefix in front of one of these
    // makes the byte sequence invalid rather than modifying it, and the caller
    // has already declined that case.
    Some(Insn {
        len: r.i,
        mn,
        ops: [rm, imm_op, Op::None],
        rep: false,
        repne: false,
        lock: false,
        osize,
        addr16: asz16,
    })
}

/// Set in a [`generated::OF_SHAPE`] word that describes an encoding's operands
/// at all. Without it the encoding's identity and length are still exact; only
/// its operand shape is unmodelled.
const SHAPE_PRESENT: u16 = 1;
/// Set when the `reg`-field operand comes before the `rm`-field one.
const SHAPE_REG_FIRST: u16 = 1 << 1;
/// Set when there is no `reg`-field operand: those bits are a group digit.
const SHAPE_RM_ONLY: u16 = 1 << 9;

/// A ModRM register field, as the register file and width the encoding names.
fn typed_reg(num: u8, class: u16) -> Op {
    match class {
        1 => Op::Xmm(num),
        2 => Op::Mmx(num),
        3 => Op::Reg(num, Size::B2),
        4 => Op::Reg(num, Size::B1),
        _ => Op::Reg(num, Size::B4),
    }
}

/// Re-stamp a memory operand with the width its encoding addresses, which the
/// ModRM byte does not carry: `movd` and `movdqa` differ only in the table.
fn sized_mem(op: Op, bytes: u8) -> Op {
    // Zero means "no width recorded", which is not the same as a zero-byte
    // access: leave the operand exactly as the ModRM decode produced it.
    if bytes == 0 {
        return op;
    }
    let (base, index, scale, disp, seg, addr16) = match op {
        Op::Mem {
            base,
            index,
            scale,
            disp,
            seg,
            addr16,
            ..
        } => (base, index, scale, disp, seg, addr16),
        other => return other,
    };
    match bytes {
        1 | 2 | 4 => Op::Mem {
            base,
            index,
            scale,
            disp,
            seg,
            size: match bytes {
                1 => Size::B1,
                2 => Size::B2,
                _ => Size::B4,
            },
            addr16,
        },
        _ => Op::MemWide {
            base,
            index,
            scale,
            disp,
            seg,
            bytes,
            addr16,
        },
    }
}

/// Set in an EVEX cell whose high bits index [`generated::EVEX_SUB`].
const EVEX_SUB_BIT: u32 = 1 << 2;
/// Set in an EVEX cell that rejects a `vvvv` field other than `1111`.
const EVEX_STRICT_VVVV: u32 = 1 << 6;
/// Set in an EVEX cell that requires a non-zero mask register.
const EVEX_NEEDS_MASK: u32 = 1 << 7;
/// Set in an EVEX cell that forbids one — it writes a mask rather than reads it.
const EVEX_FORBIDS_MASK: u32 = 1 << 8;
/// Set in an EVEX cell that forbids zeroing-merge.
const EVEX_FORBIDS_Z: u32 = 1 << 9;
/// Set in an EVEX cell that indexes memory with a vector register — a gather or
/// a scatter, which only a SIB byte can encode.
const EVEX_VSIB: u32 = 1 << 10;
/// How far an EVEX cell's mnemonic index (or block index) is shifted up.
const EVEX_NAME_SHIFT: u32 = 11;

/// Flatten an EVEX coordinate into a [`generated::EVEX_KEYS`] key.
fn evex_key(mm: u8, pp: u8, w: u8, ll: u8, b: u8, op: u8) -> u32 {
    ((((mm as u32 * 4 + pp as u32) * 2 + w as u32) * 4 + ll as u32) * 2 + b as u32) * 256
        + op as u32
}

/// Apply EVEX's compressed-displacement scaling.
///
/// An eight-bit displacement in an EVEX encoding counts *elements*, not bytes,
/// so it is multiplied by a factor the instruction chooses — which is why the
/// generated table has to carry it: nothing in the ModRM byte says what it is,
/// and an unscaled displacement addresses the wrong memory by up to 63x.
fn scale_disp(op: Op, shift: u32) -> Op {
    match op {
        Op::Mem {
            base,
            index,
            scale,
            disp,
            seg,
            size,
            addr16,
        } => Op::Mem {
            base,
            index,
            scale,
            disp: disp << shift,
            seg,
            size,
            addr16,
        },
        other => other,
    }
}

/// Set in a VEX cell for an opcode that reads no ModRM byte — `vzeroupper` and
/// `vzeroall`, where treating the next byte as one gets the length wrong.
const VEX_NO_MODRM: u32 = 1 << 2;
/// Set in a VEX cell that rejects a `vvvv` field other than `1111`.
const VEX_STRICT_VVVV: u32 = 1 << 3;
/// Set in a VEX cell whose SIB index names a vector register — the gathers and
/// scatters. [`Op::Mem`] can only name a general-purpose index, so the operand
/// of such an encoding is left unreported rather than named as the wrong
/// register file. Its length is unaffected: a VSIB byte is a SIB byte.
const VEX_VSIB: u32 = 1 << 4;
/// Set in a [`generated::VEX_MAP`] cell whose high bits index a block of
/// [`generated::VEX_SUB`] rather than naming an instruction directly.
const VEX_SUB_BIT: u32 = 1 << 5;
/// How far the mnemonic index (or the block index) is shifted up.
const VEX_NAME_SHIFT: u32 = 6;

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.u8()?, self.u8()?]))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes([
            self.u8()?,
            self.u8()?,
            self.u8()?,
            self.u8()?,
        ]))
    }
}

/// Decode one instruction from the start of `bytes`, as if it were at `ip`.
///
/// Returns `None` when the bytes are not an encoding this decoder claims. See
/// the crate documentation: that is *not* the same as "illegal instruction",
/// and a caller must not report it as one.
pub fn decode(bytes: &[u8], ip: u64) -> Option<Insn> {
    let mut r = Reader { b: bytes, i: 0 };

    // Prefixes may appear in any order and repeat; within a class the last one
    // wins. More than 15 bytes total is not an instruction.
    let (mut osz16, mut asz16, mut rep, mut repne, mut lock) = (false, false, false, false, false);
    let mut seg = None;
    let op = loop {
        let b = r.u8()?;
        match b {
            0x66 => osz16 = true,
            0x67 => asz16 = true,
            // `F2` and `F3` are one class: `F3 F2` is `repne`, not both.
            0xf3 => {
                rep = true;
                repne = false;
            }
            0xf2 => {
                repne = true;
                rep = false;
            }
            0xf0 => lock = true,
            0x26 => seg = Some(Seg::Es),
            0x2e => seg = Some(Seg::Cs),
            0x36 => seg = Some(Seg::Ss),
            0x3e => seg = Some(Seg::Ds),
            0x64 => seg = Some(Seg::Fs),
            0x65 => seg = Some(Seg::Gs),
            _ => break b,
        }
        if r.i >= MAX_INSN_LEN {
            return None;
        }
    };

    let osize = if osz16 { Size::B2 } else { Size::B4 };

    // VEX. In 32-bit mode `C4` and `C5` are `les` and `lds` unless the byte
    // after them looks like `mod == 3`, which those two cannot encode: they
    // load a far pointer out of memory. That one bit pair is the whole
    // disambiguation, and it is why the check has to happen before the
    // one-byte map is consulted.
    // EVEX. Like `C4`, `62` is a prefix only when the byte after it looks like
    // `mod == 3`; otherwise it is `bound`, which reads its limits from memory.
    if op == 0x62 && r.peek().is_some_and(|b| b >= 0xc0) {
        if osz16 || rep || repne || lock {
            return None;
        }
        let (p0, p1, p2) = (r.u8()?, r.u8()?, r.u8()?);
        // `P0` bit 3 is reserved — the three below it are the opcode-map
        // selector, which reaches 6 for the FP16 maps — `P1` bit 2 is fixed at
        // one, and `V'`, the fifth `vvvv` bit, names a register 32-bit mode
        // does not have, so it has to read as its inverted "absent" value.
        // Each is a hard reject: a processor raises #UD rather than ignoring
        // them.
        if p0 & 0b0000_1000 != 0 || p1 & 0b100 == 0 || p2 & 0b1000 == 0 {
            return None;
        }
        let mm = p0 & 7;
        let (w, vvvv, pp) = (p1 >> 7, (p1 >> 3) & 0xf, p1 & 3);
        let (z, ll, bcast, aaa) = (p2 >> 7, (p2 >> 5) & 3, (p2 >> 4) & 1, p2 & 7);
        // Zeroing-merge zeroes the lanes a mask register masks off, so asking
        // for it without naming a mask register is not an encoding, whatever
        // the opcode. This holds across the map and is not in the table.
        if z != 0 && aaa == 0 {
            return None;
        }
        let eop = r.u8()?;
        let key = evex_key(mm, pp, w, ll, bcast, eop);
        let idx = generated::EVEX_KEYS.binary_search(&key).ok()?;
        let mut cell = generated::EVEX_CELLS[idx];
        if cell & EVEX_SUB_BIT != 0 {
            let m = r.peek().unwrap_or(0);
            let block = (cell >> EVEX_NAME_SHIFT) as usize;
            cell = generated::EVEX_SUB
                [block * 16 + (((m >> 3) & 7) as usize) * 2 + usize::from(m >= 0xc0)];
        }
        if cell == 0
            || (cell & EVEX_STRICT_VVVV != 0 && vvvv != 0xf)
            || (cell & EVEX_NEEDS_MASK != 0 && aaa == 0)
            || (cell & EVEX_FORBIDS_MASK != 0 && aaa != 0)
            || (cell & EVEX_FORBIDS_Z != 0 && z != 0)
        {
            return None;
        }
        let mn = Mn::from_generated(((cell >> EVEX_NAME_SHIFT) - 1) as usize);
        // Every EVEX encoding reads a ModRM byte, and an eight-bit
        // displacement in one is *compressed*: it counts elements, not bytes,
        // so it has to be scaled by a factor the encoding chooses. Nothing in
        // the ModRM byte says what that factor is — only the table does.
        let disp8 = r.peek().is_some_and(|m| m >> 6 == 1);
        // A gather or scatter addresses memory through a vector index, and the
        // only encoding of one is a SIB byte. Without `rm == 100` there is no
        // SIB and so no such instruction — `vscatterdps` with `rm = 001` is not
        // a shorter form of it, and putting a length on it would step a linear
        // decode into the middle of whatever follows.
        if cell & EVEX_VSIB != 0 && r.peek().is_some_and(|m| m & 7 != 4) {
            return None;
        }
        let (dest, rm) = modrm(&mut r, Size::B4, seg, asz16)?;
        // A complex multiply reads both halves of each source lane and writes
        // both halves of the destination, so naming one register as destination
        // and source at once has no defined result and the processor faults.
        // The tables cannot carry this: it is a relation between three operand
        // fields, where every entry describes one field at a time.
        if overlaps_a_source(mn, dest, vvvv, rm) {
            return None;
        }
        let rm = if disp8 {
            scale_disp(rm, (cell >> 3) & 7)
        } else {
            rm
        };
        // As in `vex_tail`: for `mod == 3` this names a vector register, and
        // reporting it as `Op::Reg` would say `ecx` where the encoding said
        // `xmm1`/`zmm1`. Not reporting it is the narrower, true claim. A vector
        // INDEX is dropped for the same reason — the number in the SIB byte
        // names a vector register, not the general-purpose one it would read as.
        let rm = match rm {
            _ if cell & EVEX_VSIB != 0 => Op::None,
            Op::Reg(..) => Op::None,
            other => other,
        };
        let imm_op = match cell & 3 {
            0 => Op::None,
            1 => Op::Imm(r.u8()? as i64),
            2 => Op::Imm(r.u16()? as i64),
            _ => Op::Imm(r.u32()? as i32 as i64),
        };
        if r.i > MAX_INSN_LEN {
            return None;
        }
        return Some(Insn {
            len: r.i,
            mn,
            ops: [rm, imm_op, Op::None],
            rep,
            repne,
            lock,
            osize,
            addr16: asz16,
        });
    }

    // AMD's XOP prefix is `8F`, whose plain meaning is `pop r/m` at `/0`. The
    // discriminator there is not `mod` but the ModRM `reg` field: a non-zero
    // `/digit` is not a `pop`, and those bits are the top of XOP's own map
    // selector, so a map of 8 or more is what makes the byte a prefix.
    if op == 0x8f && r.peek().is_some_and(|b| b & 0b0011_1000 != 0) {
        if osz16 || rep || repne || lock {
            return None;
        }
        let b1 = r.u8()?;
        let b2 = r.u8()?;
        let (map, w, l, pp, vvvv) = (b1 & 0x1f, b2 >> 7, (b2 >> 2) & 1, b2 & 3, (b2 >> 3) & 0xf);
        if !(8..=10).contains(&map) {
            return None;
        }
        let xop = r.u8()?;
        return vex_tail(
            &mut r,
            &generated::XOP_MAP,
            &generated::XOP_SUB,
            vex_index(map - 8, pp, l, w, xop),
            vvvv,
            seg,
            asz16,
            osize,
        );
    }

    if matches!(op, 0xc4 | 0xc5) && r.peek().is_some_and(|b| b >= 0xc0) {
        // A legacy operand-size, repeat or lock prefix in front of a VEX
        // prefix is not a prefixed VEX instruction — it is not an instruction.
        // The mandatory prefix VEX needs is the `pp` field inside itself.
        if osz16 || rep || repne || lock {
            return None;
        }
        // `C5` is the two-byte form: implicitly the `0F` map with `W = 0`. Its
        // `R` bit and the top bit of `vvvv` occupy the positions that make the
        // byte look like `mod == 3`, so `C5` can only ever carry `vvvv <= 7`.
        //
        // `C4`'s `R`, `X` and `B` bits extend register numbers that do not
        // exist in 32-bit mode, so the processor ignores them, and so does
        // this: they are read only for the `mod == 3` test above.
        let (map, w, l, pp, vvvv) = if op == 0xc5 {
            let b1 = r.u8()?;
            (1u8, 0u8, (b1 >> 2) & 1, b1 & 3, (b1 >> 3) & 0xf)
        } else {
            let b1 = r.u8()?;
            let b2 = r.u8()?;
            (b1 & 0x1f, b2 >> 7, (b2 >> 2) & 1, b2 & 3, (b2 >> 3) & 0xf)
        };
        // Only three opcode maps are defined. The rest of the field is
        // reserved, and `8F` — not `C4` — is what carries AMD's XOP maps.
        if !(1..=3).contains(&map) {
            return None;
        }
        let vop = r.u8()?;
        return vex_tail(
            &mut r,
            &generated::VEX_MAP,
            &generated::VEX_SUB,
            vex_index(map - 1, pp, l, w, vop),
            vvvv,
            seg,
            asz16,
            osize,
        );
    }

    // x87 escapes `D8`–`DF`. `mod=3` names a register-stack operation, anything
    // else addresses memory at a width the escape and digit choose together.
    if (0xd8..=0xdf).contains(&op) {
        // No x87 instruction is lockable, and this path returns before the
        // general check below.
        if lock {
            return None;
        }
        let peeked = r.peek()?;
        let (mn, ops) = if peeked >= 0xc0 {
            let modrm = r.u8()?;
            let (mn, takes_st) = x87_reg(op, modrm)?;
            let ops = if takes_st {
                [Op::St(modrm & 7), Op::None, Op::None]
            } else {
                [Op::None; 3]
            };
            (mn, ops)
        } else {
            let (digit, mem) = modrm(&mut r, Size::B4, seg, asz16)?;
            let (mn, width) = X87_MEM[(op - 0xd8) as usize][digit as usize]?;
            // Re-stamp the operand with the width this encoding addresses;
            // `modrm` cannot know it, since the escape and digit choose it.
            let mem = match mem {
                Op::Mem {
                    base,
                    index,
                    scale,
                    disp,
                    seg,
                    addr16,
                    ..
                } => Op::MemWide {
                    base,
                    index,
                    scale,
                    disp,
                    seg,
                    bytes: width,
                    addr16,
                },
                other => other,
            };
            (mn, [mem, Op::None, Op::None])
        };
        // A long enough prefix run pushes even a two-byte escape past the
        // fifteen bytes a processor will decode.
        if r.i > MAX_INSN_LEN {
            return None;
        }
        return Some(Insn {
            len: r.i,
            mn,
            ops,
            rep,
            repne,
            lock,
            osize,
            addr16: asz16,
        });
    }

    // The `0F` map is handled two ways. Encodings whose *operands* the rest of
    // exav acts on — conditional branches, `setcc`, `cmovcc`, `movzx`, the bit
    // instructions — are hand-written above, so their operand shapes are real
    // and independently tested. Everything else, which is the SIMD region and
    // the system space, comes from the generated table: it supplies the
    // mnemonic and the immediate size, and nothing else is needed to give the
    // instruction an honest length.
    let two_slot = if op == 0x0f {
        Some(two_byte(*r.b.get(r.i)?))
    } else {
        None
    };
    if op == 0x0f && matches!(two_slot, Some(X)) {
        let op2 = r.u8()?;
        // Peeked, not consumed: the digit and `mod` select the table cell, and
        // `modrm()` reads the byte properly below. An opcode that takes no
        // ModRM byte may legitimately have nothing here — its cells are
        // uniform, so any digit selects the same instruction.
        let modrm_byte = r.peek().unwrap_or(0);
        // The table has a column per prefix *combination*, because `66` together
        // with `F3` or `F2` is not the same as either alone: several encodings
        // valid under one are rejected under both.
        let pfx = match (osz16, rep, repne) {
            (false, false, false) => 0,
            (true, false, false) => 1,
            (false, true, false) => 2,
            (false, false, true) => 3,
            (true, true, false) => 4,
            (true, false, true) => 5,
            // `F2` and `F3` are one prefix class and the last wins, so this
            // combination cannot arise.
            _ => return None,
        };
        let digit = (modrm_byte >> 3) & 7;
        let mod3 = modrm_byte >= 0xc0;
        // A handful of opcodes name a different instruction for every ModRM byte
        // in the register range rather than for every digit, so that list is
        // consulted first.
        let exact = mod3.then(|| {
            generated::OF_MOD3
                .binary_search_by_key(&(pfx as u8, op2, modrm_byte), |(p, o, m, _, _)| {
                    (*p, *o, *m)
                })
                .ok()
                .map(|i| generated::OF_MOD3[i])
        });
        // 3DNow! inverts the usual layout: `0F 0F` is followed by the ModRM,
        // SIB and displacement, and only then by the byte that says which
        // instruction this is. A decoder that stops at the operands gets both
        // the identity and the length wrong.
        if op2 == 0x0f {
            let (_, rm) = modrm(&mut r, Size::B4, seg, asz16)?;
            let cell = generated::NOW3D_MAP[r.u8()? as usize];
            if cell == 0 || lock || r.i > MAX_INSN_LEN {
                return None;
            }
            return Some(Insn {
                len: r.i,
                mn: Mn::from_generated(((cell >> 2) - 1) as usize),
                ops: [rm, Op::None, Op::None],
                rep,
                repne,
                lock,
                osize,
                addr16: asz16,
            });
        }
        // `0F 38` and `0F 3A` are three-byte escapes: the byte after them is a
        // further opcode, and the ModRM comes after that. They have their own
        // tables, keyed on prefix and that third byte.
        if matches!(op2, 0x38 | 0x3a) {
            let op3 = r.u8()?;
            // The ModRM byte sits after the third opcode byte, so the digit and
            // `mod` that select the cell are not the ones read above.
            let m = r.peek().unwrap_or(0);
            let (digit, mod3) = ((m >> 3) & 7, m >= 0xc0);
            let map = if op2 == 0x38 {
                &generated::OF38_MAP
            } else {
                &generated::OF3A_MAP
            };
            let cell = map[of_index(pfx, op3, digit, mod3)];
            if cell == 0 {
                return None;
            }
            let mn = Mn::from_generated(((cell >> 2) - 1) as usize);
            let imm = match cell & 3 {
                0 => 0usize,
                1 => 1,
                2 => 2,
                _ => 4,
            };
            // The escape maps get the same operand shapes as the `0F` map: an
            // encoding whose operands exav acts on is no less real for being
            // three bytes in. `crc32` lives here.
            let shape = if op2 == 0x38 {
                generated::OF38_SHAPE[pfx * 256 + op3 as usize]
            } else {
                generated::OF3A_SHAPE[pfx * 256 + op3 as usize]
            };
            let (field, rm) = modrm(&mut r, osize, seg, asz16)?;
            let (reg_op, rm) = match (shape & SHAPE_PRESENT != 0, rm) {
                (false, Op::Reg(..)) => (Op::None, Op::None),
                // Left at the width `modrm` produced. `OF_SHAPE` carries one
                // width per OPCODE, but the real access width varies per
                // `/digit` — `0F 1C` is one byte at one digit and four at
                // another, `F3 0F 38 D8` is 48 bytes at one and 64 at another —
                // so applying the table's single value here would be wrong more
                // often than the operand-size default it replaced. Carrying it
                // per digit needs a table the size of `OF_MAP`.
                (false, mem) => (Op::None, mem),
                (true, Op::Reg(n, _)) => (
                    typed_reg(field, (shape >> 2) & 7),
                    typed_reg(n, (shape >> 5) & 7),
                ),
                (true, mem) => (
                    typed_reg(field, (shape >> 2) & 7),
                    sized_mem(mem, (shape >> 10) as u8),
                ),
            };
            let imm_op = match imm {
                0 => Op::None,
                1 => Op::Imm(r.u8()? as i64),
                2 => Op::Imm(r.u16()? as i64),
                _ => Op::Imm(r.u32()? as i32 as i64),
            };
            let ops = if shape & SHAPE_PRESENT == 0 || shape & SHAPE_RM_ONLY != 0 {
                [rm, imm_op, Op::None]
            } else if shape & SHAPE_REG_FIRST != 0 {
                [reg_op, rm, imm_op]
            } else {
                [rm, reg_op, imm_op]
            };
            if lock || r.i > MAX_INSN_LEN {
                return None;
            }
            return Some(Insn {
                len: r.i,
                mn,
                ops,
                rep,
                repne,
                lock,
                osize,
                addr16: asz16,
            });
        }
        // Where an opcode is keyed on the whole ModRM byte, a byte missing from
        // the list is not an encoding — falling back to the digit-keyed map
        // would name the group's instruction for something the CPU rejects.
        //
        // The table is sorted by `(prefix, opcode, modrm)`, so every entry for
        // one `(prefix, opcode)` is contiguous and the first of them is a
        // partition point away — this runs on every `mod=3` `0F` decode, which
        // is most of them, and a scan of the whole table would be linear work
        // for a question with a logarithmic answer.
        let keyed_on_modrm = mod3 && {
            let key = (pfx as u8, op2);
            let at = generated::OF_MOD3.partition_point(|(p, o, _, _, _)| (*p, *o) < key);
            generated::OF_MOD3
                .get(at)
                .is_some_and(|(p, o, _, _, _)| (*p, *o) == key)
        };
        // Whether the whole ModRM byte selected the instruction. For those the
        // byte IS the opcode — `0F 01 C1` is `vmcall`, which takes nothing — so
        // reporting the `r/m` field as an operand invents one.
        let mut modrm_is_opcode = false;
        let (mn, imm) = match exact.flatten() {
            Some((_, _, _, name, imm)) => {
                modrm_is_opcode = true;
                (Mn::from_generated(name as usize), imm as usize)
            }
            None if keyed_on_modrm => return None,
            None => {
                let cell = generated::OF_MAP[of_index(pfx, op2, digit, mod3)];
                if cell == 0 {
                    return None;
                }
                let imm = match cell & 3 {
                    0 => 0usize,
                    1 => 1,
                    2 => 2,
                    _ => 4,
                };
                (Mn::from_generated(((cell >> 2) - 1) as usize), imm)
            }
        };
        // `0F 20`–`23` move to and from the control and debug registers. They
        // read a ModRM byte but ignore its `mod` field — the operand is always
        // a register — so the length probe behind `OF_HAS_MODRM` could not see
        // the byte, and the table counted it as an immediate instead. Consume
        // it here as the register it is, and drop the phantom immediate.
        let cr_dr = (0x20..=0x23).contains(&op2);
        let imm = if cr_dr { 0 } else { imm };
        // The shape says which register file each side of a SIMD encoding
        // names and how wide its memory operand is — the facts an emulator
        // needs and a length does not. `0` is "not modelled", and then only the
        // `rm` operand is reported, as before.
        let shape = generated::OF_SHAPE[pfx * 256 + op2 as usize];
        let (reg_op, rm) = if cr_dr {
            (Op::None, Op::Reg(r.u8()? & 7, Size::B4))
        } else if generated::OF_HAS_MODRM[pfx * 256 + op2 as usize] {
            let (field, rm) = modrm(&mut r, osize, seg, asz16)?;
            match (shape & SHAPE_PRESENT != 0, rm) {
                // A register operand of an encoding whose shape is unmodelled
                // could name any file. Reporting it as general-purpose would be
                // a plausible-looking lie — `movq mm0, mm1` read as `eax, ecx` —
                // so it is not reported at all. Memory *is* reported: its base,
                // index and displacement are the same whatever the access
                // width, and the `lock` check needs to see it.
                (false, Op::Reg(..)) => (Op::None, Op::None),
                // Left at the width `modrm` produced. `OF_SHAPE` carries one
                // width per OPCODE, but the real access width varies per
                // `/digit` — `0F 1C` is one byte at one digit and four at
                // another, `F3 0F 38 D8` is 48 bytes at one and 64 at another —
                // so applying the table's single value here would be wrong more
                // often than the operand-size default it replaced. Carrying it
                // per digit needs a table the size of `OF_MAP`.
                (false, mem) => (Op::None, mem),
                (true, Op::Reg(n, _)) => (
                    typed_reg(field, (shape >> 2) & 7),
                    typed_reg(n, (shape >> 5) & 7),
                ),
                (true, mem) => (
                    typed_reg(field, (shape >> 2) & 7),
                    sized_mem(mem, (shape >> 10) as u8),
                ),
            }
        } else {
            (Op::None, Op::None)
        };
        let imm_op = if imm > 0 {
            let v = match imm {
                1 => r.u8()? as i64,
                2 => r.u16()? as i64,
                _ => r.u32()? as i32 as i64,
            };
            Op::Imm(v)
        } else {
            Op::None
        };
        // A shaped encoding reports both operands in encoding order; anything
        // else reports the one it has.
        let ops = if modrm_is_opcode {
            [Op::None, imm_op, Op::None]
        } else if shape & SHAPE_PRESENT == 0 || cr_dr {
            [rm, imm_op, Op::None]
        } else if shape & SHAPE_RM_ONLY != 0 {
            // The `reg` bits are a group digit, not an operand.
            [rm, imm_op, Op::None]
        } else if shape & SHAPE_REG_FIRST != 0 {
            [reg_op, rm, imm_op]
        } else {
            [rm, reg_op, imm_op]
        };
        if lock && !lockable(mn, Some(op2), &ops) {
            return None;
        }
        // `montmul` is encoded only for 32-bit addressing, so an address-size
        // prefix leaves it with no form to decode into and the processor
        // faults. Its neighbours in the same opcode group do have both forms —
        // `xsha1` and `xsha256` share `0F A6`, and the whole `0F A7` group
        // takes the prefix without complaint — so this is one encoding, not a
        // rule about the group.
        if asz16 && mn == Mn::Montmul {
            return None;
        }
        if r.i > MAX_INSN_LEN {
            return None;
        }
        return Some(Insn {
            len: r.i,
            mn,
            ops,
            rep,
            repne,
            lock,
            osize,
            addr16: asz16,
        });
    }

    let (slot, two) = match two_slot {
        Some(s) => {
            let op2 = r.u8()?;
            (s, Some(op2))
        }
        None => (one_byte(op), None),
    };

    // The transactional-memory pair hides in the `/7` slot of the `mov`-immediate
    // group, at one exact ModRM byte. `C6 F8` is `xabort imm8` and `C7 F8` is
    // `xbegin rel`; every other `/7` there is not an encoding.
    if matches!(op, 0xc6 | 0xc7) && r.peek() == Some(0xf8) {
        // Neither is a read-modify-write, so neither is lockable, and this path
        // returns before the general check.
        if lock {
            return None;
        }
        r.i += 1;
        let (mn, ops) = if op == 0xc6 {
            (Mn::Xabort, [Op::Imm(r.u8()? as i64), Op::None, Op::None])
        } else {
            let d = match osize {
                Size::B2 => r.u16()? as i16 as i64,
                _ => r.u32()? as i32 as i64,
            };
            (Mn::Xbegin, [Op::Rel(d as u64), Op::None, Op::None])
        };
        if r.i > MAX_INSN_LEN {
            return None;
        }
        let len = r.i;
        return Some(Insn {
            len,
            mn,
            // `Size::B4`, not `osize`. A `66` prefix shortens `xbegin`'s
            // displacement to sixteen bits but does not wrap the target within
            // them the way a near branch does — the fallback address stays a
            // full 32-bit one. Passing `osize` here truncates a target the
            // hardware does not.
            ops: resolve_rel(ops, ip, len, Size::B4),
            rep,
            repne,
            lock,
            osize,
            addr16: asz16,
        });
    }

    let (mut mn, form, size) = match slot {
        X => return None,
        I(m, f) => (m, f, osize),
        B(m, f) => (m, f, Size::B1),
        G(g) => {
            // The group digit is in the ModRM byte, which is peeked rather than
            // consumed: the form decoder reads it again.
            let (m, f) = g[((r.peek()? >> 3) & 7) as usize]?;
            // Within a group the immediate form varies by opcode, not by digit.
            let f = match (op, f) {
                (0x83, Rm) => RmImm8Sex,
                (0x80..=0x82, Rm) => RmImmZ,
                (0xc0 | 0xc1, Rm) => RmImm8,
                (0xd0 | 0xd1, Rm) => RmOne,
                (0xd2 | 0xd3, Rm) => RmCl,
                _ => f,
            };
            // The byte-width member of each group shares its table; the low
            // opcode bit selects the width.
            let sz = match op {
                0x80 | 0x82 | 0xc0 | 0xd0 | 0xd2 | 0xf6 | 0xfe | 0xc6 => Size::B1,
                _ => osize,
            };
            (m, f, sz)
        }
    };

    // `E3` tests CX or ECX according to the ADDRESS size, and the two forms
    // have different names.
    if asz16 && mn == Mn::Jecxz {
        mn = Mn::Jcxz;
    }

    // A `66` prefix renames the instructions whose width is implied by the
    // mnemonic rather than carried by an operand.
    if osz16 {
        mn = match mn {
            Mn::Pushad => Mn::Pusha,
            Mn::Popad => Mn::Popa,
            Mn::Pushfd => Mn::Pushf,
            Mn::Popfd => Mn::Popf,
            Mn::Cdq => Mn::Cwd,
            Mn::Cwde => Mn::Cbw,
            Mn::Movsd => Mn::Movsw,
            Mn::Cmpsd => Mn::Cmpsw,
            Mn::Stosd => Mn::Stosw,
            Mn::Lodsd => Mn::Lodsw,
            Mn::Scasd => Mn::Scasw,
            Mn::Insd => Mn::Insw,
            Mn::Outsd => Mn::Outsw,
            Mn::Iretd => Mn::Iret,
            other => other,
        };
    }

    // A few encodings are not "the same instruction with a repeat prefix" — the
    // `F3` belongs to the opcode and names something else.
    if rep {
        match (op, two) {
            (0x90, None) => mn = Mn::Pause,
            (_, Some(0xbc)) => mn = Mn::Tzcnt,
            (_, Some(0xbd)) => mn = Mn::Lzcnt,
            _ => {}
        }
    }

    // The forms that take a register from the low three opcode bits must see
    // the *effective* opcode. In the `0F` map that is the second byte: reading
    // the escape byte instead makes every `bswap` name register seven.
    let ops = decode_form(&mut r, form, size, osize, two.unwrap_or(op), seg, asz16)?;

    // `arpl` reads a 16-bit selector, but its register form names the full
    // 32-bit registers — the one encoding where the register and memory widths
    // differ, so `modrm`'s single size cannot express it.
    let ops = if mn == Mn::Arpl {
        [sized_mem(ops[0], 2), ops[1], ops[2]]
    } else {
        ops
    };

    // A segment-register move touches TWO bytes of memory whatever the operand
    // size, and `bound` reads a PAIR of limits — eight bytes for the 32-bit
    // form. `modrm` carries one width for both the register and memory shapes,
    // so like `arpl` these have to be corrected after the fact. An emulator
    // sizing its access from `Op::Mem.size` would otherwise write four bytes for
    // `mov [ecx], ds`, clobbering two it must not touch, and read four for
    // `mov ds, [ecx]`, faulting a page early at a page boundary.
    // Some instructions take an address, not a value: `lea` computes one, and
    // `bound` reads a pair of limits from memory. With `mod=3` they are not
    // instructions at all — `62` with `mod=3` is where EVEX lives — and
    // claiming them would invent an encoding.
    //
    // This runs BEFORE the width fixup below, which can turn the operand into an
    // `Op::MemWide` and so out of this test's reach.
    if matches!(mn, Mn::Lea | Mn::Bound) && !matches!(ops[1], Op::Mem { .. }) {
        return None;
    }

    let ops = match (mn, form) {
        (Mn::Mov, RmSeg) => [sized_mem(ops[0], 2), ops[1], ops[2]],
        (Mn::Mov, SegRm) => [ops[0], sized_mem(ops[1], 2), ops[2]],
        (Mn::Bound, _) => [
            ops[0],
            sized_mem(ops[1], if osize == Size::B2 { 4 } else { 8 }),
            ops[2],
        ],
        _ => ops,
    };

    // `lock` is legal only on a read-modify-write to memory, and only for a
    // fixed set of operations. Anything else after an `F0` is a malformed byte
    // sequence, not an instruction with a spare prefix.
    if lock && !lockable(mn, two, &ops) {
        return None;
    }

    if r.i > MAX_INSN_LEN {
        return None;
    }

    let len = r.i;
    Some(Insn {
        len,
        mn,
        ops: resolve_rel(ops, ip, len, osize),
        rep,
        repne,
        lock,
        osize,
        addr16: asz16,
    })
}

/// The operations `lock` may prefix, and only with a memory destination.
fn lockable(mn: Mn, two: Option<u8>, ops: &[Op; 3]) -> bool {
    if !matches!(ops[0], Op::Mem { .. }) {
        return false;
    }
    matches!(
        mn,
        Mn::Add
            | Mn::Adc
            | Mn::And
            | Mn::Btc
            | Mn::Btr
            | Mn::Bts
            | Mn::Cmpxchg
            // The eight-byte compare-and-exchange is the reason `lock` exists
            // on 32-bit: it is how a pair of registers is swapped atomically.
            | Mn::Cmpxchg8b
            | Mn::Dec
            | Mn::Inc
            | Mn::Neg
            | Mn::Not
            | Mn::Or
            | Mn::Sbb
            | Mn::Sub
            | Mn::Xor
            | Mn::Xadd
    ) || (mn == Mn::Xchg && two.is_none())
}

/// Turn the raw displacements the form decoder produced into absolute targets.
///
/// The sum is masked to the operand size, not just carried in 64 bits. Under a
/// `66` prefix a near branch wraps within 16 bits — the hardware truncates the
/// whole instruction pointer, so `66 e9 00 00` at `0x14000` goes to `0x4004`,
/// not `0x14004`. A 16-bit near jump inside a 32-bit stub is a known
/// anti-emulation move, chosen because decoders get exactly this wrong. Without
/// the `66` it still masks to 32 bits, since this decoder describes a 32-bit
/// machine and a target above `0xFFFF_FFFF` is not an address anything can hold.
fn resolve_rel(mut ops: [Op; 3], ip: u64, len: usize, osize: Size) -> [Op; 3] {
    let mask: u64 = if osize == Size::B2 {
        0xFFFF
    } else {
        0xFFFF_FFFF
    };
    for o in ops.iter_mut() {
        if let Op::Rel(d) = *o {
            *o = Op::Rel(ip.wrapping_add(len as u64).wrapping_add(d) & mask);
        }
    }
    ops
}

/// Whether an FP16 complex multiply names its destination as a source too.
///
/// `vfmulcph` and its seven relatives treat a register pair as one complex
/// number, reading both halves of each source while writing both halves of the
/// destination. Overlap them and the result is undefined, so the processor
/// refuses the encoding rather than producing one — which makes accepting it a
/// decoder that hands an emulator an instruction no hardware will run.
///
/// `vvvv` is stored inverted, and only its low three bits can name a register a
/// 32-bit mode has. `rm` counts as a source only in the register form; against
/// memory there is nothing to collide with.
fn overlaps_a_source(mn: Mn, dest: u8, vvvv: u8, rm: Op) -> bool {
    if !matches!(
        mn,
        Mn::Vfmulcph
            | Mn::Vfmulcsh
            | Mn::Vfcmulcph
            | Mn::Vfcmulcsh
            | Mn::Vfmaddcph
            | Mn::Vfmaddcsh
            | Mn::Vfcmaddcph
            | Mn::Vfcmaddcsh
    ) {
        return false;
    }
    dest == (!vvvv) & 7 || matches!(rm, Op::Reg(n, _) if n == dest)
}

/// Read the ModRM byte with its SIB and displacement.
///
/// Returns the `reg` field — which is either a register number or a group digit,
/// depending on the opcode — and the `r/m` operand it describes: a register when
/// `mod == 3`, otherwise a memory reference already resolved to base, index,
/// scale and displacement.
fn modrm(r: &mut Reader, size: Size, seg: Option<Seg>, asz16: bool) -> Option<(u8, Op)> {
    let m = r.u8()?;
    let md = m >> 6;
    let reg = (m >> 3) & 7;
    let rm = m & 7;

    if md == 3 {
        return Some((reg, Op::Reg(rm, size)));
    }

    // A `67` prefix selects the 16-bit addressing forms: a smaller table with
    // no SIB byte, seven fixed base/index pairs, and `disp16` in the slot where
    // 32-bit addressing puts `[ebp]`.
    if asz16 {
        const BX: u8 = 3;
        const BP: u8 = 5;
        const SI: u8 = 6;
        const DI: u8 = 7;
        let (base, index) = match rm {
            0 => (Some(BX), Some(SI)),
            1 => (Some(BX), Some(DI)),
            2 => (Some(BP), Some(SI)),
            3 => (Some(BP), Some(DI)),
            4 => (Some(SI), None),
            5 => (Some(DI), None),
            6 if md == 0 => (None, None),
            6 => (Some(BP), None),
            _ => (Some(BX), None),
        };
        let disp = match md {
            0 if base.is_none() => r.u16()? as i16 as i64,
            0 => 0,
            1 => r.u8()? as i8 as i64,
            _ => r.u16()? as i16 as i64,
        };
        return Some((
            reg,
            Op::Mem {
                base,
                index,
                scale: 1,
                disp,
                seg,
                size,
                addr16: true,
            },
        ));
    }

    let (mut base, mut index, mut scale) = (Some(rm), None, 1u8);
    if rm == 4 {
        let sib = r.u8()?;
        scale = 1 << (sib >> 6);
        let idx = (sib >> 3) & 7;
        // Index 4 encodes "no index": there is no scaled ESP.
        index = if idx == 4 { None } else { Some(idx) };
        let b = sib & 7;
        // Base 5 with mod=0 is a bare disp32, not `[ebp]`.
        base = if b == 5 && md == 0 { None } else { Some(b) };
    } else if rm == 5 && md == 0 {
        base = None;
    }

    let disp = match md {
        0 if base.is_none() => r.u32()? as i32 as i64,
        0 => 0,
        1 => r.u8()? as i8 as i64,
        _ => r.u32()? as i32 as i64,
    };

    Some((
        reg,
        Op::Mem {
            base,
            index,
            scale,
            disp,
            seg,
            size,
            addr16: false,
        },
    ))
}

fn imm_z(r: &mut Reader, size: Size) -> Option<i64> {
    Some(match size {
        Size::B1 => r.u8()? as i8 as i64,
        Size::B2 => r.u16()? as i16 as i64,
        Size::B4 => r.u32()? as i32 as i64,
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_form(
    r: &mut Reader,
    form: F,
    size: Size,
    osize: Size,
    op: u8,
    seg: Option<Seg>,
    asz16: bool,
) -> Option<[Op; 3]> {
    let n = Op::None;
    // A `moffs` operand is a bare absolute address whose width follows the
    // ADDRESS size, not the operand size.
    let moffs = |r: &mut Reader| -> Option<Op> {
        let disp = if asz16 {
            r.u16()? as i64
        } else {
            r.u32()? as i64
        };
        Some(Op::Mem {
            base: None,
            index: None,
            scale: 1,
            disp,
            seg,
            size,
            addr16: asz16,
        })
    };

    Some(match form {
        Nil | Str => [n, n, n],
        RmReg => {
            let (reg, rm) = modrm(r, size, seg, asz16)?;
            [rm, Op::Reg(reg, size), n]
        }
        RegRm => {
            let (reg, rm) = modrm(r, size, seg, asz16)?;
            [Op::Reg(reg, size), rm, n]
        }
        RegRmNarrow(w) => {
            let (reg, rm) = modrm(r, w, seg, asz16)?;
            [Op::Reg(reg, osize), rm, n]
        }
        Rm => {
            let (_, rm) = modrm(r, size, seg, asz16)?;
            [rm, n, n]
        }
        RmImmZ => {
            let (_, rm) = modrm(r, size, seg, asz16)?;
            [rm, Op::Imm(imm_z(r, size)?), n]
        }
        RmImm8Sex => {
            let (_, rm) = modrm(r, size, seg, asz16)?;
            [rm, Op::Imm(r.u8()? as i8 as i64), n]
        }
        RmImm8 => {
            let (_, rm) = modrm(r, size, seg, asz16)?;
            [rm, Op::Imm(r.u8()? as i64), n]
        }
        RmOne => {
            let (_, rm) = modrm(r, size, seg, asz16)?;
            [rm, Op::Imm(1), n]
        }
        RmCl => {
            let (_, rm) = modrm(r, size, seg, asz16)?;
            [rm, Op::Reg(1, Size::B1), n]
        }
        RegRmCl => {
            let (reg, rm) = modrm(r, size, seg, asz16)?;
            [rm, Op::Reg(reg, size), Op::Reg(1, Size::B1)]
        }
        RegRmImm8 => {
            let (reg, rm) = modrm(r, size, seg, asz16)?;
            [rm, Op::Reg(reg, size), Op::Imm(r.u8()? as i64)]
        }
        RegRmImmZ => {
            let (reg, rm) = modrm(r, size, seg, asz16)?;
            [Op::Reg(reg, size), rm, Op::Imm(imm_z(r, size)?)]
        }
        RegRmImm8Sex => {
            let (reg, rm) = modrm(r, size, seg, asz16)?;
            [Op::Reg(reg, size), rm, Op::Imm(r.u8()? as i8 as i64)]
        }
        OpReg => [Op::Reg(op & 7, size), n, n],
        OpRegImm => [Op::Reg(op & 7, size), Op::Imm(imm_z(r, size)?), n],
        OpRegAcc => [Op::Reg(op & 7, size), Op::Reg(0, size), n],
        AccImmZ => [Op::Reg(0, size), Op::Imm(imm_z(r, size)?), n],
        AlImm8 => [Op::Reg(0, Size::B1), Op::Imm(r.u8()? as i8 as i64), n],
        ImmZ => [Op::Imm(imm_z(r, size)?), n, n],
        Imm8Sex => [Op::Imm(r.u8()? as i8 as i64), n, n],
        Imm8 => [Op::Imm(r.u8()? as i64), n, n],
        Imm16 => [Op::Imm(r.u16()? as i64), n, n],
        Imm16Imm8 => [Op::Imm(r.u16()? as i64), Op::Imm(r.u8()? as i64), n],
        Rel8 => [Op::Rel(r.u8()? as i8 as i64 as u64), n, n],
        RelZ => {
            let d = match size {
                Size::B2 => r.u16()? as i16 as i64,
                _ => r.u32()? as i32 as i64,
            };
            [Op::Rel(d as u64), n, n]
        }
        AccMoffs => [Op::Reg(0, size), moffs(r)?, n],
        MoffsAcc => [moffs(r)?, Op::Reg(0, size), n],
        SegOp(s) => [Op::SegReg(s), n, n],
        RmSeg => {
            let (reg, rm) = modrm(r, size, seg, asz16)?;
            [rm, Op::SegReg(seg_reg(reg)?), n]
        }
        SegRm => {
            let (reg, rm) = modrm(r, size, seg, asz16)?;
            let s = seg_reg(reg)?;
            // `mov cs, x` does not exist: CS can be read but never loaded this
            // way. Storing it (`mov ax, cs`, the `8C` direction) is fine.
            if s == Seg::Cs {
                return None;
            }
            [Op::SegReg(s), rm, n]
        }
        RegFarMem => {
            let (reg, rm) = modrm(r, size, seg, asz16)?;
            // A far pointer is loaded from memory; a register source is not an
            // encoding of these instructions.
            if !matches!(rm, Op::Mem { .. }) {
                return None;
            }
            [Op::Reg(reg, size), rm, n]
        }
        RegFarMemOnly => {
            let (_, rm) = modrm(r, size, seg, asz16)?;
            if !matches!(rm, Op::Mem { .. }) {
                return None;
            }
            [rm, n, n]
        }
        FarPtrForm => {
            // `ptr16:32` stores the offset first, then the segment selector.
            let offset = if osize == Size::B2 {
                r.u16()? as u32
            } else {
                r.u32()?
            };
            [
                Op::FarPtr {
                    seg: r.u16()?,
                    offset,
                },
                n,
                n,
            ]
        }
        AccPort => [Op::Reg(0, size), Op::Imm(r.u8()? as i64), n],
        PortAcc => [Op::Imm(r.u8()? as i64), Op::Reg(0, size), n],
        // DX is register 2, and always 16 bits when it names a port.
        AccDx => [Op::Reg(0, size), Op::Reg(2, Size::B2), n],
        DxAcc => [Op::Reg(2, Size::B2), Op::Reg(0, size), n],
    })
}

/// The ModRM `reg` field as a segment register. Only `0`–`5` name one; `6` and
/// `7` are reserved and make the instruction invalid rather than naming a
/// seventh segment.
fn seg_reg(reg: u8) -> Option<Seg> {
    Some(match reg {
        0 => Seg::Es,
        1 => Seg::Cs,
        2 => Seg::Ss,
        3 => Seg::Ds,
        4 => Seg::Fs,
        5 => Seg::Gs,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(bytes: &[u8]) -> Insn {
        decode(bytes, 0x1000).expect("decodes")
    }

    /// Both `OF_MOD3` lookups are binary searches, which answer wrongly rather
    /// than slowly on an unsorted table: a missed entry decodes `0F 01 C1` as
    /// the group's instruction with an invented operand instead of `vmcall`.
    #[test]
    fn the_modrm_keyed_table_is_sorted() {
        assert!(generated::OF_MOD3
            .windows(2)
            .all(|w| (w[0].0, w[0].1, w[0].2) < (w[1].0, w[1].1, w[1].2)));
    }

    /// `Mn` compares by index, so one name must never have two.
    ///
    /// A duplicate in `OF_NAMES` would give the second copy an index no `Mn::`
    /// constant can hold, and `mn == Mn::Whatever` would then be false for an
    /// instruction that IS that mnemonic — a silently wrong answer, not a
    /// failure. The generator emits a sorted set; this is what says so.
    #[test]
    fn name_indices_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for n in generated::OF_NAMES {
            assert!(seen.insert(n), "{n} appears twice in OF_NAMES");
        }
        // A hand-written name absent from `OF_NAMES` gets its own index, and
        // those must not collide either.
        for n in HAND_NAMES {
            if !generated::OF_NAMES.contains(n) {
                assert!(seen.insert(n), "{n} appears twice in HAND_NAMES");
            }
        }
    }

    /// Interning must round-trip: the index a constant holds must name it back.
    #[test]
    fn interned_mnemonics_name_themselves() {
        for (m, name) in [
            (Mn::Mov, "Mov"),
            (Mn::Bound, "Bound"),
            (Mn::Lea, "Lea"),
            // In both tables — must resolve to the generated index, so that a
            // decode through the `0F` map compares equal to the constant.
            (Mn::Nop, "Nop"),
            (Mn::Pause, "Pause"),
            // x87, which only the hand-written map reaches.
            (Mn::Fyl2xp1, "Fyl2xp1"),
        ] {
            assert_eq!(m.name(), name);
        }
    }

    /// A near branch wraps within the operand size, not in 64 bits.
    ///
    /// Under `66` the hardware truncates the whole instruction pointer, so a
    /// jump near the top of a 64 KiB window lands back at the bottom of it. A
    /// 16-bit near jump inside a 32-bit stub is a known anti-emulation move,
    /// picked because decoders carry the sum instead of masking it and send the
    /// emulator somewhere the CPU would never go.
    #[test]
    fn a_near_branch_wraps_within_its_operand_size() {
        // 66 e9 rel16 at 0x14000: (0x14000 + 4 + 0) & 0xFFFF.
        let i = decode(&[0x66, 0xe9, 0x00, 0x00], 0x14000).expect("decodes");
        assert_eq!(
            i.ops[0],
            Op::Rel(0x4004),
            "66-prefixed jmp must wrap at 16 bits"
        );

        // Crossing the 64 KiB boundary from below.
        let i = decode(&[0x66, 0xe8, 0x00, 0x00], 0x1ffff).expect("decodes");
        assert_eq!(i.ops[0], Op::Rel(0x3));

        // Without the prefix the same encoding stays 32-bit, and a negative
        // displacement wraps there rather than going 64-bit.
        let i = decode(&[0xeb, 0x80], 0).expect("decodes");
        assert_eq!(
            i.ops[0],
            Op::Rel(0xffff_ff82),
            "32-bit branches mask to 32 bits"
        );

        // And an ordinary forward branch is untouched.
        let i = decode(&[0xeb, 0x10], 0x1000).expect("decodes");
        assert_eq!(i.ops[0], Op::Rel(0x1012));

        // `xbegin` is the exception the masking must not swallow: `66` shortens
        // its displacement to sixteen bits without wrapping the target within
        // them, so its fallback address stays a full 32-bit one.
        let i = decode(&[0x66, 0xc7, 0xf8, 0x11, 0x22], 0x40_1000).expect("decodes");
        assert_eq!(
            i.ops[0],
            Op::Rel(0x40_3216),
            "a 66-prefixed xbegin keeps a 32-bit target"
        );
    }

    #[test]
    fn common_forms() {
        let i = one(&[0x8b, 0x45, 0x08]); // mov eax, [ebp+8]
        assert_eq!((i.mn, i.len), (Mn::Mov, 3));
        assert_eq!(i.ops[0], Op::Reg(0, Size::B4));
        assert!(matches!(
            i.ops[1],
            Op::Mem {
                base: Some(5),
                disp: 8,
                ..
            }
        ));

        let i = one(&[0xe8, 0x00, 0x00, 0x00, 0x00]); // call $+5
        assert_eq!((i.mn, i.len), (Mn::Call, 5));
        assert_eq!(i.ops[0], Op::Rel(0x1005), "a branch resolves to its target");
    }

    #[test]
    fn sib_and_disp32() {
        // mov eax, [ecx+edx*4+0x10]
        let i = one(&[0x8b, 0x44, 0x91, 0x10]);
        assert!(matches!(
            i.ops[1],
            Op::Mem {
                base: Some(1),
                index: Some(2),
                scale: 4,
                disp: 0x10,
                ..
            }
        ));
        // mov eax, [0x400000] — mod=0, rm=5 is a bare disp32, not [ebp]
        let i = one(&[0x8b, 0x05, 0x00, 0x00, 0x40, 0x00]);
        assert!(matches!(
            i.ops[1],
            Op::Mem {
                base: None,
                disp: 0x400000,
                ..
            }
        ));
    }

    #[test]
    fn an_operand_size_prefix_changes_a_branch_length() {
        // `66 E9` takes an imm16, so the instruction is four bytes, not six.
        // A wrong length here desynchronises every instruction that follows.
        let i = one(&[0x66, 0xe9, 0x34, 0x12, 0x90, 0x90]);
        assert_eq!(i.len, 4);
        assert_eq!(i.mn, Mn::Jmp);
    }

    #[test]
    fn prefixes_that_rename_rather_than_repeat() {
        assert_eq!(one(&[0xf3, 0x90]).mn, Mn::Pause, "F3 90 is pause, not nop");
        assert_eq!(
            one(&[0xf3, 0xf2, 0x90]).mn,
            Mn::Nop,
            "F2 and F3 are one class and the last wins"
        );
        assert_eq!(
            one(&[0x66, 0x60]).mn,
            Mn::Pusha,
            "66 60 is pusha, not pushad"
        );
        assert_eq!(one(&[0x67, 0xe3, 0x00]).mn, Mn::Jcxz, "67 E3 tests CX");
    }

    #[test]
    fn the_shift_group_aliases_are_named_apart() {
        assert_eq!(one(&[0xc1, 0xe0, 0x02]).mn, Mn::Shl, "/4");
        assert_eq!(
            one(&[0xc1, 0xf0, 0x02]).mn,
            Mn::Sal,
            "/6 is sal, not a second shl"
        );
    }

    #[test]
    fn sixteen_bit_addressing() {
        // 67 8b 07 => mov ax..eax, [bx]
        let i = one(&[0x67, 0x8b, 0x07]);
        assert_eq!(i.len, 3);
        assert!(matches!(
            i.ops[1],
            Op::Mem {
                base: Some(3),
                index: None,
                addr16: true,
                ..
            }
        ));
        // 67 8b 06 xx xx => a bare disp16
        let i = one(&[0x67, 0x8b, 0x06, 0x34, 0x12]);
        assert_eq!(i.len, 5);
        assert!(matches!(
            i.ops[1],
            Op::Mem {
                base: None,
                disp: 0x1234,
                ..
            }
        ));
    }

    #[test]
    fn invalid_encodings_are_declined() {
        assert!(decode(&[0x8d, 0xc0], 0).is_none(), "lea needs an address");
        assert!(decode(&[0xf0, 0x90], 0).is_none(), "nop is not lockable");
        assert!(
            decode(&[0xf0, 0x01, 0x00], 0).is_some(),
            "lock add [eax], eax is"
        );
        // SSE.
        assert_eq!(
            decode(&[0x0f, 0x10, 0xc1], 0).map(|i| (i.mn.name(), i.len)),
            Some(("Movups", 3))
        );
        // A `66` in front of a VEX prefix is not a prefixed VEX instruction.
        assert!(
            decode(&[0x66, 0xc5, 0xf8, 0x57, 0xc0], 0).is_none(),
            "a legacy prefix invalidates VEX"
        );
        // `vmovups` forbids a `vvvv` operand, so only the all-ones field is an
        // encoding. `C5 F8 10 C1` has it; `C5 F0 10 C1` names register 1.
        assert_eq!(
            decode(&[0xc5, 0xf8, 0x10, 0xc1], 0).map(|i| (i.mn.name(), i.len)),
            Some(("Vmovups", 4))
        );
        assert!(
            decode(&[0xc5, 0xf0, 0x10, 0xc1], 0).is_none(),
            "vmovups takes no third source"
        );
        assert!(decode(&[], 0).is_none(), "no bytes, no instruction");
        assert!(decode(&[0x8b], 0).is_none(), "a truncated ModRM is not one");
    }

    #[test]
    fn a_run_of_prefixes_cannot_grow_without_bound() {
        let bytes = [0x66u8; 32];
        assert!(decode(&bytes, 0).is_none(), "15 bytes is the ceiling");
    }

    #[test]
    fn mnemonic_names_match_their_variants() {
        assert_eq!(Mn::Mov.name(), "Mov");
        assert_eq!(Mn::Cmovae.name(), "Cmovae");
    }
}
