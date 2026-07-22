//! A bounded x86-32 interpreter: the execution half of the unpacking emulator.
//!
//! Decoding is done by [`exav_x86`] (dependency-free, `#![forbid(unsafe_code)]`,
//! decode-only — the same decoder the bytecode `disasm_x86` API uses), so this
//! module only has to supply *semantics*: what each instruction does to the
//! eight general registers, the flags and memory. That split is deliberate. A
//! decoder is where an emulator quietly goes wrong — one mis-sized ModRM and
//! execution continues on garbage — so it is kept in a crate whose whole job is
//! to be checked, instruction by instruction, against an independent decoder.
//!
//! The interpreter is written for *packer stubs*, not for general Windows code:
//!
//! * Ring-3, protected mode, flat 32-bit segments. `fs:`/`gs:` are the only
//!   segment overrides that resolve to anything (the emulator points `fs` at a
//!   synthetic TEB, because reading `fs:[0x30]` to find the PEB is how nearly
//!   every stub locates `kernel32`).
//! * No paging, no privilege levels, no real interrupts. `int`/`hlt`/`iret`
//!   stop the run rather than being emulated: a stub that gets there has left
//!   the path we can follow, and continuing on invented state would produce a
//!   dump that looks real and is not.
//! * An instruction that decodes but is not implemented stops the run and
//!   *names itself* ([`Stop::Unsupported`]). Silently skipping it would corrupt
//!   the unpacked image in a way no output check reliably catches.
//!
//! Every stop is a value, never a panic: all arithmetic here is explicitly
//! wrapping/checked, and all memory goes through [`Mem`], which faults instead
//! of indexing out of bounds.

use exav_x86::{Insn, Mn, Op, Seg, Size};

use crate::mem::{Fault, Mem};

/// The mnemonics the dispatch tables below match on, bound as plain constants.
///
/// [`Mn`] carries its mnemonics as associated constants, and Rust cannot bring
/// associated constants into scope with `use`. Writing them out as `Mn::Add |
/// Mn::Adc | …` across a hundred and fifty arms would bury the one thing those
/// tables exist to show: which instructions this interpreter implements, at a
/// glance. So they are re-bound here, once.
///
/// Only mnemonics with a constant in `exav-x86` can appear here — that list is
/// the vocabulary a caller may pattern-match, and adding to it is deliberate.
#[allow(non_upper_case_globals)]
mod m {
    use exav_x86::Mn;

    macro_rules! bind {
        ($($v:ident),* $(,)?) => { $(pub const $v: Mn = Mn::$v;)* };
    }

    bind![
        Aaa,
        Aad,
        Aam,
        Aas,
        Adc,
        Add,
        And,
        Bsf,
        Bsr,
        Bswap,
        Bt,
        Btc,
        Btr,
        Bts,
        Call,
        Cbw,
        Cdq,
        Clc,
        Cld,
        Cli,
        Cmc,
        Cmp,
        Cmpsb,
        Cmpsd,
        Cmpsw,
        Cmpxchg,
        Cpuid,
        Crc32,
        Cwd,
        Cwde,
        Daa,
        Das,
        Dec,
        Div,
        Emms,
        Enter,
        Femms,
        Hlt,
        Idiv,
        Imul,
        In,
        Inc,
        Insb,
        Insd,
        Insw,
        Int,
        Int1,
        Int3,
        Into,
        Jcxz,
        Jecxz,
        Jmp,
        Lahf,
        Lddqu,
        Lea,
        Leave,
        Lfence,
        Lodsb,
        Lodsd,
        Lodsw,
        Loop,
        Loope,
        Loopne,
        Mfence,
        Mov,
        Movapd,
        Movaps,
        Movd,
        Movdqa,
        Movdqu,
        Movntdq,
        Movntps,
        Movntq,
        Movq,
        Movsb,
        Movsd,
        Movss,
        Movsw,
        Movsx,
        Movupd,
        Movups,
        Movzx,
        Mul,
        Neg,
        Nop,
        Not,
        Or,
        Out,
        Outsb,
        Outsd,
        Outsw,
        Paddb,
        Paddd,
        Paddq,
        Paddw,
        Pand,
        Pandn,
        Pause,
        Pcmpeqb,
        Pcmpeqd,
        Pcmpeqw,
        Pop,
        Popa,
        Popad,
        Popf,
        Popfd,
        Por,
        Prefetchnta,
        Prefetcht0,
        Prefetcht1,
        Prefetcht2,
        Prefetchw,
        Pshufd,
        Pshufhw,
        Pshuflw,
        Pshufw,
        Pslldq,
        Psrldq,
        Psubb,
        Psubd,
        Psubq,
        Psubw,
        Punpcklbw,
        Punpckldq,
        Punpcklqdq,
        Punpcklwd,
        Push,
        Pusha,
        Pushad,
        Pushf,
        Pushfd,
        Pxor,
        Rcl,
        Rcr,
        Rdtsc,
        Ret,
        Retf,
        Rol,
        Ror,
        Sahf,
        Sal,
        Sar,
        Sbb,
        Scasb,
        Scasd,
        Scasw,
        Sfence,
        Shl,
        Shld,
        Shr,
        Shrd,
        Stc,
        Std,
        Sti,
        Stosb,
        Stosd,
        Stosw,
        Sub,
        Test,
        Wait,
        Xadd,
        Xchg,
        Xlatb,
        Xor,
        // x87.
        Fabs,
        Fadd,
        Faddp,
        Fchs,
        Fdecstp,
        Fdiv,
        Fdivp,
        Fdivr,
        Fdivrp,
        Ffree,
        Ffreep,
        Fild,
        Fincstp,
        Fist,
        Fistp,
        Fld,
        Fld1,
        Fldcw,
        Fldenv,
        Fldz,
        Fmul,
        Fmulp,
        Fnclex,
        Fninit,
        Fnop,
        Fnstcw,
        Fnstenv,
        Fnstsw,
        Fsqrt,
        Fst,
        Fstp,
        Fsub,
        Fsubp,
        Fsubr,
        Fsubrp,
        Fxch,
    ];
}

/// Why the interpreter stopped. Carried as data (not a panic, not a bool) so
/// the unpacker can report *why* a stub did not run to completion — the
/// difference between "hit an instruction we don't implement" and "jumped into
/// unmapped memory" is the difference between a bug to fix and a stub that
/// defended itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// Read, write or instruction fetch on an unmapped page.
    Fault(Fault),
    /// The bytes at `eip` do not decode as an instruction.
    Invalid(u32),
    /// A decodable instruction this interpreter does not implement.
    Unsupported(u32, Mn),
    /// `int n`, `int3` or `into`.
    Interrupt(u8),
    /// An instruction ring-3 code may not execute — `in`, `out`, `cli` with
    /// IOPL below 3. Reported as its own stop because on Windows it is an
    /// exception the program can catch, and stubs use exactly that to probe for
    /// a hypervisor: `in eax, dx` on the VMware port either returns data (inside
    /// a VM) or faults (outside one), and the handler decides what the stub
    /// does next.
    Privileged(u32),
    /// `hlt`.
    Halt,
    /// `div`/`idiv` by zero, or a quotient that does not fit.
    DivideError,
}

/// The eight 32-bit general registers, in the encoding order the ModRM byte
/// uses, which is the numbering [`Op::Reg`] reports.
pub const EAX: usize = 0;
pub const ECX: usize = 1;
pub const EDX: usize = 2;
pub const EBX: usize = 3;
pub const ESP: usize = 4;
pub const EBP: usize = 5;
pub const ESI: usize = 6;
pub const EDI: usize = 7;

/// Longest x86 instruction, and therefore the fetch window.
const MAX_INSN: usize = 16;

pub struct Cpu {
    pub regs: [u32; 8],
    pub eip: u32,
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
    pub df: bool,
    /// Trap flag. Set by a stub through `popfd` to make the processor raise a
    /// single-step exception after the *next* instruction, which its own
    /// handler catches — a standard anti-debug construction, and one that spins
    /// forever on an emulator that ignores the flag.
    pub tf: bool,
    /// Linear base the `fs:` override resolves to (the synthetic TEB).
    pub fs_base: u32,
    pub gs_base: u32,
    /// Emulated time-stamp counter. Monotonic because stubs that time
    /// themselves (an anti-emulation trick) compare two reads and take the
    /// difference; a frozen counter yields zero elapsed, which some stubs treat
    /// as "being emulated".
    tsc: u64,
    /// x87 register stack, enough to carry values a stub pushes through the FPU
    /// and to support the `fnstenv` program-counter trick.
    fpu: [f64; 8],
    fpu_top: usize,
    fpu_cw: u16,
    /// Address of the last non-control x87 instruction — what `fnstenv` stores
    /// and what "GetPC" stubs read back to learn where they are executing.
    fpu_last_ip: u32,
    /// Set when an x87 computation was approximated rather than emulated. The
    /// unpacker treats a dump produced under approximation as lower confidence.
    pub fpu_approximated: bool,
    /// Direct-mapped decode cache, tagged with the memory generation.
    /// Decompression stubs are tight loops, so the same few dozen instructions
    /// are decoded millions of times and caching them removes the decode from
    /// the inner loop. Each entry carries the [`Mem::code_generation`] it was
    /// decoded under, so a write to a page that has executed — self-modifying
    /// code — invalidates every entry at once, without touching any of them.
    cache: Vec<Option<(u64, u32, Insn)>>,
    /// SSE and MMX register files. Present because packers use vector moves as
    /// a wide `memcpy`, not because they compute with them.
    xmm: [[u8; 16]; 8],
    mmx: [u64; 8],
}

/// Decode-cache size. Power of two so the index is a mask.
const CACHE_SLOTS: usize = 1 << 14;

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

// The dispatch tables match on the `m::*` constants, which are named after the
// instructions rather than shouted, so the lint that wants constants in upper
// case would fire on every arm.
#[allow(non_upper_case_globals)]
impl Cpu {
    pub fn new() -> Self {
        Self {
            regs: [0; 8],
            eip: 0,
            cf: false,
            pf: false,
            af: false,
            zf: false,
            sf: false,
            of: false,
            df: false,
            tf: false,
            fs_base: 0,
            gs_base: 0,
            tsc: 0x0001_0000,
            fpu: [0.0; 8],
            fpu_top: 0,
            fpu_cw: 0x037f,
            fpu_last_ip: 0,
            fpu_approximated: false,
            cache: vec![None; CACHE_SLOTS],
            xmm: [[0u8; 16]; 8],
            mmx: [0u64; 8],
        }
    }

    /// EFLAGS as the `pushfd`/`popfd` pair sees it. Bit 1 reads as 1 on every
    /// x86; IF is reported set because ring-3 code always runs interruptible.
    pub fn eflags(&self) -> u32 {
        let mut f = 0x0000_0202u32;
        if self.cf {
            f |= 1 << 0;
        }
        if self.pf {
            f |= 1 << 2;
        }
        if self.af {
            f |= 1 << 4;
        }
        if self.zf {
            f |= 1 << 6;
        }
        if self.sf {
            f |= 1 << 7;
        }
        if self.tf {
            f |= 1 << 8;
        }
        if self.df {
            f |= 1 << 10;
        }
        if self.of {
            f |= 1 << 11;
        }
        f
    }

    pub fn set_eflags(&mut self, f: u32) {
        self.cf = f & (1 << 0) != 0;
        self.pf = f & (1 << 2) != 0;
        self.af = f & (1 << 4) != 0;
        self.zf = f & (1 << 6) != 0;
        self.sf = f & (1 << 7) != 0;
        self.tf = f & (1 << 8) != 0;
        self.df = f & (1 << 10) != 0;
        self.of = f & (1 << 11) != 0;
    }

    pub fn push32(&mut self, mem: &mut Mem, v: u32) -> Result<(), Stop> {
        let sp = self.regs[ESP].wrapping_sub(4);
        self.regs[ESP] = sp;
        mem.write_u32(sp, v).map_err(Stop::Fault)
    }

    pub fn pop32(&mut self, mem: &mut Mem) -> Result<u32, Stop> {
        let sp = self.regs[ESP];
        let v = mem.read_u32(sp).map_err(Stop::Fault)?;
        self.regs[ESP] = sp.wrapping_add(4);
        Ok(v)
    }

    /// Push two bytes, for the operand-size-prefixed (`66`) stack forms.
    ///
    /// A 16-bit `pushf`/`pusha` moves ESP by half what the 32-bit form does.
    /// Using the wider push leaves the stack skewed for everything after it,
    /// which both corrupts an unpack and is a cheap way for a stub to tell it is
    /// being emulated.
    fn push16(&mut self, mem: &mut Mem, v: u16) -> Result<(), Stop> {
        let sp = self.regs[ESP].wrapping_sub(2);
        self.regs[ESP] = sp;
        mem.write_u16(sp, v).map_err(Stop::Fault)
    }

    fn pop16(&mut self, mem: &mut Mem) -> Result<u16, Stop> {
        let sp = self.regs[ESP];
        let v = mem.read_u16(sp).map_err(Stop::Fault)?;
        self.regs[ESP] = sp.wrapping_add(2);
        Ok(v)
    }

    // ---- register file -------------------------------------------------

    /// Read a general-purpose register at the width the operand names it.
    ///
    /// The byte registers are the encoding's own numbering: `0`–`3` are the low
    /// bytes of the first four registers, `4`–`7` the *high* bytes of those same
    /// four. Getting that wrong is silent — `ah` and `esp` share a number.
    fn reg_read(&self, num: u8, size: Size) -> u32 {
        let n = num as usize & 7;
        match size {
            Size::B4 => self.regs[n],
            Size::B2 => self.regs[n] & 0xffff,
            Size::B1 if n < 4 => self.regs[n] & 0xff,
            Size::B1 => (self.regs[n - 4] >> 8) & 0xff,
        }
    }

    fn reg_write(&mut self, num: u8, size: Size, v: u32) {
        let n = num as usize & 7;
        match size {
            Size::B4 => self.regs[n] = v,
            Size::B2 => self.regs[n] = (self.regs[n] & 0xffff_0000) | (v & 0xffff),
            Size::B1 if n < 4 => self.regs[n] = (self.regs[n] & 0xffff_ff00) | (v & 0xff),
            Size::B1 => {
                let i = n - 4;
                self.regs[i] = (self.regs[i] & 0xffff_00ff) | ((v & 0xff) << 8);
            }
        }
    }

    /// A segment register's value in the flat model: what a Windows ring-3
    /// thread sees. Returned so `push cs` / `mov ax, ds` produce something
    /// stable; nothing in the emulator interprets them.
    fn seg_value(s: Seg) -> u32 {
        match s {
            Seg::Cs => 0x1b,
            Seg::Fs => 0x3b,
            Seg::Gs => 0x00,
            _ => 0x23,
        }
    }

    // ---- operands ------------------------------------------------------

    /// The immediate an operand carries, as the decoder sized and sign-extended
    /// it. Zero for an operand that is not one, which every caller here reaches
    /// only for encodings that have one.
    fn imm(insn: &Insn, i: usize) -> u32 {
        match insn.ops[i] {
            Op::Imm(v) => v as u32,
            _ => 0,
        }
    }

    /// The absolute target of a relative branch, already resolved by the
    /// decoder against the instruction's end address.
    fn branch_target(insn: &Insn) -> Option<u32> {
        insn.ops.iter().find_map(|o| match *o {
            Op::Rel(t) => Some(t as u32),
            _ => None,
        })
    }

    /// Whether operand `i` addresses memory.
    fn is_mem(insn: &Insn, i: usize) -> bool {
        matches!(insn.ops[i], Op::Mem { .. } | Op::MemWide { .. })
    }

    /// Width in bytes of the instruction's memory operand, whatever it is.
    ///
    /// Unlike [`Cpu::op_size`] this does not clamp to four: the callers here
    /// are the ones that move more than a register's worth at a time. An x87
    /// escape and its `/digit` choose the width together — `fld m32fp`,
    /// `fld m64fp` and `fld m80fp` are one mnemonic over three widths — and a
    /// vector move takes eight or sixteen. The decoder carries it on the
    /// operand rather than leaving it to be guessed from the mnemonic.
    fn mem_width(insn: &Insn) -> u32 {
        insn.ops
            .iter()
            .find_map(|o| match *o {
                Op::MemWide { bytes, .. } => Some(u32::from(bytes)),
                Op::Mem { size, .. } => Some(size.bytes()),
                _ => None,
            })
            .unwrap_or(4)
    }

    /// The x87 stack slot operand `i` names, or `1` — `fxch` with no operand
    /// means `fxch st(1)`, and the register forms encode the slot directly.
    fn st_index(insn: &Insn, i: usize) -> usize {
        match insn.ops.get(i) {
            Some(Op::St(n)) => *n as usize & 7,
            _ => 1,
        }
    }

    /// Byte width of operand `i`.
    ///
    /// `MemWide` is the x87 and SIMD widths that are not one of the three
    /// general-purpose sizes; a general-purpose read of one takes the low four
    /// bytes, which is what every caller that reaches it wants.
    fn op_size(insn: &Insn, i: usize) -> u32 {
        match insn.ops[i] {
            Op::Reg(_, s) => s.bytes(),
            Op::Mem { size, .. } => size.bytes(),
            Op::MemWide { bytes, .. } => u32::from(bytes).min(4),
            Op::Xmm(_) => 16,
            Op::Mmx(_) | Op::St(_) => 8,
            Op::SegReg(_) => 2,
            // An immediate carries no width of its own: the decoder has already
            // sized and sign-extended it to the operand size.
            _ => insn.osize.bytes(),
        }
    }

    /// Effective address of a memory operand — the same computation the
    /// interpreter uses, exposed so a trace line can show where an access went.
    pub fn effective_address(&self, insn: &Insn) -> u32 {
        self.ea(insn)
    }

    /// Effective address of the instruction's memory operand, with the
    /// `fs:`/`gs:` bases folded in. 16-bit addressing (a `0x67` prefix) wraps at
    /// 64 KiB.
    fn ea(&self, insn: &Insn) -> u32 {
        let (base, index, scale, disp, seg, addr16) = match insn.ops.iter().find_map(|o| match *o {
            Op::Mem {
                base,
                index,
                scale,
                disp,
                seg,
                addr16,
                ..
            }
            | Op::MemWide {
                base,
                index,
                scale,
                disp,
                seg,
                addr16,
                ..
            } => Some((base, index, scale, disp, seg, addr16)),
            _ => None,
        }) {
            Some(m) => m,
            None => return 0,
        };
        let mut a = disp as u32;
        if let Some(b) = base {
            a = a.wrapping_add(self.regs[b as usize & 7]);
        }
        if let Some(x) = index {
            a = a.wrapping_add(self.regs[x as usize & 7].wrapping_mul(u32::from(scale)));
        }
        if addr16 {
            a &= 0xffff;
        }
        match seg {
            Some(Seg::Fs) => a.wrapping_add(self.fs_base),
            Some(Seg::Gs) => a.wrapping_add(self.gs_base),
            _ => a,
        }
    }

    fn read_mem(&self, mem: &mut Mem, addr: u32, size: u32) -> Result<u32, Stop> {
        match size {
            1 => mem.read_u8(addr).map(u32::from),
            2 => mem.read_u16(addr).map(u32::from),
            _ => mem.read_u32(addr),
        }
        .map_err(Stop::Fault)
    }

    fn write_mem(&self, mem: &mut Mem, addr: u32, size: u32, v: u32) -> Result<(), Stop> {
        match size {
            1 => mem.write_u8(addr, v as u8),
            2 => mem.write_u16(addr, v as u16),
            _ => mem.write_u32(addr, v),
        }
        .map_err(Stop::Fault)
    }

    fn read_op(&self, mem: &mut Mem, insn: &Insn, i: usize) -> Result<u32, Stop> {
        match insn.ops[i] {
            Op::Reg(n, s) => Ok(self.reg_read(n, s)),
            Op::SegReg(s) => Ok(Self::seg_value(s)),
            Op::Mem { .. } | Op::MemWide { .. } => {
                let a = self.ea(insn);
                self.read_mem(mem, a, Self::op_size(insn, i))
            }
            Op::Imm(v) => Ok(v as u32),
            Op::Rel(target) => Ok(target as u32),
            // A vector or x87 register read through the general-purpose path,
            // or an operand the decoder did not model. Naming it as a
            // general-purpose register would produce a plausible wrong value.
            _ => Err(Stop::Unsupported(self.eip, insn.mn)),
        }
    }

    fn write_op(&mut self, mem: &mut Mem, insn: &Insn, i: usize, v: u32) -> Result<(), Stop> {
        match insn.ops[i] {
            Op::Reg(n, s) => {
                self.reg_write(n, s, v);
                Ok(())
            }
            // A flat address space has nothing to change, so a segment write is
            // accepted and dropped.
            Op::SegReg(_) => Ok(()),
            Op::Mem { .. } | Op::MemWide { .. } => {
                let a = self.ea(insn);
                self.write_mem(mem, a, Self::op_size(insn, i), v)
            }
            // Writing to an immediate is not encodable; reaching here means the
            // dispatch above is wrong about the operand form.
            _ => Err(Stop::Unsupported(self.eip, insn.mn)),
        }
    }

    // ---- flags ---------------------------------------------------------

    fn set_szp(&mut self, res: u32, size: u32) {
        let m = mask(size);
        let r = res & m;
        self.zf = r == 0;
        self.sf = r & sign_bit(size) != 0;
        self.pf = (r as u8).count_ones().is_multiple_of(2);
    }

    fn flags_add(&mut self, a: u32, b: u32, carry_in: u32, size: u32) -> u32 {
        let m = mask(size);
        let (a, b) = (a & m, b & m);
        let full = (a as u64) + (b as u64) + carry_in as u64;
        let res = (full as u32) & m;
        self.cf = full > m as u64;
        self.af = ((a ^ b ^ res) & 0x10) != 0;
        let sb = sign_bit(size);
        self.of = ((a ^ res) & (b ^ res) & sb) != 0;
        self.set_szp(res, size);
        res
    }

    fn flags_sub(&mut self, a: u32, b: u32, borrow_in: u32, size: u32) -> u32 {
        let m = mask(size);
        let (a, b) = (a & m, b & m);
        let full = (a as u64)
            .wrapping_sub(b as u64)
            .wrapping_sub(borrow_in as u64);
        let res = (full as u32) & m;
        self.cf = (a as u64) < (b as u64) + borrow_in as u64;
        self.af = ((a ^ b ^ res) & 0x10) != 0;
        let sb = sign_bit(size);
        self.of = ((a ^ b) & (a ^ res) & sb) != 0;
        self.set_szp(res, size);
        res
    }

    fn flags_logic(&mut self, res: u32, size: u32) -> u32 {
        let r = res & mask(size);
        self.cf = false;
        self.of = false;
        self.af = false;
        self.set_szp(r, size);
        r
    }

    /// Evaluate the condition a `jcc`/`setcc`/`cmovcc` mnemonic names.
    fn cond(&self, m: Mn) -> Option<bool> {
        Some(match m {
            Mn::Jo | Mn::Seto | Mn::Cmovo => self.of,
            Mn::Jno | Mn::Setno | Mn::Cmovno => !self.of,
            Mn::Jb | Mn::Setb | Mn::Cmovb => self.cf,
            Mn::Jae | Mn::Setae | Mn::Cmovae => !self.cf,
            Mn::Je | Mn::Sete | Mn::Cmove => self.zf,
            Mn::Jne | Mn::Setne | Mn::Cmovne => !self.zf,
            Mn::Jbe | Mn::Setbe | Mn::Cmovbe => self.cf || self.zf,
            Mn::Ja | Mn::Seta | Mn::Cmova => !self.cf && !self.zf,
            Mn::Js | Mn::Sets | Mn::Cmovs => self.sf,
            Mn::Jns | Mn::Setns | Mn::Cmovns => !self.sf,
            Mn::Jp | Mn::Setp | Mn::Cmovp => self.pf,
            Mn::Jnp | Mn::Setnp | Mn::Cmovnp => !self.pf,
            Mn::Jl | Mn::Setl | Mn::Cmovl => self.sf != self.of,
            Mn::Jge | Mn::Setge | Mn::Cmovge => self.sf == self.of,
            Mn::Jle | Mn::Setle | Mn::Cmovle => self.zf || (self.sf != self.of),
            Mn::Jg | Mn::Setg | Mn::Cmovg => !self.zf && (self.sf == self.of),
            _ => return None,
        })
    }

    // ---- the step loop -------------------------------------------------

    /// Fetch, decode and execute one instruction. Returns the number of
    /// "ticks" it cost — 1 for ordinary instructions, the iteration count for a
    /// `rep`-prefixed string operation, so that a single `rep movsd` moving a
    /// megabyte is charged what it actually costs.
    pub fn step(&mut self, mem: &mut Mem) -> Result<u64, Stop> {
        // Invalidation is a *tag* comparison, not a sweep. Self-modifying code
        // is normal here — a packer that decompresses into the pages it is
        // executing from bumps the generation on nearly every write — and
        // clearing every slot each time costs more than the decoding it was
        // meant to save. A self-modifying stub turns the cache into pure
        // overhead, by orders of magnitude, unless invalidation is this cheap.
        let gen = mem.code_generation();
        let slot = (self.eip as usize >> 1) & (CACHE_SLOTS - 1);
        let insn = match &self.cache[slot] {
            Some((g, ip, insn)) if *g == gen && *ip == self.eip => insn.clone(),
            _ => {
                let mut buf = [0u8; MAX_INSN];
                let n = mem.read_code(self.eip, &mut buf);
                if n == 0 {
                    return Err(Stop::Fault(Fault {
                        addr: self.eip,
                        write: false,
                    }));
                }
                // `None` here is "not an encoding this decoder claims", which
                // for a decoder that covers all of 32-bit mode means the bytes
                // are not an instruction.
                let Some(insn) = exav_x86::decode(&buf[..n], self.eip as u64) else {
                    return Err(Stop::Invalid(self.eip));
                };
                // Both pages an instruction can straddle are marked, so a write
                // to either one invalidates the cached decode.
                mem.mark_executed(self.eip);
                mem.mark_executed(self.eip.wrapping_add(insn.len as u32 - 1));
                self.cache[slot] = Some((gen, self.eip, insn.clone()));
                insn
            }
        };
        // Sequential flow first; branches overwrite this.
        self.eip = insn.next_ip(self.eip as u64) as u32;
        self.exec(mem, &insn)
    }

    fn exec(&mut self, mem: &mut Mem, insn: &Insn) -> Result<u64, Stop> {
        use m::*;
        let ip = self.eip.wrapping_sub(insn.len as u32);
        let m = insn.mn;

        match m {
            // String primitives are matched on `Code` rather than `Mnemonic`,
            // because `movsd`/`cmpsd` name both a string move and an SSE scalar
            // double, and confusing the two would execute the wrong thing. The
            // mnemonic only selects the candidates.
            Movsb | Movsw | Movsd | Stosb | Stosw | Stosd | Lodsb | Lodsw | Lodsd | Scasb
            | Scasw | Scasd | Cmpsb | Cmpsw | Cmpsd => {
                return match self.string_op(mem, insn)? {
                    Some(ticks) => Ok(ticks),
                    // `movsd`/`cmpsd` also name SSE scalar-double forms, which
                    // the string dispatch declines by design.
                    None if self.simd(mem, insn)? => Ok(1),
                    None => Err(Stop::Unsupported(ip, m)),
                };
            }
            Nop | Pause | Wait | Fnop | Prefetchw | Prefetchnta | Prefetcht0 | Prefetcht1
            | Prefetcht2 => {}

            Mov => {
                let v = self.read_op(mem, insn, 1)?;
                let size = Self::op_size(insn, 0);
                self.write_op(mem, insn, 0, v & mask(size))?;
            }
            Movzx => {
                let src = self.read_op(mem, insn, 1)? & mask(Self::op_size(insn, 1));
                self.write_op(mem, insn, 0, src)?;
            }
            Movsx => {
                let ssize = Self::op_size(insn, 1);
                let v = sign_extend(self.read_op(mem, insn, 1)?, ssize);
                self.write_op(mem, insn, 0, v)?;
            }
            Lea => {
                let a = self.ea(insn);
                self.write_op(mem, insn, 0, a)?;
            }
            Xchg => {
                let a = self.read_op(mem, insn, 0)?;
                let b = self.read_op(mem, insn, 1)?;
                self.write_op(mem, insn, 0, b)?;
                self.write_op(mem, insn, 1, a)?;
            }
            Xadd => {
                let size = Self::op_size(insn, 0);
                let a = self.read_op(mem, insn, 0)?;
                let b = self.read_op(mem, insn, 1)?;
                let sum = self.flags_add(a, b, 0, size);
                self.write_op(mem, insn, 1, a)?;
                self.write_op(mem, insn, 0, sum)?;
            }
            Cmpxchg => {
                let size = Self::op_size(insn, 0);
                let dst = self.read_op(mem, insn, 0)?;
                let acc = self.regs[EAX] & mask(size);
                self.flags_sub(acc, dst, 0, size);
                if acc & mask(size) == dst & mask(size) {
                    let src = self.read_op(mem, insn, 1)?;
                    self.write_op(mem, insn, 0, src)?;
                } else {
                    let keep = (self.regs[EAX] & !mask(size)) | (dst & mask(size));
                    self.regs[EAX] = keep;
                }
            }
            Bswap => {
                let v = self.read_op(mem, insn, 0)?;
                self.write_op(mem, insn, 0, v.swap_bytes())?;
            }

            Push => {
                let size = Self::op_size(insn, 0);
                let v = self.read_op(mem, insn, 0)?;
                if size == 2 {
                    let sp = self.regs[ESP].wrapping_sub(2);
                    self.regs[ESP] = sp;
                    mem.write_u16(sp, v as u16).map_err(Stop::Fault)?;
                } else {
                    // `push imm8` sign-extends to the operand size, which the
                    // decoder has already done: its `Imm` is the value the
                    // encoding means, not the byte it stored.
                    self.push32(mem, v)?;
                }
            }
            Pop => {
                let size = Self::op_size(insn, 0);
                if size == 2 {
                    let sp = self.regs[ESP];
                    let v = mem.read_u16(sp).map_err(Stop::Fault)?;
                    self.regs[ESP] = sp.wrapping_add(2);
                    self.write_op(mem, insn, 0, v as u32)?;
                } else {
                    let v = self.pop32(mem)?;
                    self.write_op(mem, insn, 0, v)?;
                }
            }
            // The `d` forms move 4 bytes per register, the `66`-prefixed forms
            // 2. The decoder already tells them apart, so the interpreter has to
            // as well or ESP drifts by 16 bytes on every `pusha`.
            Pushad => {
                let sp = self.regs[ESP];
                for i in [EAX, ECX, EDX, EBX] {
                    let v = self.regs[i];
                    self.push32(mem, v)?;
                }
                self.push32(mem, sp)?; // ESP as it was before the push sequence
                for i in [EBP, ESI, EDI] {
                    let v = self.regs[i];
                    self.push32(mem, v)?;
                }
            }
            Pusha => {
                let sp = self.regs[ESP] as u16;
                for i in [EAX, ECX, EDX, EBX] {
                    let v = self.regs[i] as u16;
                    self.push16(mem, v)?;
                }
                self.push16(mem, sp)?;
                for i in [EBP, ESI, EDI] {
                    let v = self.regs[i] as u16;
                    self.push16(mem, v)?;
                }
            }
            Popad => {
                for i in [EDI, ESI, EBP] {
                    let v = self.pop32(mem)?;
                    self.regs[i] = v;
                }
                let _discarded_esp = self.pop32(mem)?;
                for i in [EBX, EDX, ECX, EAX] {
                    let v = self.pop32(mem)?;
                    self.regs[i] = v;
                }
            }
            Popa => {
                // The 16-bit form writes only the low half of each register.
                for i in [EDI, ESI, EBP] {
                    let v = self.pop16(mem)?;
                    self.regs[i] = (self.regs[i] & 0xffff_0000) | u32::from(v);
                }
                let _discarded_sp = self.pop16(mem)?;
                for i in [EBX, EDX, ECX, EAX] {
                    let v = self.pop16(mem)?;
                    self.regs[i] = (self.regs[i] & 0xffff_0000) | u32::from(v);
                }
            }
            Pushfd => {
                let f = self.eflags();
                self.push32(mem, f)?;
            }
            Pushf => {
                let f = self.eflags() as u16;
                self.push16(mem, f)?;
            }
            Popfd => {
                let f = self.pop32(mem)?;
                self.set_eflags(f);
            }
            Popf => {
                // Only the low 16 bits are restored; the rest keep their values.
                let lo = u32::from(self.pop16(mem)?);
                let f = (self.eflags() & 0xffff_0000) | lo;
                self.set_eflags(f);
            }
            Leave => {
                self.regs[ESP] = self.regs[EBP];
                let v = self.pop32(mem)?;
                self.regs[EBP] = v;
            }
            Enter => {
                let alloc = Self::imm(insn, 0) & 0xffff;
                let level = Self::imm(insn, 1) & 0x1f;
                let bp = self.regs[EBP];
                self.push32(mem, bp)?;
                let frame = self.regs[ESP];
                for _ in 0..level.saturating_sub(1) {
                    let ptr = self.regs[EBP].wrapping_sub(4);
                    self.regs[EBP] = ptr;
                    let v = mem.read_u32(ptr).map_err(Stop::Fault)?;
                    self.push32(mem, v)?;
                }
                if level > 0 {
                    self.push32(mem, frame)?;
                }
                self.regs[EBP] = frame;
                self.regs[ESP] = self.regs[ESP].wrapping_sub(alloc);
            }

            Add | Adc | Sub | Sbb | Cmp | And | Or | Xor | Test => {
                let size = Self::op_size(insn, 0);
                let a = self.read_op(mem, insn, 0)?;
                // A narrow immediate that the encoding sign-extends to the
                // operand size (`add eax, -1` as `83 C0 FF`) arrives already
                // extended: the decoder reads it at the width the form says.
                let b = self.read_op(mem, insn, 1)?;
                let res = match m {
                    Add => self.flags_add(a, b, 0, size),
                    Adc => {
                        let c = self.cf as u32;
                        self.flags_add(a, b, c, size)
                    }
                    Sub | Cmp => self.flags_sub(a, b, 0, size),
                    Sbb => {
                        let c = self.cf as u32;
                        self.flags_sub(a, b, c, size)
                    }
                    And | Test => self.flags_logic(a & b, size),
                    Or => self.flags_logic(a | b, size),
                    _ => self.flags_logic(a ^ b, size),
                };
                if !matches!(m, Cmp | Test) {
                    self.write_op(mem, insn, 0, res)?;
                }
            }
            Inc | Dec => {
                let size = Self::op_size(insn, 0);
                let a = self.read_op(mem, insn, 0)?;
                let carry = self.cf; // inc/dec leave CF alone
                let res = if m == Inc {
                    self.flags_add(a, 1, 0, size)
                } else {
                    self.flags_sub(a, 1, 0, size)
                };
                self.cf = carry;
                self.write_op(mem, insn, 0, res)?;
            }
            Neg => {
                let size = Self::op_size(insn, 0);
                let a = self.read_op(mem, insn, 0)?;
                let res = self.flags_sub(0, a, 0, size);
                self.cf = a & mask(size) != 0;
                self.write_op(mem, insn, 0, res)?;
            }
            Not => {
                let size = Self::op_size(insn, 0);
                let a = self.read_op(mem, insn, 0)?;
                self.write_op(mem, insn, 0, !a & mask(size))?;
            }
            Mul => {
                let size = Self::op_size(insn, 0);
                let a = self.regs[EAX] & mask(size);
                let b = self.read_op(mem, insn, 0)? & mask(size);
                let full = (a as u64) * (b as u64);
                self.store_wide(full, size);
                let high = full >> (size * 8);
                self.cf = high != 0;
                self.of = self.cf;
            }
            Imul => match insn.op_count() {
                1 => {
                    let size = Self::op_size(insn, 0);
                    let a = sign_extend(self.regs[EAX], size) as i32 as i64;
                    let b = sign_extend(self.read_op(mem, insn, 0)?, size) as i32 as i64;
                    let full = a.wrapping_mul(b);
                    self.store_wide(full as u64, size);
                    let truncated = sign_extend(full as u32, size) as i32 as i64;
                    self.cf = full != truncated;
                    self.of = self.cf;
                }
                n => {
                    let size = Self::op_size(insn, 0);
                    let (a, b) = if n == 2 {
                        (
                            sign_extend(self.read_op(mem, insn, 0)?, size),
                            sign_extend(self.read_op(mem, insn, 1)?, Self::op_size(insn, 1)),
                        )
                    } else {
                        (
                            sign_extend(self.read_op(mem, insn, 1)?, Self::op_size(insn, 1)),
                            sign_extend(self.read_op(mem, insn, 2)?, Self::op_size(insn, 2)),
                        )
                    };
                    let full = (a as i32 as i64).wrapping_mul(b as i32 as i64);
                    let res = full as u32 & mask(size);
                    self.cf = full != sign_extend(res, size) as i32 as i64;
                    self.of = self.cf;
                    self.set_szp(res, size);
                    self.write_op(mem, insn, 0, res)?;
                }
            },
            Div => {
                let size = Self::op_size(insn, 0);
                let d = self.read_op(mem, insn, 0)? & mask(size);
                if d == 0 {
                    return Err(Stop::DivideError);
                }
                let num = self.load_wide(size);
                let q = num / d as u64;
                if q > mask(size) as u64 {
                    return Err(Stop::DivideError);
                }
                let r = (num % d as u64) as u32;
                self.store_quot_rem(q as u32, r, size);
            }
            Idiv => {
                let size = Self::op_size(insn, 0);
                let d = sign_extend(self.read_op(mem, insn, 0)?, size) as i32 as i64;
                if d == 0 {
                    return Err(Stop::DivideError);
                }
                let num = self.load_wide_signed(size);
                let q = num.checked_div(d).ok_or(Stop::DivideError)?;
                let lim = 1i64 << (size * 8 - 1);
                if q >= lim || q < -lim {
                    return Err(Stop::DivideError);
                }
                let r = num % d;
                self.store_quot_rem(q as u32 & mask(size), r as u32 & mask(size), size);
            }

            Shl | Sal | Shr | Sar | Rol | Ror | Rcl | Rcr => {
                self.shift(mem, insn, m)?;
            }
            Shld | Shrd => {
                let size = Self::op_size(insn, 0);
                let dst = self.read_op(mem, insn, 0)?;
                let src = self.read_op(mem, insn, 1)?;
                let count = (self.read_op(mem, insn, 2)? & 0x1f) % (size * 8).max(1);
                if count != 0 {
                    let bits = size * 8;
                    let (res, last_out) = if m == Shld {
                        let r = ((dst << count) | (src >> (bits - count))) & mask(size);
                        (r, (dst >> (bits - count)) & 1)
                    } else {
                        let r = ((dst >> count) | (src << (bits - count))) & mask(size);
                        (r, (dst >> (count - 1)) & 1)
                    };
                    self.cf = last_out != 0;
                    self.set_szp(res, size);
                    self.write_op(mem, insn, 0, res)?;
                }
            }

            Bt | Bts | Btr | Btc => {
                let size = Self::op_size(insn, 0);
                let bits = size * 8;
                let offset = self.read_op(mem, insn, 1)?;
                if Self::is_mem(insn, 0) {
                    // With a memory destination the offset addresses bits
                    // beyond the operand: the byte scanned is chosen by the
                    // offset, not masked into the first word.
                    let signed = offset as i32;
                    let word = signed.div_euclid(bits as i32);
                    let bit = signed.rem_euclid(bits as i32) as u32;
                    let addr = self.ea(insn).wrapping_add((word as u32).wrapping_mul(size));
                    let v = self.read_mem(mem, addr, size)?;
                    self.cf = (v >> bit) & 1 != 0;
                    let nv = match m {
                        Bts => v | (1 << bit),
                        Btr => v & !(1 << bit),
                        Btc => v ^ (1 << bit),
                        _ => v,
                    };
                    if m != Bt {
                        self.write_mem(mem, addr, size, nv)?;
                    }
                } else {
                    let bit = offset % bits;
                    let v = self.read_op(mem, insn, 0)?;
                    self.cf = (v >> bit) & 1 != 0;
                    let nv = match m {
                        Bts => v | (1 << bit),
                        Btr => v & !(1 << bit),
                        Btc => v ^ (1 << bit),
                        _ => v,
                    };
                    if m != Bt {
                        self.write_op(mem, insn, 0, nv)?;
                    }
                }
            }
            Bsf | Bsr => {
                let size = Self::op_size(insn, 0);
                let v = self.read_op(mem, insn, 1)? & mask(size);
                self.zf = v == 0;
                if v != 0 {
                    let idx = if m == Bsf {
                        v.trailing_zeros()
                    } else {
                        31 - v.leading_zeros()
                    };
                    self.write_op(mem, insn, 0, idx)?;
                }
            }

            Cbw => {
                let v = sign_extend(self.regs[EAX] & 0xff, 1) & 0xffff;
                self.regs[EAX] = (self.regs[EAX] & 0xffff_0000) | v;
            }
            Cwde => {
                self.regs[EAX] = sign_extend(self.regs[EAX] & 0xffff, 2);
            }
            Cwd => {
                let hi = if self.regs[EAX] & 0x8000 != 0 {
                    0xffff
                } else {
                    0
                };
                self.regs[EDX] = (self.regs[EDX] & 0xffff_0000) | hi;
            }
            Cdq => {
                self.regs[EDX] = if self.regs[EAX] & 0x8000_0000 != 0 {
                    0xffff_ffff
                } else {
                    0
                };
            }
            Xlatb => {
                let addr = self.regs[EBX].wrapping_add(self.regs[EAX] & 0xff);
                let v = mem.read_u8(addr).map_err(Stop::Fault)?;
                self.regs[EAX] = (self.regs[EAX] & 0xffff_ff00) | v as u32;
            }

            Clc => self.cf = false,
            Stc => self.cf = true,
            Cmc => self.cf = !self.cf,
            Cld => self.df = false,
            Std => self.df = true,
            Cli | Sti => {}
            Sahf => {
                let ah = (self.regs[EAX] >> 8) & 0xff;
                self.cf = ah & 0x01 != 0;
                self.pf = ah & 0x04 != 0;
                self.af = ah & 0x10 != 0;
                self.zf = ah & 0x40 != 0;
                self.sf = ah & 0x80 != 0;
            }
            Lahf => {
                let mut ah = 0x02u32;
                if self.cf {
                    ah |= 0x01;
                }
                if self.pf {
                    ah |= 0x04;
                }
                if self.af {
                    ah |= 0x10;
                }
                if self.zf {
                    ah |= 0x40;
                }
                if self.sf {
                    ah |= 0x80;
                }
                self.regs[EAX] = (self.regs[EAX] & 0xffff_00ff) | (ah << 8);
            }

            // A far target is an absolute `seg:offset`, which a flat-model
            // emulator has nowhere to put; an indirect one is read normally.
            Jmp => match insn.ops[0] {
                Op::Rel(t) => self.eip = t as u32,
                Op::FarPtr { .. } => return Err(Stop::Unsupported(ip, m)),
                _ => self.eip = self.read_op(mem, insn, 0)?,
            },
            Call => match insn.ops[0] {
                Op::Rel(t) => {
                    let ret = self.eip;
                    self.push32(mem, ret)?;
                    self.eip = t as u32;
                }
                Op::FarPtr { .. } => return Err(Stop::Unsupported(ip, m)),
                _ => {
                    let target = self.read_op(mem, insn, 0)?;
                    let ret = self.eip;
                    self.push32(mem, ret)?;
                    self.eip = target;
                }
            },
            Ret => {
                let ret = self.pop32(mem)?;
                if insn.op_count() == 1 {
                    let n = Self::imm(insn, 0) & 0xffff;
                    self.regs[ESP] = self.regs[ESP].wrapping_add(n);
                }
                self.eip = ret;
            }
            Retf => {
                // A far return in a packer stub is either a segment trick we do
                // not model or a corrupted stack; either way, continuing would
                // be guessing.
                return Err(Stop::Unsupported(ip, m));
            }
            Loop | Loope | Loopne => {
                let c = self.regs[ECX].wrapping_sub(1);
                self.regs[ECX] = c;
                let take = c != 0
                    && match m {
                        Loope => self.zf,
                        Loopne => !self.zf,
                        _ => true,
                    };
                if take {
                    self.eip = Self::branch_target(insn).unwrap_or(self.eip);
                }
            }
            Jecxz => {
                if self.regs[ECX] == 0 {
                    self.eip = Self::branch_target(insn).unwrap_or(self.eip);
                }
            }
            Jcxz => {
                if self.regs[ECX] & 0xffff == 0 {
                    self.eip = Self::branch_target(insn).unwrap_or(self.eip);
                }
            }

            Int3 => return Err(Stop::Interrupt(3)),
            Int => return Err(Stop::Interrupt(Self::imm(insn, 0) as u8)),
            Int1 => return Err(Stop::Interrupt(1)),
            Into => return Err(Stop::Interrupt(4)),
            Hlt => return Err(Stop::Halt),

            // SSE4.2 `crc32`, the CRC-32C (Castagnoli) accumulator. Packers
            // use it as a cheap integrity check over what they just unpacked.
            Crc32 => {
                let size = Self::op_size(insn, 1);
                let src = self.read_op(mem, insn, 1)? & mask(size);
                let mut crc = self.read_op(mem, insn, 0)?;
                for i in 0..size {
                    crc ^= (src >> (i * 8)) & 0xff;
                    for _ in 0..8 {
                        crc = if crc & 1 != 0 {
                            (crc >> 1) ^ 0x82f6_3b78
                        } else {
                            crc >> 1
                        };
                    }
                }
                self.write_op(mem, insn, 0, crc)?;
            }
            Cpuid => {
                // A plausible Pentium-class CPU. Stubs read this to branch on
                // features; the values only have to be self-consistent.
                let leaf = self.regs[EAX];
                let (a, b, c, d) = match leaf {
                    0 => (1, 0x756e_6547, 0x6c65_746e, 0x4965_6e69), // "GenuineIntel"
                    1 => (0x0000_0f43, 0x0000_0800, 0x0000_0000, 0x0783_fbff),
                    _ => (0, 0, 0, 0),
                };
                self.regs[EAX] = a;
                self.regs[EBX] = b;
                self.regs[ECX] = c;
                self.regs[EDX] = d;
            }
            Rdtsc => {
                self.tsc = self.tsc.wrapping_add(0x1000);
                self.regs[EAX] = self.tsc as u32;
                self.regs[EDX] = (self.tsc >> 32) as u32;
            }

            // Port I/O from ring 3: a fault the program is expected to catch.
            In | Out | Insb | Insw | Insd | Outsb | Outsw | Outsd => {
                return Err(Stop::Privileged(ip))
            }

            // Packed BCD. No compiler emits these; obfuscators do, precisely
            // because tools that skip them go wrong quietly.
            Daa | Das | Aaa | Aas => {
                let al = self.regs[EAX] & 0xff;
                let (mut res, mut cf) = (al, self.cf);
                let af = self.af || (al & 0x0f) > 9;
                match m {
                    Daa | Aaa => {
                        if af {
                            res = res.wrapping_add(6);
                            if m == Aaa {
                                let ah = (self.regs[EAX] >> 8).wrapping_add(1) & 0xff;
                                self.regs[EAX] = (self.regs[EAX] & 0xffff_0000) | (ah << 8);
                                res &= 0x0f;
                            }
                        }
                        if m == Daa && (al > 0x99 || cf) {
                            res = res.wrapping_add(0x60);
                            cf = true;
                        }
                    }
                    _ => {
                        if af {
                            res = res.wrapping_sub(6);
                            if m == Aas {
                                let ah = (self.regs[EAX] >> 8).wrapping_sub(1) & 0xff;
                                self.regs[EAX] = (self.regs[EAX] & 0xffff_0000) | (ah << 8);
                                res &= 0x0f;
                            }
                        }
                        if m == Das && (al > 0x99 || cf) {
                            res = res.wrapping_sub(0x60);
                            cf = true;
                        }
                    }
                }
                self.regs[EAX] = (self.regs[EAX] & 0xffff_ff00) | (res & 0xff);
                self.cf = cf;
                self.af = af;
                self.set_szp(res & 0xff, 1);
            }
            Aam | Aad => {
                let base = if insn.op_count() > 0 {
                    Self::imm(insn, 0) & 0xff
                } else {
                    10
                };
                let al = self.regs[EAX] & 0xff;
                let ah = (self.regs[EAX] >> 8) & 0xff;
                let (new_ah, new_al) = if m == Aam {
                    if base == 0 {
                        return Err(Stop::DivideError);
                    }
                    (al / base, al % base)
                } else {
                    (0, al.wrapping_add(ah.wrapping_mul(base)) & 0xff)
                };
                self.regs[EAX] = (self.regs[EAX] & 0xffff_0000) | (new_ah << 8) | new_al;
                self.set_szp(new_al, 1);
            }

            _ => {
                if let Some(taken) = self.cond(m) {
                    // jcc / setcc / cmovcc all decode to a condition; which of
                    // the three it is follows from the operand shape.
                    return self.conditional(mem, insn, taken).map(|_| 1);
                }
                if is_x87(m) {
                    return self.x87(mem, insn).map(|_| 1);
                }
                if self.simd(mem, insn)? {
                    return Ok(1);
                }
                return Err(Stop::Unsupported(ip, m));
            }
        }
        Ok(1)
    }

    fn conditional(&mut self, mem: &mut Mem, insn: &Insn, taken: bool) -> Result<(), Stop> {
        let name = insn.mn.name();
        if name.starts_with('J') {
            if taken {
                self.eip = Self::branch_target(insn).unwrap_or(self.eip);
            }
            Ok(())
        } else if name.starts_with("Set") {
            self.write_op(mem, insn, 0, taken as u32)
        } else {
            // cmovcc: the load happens either way on hardware, but only the
            // register write is architecturally visible.
            let v = self.read_op(mem, insn, 1)?;
            if taken {
                self.write_op(mem, insn, 0, v)?;
            }
            Ok(())
        }
    }

    // ---- helpers for the wide (EDX:EAX) forms ---------------------------

    fn store_wide(&mut self, full: u64, size: u32) {
        match size {
            1 => self.regs[EAX] = (self.regs[EAX] & 0xffff_0000) | (full as u32 & 0xffff),
            2 => {
                self.regs[EAX] = (self.regs[EAX] & 0xffff_0000) | (full as u32 & 0xffff);
                self.regs[EDX] = (self.regs[EDX] & 0xffff_0000) | ((full >> 16) as u32 & 0xffff);
            }
            _ => {
                self.regs[EAX] = full as u32;
                self.regs[EDX] = (full >> 32) as u32;
            }
        }
    }

    fn load_wide(&self, size: u32) -> u64 {
        match size {
            1 => (self.regs[EAX] & 0xffff) as u64,
            2 => (((self.regs[EDX] & 0xffff) as u64) << 16) | (self.regs[EAX] & 0xffff) as u64,
            _ => ((self.regs[EDX] as u64) << 32) | self.regs[EAX] as u64,
        }
    }

    fn load_wide_signed(&self, size: u32) -> i64 {
        match size {
            1 => (self.regs[EAX] & 0xffff) as u16 as i16 as i64,
            2 => {
                let v = ((self.regs[EDX] & 0xffff) << 16) | (self.regs[EAX] & 0xffff);
                v as i32 as i64
            }
            _ => (((self.regs[EDX] as u64) << 32) | self.regs[EAX] as u64) as i64,
        }
    }

    fn store_quot_rem(&mut self, q: u32, r: u32, size: u32) {
        match size {
            1 => self.regs[EAX] = (self.regs[EAX] & 0xffff_0000) | (q & 0xff) | ((r & 0xff) << 8),
            2 => {
                self.regs[EAX] = (self.regs[EAX] & 0xffff_0000) | (q & 0xffff);
                self.regs[EDX] = (self.regs[EDX] & 0xffff_0000) | (r & 0xffff);
            }
            _ => {
                self.regs[EAX] = q;
                self.regs[EDX] = r;
            }
        }
    }

    fn shift(&mut self, mem: &mut Mem, insn: &Insn, m: Mn) -> Result<(), Stop> {
        use m::*;
        let size = Self::op_size(insn, 0);
        let bits = size * 8;
        let raw = if insn.op_count() >= 2 {
            self.read_op(mem, insn, 1)?
        } else {
            1
        };
        let count = raw & 0x1f;
        if count == 0 {
            return Ok(());
        }
        let v = self.read_op(mem, insn, 0)? & mask(size);
        let res = match m {
            Shl | Sal => {
                let r = (v << count.min(31)) & mask(size);
                self.cf = count <= bits && ((v >> (bits - count.min(bits))) & 1) != 0;
                if count == 1 {
                    self.of = ((r ^ v) & sign_bit(size)) != 0;
                }
                r
            }
            Shr => {
                let r = v >> count.min(31);
                self.cf = count <= bits && ((v >> (count - 1)) & 1) != 0;
                if count == 1 {
                    self.of = v & sign_bit(size) != 0;
                }
                r
            }
            Sar => {
                let sv = sign_extend(v, size) as i32;
                let r = (sv >> count.min(31)) as u32 & mask(size);
                self.cf = ((sv >> (count.min(31) - 1)) & 1) != 0;
                if count == 1 {
                    self.of = false;
                }
                r
            }
            Rol => {
                let c = count % bits;
                let r = if c == 0 {
                    v
                } else {
                    ((v << c) | (v >> (bits - c))) & mask(size)
                };
                self.cf = r & 1 != 0;
                if count == 1 {
                    self.of = ((r ^ (r << 1)) & sign_bit(size)) != 0;
                }
                r
            }
            Ror => {
                let c = count % bits;
                let r = if c == 0 {
                    v
                } else {
                    ((v >> c) | (v << (bits - c))) & mask(size)
                };
                self.cf = r & sign_bit(size) != 0;
                if count == 1 {
                    let top_two = r >> (bits - 2);
                    self.of = (top_two & 1) != ((top_two >> 1) & 1);
                }
                r
            }
            Rcl | Rcr => {
                // Rotate through carry: (size*8 + 1) bits wide.
                let width = bits + 1;
                let c = count % width;
                let mut acc = ((self.cf as u64) << bits) | v as u64;
                for _ in 0..c {
                    if m == Rcl {
                        let top = (acc >> bits) & 1;
                        acc = ((acc << 1) & ((1u64 << width) - 1)) | top;
                    } else {
                        let bot = acc & 1;
                        acc = (acc >> 1) | (bot << bits);
                    }
                }
                self.cf = (acc >> bits) & 1 != 0;
                (acc as u32) & mask(size)
            }
            _ => unreachable!("shift dispatch"),
        };
        if !matches!(m, Rol | Ror | Rcl | Rcr) {
            self.set_szp(res, size);
        }
        self.write_op(mem, insn, 0, res)
    }

    // ---- string primitives ---------------------------------------------

    /// Execute a `movs`/`stos`/`lods`/`scas`/`cmps`, honouring `rep`. Returns
    /// `None` when the instruction is not a string primitive, so the caller can
    /// fall through to the ordinary dispatch.
    fn string_op(&mut self, mem: &mut Mem, insn: &Insn) -> Result<Option<u64>, Stop> {
        use m::*;
        // `movsd` and `cmpsd` name both a string primitive and an SSE scalar
        // double, and executing the wrong one would move the wrong bytes. The
        // string forms take their operands implicitly, so having none is what
        // tells them apart; the SSE forms fall through to `Ok(None)` and the
        // caller tries the vector dispatch.
        if insn.op_count() != 0 {
            return Ok(None);
        }
        let (kind, size) = match insn.mn {
            Movsb => (StrOp::Movs, 1),
            Movsw => (StrOp::Movs, 2),
            Movsd => (StrOp::Movs, 4),
            Stosb => (StrOp::Stos, 1),
            Stosw => (StrOp::Stos, 2),
            Stosd => (StrOp::Stos, 4),
            Lodsb => (StrOp::Lods, 1),
            Lodsw => (StrOp::Lods, 2),
            Lodsd => (StrOp::Lods, 4),
            Scasb => (StrOp::Scas, 1),
            Scasw => (StrOp::Scas, 2),
            Scasd => (StrOp::Scas, 4),
            Cmpsb => (StrOp::Cmps, 1),
            Cmpsw => (StrOp::Cmps, 2),
            Cmpsd => (StrOp::Cmps, 4),
            _ => return Ok(None),
        };
        let step: i64 = if self.df { -(size as i64) } else { size as i64 };
        let delta = step as u32;
        let repeat = insn.rep || insn.repne;
        let mut ticks = 0u64;
        loop {
            if repeat && self.regs[ECX] == 0 {
                break;
            }
            match kind {
                StrOp::Movs => {
                    let v = self.read_mem(mem, self.regs[ESI], size)?;
                    self.write_mem(mem, self.regs[EDI], size, v)?;
                    self.regs[ESI] = self.regs[ESI].wrapping_add(delta);
                    self.regs[EDI] = self.regs[EDI].wrapping_add(delta);
                }
                StrOp::Stos => {
                    let v = self.regs[EAX] & mask(size);
                    self.write_mem(mem, self.regs[EDI], size, v)?;
                    self.regs[EDI] = self.regs[EDI].wrapping_add(delta);
                }
                StrOp::Lods => {
                    let v = self.read_mem(mem, self.regs[ESI], size)?;
                    let keep = self.regs[EAX] & !mask(size);
                    self.regs[EAX] = keep | v;
                    self.regs[ESI] = self.regs[ESI].wrapping_add(delta);
                }
                StrOp::Scas => {
                    let a = self.regs[EAX] & mask(size);
                    let b = self.read_mem(mem, self.regs[EDI], size)?;
                    self.flags_sub(a, b, 0, size);
                    self.regs[EDI] = self.regs[EDI].wrapping_add(delta);
                }
                StrOp::Cmps => {
                    let a = self.read_mem(mem, self.regs[ESI], size)?;
                    let b = self.read_mem(mem, self.regs[EDI], size)?;
                    self.flags_sub(a, b, 0, size);
                    self.regs[ESI] = self.regs[ESI].wrapping_add(delta);
                    self.regs[EDI] = self.regs[EDI].wrapping_add(delta);
                }
            }
            ticks += 1;
            if !repeat {
                break;
            }
            self.regs[ECX] = self.regs[ECX].wrapping_sub(1);
            // `repe`/`repne` also stop on the comparison result. For the
            // non-comparing primitives the F3 prefix is a plain `rep`.
            if matches!(kind, StrOp::Scas | StrOp::Cmps) {
                let stop = if insn.repne { self.zf } else { !self.zf };
                if stop {
                    break;
                }
            }
        }
        Ok(Some(ticks.max(1)))
    }

    // ---- MMX / SSE -------------------------------------------------------

    /// The SIMD subset packers actually use, which is SIMD as a *block move*:
    /// `movdqu`/`movq` shift 16 bytes at a time where a `rep movsd` would shift
    /// 4, and `pxor` is how a decryptor applies a key to a whole block. The
    /// arithmetic-heavy parts of SSE do not appear in unpacking stubs and are
    /// not implemented.
    ///
    /// Returns `false` when the instruction is not one of these, so the caller
    /// reports it unimplemented rather than executing something else.
    fn simd(&mut self, mem: &mut Mem, insn: &Insn) -> Result<bool, Stop> {
        use m::*;
        let m = insn.mn;
        /// How many bytes a register operand holds.
        fn width(op: Op) -> usize {
            match op {
                Op::Xmm(_) => 16,
                Op::Mmx(_) => 8,
                _ => 4,
            }
        }
        match m {
            Emms | Femms | Sfence | Lfence | Mfence => Ok(true),
            Movd | Movq | Movdqa | Movdqu | Movaps | Movups | Movapd | Movupd | Movntdq
            | Movntq | Movntps | Lddqu | Movss | Movsd => {
                // Width comes from the *narrower* end: `movd` between an XMM
                // register and memory moves four bytes, not sixteen. The
                // mnemonics that name their own width say so regardless.
                let n = match m {
                    Movd | Movss => 4,
                    Movq | Movsd => 8,
                    _ => match (insn.ops[0], insn.ops[1]) {
                        (a, b) if !Self::is_mem(insn, 0) && !Self::is_mem(insn, 1) => {
                            width(a).min(width(b))
                        }
                        // The memory operand's real width, not clamped to a
                        // register's: `movdqa xmm0, [esi]` moves sixteen bytes,
                        // and moving four would leave the rest of the
                        // destination stale.
                        _ => Self::mem_width(insn) as usize,
                    },
                };
                let v = self.read_simd(mem, insn, 1, n)?;
                // `movss`/`movsd` between two XMM registers MERGE: the low lane
                // is replaced and the rest of the destination is left alone.
                // Only the load-from-memory form zero-extends. `write_simd`
                // always zeroes first, which is right for every other mnemonic
                // here and wrong for this one pair — a stub using the merge form
                // to assemble a value lane by lane would have each earlier lane
                // wiped by the next write.
                let merges = matches!(m, Movss | Movsd)
                    && matches!(insn.ops[0], Op::Xmm(_))
                    && matches!(insn.ops[1], Op::Xmm(_));
                if merges {
                    if let Op::Xmm(r) = insn.ops[0] {
                        self.xmm[r as usize & 7][..n].copy_from_slice(&v[..n]);
                        return Ok(true);
                    }
                }
                self.write_simd(mem, insn, 0, &v)?;
                Ok(true)
            }
            // Lane shuffles and whole-register shifts: how SSE code moves bytes
            // around after loading them, and therefore part of the same
            // block-move idiom.
            Pshufd | Pshufw | Pshuflw | Pshufhw => {
                let n = if matches!(insn.ops[0], Op::Xmm(_)) {
                    16
                } else {
                    8
                };
                let src = self.read_simd(mem, insn, 1, n)?;
                let order = Self::imm(insn, 2) as u8;
                let mut out = [0u8; 16];
                out[..n].copy_from_slice(&src[..n]);
                match m {
                    // Four 32-bit lanes selected by two bits each.
                    Pshufd => {
                        for lane in 0..4 {
                            let pick = ((order >> (lane * 2)) & 3) as usize;
                            out[lane * 4..lane * 4 + 4]
                                .copy_from_slice(&src[pick * 4..pick * 4 + 4]);
                        }
                    }
                    // Four 16-bit lanes, over the whole MMX register or over
                    // the low/high half of an XMM one.
                    Pshufw => {
                        for lane in 0..4 {
                            let pick = ((order >> (lane * 2)) & 3) as usize;
                            out[lane * 2..lane * 2 + 2]
                                .copy_from_slice(&src[pick * 2..pick * 2 + 2]);
                        }
                    }
                    Pshuflw => {
                        for lane in 0..4 {
                            let pick = ((order >> (lane * 2)) & 3) as usize;
                            out[lane * 2..lane * 2 + 2]
                                .copy_from_slice(&src[pick * 2..pick * 2 + 2]);
                        }
                    }
                    _ => {
                        for lane in 0..4 {
                            let pick = ((order >> (lane * 2)) & 3) as usize;
                            out[8 + lane * 2..8 + lane * 2 + 2]
                                .copy_from_slice(&src[8 + pick * 2..8 + pick * 2 + 2]);
                        }
                    }
                }
                self.write_simd(mem, insn, 0, &out[..n])?;
                Ok(true)
            }
            Pslldq | Psrldq => {
                let src = self.read_simd(mem, insn, 0, 16)?;
                let by = (Self::imm(insn, 1) as usize).min(16);
                let mut out = [0u8; 16];
                if m == Pslldq {
                    out[by..].copy_from_slice(&src[..16 - by]);
                } else {
                    out[..16 - by].copy_from_slice(&src[by..]);
                }
                self.write_simd(mem, insn, 0, &out)?;
                Ok(true)
            }
            Punpcklbw | Punpcklwd | Punpckldq | Punpcklqdq => {
                let n = if matches!(insn.ops[0], Op::Xmm(_)) {
                    16
                } else {
                    8
                };
                let a = self.read_simd(mem, insn, 0, n)?;
                let b = self.read_simd(mem, insn, 1, n)?;
                let unit = match m {
                    Punpcklbw => 1,
                    Punpcklwd => 2,
                    Punpckldq => 4,
                    _ => 8,
                };
                let mut out = [0u8; 16];
                let mut w = 0;
                let mut r = 0;
                while w + 2 * unit <= n {
                    out[w..w + unit].copy_from_slice(&a[r..r + unit]);
                    out[w + unit..w + 2 * unit].copy_from_slice(&b[r..r + unit]);
                    w += 2 * unit;
                    r += unit;
                }
                self.write_simd(mem, insn, 0, &out[..n])?;
                Ok(true)
            }
            Pxor | Por | Pand | Pandn | Paddb | Paddw | Paddd | Paddq | Psubb | Psubw | Psubd
            | Psubq | Pcmpeqb | Pcmpeqw | Pcmpeqd => {
                let n = if matches!(insn.ops[0], Op::Xmm(_)) {
                    16
                } else {
                    8
                };
                let a = self.read_simd(mem, insn, 0, n)?;
                let b = self.read_simd(mem, insn, 1, n)?;
                let mut out = [0u8; 16];
                match m {
                    Pxor => lanes8(&a, &b, &mut out, n, |x, y| x ^ y),
                    Por => lanes8(&a, &b, &mut out, n, |x, y| x | y),
                    Pand => lanes8(&a, &b, &mut out, n, |x, y| x & y),
                    Pandn => lanes8(&a, &b, &mut out, n, |x, y| !x & y),
                    Paddb => lanes8(&a, &b, &mut out, n, |x, y| x.wrapping_add(y)),
                    Psubb => lanes8(&a, &b, &mut out, n, |x, y| x.wrapping_sub(y)),
                    Pcmpeqb => lanes8(&a, &b, &mut out, n, |x, y| if x == y { 0xff } else { 0 }),
                    Paddw => lanes16(&a, &b, &mut out, n, |x, y| x.wrapping_add(y)),
                    Psubw => lanes16(&a, &b, &mut out, n, |x, y| x.wrapping_sub(y)),
                    Pcmpeqw => lanes16(&a, &b, &mut out, n, |x, y| if x == y { 0xffff } else { 0 }),
                    Paddd => lanes32(&a, &b, &mut out, n, |x, y| x.wrapping_add(y)),
                    Psubd => lanes32(&a, &b, &mut out, n, |x, y| x.wrapping_sub(y)),
                    Pcmpeqd => lanes32(
                        &a,
                        &b,
                        &mut out,
                        n,
                        |x, y| if x == y { 0xffff_ffff } else { 0 },
                    ),
                    Paddq => lanes64(&a, &b, &mut out, n, |x, y| x.wrapping_add(y)),
                    _ => lanes64(&a, &b, &mut out, n, |x, y| x.wrapping_sub(y)),
                }
                self.write_simd(mem, insn, 0, &out[..n])?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Read `n` bytes of operand `i`, from a vector register, a general
    /// register or memory.
    fn read_simd(&self, mem: &mut Mem, insn: &Insn, i: usize, n: usize) -> Result<Vec<u8>, Stop> {
        let mut out = vec![0u8; n];
        match insn.ops[i] {
            Op::Xmm(r) => {
                let src = &self.xmm[r as usize & 7];
                out.copy_from_slice(&src[..n.min(16)]);
            }
            Op::Mmx(r) => {
                let b = self.mmx[r as usize & 7].to_le_bytes();
                out[..n.min(8)].copy_from_slice(&b[..n.min(8)]);
            }
            Op::Reg(r, size) => {
                let v = self.reg_read(r, size).to_le_bytes();
                out[..n.min(4)].copy_from_slice(&v[..n.min(4)]);
            }
            Op::Mem { .. } | Op::MemWide { .. } => {
                let a = self.ea(insn);
                mem.read_into(a, &mut out).map_err(Stop::Fault)?;
            }
            Op::Imm(v) => {
                let b = v.to_le_bytes();
                out[..n.min(8)].copy_from_slice(&b[..n.min(8)]);
            }
            _ => return Err(Stop::Unsupported(self.eip, insn.mn)),
        }
        Ok(out)
    }

    fn write_simd(&mut self, mem: &mut Mem, insn: &Insn, i: usize, v: &[u8]) -> Result<(), Stop> {
        match insn.ops[i] {
            Op::Xmm(r) => {
                // A write narrower than the register zeroes the rest, which is
                // what `movd xmm0, eax` does.
                let dst = &mut self.xmm[r as usize & 7];
                *dst = [0u8; 16];
                dst[..v.len().min(16)].copy_from_slice(&v[..v.len().min(16)]);
                Ok(())
            }
            Op::Mmx(r) => {
                let mut b = [0u8; 8];
                b[..v.len().min(8)].copy_from_slice(&v[..v.len().min(8)]);
                self.mmx[r as usize & 7] = u64::from_le_bytes(b);
                Ok(())
            }
            Op::Reg(r, size) => {
                let mut b = [0u8; 4];
                b[..v.len().min(4)].copy_from_slice(&v[..v.len().min(4)]);
                self.reg_write(r, size, u32::from_le_bytes(b));
                Ok(())
            }
            Op::Mem { .. } | Op::MemWide { .. } => {
                let a = self.ea(insn);
                mem.write_bytes(a, v).map_err(Stop::Fault)
            }
            _ => Err(Stop::Unsupported(self.eip, insn.mn)),
        }
    }

    // ---- x87 ------------------------------------------------------------

    /// The x87 subset packer stubs actually use. Two things matter here: stubs
    /// move 64-bit values through the FPU stack as a cheap wide load/store, and
    /// they read back the FPU instruction pointer via `fnstenv` to learn their
    /// own address ("GetPC"). Arithmetic is emulated in `f64`, which is exact
    /// for the integer-valued operands these uses involve; anything outside the
    /// subset sets `fpu_approximated`, which the run reports so a caller can
    /// weigh a dump that rests on arithmetic this emulator did not perform.
    fn x87(&mut self, mem: &mut Mem, insn: &Insn) -> Result<(), Stop> {
        use m::*;
        let m = insn.mn;
        // The stored FPU IP is the address of the last *arithmetic* x87
        // instruction; the control ones (`fnstenv`, `fldcw`, ...) do not update
        // it, which is precisely what the GetPC trick relies on.
        if !matches!(m, Fnstenv | Fldenv | Fnstcw | Fldcw | Fnstsw) {
            self.fpu_last_ip = self.eip.wrapping_sub(insn.len as u32);
        }
        match m {
            Fninit => {
                self.fpu = [0.0; 8];
                self.fpu_top = 0;
                self.fpu_cw = 0x037f;
            }
            Fnclex => {}
            Fldz => self.fpu_push(0.0),
            Fld1 => self.fpu_push(1.0),
            Fld => {
                let v = match insn.ops[0] {
                    Op::St(_) => self.fpu_get(Self::st_index(insn, 0)),
                    _ => {
                        let a = self.ea(insn);
                        self.read_float(mem, a, Self::mem_width(insn))?
                    }
                };
                self.fpu_push(v);
            }
            Fild => {
                let a = self.ea(insn);
                let size = Self::mem_width(insn);
                let v = match size {
                    2 => mem.read_u16(a).map_err(Stop::Fault)? as i16 as f64,
                    4 => mem.read_u32(a).map_err(Stop::Fault)? as i32 as f64,
                    _ => {
                        let lo = mem.read_u32(a).map_err(Stop::Fault)? as u64;
                        let hi = mem.read_u32(a.wrapping_add(4)).map_err(Stop::Fault)? as u64;
                        (((hi << 32) | lo) as i64) as f64
                    }
                };
                self.fpu_push(v);
            }
            Fst | Fstp => {
                let v = self.fpu_get(0);
                match insn.ops[0] {
                    Op::St(_) => {
                        let n = Self::st_index(insn, 0);
                        self.fpu_set(n, v);
                    }
                    _ => {
                        let a = self.ea(insn);
                        self.write_float(mem, a, Self::mem_width(insn), v)?;
                    }
                }
                if m == Fstp {
                    self.fpu_pop();
                }
            }
            Fist | Fistp => {
                let v = self.fpu_get(0);
                let a = self.ea(insn);
                let size = Self::mem_width(insn);
                let i = v as i64;
                match size {
                    2 => mem.write_u16(a, i as u16).map_err(Stop::Fault)?,
                    4 => mem.write_u32(a, i as u32).map_err(Stop::Fault)?,
                    _ => {
                        mem.write_u32(a, i as u32).map_err(Stop::Fault)?;
                        mem.write_u32(a.wrapping_add(4), (i >> 32) as u32)
                            .map_err(Stop::Fault)?;
                    }
                }
                if m == Fistp {
                    self.fpu_pop();
                }
            }
            Fxch => {
                let n = if insn.op_count() > 0 {
                    Self::st_index(insn, 0)
                } else {
                    1
                };
                let a = self.fpu_get(0);
                let b = self.fpu_get(n);
                self.fpu_set(0, b);
                self.fpu_set(n, a);
            }
            Fincstp => self.fpu_top = (self.fpu_top + 1) % 8,
            Fdecstp => self.fpu_top = (self.fpu_top + 7) % 8,
            Ffree | Ffreep => {
                if m == Ffreep {
                    self.fpu_pop();
                }
            }
            Fnstenv => {
                // 28-byte protected-mode environment. Only the FPU instruction
                // pointer at offset 12 is meaningful to a stub.
                let a = self.ea(insn);
                let mut env = [0u8; 28];
                env[0..2].copy_from_slice(&self.fpu_cw.to_le_bytes());
                env[4..6].copy_from_slice(&0u16.to_le_bytes()); // status word
                env[8..10].copy_from_slice(&0xffffu16.to_le_bytes()); // tag word
                env[12..16].copy_from_slice(&self.fpu_last_ip.to_le_bytes());
                mem.write_bytes(a, &env).map_err(Stop::Fault)?;
            }
            Fldenv => {
                let a = self.ea(insn);
                self.fpu_cw = mem.read_u16(a).map_err(Stop::Fault)?;
            }
            Fnstcw => {
                let a = self.ea(insn);
                mem.write_u16(a, self.fpu_cw).map_err(Stop::Fault)?;
            }
            Fldcw => {
                let a = self.ea(insn);
                self.fpu_cw = mem.read_u16(a).map_err(Stop::Fault)?;
            }
            Fnstsw => {
                // Status word: C0..C3 report the last comparison. Only the
                // "equal"/"less" bits are modelled.
                let sw = 0u16;
                match insn.ops[0] {
                    Op::St(_) => self.regs[EAX] = (self.regs[EAX] & 0xffff_0000) | sw as u32,
                    _ => {
                        let a = self.ea(insn);
                        mem.write_u16(a, sw).map_err(Stop::Fault)?;
                    }
                }
            }
            Fadd | Fsub | Fsubr | Fmul | Fdiv | Fdivr | Faddp | Fsubp | Fsubrp | Fmulp | Fdivp
            | Fdivrp => {
                let (dst_idx, rhs) = if insn.op_count() == 0 {
                    (1, self.fpu_get(0))
                } else if insn.op_count() == 1 {
                    match insn.ops[0] {
                        Op::St(_) => (0, self.fpu_get(Self::st_index(insn, 0))),
                        _ => {
                            let a = self.ea(insn);
                            let size = Self::mem_width(insn);
                            (0, self.read_float(mem, a, size)?)
                        }
                    }
                } else {
                    (
                        Self::st_index(insn, 0),
                        self.fpu_get(Self::st_index(insn, 1)),
                    )
                };
                let lhs = self.fpu_get(dst_idx);
                let r = match m {
                    Fadd | Faddp => lhs + rhs,
                    Fsub | Fsubp => lhs - rhs,
                    Fsubr | Fsubrp => rhs - lhs,
                    Fmul | Fmulp => lhs * rhs,
                    Fdiv | Fdivp => lhs / rhs,
                    _ => rhs / lhs,
                };
                self.fpu_set(dst_idx, r);
                if matches!(m, Faddp | Fsubp | Fsubrp | Fmulp | Fdivp | Fdivrp) {
                    self.fpu_pop();
                }
            }
            Fchs => {
                let v = -self.fpu_get(0);
                self.fpu_set(0, v);
            }
            Fabs => {
                let v = self.fpu_get(0).abs();
                self.fpu_set(0, v);
            }
            Fsqrt => {
                let v = self.fpu_get(0).sqrt();
                self.fpu_set(0, v);
            }
            _ => {
                // Comparisons, transcendentals and the rest are skipped, and the
                // run is marked approximated. The mark reaches the caller in
                // `Report::fpu_approximated`: a stub whose result depended on
                // one of these took a path the emulator did not, so anything
                // built afterwards is suspect even when it looks like a payload.
                self.fpu_approximated = true;
            }
        }
        Ok(())
    }

    fn fpu_push(&mut self, v: f64) {
        self.fpu_top = (self.fpu_top + 7) % 8;
        self.fpu[self.fpu_top] = v;
    }
    fn fpu_pop(&mut self) {
        self.fpu_top = (self.fpu_top + 1) % 8;
    }
    fn fpu_get(&self, i: usize) -> f64 {
        self.fpu[(self.fpu_top + i) % 8]
    }
    fn fpu_set(&mut self, i: usize, v: f64) {
        let idx = (self.fpu_top + i) % 8;
        self.fpu[idx] = v;
    }

    fn read_float(&self, mem: &mut Mem, addr: u32, size: u32) -> Result<f64, Stop> {
        match size {
            4 => Ok(f32::from_bits(mem.read_u32(addr).map_err(Stop::Fault)?) as f64),
            8 => {
                let lo = mem.read_u32(addr).map_err(Stop::Fault)? as u64;
                let hi = mem.read_u32(addr.wrapping_add(4)).map_err(Stop::Fault)? as u64;
                Ok(f64::from_bits((hi << 32) | lo))
            }
            _ => {
                // 80-bit extended: read the 64-bit significand and the exponent
                // and rebuild an f64. Packers use `fld tbyte` to move data, and
                // the values involved are small integers where this is exact.
                let lo = mem.read_u32(addr).map_err(Stop::Fault)? as u64;
                let hi = mem.read_u32(addr.wrapping_add(4)).map_err(Stop::Fault)? as u64;
                let se = mem.read_u16(addr.wrapping_add(8)).map_err(Stop::Fault)?;
                let signif = (hi << 32) | lo;
                let sign = if se & 0x8000 != 0 { -1.0 } else { 1.0 };
                let exp = (se & 0x7fff) as i32 - 16383;
                if signif == 0 {
                    return Ok(0.0 * sign);
                }
                Ok(sign * (signif as f64) * (2f64).powi(exp - 63))
            }
        }
    }

    fn write_float(&self, mem: &mut Mem, addr: u32, size: u32, v: f64) -> Result<(), Stop> {
        match size {
            4 => mem
                .write_u32(addr, (v as f32).to_bits())
                .map_err(Stop::Fault),
            8 => mem
                .write_bytes(addr, &v.to_bits().to_le_bytes())
                .map_err(Stop::Fault),
            _ => {
                // 80-bit store, rebuilt from the f64 the emulator keeps.
                let (signif, exp, sign) = extended_parts(v);
                let mut b = [0u8; 10];
                b[..8].copy_from_slice(&signif.to_le_bytes());
                let se = ((exp + 16383) as u16 & 0x7fff) | if sign { 0x8000 } else { 0 };
                b[8..10].copy_from_slice(&se.to_le_bytes());
                mem.write_bytes(addr, &b).map_err(Stop::Fault)
            }
        }
    }
}

/// Split an `f64` into the (significand, exponent, sign) an 80-bit extended
/// store needs.
fn extended_parts(v: f64) -> (u64, i32, bool) {
    if v == 0.0 {
        return (0, -16383, v.is_sign_negative());
    }
    let sign = v < 0.0;
    let a = v.abs();
    let exp = a.log2().floor() as i32;
    let signif = (a / (2f64).powi(exp) * (2f64).powi(63)) as u64;
    (signif, exp, sign)
}

enum StrOp {
    Movs,
    Stos,
    Lods,
    Scas,
    Cmps,
}

#[inline]
fn mask(size: u32) -> u32 {
    match size {
        1 => 0xff,
        2 => 0xffff,
        _ => 0xffff_ffff,
    }
}

#[inline]
fn sign_bit(size: u32) -> u32 {
    match size {
        1 => 0x80,
        2 => 0x8000,
        _ => 0x8000_0000,
    }
}

#[inline]
fn sign_extend(v: u32, size: u32) -> u32 {
    match size {
        1 => v as u8 as i8 as i32 as u32,
        2 => v as u16 as i16 as i32 as u32,
        _ => v,
    }
}

/// Apply `f` lane-wise over `n` bytes.
fn lanes8(a: &[u8], b: &[u8], out: &mut [u8; 16], n: usize, f: impl Fn(u8, u8) -> u8) {
    for i in 0..n {
        out[i] = f(a[i], b[i]);
    }
}

fn lanes16(a: &[u8], b: &[u8], out: &mut [u8; 16], n: usize, f: impl Fn(u16, u16) -> u16) {
    for i in (0..n).step_by(2) {
        let x = u16::from_le_bytes([a[i], a[i + 1]]);
        let y = u16::from_le_bytes([b[i], b[i + 1]]);
        out[i..i + 2].copy_from_slice(&f(x, y).to_le_bytes());
    }
}

fn lanes32(a: &[u8], b: &[u8], out: &mut [u8; 16], n: usize, f: impl Fn(u32, u32) -> u32) {
    for i in (0..n).step_by(4) {
        let x = u32::from_le_bytes([a[i], a[i + 1], a[i + 2], a[i + 3]]);
        let y = u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        out[i..i + 4].copy_from_slice(&f(x, y).to_le_bytes());
    }
}

fn lanes64(a: &[u8], b: &[u8], out: &mut [u8; 16], n: usize, f: impl Fn(u64, u64) -> u64) {
    for i in (0..n).step_by(8) {
        let x = u64::from_le_bytes(a[i..i + 8].try_into().expect("8 bytes"));
        let y = u64::from_le_bytes(b[i..i + 8].try_into().expect("8 bytes"));
        out[i..i + 8].copy_from_slice(&f(x, y).to_le_bytes());
    }
}

/// Whether a mnemonic belongs to the x87 unit. Used to route to the FPU
/// subset instead of failing the run outright.
#[allow(non_upper_case_globals)]
fn is_x87(m: Mn) -> bool {
    // `name()` is a `&'static str`, so this classifies without allocating. This
    // sits on `exec`'s fallthrough, which an x87-heavy decode loop reaches once
    // per instruction.
    m.name().starts_with('F')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble nothing — the tests carry hand-written machine code, because
    /// the point is to pin the *semantics* of specific encodings.
    fn run(code: &[u8], setup: impl FnOnce(&mut Cpu)) -> (Cpu, Mem) {
        let mut mem = Mem::new(64);
        mem.map(0x1000, 0x1000).unwrap();
        mem.map(0x8000, 0x2000).unwrap(); // stack
        mem.write_bytes(0x1000, code).unwrap();
        let mut cpu = Cpu::new();
        cpu.eip = 0x1000;
        cpu.regs[ESP] = 0x9000;
        setup(&mut cpu);
        let end = 0x1000 + code.len() as u32;
        for _ in 0..10_000 {
            if cpu.eip >= end || cpu.eip < 0x1000 {
                break;
            }
            match cpu.step(&mut mem) {
                Ok(_) => {}
                Err(e) => panic!("stopped: {e:?} at {:#x}", cpu.eip),
            }
        }
        (cpu, mem)
    }

    #[test]
    fn mov_add_sub_and_flags() {
        // b8 05 00 00 00   mov eax, 5
        // 83 c0 fb         add eax, -5
        let (cpu, _) = run(&[0xb8, 0x05, 0, 0, 0, 0x83, 0xc0, 0xfb], |_| {});
        assert_eq!(cpu.regs[EAX], 0);
        assert!(cpu.zf, "5 + (-5) sets ZF");
        assert!(cpu.cf, "the addition carried out of 32 bits");
    }

    #[test]
    fn sub_borrow_and_sign() {
        // b8 01 00 00 00   mov eax, 1
        // 2d 02 00 00 00   sub eax, 2
        let (cpu, _) = run(&[0xb8, 1, 0, 0, 0, 0x2d, 2, 0, 0, 0], |_| {});
        assert_eq!(cpu.regs[EAX], 0xffff_ffff);
        assert!(cpu.cf && cpu.sf && !cpu.zf && !cpu.of);
    }

    #[test]
    fn byte_registers_alias_the_low_bits() {
        // b8 78 56 34 12   mov eax, 0x12345678
        // b4 ff            mov ah, 0xff
        // fe c0            inc al
        let (cpu, _) = run(
            &[0xb8, 0x78, 0x56, 0x34, 0x12, 0xb4, 0xff, 0xfe, 0xc0],
            |_| {},
        );
        assert_eq!(cpu.regs[EAX], 0x1234_ff79);
    }

    #[test]
    fn push_pop_and_pushad_roundtrip() {
        // 60               pushad
        // b8 ff ff ff ff   mov eax, -1
        // 61               popad
        let (cpu, _) = run(&[0x60, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x61], |c| {
            c.regs[EAX] = 0x1111;
        });
        assert_eq!(cpu.regs[EAX], 0x1111, "popad restores what pushad saved");
        assert_eq!(cpu.regs[ESP], 0x9000, "and leaves the stack balanced");
    }

    #[test]
    fn rep_movsb_copies_and_is_charged_per_byte() {
        let mut mem = Mem::new(64);
        mem.map(0x1000, 0x3000).unwrap();
        mem.write_bytes(0x2000, b"unpack me").unwrap();
        mem.write_bytes(0x1000, &[0xf3, 0xa4]).unwrap(); // rep movsb
        let mut cpu = Cpu::new();
        cpu.eip = 0x1000;
        cpu.regs[ESI] = 0x2000;
        cpu.regs[EDI] = 0x3000;
        cpu.regs[ECX] = 9;
        let ticks = cpu.step(&mut mem).unwrap();
        assert_eq!(ticks, 9, "a rep is charged its iteration count");
        assert_eq!(&mem.snapshot(0x3000, 9), b"unpack me");
        assert_eq!(cpu.regs[ECX], 0);
    }

    #[test]
    fn rep_movsb_downward_honours_the_direction_flag() {
        let mut mem = Mem::new(64);
        mem.map(0x1000, 0x3000).unwrap();
        mem.write_bytes(0x2000, b"abcd").unwrap();
        mem.write_bytes(0x1000, &[0xf3, 0xa4]).unwrap();
        let mut cpu = Cpu::new();
        cpu.eip = 0x1000;
        cpu.df = true;
        cpu.regs[ESI] = 0x2003;
        cpu.regs[EDI] = 0x3003;
        cpu.regs[ECX] = 4;
        cpu.step(&mut mem).unwrap();
        assert_eq!(&mem.snapshot(0x3000, 4), b"abcd");
    }

    #[test]
    fn call_ret_uses_the_stack() {
        // e8 02 00 00 00   call +2      -> the inc below
        // eb 7f            jmp far past the end (stops the harness)
        // 40               inc eax
        // c3               ret          -> back to the jmp
        let (cpu, _) = run(&[0xe8, 0x02, 0, 0, 0, 0xeb, 0x7f, 0x40, 0xc3], |_| {});
        assert_eq!(cpu.regs[EAX], 1, "the called code ran");
        assert_eq!(cpu.regs[ESP], 0x9000, "the ret popped the return address");
    }

    #[test]
    fn conditional_jump_and_setcc() {
        // 31 c0            xor eax, eax
        // 74 02            je +2
        // b0 ff            mov al, 0xff   (skipped)
        // 0f 94 c3         sete bl
        let (cpu, _) = run(
            &[0x31, 0xc0, 0x74, 0x02, 0xb0, 0xff, 0x0f, 0x94, 0xc3],
            |_| {},
        );
        assert_eq!(cpu.regs[EAX], 0, "the taken branch skipped the mov");
        assert_eq!(cpu.regs[EBX] & 0xff, 1, "sete recorded ZF");
    }

    #[test]
    fn shifts_and_rotates() {
        // b8 01 00 00 80   mov eax, 0x80000001
        // d1 c0            rol eax, 1
        let (cpu, _) = run(&[0xb8, 0x01, 0x00, 0x00, 0x80, 0xd1, 0xc0], |_| {});
        assert_eq!(cpu.regs[EAX], 3);
        assert!(cpu.cf);
    }

    #[test]
    fn mul_and_div_roundtrip() {
        // b8 00 00 10 00   mov eax, 0x100000
        // bb 07 00 00 00   mov ebx, 7
        // f7 e3            mul ebx
        // f7 f3            div ebx
        let (cpu, _) = run(
            &[
                0xb8, 0x00, 0x00, 0x10, 0x00, 0xbb, 0x07, 0, 0, 0, 0xf7, 0xe3, 0xf7, 0xf3,
            ],
            |_| {},
        );
        assert_eq!(cpu.regs[EAX], 0x100000);
        assert_eq!(cpu.regs[EDX], 0, "no remainder");
    }

    #[test]
    fn division_by_zero_stops_the_run() {
        let mut mem = Mem::new(16);
        mem.map(0x1000, 0x1000).unwrap();
        mem.write_bytes(0x1000, &[0xf7, 0xf3]).unwrap(); // div ebx
        let mut cpu = Cpu::new();
        cpu.eip = 0x1000;
        cpu.regs[EAX] = 1;
        cpu.regs[EBX] = 0;
        assert_eq!(cpu.step(&mut mem), Err(Stop::DivideError));
    }

    #[test]
    fn unmapped_fetch_faults_rather_than_panicking() {
        let mut mem = Mem::new(16);
        let mut cpu = Cpu::new();
        cpu.eip = 0x4000;
        assert!(matches!(cpu.step(&mut mem), Err(Stop::Fault(_))));
    }

    #[test]
    fn an_unimplemented_instruction_names_itself() {
        let mut mem = Mem::new(16);
        mem.map(0x1000, 0x1000).unwrap();
        // 0f 51 c0 = sqrtps xmm0, xmm0 — decodes cleanly, and floating-point
        // SIMD arithmetic is outside the subset the interpreter implements.
        mem.write_bytes(0x1000, &[0x0f, 0x51, 0xc0]).unwrap();
        let mut cpu = Cpu::new();
        cpu.eip = 0x1000;
        match cpu.step(&mut mem) {
            Err(Stop::Unsupported(ip, m)) => {
                assert_eq!(ip, 0x1000);
                assert_eq!(m.name(), "Sqrtps");
            }
            other => panic!("expected an Unsupported stop, got {other:?}"),
        }
    }

    #[test]
    fn fnstenv_reports_the_last_fpu_instruction_address() {
        // The GetPC idiom: fldz ; fnstenv [esp-0xc] ; pop eax  leaves the
        // address of the fldz in eax.
        // d9 ee                fldz
        // d9 74 24 f4          fnstenv [esp-0xc]
        // 58                   pop eax
        let (cpu, _) = run(&[0xd9, 0xee, 0xd9, 0x74, 0x24, 0xf4, 0x58], |_| {});
        assert_eq!(cpu.regs[EAX], 0x1000, "eax holds the address of the fldz");
    }

    #[test]
    fn fs_segment_reads_resolve_to_the_teb_base() {
        let mut mem = Mem::new(64);
        mem.map(0x1000, 0x1000).unwrap();
        mem.map(0x7000, 0x1000).unwrap();
        mem.write_u32(0x7030, 0xcafe_babe).unwrap();
        // 64 a1 30 00 00 00    mov eax, fs:[0x30]
        mem.write_bytes(0x1000, &[0x64, 0xa1, 0x30, 0, 0, 0])
            .unwrap();
        let mut cpu = Cpu::new();
        cpu.eip = 0x1000;
        cpu.fs_base = 0x7000;
        cpu.step(&mut mem).unwrap();
        assert_eq!(cpu.regs[EAX], 0xcafe_babe);
    }

    #[test]
    fn loop_counts_down_in_ecx() {
        // b9 05 00 00 00   mov ecx, 5
        // 40               inc eax
        // e2 fd            loop -3
        let (cpu, _) = run(&[0xb9, 0x05, 0, 0, 0, 0x40, 0xe2, 0xfd], |_| {});
        assert_eq!(cpu.regs[EAX], 5);
        assert_eq!(cpu.regs[ECX], 0);
    }

    #[test]
    fn lodsb_stosb_with_a_transform_is_the_shape_a_decryptor_uses() {
        // ac        lodsb
        // 34 aa     xor al, 0xaa
        // aa        stosb
        // e2 fa     loop -6
        let mut mem = Mem::new(64);
        mem.map(0x1000, 0x3000).unwrap();
        let plain = b"the original image";
        let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0xaa).collect();
        mem.write_bytes(0x2000, &cipher).unwrap();
        mem.write_bytes(0x1000, &[0xac, 0x34, 0xaa, 0xaa, 0xe2, 0xfa])
            .unwrap();
        let mut cpu = Cpu::new();
        cpu.eip = 0x1000;
        cpu.regs[ESI] = 0x2000;
        cpu.regs[EDI] = 0x3000;
        cpu.regs[ECX] = plain.len() as u32;
        for _ in 0..1000 {
            if cpu.eip >= 0x1006 {
                break;
            }
            cpu.step(&mut mem).unwrap();
        }
        assert_eq!(&mem.snapshot(0x3000, plain.len()), plain);
    }
}
