//! Bounded execution of decoded bytecode functions ([`super::instr`]).
//!
//! Security model: pure safe Rust, no `unsafe`, no native codegen, no syscalls.
//! The program sees the file only through a fixed read-only API; all memory is
//! bounds-checked Rust `Vec`s; every run is capped by instruction and call-depth
//! budgets. A program can at worst be abandoned or return nothing; it can never
//! corrupt memory.
//!
//! # Memory model
//!
//! Each function activation gets a frame: a flat byte buffer (its "stack")
//! holding every value laid out by type size/alignment, plus `map[id]` giving
//! value `id`'s byte offset. Pointers are a tagged 64-bit `(region << 32) |
//! offset`, never a host address. Regions are: per-frame stacks (so a callee
//! can write through a pointer into its caller's frame), the read-only globals
//! (resolved structurally from the `G` record), and the predefined file size.
//! Every access is bounds-checked against its region.
//!
//! # Where the API shapes come from
//!
//! Several structures named here (`cli_exe_section`, `cli_pe_hook_data`,
//! `cli_environment`) are the ABI a `.cbc` program was compiled against, so an
//! interpreter has to reproduce them field for field or the program reads
//! garbage. Their layouts are established from the accesses real programs make:
//! run a program, watch which offsets it loads and what it does with them. That
//! is the same method used for the signature formats, and it is the only one
//! available: the shapes are an interface, and interfaces have to be matched
//! exactly whatever their provenance.

use super::decode::Operand;
use crate::byte_source::{ByteSource, CHUNK};
use super::instr::{Body, Function, Inst};
use super::instr::{OP_GEP1, OP_ICMP_FIRST, OP_ICMP_LAST, OP_SEXT, OP_TRUNC, OP_ZEXT};
use super::types::{Globals, TypeTable};
use std::rc::Rc;
/// Deterministic instruction cap per program run: a *failsafe* against a
/// runaway loop in this interpreter, NOT a budget on the trusted bytecode.
///
/// Bounded by step count, not wall clock: a wall-clock budget would make
/// detection depend on machine load, letting an attacker (or a busy server) push
/// a program past the deadline to evade detection. A step count depends only on
/// the input, so the verdict is reproducible everywhere.
///
/// Set far above what real programs need. An unpacker in the published bytecode
/// set loops over a whole PE section, and the ones that unpack MPRESS run into
/// the hundreds of millions of opcodes for a single sample. A cap that trips on
/// one of those is worse than no cap at all: exav loads the program, matches its
/// trigger, starts running it and gives up just short of the answer, so the
/// packed payload goes unexamined and the file scans clean.
///
/// The daemon's per-job wall-clock and memory limits bound the time a scan may
/// take; this only has to stop a program that never terminates.
const MAX_STEPS: u64 = 1_000_000_000;
const MAX_BYTES: usize = 16 << 20;
const MAX_DEPTH: usize = 64;

/// The predefined global holding the scanned file's size (`GLOBAL_FILESIZE`).
const GLOBAL_FILESIZE: u64 = 0x8004;
/// The predefined global holding the parsed PE header struct (`GLOBAL_PEDATA`).
const GLOBAL_PEDATA: u64 = 0x8003;
/// Marks a global target as a predefined global rather than another global id.
const GLOBAL_PREDEFINED: u64 = 0x8000;

// Opcodes with bespoke handling (others come from the `instr` constants).
const OP_SELECT: u8 = 31;
const OP_COPY: u8 = 34;
const OP_MEMSET: u8 = 40;
const OP_MEMCPY: u8 = 41;
const OP_MEMMOVE: u8 = 42;
const OP_MEMCMP: u8 = 43;
const OP_ISBIGENDIAN: u8 = 44;
const OP_ABORT: u8 = 45;
const OP_BSWAP16: u8 = 46;
const OP_BSWAP32: u8 = 47;
const OP_BSWAP64: u8 = 48;
const OP_PTRDIFF32: u8 = 49;
const OP_PTRTOINT64: u8 = 50;
const OP_STORE: u8 = 38;
const OP_LOAD: u8 = 39;

// Pointer region tags (the high 32 bits of a composed pointer).
const R_NULL: i64 = 0;
const R_FILESIZE: i64 = 1;
/// The parsed PE header struct region (`__clambc_pedata`).
const R_PEDATA: i64 = 2;
/// A read-only all-zero region for predefined globals we don't model yet
/// (`__clambc_kind`, `match_counts`). Reads return 0 so a program runs
/// rather than hitting "unsupported".
const R_ZERO: i64 = 3;
/// The `__clambc_match_offsets` region: per-subsignature trigger-match offsets.
const R_MATCHOFF: i64 = 4;
/// `GLOBAL_MATCH_OFFSETS`.
const GLOBAL_MATCH_OFFSETS: u64 = 0x8005;
/// Base for per-frame stack regions; region `R_STACK + f` is frame `f`.
const R_STACK: i64 = 0x1000;
/// Base for `malloc` heap regions; region `R_HEAP + i` is allocation `i`.
const R_HEAP: i64 = 0x8000;
/// Base for global regions; region `R_GLOBAL + g` is global id `g`.
const R_GLOBAL: i64 = 0x10_0000;
/// Cap on one extraction buffer. It is exav's own: a `write` past it stops
/// the run as incomplete.
const MAX_ALLOC: usize = 256 << 20;
/// The largest `malloc` ClamAV 1.4.3 grants: it returns NULL from
/// `(128 << 20) - 8` bytes up, and so does exav.
const MAX_MALLOC: usize = (128 << 20) - 9;
/// Size of `__clambc_pedata`.
const PEDATA_LEN: usize = 648;

fn compose(region: i64, off: u32) -> i64 {
    (region << 32) | i64::from(off)
}
fn ptr_region(p: i64) -> i64 {
    (p >> 32) & 0xffff_ffff
}
fn ptr_off(p: i64) -> u32 {
    p as u32
}
/// Byte width of an integer type id (its low 15 bits); pointers/aggregates = 8.
fn type_bytes(id: u32) -> usize {
    match id & 0x7fff {
        0 => 0,
        1..=8 => 1,
        9..=16 => 2,
        17..=32 => 4,
        _ => 8,
    }
}
fn bits_to_bytes(bits: u32) -> usize {
    match bits {
        0 => 0,
        1..=8 => 1,
        9..=16 => 2,
        17..=32 => 4,
        _ => 8,
    }
}

/// A host API exav implements for executing programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    SetVirusName,
    Read,
    Seek,
    FileByteAt,
    FileFind,
    FileFindLimit,
    ReadNumber,
    GetPeSection,
    PeRawaddr,
    DisasmX86,
    Malloc,
    Write,
    ExtractNew,
    Memstr,
    EngineFunctionalityLevel,
    EngineDconfLevel,
    // Context-dependent APIs not yet fed real data: best-effort "nothing"
    // stubs so the program runs without hitting an unsupported call.
    GetEnvironment,
    MatchIcon,
    PdfGetPhase,
    PdfGetFlags,
    PdfGetOffset,
    PdfGetObjSize,
    PdfGetObjId,
    PdfLookupObj,
    /// Buffered file read. Not yet implemented: we report EOF (0) so a reading
    /// loop terminates cleanly. Tracked as a data-fabricating stub (it fakes
    /// EOF instead of returning real bytes) so a dependent result is flagged
    /// and this never gets silently forgotten at review time.
    FillBuffer,
    // Deterministic math/util (fully implemented).
    Isin,
    Icos,
    Iexp,
    Ipow,
    Ilog2,
    Atoi,
    Hex2ui,
    VersionCompare,
    EntropyBuffer,
    Debug,
    // Safe stubs for the rest of the API surface (recognized so a program is
    // never rejected for an "unsupported" call; they fail-safe). `StubZero`
    // returns 0 (success/none), `StubNeg` returns -1 (failure/not-found, so
    // loops exit), `StubNull` returns 0 (null pointer).
    StubZero,
    StubNeg,
    StubNull,
    Unsupported,
}

/// Whether exav's executor implements this API (a prerequisite for running a
/// program that declares it).
pub fn api_supported(name: &str) -> bool {
    !matches!(api_of(name), Api::Unsupported)
}

/// Map an API name (from the program's declarations) to a handler.
pub fn api_of(name: &str) -> Api {
    match name {
        "setvirusname" => Api::SetVirusName,
        "read" => Api::Read,
        "seek" => Api::Seek,
        "file_byteat" => Api::FileByteAt,
        "file_find" => Api::FileFind,
        "file_find_limit" => Api::FileFindLimit,
        "read_number" => Api::ReadNumber,
        "get_pe_section" => Api::GetPeSection,
        "pe_rawaddr" => Api::PeRawaddr,
        "disasm_x86" => Api::DisasmX86,
        "malloc" => Api::Malloc,
        "write" => Api::Write,
        "extract_new" => Api::ExtractNew,
        "memstr" => Api::Memstr,
        "engine_dconf_level" => Api::EngineDconfLevel,
        "get_environment" => Api::GetEnvironment,
        "matchicon" => Api::MatchIcon,
        "pdf_get_phase" => Api::PdfGetPhase,
        "pdf_get_flags" => Api::PdfGetFlags,
        "pdf_get_offset" => Api::PdfGetOffset,
        "pdf_getobjsize" => Api::PdfGetObjSize,
        "pdf_getobjid" => Api::PdfGetObjId,
        "fill_buffer" => Api::FillBuffer,
        "pdf_lookupobj" => Api::PdfLookupObj,
        "engine_functionality_level" => Api::EngineFunctionalityLevel,
        "debug_print_str"
        | "debug_print_str_start"
        | "debug_print_str_nonl"
        | "debug_print_uint"
        | "bytecode_rt_error" => Api::Debug,
        // Deterministic math/util, fully implemented.
        "isin" => Api::Isin,
        "icos" => Api::Icos,
        "iexp" => Api::Iexp,
        "ipow" => Api::Ipow,
        "ilog2" => Api::Ilog2,
        "atoi" => Api::Atoi,
        "hex2ui" => Api::Hex2ui,
        "version_compare" => Api::VersionCompare,
        "entropy_buffer" => Api::EntropyBuffer,
        // No-op / informational APIs → 0 (success/none/inactive).
        "check_platform"
        | "running_on_jit"
        | "disable_bytecode_if"
        | "disable_jit_if"
        | "engine_db_options"
        | "engine_scan_options"
        | "engine_scan_options_ex"
        | "get_file_reliability"
        | "input_switch"
        | "test1"
        | "test2"
        | "trace_directory"
        | "trace_op"
        | "trace_ptr"
        | "trace_scope"
        | "trace_source"
        | "trace_value"
        | "extract_set_container"
        | "pdf_set_flags"
        | "pdf_setobjflags"
        | "pdf_getobjflags"
        | "pdf_get_flags_unused"
        | "json_is_active"
        | "hashset_done"
        | "map_done"
        | "buffer_pipe_done"
        | "inflate_done"
        | "bzip2_done"
        | "lzma_done"
        | "jsnorm_done"
        | "buffer_pipe_read_stopped"
        | "buffer_pipe_write_stopped"
        | "buffer_pipe_read_avail"
        | "buffer_pipe_write_avail"
        | "pdf_get_obj_num" => Api::StubZero,
        // Lookup/alloc/process that must fail-safe (-1) so callers don't loop.
        "hashset_new"
        | "hashset_add"
        | "hashset_contains"
        | "hashset_remove"
        | "hashset_empty"
        | "map_new"
        | "map_addkey"
        | "map_find"
        | "map_setvalue"
        | "map_getvaluesize"
        | "map_remove"
        | "buffer_pipe_new"
        | "buffer_pipe_new_fromfile"
        | "inflate_init"
        | "inflate_process"
        | "bzip2_init"
        | "bzip2_process"
        | "lzma_init"
        | "lzma_process"
        | "jsnorm_init"
        | "jsnorm_process"
        | "json_get_object"
        | "json_get_array_idx"
        | "json_get_array_length"
        | "json_get_boolean"
        | "json_get_int"
        | "json_get_string"
        | "json_get_string_length"
        | "json_get_type"
        | "pdf_get_dumpedobjid" => Api::StubNeg,
        // Pointer-returning APIs that fail-safe with NULL (0).
        "buffer_pipe_read_get" | "buffer_pipe_write_get" | "map_getvalue" | "pdf_getobj" => {
            Api::StubNull
        }
        _ => Api::Unsupported,
    }
}

/// Outcome of running one program.
#[derive(Debug, Default)]
pub struct Outcome {
    pub detection: Option<String>,
    pub steps: u64,
    /// True if the program used an unimplemented op/API, made an out-of-bounds
    /// access, divided by zero or aborted. The result is then unreliable and
    /// must be ignored.
    pub hit_unsupported: bool,
    /// True if exav, not the program, stopped the run before it finished (out
    /// of steps or call depth, a frame too large, an op or API exav does not
    /// model, output past exav's extraction cap, PE header data exav lacks, or
    /// a VM panic): what it would have found is unknown, so the scan is
    /// incomplete. A program's own failure (an out-of-bounds access, a
    /// division by zero, an abort) ends it as it would in ClamAV, and is not.
    /// Also true when a `write` was refused at the scan's limits: the run
    /// went on, but what it would have written was not scanned.
    pub incomplete: bool,
    /// Buffers the program extracted (via `write`+`extract_new`) for the engine
    /// to recursively re-scan (how unpacker programs surface embedded files).
    pub extracted: Vec<Vec<u8>>,
    /// Data-fabricating stub APIs this run invoked.
    /// Non-empty means the result leaned on at least one unimplemented API and
    /// should be treated with suspicion even when no unsupported op was hit.
    pub stubbed: Vec<String>,
}

/// PDF object table for the `pdf_*` APIs: `(object id, start offset)` sorted by
/// start, plus the file size. (`PDF_PHASE_PARSED`.)
#[derive(Debug, Clone, Default)]
pub struct PdfCtx {
    pub objs: Vec<(u32, u32)>,
    pub size: u32,
}

/// Scan a PDF for `id gen obj` markers, returning a [`PdfCtx`] (objects sorted
/// by offset). This mirrors what the PDF parser feeds the bytecode.
pub fn pdf_ctx(data: &dyn ByteSource) -> PdfCtx {
    let mut objs = Vec::new();
    let mut from = 0;
    // " obj" cannot overlap itself, so one byte on finds every occurrence.
    while let Some(pos) = data.find(b" obj", from, data.len()) {
        from = pos + 1;
        // Before " obj": "<id> <gen>". Walk back over gen digits, a space, id.
        let (i, _) = digits_before(data, pos);
        if i == pos || i == 0 || data.window(i - 1, 1)[..] != *b" " {
            continue;
        }
        let id_end = i - 1; // the space
        let (i, id) = digits_before(data, id_end);
        if i == id_end {
            continue;
        }
        objs.push((id, i as u32));
        if objs.len() >= 8192 {
            break;
        }
    }
    objs.sort_by_key(|&(_, start)| start);
    PdfCtx {
        objs,
        size: data.len().min(u32::MAX as usize) as u32,
    }
}

/// Where the run of ASCII digits ending at `end` starts, and its value as
/// `str::parse::<u32>` reads it (0 when it does not fit). Read backwards a
/// window at a time, so a long run costs no more memory than a short one.
fn digits_before(data: &dyn ByteSource, end: usize) -> (usize, u32) {
    let mut start = end;
    let mut value = 0u64;
    let mut overflow = false;
    // 10 to the power of the digits read so far, until it passes `u32::MAX`:
    // past that, any digit but 0 overflows.
    let mut scale = Some(1u64);
    let mut span = 64;
    loop {
        let from = start.saturating_sub(span);
        let w = data.window(from, start - from);
        if w.len() != start - from {
            // Unreadable: the run ends where reading did.
            return (start, if overflow { 0 } else { value as u32 });
        }
        for (k, &b) in w.iter().enumerate().rev() {
            if !b.is_ascii_digit() {
                return (from + k + 1, if overflow { 0 } else { value as u32 });
            }
            let d = (b - b'0') as u64;
            if d != 0 {
                match scale {
                    Some(s) => {
                        value += d * s;
                        overflow |= value > u32::MAX as u64;
                    }
                    None => overflow = true,
                }
            }
            scale = scale.and_then(|s| s.checked_mul(10)).filter(|&s| s <= 1 << 40);
        }
        if from == 0 {
            return (0, if overflow { 0 } else { value as u32 });
        }
        start = from;
        span = (span * 2).min(CHUNK);
    }
}

/// Execution context for one run.
pub struct Ctx<'a> {
    pub file: &'a dyn ByteSource,
    pub flevel: u32,
    /// The program's decoded type table (`T` record).
    pub types: &'a TypeTable,
    /// The program's decoded constant globals (`G` record).
    pub globals: &'a Globals,
    /// Parsed PE header/section info, when the scanned file is a PE (enables
    /// `get_pe_section` / `pe_rawaddr`).
    pub pe: Option<&'a crate::pe::BcPe>,
    /// Parsed PDF object table, when the scanned file is a PDF (enables the
    /// `pdf_*` APIs).
    pub pdf: Option<&'a PdfCtx>,
    /// Per-subsignature trigger-match offsets (`__clambc_match_offsets`), for
    /// logical programs that start analysis at where their pattern matched.
    pub match_offsets: &'a [u32],
    /// API declarations as `(global_id, name)`, exactly as parsed.
    pub apis: &'a [(u32, String)],
    /// Detection name reported when `setvirusname` can't resolve a name.
    pub default_name: &'a str,
    pub write_limits: WriteLimits,
}

/// The scan's limits on what `write` makes: the size of one output file, and
/// the bytes a run may write in all. A `write` past either returns -1, as one
/// past ClamAV's file and scan size limits does.
#[derive(Clone, Copy, Debug)]
pub struct WriteLimits {
    pub file: u64,
    pub total: u64,
}

impl WriteLimits {
    pub const NONE: Self = WriteLimits {
        file: u64::MAX,
        total: u64::MAX,
    };
}

/// One function activation.
struct Frame<'a> {
    vtypes: &'a [u32],
    /// Where each value sits in `stack`.
    slots: Rc<[Slot]>,
    stack: Vec<u8>,
}

/// A value's byte offset in its frame, and its width in bytes (at least 1).
#[derive(Clone, Copy)]
struct Slot {
    off: u32,
    w: u32,
}

/// Control-flow result of executing one instruction.
enum Flow {
    Next,
    Jump(usize),
    Return(i64),
}

struct Machine<'a> {
    ctx: &'a Ctx<'a>,
    frames: Vec<Frame<'a>>,
    /// Per function, where each of its values sits in a frame and the
    /// frame's size: worked out at its first call, not at every one.
    layouts: Vec<Option<(Rc<[Slot]>, usize)>>,
    /// The program's declared APIs, by `CALL_API` id, resolved once per run.
    apis: Vec<(u32, Api)>,
    /// Globals rendered to bytes once (a global read happens in hot loops, so
    /// this must not reallocate per access).
    gcache: Vec<Vec<u8>>,
    /// `malloc` allocations, indexed by region `R_HEAP + i`.
    heaps: Vec<Vec<u8>>,
    /// The in-progress extraction buffer (`write` appends here).
    extract_cur: Vec<u8>,
    /// Finalized extracted buffers (`extract_new` flushes `extract_cur` here).
    extracted: Vec<Vec<u8>>,
    /// Bytes `write` took this run, and whether it refused some at the scan's
    /// limits.
    written: u64,
    limited: bool,
    cursor: usize,
    detection: Option<String>,
    steps: u64,
    unsupported: bool,
    /// Something the interpreter does not model, or one of its own bounds,
    /// stopped the run: what the program would have found is unknown.
    gap: bool,
    halt: bool,
    /// The file is a PE whose header data `ctx.pe` lacks.
    pe_missing: bool,
    /// Names of *data-fabricating* stub APIs the run actually invoked (lookup /
    /// allocation / decompression APIs we answer with a fixed fail-safe value
    /// instead of real behavior). A detection that depended on one of these ran
    /// partly on fiction, so it is surfaced in [`Outcome::stubbed`] and never
    /// silently trusted. Benign no-ops (debug/trace/platform) are not recorded.
    stubbed: std::collections::BTreeSet<String>,
    /// Opt-in (`EXAV_DEBUG_BC_TRACE`) execution trace of the data-access APIs, for
    /// debugging why a gated program does or doesn't detect. Read once at
    /// construction, so it costs nothing in the hot path when off.
    trace: bool,
    /// Opt-in (`EXAV_DEBUG_BC_FN=<idx>`) per-instruction value trace of one function,
    /// for debugging a divergent computation. `None` when off.
    trace_fn: Option<usize>,
}

impl<'a> Machine<'a> {
    /// The program failed: the run ends here and its result is discarded.
    /// Carried on, it would compute on the zeros a failed read returns.
    fn flag(&mut self) {
        self.unsupported = true;
        self.halt = true;
    }

    /// [`Self::flag`] for a stop that is exav's, not the program's: the run is
    /// then incomplete rather than a program failure ClamAV would also have.
    fn gap(&mut self) {
        self.flag();
        self.gap = true;
    }

    /// `__clambc_pedata`. A file that is not a PE reads as zeros, as in
    /// ClamAV. A PE whose header data exav lacks may be one ClamAV has data
    /// for, so that is a gap.
    fn pedata(&mut self) -> Option<&'a [u8]> {
        if let Some(pe) = self.ctx.pe {
            return Some(&pe.pedata);
        }
        if self.pe_missing {
            self.gap();
            return None;
        }
        Some(&[0; PEDATA_LEN])
    }

    /// Record that a fail-safe stub fabricated a result, and (under
    /// `EXAV_DEBUG_BC_WARN`) warn once so a missing implementation is never silent.
    fn note_stub(&mut self, name: &str) {
        if self.stubbed.insert(name.to_string()) && std::env::var_os("EXAV_DEBUG_BC_WARN").is_some() {
            eprintln!("[exav bytecode] WARN: stubbed API `{name}` returned a fail-safe value; result may diverge from ClamAV");
        }
    }

    // --- per-frame raw memory (bounds-checked) ---
    #[inline(always)]
    fn rd_mem(&mut self, frame: usize, off: u32, w: usize) -> i64 {
        let o = off as usize;
        let Some(b) = self.frames.get(frame).and_then(|fr| fr.stack.get(o..o.checked_add(w)?)).filter(|_| w != 0) else {
            self.flag();
            return 0;
        };
        // The widths values come in, read whole; any other a byte at a time.
        let v = match w {
            1 => u64::from(b[0]),
            2 => u64::from(u16::from_le_bytes([b[0], b[1]])),
            4 => u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            8 => u64::from_le_bytes(b.try_into().expect("eight bytes")),
            _ => b.iter().enumerate().fold(0u64, |v, (i, &x)| v | u64::from(x) << (8 * i)),
        };
        v as i64
    }
    #[inline(always)]
    fn wr_mem(&mut self, frame: usize, off: u32, w: usize, val: i64) {
        let o = off as usize;
        let Some(b) = self.frames.get_mut(frame).and_then(|fr| fr.stack.get_mut(o..o.checked_add(w)?)).filter(|_| w != 0) else {
            self.flag();
            return;
        };
        let v = (val as u64).to_le_bytes();
        match w {
            1 | 2 | 4 | 8 => b.copy_from_slice(&v[..w]),
            _ => {
                for (i, x) in b.iter_mut().enumerate() {
                    *x = ((val as u64) >> (8 * i)) as u8;
                }
            }
        }
    }

    #[inline(always)]
    fn slot(&self, fi: usize, id: u32) -> Option<Slot> {
        self.frames.get(fi)?.slots.get(id as usize).copied()
    }
    fn type_of(&self, fi: usize, id: u32) -> u32 {
        self.frames
            .get(fi)
            .and_then(|fr| fr.vtypes.get(id as usize).copied())
            .unwrap_or(0)
    }

    /// Store an instruction result into value `id`'s slot at its type width.
    #[inline(always)]
    fn set(&mut self, fi: usize, id: u32, v: i64) {
        let Some(s) = self.slot(fi, id) else {
            self.flag();
            return;
        };
        self.wr_mem(fi, s.off, s.w as usize, v);
    }

    // --- operand evaluation ---
    #[inline(always)]
    fn value(&mut self, fi: usize, op: &Operand, w: usize) -> i64 {
        match *op {
            Operand::Reg(i) => match self.slot(fi, i) {
                Some(s) => self.rd_mem(fi, s.off, w),
                None => {
                    self.flag();
                    0
                }
            },
            Operand::Const(c) => mask(c as i64, (w * 8) as u32),
            // A global used as a value reads its stored content: the composed
            // pointer for a pointer global, or the scalar for a scalar global
            // (it is NOT dereferenced; LOAD does that separately).
            Operand::Global(g) => self.global_value(g),
        }
    }

    fn global_value(&mut self, g: u32) -> i64 {
        match self.ctx.globals.values.get(g as usize).map(|v| v.len()) {
            Some(l) if l >= 2 => self.global_ptr(g),
            Some(_) => self.ctx.globals.values[g as usize]
                .first()
                .map(|&v| v as i64)
                .unwrap_or(0),
            None => {
                self.flag();
                0
            }
        }
    }
    #[inline(always)]
    fn op_width(&self, fi: usize, op: &Operand) -> usize {
        match *op {
            Operand::Reg(i) => self.slot(fi, i).map_or(1, |s| s.w as usize),
            _ => 8,
        }
    }
    #[inline(always)]
    fn value_nat(&mut self, fi: usize, op: &Operand) -> i64 {
        let w = self.op_width(fi, op);
        self.value(fi, op, w)
    }
    /// Evaluate the first three call arguments as integers.
    fn arg3(&mut self, fi: usize, args: &[Operand]) -> (i64, i64, i64) {
        let z = Operand::Const(0);
        (
            self.value_nat(fi, args.first().unwrap_or(&z)),
            self.value_nat(fi, args.get(1).unwrap_or(&z)),
            self.value_nat(fi, args.get(2).unwrap_or(&z)),
        )
    }

    /// Resolve an operand used as a pointer into a composed `(region, offset)`.
    fn ptr(&mut self, fi: usize, op: &Operand) -> i64 {
        match *op {
            Operand::Reg(i) => {
                let ty = self.type_of(fi, i);
                let Some(Slot { off, .. }) = self.slot(fi, i) else {
                    self.flag();
                    return R_NULL;
                };
                if ty & GLOBAL_PREDEFINED as u32 != 0 {
                    compose(R_STACK + fi as i64, off) // address-of buffer local
                } else {
                    self.rd_mem(fi, off, 8) // pointer-valued SSA: slot holds the pointer
                }
            }
            Operand::Global(g) => self.global_ptr(g),
            Operand::Const(_) => R_NULL,
        }
    }

    /// A call/return argument: a pointer if it names a buffer or global, else
    /// the integer value.
    fn arg_value(&mut self, fi: usize, op: &Operand) -> i64 {
        match *op {
            Operand::Reg(i) if self.type_of(fi, i) & GLOBAL_PREDEFINED as u32 != 0 => {
                self.ptr(fi, op)
            }
            Operand::Global(_) => self.ptr(fi, op),
            _ => self.value_nat(fi, op),
        }
    }

    fn global_ptr(&mut self, g: u32) -> i64 {
        let Some(gv) = self.ctx.globals.values.get(g as usize) else {
            self.flag();
            return R_NULL;
        };
        if gv.len() >= 2 {
            let (offset, target) = (gv[0], gv[1]);
            if target & GLOBAL_PREDEFINED != 0 {
                return match target {
                    GLOBAL_FILESIZE => compose(R_FILESIZE, offset as u32),
                    GLOBAL_PEDATA => compose(R_PEDATA, offset as u32),
                    GLOBAL_MATCH_OFFSETS => compose(R_MATCHOFF, offset as u32),
                    // kind / match_counts: read as zero.
                    _ => compose(R_ZERO, offset as u32),
                };
            }
            return compose(R_GLOBAL + target as i64, offset as u32);
        }
        self.flag();
        R_NULL
    }

    fn deref_int(&mut self, p: i64, w: usize) -> i64 {
        let (region, off) = (ptr_region(p), ptr_off(p));
        if region == R_FILESIZE {
            let fs = (self.ctx.file.len().min(u32::MAX as usize) as u32).to_le_bytes();
            return read_le(&fs, off as usize, w).unwrap_or_else(|| {
                self.flag();
                0
            });
        }
        if region == R_PEDATA {
            let Some(pd) = self.pedata() else {
                return 0;
            };
            return read_le(pd, off as usize, w).unwrap_or_else(|| {
                self.flag();
                0
            });
        }
        if region == R_ZERO {
            return 0;
        }
        if region == R_MATCHOFF {
            // match_offsets[i] is a u32; index = byte offset / 4.
            let i = off as usize / 4;
            return self
                .ctx
                .match_offsets
                .get(i)
                .map(|&v| v as i64)
                .unwrap_or(0);
        }
        if region >= R_GLOBAL {
            let g = (region - R_GLOBAL) as usize;
            let v = self.gcache.get(g).and_then(|b| read_le(b, off as usize, w));
            return v.unwrap_or_else(|| {
                self.flag();
                0
            });
        }
        if region >= R_HEAP {
            let h = (region - R_HEAP) as usize;
            let v = self
                .heaps
                .get(h)
                .and_then(|buf| read_le(buf, off as usize, w));
            return v.unwrap_or_else(|| {
                self.flag();
                0
            });
        }
        if region >= R_STACK {
            return self.rd_mem((region - R_STACK) as usize, off, w);
        }
        self.flag();
        0
    }
    fn store_int(&mut self, p: i64, w: usize, val: i64) {
        let region = ptr_region(p);
        if (R_HEAP..R_GLOBAL).contains(&region) {
            self.wr_heap((region - R_HEAP) as usize, ptr_off(p), w, val);
        } else if (R_STACK..R_HEAP).contains(&region) {
            self.wr_mem((region - R_STACK) as usize, ptr_off(p), w, val);
        } else {
            self.flag();
        }
    }
    fn wr_heap(&mut self, h: usize, off: u32, w: usize, val: i64) {
        let o = off as usize;
        let ok = self
            .heaps
            .get(h)
            .map(|buf| w != 0 && o.checked_add(w).is_some_and(|end| end <= buf.len()))
            .unwrap_or(false);
        if !ok {
            self.flag();
            return;
        }
        let v = val as u64;
        let buf = &mut self.heaps[h];
        for i in 0..w {
            buf[o + i] = (v >> (8 * i)) as u8;
        }
    }

    fn global_bytes(&self, g: usize) -> &[u8] {
        self.gcache.get(g).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Read `len` bytes through a pointer (for API arguments and memops).
    fn read_region(&mut self, p: i64, len: usize) -> Vec<u8> {
        let (region, off) = (ptr_region(p), ptr_off(p) as usize);
        let slice = |buf: &[u8]| {
            buf.get(off..off.saturating_add(len).min(buf.len()))
                .unwrap_or(&[])
                .to_vec()
        };
        if region == R_PEDATA {
            return self.pedata().map(slice).unwrap_or_default();
        }
        if region == R_ZERO {
            // Cap the zero-fill: `len` is attacker-controlled (memcpy/memmem/
            // memstr feed it), and an uncapped `vec![0; len]` would abort the
            // process on a huge length. Short reads are already normal here.
            return vec![0u8; len.min(MAX_BYTES)];
        }
        // The two regions [`Self::deref_int`] reads as values, read as bytes.
        if region == R_FILESIZE {
            return slice(&(self.ctx.file.len().min(u32::MAX as usize) as u32).to_le_bytes());
        }
        if region == R_MATCHOFF {
            let offs: Vec<u8> = self.ctx.match_offsets.iter().flat_map(|o| o.to_le_bytes()).collect();
            return slice(&offs);
        }
        if region >= R_GLOBAL {
            return slice(self.global_bytes((region - R_GLOBAL) as usize));
        }
        if region >= R_HEAP {
            return self
                .heaps
                .get((region - R_HEAP) as usize)
                .map(|b| slice(b))
                .unwrap_or_default();
        }
        if region >= R_STACK {
            let fr = (region - R_STACK) as usize;
            return self
                .frames
                .get(fr)
                .map(|f| slice(&f.stack))
                .unwrap_or_default();
        }
        self.flag();
        Vec::new()
    }
    fn write_region(&mut self, p: i64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.store_int(
                compose(ptr_region(p), ptr_off(p).wrapping_add(i as u32)),
                1,
                b as i64,
            );
        }
    }

    fn read_cstring(&self, p: i64) -> Option<String> {
        let (region, off) = (ptr_region(p), ptr_off(p) as usize);
        let take = |b: &[u8]| -> Option<String> {
            let s: Vec<u8> = b
                .get(off..)?
                .iter()
                .take_while(|&&x| x != 0)
                .copied()
                .collect();
            Some(String::from_utf8_lossy(&s).into_owned())
        };
        if region >= R_GLOBAL {
            take(self.global_bytes((region - R_GLOBAL) as usize))
        } else if region >= R_HEAP {
            take(self.heaps.get((region - R_HEAP) as usize)?.as_slice())
        } else if region >= R_STACK {
            take(
                self.frames
                    .get((region - R_STACK) as usize)?
                    .stack
                    .as_slice(),
            )
        } else {
            None
        }
    }

    fn api_for(&self, func: u32) -> Api {
        self.apis
            .iter()
            .find(|(id, _)| *id == func.saturating_add(1))
            .map_or(Api::Unsupported, |&(_, a)| a)
    }

    fn call_api(&mut self, fi: usize, api: Api, args: &[Operand]) -> i64 {
        match api {
            Api::SetVirusName => {
                let name = match args.first() {
                    Some(op) => {
                        let p = self.ptr(fi, op);
                        self.read_cstring(p)
                    }
                    None => None,
                }
                .filter(|s| !s.is_empty());
                self.detection = Some(name.unwrap_or_else(|| self.ctx.default_name.to_string()));
                if self.trace {
                    eprintln!("[trace] setvirusname -> {:?}", self.detection);
                }
                0
            }
            Api::Read => {
                let size = self
                    .value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)))
                    .max(0) as usize;
                let avail = self.ctx.file.len().saturating_sub(self.cursor).min(size);
                let bytes = self.ctx.file.window(self.cursor, avail);
                if let Some(op) = args.first() {
                    let p = self.ptr(fi, op);
                    self.write_region(p, &bytes);
                }
                self.cursor += bytes.len();
                bytes.len() as i64
            }
            Api::Seek => {
                let off = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(0)));
                let whence = self.value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)));
                let base = match whence {
                    1 => self.cursor as i64,
                    2 => self.ctx.file.len() as i64,
                    _ => 0,
                };
                let pos = base.checked_add(off);
                let Some(pos) = pos.filter(|&p| (0..=self.ctx.file.len() as i64).contains(&p))
                else {
                    if self.trace {
                        eprintln!("[trace] seek(off={off}, whence={whence}) -> OOB(-1)");
                    }
                    return -1;
                };
                self.cursor = pos as usize;
                if self.trace {
                    eprintln!(
                        "[trace] seek(off={off}, whence={whence}) -> cursor={}",
                        self.cursor
                    );
                }
                self.cursor as i64
            }
            Api::FileByteAt => {
                let off = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(0)));
                match usize::try_from(off).ok().map(|o| self.ctx.file.window(o, 1)) {
                    Some(b) if b.len() == 1 => b[0] as i64,
                    _ => -1,
                }
            }
            Api::FileFind | Api::FileFindLimit => {
                let len = self
                    .value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)))
                    .max(0) as usize;
                let limit = if matches!(api, Api::FileFindLimit) {
                    self.value_nat(fi, args.get(2).unwrap_or(&Operand::Const(0)))
                        .max(0) as usize
                } else {
                    self.ctx.file.len()
                };
                if len == 0 || len > 1024 {
                    return -1;
                }
                let p = self.ptr(fi, args.first().unwrap_or(&Operand::Const(0)));
                let pat = self.read_region(p, len);
                if pat.len() != len {
                    return -1;
                }
                let end = limit.min(self.ctx.file.len());
                match self.ctx.file.find(&pat, self.cursor, end) {
                    Some(at) => at as i64,
                    None => -1,
                }
            }
            Api::ReadNumber => {
                let radix = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(10)));
                if radix != 10 && radix != 16 {
                    return -1;
                }
                self.read_number(radix as u32)
            }
            Api::GetPeSection => {
                // get_pe_section(out, num): write section `num` (9 × u32, the
                // cli_exe_section layout) into the caller's buffer.
                let num = self.value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)));
                let Some(pe) = self.ctx.pe else { return -1 };
                let Some(&s) = usize::try_from(num).ok().and_then(|n| pe.sections.get(n)) else {
                    return -1;
                };
                // rva, vsz, raw, rsz, chr, then the "unaligned" mirror fields.
                let fields = [
                    s.rva, s.vsz, s.raw, s.rsz, s.chr, s.rva, s.vsz, s.raw, s.rsz,
                ];
                let mut buf = Vec::with_capacity(36);
                for f in fields {
                    buf.extend_from_slice(&f.to_le_bytes());
                }
                let p = self.ptr(fi, args.first().unwrap_or(&Operand::Const(0)));
                self.write_region(p, &buf);
                0
            }
            Api::PeRawaddr => {
                let rva = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(0))) as u32;
                match self
                    .ctx
                    .pe
                    .and_then(|pe| pe.rawaddr(rva, self.ctx.file.len()))
                {
                    Some(raw) => raw as i64,
                    None => 0xffff_ffff, // PE_INVALID_RVA
                }
            }
            Api::DisasmX86 => {
                // disasm_x86(result, len): decode one instruction at the cursor
                // into the caller's DISASM_RESULT; return the offset just past
                // it (the cursor is not advanced, matching the ABI).
                let bytes = self.ctx.file.window(self.cursor, 32).into_owned();
                let n = bytes.len();
                match super::disasm::disasm_one(&bytes) {
                    Some((res, len)) => {
                        if self.trace {
                            eprintln!(
                                "[trace] disasm_x86 @cursor={} bytes={:02x?} -> len={} op={} arg0.access={}",
                                self.cursor, &bytes[..n.min(8)], len, res[0], res.get(5).copied().unwrap_or(0)
                            );
                        }
                        let p = self.ptr(fi, args.first().unwrap_or(&Operand::Const(0)));
                        self.write_region(p, &res);
                        (self.cursor + len) as i64
                    }
                    None => {
                        if self.trace {
                            eprintln!("[trace] disasm_x86 @cursor={} -> NONE", self.cursor);
                        }
                        // The decoder cannot distinguish "not an instruction"
                        // from "an instruction outside my scope", so neither can
                        // this. Returning the ABI's -1 would let the program
                        // carry on down a branch it would not have taken with a
                        // full decoder, and report a verdict built on it. End
                        // the run as unsupported instead: the detection is
                        // discarded, and nothing is written past this point.
                        self.flag();
                        -1
                    }
                }
            }
            Api::Malloc => {
                // malloc(size): a fresh zeroed heap allocation; returns a
                // pointer to it (region R_HEAP + index).
                let size = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(0)));
                if size <= 0 || size as usize > MAX_MALLOC {
                    if self.trace {
                        eprintln!("[trace] malloc({size}) -> NULL (over MAX_MALLOC {MAX_MALLOC})");
                        for (hi, h) in self.heaps.iter().enumerate() {
                            let n = h.len().min(32);
                            eprintln!(
                                "[trace]   heap#{hi} ({} bytes) [0..{n}]={:02x?}",
                                h.len(),
                                &h[..n]
                            );
                        }
                    }
                    return 0; // null
                }
                if self.trace {
                    eprintln!("[trace] malloc({size}) -> heap#{}", self.heaps.len());
                }
                let idx = self.heaps.len();
                self.heaps.push(vec![0u8; size as usize]);
                compose(R_HEAP + idx as i64, 0)
            }
            Api::Write => {
                // write(data, len): append to the current extraction buffer.
                let len = self
                    .value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)))
                    .max(0) as usize;
                let p = self.ptr(fi, args.first().unwrap_or(&Operand::Const(0)));
                let bytes = self.read_region(p, len);
                let n = bytes.len();
                let file = (self.extract_cur.len() + n) as u64;
                let limits = self.ctx.write_limits;
                if file > limits.file || self.written.saturating_add(n as u64) > limits.total {
                    // The program sees the failure and carries on; what it
                    // would have written goes unscanned.
                    self.limited = true;
                    return -1;
                }
                if self.extract_cur.len() + n > MAX_ALLOC {
                    self.gap();
                    return -1;
                }
                self.extract_cur.extend_from_slice(&bytes);
                self.written += n as u64;
                if self.trace {
                    eprintln!(
                        "[trace] write(len={len}) -> {n} bytes (extract_cur={})",
                        self.extract_cur.len()
                    );
                }
                n as i64
            }
            Api::ExtractNew => {
                // extract_new(id): finalize the current extraction buffer as a
                // new embedded file for the engine to re-scan; reset.
                if self.trace {
                    eprintln!(
                        "[trace] extract_new -> flush {} bytes",
                        self.extract_cur.len()
                    );
                }
                if !self.extract_cur.is_empty() {
                    self.extracted.push(std::mem::take(&mut self.extract_cur));
                }
                0
            }
            Api::Memstr => {
                // memstr(haystack, hlen, needle, nlen): substring search,
                // returns the offset within the haystack or -1.
                let hp = self.ptr(fi, args.first().unwrap_or(&Operand::Const(0)));
                let hlen = self
                    .value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)))
                    .max(0) as usize;
                let np = self.ptr(fi, args.get(2).unwrap_or(&Operand::Const(0)));
                let nlen = self
                    .value_nat(fi, args.get(3).unwrap_or(&Operand::Const(0)))
                    .max(0) as usize;
                if nlen == 0 || nlen > hlen {
                    return -1;
                }
                let hay = self.read_region(hp, hlen);
                let needle = self.read_region(np, nlen);
                match find_sub(&hay, &needle) {
                    Some(i) => i as i64,
                    None => -1,
                }
            }
            Api::EngineFunctionalityLevel => self.ctx.flevel as i64,
            // The dconf level is documented as "usually identical to the
            // functionality level": a small integer, NOT a bitmask. Returning
            // 0xFFFFFFFF made every `dconf & bit` test and flevel comparison
            // pass, which can push a program onto a detection path it should
            // skip (false positive). Mirror the functionality level instead.
            Api::EngineDconfLevel => self.ctx.flevel as i64,
            Api::GetEnvironment => {
                // Zero-fill the caller's cli_environment (platform unknown).
                let len = self
                    .value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)))
                    .clamp(0, MAX_ALLOC as i64) as usize;
                let p = self.ptr(fi, args.first().unwrap_or(&Operand::Const(0)));
                self.write_region(p, &vec![0u8; len]);
                0
            }
            // No icon-group matching yet.
            Api::MatchIcon => -1,
            // PDF object APIs, backed by the parsed object table.
            Api::PdfGetPhase => {
                if self.ctx.pdf.is_some() {
                    1 // PDF_PHASE_PARSED
                } else {
                    0 // PDF_PHASE_NONE
                }
            }
            Api::PdfGetFlags => 0, // per-object flag bits not modeled
            Api::PdfLookupObj => {
                let objid = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(0))) as u32;
                match self.ctx.pdf {
                    Some(p) => p
                        .objs
                        .iter()
                        .position(|&(id, _)| id == objid)
                        .map(|i| i as i64)
                        .unwrap_or(-1),
                    None => -1,
                }
            }
            Api::PdfGetObjSize => {
                let idx = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(0)));
                match self.ctx.pdf {
                    Some(p) if idx >= 0 && (idx as usize) < p.objs.len() => {
                        let i = idx as usize;
                        if i + 1 == p.objs.len() {
                            p.size.saturating_sub(p.objs[i].1) as i64
                        } else {
                            (p.objs[i + 1]
                                .1
                                .saturating_sub(p.objs[i].1)
                                .saturating_sub(4)) as i64
                        }
                    }
                    _ => 0,
                }
            }
            Api::PdfGetOffset => {
                let idx = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(0)));
                match self.ctx.pdf {
                    Some(p) if idx >= 0 && (idx as usize) < p.objs.len() => {
                        p.objs[idx as usize].1 as i64
                    }
                    _ => -1,
                }
            }
            Api::PdfGetObjId => {
                // Contract: return `objid << 8 | generation` for the object at
                // index `i`, or -1 if the index is invalid. We parse the object
                // number but not the generation, so generation is 0.
                let idx = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(0)));
                match self.ctx.pdf {
                    Some(p) if idx >= 0 && (idx as usize) < p.objs.len() => {
                        // `objid << 8 | generation`; generation unparsed (0).
                        (p.objs[idx as usize].0 as i64) << 8
                    }
                    _ => -1,
                }
            }
            // Buffered read: report EOF so a read loop stops. Fabricates EOF
            // rather than real bytes, so it is tracked as a stub (see dispatch).
            Api::FillBuffer => 0,
            // Trig/exp/log APIs: round(c * f(a/b)) computed in f64; b == 0 -> sentinel.
            Api::Isin => {
                let (a, b, c) = self.arg3(fi, args);
                if b == 0 {
                    return 0x7fff_ffff;
                }
                (c as f64 * (a as f64 / b as f64).sin()).round() as i64
            }
            Api::Icos => {
                let (a, b, c) = self.arg3(fi, args);
                if b == 0 {
                    return 0x7fff_ffff;
                }
                (c as f64 * (a as f64 / b as f64).cos()).round() as i64
            }
            Api::Iexp => {
                let (a, b, c) = self.arg3(fi, args);
                if b == 0 {
                    return 0x7fff_ffff;
                }
                (c as f64 * (a as f64 / b as f64).exp()).round() as i64
            }
            Api::Ipow => {
                let (a, b, c) = self.arg3(fi, args);
                if a == 0 && b < 0 {
                    return 0x7fff_ffff;
                }
                (c as f64 * (a as f64).powf(b as f64)).round() as i64
            }
            Api::Ilog2 => {
                let a = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(0)));
                let b = self.value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)));
                if b == 0 {
                    return 0x7fff_ffff;
                }
                ((1i64 << 26) as f64 * (a as f64 / b as f64).log2()).round() as i64
            }
            Api::Atoi => {
                let p = self.ptr(fi, args.first().unwrap_or(&Operand::Const(0)));
                let len = self
                    .value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)))
                    .max(0) as usize;
                let bytes = self.read_region(p, len);
                let s = bytes.iter().skip_while(|b| b.is_ascii_whitespace());
                let s: Vec<u8> = s.copied().collect();
                let s = s.strip_prefix(b"+").unwrap_or(&s);
                if s.first().map(|b| b.is_ascii_digit()) != Some(true) {
                    return -1;
                }
                let digits: String = s
                    .iter()
                    .take_while(|b| b.is_ascii_digit())
                    .map(|&b| b as char)
                    .collect();
                digits.parse::<i64>().unwrap_or(-1)
            }
            Api::Hex2ui => {
                let h = self.value_nat(fi, args.first().unwrap_or(&Operand::Const(0))) as u8;
                let l = self.value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0))) as u8;
                match (hex_nibble(h), hex_nibble(l)) {
                    (Some(hi), Some(lo)) => ((hi << 4) | lo) as i64,
                    _ => -1,
                }
            }
            Api::VersionCompare => {
                let lp = self.ptr(fi, args.first().unwrap_or(&Operand::Const(0)));
                let ll = self
                    .value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)))
                    .max(0) as usize;
                let rp = self.ptr(fi, args.get(2).unwrap_or(&Operand::Const(0)));
                let rl = self
                    .value_nat(fi, args.get(3).unwrap_or(&Operand::Const(0)))
                    .max(0) as usize;
                let (l, r) = (self.read_region(lp, ll), self.read_region(rp, rl));
                version_compare(&l, &r)
            }
            Api::EntropyBuffer => {
                let p = self.ptr(fi, args.first().unwrap_or(&Operand::Const(0)));
                let len = self.value_nat(fi, args.get(1).unwrap_or(&Operand::Const(0)));
                if len <= 0 {
                    return -1;
                }
                let buf = self.read_region(p, len as usize);
                if buf.is_empty() {
                    return -1;
                }
                (crate::pe::shannon_entropy(&buf) * (1u32 << 26) as f64) as i64
            }
            Api::Debug => 0,
            Api::StubZero => 0,
            Api::StubNeg => -1,
            Api::StubNull => 0,
            Api::Unsupported => {
                self.gap();
                0
            }
        }
    }

    fn read_number(&mut self, radix: u32) -> i64 {
        let is_digit = |b: u8| b.is_ascii_digit() || (radix == 16 && b.is_ascii_hexdigit());
        let file = self.ctx.file;
        // The value of the first run of digits at or after the cursor, as
        // `i64::from_str_radix` reads it: 0 once it overflows.
        let mut value = Some(0i64);
        let mut started = false;
        let mut end = None;
        file.chunks(self.cursor, file.len(), &mut |at, chunk| {
            for (k, &b) in chunk.iter().enumerate() {
                if is_digit(b) {
                    started = true;
                    let d = (b as char).to_digit(radix).unwrap_or(0) as i64;
                    value = value
                        .and_then(|v| v.checked_mul(radix as i64))
                        .and_then(|v| v.checked_add(d));
                } else if started {
                    end = Some(at + k);
                    return false;
                }
            }
            true
        });
        if !started {
            return -1;
        }
        self.cursor = end.unwrap_or(file.len());
        value.unwrap_or(0)
    }

    fn gep(&mut self, fi: usize, opcode: u8, first_ty: u32, base: &Operand, idx: &Operand) -> i64 {
        let base = self.ptr(fi, base);
        let index = self.value_nat(fi, idx);
        let pointee = self.ctx.types.pointee(first_ty);
        let delta = if opcode == OP_GEP1 {
            // GEP1: index scaled by the pointee's size (resolved at prepare time).
            let esz = pointee.map(|p| self.ctx.types.size(p)).unwrap_or(1).max(1);
            // The program's own number, wrapped as the address is.
            index.wrapping_mul(esz as i64)
        } else if index == 0 {
            0
        } else if let Some(p) = pointee {
            // GEPZ: a struct field index becomes the sum of preceding field
            // sizes; any non-struct aggregate uses the index RAW (left
            // unscaled), not index*size.
            if self.ctx.types.is_struct(p) {
                self.ctx.types.field_offset(p, index as usize).unwrap_or(0) as i64
            } else {
                index
            }
        } else {
            self.flag();
            0
        };
        compose(ptr_region(base), ptr_off(base).wrapping_add(delta as u32))
    }

    /// Execute one function activation, returning its result value.
    fn exec_fn(&mut self, funcs: &'a [Function], idx: usize, args: &[i64], depth: usize) -> i64 {
        if self.halt {
            self.flag();
            return 0;
        }
        if depth > MAX_DEPTH {
            self.gap();
            return 0;
        }
        let Some(f) = funcs.get(idx) else {
            self.flag();
            return 0;
        };
        if self.layouts.len() < funcs.len() {
            self.layouts.resize(funcs.len(), None);
        }
        let types = self.ctx.types;
        let (slots, nbytes) = self.layouts[idx].get_or_insert_with(|| layout(f, types));
        let (slots, nbytes) = (Rc::clone(slots), *nbytes);
        if nbytes > MAX_BYTES {
            self.gap();
            return 0;
        }
        self.frames.push(Frame {
            vtypes: &f.types,
            slots,
            stack: vec![0u8; nbytes],
        });
        let fi = self.frames.len() - 1;
        for (k, &a) in args.iter().enumerate() {
            self.set(fi, k as u32, a);
        }

        let mut ret = 0i64;
        let mut bb = 0usize;
        'outer: while let Some(block) = funcs[idx].blocks.get(bb) {
            let mut next: Option<usize> = None;
            for inst in block {
                self.steps += 1;
                if self.steps > MAX_STEPS {
                    self.unsupported = true; // failsafe cap hit: result is incomplete
                    break 'outer;
                }
                if self.halt {
                    break 'outer;
                }
                let flow = self.step(funcs, fi, inst, depth);
                if self.trace_fn == Some(idx) {
                    // Read at the value's own width, without the checks that
                    // would end the run: tracing must not change the result.
                    let v = self
                        .slot(fi, inst.dest)
                        .and_then(|s| crate::bytes::at(&self.frames[fi].stack, s.off as usize, s.w as usize))
                        .map_or(0, |b| b.iter().rev().fold(0u64, |v, &x| v << 8 | u64::from(x)) as i64);
                    eprintln!(
                        "[fn{idx} bb{bb}] op={:<2} dest={:<3} ty={:<3} => {v} (0x{:x})",
                        inst.opcode, inst.dest, inst.ty, v as u64
                    );
                }
                match flow {
                    Flow::Next => {}
                    Flow::Jump(t) => {
                        next = Some(t);
                        break;
                    }
                    Flow::Return(v) => {
                        ret = v;
                        break 'outer;
                    }
                }
            }
            match next {
                Some(t) => bb = t,
                None => break,
            }
        }
        self.frames.pop();
        ret
    }

    fn step(&mut self, funcs: &'a [Function], fi: usize, inst: &Inst, depth: usize) -> Flow {
        match &inst.body {
            Body::Jmp(t) => Flow::Jump(*t as usize),
            Body::Branch { cond, t, f } => {
                // Branch on `condition & 1` (the low bit), not != 0.
                let c = self.value_nat(fi, cond) & 1;
                Flow::Jump(if c != 0 { *t } else { *f } as usize)
            }
            Body::Ret(None) => Flow::Return(0),
            Body::Ret(Some(op)) => {
                let v = self.arg_value(fi, op);
                Flow::Return(v)
            }
            Body::Call { api, func, args } => {
                let r = if *api {
                    let a = self.api_for(*func);
                    // Data-fabricating stubs (a lookup/alloc/decompress we answer
                    // with a fixed fail-safe value) taint any result that flows
                    // from them; record the API name so the outcome can't be
                    // silently trusted. Benign no-ops are not recorded.
                    if matches!(
                        a,
                        Api::StubNeg
                            | Api::StubNull
                            | Api::GetEnvironment
                            | Api::MatchIcon
                            | Api::FillBuffer
                    ) {
                        let name = self
                            .ctx
                            .apis
                            .iter()
                            .find(|(id, _)| *id == func.saturating_add(1))
                            .map(|(_, n)| n.clone())
                            .unwrap_or_default();
                        self.note_stub(&name);
                    }
                    self.call_api(fi, a, args)
                } else {
                    let argvals: Vec<i64> = args.iter().map(|o| self.arg_value(fi, o)).collect();
                    self.exec_fn(funcs, *func as usize, &argvals, depth + 1)
                };
                // A void call (result type 0) has no destination: its `dest`
                // field is a placeholder (0). Storing into it would clobber
                // value id 0, which for a callee with arguments is its first
                // argument (SSA result ids are always >= numArgs). Only write
                // back a non-void result.
                if inst.ty != 0 {
                    self.set(fi, inst.dest, r);
                }
                Flow::Next
            }
            Body::Gep { first, ops } => {
                let p = match ops.split_first() {
                    // GEP1/GEPZ: base + a single index.
                    Some((base, [idx])) => self.gep(fi, inst.opcode, *first, base, idx),
                    // GEPN: base then N indices; sum each scaled by the element
                    // size of `first`'s pointee (best-effort flat indexing).
                    Some((base, idxs)) => {
                        let esz = self
                            .ctx
                            .types
                            .pointee(*first)
                            .map(|p| self.ctx.types.size(p))
                            .unwrap_or(1)
                            .max(1) as i64;
                        let base = self.ptr(fi, base);
                        let delta: i64 = idxs
                            .iter()
                            .map(|o| self.value_nat(fi, o))
                            .fold(0i64, i64::wrapping_add)
                            .wrapping_mul(esz);
                        compose(ptr_region(base), ptr_off(base).wrapping_add(delta as u32))
                    }
                    None => {
                        self.flag();
                        R_NULL
                    }
                };
                self.set(fi, inst.dest, p);
                Flow::Next
            }
            Body::Ops(ops) => self.step_ops(fi, inst, ops),
        }
    }

    fn step_ops(&mut self, fi: usize, inst: &Inst, ops: &[Operand]) -> Flow {
        let opc = inst.opcode;
        match opc {
            1..=13 => {
                let bits = inst.ty;
                let (a, b) = (self.value_nat(fi, &ops[0]), self.value_nat(fi, &ops[1]));
                // Div/rem by zero: abort the bytecode (no detection).
                // Continuing with a fake quotient could reach setvirusname and
                // false-positive, so halt + discard instead.
                if matches!(opc, 4..=7) && b == 0 {
                    self.flag();
                    self.halt = true;
                    return Flow::Next;
                }
                // Signed div/rem and arithmetic-shift-right need sign-extended inputs.
                let (a, b) = if matches!(opc, 5 | 7 | 10) {
                    (sext(a, bits), sext(b, bits))
                } else {
                    (a, b)
                };
                self.set(fi, inst.dest, mask(arith(opc, a, b), bits));
            }
            OP_ICMP_FIRST..=OP_ICMP_LAST => {
                let bits = inst.ty;
                let (a, b) = (self.value_nat(fi, &ops[0]), self.value_nat(fi, &ops[1]));
                // Compare at the instruction's width: signed predicates sign-extend,
                // others zero-extend (so a 32-bit 0xFFFFFFFF is -1, not 4.29e9).
                let (a, b) = if matches!(opc, 27..=30) {
                    (sext(a, bits), sext(b, bits))
                } else {
                    (mask(a, bits), mask(b, bits))
                };
                self.set(fi, inst.dest, icmp(opc, a, b));
            }
            OP_TRUNC | OP_ZEXT => {
                let v = self.value_nat(fi, &ops[0]);
                self.set(fi, inst.dest, mask(v, inst.ty));
            }
            OP_SEXT => {
                // Sign-extend from the source operand's width to the result width.
                let src_bits = (self.op_width(fi, &ops[0]) * 8) as u32;
                let v = sext(self.value_nat(fi, &ops[0]), src_bits);
                self.set(fi, inst.dest, mask(v, inst.ty));
            }
            OP_SELECT => {
                let v = if self.value_nat(fi, &ops[0]) != 0 {
                    self.value_nat(fi, &ops[1])
                } else {
                    self.value_nat(fi, &ops[2])
                };
                self.set(fi, inst.dest, v);
            }
            OP_COPY => {
                let w = bits_to_bytes(inst.ty).max(1);
                let v = self.value(fi, &ops[0], w);
                if let Operand::Reg(dst) = ops[1] {
                    self.set(fi, dst, v);
                }
            }
            OP_LOAD => {
                let w = bits_to_bytes(inst.ty).max(1);
                let p = self.ptr(fi, &ops[0]);
                let v = self.deref_int(p, w);
                self.set(fi, inst.dest, v);
            }
            OP_STORE => {
                let w = bits_to_bytes(inst.ty).max(1);
                let v = self.value(fi, &ops[0], w);
                let p = self.ptr(fi, &ops[1]);
                self.store_int(p, w, v);
            }
            OP_MEMCPY | OP_MEMMOVE => {
                let n = self.value_nat(fi, &ops[2]).max(0) as usize;
                let dst = self.ptr(fi, &ops[0]);
                let src = self.ptr(fi, &ops[1]);
                let bytes = self.read_region(src, n);
                self.write_region(dst, &bytes);
            }
            OP_MEMSET => {
                let n = self.value_nat(fi, &ops[2]).max(0) as usize;
                let val = self.value_nat(fi, &ops[1]) as u8;
                let dst = self.ptr(fi, &ops[0]);
                self.write_region(dst, &vec![val; n.min(MAX_BYTES)]);
            }
            OP_MEMCMP => {
                let n = self.value_nat(fi, &ops[2]).max(0) as usize;
                let p1 = self.ptr(fi, &ops[0]);
                let p2 = self.ptr(fi, &ops[1]);
                let (a, b) = (self.read_region(p1, n), self.read_region(p2, n));
                let r = match a.cmp(&b) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                self.set(fi, inst.dest, r);
            }
            OP_ISBIGENDIAN => self.set(fi, inst.dest, 0), // exav targets little-endian hosts
            OP_BSWAP16 => {
                let v = self.value_nat(fi, &ops[0]) as u16;
                self.set(fi, inst.dest, v.swap_bytes() as i64);
            }
            OP_BSWAP32 => {
                let v = self.value_nat(fi, &ops[0]) as u32;
                self.set(fi, inst.dest, v.swap_bytes() as i64);
            }
            OP_BSWAP64 => {
                let v = self.value_nat(fi, &ops[0]);
                self.set(fi, inst.dest, (v as u64).swap_bytes() as i64);
            }
            OP_PTRTOINT64 => {
                let p = self.ptr(fi, &ops[0]);
                self.set(fi, inst.dest, p);
            }
            OP_PTRDIFF32 => {
                let p1 = self.ptr(fi, &ops[0]);
                let p2 = self.ptr(fi, &ops[1]);
                let d = if ptr_region(p1) == ptr_region(p2) {
                    i64::from(ptr_off(p1)) - i64::from(ptr_off(p2))
                } else {
                    self.flag();
                    0
                };
                self.set(fi, inst.dest, d);
            }
            // ClamAV fails the run here and drops its virus name.
            OP_ABORT => {
                self.flag();
                return Flow::Return(0);
            }
            _ => self.gap(), // any remaining op needs more modeling
        }
        Flow::Next
    }
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `version_compare`: compare dotted version strings numerically.
fn version_compare(l: &[u8], r: &[u8]) -> i64 {
    let (mut i, mut j) = (0usize, 0usize);
    loop {
        while i < l.len()
            && j < r.len()
            && l[i] == r[j]
            && !l[i].is_ascii_digit()
            && !r[j].is_ascii_digit()
        {
            i += 1;
            j += 1;
        }
        if i == l.len() && j == r.len() {
            return 0;
        }
        if i == l.len() {
            return -1;
        }
        if j == r.len() {
            return 1;
        }
        if !l[i].is_ascii_digit() || !r[j].is_ascii_digit() {
            return if l[i] < r[j] { -1 } else { 1 };
        }
        let (mut li, mut ri) = (0u64, 0u64);
        while i < l.len() && l[i].is_ascii_digit() {
            li = li.saturating_mul(10).saturating_add((l[i] - b'0') as u64);
            i += 1;
        }
        while j < r.len() && r[j].is_ascii_digit() {
            ri = ri.saturating_mul(10).saturating_add((r[j] - b'0') as u64);
            j += 1;
        }
        if li != ri {
            return if li < ri { -1 } else { 1 };
        }
    }
}

fn read_le(buf: &[u8], off: usize, w: usize) -> Option<i64> {
    let slice = buf.get(off..off.checked_add(w)?)?;
    let mut v = 0u64;
    for (i, &b) in slice.iter().enumerate() {
        v |= u64::from(b) << (8 * i);
    }
    Some(v as i64)
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    memchr::memmem::find(hay, needle)
}

fn mask(v: i64, bits: u32) -> i64 {
    if bits == 0 || bits >= 64 {
        v
    } else {
        (v as u64 & ((1u64 << bits) - 1)) as i64
    }
}

/// Sign-extend the low `bits` of `v` to a full `i64`.
fn sext(v: i64, bits: u32) -> i64 {
    if bits == 0 || bits >= 64 {
        v
    } else {
        let shift = 64 - bits;
        (v << shift) >> shift // arithmetic shift carries the sign
    }
}

fn icmp(op: u8, a: i64, b: i64) -> i64 {
    let (ua, ub) = (a as u64, b as u64);
    let r = match op {
        21 => a == b,
        22 => a != b,
        23 => ua > ub,
        24 => ua >= ub,
        25 => ua < ub,
        26 => ua <= ub,
        27 => a > b,
        28 => a >= b,
        29 => a <= b,
        30 => a < b,
        _ => false,
    };
    r as i64
}

fn arith(op: u8, a: i64, b: i64) -> i64 {
    match op {
        1 => a.wrapping_add(b),
        2 => a.wrapping_sub(b),
        3 => a.wrapping_mul(b),
        4 => (a as u64).checked_div(b as u64).unwrap_or(0) as i64,
        5 => a.checked_div(b).unwrap_or(0),
        6 => (a as u64).checked_rem(b as u64).unwrap_or(0) as i64,
        7 => a.checked_rem(b).unwrap_or(0),
        8 => a.wrapping_shl(b as u32),
        9 => ((a as u64) >> (b as u32 & 63)) as i64,
        10 => a >> (b as u32 & 63),
        11 => a & b,
        12 => a | b,
        13 => a ^ b,
        _ => 0,
    }
}

/// Lay out a function's value buffer: assign each value an aligned byte offset.
fn layout(f: &Function, types: &TypeTable) -> (Rc<[Slot]>, usize) {
    let mut slots = Vec::with_capacity(f.types.len());
    let mut bytes = 0usize;
    for &ty in &f.types {
        let align = types.align(ty).max(1);
        let size = types.size(ty).max(1);
        bytes = bytes.saturating_add(align - 1) & !(align - 1);
        slots.push(Slot {
            off: bytes as u32,
            w: type_bytes(ty).max(1) as u32,
        });
        bytes = bytes.saturating_add(size);
    }
    bytes = bytes.saturating_add(7) & !7;
    (slots.into(), bytes)
}

/// `ctx`'s declared APIs, resolved by name.
fn resolve_apis(ctx: &Ctx) -> Vec<(u32, Api)> {
    ctx.apis.iter().map(|(id, n)| (*id, api_of(n))).collect()
}

/// Run `entry` over `ctx`. Bounded; call inside `catch_unwind` for isolation.
pub fn run(funcs: &[Function], entry: usize, ctx: &Ctx) -> Outcome {
    run_inner(funcs, entry, ctx, false)
}

/// [`run`] over a PE whose header data `ctx.pe` lacks (too large to load, or
/// rejected by exav's parser): reading `__clambc_pedata` is then a gap.
pub fn run_without_pe_data(funcs: &[Function], entry: usize, ctx: &Ctx) -> Outcome {
    run_inner(funcs, entry, ctx, true)
}

fn run_inner(funcs: &[Function], entry: usize, ctx: &Ctx, pe_missing: bool) -> Outcome {
    let gcache: Vec<Vec<u8>> = ctx
        .globals
        .values
        .iter()
        .map(|v| v.iter().map(|&c| c as u8).collect())
        .collect();
    let mut m = Machine {
        ctx,
        frames: Vec::new(),
        layouts: Vec::new(),
        apis: resolve_apis(ctx),
        gcache,
        heaps: Vec::new(),
        extract_cur: Vec::new(),
        extracted: Vec::new(),
        written: 0,
        limited: false,
        cursor: 0,
        detection: None,
        steps: 0,
        unsupported: false,
        gap: false,
        halt: false,
        pe_missing,
        stubbed: std::collections::BTreeSet::new(),
        trace: std::env::var_os("EXAV_DEBUG_BC_TRACE").is_some(),
        trace_fn: std::env::var("EXAV_DEBUG_BC_FN")
            .ok()
            .and_then(|s| s.parse().ok()),
    };
    m.exec_fn(funcs, entry, &[], 0);
    // Flush whatever the program wrote but never explicitly finalized.
    //
    // `extract_new` finalizes a buffer, but a program is not obliged to call it:
    // in ClamAV, `write` appends to an implicitly-opened tempfile that gets
    // scanned when the program ends, so an unpacker that writes its output and
    // returns is complete and correct. Requiring the explicit call meant exav
    // ran ClamAV's MPRESS unpacker to completion, received the full 994 KB
    // decompressed image through `write`, and then discarded it. The payload
    // was recovered and thrown away, and the file scanned clean.
    if !m.extract_cur.is_empty() {
        m.extracted.push(std::mem::take(&mut m.extract_cur));
    }
    Outcome {
        detection: m.detection,
        steps: m.steps,
        hit_unsupported: m.unsupported,
        incomplete: m.steps > MAX_STEPS || m.gap || m.limited,
        extracted: m.extracted,
        stubbed: m.stubbed.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::instr::{
        Body, Function, Inst, OP_BRANCH, OP_CALL_API, OP_JMP, OP_RET, OP_RET_VOID,
    };
    use crate::bytecode::types::{Globals, TypeTable};

    fn detector() -> Vec<Function> {
        let blocks = vec![
            vec![
                Inst {
                    opcode: 33,
                    dest: 2,
                    ty: 32,
                    body: Body::Call {
                        api: true,
                        func: 0, /* global id 1: file_byteat */
                        args: vec![Operand::Const(0)],
                    },
                },
                Inst {
                    opcode: 21,
                    dest: 3,
                    ty: 8,
                    body: Body::Ops(vec![Operand::Reg(2), Operand::Const(0x4d)]),
                },
                Inst {
                    opcode: OP_BRANCH,
                    dest: 0,
                    ty: 0,
                    body: Body::Branch {
                        cond: Operand::Reg(3),
                        t: 1,
                        f: 2,
                    },
                },
            ],
            vec![
                Inst {
                    opcode: 33,
                    dest: 4,
                    ty: 32,
                    body: Body::Call {
                        api: true,
                        func: 1, /* global id 2: setvirusname */
                        args: vec![],
                    },
                },
                Inst {
                    opcode: OP_RET_VOID,
                    dest: 0,
                    ty: 0,
                    body: Body::Ret(None),
                },
            ],
            vec![Inst {
                opcode: OP_RET_VOID,
                dest: 0,
                ty: 0,
                body: Body::Ret(None),
            }],
        ];
        vec![Function {
            num_args: 0,
            return_type: 0,
            types: vec![32, 32, 32, 1, 32],
            num_insts: 6,
            num_bb: 3,
            blocks,
        }]
    }

    fn apis() -> Vec<(u32, String)> {
        vec![(1, "file_byteat".into()), (2, "setvirusname".into())]
    }

    fn ctx<'a>(
        file: &'a dyn ByteSource,
        apis: &'a [(u32, String)],
        globals: &'a Globals,
        types: &'a TypeTable,
    ) -> Ctx<'a> {
        Ctx {
            file,
            flevel: 110,
            types,
            globals,
            pe: None,
            pdf: None,
            match_offsets: &[],
            apis,
            default_name: "Test.BC.Found",
            write_limits: WriteLimits::NONE,
        }
    }

    fn machine<'a>(c: &'a Ctx<'a>) -> Machine<'a> {
        Machine {
            ctx: c,
            frames: vec![Frame {
                vtypes: &[],
                slots: Rc::from([]),
                stack: vec![],
            }],
            layouts: Vec::new(),
            apis: resolve_apis(c),
            gcache: c
                .globals
                .values
                .iter()
                .map(|v| v.iter().map(|&x| x as u8).collect())
                .collect(),
            heaps: Vec::new(),
            extract_cur: Vec::new(),
            extracted: Vec::new(),
            written: 0,
            limited: false,
            cursor: 0,
            detection: None,
            steps: 0,
            unsupported: false,
            gap: false,
            halt: false,
            pe_missing: false,
            stubbed: std::collections::BTreeSet::new(),
            trace: false,
            trace_fn: None,
        }
    }

    #[test]
    fn frame_memory_reads_back_every_width() {
        let (apis, globals, types) = (apis(), Globals::default(), TypeTable::default());
        let c = ctx(b"", &apis, &globals, &types);
        let mut m = machine(&c);
        for w in 1..=8usize {
            m.frames[0].stack = vec![0xAA; 16];
            m.wr_mem(0, 3, w, 0x0807_0605_0403_0201);
            let want = (0x0807_0605_0403_0201u64 & (u64::MAX >> (64 - 8 * w))) as i64;
            assert_eq!(m.rd_mem(0, 3, w), want, "width {w}");
            assert_eq!(m.frames[0].stack[2], 0xAA, "width {w}");
            assert_eq!(m.frames[0].stack[3 + w], 0xAA, "width {w}");
            assert!(!m.unsupported);
            assert_eq!(m.rd_mem(0, 17 - w as u32, w), 0, "width {w} past the end");
            assert!(m.unsupported);
            m.unsupported = false;
        }
    }

    /// An index is the program's own number: scaled past `i64`, it wraps as
    /// the address does, and does not stop the program.
    #[test]
    fn a_pointer_index_scaled_past_i64_wraps() {
        let (apis, globals, types) = (apis(), Globals::default(), TypeTable::default());
        let c = ctx(b"", &apis, &globals, &types);
        let mut m = machine(&c);
        // `i64*`: eight bytes an element.
        let p = m.gep(
            0,
            OP_GEP1,
            0x8000 | 64,
            &Operand::Const(0),
            &Operand::Const(i64::MAX as u64),
        );
        assert_eq!(ptr_off(p), (i64::MAX.wrapping_mul(8)) as u32);
        assert!(!m.unsupported);
    }

    #[test]
    fn detects_on_match() {
        let (apis, globals, types) = (apis(), Globals::default(), TypeTable::default());
        let out = run(&detector(), 0, &ctx(b"MZ...", &apis, &globals, &types));
        assert_eq!(out.detection.as_deref(), Some("Test.BC.Found"));
    }

    #[test]
    fn clean_on_no_match() {
        let (apis, globals, types) = (apis(), Globals::default(), TypeTable::default());
        let out = run(&detector(), 0, &ctx(b"ELF", &apis, &globals, &types));
        assert!(out.detection.is_none());
    }

    // A void call has dest=0 as a placeholder; storing its (void) result must
    // NOT clobber value id 0, which in the callee is its first argument. This
    // bug nulled pointer arguments across a void call and broke any program
    // that called a void helper while holding a live arg (e.g. unpackers).
    #[test]
    fn void_call_does_not_clobber_first_arg() {
        // fn1(arg0): call void fn2(); return arg0.  fn2(): retvoid.
        // entry fn0: r = fn1(0x4d); detect iff r == 0x4d (arg survived).
        let fn0 = Function {
            num_args: 0,
            return_type: 32,
            types: vec![32, 1],
            num_insts: 5,
            num_bb: 3,
            blocks: vec![
                vec![
                    Inst {
                        opcode: 32,
                        dest: 0,
                        ty: 32,
                        body: Body::Call {
                            api: false,
                            func: 1,
                            args: vec![Operand::Const(0x4d)],
                        },
                    },
                    Inst {
                        opcode: 21,
                        dest: 1,
                        ty: 8,
                        body: Body::Ops(vec![Operand::Reg(0), Operand::Const(0x4d)]),
                    },
                    Inst {
                        opcode: OP_BRANCH,
                        dest: 0,
                        ty: 0,
                        body: Body::Branch {
                            cond: Operand::Reg(1),
                            t: 1,
                            f: 2,
                        },
                    },
                ],
                vec![
                    Inst {
                        opcode: 33,
                        dest: 0,
                        ty: 32,
                        body: Body::Call {
                            api: true,
                            func: 0,
                            args: vec![],
                        },
                    },
                    Inst {
                        opcode: OP_RET_VOID,
                        dest: 0,
                        ty: 0,
                        body: Body::Ret(None),
                    },
                ],
                vec![Inst {
                    opcode: OP_RET_VOID,
                    dest: 0,
                    ty: 0,
                    body: Body::Ret(None),
                }],
            ],
        };
        let fn1 = Function {
            num_args: 1,
            return_type: 32,
            types: vec![32],
            num_insts: 2,
            num_bb: 1,
            blocks: vec![vec![
                // void call to fn2 (dest=0, ty=0): must not overwrite Reg0 (arg).
                Inst {
                    opcode: 32,
                    dest: 0,
                    ty: 0,
                    body: Body::Call {
                        api: false,
                        func: 2,
                        args: vec![],
                    },
                },
                Inst {
                    opcode: 19,
                    dest: 0,
                    ty: 32,
                    body: Body::Ret(Some(Operand::Reg(0))),
                },
            ]],
        };
        let fn2 = Function {
            num_args: 0,
            return_type: 0,
            types: vec![],
            num_insts: 1,
            num_bb: 1,
            blocks: vec![vec![Inst {
                opcode: OP_RET_VOID,
                dest: 0,
                ty: 0,
                body: Body::Ret(None),
            }]],
        };
        let apis = vec![(1, "setvirusname".to_string())];
        let (globals, types) = (Globals::default(), TypeTable::default());
        let out = run(&[fn0, fn1, fn2], 0, &ctx(b"", &apis, &globals, &types));
        assert_eq!(out.detection.as_deref(), Some("Test.BC.Found"));
    }

    /// What the interpreter cannot model leaves the program's answer unknown,
    /// so the run is incomplete. A program's own failure (a division by zero)
    /// ends it as it would in ClamAV: discarded, not incomplete.
    #[test]
    fn an_unmodeled_step_is_incomplete_a_program_fault_is_not() {
        let one = |inst: Inst| {
            vec![Function {
                num_args: 0,
                return_type: 0,
                types: vec![32],
                num_insts: 2,
                num_bb: 1,
                blocks: vec![vec![
                    inst,
                    Inst {
                        opcode: OP_RET,
                        dest: 0,
                        ty: 0,
                        body: Body::Ret(None),
                    },
                ]],
            }]
        };
        let (apis, globals, types) = (Vec::new(), Globals::default(), TypeTable::default());
        let c = ctx(b"", &apis, &globals, &types);
        let unmodeled = one(Inst {
            opcode: 250,
            dest: 0,
            ty: 32,
            body: Body::Ops(vec![]),
        });
        let unknown_api = one(Inst {
            opcode: OP_CALL_API,
            dest: 0,
            ty: 32,
            body: Body::Call {
                api: true,
                func: 7,
                args: vec![],
            },
        });
        let div_zero = one(Inst {
            opcode: 4,
            dest: 0,
            ty: 32,
            body: Body::Ops(vec![Operand::Const(1), Operand::Const(0)]),
        });
        for (name, funcs, incomplete) in [
            ("unmodeled op", unmodeled, true),
            ("unknown API", unknown_api, true),
            ("division by zero", div_zero, false),
        ] {
            let out = run(&funcs, 0, &c);
            assert!(out.hit_unsupported, "{name}");
            assert_eq!(out.incomplete, incomplete, "{name}");
        }
    }

    /// A program's own fault ends its run there: it cannot carry on into a
    /// step exav does not model and make the scan incomplete after all.
    #[test]
    fn a_program_fault_ends_the_run() {
        let inst = |opcode, body| Inst {
            opcode,
            dest: 0,
            ty: 32,
            body,
        };
        let funcs = vec![Function {
            num_args: 0,
            return_type: 0,
            types: vec![32],
            num_insts: 3,
            num_bb: 1,
            blocks: vec![vec![
                // A value the function does not have: out of bounds.
                inst(1, Body::Ops(vec![Operand::Reg(99), Operand::Const(1)])),
                inst(250, Body::Ops(vec![])),
                inst(OP_RET, Body::Ret(None)),
            ]],
        }];
        let (apis, globals, types) = (Vec::new(), Globals::default(), TypeTable::default());
        let out = run(&funcs, 0, &ctx(b"", &apis, &globals, &types));
        assert!(out.hit_unsupported);
        assert!(!out.incomplete, "the fault ended the run before the unmodeled op");
    }

    /// An abort after `setvirusname` fails the run in ClamAV: the name is
    /// dropped, and the run is not incomplete.
    #[test]
    fn an_abort_discards_the_detection() {
        let inst = |opcode, body| Inst {
            opcode,
            dest: 0,
            ty: 32,
            body,
        };
        let funcs = vec![Function {
            num_args: 0,
            return_type: 0,
            types: vec![32],
            num_insts: 3,
            num_bb: 1,
            blocks: vec![vec![
                inst(
                    OP_CALL_API,
                    Body::Call {
                        api: true,
                        func: 0,
                        args: vec![],
                    },
                ),
                inst(OP_ABORT, Body::Ops(vec![])),
                inst(OP_RET, Body::Ret(None)),
            ]],
        }];
        let apis = vec![(1, "setvirusname".to_string())];
        let (globals, types) = (Globals::default(), TypeTable::default());
        let out = run(&funcs, 0, &ctx(b"", &apis, &globals, &types));
        assert_eq!(out.detection.as_deref(), Some("Test.BC.Found"));
        assert!(out.hit_unsupported);
        assert!(!out.incomplete);
    }

    /// Bytes `disasm_x86` cannot decode end the run there, so nothing the
    /// program writes after it is kept as output.
    #[test]
    fn an_undecoded_instruction_ends_the_run() {
        let (apis, globals, types) = (apis(), Globals::default(), TypeTable::default());
        let c = ctx(b"", &apis, &globals, &types);
        let mut m = machine(&c);
        assert_eq!(m.call_api(0, Api::DisasmX86, &[]), -1);
        assert!(m.unsupported && m.halt && !m.gap);
    }

    /// `malloc` returns NULL where ClamAV's does, and the program sees it.
    #[test]
    fn malloc_past_clamav_limit_is_null() {
        let (apis, globals, types) = (apis(), Globals::default(), TypeTable::default());
        let c = ctx(b"", &apis, &globals, &types);
        let mut m = machine(&c);
        assert_ne!(m.call_api(0, Api::Malloc, &[Operand::Const(MAX_MALLOC as u64)]), 0);
        assert_eq!(m.call_api(0, Api::Malloc, &[Operand::Const(MAX_MALLOC as u64 + 1)]), 0);
        assert!(!m.unsupported && !m.gap);
    }

    /// Output past exav's own cap is not dropped silently: the run stops
    /// as incomplete.
    #[test]
    fn write_past_the_extraction_cap_is_a_gap() {
        let globals = Globals {
            values: vec![vec![0, 1], vec![0x41, 0x42]],
        };
        let (apis, types) = (apis(), TypeTable::default());
        let c = ctx(b"", &apis, &globals, &types);
        let mut m = machine(&c);
        let args = [Operand::Global(0), Operand::Const(2)];
        m.extract_cur = vec![0; MAX_ALLOC - 2];
        assert_eq!(m.call_api(0, Api::Write, &args), 2);
        assert!(!m.gap);
        assert_eq!(m.call_api(0, Api::Write, &args), -1);
        assert_eq!(m.extract_cur.len(), MAX_ALLOC);
        assert!(m.gap && m.halt);
    }

    /// A `write` past the scan's limits, on one output file or on all of a
    /// run's, fails and the run goes on, as in ClamAV; the scan is then
    /// incomplete.
    #[test]
    fn write_past_the_scan_limits_fails_and_the_run_goes_on() {
        let globals = Globals {
            values: vec![vec![0, 1], vec![0x41, 0x42, 0x43]],
        };
        let (apis, types) = (apis(), TypeTable::default());
        let args = [Operand::Global(0), Operand::Const(3)];
        // Three bytes to one file, seven in all.
        let c = Ctx {
            write_limits: WriteLimits { file: 3, total: 7 },
            ..ctx(b"", &apis, &globals, &types)
        };
        let mut m = machine(&c);
        assert_eq!(m.call_api(0, Api::Write, &args), 3);
        assert_eq!(m.call_api(0, Api::Write, &args), -1, "past one file's limit");
        assert!(m.limited && !m.halt && !m.gap && !m.unsupported);
        m.call_api(0, Api::ExtractNew, &[]);
        assert_eq!(m.call_api(0, Api::Write, &args), 3);
        m.call_api(0, Api::ExtractNew, &[]);
        assert_eq!(m.call_api(0, Api::Write, &args), -1, "past the run's limit");
        assert_eq!(m.call_api(0, Api::Write, &[Operand::Global(0), Operand::Const(1)]), 1);
        assert_eq!(m.extracted, vec![b"ABC".to_vec(), b"ABC".to_vec()]);
        assert_eq!(m.extract_cur, b"A");
        assert!(!m.halt);
    }

    /// On a file that is not a PE, `__clambc_pedata` reads as zeros up to its
    /// size, as in ClamAV; past it is out of bounds. On a PE whose header data
    /// exav lacks, reading it is a gap.
    #[test]
    fn pedata_without_a_pe() {
        let pe = crate::pe::bytecode_pe(include_bytes!("../../tests/testdata/tiny_pe32.exe"));
        assert_eq!(pe.expect("tiny PE parses").pedata.len(), PEDATA_LEN);
        let (apis, globals, types) = (apis(), Globals::default(), TypeTable::default());
        let c = ctx(b"not a PE", &apis, &globals, &types);
        let mut m = machine(&c);
        assert_eq!(m.deref_int(compose(R_PEDATA, 4), 4), 0);
        assert_eq!(m.deref_int(compose(R_PEDATA, PEDATA_LEN as u32 - 4), 4), 0);
        assert_eq!(m.read_region(compose(R_PEDATA, 0), 8), vec![0; 8]);
        assert!(!m.unsupported);
        m.deref_int(compose(R_PEDATA, PEDATA_LEN as u32 - 3), 4);
        assert!(m.unsupported && !m.gap);

        // An `MZ` file exav does not take for a PE reads zeros too.
        let c = ctx(b"MZ\x90\x00", &apis, &globals, &types);
        let mut m = machine(&c);
        assert_eq!(m.deref_int(compose(R_PEDATA, 4), 4), 0);
        assert!(!m.unsupported);

        let mut m = machine(&c);
        m.pe_missing = true;
        assert_eq!(m.deref_int(compose(R_PEDATA, 4), 4), 0);
        assert!(m.gap);
    }

    #[test]
    fn infinite_loop_is_bounded() {
        let blocks = vec![vec![Inst {
            opcode: OP_JMP,
            dest: 0,
            ty: 0,
            body: Body::Jmp(0),
        }]];
        let funcs = vec![Function {
            num_args: 0,
            return_type: 0,
            types: vec![],
            num_insts: 1,
            num_bb: 1,
            blocks,
        }];
        let (apis, globals, types) = (Vec::new(), Globals::default(), TypeTable::default());
        let out = run(&funcs, 0, &ctx(b"", &apis, &globals, &types));
        assert!(out.steps <= MAX_STEPS + 1);
        assert!(out.detection.is_none());
        assert!(out.incomplete, "a program cut short is not one that found nothing");
    }

    #[test]
    fn resolves_global_string() {
        let globals = Globals {
            values: vec![vec![0], vec![69, 105, 99, 97, 114, 0], vec![0, 1]],
        };
        let (apis, types) = (Vec::<(u32, String)>::new(), TypeTable::default());
        let c = ctx(b"", &apis, &globals, &types);
        let mut m = machine(&c);
        let p = m.global_ptr(2);
        assert_eq!(m.read_cstring(p).as_deref(), Some("Eicar"));
    }

    #[test]
    fn resolves_filesize_global() {
        let globals = Globals {
            values: vec![vec![0, GLOBAL_FILESIZE]],
        };
        let (apis, types) = (Vec::<(u32, String)>::new(), TypeTable::default());
        let c = ctx(b"12345678", &apis, &globals, &types);
        let mut m = machine(&c);
        let p = m.global_ptr(0);
        assert_eq!(m.deref_int(p, 4), 8);
    }

    #[test]
    fn find_sub_works() {
        assert_eq!(find_sub(b"hello world", b"world"), Some(6));
        assert_eq!(find_sub(b"hello", b"xyz"), None);
    }

    /// The object table as it was computed over a slice, before the file was a
    /// source.
    fn slice_pdf_objs(data: &[u8]) -> Vec<(u32, u32)> {
        let mut objs = Vec::new();
        for pos in memchr::memmem::find_iter(data, b" obj") {
            let mut i = pos;
            let back_digits = |i: &mut usize| {
                let s = *i;
                while *i > 0 && data[*i - 1].is_ascii_digit() {
                    *i -= 1;
                }
                s != *i
            };
            if !back_digits(&mut i) || i == 0 || data[i - 1] != b' ' {
                continue;
            }
            i -= 1;
            let id_end = i;
            if !back_digits(&mut i) || id_end == i {
                continue;
            }
            let id: u32 = std::str::from_utf8(&data[i..id_end])
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            objs.push((id, i as u32));
        }
        objs.sort_by_key(|&(_, start)| start);
        objs
    }

    fn pdf_like() -> Vec<u8> {
        let mut d = b"%PDF-1.7\n1 0 obj\n".to_vec();
        d.extend_from_slice(b"x 12 0 obj 4294967295 0 obj 4294967297 3 obj");
        d.extend_from_slice(b" 00000000000000000000000000000000000000000000000000000000000000000000000000000000007 0 obj");
        d.extend_from_slice(b" 100000000000000000000000000000000000000000000000000000000000000000000000000000000000 1 obj");
        d.extend_from_slice(b"nospace0 obj 5  0 obj  obj 0 obj 9 obj");
        let mut long = vec![b'1'; 3 * CHUNK];
        long.extend_from_slice(b" 0 obj");
        d.extend_from_slice(&long);
        d.extend_from_slice(b" 42 7 obj");
        d
    }

    #[test]
    fn the_pdf_object_table_is_the_same_read_in_blocks() {
        let d = pdf_like();
        let want = slice_pdf_objs(&d);
        assert!(want.len() >= 6, "the table must hold what the input plants: {want:?}");
        let cache = crate::byte_source::BlockCache::with_sizes(std::io::Cursor::new(d.clone()), 5, 20)
            .unwrap();
        assert_eq!(pdf_ctx(&d).objs, want);
        assert_eq!(pdf_ctx(&cache).objs, want);
    }

    /// `read_number` as it was over a slice.
    fn slice_read_number(file: &[u8], cursor: usize, radix: u32) -> (i64, usize) {
        let is_digit = |b: u8| b.is_ascii_digit() || (radix == 16 && b.is_ascii_hexdigit());
        let Some(start) = (cursor..file.len()).find(|&i| is_digit(file[i])) else {
            return (-1, cursor);
        };
        let mut end = start;
        while end < file.len() && is_digit(file[end]) {
            end += 1;
        }
        let v = std::str::from_utf8(&file[start..end])
            .ok()
            .and_then(|s| i64::from_str_radix(s, radix).ok())
            .unwrap_or(0);
        (v, end)
    }

    #[test]
    fn read_number_reads_what_it_read_over_a_slice() {
        let mut d = b"abc 123 x 0x7fffffffffffffff z 9223372036854775807 9223372036854775808 ".to_vec();
        d.extend_from_slice(b"FfEe 00000000000000000000000000000000000000000000042 q");
        d.extend(std::iter::repeat_n(b'5', 3 * CHUNK));
        d.extend_from_slice(b" 77");
        let (apis, globals, types) = (Vec::<(u32, String)>::new(), Globals::default(), TypeTable::default());
        let cache = crate::byte_source::BlockCache::with_sizes(std::io::Cursor::new(d.clone()), 3, 12)
            .unwrap();
        for radix in [10, 16] {
            for src in [&d as &dyn ByteSource, &cache] {
                let c = Ctx {
                    file: src,
                    ..ctx(&d, &apis, &globals, &types)
                };
                let mut m = machine(&c);
                let mut cursor = 0;
                loop {
                    let want = slice_read_number(&d, cursor, radix);
                    m.cursor = cursor;
                    let got = m.read_number(radix);
                    assert_eq!((got, m.cursor), want, "radix {radix} from {cursor}");
                    if want.0 == -1 {
                        break;
                    }
                    cursor = want.1;
                }
            }
        }
    }
}
