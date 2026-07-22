//! The driver: run a packer stub under the interpreter and capture the image
//! it rebuilds.
//!
//! ## When to stop and take the picture
//!
//! Every runtime packer, whatever it compresses with, ends the same way: it
//! finishes writing the original image into memory and transfers control to the
//! original entry point. That transfer is the moment the payload exists in the
//! clear, and it has a signature the emulator can recognise without knowing
//! anything about the packer:
//!
//! > execution arrives at an address inside the image, in a **different
//! > section** from the one the stub started in, on a page **the stub itself
//! > wrote**.
//!
//! Both halves matter. "Different section" alone would fire on the stub calling
//! a helper; "written page" alone would fire on the stub's own scratch data. A
//! page that the stub produced *and* then executed is the original code.
//!
//! ## When the stub does not get there
//!
//! Stubs defend themselves, and some will not run to completion here: an
//! instruction the interpreter does not implement, a Windows API it does not
//! provide, a deliberate fault. That is reported, not hidden — and if the run
//! still rewrote a meaningful part of the image, the partial reconstruction is
//! offered separately from a clean one, because a half-decompressed image is
//! worth scanning but is not the same claim as "this is the original program".
//!
//! ## Exceptions
//!
//! Faults are delivered to the stub's own SEH chain rather than ending the run,
//! because throwing an exception at itself and continuing from the handler is a
//! standard anti-emulation move (PESpin, Yoda's Protector, tElock). The
//! emulator builds the `EXCEPTION_RECORD` and `CONTEXT` on the stack, calls the
//! handler, and resumes from the context the handler leaves behind — including
//! any registers or instruction pointer it edited, which is exactly the
//! mechanism those stubs are using.

use crate::cpu::{Cpu, Stop, EAX, EBX, ESP};
use crate::image::PeImage;
use crate::mem::{Mem, PAGE_SIZE};
use crate::win::{ApiEffect, Env, INITIAL_ESP, TEB_BASE};

/// Windows exception codes the emulator can raise.
const STATUS_ACCESS_VIOLATION: u32 = 0xc000_0005;
const STATUS_BREAKPOINT: u32 = 0x8000_0003;
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xc000_001d;
const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xc000_0094;
const STATUS_INTEGER_OVERFLOW: u32 = 0xc000_0095;
const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xc000_0096;
const STATUS_SINGLE_STEP: u32 = 0x8000_0004;

/// Size of the x86 `CONTEXT` structure.
const CONTEXT_SIZE: u32 = 0x2cc;
/// Size of `EXCEPTION_RECORD`.
const EXC_RECORD_SIZE: u32 = 0x50;

/// How much of the image a run that never reached an entry point must have
/// rewritten before its partial reconstruction is worth reporting.
const MIN_PARTIAL_DIRTY: u64 = 64 * 1024;

/// How much of the image must have been rebuilt before a jump into it can be
/// the original entry point. Obfuscated programs — not packed ones — write a
/// jump table into another section and transfer through it after a few hundred
/// instructions; without a floor, that is indistinguishable from an unpack.
const MIN_UNPACK_DIRTY: u64 = 32 * 1024;

/// How long a run may go without writing a page it has not written before.
/// Sized so a slow but genuine decompressor — which produces output steadily —
/// never trips it, while a spin loop is cut off in a fraction of a second.
const PROGRESS_WINDOW: u64 = 8_000_000;

/// How many distinct pages a run must write within one progress window to
/// count as still unpacking. A sweep over a destination lights up far more than
/// this; a spin loop hammering one address lights up one.
const MIN_WRITE_SPREAD: u32 = 6;

/// How many calls to unimplemented exports a run may make before it is treated
/// as no longer following the program. Each one leaves the stack potentially
/// skewed, so a run that makes many of them is not executing anything real.
const MAX_UNIMPLEMENTED_CALLS: u32 = 64;

/// Everything that bounds a run.
///
/// This is the sandbox's contract. The emulator follows control flow supplied
/// by the file being scanned — the one place in exav where hostile input
/// decides what executes next rather than what gets parsed — so every way a
/// run can end is a number here, and a run that hits any of them stops and
/// reports rather than continuing on a guess.
///
/// An embedder should set these deliberately. [`Default`] is tuned for the scan
/// path, where the emulator is one stage among many and a stub that misbehaves
/// should cost little; a triage tool that wants to watch a single sample to its
/// conclusion will want larger budgets and `trace` on.
///
/// The bounds are independent, and a stub defeats the emulator by reaching any
/// one of them. Raising a single limit rarely changes an outcome on its own.
pub struct EmuLimits {
    /// Instruction budget. A `rep` counts its iterations, so this bounds work,
    /// not instruction *count* — a stub cannot buy time with one long `rep`.
    pub max_ticks: u64,
    /// Resident-page cap for the whole address space.
    pub max_pages: usize,
    /// Largest dump to build.
    pub max_dump: usize,
    /// How much of the image must have been rebuilt before a jump into it can
    /// be the original entry point (`MIN_UNPACK_DIRTY`).
    pub min_unpack_dirty: u64,
    /// How much must have been rebuilt before a run that never reached an entry
    /// point reports its partial reconstruction (`MIN_PARTIAL_DIRTY`).
    pub min_partial_dirty: u64,
    /// Record the instructions leading up to the stop. Off on the scan path
    /// (it costs a formatted string per instruction); the triage tool turns it
    /// on, and it is the difference between "faulted at 0x2f4e0" and knowing
    /// which instruction computed that address.
    pub trace: bool,
}

impl Default for EmuLimits {
    fn default() -> Self {
        Self {
            // Enough for a multi-megabyte image through a byte-at-a-time
            // decompressor, and small enough that a stub which loops forever
            // costs a bounded amount of CPU.
            max_ticks: 200_000_000,
            // 192 MiB of emulated memory.
            max_pages: 48 * 1024,
            max_dump: 64 << 20,
            min_unpack_dirty: MIN_UNPACK_DIRTY,
            min_partial_dirty: MIN_PARTIAL_DIRTY,
            trace: false,
        }
    }
}

/// How many instructions the trace keeps.
const TRACE_LEN: usize = 48;

/// The image a stub rebuilt.
pub struct Unpacked {
    /// The reconstructed PE, in memory layout.
    pub data: Vec<u8>,
    /// Entry point of the recovered program, as an RVA.
    pub oep_rva: u32,
    /// Whether the stub actually transferred control to it. False means the run
    /// stopped early and this is what had been rebuilt by then.
    pub reached_oep: bool,
}

/// Outcome of one emulation, including the diagnostics that make a stub which
/// did *not* unpack actionable.
pub struct Report {
    pub unpacked: Option<Unpacked>,
    /// Why the run ended, in a form fit for a log line.
    pub stop: String,
    pub ticks: u64,
    /// Exports the stub called that the emulator does not implement.
    pub missing_apis: Vec<String>,
    /// Bytes of the image the stub rewrote.
    pub dirty_bytes: u64,
    /// PE images found in memory the stub allocated. Independent of
    /// `unpacked`: a loader that never writes to its own image produces these
    /// and nothing else.
    pub extra: Vec<Vec<u8>>,
    /// The last instructions executed, when tracing was on.
    pub tail: Vec<String>,
    /// Every Windows call the run made, when tracing was on.
    pub api_calls: Vec<String>,
    /// An x87 instruction outside the emulated subset was skipped.
    ///
    /// Comparisons and transcendentals are not emulated. A stub that computed
    /// with them reached its result by a path this run did not follow, so
    /// whatever it produced afterwards rests on registers that were never
    /// updated. The dump is still offered — it is usually still the payload —
    /// but a caller weighing how much to trust it, or triaging why an unpack
    /// came out wrong, needs to know the arithmetic was incomplete.
    pub fpu_approximated: bool,
}

/// Run the stub of `file` and report what it produced.
pub fn unpack(file: &[u8], limits: &EmuLimits) -> Report {
    let mut report = Report {
        unpacked: None,
        stop: String::new(),
        ticks: 0,
        missing_apis: Vec::new(),
        dirty_bytes: 0,
        extra: Vec::new(),
        tail: Vec::new(),
        api_calls: Vec::new(),
        fpu_approximated: false,
    };
    let Some(image) = PeImage::parse(file) else {
        report.stop = "not a 32-bit PE".to_string();
        return report;
    };
    let mut mem = Mem::new(limits.max_pages);
    if image.map_into(file, &mut mem).is_err() {
        report.stop = "image does not fit the page budget".to_string();
        return report;
    }
    let mut env = match Env::new(&mut mem, image.base, image.size_of_image, file) {
        Ok(e) => e,
        Err(_) => {
            report.stop = "environment does not fit the page budget".to_string();
            return report;
        }
    };

    env.trace = limits.trace;

    // The loader binds imports before the entry point runs; the stub calls
    // through those slots straight away.
    let (dir_rva, dir_size) = image.import_dir;
    let _ = env.bind_imports(&mut mem, image.base, dir_rva, dir_size);

    let mut cpu = Cpu::new();
    cpu.eip = image.base.wrapping_add(image.entry_rva);
    cpu.regs[ESP] = INITIAL_ESP;
    cpu.fs_base = TEB_BASE;
    // What a thread sees at the entry point on Windows: EBX holds the PEB, and
    // the return address is into kernel32.
    cpu.regs[EBX] = crate::win::PEB_BASE;
    let process_return = env.process_return();
    let seh_return = env.seh_return();
    // A DLL is entered as `DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)`. Those
    // three arguments have to be on the stack: a packed DLL's stub reads them,
    // and without them it faults on its first instruction.
    let pushed = if image.is_dll {
        cpu.push32(&mut mem, 0)
            .and_then(|()| cpu.push32(&mut mem, 1))
            .and_then(|()| cpu.push32(&mut mem, image.base))
            .and_then(|()| cpu.push32(&mut mem, process_return))
    } else {
        cpu.push32(&mut mem, process_return)
    };
    if pushed.is_err() {
        report.stop = "stack is not mapped".to_string();
        return report;
    }

    let stub_section = image.section_of(image.entry_rva);
    let image_end = image.base.saturating_add(image.size_of_image);

    let mut seh = SehState {
        seh_return,
        ..Default::default()
    };
    let mut oep: Option<u32> = None;
    let mut ticks: u64 = 0;
    let mut unimplemented_calls = 0u32;
    let mut faulted_api_calls = 0u32;
    let mut progress_deadline: u64 = PROGRESS_WINDOW;
    let stop_reason: String;
    let mut trace: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut recheck: Vec<u64> = vec![0; image.sections.len() + 1];

    loop {
        if ticks >= limits.max_ticks {
            stop_reason = format!("instruction budget ({} ticks) exhausted", limits.max_ticks);
            break;
        }
        // A stub that is unpacking writes pages continuously. One that has not
        // touched a new page in millions of instructions is spinning — an
        // anti-emulation delay loop, or a decompressor that lost its way — and
        // running it to the full budget only spends scan time to reach the same
        // place. Checked on a coarse interval so the check itself is free.
        if ticks >= progress_deadline {
            if mem.take_write_spread() < MIN_WRITE_SPREAD {
                stop_reason = format!("no progress in {PROGRESS_WINDOW} ticks");
                break;
            }
            progress_deadline = ticks + PROGRESS_WINDOW;
        }
        let eip = cpu.eip;

        if eip == process_return {
            stop_reason = "the stub returned to the loader".to_string();
            break;
        }
        if eip == seh_return {
            // Charged like any other step. Dispatching a handler runs no
            // instruction, so an SEH chain that keeps returning here would
            // otherwise advance neither the tick budget nor the progress
            // window — a loop the emulator cannot see itself taking.
            ticks += 1;
            match seh.handler_returned(&mut cpu, &mut mem) {
                Ok(SehOutcome::Resumed) => continue,
                Ok(SehOutcome::TryNext) => match seh.dispatch_next(&mut cpu, &mut mem) {
                    Ok(true) => continue,
                    Ok(false) | Err(_) => {
                        stop_reason = "no exception handler accepted the fault".to_string();
                        break;
                    }
                },
                Err(_) => {
                    stop_reason = "exception handler left an unreadable context".to_string();
                    break;
                }
            }
        }
        if env.is_trap(eip) {
            // Where the call came from, in case servicing it faults: the return
            // address is still on the stack at this point.
            let call_esp = cpu.regs[ESP];
            match env.call(&mut cpu, &mut mem) {
                Ok(ApiEffect::Continue) => {
                    // One tick for the call, plus one per page the call moved.
                    // `memcpy` and friends copy up to 64 MiB per call, so
                    // charging a flat tick would let a stub spend the whole
                    // budget's worth of work on every single tick — the bound
                    // has to be on work, not on how many calls it took.
                    ticks += 1 + env.take_bulk_bytes() / PAGE_SIZE as u64;
                    continue;
                }
                Ok(ApiEffect::Exit) => {
                    stop_reason = "the stub called ExitProcess".to_string();
                    break;
                }
                Ok(ApiEffect::Unimplemented) => {
                    // Continue, but remember: the stack may now be skewed by
                    // whatever a stdcall callee would have removed.
                    ticks += 1;
                    unimplemented_calls += 1;
                    if unimplemented_calls > MAX_UNIMPLEMENTED_CALLS {
                        stop_reason = format!(
                            "too many unimplemented exports ({})",
                            env.missing_apis.last().cloned().unwrap_or_default()
                        );
                        break;
                    }
                    continue;
                }
                Err(Stop::Fault(_)) => {
                    // The stub passed a pointer that does not resolve — a
                    // buffer it never allocated, a string built from a value
                    // this environment answered differently. On Windows that is
                    // a failed call, not a dead process: the API returns an
                    // error and the program carries on, often down a fallback
                    // path that unpacks perfectly well. Return failure and
                    // resume at the caller.
                    let ret = mem.read_u32(call_esp).unwrap_or(0);
                    if ret == 0 || !mem.is_mapped(ret, 1) {
                        stop_reason = "an API call faulted with no way back".to_string();
                        break;
                    }
                    cpu.regs[EAX] = 0;
                    cpu.regs[ESP] = call_esp.wrapping_add(4);
                    cpu.eip = ret;
                    ticks += 1;
                    faulted_api_calls += 1;
                    if faulted_api_calls > MAX_UNIMPLEMENTED_CALLS {
                        stop_reason = "too many API calls faulted".to_string();
                        break;
                    }
                    continue;
                }
                Err(e) => {
                    stop_reason = format!("fault servicing an API call: {e:?}");
                    break;
                }
            }
        }

        // The tail transfer: into the image, into a different section from the
        // stub's, onto a page the stub wrote.
        if oep.is_none() && eip >= image.base && eip < image_end {
            let rva = eip - image.base;
            let sec = image.section_of(rva);
            // The transfer has to cross into another SECTION, not merely onto a
            // page the stub wrote and never executed. The page-level rule is the
            // tempting one and it is wrong: a stub that relocates its own
            // decompressor to a fresh page and jumps there satisfies it, which
            // PEtite does within ten thousand instructions of starting. The run
            // then stops at what only looks like an entry point and dumps a
            // *half-decompressed* image. Stopping late and dumping everything
            // beats stopping at the first plausible-looking jump.
            if sec != stub_section
                && mem.watched_dirty_bytes() >= limits.min_unpack_dirty
                && mem.is_dirty(eip)
                && rebuilt(&image, sec, &mut mem, &mut recheck, ticks)
            {
                oep = Some(rva);
                stop_reason = format!("reached the original entry point at RVA {rva:#x}");
                break;
            }
        }

        if limits.trace {
            if trace.len() == TRACE_LEN {
                trace.pop_front();
            }
            trace.push_back(disassemble(&cpu, &mut mem));
        }

        // The trap flag has to be sampled *before* the instruction: setting it
        // with `popfd` does not trap on the `popfd` itself, only after the one
        // that follows.
        let stepping = cpu.tf;

        match cpu.step(&mut mem) {
            Ok(t) => {
                ticks += t;
                if stepping && cpu.tf {
                    // Single-step exception, delivered to the stub's own
                    // handler exactly as the processor would. The flag is
                    // cleared for the handler's own execution; whether it comes
                    // back on is up to the context the handler returns.
                    cpu.tf = false;
                    match seh.raise(&mut cpu, &mut mem, STATUS_SINGLE_STEP, eip) {
                        Ok(true) => continue,
                        _ => {
                            stop_reason = "single-step exception with no handler".to_string();
                            break;
                        }
                    }
                }
            }
            Err(Stop::Fault(f)) if env.grow_stack(&mut mem, f.addr) => {
                // The stack grew into its guard region, which on Windows just
                // commits another page. Retry the instruction.
                ticks += 1;
                continue;
            }
            Err(stop) => {
                ticks += 1;
                // Deliver the fault to the stub's own handler chain; only if
                // nothing accepts it does the run end.
                let code = exception_code(&stop);
                match code.and_then(|c| seh.raise(&mut cpu, &mut mem, c, eip).ok()) {
                    Some(true) => continue,
                    _ => {
                        stop_reason = describe(&stop);
                        break;
                    }
                }
            }
        }
        if mem.at_capacity() {
            stop_reason = "emulated memory budget exhausted".to_string();
            break;
        }
    }

    report.ticks = ticks;
    report.stop = stop_reason;
    report.fpu_approximated = cpu.fpu_approximated;
    report.missing_apis = std::mem::take(&mut env.missing_apis);
    report.tail = trace.into_iter().collect();
    report.api_calls = std::mem::take(&mut env.api_log);

    // How much of the image the stub rewrote — the measure of whether anything
    // was actually reconstructed.
    //
    // Counted in pages rather than walked by address: `ImageBase` has no upper
    // bound in the header, so `base + SizeOfImage` can pass 4 GiB, `image_end`
    // saturates, and a `u32` cursor stepping toward it wraps to zero and never
    // arrives. This runs after the emulation loop, where the tick budget, the
    // progress window and the page cap are all already spent — a loop that does
    // not end here does not end at all.
    let mut dirty = 0u64;
    let pages = (u64::from(image_end) - u64::from(image.base)) / PAGE_SIZE as u64;
    for i in 0..pages {
        let page = (u64::from(image.base) + i * PAGE_SIZE as u64) as u32;
        if mem.is_dirty(page) {
            dirty += PAGE_SIZE as u64;
        }
    }
    report.dirty_bytes = dirty;

    // Images the stub built in memory it allocated. These are collected whether
    // or not the stub also rewrote its own image, because a loader that unfolds
    // the payload into fresh pages and runs it from there never touches the
    // image at all — and that shape is a dropper, not an edge case.
    report.extra = allocated_payloads(&env, &mut mem, limits.max_dump, file);

    // A run that stopped early having rewritten a page or two rebuilt nothing —
    // that is a stub that faulted on its way in, and dumping its image would
    // hand the scanner the packed file back under a name that says "unpacked".
    if dirty == 0 || (oep.is_none() && dirty < limits.min_partial_dirty) {
        return report;
    }

    let entry = oep.unwrap_or(image.entry_rva);
    let Some(data) = image.dump(&mut mem, file, entry, limits.max_dump) else {
        // The stop still reads "reached the original entry point", which without
        // this would leave a triager looking for a file that was never written.
        // Say which gate dropped it.
        report.stop = format!("{}, but the dump exceeded max_dump", report.stop);
        return report;
    };
    report.unpacked = Some(Unpacked {
        data,
        oep_rva: entry,
        reached_oep: oep.is_some(),
    });
    report
}

/// Whether the section execution just entered was *rebuilt* rather than merely
/// touched.
///
/// Landing on a dirty page in another section is necessary but not sufficient:
/// obfuscated (not packed) programs write a word into a data section and jump
/// through it, which looks identical at one instruction's resolution. What
/// separates the two is bulk — an unpacker rewrites the section it hands
/// control to, so a quarter of that section's pages, at minimum, carry bytes
/// the stub produced.
///
/// `recheck` throttles the scan: a stub that jumps in and out of a section
/// would otherwise pay for a page walk on every crossing.
fn rebuilt(
    image: &PeImage,
    sec: Option<usize>,
    mem: &mut Mem,
    recheck: &mut [u64],
    ticks: u64,
) -> bool {
    const RECHECK_INTERVAL: u64 = 100_000;
    const MAX_PAGES_SCANNED: u32 = 1 << 16;
    let Some(idx) = sec else {
        // Outside every section: nothing to measure, so nothing to claim.
        return false;
    };
    let slot = &mut recheck[idx.min(recheck.len() - 1)];
    if *slot != 0 && ticks < *slot {
        return false;
    }
    *slot = ticks + RECHECK_INTERVAL;

    let s = &image.sections[idx];
    let len = s.vsize.max(s.raw_size).max(image.section_align);
    let pages = (len / PAGE_SIZE as u32).clamp(1, MAX_PAGES_SCANNED);
    let mut dirty = 0u32;
    for p in 0..pages {
        if mem.is_dirty(
            image
                .base
                .wrapping_add(s.vaddr)
                .wrapping_add(p * PAGE_SIZE as u32),
        ) {
            dirty += 1;
        }
    }
    dirty * 4 >= pages
}

/// Regions the stub allocated that hold a PE image. Some packers rebuild the
/// original program in fresh memory and only then map it over themselves — or
/// never do, and run it from there.
fn allocated_payloads(env: &Env, mem: &mut Mem, cap: usize, file: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for &(base, size) in &env.allocations {
        if size < 0x200 || size as usize > cap {
            continue;
        }
        let head = mem.snapshot(base, 0x40);
        if head.len() < 2 || &head[..2] != b"MZ" {
            continue;
        }
        let body = mem.snapshot(base, size as usize);
        if PeImage::parse(&body).is_none() {
            continue;
        }
        // A stub that reads its own file into memory — Neolite does, and so do
        // most self-extractors — leaves a copy of the input in an allocation.
        // Emitting that as a discovered payload feeds the file back into the
        // unpacker, which finds the same copy again, one nesting level deeper,
        // for as long as the recursion budget lasts.
        let same_prefix = body.len() >= file.len()
            && file.len() >= 0x200
            && body[..file.len().min(0x1000)] == file[..file.len().min(0x1000)];
        if !same_prefix {
            out.push(body);
        }
        if out.len() >= 4 {
            break;
        }
    }
    out
}

/// One trace line: the instruction at `eip` plus the register state going into
/// it, which is what makes a bad address attributable to the instruction that
/// computed it.
fn disassemble(cpu: &Cpu, mem: &mut Mem) -> String {
    let mut buf = [0u8; 16];
    let n = mem.read_code(cpu.eip, &mut buf);
    // The mnemonic and the operand shapes, not assembly text: what matters when
    // triaging is which instruction ran and where it touched memory, and a
    // formatter would be a second rendering of the same facts to keep correct.
    let mut text = String::new();
    match n
        .checked_sub(1)
        .and_then(|_| exav_x86::decode(&buf[..n], cpu.eip as u64))
    {
        Some(insn) => {
            text = format!("{:?} {:?}", insn.mn, &insn.ops[..insn.op_count()]);
            if insn
                .ops
                .iter()
                .any(|o| matches!(o, exav_x86::Op::Mem { .. } | exav_x86::Op::MemWide { .. }))
            {
                text.push_str(&format!(" ea={:08x}", cpu.effective_address(&insn)));
            }
        }
        None if n == 0 => text.push_str("<unmapped>"),
        None => text.push_str("<undecodable>"),
    }
    format!(
        "{:08x}  {text:<32} eax={:08x} ecx={:08x} edx={:08x} ebx={:08x} esp={:08x} ebp={:08x} esi={:08x} edi={:08x}",
        cpu.eip,
        cpu.regs[0], cpu.regs[1], cpu.regs[2], cpu.regs[3],
        cpu.regs[4], cpu.regs[5], cpu.regs[6], cpu.regs[7],
    )
}

fn describe(stop: &Stop) -> String {
    match stop {
        Stop::Fault(f) => format!(
            "unhandled {} fault at {:#010x}",
            if f.write { "write" } else { "read" },
            f.addr
        ),
        Stop::Invalid(ip) => format!("undecodable instruction at {ip:#010x}"),
        Stop::Unsupported(ip, m) => format!("unimplemented instruction {m:?} at {ip:#010x}"),
        Stop::Interrupt(n) => format!("int {n:#x}"),
        Stop::Privileged(ip) => format!("privileged instruction at {ip:#010x}"),
        Stop::Halt => "hlt".to_string(),
        Stop::DivideError => "divide error".to_string(),
    }
}

/// The Windows exception a stop corresponds to, for delivery to an SEH handler.
fn exception_code(stop: &Stop) -> Option<u32> {
    Some(match stop {
        Stop::Fault(_) => STATUS_ACCESS_VIOLATION,
        Stop::Invalid(_) => STATUS_ILLEGAL_INSTRUCTION,
        Stop::Interrupt(3) => STATUS_BREAKPOINT,
        // `into` raises overflow, not a privilege fault. A handler that switches
        // on the code takes a different branch for each, and a stub that checks
        // which one it got learns it is not on a real CPU.
        Stop::Interrupt(4) => STATUS_INTEGER_OVERFLOW,
        Stop::Interrupt(_) => STATUS_PRIVILEGED_INSTRUCTION,
        Stop::Privileged(_) => STATUS_PRIVILEGED_INSTRUCTION,
        Stop::DivideError => STATUS_INTEGER_DIVIDE_BY_ZERO,
        // An unimplemented instruction is a gap in the emulator, not something
        // the program did. Handing it to the stub's handler would let a broken
        // emulation masquerade as an anti-debug trick.
        Stop::Unsupported(..) => return None,
        Stop::Halt => return None,
    })
}

/// Structured-exception dispatch state, carried across steps because a handler
/// runs as ordinary emulated code and only reports its verdict on return.
#[derive(Default)]
struct SehState {
    /// Where a handler returns to, so the driver regains control.
    seh_return: u32,
    /// Registration record currently being tried.
    frame: u32,
    /// Address of the `CONTEXT` handed to the handler.
    context: u32,
    /// Address of the `EXCEPTION_RECORD`.
    record: u32,
    active: bool,
}

enum SehOutcome {
    Resumed,
    TryNext,
}

impl SehState {
    /// Deliver `code` to the head of the thread's exception chain. Returns
    /// false when there is no handler to run.
    fn raise(&mut self, cpu: &mut Cpu, mem: &mut Mem, code: u32, at: u32) -> Result<bool, Stop> {
        let head = mem.read_u32(cpu.fs_base).map_err(Stop::Fault)?;
        if head == 0xffff_ffff || head == 0 || !mem.is_mapped(head, 8) {
            return Ok(false);
        }
        // Build the records below the current stack pointer, leaving room so
        // the handler's own frame cannot overwrite them.
        let mut sp = cpu.regs[ESP] & !0xf;
        sp = sp.wrapping_sub(CONTEXT_SIZE);
        let context = sp;
        sp = sp.wrapping_sub(EXC_RECORD_SIZE);
        let record = sp;
        if !mem.is_mapped(record, CONTEXT_SIZE + EXC_RECORD_SIZE) {
            return Ok(false);
        }

        let mut rec = [0u8; EXC_RECORD_SIZE as usize];
        rec[0..4].copy_from_slice(&code.to_le_bytes());
        rec[12..16].copy_from_slice(&at.to_le_bytes()); // ExceptionAddress
        mem.write_bytes(record, &rec).map_err(Stop::Fault)?;
        write_context(cpu, mem, context, at)?;

        self.frame = head;
        self.context = context;
        self.record = record;
        self.active = true;
        cpu.regs[ESP] = record;
        self.enter_handler(cpu, mem)?;
        Ok(true)
    }

    /// Push the handler's four arguments and jump to it.
    fn enter_handler(&mut self, cpu: &mut Cpu, mem: &mut Mem) -> Result<(), Stop> {
        let handler = mem.read_u32(self.frame + 4).map_err(Stop::Fault)?;
        cpu.push32(mem, 0)?; // DispatcherContext
        let ctx = self.context;
        cpu.push32(mem, ctx)?;
        let frame = self.frame;
        cpu.push32(mem, frame)?;
        let rec = self.record;
        cpu.push32(mem, rec)?;
        cpu.push32(mem, self.seh_return)?;
        cpu.eip = handler;
        Ok(())
    }

    /// The handler returned: `eax` carries its disposition.
    fn handler_returned(&mut self, cpu: &mut Cpu, mem: &mut Mem) -> Result<SehOutcome, Stop> {
        if !self.active {
            return Ok(SehOutcome::TryNext);
        }
        match cpu.regs[EAX] {
            // ExceptionContinueExecution: resume from the context, which the
            // handler will usually have edited. Resuming from anything else
            // would discard the edit the handler exists to make.
            0 => {
                read_context(cpu, mem, self.context)?;
                self.active = false;
                Ok(SehOutcome::Resumed)
            }
            _ => Ok(SehOutcome::TryNext),
        }
    }

    /// Walk to the next registration record and run its handler.
    fn dispatch_next(&mut self, cpu: &mut Cpu, mem: &mut Mem) -> Result<bool, Stop> {
        let next = mem.read_u32(self.frame).map_err(Stop::Fault)?;
        if next == 0xffff_ffff || next == 0 || !mem.is_mapped(next, 8) {
            self.active = false;
            return Ok(false);
        }
        self.frame = next;
        self.enter_handler(cpu, mem)?;
        Ok(true)
    }
}

/// Write the CPU state into an x86 `CONTEXT` at `addr`.
fn write_context(cpu: &Cpu, mem: &mut Mem, addr: u32, eip: u32) -> Result<(), Stop> {
    let mut ctx = vec![0u8; CONTEXT_SIZE as usize];
    let put = |c: &mut Vec<u8>, off: usize, v: u32| {
        c[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    put(&mut ctx, 0x00, 0x0001_0007); // ContextFlags: FULL
    put(&mut ctx, 0x8c, 0x0000); // SegGs
    put(&mut ctx, 0x90, 0x003b); // SegFs
    put(&mut ctx, 0x94, 0x0023); // SegEs
    put(&mut ctx, 0x98, 0x0023); // SegDs
    put(&mut ctx, 0x9c, cpu.regs[7]); // Edi
    put(&mut ctx, 0xa0, cpu.regs[6]); // Esi
    put(&mut ctx, 0xa4, cpu.regs[3]); // Ebx
    put(&mut ctx, 0xa8, cpu.regs[2]); // Edx
    put(&mut ctx, 0xac, cpu.regs[1]); // Ecx
    put(&mut ctx, 0xb0, cpu.regs[0]); // Eax
    put(&mut ctx, 0xb4, cpu.regs[5]); // Ebp
    put(&mut ctx, 0xb8, eip); // Eip: the faulting instruction
    put(&mut ctx, 0xbc, 0x001b); // SegCs
    put(&mut ctx, 0xc0, cpu.eflags()); // EFlags
    put(&mut ctx, 0xc4, cpu.regs[4]); // Esp
    put(&mut ctx, 0xc8, 0x0023); // SegSs
    mem.write_bytes(addr, &ctx).map_err(Stop::Fault)
}

/// Restore the CPU from a `CONTEXT` the handler may have modified.
fn read_context(cpu: &mut Cpu, mem: &mut Mem, addr: u32) -> Result<(), Stop> {
    let get = |mem: &mut Mem, off: u32| mem.read_u32(addr + off).map_err(Stop::Fault);
    cpu.regs[7] = get(mem, 0x9c)?;
    cpu.regs[6] = get(mem, 0xa0)?;
    cpu.regs[3] = get(mem, 0xa4)?;
    cpu.regs[2] = get(mem, 0xa8)?;
    cpu.regs[1] = get(mem, 0xac)?;
    cpu.regs[0] = get(mem, 0xb0)?;
    cpu.regs[5] = get(mem, 0xb4)?;
    cpu.eip = get(mem, 0xb8)?;
    let flags = get(mem, 0xc0)?;
    cpu.set_eflags(flags);
    cpu.regs[4] = get(mem, 0xc4)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Limits for the hand-written stubs below: they rebuild a few hundred
    /// bytes, where the shipping thresholds are sized for a real unpack of tens
    /// of kilobytes. Both sides are covered — `a_small_rewrite_is_not_an_unpack`
    /// exercises the shipping value.
    fn tiny_limits() -> EmuLimits {
        EmuLimits {
            min_unpack_dirty: 0,
            min_partial_dirty: 0,
            ..Default::default()
        }
    }

    /// Build a packed-looking PE: section 0 (`.text`) is the destination, the
    /// last section holds `stub` and the entry point.
    fn packed_pe(stub: &[u8], payload_rva: u32) -> Vec<u8> {
        let pe_off = 0x80usize;
        let opt_size = 0xe0usize;
        let sec_table = pe_off + 24 + opt_size;
        let num = 2usize;
        let headers = 0x400usize;
        let stub_raw = headers;
        let mut d = vec![0u8; stub_raw + 0x1000];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_off + 4;
        d[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes());
        d[coff + 2..coff + 4].copy_from_slice(&(num as u16).to_le_bytes());
        d[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt = coff + 20;
        d[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        d[opt + 16..opt + 20].copy_from_slice(&0x2000u32.to_le_bytes()); // entry: section 1
        d[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        d[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
        d[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        // Section 0: the empty destination the stub fills in.
        let s0 = sec_table;
        d[s0..s0 + 5].copy_from_slice(b".text");
        d[s0 + 8..s0 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        d[s0 + 12..s0 + 16].copy_from_slice(&payload_rva.to_le_bytes());
        d[s0 + 16..s0 + 20].copy_from_slice(&0u32.to_le_bytes()); // no raw data
        d[s0 + 20..s0 + 24].copy_from_slice(&0u32.to_le_bytes());
        // Section 1: the stub.
        let s1 = sec_table + 40;
        d[s1..s1 + 5].copy_from_slice(b".pack");
        d[s1 + 8..s1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        d[s1 + 12..s1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        d[s1 + 16..s1 + 20].copy_from_slice(&(stub.len() as u32).to_le_bytes());
        d[s1 + 20..s1 + 24].copy_from_slice(&(stub_raw as u32).to_le_bytes());
        d[stub_raw..stub_raw + stub.len()].copy_from_slice(stub);
        d
    }

    #[test]
    fn a_stub_that_decrypts_and_jumps_is_unpacked_at_its_entry_point() {
        // The archetype: copy a XOR-encrypted body into .text, then jump to it.
        //   be 00 30 40 00    mov esi, 0x403000   (cipher, in the stub section)
        //   bf 00 10 40 00    mov edi, 0x401000   (destination, .text)
        //   b9 10 00 00 00    mov ecx, 16
        //   ac                lodsb
        //   34 5a             xor al, 0x5a
        //   aa                stosb
        //   e2 fa             loop -6
        //   e9 xx xx xx xx    jmp 0x401000
        let plain: [u8; 16] = *b"ORIGINAL PROGRAM";
        let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x5a).collect();
        let mut stub = vec![
            0xbe, 0x00, 0x30, 0x40, 0x00, // mov esi, 0x403000
            0xbf, 0x00, 0x10, 0x40, 0x00, // mov edi, 0x401000
            0xb9, 0x10, 0x00, 0x00, 0x00, // mov ecx, 16
            0xac, 0x34, 0x5a, 0xaa, 0xe2, 0xfa, // the copy loop
        ];
        // jmp rel32 to 0x401000 from the instruction after this one.
        let jmp_at = 0x0040_2000u32 + stub.len() as u32;
        let rel = 0x0040_1000u32.wrapping_sub(jmp_at + 5) as i32;
        stub.push(0xe9);
        stub.extend_from_slice(&rel.to_le_bytes());
        // The cipher text lives at RVA 0x3000, one page past the stub.
        let mut file = packed_pe(&stub, 0x1000);
        // Grow the stub section's raw data so the cipher is inside the file.
        let sec_table = 0x80 + 24 + 0xe0;
        let s1 = sec_table + 40;
        file[s1 + 8..s1 + 12].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualSize
        file[s1 + 16..s1 + 20].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfRawData
        let stub_raw = 0x400usize;
        file.resize(stub_raw + 0x2000, 0);
        file[stub_raw + 0x1000..stub_raw + 0x1000 + cipher.len()].copy_from_slice(&cipher);
        let opt = 0x80 + 24;
        file[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes()); // SizeOfImage

        let r = unpack(&file, &tiny_limits());
        let u = r.unpacked.expect("the image was reconstructed");
        assert!(u.reached_oep, "stopped at the tail jump: {}", r.stop);
        assert_eq!(u.oep_rva, 0x1000);
        let pe = PeImage::parse(&u.data).unwrap();
        assert_eq!(pe.entry_rva, 0x1000, "the dump's entry point is the OEP");
        let at = pe.sections[0].raw_ptr as usize;
        assert_eq!(
            &u.data[at..at + plain.len()],
            &plain,
            "the decrypted program is in the dump"
        );
    }

    /// A PE whose image runs up against the top of the address space must not
    /// hang the scan.
    ///
    /// `ImageBase` is a header field with no upper bound, so `base +
    /// SizeOfImage` can pass 4 GiB. Any walk that steps a `u32` cursor toward a
    /// saturated end address wraps to zero and never reaches it — and this walk
    /// runs *after* the emulation loop, so the tick budget, the progress window
    /// and the page cap are all already spent. Nothing else would stop it.
    ///
    /// The watchdog is the assertion: on a hang the thread never finishes, and
    /// the test fails on the join deadline rather than taking the suite with it.
    #[test]
    fn an_image_at_the_top_of_the_address_space_terminates() {
        // 32 pages, so mapping stays well inside the page budget; the overflow
        // is in the arithmetic, not in how much is mapped.
        let mut file = packed_pe(&[0xc3], 0x1000); // `ret`
        let opt = 0x80 + 24;
        file[opt + 28..opt + 32].copy_from_slice(&0xFFFF_0000u32.to_le_bytes()); // ImageBase
        file[opt + 56..opt + 60].copy_from_slice(&0x0002_0000u32.to_le_bytes()); // SizeOfImage

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = unpack(&file, &EmuLimits::default());
            let _ = tx.send(r.dirty_bytes);
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(20)).is_ok(),
            "unpack did not return for an image based at 0xFFFF0000. The \
             dirty-page walk stepped a u32 cursor past a saturated end address, \
             wrapped to zero, and never terminated."
        );
    }

    #[test]
    fn a_small_rewrite_is_not_an_unpack() {
        // The same stub as above under the shipping thresholds: it rebuilds 16
        // bytes and jumps to them, which is what an obfuscated program's jump
        // table looks like, not what an unpacker's output looks like. No entry
        // point is claimed and no dump is offered.
        let plain: [u8; 16] = *b"ORIGINAL PROGRAM";
        let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x5a).collect();
        let mut stub = vec![
            0xbe, 0x00, 0x30, 0x40, 0x00, // mov esi, 0x403000
            0xbf, 0x00, 0x10, 0x40, 0x00, // mov edi, 0x401000
            0xb9, 0x10, 0x00, 0x00, 0x00, // mov ecx, 16
            0xac, 0x34, 0x5a, 0xaa, 0xe2, 0xfa,
        ];
        let jmp_at = 0x0040_2000u32 + stub.len() as u32;
        let rel = 0x0040_1000u32.wrapping_sub(jmp_at + 5) as i32;
        stub.push(0xe9);
        stub.extend_from_slice(&rel.to_le_bytes());
        let mut file = packed_pe(&stub, 0x1000);
        let sec_table = 0x80 + 24 + 0xe0;
        let s1 = sec_table + 40;
        file[s1 + 8..s1 + 12].copy_from_slice(&0x2000u32.to_le_bytes());
        file[s1 + 16..s1 + 20].copy_from_slice(&0x2000u32.to_le_bytes());
        file.resize(0x400 + 0x2000, 0);
        file[0x1400..0x1400 + cipher.len()].copy_from_slice(&cipher);

        let r = unpack(&file, &EmuLimits::default());
        assert!(
            r.unpacked.is_none(),
            "16 rebuilt bytes are below the floor: {}",
            r.stop
        );
    }

    #[test]
    fn a_stub_that_never_writes_produces_no_dump() {
        // ret: does nothing, writes nothing. There is no reconstruction to
        // report, and inventing one would be worse than reporting none.
        let file = packed_pe(&[0xc3], 0x1000);
        let r = unpack(&file, &EmuLimits::default());
        assert!(r.unpacked.is_none());
        assert_eq!(r.dirty_bytes, 0);
        assert!(r.stop.contains("returned to the loader"), "{}", r.stop);
    }

    #[test]
    fn an_endless_loop_is_stopped_by_the_tick_budget() {
        // eb fe = jmp $
        let file = packed_pe(&[0xeb, 0xfe], 0x1000);
        let limits = EmuLimits {
            max_ticks: 10_000,
            ..Default::default()
        };
        let r = unpack(&file, &limits);
        assert!(r.stop.contains("budget"), "{}", r.stop);
        assert!(r.ticks >= 10_000);
    }

    #[test]
    fn a_fault_is_delivered_to_the_stubs_own_seh_handler() {
        // Install a handler, fault, and have the handler rewrite the context's
        // EIP so execution continues — the anti-emulation pattern.
        //
        //   68 <handler>      push handler
        //   64 ff 35 00 00 00 00   push fs:[0]
        //   64 89 25 00 00 00 00   mov fs:[0], esp
        //   31 c0             xor eax, eax
        //   c7 00 00 00 00 00 mov dword [eax], 0     <- access violation
        //   b8 01 00 00 00    mov eax, 1             <- resumed here
        //   c3                ret
        // handler:
        //   8b 44 24 0c       mov eax, [esp+0xc]     ; CONTEXT*
        //   8b 4c 24 04       mov ecx, [esp+4]       ; unused
        //   c7 80 b8 00 00 00 <resume>  mov [eax+0xb8], resume
        //   31 c0             xor eax, eax           ; ExceptionContinueExecution
        //   c3                ret
        let base = 0x0040_2000u32;
        let mut stub: Vec<u8> = Vec::new();
        let handler_at_placeholder = stub.len() + 1;
        stub.extend_from_slice(&[0x68, 0, 0, 0, 0]); // push handler (patched)
        stub.extend_from_slice(&[0x64, 0xff, 0x35, 0, 0, 0, 0]); // push fs:[0]
        stub.extend_from_slice(&[0x64, 0x89, 0x25, 0, 0, 0, 0]); // mov fs:[0], esp
        stub.extend_from_slice(&[0x31, 0xc0]); // xor eax, eax
        stub.extend_from_slice(&[0xc7, 0x00, 0, 0, 0, 0]); // mov [eax], 0
        let resume_off = stub.len();
        stub.extend_from_slice(&[0xa3, 0x00, 0x10, 0x40, 0x00]); // mov [0x401000], eax
        stub.extend_from_slice(&[0xe9, 0, 0, 0, 0]); // jmp .text (patched)
        let jmp_at = base + stub.len() as u32 - 5;
        let rel = 0x0040_1000u32.wrapping_sub(jmp_at + 5) as i32;
        let n = stub.len();
        stub[n - 4..].copy_from_slice(&rel.to_le_bytes());

        let handler_off = stub.len();
        stub.extend_from_slice(&[0x8b, 0x44, 0x24, 0x0c]); // mov eax, [esp+0xc]
        stub.extend_from_slice(&[0xc7, 0x80, 0xb8, 0x00, 0x00, 0x00]); // mov [eax+0xb8], imm32
        stub.extend_from_slice(&(base + resume_off as u32).to_le_bytes());
        stub.extend_from_slice(&[0x31, 0xc0, 0xc3]); // xor eax, eax ; ret

        let handler_va = base + handler_off as u32;
        stub[handler_at_placeholder..handler_at_placeholder + 4]
            .copy_from_slice(&handler_va.to_le_bytes());

        let file = packed_pe(&stub, 0x1000);
        let r = unpack(&file, &tiny_limits());
        assert!(
            r.unpacked.as_ref().is_some_and(|u| u.reached_oep),
            "the handler resumed execution and the stub reached its target: {}",
            r.stop
        );
    }

    #[test]
    fn an_unimplemented_instruction_is_reported_not_swallowed() {
        // 0f 51 c0 = sqrtps, which the interpreter does not implement.
        let file = packed_pe(&[0x0f, 0x51, 0xc0], 0x1000);
        let r = unpack(&file, &EmuLimits::default());
        assert!(r.stop.contains("Sqrtps"), "{}", r.stop);
        assert!(
            r.unpacked.is_none(),
            "nothing was written, so nothing is claimed"
        );
    }

    #[test]
    fn a_stub_that_walks_the_peb_finds_kernel32_and_calls_it() {
        //   64 a1 30 00 00 00   mov eax, fs:[0x30]     ; PEB
        //   8b 40 0c            mov eax, [eax+0xc]     ; Ldr
        //   8b 40 1c            mov eax, [eax+0x1c]    ; InInitializationOrder
        //   8b 00               mov eax, [eax]         ; second entry (kernel32)
        //   8b 58 08            mov ebx, [eax+8]       ; DllBase
        //   89 1d 00 10 40 00   mov [0x401000], ebx    ; prove it, in .text
        //   c3                  ret
        let stub = vec![
            0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, 0x8b, 0x40, 0x0c, 0x8b, 0x40, 0x1c, 0x8b, 0x00,
            0x8b, 0x58, 0x08, 0x89, 0x1d, 0x00, 0x10, 0x40, 0x00, 0xc3,
        ];
        let file = packed_pe(&stub, 0x1000);
        let r = unpack(&file, &tiny_limits());
        let u = r.unpacked.expect("the stub wrote into the image");
        let pe = PeImage::parse(&u.data).unwrap();
        let at = pe.sections[0].raw_ptr as usize;
        let found = u32::from_le_bytes(u.data[at..at + 4].try_into().unwrap());
        assert_eq!(
            found, 0x7c80_0000,
            "the walk reached the synthetic kernel32"
        );
    }
}
