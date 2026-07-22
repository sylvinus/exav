#![no_main]
//! The x86 emulator on hostile bytes.
//!
//! This target exists because the emulator is the one place where a scanned
//! file supplies **control flow** rather than data: the input's own bytes decide
//! which instruction executes next, which memory is touched, and which Windows
//! call is made. Everything else in the scanner parses attacker-controlled
//! structure; this runs it.
//!
//! Two things are being looked for:
//!
//! * **Panics.** Every stop in `exav-pe-emu` is meant to be a value — a fault, an
//!   unimplemented instruction, a budget — never an unwind. Release builds keep
//!   overflow checks on, so a single missed wrapping operation in the
//!   interpreter is a panic, and a panic is a denial of service on a scanner
//!   that is handed the file by an attacker.
//! * **The decoder.** `iced-x86` is the only dependency the emulated bytes
//!   reach, and it contains `unsafe`. exav's own emulator code forbids it, so
//!   this is the sharpest path from a crafted instruction stream to host memory,
//!   and it should be fuzzed through the entry point exav actually uses.
//!
//! Budgets are tight on purpose: the point is coverage per second, not letting
//! one input run a hundred million instructions.
//!
//! Seed corpus: `fuzz/corpus/pe_emulator/` — small packed PEs, so the mutator
//! starts inside a stub rather than rediscovering the PE header.
use exav_pe_emu::{unpack, EmuLimits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Enough instructions to get through a stub's prologue and into its loops,
    // few enough that a mutation which finds an infinite loop costs
    // milliseconds. The memory caps bound what one input can allocate.
    let limits = EmuLimits {
        max_ticks: 2_000_000,
        max_pages: 4096, // 16 MiB of emulated address space
        max_dump: 4 << 20,
        ..Default::default()
    };
    let report = unpack(data, &limits);

    // Whatever came back has to be self-consistent: the emulator promises that
    // an image it hands over parses as a PE, because the scanner treats it as
    // one. A dump that does not is a bug here, not downstream.
    if let Some(u) = report.unpacked {
        assert!(
            u.data.len() >= 0x40 && &u.data[..2] == b"MZ",
            "emitted a dump that is not a PE image"
        );
        assert!(u.data.len() <= limits.max_dump, "dump exceeded its cap");
    }
    for extra in &report.extra {
        assert!(
            extra.len() >= 0x40 && &extra[..2] == b"MZ",
            "emitted an allocation payload that is not a PE image"
        );
    }
});
