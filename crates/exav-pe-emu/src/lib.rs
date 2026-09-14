//! A sandboxed x86-32 emulator for PE runtime-packer stubs.
//!
//! A runtime packer replaces a program's code with a compressed or encrypted
//! blob plus a small stub that reconstructs it in memory at start-up. Static
//! unpacking means reimplementing each stub's format, version by version — and
//! the packers that matter defend against exactly that, with layouts that vary
//! per build. Running the stub instead is format-agnostic: whatever scheme it
//! uses, it must produce the original image in memory before it jumps to it,
//! and *that* is the moment worth capturing.
//!
//! The pieces:
//!
//! * `mem` — a sparse 32-bit address space that faults on unmapped access and
//!   remembers which pages the stub wrote.
//! * `cpu` — an x86-32 interpreter (decoding via `exav-x86`) that stops, by
//!   value, on anything it cannot faithfully execute.
//! * `win` — the minimum Windows a stub sees: a TEB/PEB, a loader module
//!   list, and synthetic `kernel32`/`ntdll` images whose exports are trap
//!   addresses. Both ways a stub resolves imports — calling `GetProcAddress`
//!   and walking the export directory by hand — therefore work.
//! * `image` — mapping the PE in, and dumping it back out once the stub has
//!   rebuilt it.
//! * [`run`] — the driver: budgets, the original-entry-point heuristics, and
//!   the acceptance test a dump must pass before it is emitted.
//!
//! The public surface is [`run`] plus [`PAGE_SIZE`]; the rest is internals.
//!
//! **Nothing escapes the sandbox.** The emulator has no syscalls, no file or
//! network access and no host memory beyond the page table; an emulated
//! `CreateFile` returns a handle that does nothing. Malware being unpacked here
//! is *interpreted*, never executed.

#![forbid(unsafe_code)]

pub(crate) mod cpu;
pub(crate) mod image;
pub(crate) mod mem;
pub mod run;
pub(crate) mod win;

pub use mem::PAGE_SIZE;
pub use run::{unpack, EmuLimits, Report, Unpacked};
