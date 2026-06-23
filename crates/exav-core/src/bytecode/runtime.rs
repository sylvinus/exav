//! Gating and execution of bytecode programs during a scan.
//!
//! A bytecode program runs only when its gate fires. A program that carries a
//! line-2 logical signature (a `.ldb` trigger) is gated by it — regardless of
//! its `kind` — registered in a dedicated [`SigEngine`] under the synthetic
//! name `__bc__<index>`; a match runs that program and supplies the per-subsig
//! match offsets it reads. Only a program with no logical signature (a bare
//! hook name) runs unconditionally, on every file of its hook's type (`kind`
//! selects PE unpacker / PDF / any). A program's detection is whatever it
//! passes to `setvirusname`; if it hits an unsupported op the result is
//! discarded (never trusted).
//!
//! A forced mode (`run_forced` / `run_all_forced`) runs programs regardless of
//! their gate, for testing and differential validation against clamscan.

use super::exec;
use super::parse::{self, Bytecode};
use crate::engine::{EngineBuilder, SigEngine};
use crate::filetype::FileType;
use crate::pe;

/// Engine functionality level reported to programs via the API.
const FLEVEL: u32 = 167;

// Bytecode `kind` values (the hook point). A program is gated by its logical
// signature when it has one, regardless of kind; kind only selects the hook
// type for the bare-hook (no logical signature) programs below.
const KIND_PE_UNPACKER: u32 = 257;
const KIND_PDF: u32 = 258;
const KIND_PE_ALL: u32 = 259;

/// All loaded bytecode programs plus their gates.
pub struct BytecodeRuntime {
    programs: Vec<Bytecode>,
    /// Raw `.cbc` texts of the kept programs (so the runtime can be cached and
    /// rebuilt without a custom serializer for the parsed form).
    sources: Vec<String>,
    /// Logical triggers, each named `__bc__<index>`.
    triggers: SigEngine,
    /// Hook programs: `(program index, file type it hooks; None = any)`.
    hooks: Vec<(usize, Option<FileType>)>,
}

impl Default for BytecodeRuntime {
    fn default() -> Self {
        Self::empty()
    }
}

impl BytecodeRuntime {
    pub fn empty() -> Self {
        Self {
            programs: Vec::new(),
            sources: Vec::new(),
            triggers: EngineBuilder::new().build(),
            hooks: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.programs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }
    /// Raw `.cbc` texts of the kept programs (for caching).
    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    /// Build from raw `.cbc` texts. Texts that fail to parse are skipped.
    pub fn from_sources(sources: Vec<String>) -> Self {
        let mut programs = Vec::new();
        let mut kept = Vec::new();
        let mut eb = EngineBuilder::new();
        let mut hooks = Vec::new();
        for src in sources {
            let Ok(bc) = parse::parse(&src) else { continue };
            let idx = programs.len();
            // A bytecode's `kind` says *when* it runs (which hook); a logical
            // signature on line 2, if present, says *whether* it runs and
            // supplies the per-subsig match offsets the program reads. So gate
            // on the logical signature whenever there is one — independent of
            // kind. Only a bytecode with no logical signature (a bare hook
            // name) runs unconditionally, on every file of its hook's type.
            if let Some(line) = retrigger(&bc.trigger, idx) {
                eb.add_ldb(&line);
            } else {
                match bc.header.kind {
                    KIND_PE_UNPACKER | KIND_PE_ALL => hooks.push((idx, Some(FileType::Pe))),
                    KIND_PDF => hooks.push((idx, Some(FileType::Pdf))),
                    _ => hooks.push((idx, None)),
                }
            }
            programs.push(bc);
            kept.push(src);
        }
        Self {
            programs,
            sources: kept,
            triggers: eb.build(),
            hooks,
        }
    }

    /// Run every program whose gate fires on `data`. Returns the first
    /// detection as `(name, program_index)` plus every buffer any program
    /// extracted (for the engine to recursively re-scan — unpackers surface
    /// their payload via `write`+`extract_new` without detecting directly).
    pub fn scan(
        &self,
        data: &[u8],
        ft: FileType,
        layout: Option<&pe::PeLayout>,
    ) -> (Option<(String, usize)>, Vec<Vec<u8>>) {
        let mut detection = None;
        let mut extracted = Vec::new();
        if self.is_empty() {
            return (detection, extracted);
        }
        let pe = if ft == FileType::Pe {
            pe::bytecode_pe(data)
        } else {
            None
        };
        let pdf = if ft == FileType::Pdf {
            Some(exec::pdf_ctx(data))
        } else {
            None
        };
        let run_one = |idx: usize,
                       det: &mut Option<(String, usize)>,
                       ex: &mut Vec<Vec<u8>>,
                       match_offs: &[u32]| {
            let Some(bc) = self.programs.get(idx) else {
                return;
            };
            let o = run_program(bc, data, pe.as_ref(), pdf.as_ref(), match_offs);
            if o.hit_unsupported {
                return;
            }
            ex.extend(o.extracted);
            if det.is_none() {
                if let Some(d) = o.detection {
                    *det = Some((d, idx));
                }
            }
        };
        // Logical programs, gated by their trigger signature; pass the match
        // offset so `__clambc_match_offsets` reflects where the pattern matched.
        if !self.triggers.is_empty() {
            let mut matches = Vec::new();
            self.triggers.scan_logical_offsets(data, ft, layout, &mut matches);
            for (name, suboffs) in &matches {
                if let Some(idx) = name
                    .strip_prefix("__bc__")
                    .and_then(|n| n.parse::<usize>().ok())
                {
                    // `__clambc_match_offsets[i]` = where subsig `i` matched.
                    // The VM indexes a fixed 64-slot array; pad with the
                    // no-match sentinel and clamp pathological subsig counts.
                    let mut mo = vec![u32::MAX; 64];
                    for (i, &o) in suboffs.iter().take(64).enumerate() {
                        mo[i] = o;
                    }
                    run_one(idx, &mut detection, &mut extracted, &mo);
                }
            }
        }
        // Hook programs, run on every file of their type (no trigger match).
        for &(idx, hook_ft) in &self.hooks {
            if hook_ft.is_none() || hook_ft == Some(ft) {
                run_one(idx, &mut detection, &mut extracted, &[]);
            }
        }
        (detection, extracted)
    }

    /// Run program `idx` regardless of its gate (forced mode, for testing).
    pub fn run_forced(&self, idx: usize, data: &[u8]) -> Option<exec::Outcome> {
        let bc = self.programs.get(idx)?;
        let pe = pe::bytecode_pe(data);
        let pdf = exec::pdf_ctx(data);
        Some(run_program(bc, data, pe.as_ref(), Some(&pdf), &[]))
    }

    /// Run every program regardless of its gate; returns `(name, idx)` for each
    /// that reports a detection with no unsupported op (differential testing).
    pub fn run_all_forced(&self, data: &[u8]) -> Vec<(String, usize)> {
        let pe = pe::bytecode_pe(data);
        let pdf = exec::pdf_ctx(data);
        let mut out = Vec::new();
        for (idx, bc) in self.programs.iter().enumerate() {
            let o = run_program(bc, data, pe.as_ref(), Some(&pdf), &[]);
            if !o.hit_unsupported {
                if let Some(d) = o.detection {
                    out.push((d, idx));
                }
            }
        }
        out
    }

}

/// Run one program's entry function (0) under a bounded, panic-isolated VM.
fn run_program(
    bc: &Bytecode,
    data: &[u8],
    pe: Option<&pe::BcPe>,
    pdf: Option<&exec::PdfCtx>,
    match_offsets: &[u32],
) -> exec::Outcome {
    let ctx = exec::Ctx {
        file: data,
        flevel: FLEVEL,
        types: &bc.types,
        globals: &bc.globals,
        pe,
        pdf,
        match_offsets,
        apis: &bc.apis,
        default_name: &bc.name,
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exec::run(&bc.functions, 0, &ctx)
    }))
    .unwrap_or_default()
}

/// Replace a trigger's signature name with `__bc__<idx>` so a match maps back
/// to the program. `None` if the trigger has no body (a bare hook name).
fn retrigger(trigger: &str, idx: usize) -> Option<String> {
    let (_name, rest) = trigger.split_once(';')?;
    // A logical signature is `TDB;expr;subsig0[;subsig1...]` — at least three
    // `;`-separated fields after the name. Fewer means a bare hook name (or a
    // name+TDB with no subsignatures), which is not lsig-gated.
    if rest.split(';').count() < 3 {
        return None;
    }
    Some(format!("__bc__{idx};{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The real EICAR bytecode trigger + program would need the .cbc text; here
    // we test the gate plumbing with the retrigger helper and an empty runtime.
    #[test]
    fn retrigger_renames_only_the_name() {
        assert_eq!(
            retrigger("Foo.Bar;Engine:56-255,Target:0;0;dead", 7).as_deref(),
            Some("__bc__7;Engine:56-255,Target:0;0;dead")
        );
        assert_eq!(retrigger("BareHookName", 3), None);
    }

    #[test]
    fn empty_runtime_scans_nothing() {
        let rt = BytecodeRuntime::empty();
        assert!(rt.is_empty());
        let (det, extracted) = rt.scan(b"anything", FileType::Pe, None);
        assert_eq!(det, None);
        assert!(extracted.is_empty());
    }
}
