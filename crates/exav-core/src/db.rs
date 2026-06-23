//! Signature database loading from files/directories, including CVD/CLD
//! containers. Routes each db file to the right matcher by extension.
//!
//! Recognised:
//!   `.ndb`           byte signatures (literal bodies)
//!   `.db`            exav simple `Name=HEX`
//!   `.hdb/.hsb/...`  whole-file hash signatures
//!   `.fdb`           exav fuzzy signatures (imphash/tlsh)
//!   `.cvd/.cld`      signature container (extracted, then routed)
//!   `.ldb`           logical signatures (not yet matched; counted)

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::cvd;
use crate::engine::EngineBuilder;

/// Read a database file into memory, bounded so a huge or special file (a
/// FIFO/device reports length 0) can't exhaust memory.
fn read_capped(path: &Path) -> Result<Vec<u8>, String> {
    const MAX_DB_FILE: u64 = 2 * 1024 * 1024 * 1024;
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut buf = Vec::new();
    f.take(MAX_DB_FILE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if buf.len() as u64 > MAX_DB_FILE {
        return Err(format!("{}: database file too large", path.display()));
    }
    Ok(buf)
}
use crate::fuzzy::FuzzyDb;
use crate::hashes::{HashDb, SectionHashDb};
use crate::ml::HeuristicModel;
use crate::patterns::{Pattern, PatternSet, EICAR};
use crate::Database;

/// Accumulates parsed signatures from multiple files before building.
#[derive(Default)]
pub struct Loader {
    /// Literal patterns for the streaming path (literal `.ndb` + `.db`).
    patterns: Vec<Pattern>,
    /// The full in-memory engine, fed signature text file-by-file so the raw
    /// text is dropped as it's compiled (rather than concatenated and held
    /// alive through the memory-heavy automaton build).
    engine: EngineBuilder,
    hashes: HashDb,
    sections: SectionHashDb,
    fuzzy: FuzzyDb,
    cdb: crate::container::CdbDb,
    yara: crate::yara::YaraDb,
    allow: HashDb,
    ignored: std::collections::HashSet<String>,
    /// Raw `.cbc` texts; parsed and gated into a runtime at [`Self::build`].
    bytecode_sources: Vec<String>,
}

impl Loader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a path that is either a single db file/container or a directory
    /// (scanned recursively for db files).
    pub fn add_path(&mut self, path: &Path) -> Result<(), String> {
        if path.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(path)
                .map_err(|e| format!("read dir {}: {e}", path.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .collect();
            entries.sort();
            for p in entries {
                if p.is_file() {
                    self.add_file(&p)?;
                }
            }
            Ok(())
        } else {
            self.add_file(path)
        }
    }

    fn add_file(&mut self, path: &Path) -> Result<(), String> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        match ext.as_str() {
            "cvd" | "cld" => {
                let data = read_capped(path)?;
                let (_hdr, files) = cvd::read(&data)?;
                for f in files {
                    self.add_named_bytes(&f.name, &f.data);
                }
                Ok(())
            }
            "ndb" | "ndu" | "db" | "hdb" | "hdu" | "hsb" | "hsu" | "fdb" | "imp" | "ldb" | "ldu"
            | "mdb" | "mdu" | "msb" | "cdb" | "ftm" | "yar" | "yara" | "fp" | "sfp" | "ign" | "ign2" | "cbc" => {
                let data = read_capped(path)?;
                self.add_named_text(name, &String::from_utf8_lossy(&data));
                Ok(())
            }
            // Skip anything else in a database directory (.cdiff/.sign/.info,
            // state files, etc.) without reading it.
            _ => Ok(()),
        }
    }

    /// Route raw bytes from a CVD member by its name/extension.
    fn add_named_bytes(&mut self, name: &str, data: &[u8]) {
        // db members are text; lossy decode is fine for signature lines.
        let text = String::from_utf8_lossy(data);
        self.add_named_text(name, &text);
    }

    fn add_named_text(&mut self, name: &str, text: &str) {
        let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        match ext.as_str() {
            // `.ndb`/`.ndu` (unpacked-content variant share the format).
            "ndb" | "ndu" => {
                // Literal subset for streaming; full text for the engine.
                let (mut pats, _unsup) = PatternSet::parse_ndb(text);
                self.patterns.append(&mut pats);
                self.engine.add_ndb(text);
            }
            "db" => {
                if let Ok(mut pats) = PatternSet::parse_simple(text) {
                    self.patterns.append(&mut pats);
                }
            }
            "hdb" | "hsb" | "hdu" | "hsu" => self.hashes.extend_from_text(text),
            "mdb" | "mdu" | "msb" => self.sections.extend_from_text(text),
            "fdb" => self.fuzzy.extend_from_text(text),
            "imp" => self.fuzzy.extend_imp(text),
            "cdb" => self.cdb.extend_from_text(text),
            "yar" | "yara" => self.yara.extend_from_text(text),
            // Whole-file hash allowlist (clears a detection).
            "fp" | "sfp" => self.allow.extend_from_text(text),
            // Signature-name ignore lists. `.ign` is `db:line:name`, `.ign2`
            // is just the name; the trailing `:`-field is the name in both.
            "ign" | "ign2" => {
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some(name) = line.rsplit(':').next() {
                        self.ignored.insert(name.to_string());
                    }
                }
            }
            "ldb" | "ldu" => {
                self.engine.add_ldb(text);
            }
            // Bytecode programs: keep the raw text; parsing + gating happens at
            // build() (the runtime drops any that fail to parse).
            "cbc" if crate::bytecode::parse(text).is_ok() => {
                self.bytecode_sources.push(text.to_string());
            }
            _ => {}
        }
    }

    /// Build the final database. If no patterns were loaded, the built-in
    /// EICAR pattern is retained so the engine always has at least a test
    /// signature.
    pub fn build(mut self) -> Result<Database, String> {
        // Fold EICAR into the engine so in-memory scans detect it without the
        // streaming automaton; also keep it in the streaming literal set.
        self.engine.add_literal("Exav.Test.EICAR", EICAR);

        // Sort + intern the hash tables BEFORE building the (memory-heavy)
        // automaton: finalize collapses millions of per-entry strings into one
        // buffer, so that transient doesn't coexist with the build's peak.
        let mut hashes = self.hashes;
        let mut sections = self.sections;
        let mut allow = self.allow;
        hashes.finalize();
        sections.finalize();
        allow.finalize();

        let engine = self.engine.build();

        let mut pats = self.patterns;
        pats.push(Pattern::new("Exav.Test.EICAR", EICAR));
        let patterns = PatternSet::build(&pats, 0)?;

        Ok(Database {
            patterns,
            engine,
            hashes,
            sections,
            fuzzy: self.fuzzy,
            cdb: self.cdb,
            yara: self.yara,
            allow,
            ignored: self.ignored,
            bytecode: crate::bytecode::runtime::BytecodeRuntime::from_sources(
                self.bytecode_sources,
            ),
            model: Box::new(HeuristicModel),
            ml_threshold: 0.85,
        })
    }
}

/// Load a database from a file/dir path (convenience). A prebuilt exav cache
/// file (see [`crate::cache`]) is detected by its magic tag and loaded
/// directly, skipping signature parsing and automaton construction.
pub fn load(path: &Path) -> Result<Database, String> {
    if path.is_file() && crate::cache::is_cache_file(path) {
        return crate::cache::load(path).map_err(|e| format!("{}: {e}", path.display()));
    }
    let mut loader = Loader::new();
    loader.add_path(path)?;
    loader.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_mixed_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.ndb"),
            "Sig.A:0:*:deadbeef\nSig.W:0:*:de*ad\n",
        )
        .unwrap();
        let d = crate::hashes::digests_of(b"x");
        std::fs::write(dir.path().join("b.hdb"), format!("{}:*:Sig.H\n", d.md5)).unwrap();
        let mut f = std::fs::File::create(dir.path().join("c.fdb")).unwrap();
        writeln!(f, "imphash:abcd:Sig.F").unwrap();

        let db = load(dir.path()).unwrap();
        assert!(!db.patterns.is_empty());
        // "de*ad" has no >=2-byte literal anchor -> counted unsupported.
        assert_eq!(db.unsupported_count(), 1);
        assert!(!db.hashes.is_empty());
        assert!(!db.fuzzy.is_empty());
    }
}
