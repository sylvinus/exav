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

/// An error loading a signature database.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("read dir {path}: {source}")]
    ReadDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: database file too large")]
    TooLarge { path: String },
    #[error("parsing signature container: {0}")]
    Container(String),
    #[error("building pattern set: {0}")]
    Patterns(String),
    #[error("loading cache {path}: {source}")]
    Cache {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Read a database file into memory, bounded so a huge or special file (a
/// FIFO/device reports length 0) can't exhaust memory.
fn read_capped(path: &Path) -> Result<Vec<u8>, DbError> {
    const MAX_DB_FILE: u64 = 2 * 1024 * 1024 * 1024;
    let io_err = |e: std::io::Error| DbError::Io {
        path: path.display().to_string(),
        source: e,
    };
    let f = File::open(path).map_err(io_err)?;
    let mut buf = Vec::new();
    f.take(MAX_DB_FILE + 1).read_to_end(&mut buf).map_err(io_err)?;
    if buf.len() as u64 > MAX_DB_FILE {
        return Err(DbError::TooLarge {
            path: path.display().to_string(),
        });
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
    /// ClamAV `--detect-pua`: when false (default), the PUA-variant databases
    /// (`.ndu`/`.ldu`/`.hdu`/`.hsu`/`.mdu`) are skipped entirely and `PUA.*`
    /// signatures elsewhere are dropped.
    detect_pua: bool,
    /// Retained for API/CLI compatibility (`--clamav-compat` calls
    /// [`Self::set_unofficial_suffix`]), but no longer affects what is stored.
    ///
    /// Provenance — whether a signature came from an unofficial (non-`.cvd`)
    /// database — is now recorded *per signature*, always, regardless of this
    /// flag. The `.UNOFFICIAL` name suffix / `YARA.` prefix is applied at REPORT
    /// time (gated on `ScanOptions::compat`), so ONE cache serves both compat and
    /// non-compat scans. Official `.cvd`/`.cld` sigs carry `unofficial=false` and
    /// are never suffixed. See `crate::report_name`.
    unofficial_suffix: bool,
    /// `.ftm` file-type magic rules (fallback type detection).
    ftm: crate::filetype::FtmMagics,
    /// `.idb` PE-icon perceptual-hash signatures.
    icons: crate::icon::IconDb,
    /// Passwords parsed from `.pwdb` files, used to decrypt encrypted archive
    /// members. User-supplied (the official CVDs ship no `.pwdb`).
    passwords: Vec<String>,
}

impl Loader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable ClamAV PUA detection (`--detect-pua`): load the `.??u` PUA
    /// databases and keep `PUA.*` signatures. Off by default. Must be set before
    /// loading any path.
    pub fn set_detect_pua(&mut self, on: bool) {
        self.detect_pua = on;
        self.engine.set_detect_pua(on);
    }

    /// Retained for API/CLI compatibility (`--clamav-compat`). The unofficial
    /// suffix is now applied at scan/report time (gated on `ScanOptions::compat`),
    /// using per-signature provenance recorded at load regardless of this flag, so
    /// one cache serves both modes. Kept as a setter so callers/tests don't break;
    /// it no longer changes what gets cached.
    pub fn set_unofficial_suffix(&mut self, on: bool) {
        self.unofficial_suffix = on;
    }

    /// Load a path that is either a single db file/container or a directory
    /// (scanned recursively for db files).
    pub fn add_path(&mut self, path: &Path) -> Result<(), DbError> {
        if path.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(path)
                .map_err(|e| DbError::ReadDir {
                    path: path.display().to_string(),
                    source: e,
                })?
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

    fn add_file(&mut self, path: &Path) -> Result<(), DbError> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        match ext.as_str() {
            "cvd" | "cld" => {
                // A `.cvd`/`.cld` is an official (signed) container: its members
                // keep their names verbatim (no `.UNOFFICIAL`).
                let data = read_capped(path)?;
                let (_hdr, files) = cvd::read(&data).map_err(DbError::Container)?;
                for f in files {
                    self.add_named_bytes(&f.name, &f.data, true);
                }
                Ok(())
            }
            "ndb" | "ndu" | "db" | "hdb" | "hdu" | "hsb" | "hsu" | "fdb" | "imp" | "ldb" | "ldu"
            | "mdb" | "mdu" | "msb" | "cdb" | "ftm" | "pdb" | "gdb" | "wdb" | "crb" | "yar"
            | "yara" | "fp" | "sfp" | "ign" | "ign2" | "cbc" | "idb" | "pwdb" => {
                // A loose signature file is unofficial (not a signed container).
                let data = read_capped(path)?;
                self.add_named_text(name, &String::from_utf8_lossy(&data), false);
                Ok(())
            }
            // Skip anything else in a database directory (.cdiff/.sign/.info,
            // state files, etc.) without reading it.
            _ => Ok(()),
        }
    }

    /// Route raw bytes from a CVD member by its name/extension. `official` is
    /// true for members of a signed `.cvd`/`.cld`.
    fn add_named_bytes(&mut self, name: &str, data: &[u8], official: bool) {
        // db members are text; lossy decode is fine for signature lines.
        let text = String::from_utf8_lossy(data);
        self.add_named_text(name, &text, official);
    }

    fn add_named_text(&mut self, name: &str, text: &str, official: bool) {
        let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        // Provenance: a signature from any database that is NOT a signed
        // `.cvd`/`.cld` container is "unofficial" — ClamAV suffixes such
        // detections with `.UNOFFICIAL` (and YARA rules with a `YARA.` prefix).
        // We record this bit per signature, ALWAYS (independent of any compat
        // flag), and store the CLEAN name. The suffix is applied at report time
        // (see `crate::report_name`), gated on `ScanOptions::compat`, so a single
        // cache serves both compat and non-compat scans.
        let unofficial = !official;
        // The `.??u` databases (`.ndu`/`.ldu`/`.hdu`/`.hsu`/`.mdu`) are ClamAV's
        // PUA signature sets, loaded only with `DetectPUA`. Skip them by default
        // so exav doesn't flag PUA (notably hash-based PUA, which has no `PUA.`
        // name gate) on a default config.
        if !self.detect_pua && matches!(ext.as_str(), "ndu" | "ldu" | "hdu" | "hsu" | "mdu" | "sdu")
        {
            return;
        }
        match ext.as_str() {
            // `.ndb`/`.ndu` (unpacked-content variant share the format).
            "ndb" | "ndu" => {
                // Literal subset for streaming; full text for the engine.
                let (mut pats, _unsup) = PatternSet::parse_ndb_prov(text, unofficial);
                self.patterns.append(&mut pats);
                self.engine.add_ndb(text, unofficial);
            }
            "db" => {
                if let Ok(mut pats) = PatternSet::parse_simple(text) {
                    self.patterns.append(&mut pats);
                }
            }
            "hdb" | "hsb" | "hdu" | "hsu" => self.hashes.extend_from_text_prov(text, unofficial),
            "mdb" | "mdu" | "msb" => self.sections.extend_from_text_prov(text, unofficial),
            "fdb" => self.fuzzy.extend_from_text(text),
            "imp" => self.fuzzy.extend_imp(text),
            "cdb" => self.cdb.extend_from_text_prov(text, unofficial),
            // File-type magic: applied as a fallback when content detection is
            // inconclusive (never overrides native typing).
            "ftm" => self.ftm.extend_from_text(text),
            // Phishing (`.pdb`/`.gdb`/`.wdb`) and Authenticode-cert (`.crb`)
            // databases are RECOGNISED but deliberately not applied yet: each is
            // a separate subsystem (URL display-vs-real comparison; PKCS#7 cert
            // verification) with ~no ROI on a binary-malware corpus. Handled as
            // an explicit no-op so they aren't silently misrouted.
            "pdb" | "gdb" | "wdb" | "crb" => {}
            "yar" | "yara" => self.yara.extend_from_text(text, unofficial),
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
                self.engine.add_ldb(text, unofficial);
            }
            // PE-icon perceptual-hash signatures (`daily.idb`, `main.idb`):
            // referenced by `IconGroup1/2`-constrained logical sigs.
            "idb" => self.icons.extend_from_text(text),
            // ClamAV password database: each line is
            // `SignatureName;TargetDescriptionBlock;PWStorageType;Password`
            // (PWStorageType 0 = cleartext, 1 = hex-encoded). We use only the
            // password value as a candidate for archive decryption; the
            // signature-name / target-description scoping is not yet applied
            // (every loaded password is tried against every encrypted member).
            "pwdb" => parse_pwdb_into(text, &mut self.passwords),
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
    pub fn build(mut self) -> Result<Database, DbError> {
        // Fold EICAR into the engine so in-memory scans detect it without the
        // streaming automaton; also keep it in the streaming literal set.
        self.engine.add_literal("Eicar-Test-Signature", EICAR);

        // Sort + intern the hash tables BEFORE building the (memory-heavy)
        // automaton: finalize collapses millions of per-entry strings into one
        // buffer, so that transient doesn't coexist with the build's peak.
        let mut hashes = self.hashes;
        let mut sections = self.sections;
        let mut allow = self.allow;
        hashes.finalize();
        sections.finalize();
        allow.finalize();
        // Compile YARA rules now (slow for large rulesets) so the result is
        // stored in the cache and scans don't recompile on first use.
        self.yara.finalize();

        let engine = self.engine.build();

        let mut pats = self.patterns;
        pats.push(Pattern::new("Eicar-Test-Signature", EICAR));
        let patterns = PatternSet::build(&pats, 0).map_err(DbError::Patterns)?;

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
            ftm: self.ftm,
            icons: self.icons,
            passwords: self.passwords,
        })
    }
}

/// Parse a ClamAV `.pwdb` password database into `out`. Each non-comment line is
/// `SignatureName;TargetDescriptionBlock;PWStorageType;Password`, where
/// `PWStorageType` is `0` (cleartext) or `1` (hex-encoded). Malformed lines and
/// undecodable hex are skipped (best-effort; a bad line never aborts the load).
/// Duplicates are de-duplicated, preserving first-seen order.
fn parse_pwdb_into(text: &str, out: &mut Vec<String>) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split into at most 4 fields; the password may itself contain ';' only
        // in the cleartext case, but ClamAV's format treats the 4th field as the
        // remainder, so `splitn(4, ';')` keeps a `;` inside a cleartext password.
        let mut it = line.splitn(4, ';');
        let (_name, _target, storage, pw) =
            match (it.next(), it.next(), it.next(), it.next()) {
                (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
                _ => continue,
            };
        let password = match storage.trim() {
            "0" => pw.to_string(),
            "1" => match hex_decode(pw.trim()) {
                Some(bytes) => match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => continue, // non-UTF8 password: skip (we try &str)
                },
                None => continue,
            },
            _ => continue,
        };
        if !password.is_empty() && !out.contains(&password) {
            out.push(password);
        }
    }
}

/// Decode an even-length ASCII hex string to bytes; `None` on any non-hex digit
/// or odd length.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut i = 0;
    while i < b.len() {
        out.push((nib(b[i])? << 4) | nib(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// Load a database from a file/dir path (convenience). A prebuilt exav cache
/// file (see [`crate::cache`]) is detected by its magic tag and loaded
/// directly, skipping signature parsing and automaton construction.
pub fn load(path: &Path) -> Result<Database, DbError> {
    load_with_pua(path, false)
}

/// As [`load`], with control over ClamAV PUA detection. A prebuilt cache already
/// reflects the PUA choice made when it was built, so `detect_pua` only affects
/// loading a raw db file/dir/CVD.
pub fn load_with_pua(path: &Path, detect_pua: bool) -> Result<Database, DbError> {
    load_with_options(path, detect_pua, false)
}

/// As [`load`], with control over PUA detection and the unofficial-name suffix.
/// `unofficial_suffix` (set under `--clamav-compat`) tags signatures from
/// unofficial databases with `.UNOFFICIAL`/`YARA.` for exact ClamAV output. A
/// prebuilt cache already reflects the choices made when it was built, so these
/// only affect loading a raw db file/dir/CVD.
pub fn load_with_options(
    path: &Path,
    detect_pua: bool,
    unofficial_suffix: bool,
) -> Result<Database, DbError> {
    if path.is_file() && crate::cache::is_cache_file(path) {
        return crate::cache::load(path).map_err(|e| DbError::Cache {
            path: path.display().to_string(),
            source: e,
        });
    }
    let mut loader = Loader::new();
    loader.set_detect_pua(detect_pua);
    loader.set_unofficial_suffix(unofficial_suffix);
    loader.add_path(path)?;
    loader.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_pwdb_cleartext_and_hex() {
        // "secret" = 736563726574 in hex.
        let text = "\
# comment\n\
Sig.A;Engine:81-255,Target:0;0;cleartext-pw\n\
Sig.B;Engine:81-255,Target:0;1;736563726574\n\
malformed-line-no-fields\n\
Sig.C;td;0;cleartext-pw\n"; // duplicate password de-duped
        let mut out = Vec::new();
        parse_pwdb_into(text, &mut out);
        assert_eq!(out, vec!["cleartext-pw".to_string(), "secret".to_string()]);
    }

    #[test]
    fn pwdb_loaded_into_database_pool() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("p.pwdb"),
            "Sig;Engine:81-255,Target:0;0;hunter2\n",
        )
        .unwrap();
        // Need at least one real signature db so the loader builds.
        std::fs::write(dir.path().join("a.ndb"), "Sig.A:0:*:6d616c77617265\n").unwrap();
        let db = load(dir.path()).unwrap();
        assert_eq!(db.passwords, vec!["hunter2".to_string()]);
    }

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

    #[test]
    fn loose_ndb_stores_clean_name_with_provenance() {
        use crate::filetype::FileType;
        let dir = tempfile::tempdir().unwrap();
        // 6d616c77617265 = "malware". A loose `.ndb` is unofficial.
        std::fs::write(dir.path().join("a.ndb"), "Demo.Loose:0:*:6d616c77617265\n").unwrap();
        let db = load(dir.path()).unwrap();
        // The engine stores the CLEAN name plus an `unofficial=true` provenance
        // bit; the `.UNOFFICIAL` suffix is NEVER baked into the name.
        assert_eq!(
            db.engine.scan(b"xx malware xx", FileType::Unknown),
            Some(("Demo.Loose".to_string(), 3, true))
        );
    }

    /// (a) non-compat reports the clean name; (b) a compat scan of the SAME
    /// loaded DB reports `name.UNOFFICIAL`. One cache/database serves both.
    #[test]
    fn report_time_suffix_from_one_db() {
        use crate::{analyze, ScanOptions, Verdict};
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.ndb"), "Demo.Loose:0:*:6d616c77617265\n").unwrap();
        let db = load(dir.path()).unwrap();
        let data = b"xx malware xx";

        let clean = match analyze(&db, data, &ScanOptions::default()).verdict {
            Verdict::Infected { signature, .. } => signature,
            other => panic!("expected detection, got {other:?}"),
        };
        assert_eq!(clean, "Demo.Loose");

        let mut compat = ScanOptions::default();
        compat.compat = true;
        let suffixed = match analyze(&db, data, &compat).verdict {
            Verdict::Infected { signature, .. } => signature,
            other => panic!("expected detection, got {other:?}"),
        };
        assert_eq!(suffixed, "Demo.Loose.UNOFFICIAL");
    }

    /// (c) an official `.cvd` signature is NEVER suffixed, even in compat, while a
    /// loose sig loaded alongside it IS — proving per-signature provenance for a
    /// mixed source.
    #[test]
    fn official_cvd_never_suffixed_mixed_source() {
        use crate::{analyze, ScanOptions, Verdict};
        let mut loader = Loader::new();
        // Official member (as if from a `.cvd`): 6f6666696369616c = "official".
        loader.add_named_text("main.ndb", "Demo.Official:0:*:6f6666696369616c\n", true);
        // Loose unofficial member in the same matcher.
        loader.add_named_text("extra.ndb", "Demo.Loose:0:*:6d616c77617265\n", false);
        let db = loader.build().unwrap();

        let mut compat = ScanOptions::default();
        compat.compat = true;

        let official = match analyze(&db, b"-- official --", &compat).verdict {
            Verdict::Infected { signature, .. } => signature,
            other => panic!("expected detection, got {other:?}"),
        };
        assert_eq!(official, "Demo.Official", "official sig must not be suffixed");

        let loose = match analyze(&db, b"-- malware --", &compat).verdict {
            Verdict::Infected { signature, .. } => signature,
            other => panic!("expected detection, got {other:?}"),
        };
        assert_eq!(loose, "Demo.Loose.UNOFFICIAL");
    }

    /// (d) a compat `.ign2` naming the SUFFIXED detection still suppresses it
    /// (the suffix is applied before suppression).
    #[test]
    fn ign_suppresses_suffixed_name_in_compat() {
        use crate::{analyze, ScanOptions, Verdict};
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.ndb"), "Demo.Loose:0:*:6d616c77617265\n").unwrap();
        // A real-world compat `.ign2` names the suffixed detection.
        std::fs::write(dir.path().join("b.ign2"), "Demo.Loose.UNOFFICIAL\n").unwrap();
        let db = load(dir.path()).unwrap();
        let data = b"xx malware xx";

        let mut compat = ScanOptions::default();
        compat.compat = true;
        // In compat the detection name is suffixed and matches the ign entry.
        assert_eq!(analyze(&db, data, &compat).verdict, Verdict::Clean);
        // In non-compat the detection is the clean `Demo.Loose`, which the
        // suffixed ign entry does NOT name — so it still fires.
        assert!(matches!(
            analyze(&db, data, &ScanOptions::default()).verdict,
            Verdict::Infected { .. }
        ));
    }
}
