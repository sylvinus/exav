//! The signature files in `fuzz/db/`, loaded as a scanner would load them.
//!
//! Included with `#[path = "../db.rs"] mod db;`.
#![allow(dead_code)]

use std::sync::{Arc, OnceLock};

use exav_core::{loader, Scanner};

/// Every file of `fuzz/db/`, by the extension the loader routes it on.
pub const FILES: &[(&str, &[u8])] = &[
    ("ndb", include_bytes!("db/fuzz.ndb")),
    ("ldb", include_bytes!("db/fuzz.ldb")),
    ("hdb", include_bytes!("db/fuzz.hdb")),
    ("hsb", include_bytes!("db/fuzz.hsb")),
    ("mdb", include_bytes!("db/fuzz.mdb")),
    ("cdb", include_bytes!("db/fuzz.cdb")),
    ("ftm", include_bytes!("db/fuzz.ftm")),
    ("yar", include_bytes!("db/fuzz.yar")),
    ("pdb", include_bytes!("db/fuzz.pdb")),
    ("wdb", include_bytes!("db/fuzz.wdb")),
    ("fdb", include_bytes!("db/fuzz.fdb")),
    ("imp", include_bytes!("db/fuzz.imp")),
    ("crb", include_bytes!("db/fuzz.crb")),
    ("db", include_bytes!("db/fuzz.db")),
    ("fp", include_bytes!("db/fuzz.fp")),
    ("ign2", include_bytes!("db/fuzz.ign2")),
    ("pwdb", include_bytes!("db/fuzz.pwdb")),
    ("cbc", include_bytes!("db/fuzz.cbc")),
];

/// The extensions a framed input's kind byte picks from: the loader's own list.
pub const KINDS: &[&str] = &[
    "ndb", "ldb", "hdb", "hsb", "mdb", "msb", "cdb", "ftm", "yar", "pdb", "gdb", "wdb", "fdb",
    "imp", "crb", "db", "fp", "sfp", "ign", "ign2", "pwdb", "cbc", "idb",
];

pub fn kind(byte: u8) -> &'static str {
    KINDS[byte as usize % KINDS.len()]
}

static DB: OnceLock<Arc<Scanner>> = OnceLock::new();

fn built() -> &'static Arc<Scanner> {
    DB.get_or_init(|| {
        // `EXAV_FUZZ_DB_SKIP=yar,ldb` leaves those files out, to see what a
        // file costs a scan; the checks below are for the whole set.
        let skip = std::env::var("EXAV_FUZZ_DB_SKIP").unwrap_or_default();
        let skipped = |ext: &str| skip.split(',').any(|s| s == ext);
        let mut b = loader::Builder::new();
        for (ext, bytes) in FILES.iter().filter(|(e, _)| !skipped(e)) {
            b.add_named_bytes(&format!("fuzz.{ext}"), bytes, false);
        }
        let db = b.build().expect("the fuzz signature files build");
        // A line the loader rejects is a line no input reaches.
        assert_eq!(db.unsupported_count(), 0, "a signature of fuzz/db/ does not load");
        let yara = FILES.iter().find(|(e, _)| *e == "yar").expect("a YARA file").1;
        exav_core::yara::compile(std::str::from_utf8(yara).expect("UTF-8"))
            .unwrap_or_else(|e| panic!("a rule of fuzz/db/fuzz.yar does not compile: {e}"));
        Arc::new(db)
    })
}

/// A scanner over all of `FILES`, built once.
pub fn scanner() -> &'static Scanner {
    built()
}

/// The same, shared.
pub fn shared() -> Arc<Scanner> {
    built().clone()
}
