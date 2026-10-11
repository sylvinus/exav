//! Entry points for the fuzz targets over what the daemon reads off the
//! network: the clamd command loop and the ICAP request loop, over memory in
//! place of a socket. Not an API; built only with the `fuzzing` feature.

use exav_core::{ScanOptions, Scanner};
use std::io::{self, Cursor, Read};

use crate::daemon::{handle_conn, FdSource};

/// A connection's bytes, from memory. A transport that cannot pass a
/// descriptor, as TCP cannot.
struct Memory<'a>(Cursor<&'a [u8]>);

impl Read for Memory<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl FdSource for Memory<'_> {
    fn take_fd(&mut self) -> Option<std::fs::File> {
        None
    }
}

/// One clamd connection that sends `input`, and what the daemon answers.
/// Verbs that take a path answer an error: see `daemon::dispatch`.
pub fn clamd(input: &[u8], db: &Scanner, opts: &ScanOptions) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = handle_conn(
        Memory(Cursor::new(input)),
        &mut out,
        db,
        opts,
        &|| {},
        &|| {},
        &|| {},
        &|| false,
        false,
    );
    out
}

/// One ICAP connection that sends `input`, and what the server answers.
#[cfg(feature = "icap")]
pub fn icap(input: &[u8], db: std::sync::Arc<Scanner>, opts: &ScanOptions) -> Vec<u8> {
    crate::icap::fuzz_exchange(input, db, opts)
}
