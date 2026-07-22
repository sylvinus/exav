// Vendored from rust-cab (https://github.com/mdsteele/rust-cab)
// License: MIT
// Original author: Michael L. Heilemeier (mdsteele)
// Adapted for exav-unpack: removed builder (write support), unused public types,
// datetime module, tests. Added bounds checks for folder data_blocks OOB and
// Read::read underflow (both panics on malformed CABs).

#![forbid(unsafe_code)]

#[macro_use]
mod macros;
pub(crate) mod cabinet;
pub(crate) mod consts;
pub(crate) mod ctype;
pub(crate) mod file;
pub(crate) mod folder;
pub(crate) mod mszip;
mod qtm;
pub(crate) mod string;
