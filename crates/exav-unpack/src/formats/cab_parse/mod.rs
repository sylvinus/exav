// Vendored from rust-cab (https://github.com/mdsteele/rust-cab)
// License: MIT
// Original author: Michael L. Heilemeier (mdsteele)
// Adapted for exav-unpack: removed builder (write support), unused public types,
// datetime module, tests. Added bounds checks for folder data_blocks OOB and
// Read::read underflow (both panics on malformed CABs). `ReadLe` in place of
// `byteorder`.

#![forbid(unsafe_code)]

use std::io::{self, Read};

/// Little-endian integers read off a reader.
pub(crate) trait ReadLe: Read {
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut b = [0u8; 1];
        self.read_exact(&mut b)?;
        Ok(b[0])
    }

    fn read_u16_le(&mut self) -> io::Result<u16> {
        let mut b = [0u8; 2];
        self.read_exact(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    fn read_u32_le(&mut self) -> io::Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
}

impl<R: Read + ?Sized> ReadLe for R {}

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
