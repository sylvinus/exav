use std::io;

use lzxd::Lzxd;

use crate::formats::cab_parse::mszip::MsZipDecompressor;

const CTYPE_NONE: u16 = 0;
const CTYPE_MSZIP: u16 = 1;
const CTYPE_QUANTUM: u16 = 2;
const CTYPE_LZX: u16 = 3;

const QUANTUM_LEVEL_MIN: u16 = 1;
const QUANTUM_LEVEL_MAX: u16 = 7;
const QUANTUM_MEMORY_MIN: u16 = 10;
const QUANTUM_MEMORY_MAX: u16 = 21;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub(crate) enum CompressionType {
    None,
    MsZip,
    #[allow(dead_code)]
    Quantum(u16, u16),
    Lzx(lzxd::WindowSize),
}

impl CompressionType {
    pub(crate) fn from_bitfield(bits: u16) -> io::Result<CompressionType> {
        let ctype = bits & 0x000f;
        if ctype == CTYPE_NONE {
            Ok(CompressionType::None)
        } else if ctype == CTYPE_MSZIP {
            Ok(CompressionType::MsZip)
        } else if ctype == CTYPE_QUANTUM {
            let level = (bits & 0x00f0) >> 4;
            if !(QUANTUM_LEVEL_MIN..=QUANTUM_LEVEL_MAX).contains(&level) {
                invalid_data!("Invalid Quantum level: 0x{:02x}", level);
            }
            let memory = (bits & 0x1f00) >> 8;
            if !(QUANTUM_MEMORY_MIN..=QUANTUM_MEMORY_MAX).contains(&memory) {
                invalid_data!("Invalid Quantum memory: 0x{:02x}", memory);
            }
            Ok(CompressionType::Quantum(level, memory))
        } else if ctype == CTYPE_LZX {
            let window = (bits & 0x1f00) >> 8;
            let window = match window {
                15 => lzxd::WindowSize::KB32,
                16 => lzxd::WindowSize::KB64,
                17 => lzxd::WindowSize::KB128,
                18 => lzxd::WindowSize::KB256,
                19 => lzxd::WindowSize::KB512,
                20 => lzxd::WindowSize::MB1,
                21 => lzxd::WindowSize::MB2,
                22 => lzxd::WindowSize::MB4,
                23 => lzxd::WindowSize::MB8,
                24 => lzxd::WindowSize::MB16,
                25 => lzxd::WindowSize::MB32,
                _ => invalid_data!("Invalid LZX window: 0x{:02x}", window),
            };
            Ok(CompressionType::Lzx(window))
        } else {
            invalid_data!("Invalid compression type: 0x{:04x}", bits);
        }
    }

    pub(crate) fn into_decompressor(self) -> io::Result<Decompressor> {
        match self {
            CompressionType::None => Ok(Decompressor::Uncompressed),
            CompressionType::MsZip => Ok(Decompressor::MsZip(Box::new(MsZipDecompressor::new()))),
            CompressionType::Quantum(_level, window) => Ok(Decompressor::Quantum(Box::new(
                super::qtm::QuantumDecompressor::new(window)?,
            ))),
            CompressionType::Lzx(window_size) => {
                Ok(Decompressor::Lzx(Box::new(Lzxd::new(window_size))))
            }
        }
    }
}

pub(crate) enum Decompressor {
    Uncompressed,
    MsZip(Box<MsZipDecompressor>),
    Lzx(Box<Lzxd>),
    Quantum(Box<super::qtm::QuantumDecompressor>),
}

/// What one CFDATA block gave: the bytes it decoded, and the error that
/// stopped it short of its size, if one did.
pub(crate) struct Decoded {
    pub(crate) data: Vec<u8>,
    pub(crate) error: Option<io::Error>,
}

impl Decoded {
    pub(crate) fn failed(error: io::Error) -> Self {
        Decoded {
            data: Vec::new(),
            error: Some(error),
        }
    }

    fn of(result: io::Result<Vec<u8>>) -> Self {
        match result {
            Ok(data) => Decoded { data, error: None },
            Err(e) => Decoded::failed(e),
        }
    }
}

impl Decompressor {
    /// Decode one block. `cut`: the file ended inside it, so `data` is what
    /// was there. Only MSZIP and stored blocks give back a part of a block
    /// that failed or was cut: LZX and Quantum hand over a frame whole or not
    /// at all.
    pub(crate) fn decompress(
        &mut self,
        data: Vec<u8>,
        uncompressed_size: usize,
        cut: bool,
    ) -> Decoded {
        let cut_error = |e: io::Error| {
            if cut {
                io::Error::new(io::ErrorKind::UnexpectedEof, e)
            } else {
                e
            }
        };
        match self {
            Decompressor::Uncompressed => Decoded {
                data,
                error: cut.then(|| io::ErrorKind::UnexpectedEof.into()),
            },
            Decompressor::MsZip(decompressor) => {
                decompressor.decompress_block(&data, uncompressed_size, cut)
            }
            Decompressor::Lzx(decompressor) => Decoded::of(
                decompressor
                    .decompress_next(&data, uncompressed_size)
                    .map(|slice| slice.to_vec())
                    .map_err(io::Error::other)
                    .map_err(cut_error),
            ),
            Decompressor::Quantum(decompressor) => Decoded::of(
                decompressor
                    .decompress_block(&data, uncompressed_size)
                    .map_err(cut_error),
            ),
        }
    }
}
