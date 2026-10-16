use std::io;

use flate2::Decompress;

const MSZIP_SIGNATURE: u16 = 0x4B43; // "CK" little-endian
const MSZIP_SIGNATURE_LEN: usize = 2;
const DEFLATE_MAX_DICT_LEN: usize = 0x8000;

pub(crate) struct MsZipDecompressor {
    decompressor: Decompress,
    dictionary: Vec<u8>,
}

impl MsZipDecompressor {
    pub(crate) fn new() -> MsZipDecompressor {
        MsZipDecompressor {
            decompressor: Decompress::new(false),
            dictionary: Vec::with_capacity(DEFLATE_MAX_DICT_LEN),
        }
    }

    /// Decode one CFDATA block. `cut`: the file ended inside the block, so
    /// `data` is what was there of it.
    ///
    /// What came out before a failure is returned with it, so that a block
    /// damaged or cut part way keeps its decoded start. Once a block has
    /// failed the history the next one needs is wrong: the caller stops.
    pub(crate) fn decompress_block(
        &mut self,
        data: &[u8],
        uncompressed_size: usize,
        cut: bool,
    ) -> super::ctype::Decoded {
        use super::ctype::Decoded;
        let eof = |m: &str| io::Error::new(io::ErrorKind::UnexpectedEof, m.to_string());
        let bad = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
        if data.len() < MSZIP_SIGNATURE_LEN {
            return Decoded::failed(if cut {
                eof("MSZIP block cut inside its signature")
            } else {
                bad("MSZIP decompression failed: Invalid block signature".into())
            });
        }
        if ((data[0] as u16) | ((data[1] as u16) << 8)) != MSZIP_SIGNATURE {
            return Decoded::failed(bad(
                "MSZIP decompression failed: Invalid block signature".into()
            ));
        }
        let data = &data[MSZIP_SIGNATURE_LEN..];
        // Each CFDATA block is an independent raw-deflate stream, but back-
        // references may reach up to 32 KiB into the *previous* block's output.
        // The pure-Rust `flate2` backend (miniz_oxide) has no
        // `inflateSetDictionary`, so we carry the history by prepending it as a
        // synthetic *stored* deflate block and decoding `[dict][block]` in ONE
        // pass, then dropping the `dict` prefix. The single call matters: priming
        // in one call and decoding in another leaves the window wrong for every
        // block after the first.
        self.decompressor.reset(false);
        let dict_len = self.dictionary.len();
        let mut input: Vec<u8> = Vec::with_capacity(dict_len + 5 + data.len());
        if dict_len > 0 {
            debug_assert!(dict_len <= DEFLATE_MAX_DICT_LEN);
            let length = dict_len as u16;
            // A raw-deflate *stored* block: a header byte (BFINAL=0, BTYPE=00,
            // remaining bits ignored → 0x00), then LEN/NLEN, then the literal
            // bytes. The header byte is easy to leave out and the failure is
            // quiet: the decoder then takes the first LEN byte for the header,
            // mis-primes the window, and every block after the first decodes to
            // garbage that still looks like data.
            input.push(0x00);
            input.extend_from_slice(&length.to_le_bytes());
            input.extend_from_slice(&(!length).to_le_bytes());
            input.extend_from_slice(&self.dictionary);
        }
        input.extend_from_slice(data);
        let mut combined =
            Vec::<u8>::with_capacity(dict_len + crate::cap_prealloc(uncompressed_size));
        let flush = flate2::FlushDecompress::Finish;
        let result = self
            .decompressor
            .decompress_vec(&input, &mut combined, flush);
        // Drop the dictionary prefix we prepended.
        if combined.len() < dict_len {
            return Decoded::failed(bad(
                "MSZIP decompression failed: dictionary prefix truncated".into(),
            ));
        }
        let mut out = combined.split_off(dict_len);
        if let Err(error) = result {
            out.truncate(uncompressed_size);
            return Decoded {
                data: out,
                error: Some(bad(format!("MSZIP decompression failed: {error}"))),
            };
        }
        if out.len() != uncompressed_size {
            let short = out.len() < uncompressed_size;
            let message = format!(
                "MSZIP decompression failed: Incorrect uncompressed size \
                 (expected {}, was actually {})",
                uncompressed_size,
                out.len()
            );
            out.truncate(uncompressed_size);
            // A stream that ends early in a block the file cut is the cut; in
            // a whole block it is damage.
            let error = if short && cut {
                eof(&message)
            } else {
                bad(message)
            };
            return Decoded {
                data: out,
                error: Some(error),
            };
        }
        if out.len() >= DEFLATE_MAX_DICT_LEN {
            let start = out.len() - DEFLATE_MAX_DICT_LEN;
            self.dictionary = out[start..].to_vec();
        } else {
            let total = self.dictionary.len() + out.len();
            if total > DEFLATE_MAX_DICT_LEN {
                self.dictionary.drain(..(total - DEFLATE_MAX_DICT_LEN));
            }
            self.dictionary.extend_from_slice(&out);
        }
        Decoded {
            data: out,
            error: None,
        }
    }
}
