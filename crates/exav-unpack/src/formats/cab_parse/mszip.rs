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

    pub(crate) fn decompress_block(
        &mut self,
        data: &[u8],
        uncompressed_size: usize,
    ) -> io::Result<Vec<u8>> {
        if data.len() < MSZIP_SIGNATURE_LEN
            || ((data[0] as u16) | ((data[1] as u16) << 8)) != MSZIP_SIGNATURE
        {
            invalid_data!("MSZIP decompression failed: Invalid block signature");
        }
        let data = &data[MSZIP_SIGNATURE_LEN..];
        // Each CFDATA block is an independent raw-deflate stream, but back-
        // references may reach up to 32 KiB into the *previous* block's output.
        // The pure-Rust `flate2` backend (miniz_oxide) has no
        // `inflateSetDictionary`, so we carry the history by prepending it as a
        // synthetic *stored* deflate block and decoding `[dict][block]` in ONE
        // pass, then dropping the `dict` prefix. Doing it in a single
        // `decompress_vec` call (rather than two, dict then data) is what makes
        // the window correct for the 2nd+ block — the previous two-call priming
        // decoded only the first block.
        self.decompressor.reset(false);
        let dict_len = self.dictionary.len();
        let mut input: Vec<u8> = Vec::with_capacity(dict_len + 5 + data.len());
        if dict_len > 0 {
            debug_assert!(dict_len <= DEFLATE_MAX_DICT_LEN);
            let length = dict_len as u16;
            // A raw-deflate *stored* block: a header byte (BFINAL=0, BTYPE=00,
            // remaining bits ignored → 0x00), then LEN/NLEN, then the literal
            // bytes. The previous code omitted this header byte, so the decoder
            // consumed the first LEN byte as the block header and mis-primed the
            // window — which is why every 2nd+ MSZIP block decoded to garbage.
            input.push(0x00);
            input.extend_from_slice(&length.to_le_bytes());
            input.extend_from_slice(&(!length).to_le_bytes());
            input.extend_from_slice(&self.dictionary);
        }
        input.extend_from_slice(data);
        let mut combined =
            Vec::<u8>::with_capacity(dict_len + crate::cap_prealloc(uncompressed_size));
        let flush = flate2::FlushDecompress::Finish;
        match self
            .decompressor
            .decompress_vec(&input, &mut combined, flush)
        {
            Ok(_) => {}
            Err(error) => {
                invalid_data!("MSZIP decompression failed: {}", error);
            }
        }
        // Drop the dictionary prefix we prepended.
        if combined.len() < dict_len {
            invalid_data!("MSZIP decompression failed: dictionary prefix truncated");
        }
        let out = combined.split_off(dict_len);
        if out.len() != uncompressed_size {
            invalid_data!(
                "MSZIP decompression failed: Incorrect uncompressed size \
                 (expected {}, was actually {})",
                uncompressed_size,
                out.len()
            );
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
        Ok(out)
    }
}
