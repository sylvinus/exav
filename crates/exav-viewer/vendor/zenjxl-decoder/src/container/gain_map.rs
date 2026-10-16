// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Parser and serializer for the JPEG XL Gain Map bundle (`jhgm` box).
//!
//! The `jhgm` box contains an HDR gain map conforming to ISO 21496-1.
//! In JXL, the base image is HDR and the gain map maps HDR to SDR
//! (inverse direction from JPEG/AVIF).
//!
//! The gain map codestream is a bare JXL codestream (no container wrapper).
//! The ISO 21496-1 metadata blob is stored as raw bytes for the caller
//! to parse (e.g., via ultrahdr-core).

use crate::error::{Error, Result};

/// Current version of the gain map bundle format.
const JHGM_VERSION: u8 = 0x00;

/// Parsed JXL gain map bundle from a `jhgm` container box.
///
/// The bundle contains the ISO 21496-1 metadata, an optional JXL
/// ColorEncoding, an optional Brotli-compressed ICC profile for the
/// alternate rendition, and the bare JXL codestream of the gain map image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GainMapBundle {
    /// ISO 21496-1 binary metadata blob (unparsed — caller parses with ultrahdr-core).
    pub metadata: Vec<u8>,
    /// JXL ColorEncoding for the gain map (optional, raw bytes — JXL-native bit-packed).
    pub color_encoding: Option<Vec<u8>>,
    /// Brotli-compressed ICC profile for alternate rendition (optional, not decompressed).
    pub alt_icc_compressed: Option<Vec<u8>>,
    /// Bare JXL codestream of the gain map image (no container wrapper).
    pub gain_map_codestream: Vec<u8>,
}

impl GainMapBundle {
    /// Parse a gain map bundle from the raw payload of a `jhgm` box.
    ///
    /// Wire format:
    /// ```text
    /// jhgm_version:            u8       // must be 0x00
    /// gain_map_metadata_size:  u16 BE   // size of ISO 21496-1 metadata
    /// gain_map_metadata:       [u8; N]  // ISO 21496-1 binary metadata
    /// color_encoding_size:     u8       // 0 = absent; else byte count
    /// color_encoding:          [u8; M]  // JXL ColorEncoding (optional)
    /// alt_icc_size:            u32 BE   // size of Brotli-compressed ICC
    /// alt_icc:                 [u8; K]  // Brotli-compressed ICC (optional)
    /// gain_map:                [u8; *]  // remaining bytes = bare JXL codestream
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut pos = 0;

        // --- version ---
        if data.is_empty() {
            return Err(Error::InvalidGainMap("empty jhgm box".into()));
        }
        let version = data[pos];
        pos += 1;
        if version != JHGM_VERSION {
            return Err(Error::InvalidGainMap(format!(
                "unsupported jhgm version: {version:#04x}, expected {JHGM_VERSION:#04x}"
            )));
        }

        // --- gain_map_metadata_size (u16 BE) ---
        if pos + 2 > data.len() {
            return Err(Error::InvalidGainMap(
                "truncated: missing metadata size".into(),
            ));
        }
        let metadata_size = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + metadata_size > data.len() {
            return Err(Error::InvalidGainMap(format!(
                "truncated: metadata size {metadata_size} exceeds remaining {} bytes",
                data.len() - pos
            )));
        }
        let metadata = data[pos..pos + metadata_size].to_vec();
        pos += metadata_size;

        // --- color_encoding_size (u8) ---
        if pos >= data.len() {
            return Err(Error::InvalidGainMap(
                "truncated: missing color_encoding_size".into(),
            ));
        }
        let color_encoding_size = data[pos] as usize;
        pos += 1;

        let color_encoding = if color_encoding_size == 0 {
            None
        } else {
            if pos + color_encoding_size > data.len() {
                return Err(Error::InvalidGainMap(format!(
                    "truncated: color_encoding size {color_encoding_size} exceeds remaining {} bytes",
                    data.len() - pos
                )));
            }
            let ce = data[pos..pos + color_encoding_size].to_vec();
            pos += color_encoding_size;
            Some(ce)
        };

        // --- alt_icc_size (u32 BE) ---
        if pos + 4 > data.len() {
            return Err(Error::InvalidGainMap(
                "truncated: missing alt_icc_size".into(),
            ));
        }
        let alt_icc_size =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        let alt_icc_compressed = if alt_icc_size == 0 {
            None
        } else {
            if pos + alt_icc_size > data.len() {
                return Err(Error::InvalidGainMap(format!(
                    "truncated: alt_icc size {alt_icc_size} exceeds remaining {} bytes",
                    data.len() - pos
                )));
            }
            let icc = data[pos..pos + alt_icc_size].to_vec();
            pos += alt_icc_size;
            Some(icc)
        };

        // --- gain_map codestream (remainder) ---
        let gain_map_codestream = data[pos..].to_vec();

        Ok(GainMapBundle {
            metadata,
            color_encoding,
            alt_icc_compressed,
            gain_map_codestream,
        })
    }

    /// Serialize a gain map bundle to the wire format used inside a `jhgm` box.
    ///
    /// Returns the raw bytes that form the payload of a `jhgm` container box.
    pub fn serialize(&self) -> Vec<u8> {
        let metadata_size = self.metadata.len();
        let color_encoding_size = self.color_encoding.as_ref().map_or(0, |v| v.len());
        let alt_icc_size = self.alt_icc_compressed.as_ref().map_or(0, |v| v.len());

        // Pre-allocate: version(1) + meta_size(2) + meta(N) + ce_size(1) + ce(M)
        //             + icc_size(4) + icc(K) + codestream
        let total = 1
            + 2
            + metadata_size
            + 1
            + color_encoding_size
            + 4
            + alt_icc_size
            + self.gain_map_codestream.len();
        let mut buf = Vec::with_capacity(total);

        // version
        buf.push(JHGM_VERSION);

        // gain_map_metadata_size + metadata
        // Truncate to u16::MAX if somehow larger (shouldn't happen in practice)
        let meta_len = metadata_size.min(u16::MAX as usize) as u16;
        buf.extend_from_slice(&meta_len.to_be_bytes());
        buf.extend_from_slice(&self.metadata[..meta_len as usize]);

        // color_encoding_size + color_encoding
        // Truncate to u8::MAX if somehow larger
        let ce_len = color_encoding_size.min(u8::MAX as usize) as u8;
        buf.push(ce_len);
        if let Some(ref ce) = self.color_encoding {
            buf.extend_from_slice(&ce[..ce_len as usize]);
        }

        // alt_icc_size + alt_icc
        let icc_len = alt_icc_size.min(u32::MAX as usize) as u32;
        buf.extend_from_slice(&icc_len.to_be_bytes());
        if let Some(ref icc) = self.alt_icc_compressed {
            buf.extend_from_slice(&icc[..icc_len as usize]);
        }

        // gain_map codestream
        buf.extend_from_slice(&self.gain_map_codestream);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid jhgm bundle by hand.
    fn build_minimal_bundle(
        metadata: &[u8],
        color_encoding: Option<&[u8]>,
        alt_icc: Option<&[u8]>,
        gain_map: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        // version
        buf.push(0x00);
        // metadata size + metadata
        buf.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
        buf.extend_from_slice(metadata);
        // color_encoding_size + color_encoding
        match color_encoding {
            None => buf.push(0),
            Some(ce) => {
                buf.push(ce.len() as u8);
                buf.extend_from_slice(ce);
            }
        }
        // alt_icc_size + alt_icc
        match alt_icc {
            None => buf.extend_from_slice(&0u32.to_be_bytes()),
            Some(icc) => {
                buf.extend_from_slice(&(icc.len() as u32).to_be_bytes());
                buf.extend_from_slice(icc);
            }
        }
        // gain_map codestream
        buf.extend_from_slice(gain_map);
        buf
    }

    #[test]
    fn test_parse_minimal_bundle() {
        let metadata = b"\x01\x02\x03";
        let gain_map = b"\xff\x0a"; // fake codestream signature bytes
        let data = build_minimal_bundle(metadata, None, None, gain_map);

        let bundle = GainMapBundle::parse(&data).unwrap();
        assert_eq!(bundle.metadata, metadata);
        assert!(bundle.color_encoding.is_none());
        assert!(bundle.alt_icc_compressed.is_none());
        assert_eq!(bundle.gain_map_codestream, gain_map);
    }

    #[test]
    fn test_parse_full_bundle() {
        let metadata = b"ISO21496-1 test metadata blob";
        let color_encoding = b"\xAA\xBB\xCC\xDD";
        let alt_icc = b"brotli-compressed-icc-data-here";
        let gain_map = b"\xff\x0a\x00\x01\x02\x03\x04\x05";

        let data = build_minimal_bundle(metadata, Some(color_encoding), Some(alt_icc), gain_map);

        let bundle = GainMapBundle::parse(&data).unwrap();
        assert_eq!(bundle.metadata.as_slice(), metadata.as_slice());
        assert_eq!(
            bundle.color_encoding.as_deref(),
            Some(color_encoding.as_slice())
        );
        assert_eq!(
            bundle.alt_icc_compressed.as_deref(),
            Some(alt_icc.as_slice())
        );
        assert_eq!(bundle.gain_map_codestream.as_slice(), gain_map.as_slice());
    }

    #[test]
    fn test_roundtrip_minimal() {
        let original = GainMapBundle {
            metadata: vec![0x10, 0x20, 0x30],
            color_encoding: None,
            alt_icc_compressed: None,
            gain_map_codestream: vec![0xFF, 0x0A, 0x00],
        };
        let serialized = original.serialize();
        let parsed = GainMapBundle::parse(&serialized).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_roundtrip_full() {
        let original = GainMapBundle {
            metadata: vec![0x01; 100],
            color_encoding: Some(vec![0xAA, 0xBB, 0xCC]),
            alt_icc_compressed: Some(vec![0xDD; 256]),
            gain_map_codestream: vec![0xFF, 0x0A, 0x00, 0x01, 0x02],
        };
        let serialized = original.serialize();
        let parsed = GainMapBundle::parse(&serialized).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_roundtrip_empty_gain_map() {
        // Edge case: gain map codestream is empty (degenerate but parse should handle it)
        let original = GainMapBundle {
            metadata: vec![0x42],
            color_encoding: None,
            alt_icc_compressed: None,
            gain_map_codestream: vec![],
        };
        let serialized = original.serialize();
        let parsed = GainMapBundle::parse(&serialized).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_error_empty_data() {
        let result = GainMapBundle::parse(&[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn test_error_wrong_version() {
        let mut data = build_minimal_bundle(b"\x01", None, None, b"\xff");
        data[0] = 0x01; // wrong version
        let result = GainMapBundle::parse(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("version"), "unexpected error: {err}");
    }

    #[test]
    fn test_error_truncated_metadata_size() {
        // Just version byte, no metadata size
        let result = GainMapBundle::parse(&[0x00]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("truncated"), "unexpected error: {err}");
    }

    #[test]
    fn test_error_metadata_exceeds_data() {
        // Version + metadata_size=1000 but only 2 bytes of actual metadata
        let mut data = vec![0x00]; // version
        data.extend_from_slice(&1000u16.to_be_bytes()); // metadata size = 1000
        data.extend_from_slice(&[0x01, 0x02]); // only 2 bytes
        let result = GainMapBundle::parse(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("truncated"), "unexpected error: {err}");
    }

    #[test]
    fn test_error_truncated_color_encoding_size() {
        // Version + valid metadata but no color_encoding_size byte
        let mut data = vec![0x00]; // version
        data.extend_from_slice(&0u16.to_be_bytes()); // metadata size = 0
        // missing color_encoding_size
        let result = GainMapBundle::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_truncated_color_encoding() {
        // color_encoding_size says 10 bytes but only 3 available
        let mut data = vec![0x00]; // version
        data.extend_from_slice(&0u16.to_be_bytes()); // metadata size = 0
        data.push(10); // color_encoding_size = 10
        data.extend_from_slice(&[0x01, 0x02, 0x03]); // only 3 bytes
        let result = GainMapBundle::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_truncated_alt_icc_size() {
        // Valid up to color_encoding but missing alt_icc_size
        let mut data = vec![0x00]; // version
        data.extend_from_slice(&0u16.to_be_bytes()); // metadata size = 0
        data.push(0); // color_encoding_size = 0
        // missing alt_icc_size (needs 4 bytes)
        data.push(0x01); // only 1 byte
        let result = GainMapBundle::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_alt_icc_exceeds_data() {
        let mut data = vec![0x00]; // version
        data.extend_from_slice(&0u16.to_be_bytes()); // metadata size = 0
        data.push(0); // color_encoding_size = 0
        data.extend_from_slice(&500u32.to_be_bytes()); // alt_icc_size = 500
        data.extend_from_slice(&[0xAA; 10]); // only 10 bytes
        let result = GainMapBundle::parse(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("truncated"), "unexpected error: {err}");
    }

    #[test]
    fn test_large_metadata() {
        // Metadata near u16::MAX
        let metadata = vec![0x42; 60_000];
        let gain_map = vec![0xFF, 0x0A];
        let original = GainMapBundle {
            metadata,
            color_encoding: None,
            alt_icc_compressed: None,
            gain_map_codestream: gain_map,
        };
        let serialized = original.serialize();
        let parsed = GainMapBundle::parse(&serialized).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_large_alt_icc() {
        // Large ICC profile
        let alt_icc = vec![0xDD; 100_000];
        let original = GainMapBundle {
            metadata: vec![0x01],
            color_encoding: None,
            alt_icc_compressed: Some(alt_icc),
            gain_map_codestream: vec![0xFF, 0x0A],
        };
        let serialized = original.serialize();
        let parsed = GainMapBundle::parse(&serialized).unwrap();
        assert_eq!(original, parsed);
    }

    /// Test that building a jhgm box (header + payload) and extracting the payload
    /// round-trips correctly. This simulates what the container parser does.
    #[test]
    fn test_box_level_roundtrip() {
        let bundle = GainMapBundle {
            metadata: vec![0x01, 0x02],
            color_encoding: Some(vec![0xAA]),
            alt_icc_compressed: Some(vec![0xBB, 0xCC]),
            gain_map_codestream: vec![0xFF, 0x0A, 0x00],
        };

        // Serialize the bundle payload
        let payload = bundle.serialize();

        // Build a complete jhgm box: [u32 BE size][b"jhgm"][payload]
        let box_size = (8 + payload.len()) as u32;
        let mut jhgm_box = Vec::new();
        jhgm_box.extend_from_slice(&box_size.to_be_bytes());
        jhgm_box.extend_from_slice(b"jhgm");
        jhgm_box.extend_from_slice(&payload);

        // Verify the box header
        assert_eq!(&jhgm_box[4..8], b"jhgm");

        // Extract payload from box and re-parse
        let extracted_payload = &jhgm_box[8..];
        let parsed = GainMapBundle::parse(extracted_payload).unwrap();
        assert_eq!(bundle, parsed);
    }
}
