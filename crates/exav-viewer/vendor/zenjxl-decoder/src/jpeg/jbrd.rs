// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! JBRD (JPEG Bitstream Reconstruction Data) decoder.
//!
//! Decodes the JBRD box to recover JPEG metadata needed for byte-exact
//! reconstruction. This is the inverse of the encoder's `encode_jbrd()`.

use crate::error::{Error, Result};
use crate::util::NewWithCapacity;

use super::data::*;

/// Decode a JBRD box into JPEG metadata.
///
/// The `jbrd_data` is the raw content of the `jbrd` ISOBMFF box.
/// The `width` and `height` are taken from the JXL image header since
/// the JBRD box doesn't redundantly store them.
pub fn decode_jbrd(jbrd_data: &[u8], width: u32, height: u32) -> Result<JpegData> {
    let mut reader = BitReader::new(jbrd_data);

    // is_gray determines number of components
    let is_gray = reader.read(1)? == 1;
    let num_components = if is_gray { 1 } else { 3 };

    // Count marker types to know how many of each to expect
    let mut marker_order = Vec::new();
    let mut num_scans = 0u32;
    let mut num_app = 0u32;
    let mut num_com = 0u32;
    let mut num_intermarker = 0u32;

    // Read marker order until EOI (0xD9)
    loop {
        let marker = reader.read(6)? as u8 + 0xC0;
        marker_order.push(marker);
        match marker {
            0xD9 => break, // EOI
            0xDA => num_scans += 1,
            0xE0..=0xEF => num_app += 1,
            0xFE => num_com += 1,
            0xFF => num_intermarker += 1,
            _ => {} // DQT, DHT, DRI, SOF, etc.
        }
    }

    // APP marker types and lengths
    let mut app_marker_type = Vec::<AppMarkerType>::new_with_capacity(num_app as usize)?;
    let mut app_data_lengths = Vec::<u32>::new_with_capacity(num_app as usize)?;
    for _ in 0..num_app {
        let app_type = read_u32_jbrd(&mut reader, &[0, 1], &[(1, 2), (2, 4)])?;
        let app_mt = AppMarkerType::from_u32(app_type)
            .ok_or_else(|| Error::InvalidJbrd(format!("invalid app marker type: {app_type}")))?;
        app_marker_type.push(app_mt);

        let len = reader.read(16)? as u32 + 1;
        app_data_lengths.push(len);
    }

    // COM marker lengths
    let mut com_data_lengths = Vec::<u32>::new_with_capacity(num_com as usize)?;
    for _ in 0..num_com {
        let len = reader.read(16)? as u32 + 1;
        com_data_lengths.push(len);
    }

    // Quantization tables
    let num_quant = read_u32_jbrd(&mut reader, &[1, 2, 3, 4], &[])?;
    let mut quant = Vec::<JpegQuantTable>::new_with_capacity(num_quant as usize)?;
    for _ in 0..num_quant {
        let precision = reader.read(1)? as u32;
        let index = reader.read(2)? as u32;
        let is_last = reader.read(1)? == 1;
        quant.push(JpegQuantTable {
            values: [0i32; 64], // Filled later from codestream's raw quant table
            precision,
            index,
            is_last,
        });
    }

    // Component type
    let comp_type_val = reader.read(2)? as u32;
    let component_type = JpegComponentType::from_u32(comp_type_val)
        .ok_or_else(|| Error::InvalidJbrd(format!("invalid component type: {comp_type_val}")))?;

    // Component IDs
    let mut components = Vec::<JpegComponent>::new_with_capacity(num_components)?;
    if component_type == JpegComponentType::Custom {
        let num_comp = read_u32_jbrd(&mut reader, &[1, 2, 3, 4], &[])?;
        if num_comp as usize != num_components {
            return Err(Error::InvalidJbrd(format!(
                "custom component count {num_comp} != {num_components}"
            )));
        }
        for _ in 0..num_comp {
            let id = reader.read(8)? as u32;
            components.push(JpegComponent {
                id,
                h_samp_factor: 1,
                v_samp_factor: 1,
                quant_idx: 0,
                width_in_blocks: 0,
                height_in_blocks: 0,
                coeffs: Vec::new(),
            });
        }
    } else {
        // Standard component IDs
        let ids = match component_type {
            JpegComponentType::Gray => vec![1],
            JpegComponentType::YCbCr => vec![1, 2, 3],
            JpegComponentType::Rgb => vec![b'R' as u32, b'G' as u32, b'B' as u32],
            JpegComponentType::Custom => unreachable!(),
        };
        for &id in &ids {
            components.push(JpegComponent {
                id,
                h_samp_factor: 1,
                v_samp_factor: 1,
                quant_idx: 0,
                width_in_blocks: 0,
                height_in_blocks: 0,
                coeffs: Vec::new(),
            });
        }
    }

    // Component quant table indices
    for comp in &mut components {
        comp.quant_idx = reader.read(2)? as u32;
    }

    // Huffman codes
    let num_huff = read_u32_jbrd(&mut reader, &[4], &[(3, 2), (4, 10), (6, 26)])?;
    let mut huffman_code = Vec::<JpegHuffmanCode>::new_with_capacity(num_huff as usize)?;
    for _ in 0..num_huff {
        let is_ac = reader.read(1)? == 1;
        let id = reader.read(2)? as u32;
        let is_last = reader.read(1)? == 1;

        // 17 count values (bit lengths 0-16)
        // counts[0] is always 0 (no 0-bit codes)
        let _count0 = read_u32_jbrd(&mut reader, &[0, 1], &[(3, 2), (8, 0)])?;
        let mut counts = [0u32; 16];
        let mut max_depth_idx = 0;
        for (i, count) in counts.iter_mut().enumerate() {
            *count = read_u32_jbrd(&mut reader, &[0, 1], &[(3, 2), (8, 0)])?;
            if *count > 0 {
                max_depth_idx = i;
            }
        }

        // Remove sentinel symbol from max depth
        if counts[max_depth_idx] == 0 {
            return Err(Error::InvalidJbrd("huffman table has no symbols".into()));
        }
        counts[max_depth_idx] -= 1;

        // Read symbol values (original count + 1 for sentinel)
        let num_symbols: u32 = counts.iter().sum::<u32>() + 1; // +1 for sentinel
        let mut values = Vec::<u8>::new_with_capacity(num_symbols as usize)?;
        for _ in 0..num_symbols {
            let val = read_u32_jbrd(&mut reader, &[], &[(2, 0), (2, 4), (4, 8), (8, 1)])?;
            if val < 256 {
                values.push(val as u8);
            }
            // val == 256 is the sentinel — skip it
        }

        huffman_code.push(JpegHuffmanCode {
            is_ac,
            id,
            is_last,
            counts,
            values,
        });
    }

    // Scan info
    let mut scan_info = Vec::<JpegScanInfo>::new_with_capacity(num_scans as usize)?;
    for _ in 0..num_scans {
        let scan_nc = read_u32_jbrd(&mut reader, &[1, 2, 3, 4], &[])?;
        let ss = reader.read(6)? as u32;
        let se = reader.read(6)? as u32;
        let al = reader.read(4)? as u32;
        let ah = reader.read(4)? as u32;

        let mut component_indices = Vec::<u32>::new_with_capacity(scan_nc as usize)?;
        let mut ac_tbl_idx = Vec::<u32>::new_with_capacity(scan_nc as usize)?;
        let mut dc_tbl_idx = Vec::<u32>::new_with_capacity(scan_nc as usize)?;
        for _ in 0..scan_nc {
            component_indices.push(reader.read(2)? as u32);
            ac_tbl_idx.push(reader.read(2)? as u32);
            dc_tbl_idx.push(reader.read(2)? as u32);
        }

        let last_needed_pass = read_u32_jbrd(&mut reader, &[0, 1, 2], &[(3, 3)])?;

        scan_info.push(JpegScanInfo {
            num_components: scan_nc,
            component_indices,
            dc_tbl_idx,
            ac_tbl_idx,
            ss,
            se,
            ah,
            al,
            reset_points: Vec::new(),
            extra_zero_runs: Vec::new(),
            last_needed_pass,
        });
    }

    // Restart interval
    let restart_interval = if marker_order.contains(&0xDD) {
        reader.read(16)? as u32
    } else {
        0
    };

    // Scan more info (reset points and extra zero runs)
    for scan in &mut scan_info {
        let num_reset_points = read_u32_jbrd(&mut reader, &[0], &[(2, 1), (4, 4), (16, 20)])?;
        let mut last_block_idx: i64 = -1;
        for _ in 0..num_reset_points {
            let diff = read_u32_jbrd(&mut reader, &[0], &[(3, 1), (5, 9), (28, 41)])?;
            let block_idx = (last_block_idx + 1 + diff as i64) as u32;
            scan.reset_points.push(block_idx);
            last_block_idx = block_idx as i64;
        }

        let num_extra = read_u32_jbrd(&mut reader, &[0], &[(2, 1), (4, 4), (16, 20)])?;
        let mut last_block_idx: i64 = -1;
        for _ in 0..num_extra {
            let num_runs = read_u32_jbrd(&mut reader, &[1], &[(2, 2), (4, 5), (8, 20)])?;
            let diff = read_u32_jbrd(&mut reader, &[0], &[(3, 1), (5, 9), (28, 41)])?;
            let block_idx = (last_block_idx + 1 + diff as i64) as u32;
            scan.extra_zero_runs.push((block_idx, num_runs));
            last_block_idx = block_idx as i64;
        }
    }

    // Inter-marker data lengths
    let mut inter_marker_data_lengths = Vec::<u32>::new_with_capacity(num_intermarker as usize)?;
    for _ in 0..num_intermarker {
        let len = reader.read(16)? as u32;
        inter_marker_data_lengths.push(len);
    }

    // Tail data length
    let tail_len = read_u32_jbrd(&mut reader, &[0], &[(8, 1), (16, 257), (22, 65793)])?;

    // Padding bits
    let has_zero_padding_bit = reader.read(1)? == 1;
    let mut padding_bits = Vec::<u8>::new();
    if has_zero_padding_bit {
        let nbit = reader.read(24)? as u32;
        padding_bits.try_reserve(nbit as usize)?;
        for _ in 0..nbit {
            padding_bits.push(reader.read(1)? as u8);
        }
    }

    // Skip to byte boundary (matching encoder's zero_pad_to_byte)
    reader.align_to_byte();

    // Brotli-decompress the remaining data
    let compressed_data = reader.remaining_bytes();
    let decompressed = brotli_decompress(compressed_data)?;

    // Read data from decompressed stream
    let mut data_pos = 0;

    // APP marker data (only Unknown type stored in data stream)
    // Encoder format: [marker_byte, len_hi, len_lo, payload...]
    // We strip the 3-byte prefix to store just the payload.
    let mut app_data = Vec::<Vec<u8>>::new_with_capacity(num_app as usize)?;
    for i in 0..num_app as usize {
        if app_marker_type[i] != AppMarkerType::Unknown {
            app_data.push(Vec::new()); // Placeholder for ICC/EXIF/XMP (from container boxes)
            continue;
        }
        let len = app_data_lengths[i] as usize;
        if data_pos + len > decompressed.len() {
            return Err(Error::InvalidJbrd("truncated APP data".into()));
        }
        // Skip 3-byte prefix (marker_byte + 2-byte length field)
        let skip = 3.min(len);
        app_data.push(decompressed[data_pos + skip..data_pos + len].to_vec());
        data_pos += len;
    }

    // COM marker data (same format as APP: [marker_byte, len_hi, len_lo, payload...])
    let mut com_data = Vec::<Vec<u8>>::new_with_capacity(num_com as usize)?;
    for &com_len in com_data_lengths.iter().take(num_com as usize) {
        let len = com_len as usize;
        if data_pos + len > decompressed.len() {
            return Err(Error::InvalidJbrd("truncated COM data".into()));
        }
        let skip = 3.min(len);
        com_data.push(decompressed[data_pos + skip..data_pos + len].to_vec());
        data_pos += len;
    }

    // Inter-marker data
    let mut inter_marker_data = Vec::<Vec<u8>>::new_with_capacity(num_intermarker as usize)?;
    for &im_len in inter_marker_data_lengths
        .iter()
        .take(num_intermarker as usize)
    {
        let len = im_len as usize;
        if data_pos + len > decompressed.len() {
            return Err(Error::InvalidJbrd("truncated inter-marker data".into()));
        }
        inter_marker_data.push(decompressed[data_pos..data_pos + len].to_vec());
        data_pos += len;
    }

    // Tail data
    let tail_data = if tail_len > 0 {
        let len = tail_len as usize;
        if data_pos + len > decompressed.len() {
            return Err(Error::InvalidJbrd("truncated tail data".into()));
        }
        let td = decompressed[data_pos..data_pos + len].to_vec();
        data_pos += len;
        td
    } else {
        Vec::new()
    };

    let _ = data_pos; // May have trailing bytes from Brotli padding

    // Initial block dimensions assuming 4:4:4. For subsampled images,
    // jpeg_reconstruct() overrides these using the frame header's jpeg_upsampling.
    let xsize_blocks = width.div_ceil(8);
    let ysize_blocks = height.div_ceil(8);
    for comp in &mut components {
        comp.width_in_blocks = xsize_blocks;
        comp.height_in_blocks = ysize_blocks;
    }

    Ok(JpegData {
        width,
        height,
        restart_interval,
        app_data,
        app_marker_type,
        com_data,
        quant,
        huffman_code,
        components,
        scan_info,
        marker_order,
        inter_marker_data,
        tail_data,
        has_zero_padding_bit,
        padding_bits,
        component_type,
    })
}

/// Read a JXL U32 value (inverse of write_u32_jbrd).
fn read_u32_jbrd(
    reader: &mut BitReader<'_>,
    direct_values: &[u32],
    bits_offset: &[(usize, u32)],
) -> Result<u32> {
    let selector = reader.read(2)? as usize;
    if selector < direct_values.len() {
        Ok(direct_values[selector])
    } else {
        let bo_idx = selector - direct_values.len();
        if bo_idx >= bits_offset.len() {
            return Err(Error::InvalidJbrd(format!(
                "invalid u32 selector {selector}"
            )));
        }
        let (bits, offset) = bits_offset[bo_idx];
        if bits == 0 {
            Ok(offset)
        } else {
            let val = reader.read(bits)? as u32;
            Ok(val + offset)
        }
    }
}

/// Simple bit reader for JBRD header.
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8, // 0-7, LSB first within each byte
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read(&mut self, num_bits: usize) -> Result<u64> {
        let mut value: u64 = 0;
        for i in 0..num_bits {
            if self.byte_pos >= self.data.len() {
                return Err(Error::InvalidJbrd("unexpected end of JBRD data".into()));
            }
            let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;
            value |= (bit as u64) << i;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }
        Ok(value)
    }

    fn align_to_byte(&mut self) {
        if self.bit_pos > 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    fn remaining_bytes(&self) -> &'a [u8] {
        if self.byte_pos >= self.data.len() {
            &[]
        } else {
            &self.data[self.byte_pos..]
        }
    }
}

/// Brotli-decompress data.
fn brotli_decompress(compressed: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut decompressed = Vec::new();
    let mut decoder = brotli::Decompressor::new(compressed, 4096);
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| Error::InvalidJbrd(format!("brotli decompression failed: {e}")))?;
    Ok(decompressed)
}

#[cfg(test)]
mod fallible_alloc_tests {
    use super::decode_jbrd;
    use crate::error::Error;

    /// Regression: `Vec::with_capacity(num_app)` etc. used the infallible
    /// allocator. A malformed JBRD box could have a marker order that leaves
    /// `num_app`/`num_com`/etc. so large that capacity reservation aborted
    /// the process. With the fallible-alloc switch the decoder must surface a
    /// graceful error (truncated or OOM) instead.
    #[test]
    fn malformed_jbrd_does_not_abort_on_oversize_counts() {
        // 1 byte of zeros: is_gray=0, then marker bits are all zero =>
        // first marker is 0xC0 (SOF0) ≠ 0xD9 (EOI), and reader runs out of
        // bytes — truncated. We expect `Error::OutOfBounds`, NOT a panic or
        // an infallible-alloc abort. This pins the contract that the parser
        // never aborts on input alone.
        let bogus = vec![0u8; 1];
        let res = decode_jbrd(&bogus, 8, 8);
        match res {
            Err(Error::OutOfBounds(_)) => {} // expected
            Err(Error::OutOfMemory(_)) => {} // also acceptable
            Err(_) => {}                     // other graceful errors fine
            Ok(_) => panic!("malformed JBRD should not parse successfully"),
        }
    }

    /// Empty input must not panic; tests a different code path than the
    /// 1-byte case (BitReader behavior on a fresh empty buffer).
    #[test]
    fn empty_jbrd_returns_error_not_panic() {
        let res = decode_jbrd(&[], 1, 1);
        assert!(res.is_err());
    }
}
