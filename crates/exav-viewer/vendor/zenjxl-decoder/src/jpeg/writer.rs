// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! JPEG bitstream writer for reconstruction from JXL.
//!
//! Writes a valid JPEG file from reconstructed coefficient data and
//! JBRD metadata (Huffman tables, quant tables, scan headers, markers).

use crate::error::{Error, Result};

use super::data::*;

/// JPEG zigzag scan order: maps zigzag position → natural (row-major) position.
#[rustfmt::skip]
const ZIGZAG: [usize; 64] = [
     0,  1,  8, 16,  9,  2,  3, 10,
    17, 24, 32, 25, 18, 11,  4,  5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13,  6,  7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63,
];

/// Write a complete JPEG file from reconstructed data.
///
/// Returns the byte-exact original JPEG.
pub fn write_jpeg(jpeg: &JpegData) -> Result<Vec<u8>> {
    let mut out = Vec::new();

    {
        let mut writer = JpegWriter::new(&mut out);

        // SOI
        writer.write_marker(0xD8)?;

        // Process markers in original order
        let mut app_idx = 0usize;
        let mut com_idx = 0usize;
        let mut scan_idx = 0usize;
        let mut dqt_idx = 0usize;
        let mut dht_idx = 0usize;
        let mut intermarker_idx = 0usize;

        // Active Huffman encode tables, updated as each DHT marker is emitted.
        // A progressive JPEG redefines the same table slots (e.g. AC table 0)
        // between scans, so the writer must use the table in force at each SOS
        // rather than a single set built from every huffman_code entry.
        let mut active_dc: [Option<HuffmanEncodeTable>; 4] = [None, None, None, None];
        let mut active_ac: [Option<HuffmanEncodeTable>; 4] = [None, None, None, None];

        for &marker in &jpeg.marker_order {
            match marker {
                0xD9 => {
                    // EOI
                    writer.write_marker(0xD9)?;
                }
                0xDA => {
                    // SOS - write scan header + entropy-coded data
                    if scan_idx >= jpeg.scan_info.len() {
                        return Err(Error::InvalidJbrd("too many SOS markers".into()));
                    }
                    writer.write_sos(jpeg, scan_idx, &active_dc, &active_ac)?;
                    scan_idx += 1;
                }
                0xE0..=0xEF => {
                    // APP markers
                    if app_idx >= jpeg.app_data.len() {
                        return Err(Error::InvalidJbrd("too many APP markers".into()));
                    }
                    writer.write_app_marker(marker, &jpeg.app_data[app_idx])?;
                    app_idx += 1;
                }
                0xFE => {
                    // COM
                    if com_idx >= jpeg.com_data.len() {
                        return Err(Error::InvalidJbrd("too many COM markers".into()));
                    }
                    writer.write_com_marker(&jpeg.com_data[com_idx])?;
                    com_idx += 1;
                }
                0xDB => {
                    // DQT
                    writer.write_dqt(jpeg, &mut dqt_idx)?;
                }
                0xC4 => {
                    // DHT — emits the table bytes AND updates the active tables.
                    writer.write_dht(jpeg, &mut dht_idx, &mut active_dc, &mut active_ac)?;
                }
                0xC0..=0xC2 => {
                    // SOF0 (baseline) / SOF1 (extended sequential) / SOF2
                    // (progressive). Emit the exact SOF marker the original
                    // used — dropping it (the old `_ =>` fall-through) lost a
                    // whole SOF segment and corrupted the marker stream.
                    writer.write_sof(jpeg, marker)?;
                }
                0xDD => {
                    // DRI
                    writer.write_dri(jpeg.restart_interval)?;
                }
                0xFF => {
                    // Inter-marker data
                    if intermarker_idx >= jpeg.inter_marker_data.len() {
                        return Err(Error::InvalidJbrd("too many inter-marker data".into()));
                    }
                    writer.write_intermarker_data(&jpeg.inter_marker_data[intermarker_idx]);
                    intermarker_idx += 1;
                }
                _ => {
                    // Other markers (SOF1, etc.) — shouldn't appear for baseline
                }
            }
        }
    }

    // Tail data (bytes after EOI)
    out.extend_from_slice(&jpeg.tail_data);

    Ok(out)
}

/// JPEG bitstream writer.
struct JpegWriter<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> JpegWriter<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    fn write_intermarker_data(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
    }

    fn write_marker(&mut self, marker: u8) -> Result<()> {
        self.out.push(0xFF);
        self.out.push(marker);
        Ok(())
    }

    fn write_app_marker(&mut self, marker: u8, data: &[u8]) -> Result<()> {
        self.out.push(0xFF);
        self.out.push(marker);
        // APP data includes marker_byte + length + payload in encoder format
        // But in the JBRD decoder, data is the raw payload as stored
        // The length field covers the payload + 2 bytes for the length itself
        let len = (data.len() + 2) as u16;
        self.out.extend_from_slice(&len.to_be_bytes());
        self.out.extend_from_slice(data);
        Ok(())
    }

    fn write_com_marker(&mut self, data: &[u8]) -> Result<()> {
        self.out.push(0xFF);
        self.out.push(0xFE);
        let len = (data.len() + 2) as u16;
        self.out.extend_from_slice(&len.to_be_bytes());
        self.out.extend_from_slice(data);
        Ok(())
    }

    fn write_dri(&mut self, restart_interval: u32) -> Result<()> {
        self.out.push(0xFF);
        self.out.push(0xDD);
        self.out.extend_from_slice(&4u16.to_be_bytes()); // length = 4
        self.out
            .extend_from_slice(&(restart_interval as u16).to_be_bytes());
        Ok(())
    }

    fn write_dqt(&mut self, jpeg: &JpegData, idx: &mut usize) -> Result<()> {
        self.out.push(0xFF);
        self.out.push(0xDB);

        // Collect tables until is_last
        let start = *idx;
        let mut total_payload = 0usize;
        loop {
            if *idx >= jpeg.quant.len() {
                return Err(Error::InvalidJbrd("too many DQT tables".into()));
            }
            let qt = &jpeg.quant[*idx];
            let precision_bytes = if qt.precision == 0 { 1 } else { 2 };
            total_payload += 1 + 64 * precision_bytes; // 1 byte for Pq|Tq
            let is_last = qt.is_last;
            *idx += 1;
            if is_last {
                break;
            }
        }

        let length = (total_payload + 2) as u16;
        self.out.extend_from_slice(&length.to_be_bytes());

        for i in start..*idx {
            let qt = &jpeg.quant[i];
            let pq_tq = ((qt.precision as u8) << 4) | (qt.index as u8);
            self.out.push(pq_tq);
            if qt.precision == 0 {
                // 8-bit values in zigzag order
                for &zi in &ZIGZAG {
                    self.out.push(qt.values[zi] as u8);
                }
            } else {
                // 16-bit values in zigzag order
                for &zi in &ZIGZAG {
                    self.out
                        .extend_from_slice(&(qt.values[zi] as u16).to_be_bytes());
                }
            }
        }

        Ok(())
    }

    fn write_dht(
        &mut self,
        jpeg: &JpegData,
        idx: &mut usize,
        active_dc: &mut [Option<HuffmanEncodeTable>; 4],
        active_ac: &mut [Option<HuffmanEncodeTable>; 4],
    ) -> Result<()> {
        self.out.push(0xFF);
        self.out.push(0xC4);

        // Collect tables until is_last
        let start = *idx;
        let mut total_payload = 0usize;
        loop {
            if *idx >= jpeg.huffman_code.len() {
                return Err(Error::InvalidJbrd("too many DHT tables".into()));
            }
            let hc = &jpeg.huffman_code[*idx];
            let num_values: u32 = hc.counts.iter().sum();
            total_payload += 1 + 16 + num_values as usize;
            let is_last = hc.is_last;
            *idx += 1;
            if is_last {
                break;
            }
        }

        let length = (total_payload + 2) as u16;
        self.out.extend_from_slice(&length.to_be_bytes());

        for i in start..*idx {
            let hc = &jpeg.huffman_code[i];
            let tc_th = if hc.is_ac { 0x10 } else { 0x00 } | (hc.id as u8);
            self.out.push(tc_th);
            for &count in &hc.counts {
                self.out.push(count as u8);
            }
            for &val in &hc.values {
                self.out.push(val);
            }
            // Update the active table set for subsequent scans.
            let table = HuffmanEncodeTable::from_counts_values(&hc.counts, &hc.values);
            if hc.is_ac {
                active_ac[hc.id as usize] = Some(table);
            } else {
                active_dc[hc.id as usize] = Some(table);
            }
        }

        Ok(())
    }

    fn write_sof(&mut self, jpeg: &JpegData, marker: u8) -> Result<()> {
        self.out.push(0xFF);
        self.out.push(marker);

        let nc = jpeg.components.len();
        let length = (8 + 3 * nc) as u16;
        self.out.extend_from_slice(&length.to_be_bytes());

        self.out.push(8); // sample precision = 8 bits
        self.out
            .extend_from_slice(&(jpeg.height as u16).to_be_bytes());
        self.out
            .extend_from_slice(&(jpeg.width as u16).to_be_bytes());
        self.out.push(nc as u8);

        for comp in &jpeg.components {
            self.out.push(comp.id as u8);
            let hv = ((comp.h_samp_factor as u8) << 4) | (comp.v_samp_factor as u8);
            self.out.push(hv);
            self.out.push(comp.quant_idx as u8);
        }

        Ok(())
    }

    fn write_sos(
        &mut self,
        jpeg: &JpegData,
        scan_idx: usize,
        active_dc: &[Option<HuffmanEncodeTable>; 4],
        active_ac: &[Option<HuffmanEncodeTable>; 4],
    ) -> Result<()> {
        let scan = &jpeg.scan_info[scan_idx];

        // SOS header
        self.out.push(0xFF);
        self.out.push(0xDA);

        let length = (6 + 2 * scan.num_components) as u16;
        self.out.extend_from_slice(&length.to_be_bytes());
        self.out.push(scan.num_components as u8);

        for i in 0..scan.num_components as usize {
            let comp_idx = scan.component_indices[i] as usize;
            self.out.push(jpeg.components[comp_idx].id as u8);
            let td_ta = ((scan.dc_tbl_idx[i] as u8) << 4) | (scan.ac_tbl_idx[i] as u8);
            self.out.push(td_ta);
        }

        self.out.push(scan.ss as u8);
        self.out.push(scan.se as u8);
        let ah_al = ((scan.ah as u8) << 4) | (scan.al as u8);
        self.out.push(ah_al);

        // Huffman encode coefficients (using the tables in force at this SOS).
        self.write_scan_data(jpeg, scan_idx, active_dc, active_ac)?;

        Ok(())
    }

    fn write_scan_data(
        &mut self,
        jpeg: &JpegData,
        scan_idx: usize,
        dc_tables: &[Option<HuffmanEncodeTable>; 4],
        ac_tables: &[Option<HuffmanEncodeTable>; 4],
    ) -> Result<()> {
        let scan = &jpeg.scan_info[scan_idx];

        // Progressive / successive-approximation scans (spectral selection +
        // EOB runs) use a different entropy structure than baseline sequential.
        if !(scan.ss == 0 && scan.se == 63 && scan.ah == 0 && scan.al == 0) {
            return self.write_scan_data_progressive(jpeg, scan_idx, dc_tables, ac_tables);
        }

        let mut bw = BitWriter::new();
        let mut padding_bit_idx = 0usize;
        let mut extra_zero_idx = 0usize;
        // Restart (DRI): emit RSTn every `restart_interval` MCUs. Baseline
        // restart is interval-driven — the progressive `reset_points` list is
        // empty for baseline scans, so relying on it dropped every RST marker.
        let restart_interval = jpeg.restart_interval;
        let mut restart_counter: u32 = 0;
        let mut rst_marker_idx: u32 = 0;

        // Track DC predictions (one per component)
        let mut dc_pred = vec![0i32; jpeg.components.len()];

        // For baseline sequential JPEG (ss=0, se=63, ah=0, al=0):
        // interleaved components, MCU-based ordering
        let is_interleaved = scan.num_components > 1;

        // Calculate MCU dimensions
        let (mcu_rows, mcu_cols) = if is_interleaved {
            let max_h: u32 = jpeg
                .components
                .iter()
                .map(|c| c.h_samp_factor)
                .max()
                .unwrap_or(1);
            let max_v: u32 = jpeg
                .components
                .iter()
                .map(|c| c.v_samp_factor)
                .max()
                .unwrap_or(1);
            let mcu_cols = jpeg.width.div_ceil(max_h * 8);
            let mcu_rows = jpeg.height.div_ceil(max_v * 8);
            (mcu_rows, mcu_cols)
        } else {
            let comp_idx = scan.component_indices[0] as usize;
            let comp = &jpeg.components[comp_idx];
            (comp.height_in_blocks, comp.width_in_blocks)
        };

        let mut block_count: u32 = 0;

        for mcu_row in 0..mcu_rows {
            for mcu_col in 0..mcu_cols {
                // Restart marker every `restart_interval` MCUs (DRI). The
                // original encoder pads the partial final byte of each entropy
                // segment (captured in padding_bits) and resets DC prediction
                // at the boundary.
                if restart_interval > 0 && restart_counter == restart_interval {
                    bw.pad_to_byte(&jpeg.padding_bits, &mut padding_bit_idx);
                    self.out.extend_from_slice(&bw.finish());
                    bw = BitWriter::new();

                    let rst_marker = 0xD0 + ((rst_marker_idx % 8) as u8);
                    self.out.push(0xFF);
                    self.out.push(rst_marker);

                    dc_pred.fill(0);
                    rst_marker_idx += 1;
                    restart_counter = 0;
                }

                for sci in 0..scan.num_components as usize {
                    let comp_idx = scan.component_indices[sci] as usize;
                    let comp = &jpeg.components[comp_idx];
                    let dc_table = dc_tables[scan.dc_tbl_idx[sci] as usize]
                        .as_ref()
                        .ok_or_else(|| Error::InvalidJbrd("missing DC table".into()))?;
                    let ac_table = ac_tables[scan.ac_tbl_idx[sci] as usize]
                        .as_ref()
                        .ok_or_else(|| Error::InvalidJbrd("missing AC table".into()))?;

                    // How many blocks per MCU for this component
                    let (h_blocks, v_blocks) = if is_interleaved {
                        (comp.h_samp_factor, comp.v_samp_factor)
                    } else {
                        (1, 1)
                    };

                    for v in 0..v_blocks {
                        for h in 0..h_blocks {
                            let (by, bx) = if is_interleaved {
                                (
                                    mcu_row * comp.v_samp_factor + v,
                                    mcu_col * comp.h_samp_factor + h,
                                )
                            } else {
                                (mcu_row, mcu_col)
                            };

                            if by >= comp.height_in_blocks || bx >= comp.width_in_blocks {
                                // Padding block — encode as zero
                                encode_dc(&mut bw, 0, &mut dc_pred[comp_idx], dc_table);
                                encode_ac_eob(&mut bw, ac_table);
                            } else {
                                let block_offset = (by * comp.width_in_blocks + bx) as usize * 64;
                                let coeffs = &comp.coeffs[block_offset..block_offset + 64];

                                // Check for extra zero runs before this block
                                while extra_zero_idx < scan.extra_zero_runs.len()
                                    && scan.extra_zero_runs[extra_zero_idx].0 == block_count
                                {
                                    let num_runs = scan.extra_zero_runs[extra_zero_idx].1;
                                    for _ in 0..num_runs {
                                        // Emit ZRL (15 zero run, zero amplitude)
                                        bw.write_huffman(ac_table, 0xF0);
                                    }
                                    extra_zero_idx += 1;
                                }

                                encode_dc(
                                    &mut bw,
                                    coeffs[0] as i32,
                                    &mut dc_pred[comp_idx],
                                    dc_table,
                                );
                                encode_ac(&mut bw, coeffs, ac_table);
                            }

                            block_count += 1;
                        }
                    }
                }

                restart_counter += 1;
            }
        }

        // Flush remaining bits
        bw.pad_to_byte(&jpeg.padding_bits, &mut padding_bit_idx);
        self.out.extend_from_slice(&bw.finish());

        Ok(())
    }

    /// Write a progressive (or successive-approximation refinement) scan.
    /// Mirrors brunsli's `DoEncodeScan` (jpeg_data_writer.cc): spectral
    /// selection [Ss,Se] + bit-plane Al, EOB-run buffering, per-block
    /// `reset_points` (entropy-state flush, NOT a marker) and `extra_zero_runs`.
    fn write_scan_data_progressive(
        &mut self,
        jpeg: &JpegData,
        scan_idx: usize,
        dc_tables: &[Option<HuffmanEncodeTable>; 4],
        ac_tables: &[Option<HuffmanEncodeTable>; 4],
    ) -> Result<()> {
        let scan = &jpeg.scan_info[scan_idx];
        let ss = scan.ss as usize;
        let se = scan.se as usize;
        let al = scan.al;
        let is_refinement = scan.ah > 0;

        let num_comp = scan.num_components as usize;
        let is_interleaved = num_comp > 1;
        let max_h = jpeg
            .components
            .iter()
            .map(|c| c.h_samp_factor)
            .max()
            .unwrap_or(1);
        let max_v = jpeg
            .components
            .iter()
            .map(|c| c.v_samp_factor)
            .max()
            .unwrap_or(1);
        let base = &jpeg.components[scan.component_indices[0] as usize];
        // Interleaved scans walk the MCU grid. Non-interleaved scans walk the
        // component's NATURAL block grid `DivCeil(dim*samp, 8*max_samp)` — NOT
        // its MCU-padded `width_in_blocks`, which is wider for luma when the
        // image dimensions aren't a multiple of `8*max_samp`. Iterating the
        // extra MCU-padding column/row would misalign `block_scan_index`
        // (reset_points / extra_zero_runs) and the EOB-run structure. (Block
        // indexing still uses the MCU-padded `width_in_blocks` stride below.)
        let (mcus_per_row, mcu_rows) = if is_interleaved {
            (
                jpeg.width.div_ceil(8 * max_h),
                jpeg.height.div_ceil(8 * max_v),
            )
        } else {
            (
                (jpeg.width * base.h_samp_factor).div_ceil(8 * max_h),
                (jpeg.height * base.v_samp_factor).div_ceil(8 * max_v),
            )
        };
        let restart_interval = jpeg.restart_interval;
        let flush_ac_idx = scan.ac_tbl_idx[0] as usize;

        let mut bw = BitWriter::new();
        let mut cs = DctCodingState::new();
        let mut padding_bit_idx = 0usize;
        let mut last_dc = vec![0i32; jpeg.components.len()];
        let mut restarts_to_go = restart_interval;
        let mut next_restart_marker = 0u32;
        let mut block_scan_index: u32 = 0;
        let mut extra_zero_pos = 0usize;
        let mut reset_point_pos = 0usize;
        let zero_block = [0i16; 64];

        for mcu_y in 0..mcu_rows {
            for mcu_x in 0..mcus_per_row {
                // Restart marker every `restart_interval` MCUs: flush the EOB
                // run, pad to a byte, emit RSTn, reset DC prediction.
                if restart_interval > 0 && restarts_to_go == 0 {
                    if ss > 0
                        && let Some(ac) = ac_tables[flush_ac_idx].as_ref()
                    {
                        cs.flush(&mut bw, ac);
                    }
                    bw.pad_to_byte(&jpeg.padding_bits, &mut padding_bit_idx);
                    self.out.extend_from_slice(&bw.finish());
                    bw = BitWriter::new();
                    self.out.push(0xFF);
                    self.out.push(0xD0 + next_restart_marker as u8);
                    next_restart_marker = (next_restart_marker + 1) & 0x7;
                    restarts_to_go = restart_interval;
                    last_dc.fill(0);
                }
                for sci in 0..num_comp {
                    let comp_idx = scan.component_indices[sci] as usize;
                    let comp = &jpeg.components[comp_idx];
                    let dc_idx = scan.dc_tbl_idx[sci] as usize;
                    let ac_idx = scan.ac_tbl_idx[sci] as usize;
                    let (n_blocks_y, n_blocks_x) = if is_interleaved {
                        (comp.v_samp_factor, comp.h_samp_factor)
                    } else {
                        (1, 1)
                    };
                    for iy in 0..n_blocks_y {
                        for ix in 0..n_blocks_x {
                            let block_y = (mcu_y * n_blocks_y + iy) as usize;
                            let block_x = (mcu_x * n_blocks_x + ix) as usize;

                            // reset_point: flush the pending EOB run (no marker).
                            if reset_point_pos < scan.reset_points.len()
                                && block_scan_index == scan.reset_points[reset_point_pos]
                            {
                                if let Some(ac) = ac_tables[ac_idx].as_ref() {
                                    cs.flush(&mut bw, ac);
                                }
                                reset_point_pos += 1;
                            }
                            // extra zero runs (extra ZRLs) before this block.
                            let mut num_zero_runs = 0u32;
                            if extra_zero_pos < scan.extra_zero_runs.len()
                                && scan.extra_zero_runs[extra_zero_pos].0 == block_scan_index
                            {
                                num_zero_runs = scan.extra_zero_runs[extra_zero_pos].1;
                                extra_zero_pos += 1;
                            }

                            // Edge MCUs reference blocks past the component grid
                            // (MCU padding); those are all-zero.
                            let coeffs: &[i16] = if block_y < comp.height_in_blocks as usize
                                && block_x < comp.width_in_blocks as usize
                            {
                                let bi = block_y * comp.width_in_blocks as usize + block_x;
                                &comp.coeffs[bi * 64..bi * 64 + 64]
                            } else {
                                &zero_block
                            };

                            // Each encoder reads only the table relevant to its
                            // band (DC-only scans never touch the AC table, and
                            // its DHT may not even be active yet). Supply a
                            // non-None reference for the unused slot.
                            let dc = dc_tables[dc_idx].as_ref();
                            let ac = ac_tables[ac_idx].as_ref();
                            let any = dc.or(ac).ok_or_else(|| {
                                Error::InvalidJbrd("no active Huffman table for scan".into())
                            })?;
                            let dc = dc.unwrap_or(any);
                            let ac = ac.unwrap_or(any);
                            if is_refinement {
                                encode_refinement(&mut bw, coeffs, ac, ss, se, al, &mut cs);
                            } else {
                                encode_block_progressive(
                                    &mut bw,
                                    coeffs,
                                    dc,
                                    ac,
                                    ss,
                                    se,
                                    al,
                                    num_zero_runs,
                                    &mut cs,
                                    &mut last_dc[comp_idx],
                                );
                            }
                            block_scan_index += 1;
                        }
                    }
                }
                if restart_interval > 0 {
                    restarts_to_go -= 1;
                }
            }
        }
        // Final flush of any pending EOB run + byte padding.
        if ss > 0
            && let Some(ac) = ac_tables[flush_ac_idx].as_ref()
        {
            cs.flush(&mut bw, ac);
        }
        bw.pad_to_byte(&jpeg.padding_bits, &mut padding_bit_idx);
        self.out.extend_from_slice(&bw.finish());
        Ok(())
    }
}

/// Encode a DC coefficient using DPCM + Huffman.
fn encode_dc(bw: &mut BitWriter, dc: i32, dc_pred: &mut i32, table: &HuffmanEncodeTable) {
    let diff = dc - *dc_pred;
    *dc_pred = dc;

    let (category, extra_bits, extra_len) = categorize(diff);
    bw.write_huffman(table, category as u8);
    if extra_len > 0 {
        bw.write_bits(extra_bits, extra_len);
    }
}

/// Encode AC coefficients in zigzag order using run-length + Huffman.
/// `block` is a 64-element block in natural (row-major) order.
fn encode_ac(bw: &mut BitWriter, block: &[i16], table: &HuffmanEncodeTable) {
    let mut zero_run = 0u32;
    // Find last nonzero in zigzag order (zigzag positions 1-63)
    let mut last_nonzero_zi = 0usize; // zigzag index (1-based)
    for zi in (1..64).rev() {
        if block[ZIGZAG[zi]] != 0 {
            last_nonzero_zi = zi;
            break;
        }
    }

    if last_nonzero_zi == 0 {
        // All AC zeros — emit EOB
        bw.write_huffman(table, 0x00);
        return;
    }

    for zi in 1..=last_nonzero_zi {
        let coeff = block[ZIGZAG[zi]];
        if coeff == 0 {
            zero_run += 1;
            continue;
        }
        // Emit ZRL for runs > 15
        while zero_run > 15 {
            bw.write_huffman(table, 0xF0); // ZRL
            zero_run -= 16;
        }
        let (category, extra_bits, extra_len) = categorize(coeff as i32);
        let symbol = ((zero_run as u8) << 4) | (category as u8);
        bw.write_huffman(table, symbol);
        if extra_len > 0 {
            bw.write_bits(extra_bits, extra_len);
        }
        zero_run = 0;
    }

    // EOB if not at the last zigzag position (63)
    if last_nonzero_zi < 63 {
        bw.write_huffman(table, 0x00);
    }
}

/// Encode AC EOB (for padding blocks).
fn encode_ac_eob(bw: &mut BitWriter, table: &HuffmanEncodeTable) {
    bw.write_huffman(table, 0x00);
}

/// `Log2FloorNonZero(x)` for x > 0 (== floor(log2(x))).
#[inline]
fn log2_floor_nz(x: u32) -> u32 {
    31 - x.leading_zeros()
}

/// Progressive EOB-run coding state — mirrors brunsli's `DCTCodingState`.
/// Buffers a run of end-of-band markers (coded as one `EOBn` symbol) plus the
/// trailing correction bits emitted by AC refinement scans.
struct DctCodingState {
    eob_run: u32,
    /// Buffered correction bits, one per element, in emission order.
    refinement_bits: Vec<u8>,
}

impl DctCodingState {
    fn new() -> Self {
        Self {
            eob_run: 0,
            refinement_bits: Vec::new(),
        }
    }

    /// Emit the buffered EOB run (as an `EOBn` Huffman symbol + extra bits)
    /// followed by the buffered correction bits, then reset.
    fn flush(&mut self, bw: &mut BitWriter, ac: &HuffmanEncodeTable) {
        if self.eob_run > 0 {
            let nbits = log2_floor_nz(self.eob_run);
            bw.write_huffman(ac, (nbits << 4) as u8);
            if nbits > 0 {
                bw.write_bits(self.eob_run & ((1 << nbits) - 1), nbits);
            }
            self.eob_run = 0;
        }
        for &b in &self.refinement_bits {
            bw.write_bits(b as u32, 1);
        }
        self.refinement_bits.clear();
    }

    /// Buffer one end-of-band (+ optional correction bits). Auto-flush at the
    /// 0x7FFF run-length ceiling.
    fn buffer_end_of_band(&mut self, new_bits: &[u8], bw: &mut BitWriter, ac: &HuffmanEncodeTable) {
        self.eob_run += 1;
        self.refinement_bits.extend_from_slice(new_bits);
        if self.eob_run == 0x7FFF {
            self.flush(bw, ac);
        }
    }
}

/// Progressive first-pass block (DC-first when Ss==0, else AC-first).
/// Port of brunsli `EncodeDCTBlockProgressive`. `coeffs` is natural order.
#[allow(clippy::too_many_arguments)]
fn encode_block_progressive(
    bw: &mut BitWriter,
    coeffs: &[i16],
    dc: &HuffmanEncodeTable,
    ac: &HuffmanEncodeTable,
    ss: usize,
    se: usize,
    al: u32,
    num_zero_runs: u32,
    cs: &mut DctCodingState,
    last_dc: &mut i32,
) {
    let eob_run_allowed = ss > 0;
    let mut k0 = ss;
    if ss == 0 {
        let temp2 = (coeffs[0] as i32) >> al;
        let mut temp = temp2 - *last_dc;
        *last_dc = temp2;
        let mut t2 = temp;
        if temp < 0 {
            temp = -temp;
            t2 -= 1;
        }
        let nbits = if temp == 0 {
            0
        } else {
            log2_floor_nz(temp as u32) + 1
        };
        bw.write_huffman(dc, nbits as u8);
        if nbits > 0 {
            bw.write_bits((t2 as u32) & ((1u32 << nbits) - 1), nbits);
        }
        k0 = 1;
    }
    if k0 > se {
        return;
    }
    let mut r: i32 = 0;
    for k in k0..=se {
        let mut temp = coeffs[ZIGZAG[k]] as i32;
        if temp == 0 {
            r += 1;
            continue;
        }
        let t2;
        if temp < 0 {
            temp = -temp;
            temp >>= al;
            t2 = !temp;
        } else {
            temp >>= al;
            t2 = temp;
        }
        if temp == 0 {
            // Coefficient quantized to 0 at this bit-plane → still a zero run.
            r += 1;
            continue;
        }
        cs.flush(bw, ac);
        while r > 15 {
            bw.write_huffman(ac, 0xF0);
            r -= 16;
        }
        let nbits = log2_floor_nz(temp as u32) + 1;
        bw.write_huffman(ac, (((r as u32) << 4) | nbits) as u8);
        bw.write_bits((t2 as u32) & ((1u32 << nbits) - 1), nbits);
        r = 0;
    }
    if num_zero_runs > 0 {
        cs.flush(bw, ac);
        for _ in 0..num_zero_runs {
            bw.write_huffman(ac, 0xF0);
            r -= 16;
        }
    }
    if r > 0 {
        cs.buffer_end_of_band(&[], bw, ac);
        if !eob_run_allowed {
            cs.flush(bw, ac);
        }
    }
}

/// Successive-approximation refinement block (Ah > 0).
/// Port of brunsli `EncodeRefinementBits`.
fn encode_refinement(
    bw: &mut BitWriter,
    coeffs: &[i16],
    ac: &HuffmanEncodeTable,
    ss: usize,
    se: usize,
    al: u32,
    cs: &mut DctCodingState,
) {
    let eob_run_allowed = ss > 0;
    let mut k0 = ss;
    if ss == 0 {
        // Refine the DC: emit the next bit.
        bw.write_bits(((coeffs[0] as i32) >> al) as u32 & 1, 1);
        k0 = 1;
    }
    if k0 > se {
        return;
    }
    let mut abs_values = [0i32; 64];
    let mut eob = 0usize;
    for k in k0..=se {
        let abs_val = (coeffs[ZIGZAG[k]] as i32).abs();
        abs_values[k] = abs_val >> al;
        if abs_values[k] == 1 {
            eob = k;
        }
    }
    let mut r: i32 = 0;
    let mut refinement_bits: Vec<u8> = Vec::new();
    for k in k0..=se {
        if abs_values[k] == 0 {
            r += 1;
            continue;
        }
        while r > 15 && k <= eob {
            cs.flush(bw, ac);
            bw.write_huffman(ac, 0xF0);
            r -= 16;
            for &b in &refinement_bits {
                bw.write_bits(b as u32, 1);
            }
            refinement_bits.clear();
        }
        if abs_values[k] > 1 {
            // Already-significant coefficient → one correction bit.
            refinement_bits.push((abs_values[k] & 1) as u8);
            continue;
        }
        // Newly-significant coefficient.
        cs.flush(bw, ac);
        let symbol = (((r as u32) << 4) | 1) as u8;
        let new_nonzero_bit = if (coeffs[ZIGZAG[k]] as i32) < 0 {
            0u32
        } else {
            1u32
        };
        bw.write_huffman(ac, symbol);
        bw.write_bits(new_nonzero_bit, 1);
        for &b in &refinement_bits {
            bw.write_bits(b as u32, 1);
        }
        refinement_bits.clear();
        r = 0;
    }
    if r > 0 || !refinement_bits.is_empty() {
        cs.buffer_end_of_band(&refinement_bits, bw, ac);
        if !eob_run_allowed {
            cs.flush(bw, ac);
        }
    }
}

/// Categorize a coefficient value for Huffman encoding.
/// Returns (category, extra_bits, extra_bit_length).
fn categorize(value: i32) -> (u32, u32, u32) {
    if value == 0 {
        return (0, 0, 0);
    }
    let abs_val = value.unsigned_abs();
    let category = 32 - abs_val.leading_zeros(); // = ceil(log2(abs+1))
    // For positive values: extra_bits = value
    // For negative values: extra_bits = value + (1 << category) - 1
    let extra_bits = if value > 0 {
        value as u32
    } else {
        (value + (1 << category) - 1) as u32
    };
    (category, extra_bits, category)
}

/// Huffman encode table: symbol → (code, length).
struct HuffmanEncodeTable {
    codes: [u32; 256],
    lengths: [u8; 256],
}

impl HuffmanEncodeTable {
    fn from_counts_values(counts: &[u32; 16], values: &[u8]) -> Self {
        let mut codes = [0u32; 256];
        let mut lengths = [0u8; 256];

        // Generate Huffman codes from counts (JPEG standard algorithm)
        let mut code: u32 = 0;
        let mut val_idx = 0;
        for (bits_minus_1, &count) in counts.iter().enumerate() {
            let bits = bits_minus_1 as u8 + 1;
            for _ in 0..count {
                if val_idx < values.len() {
                    let symbol = values[val_idx] as usize;
                    codes[symbol] = code;
                    lengths[symbol] = bits;
                    val_idx += 1;
                }
                code += 1;
            }
            code <<= 1;
        }

        Self { codes, lengths }
    }
}

/// Bitstream writer for JPEG entropy-coded data.
struct BitWriter {
    buffer: Vec<u8>,
    bit_buffer: u32,
    bits_in_buffer: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            bit_buffer: 0,
            bits_in_buffer: 0,
        }
    }

    fn write_huffman(&mut self, table: &HuffmanEncodeTable, symbol: u8) {
        let code = table.codes[symbol as usize];
        let length = table.lengths[symbol as usize];
        if length > 0 {
            self.write_bits(code, length as u32);
        }
    }

    fn write_bits(&mut self, value: u32, num_bits: u32) {
        // JPEG uses MSB-first bit packing
        // We accumulate bits MSB-first in bit_buffer
        self.bit_buffer = (self.bit_buffer << num_bits) | (value & ((1 << num_bits) - 1));
        self.bits_in_buffer += num_bits;

        while self.bits_in_buffer >= 8 {
            self.bits_in_buffer -= 8;
            let byte = ((self.bit_buffer >> self.bits_in_buffer) & 0xFF) as u8;
            self.buffer.push(byte);
            if byte == 0xFF {
                self.buffer.push(0x00); // byte stuffing
            }
        }
    }

    fn pad_to_byte(&mut self, padding_bits: &[u8], padding_idx: &mut usize) {
        while !self.bits_in_buffer.is_multiple_of(8) {
            let bit = if *padding_idx < padding_bits.len() {
                let b = padding_bits[*padding_idx];
                *padding_idx += 1;
                b
            } else {
                1 // Default pad with 1s (standard JPEG)
            };
            self.write_bits(bit as u32, 1);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        // Any remaining bits should have been padded already
        debug_assert!(self.bits_in_buffer == 0);
        std::mem::take(&mut self.buffer)
    }
}
