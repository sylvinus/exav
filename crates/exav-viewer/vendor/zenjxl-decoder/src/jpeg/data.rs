// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Data structures for reconstructed JPEG metadata.

/// Classification of APP markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AppMarkerType {
    Unknown = 0,
    Icc = 1,
    Exif = 2,
    Xmp = 3,
}

impl AppMarkerType {
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Unknown),
            1 => Some(Self::Icc),
            2 => Some(Self::Exif),
            3 => Some(Self::Xmp),
            _ => None,
        }
    }
}

/// JPEG quantization table.
#[derive(Debug, Clone)]
pub struct JpegQuantTable {
    /// 64 quantization values in natural (row-major) order.
    pub values: [i32; 64],
    /// Precision: 0 = 8-bit, 1 = 16-bit.
    pub precision: u32,
    /// DQT table index (0-3).
    pub index: u32,
    /// Whether this is the last table in its DQT marker.
    pub is_last: bool,
}

/// JPEG Huffman code table.
#[derive(Debug, Clone)]
pub struct JpegHuffmanCode {
    /// Whether this is an AC table (true) or DC table (false).
    pub is_ac: bool,
    /// Table ID (0-3).
    pub id: u32,
    /// Whether this is the last table in its DHT marker.
    pub is_last: bool,
    /// Number of codes at each bit length (1-16). Index 0 = 1-bit codes.
    pub counts: [u32; 16],
    /// Symbol values, ordered by code length then value.
    pub values: Vec<u8>,
}

/// JPEG image component.
#[derive(Debug, Clone)]
pub struct JpegComponent {
    /// Component ID byte.
    pub id: u32,
    /// Horizontal sampling factor (1-4).
    pub h_samp_factor: u32,
    /// Vertical sampling factor (1-4).
    pub v_samp_factor: u32,
    /// Index into `JpegData::quant` for this component's quant table.
    pub quant_idx: u32,
    /// Width in 8x8 blocks.
    pub width_in_blocks: u32,
    /// Height in 8x8 blocks.
    pub height_in_blocks: u32,
    /// Reconstructed quantized DCT coefficients, block-by-block in raster order.
    /// Each block has 64 coefficients in natural (row-major) order.
    pub coeffs: Vec<i16>,
}

/// JPEG scan information.
#[derive(Debug, Clone)]
pub struct JpegScanInfo {
    /// Number of components in this scan (1-4).
    pub num_components: u32,
    /// Component indices (into JpegData::components).
    pub component_indices: Vec<u32>,
    /// DC Huffman table index per component.
    pub dc_tbl_idx: Vec<u32>,
    /// AC Huffman table index per component.
    pub ac_tbl_idx: Vec<u32>,
    /// Start of spectral selection (Ss).
    pub ss: u32,
    /// End of spectral selection (Se).
    pub se: u32,
    /// Successive approximation high bit (Ah).
    pub ah: u32,
    /// Successive approximation low bit (Al).
    pub al: u32,
    /// Block indices where RST markers occur.
    pub reset_points: Vec<u32>,
    /// (block_index, num_extra_zero_runs) for extra zero runs before EOB.
    pub extra_zero_runs: Vec<(u32, u32)>,
    /// Last needed pass (always 0 for baseline JPEG).
    #[allow(dead_code)] // Populated from JBRD for progressive JPEG support
    pub last_needed_pass: u32,
}

/// JPEG component type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum JpegComponentType {
    Gray = 0,
    YCbCr = 1,
    Rgb = 2,
    Custom = 3,
}

impl JpegComponentType {
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Gray),
            1 => Some(Self::YCbCr),
            2 => Some(Self::Rgb),
            3 => Some(Self::Custom),
            _ => None,
        }
    }
}

/// Complete JPEG reconstruction data.
///
/// Populated from the JBRD box and reconstructed coefficients. Contains
/// everything needed to write a byte-exact copy of the original JPEG.
#[derive(Debug, Clone)]
pub struct JpegData {
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Restart interval (from DRI marker, 0 = none).
    pub restart_interval: u32,
    /// Raw APP marker data.
    pub app_data: Vec<Vec<u8>>,
    /// Classification of each APP marker.
    #[allow(dead_code)] // Populated from JBRD for marker reconstruction
    pub app_marker_type: Vec<AppMarkerType>,
    /// Raw COM marker data.
    pub com_data: Vec<Vec<u8>>,
    /// Quantization tables.
    pub quant: Vec<JpegQuantTable>,
    /// Huffman code tables.
    pub huffman_code: Vec<JpegHuffmanCode>,
    /// Image components.
    pub components: Vec<JpegComponent>,
    /// Scan information.
    pub scan_info: Vec<JpegScanInfo>,
    /// Marker order (sequence of second bytes of 0xFF XX markers).
    pub marker_order: Vec<u8>,
    /// Data between markers.
    pub inter_marker_data: Vec<Vec<u8>>,
    /// Data after EOI marker.
    pub tail_data: Vec<u8>,
    /// Whether there are any non-zero padding bits.
    #[allow(dead_code)] // Populated from JBRD for bit-exact reconstruction
    pub has_zero_padding_bit: bool,
    /// Individual padding bits.
    pub padding_bits: Vec<u8>,
    /// Component type classification.
    pub component_type: JpegComponentType,
}
