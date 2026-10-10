//! bzip2 decoder, vendored from `bzip2-rs` 0.1.2 (Copyright Paolo Barbolini,
//! MIT OR Apache-2.0; attributed in `NOTICE`). Pure Rust, no `unsafe`.
//!
//! Changes from upstream:
//! * the streaming decoder buffers enough input for the largest compressed
//!   block, which is larger than the block itself when the data does not
//!   compress (upstream issue #13, unfixed in any release);
//! * the `rustc_1_37` code paths are taken unconditionally, the `nightly`
//!   ones dropped, and lints brought up to this crate's settings;
//! * paths and visibility adapted to a module of this crate;
//! * a mode for NSIS's bzip2, which has no stream header, marks a block and
//!   the end of the stream with one byte each, and has no checksums or
//!   randomised bit (`DecoderReader::new_nsis`);
//! * a block whose bits run out at the end of the input is an `UnexpectedEof`
//!   error, told apart from damage;
//! * a block failing its CRC does not stop the stream: the blocks after it
//!   are decoded, and the mismatch is a checksum-mismatch error
//!   (`crate::checksum_mismatch`) at the end of the stream.

pub(crate) use self::decoder::DecoderReader;

mod bitreader;
mod block;
mod crc;
mod decoder;
mod header;
mod huffman;
mod move_to_front;

const LEN_258: usize = 512;
