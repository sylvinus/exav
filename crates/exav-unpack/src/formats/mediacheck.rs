//! Structural validation of image formats — ClamAV's `Heuristics.Broken.Media.*`
//! family, reported under `--alert-broken-media`.
//!
//! The premise is that a decoder is forgiving and a parser is not. Every viewer
//! that renders a truncated GIF or a JPEG with a bogus segment length is being
//! generous; the generosity is what exploit writers aim at, and the mismatch
//! between "renders fine" and "does not hold together" is itself the signal.
//! So these checks are deliberately strict about the *container* and say nothing
//! at all about pixels.
//!
//! Every name here is ClamAV's exactly, because the name is the API: a gateway
//! filtering on `Heuristics.Broken.Media.PNG.EOFReadingChunk` will not match a
//! tidier spelling of the same condition.
//!
//! The formats are all published standards (GIF89a, the PNG specification,
//! TIFF 6.0, and JPEG/JFIF), so each check below follows from the spec rather
//! than from any implementation.

/// The first structural fault found in `data`, as a ClamAV alert name, or `None`
/// when the file is either well formed or not an image this validates.
///
/// Returns on the *first* fault: a file with several is still one alert, and the
/// earliest one is the most informative about where parsing diverged.
pub fn broken_media_alert(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return check_gif(data);
    }
    if data.starts_with(b"\x89PNG") {
        // Matched on the 4-byte prefix, NOT the full 8-byte signature.
        //
        // The rest of that signature (`\r\n\x1a\n`) is a corruption detector by
        // design: it catches a transfer that translated line endings, which is
        // why a mangled copy reads `\r\n\x1a\r\n`. Requiring it exactly meant a
        // PNG damaged in precisely the way the signature was built to reveal was
        // not recognised as a PNG at all, so the broken-media check never ran and
        // the file came back clean.
        //
        // A file claiming to be a PNG and failing to parse as one is the whole
        // point of this heuristic; `check_png` then names the specific fault.
        return check_png(data);
    }
    if data.starts_with(b"II\x2a\x00") || data.starts_with(b"MM\x00\x2a") {
        return check_tiff(data);
    }
    if data.starts_with(b"\xff\xd8") {
        return check_jpeg(data);
    }
    None
}

// ------------------------------------------------------------------------ GIF

fn check_gif(d: &[u8]) -> Option<&'static str> {
    // Header (6) + logical screen descriptor (7).
    if d.len() < 13 {
        return Some("Heuristics.Broken.Media.GIF.TruncatedScreenDescriptor");
    }
    let flags = d[10];
    let mut p = 13usize;
    // Global colour table, when the flag is set: 3 bytes per entry, 2^(n+1)
    // entries.
    if flags & 0x80 != 0 {
        let entries = 1usize << ((flags & 0x07) + 1);
        p = p.checked_add(entries.checked_mul(3)?)?;
        if p > d.len() {
            return Some("Heuristics.Broken.Media.GIF.TruncatedGlobalColorTable");
        }
    }
    let mut saw_image = false;
    loop {
        let Some(&block) = d.get(p) else {
            // Ran out before the trailer.
            return Some(if saw_image {
                "Heuristics.Broken.Media.GIF.TruncatedImageDataBlock"
            } else {
                "Heuristics.Broken.Media.GIF.MissingImageData"
            });
        };
        p += 1;
        match block {
            0x3B => break, // trailer
            0x21 => {
                // Extension: one label byte, then sub-blocks.
                if d.get(p).is_none() {
                    return Some("Heuristics.Broken.Media.GIF.TruncatedExtension");
                }
                p += 1;
                p = skip_subblocks(d, p)
                    .ok_or("Heuristics.Broken.Media.GIF.TruncatedExtensionSubBlock")
                    .ok()?;
            }
            0x2C => {
                // Image descriptor: 9 bytes, then optional local colour table,
                // then an LZW code-size byte and sub-blocks.
                let Some(desc) = d.get(p..p + 9) else {
                    return Some("Heuristics.Broken.Media.GIF.TruncatedImageDescriptor");
                };
                let lflags = desc[8];
                p += 9;
                if lflags & 0x80 != 0 {
                    let entries = 1usize << ((lflags & 0x07) + 1);
                    p = p.checked_add(entries.checked_mul(3)?)?;
                    if p > d.len() {
                        return Some("Heuristics.Broken.Media.GIF.TruncatedImageDescriptor");
                    }
                }
                if d.get(p).is_none() {
                    return Some("Heuristics.Broken.Media.GIF.TruncatedImageDataBlock");
                }
                p += 1; // LZW minimum code size
                let Some(np) = skip_subblocks(d, p) else {
                    return Some("Heuristics.Broken.Media.GIF.TruncatedImageDataBlock");
                };
                p = np;
                saw_image = true;
            }
            _ => return Some("Heuristics.Broken.Media.GIF.UnknownBlockLabel"),
        }
    }
    if !saw_image {
        return Some("Heuristics.Broken.Media.GIF.MissingImageData");
    }
    None
}

/// Walk a GIF sub-block chain to its terminating zero-length block.
fn skip_subblocks(d: &[u8], mut p: usize) -> Option<usize> {
    loop {
        let n = *d.get(p)? as usize;
        p += 1;
        if n == 0 {
            return Some(p);
        }
        p = p.checked_add(n)?;
        if p > d.len() {
            return None;
        }
    }
}

// ------------------------------------------------------------------------ PNG

fn check_png(d: &[u8]) -> Option<&'static str> {
    let mut p = 8usize; // signature
    loop {
        if p == d.len() {
            // Ran out exactly at a chunk boundary without IEND.
            return Some("Heuristics.Broken.Media.PNG.EOFReadingChunk");
        }
        let Some(lb) = d.get(p..p + 4) else {
            return Some("Heuristics.Broken.Media.PNG.EOFReadingChunk");
        };
        let len = u32::from_be_bytes([lb[0], lb[1], lb[2], lb[3]]) as usize;
        // The spec caps a chunk length at 2^31-1; anything above is invalid
        // regardless of what follows.
        if len > 0x7fff_ffff {
            return Some("Heuristics.Broken.Media.PNG.InvalidChunkLength");
        }
        let Some(ty) = d.get(p + 4..p + 8) else {
            return Some("Heuristics.Broken.Media.PNG.EOFReadingChunkType");
        };
        let is_end = ty == b"IEND";
        let Some(end) = p.checked_add(8).and_then(|q| q.checked_add(len)) else {
            return Some("Heuristics.Broken.Media.PNG.InvalidChunkLength");
        };
        if end > d.len() {
            return Some("Heuristics.Broken.Media.PNG.EOFReadingChunk");
        }
        if end.checked_add(4)? > d.len() {
            return Some("Heuristics.Broken.Media.PNG.EOFReadingChunkCRC");
        }
        p = end + 4;
        if is_end {
            return None;
        }
    }
}

// ----------------------------------------------------------------------- TIFF

fn check_tiff(d: &[u8]) -> Option<&'static str> {
    let le = d.starts_with(b"II");
    let u16at = |o: usize| -> Option<u16> {
        let b = d.get(o..o + 2)?;
        Some(if le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    };
    let u32at = |o: usize| -> Option<u32> {
        let b = d.get(o..o + 4)?;
        Some(if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };

    let Some(first) = u32at(4) else {
        return Some("Heuristics.Broken.Media.TIFF.EOFReadingFirstIFDOffset");
    };
    let mut off = first as usize;
    let mut prev = 0usize;
    // Bound the walk: a crafted file can otherwise chain IFDs indefinitely.
    for _ in 0..64 {
        if off == 0 {
            return None; // end of the IFD chain
        }
        if off >= d.len() {
            return Some("Heuristics.Broken.Media.TIFF.InvalidIFDOffset");
        }
        // The chain must move forward; a backward or repeated offset is how a
        // parser is made to loop.
        if off <= prev {
            return Some("Heuristics.Broken.Media.TIFF.OutOfOrderIFDOffset");
        }
        prev = off;
        let Some(n) = u16at(off) else {
            return Some("Heuristics.Broken.Media.TIFF.EOFReadingNumIFDDirectoryEntries");
        };
        let entries_end = off
            .checked_add(2)?
            .checked_add((n as usize).checked_mul(12)?)?;
        if entries_end > d.len() {
            return Some("Heuristics.Broken.Media.TIFF.EOFReadingIFDEntry");
        }
        // Each entry's value, when it does not fit inline, is an offset that has
        // to land inside the file.
        for i in 0..n as usize {
            let e = off + 2 + i * 12;
            let count = u32at(e + 4)? as usize;
            let ty = u16at(e + 2)?;
            let size = tiff_type_size(ty);
            let bytes = count.saturating_mul(size);
            if size > 0 && bytes > 4 {
                let vo = u32at(e + 8)? as usize;
                if vo.saturating_add(bytes) > d.len() {
                    return Some("Heuristics.Broken.Media.TIFF.OutOfBoundsAccess");
                }
            }
        }
        let Some(next) = u32at(entries_end) else {
            return Some("Heuristics.Broken.Media.TIFF.EOFReadingChunkCRC");
        };
        off = next as usize;
    }
    None
}

/// Byte width of a TIFF field type; 0 for types this does not model, which are
/// skipped rather than guessed at.
fn tiff_type_size(ty: u16) -> usize {
    match ty {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 => 4,
        5 | 10 | 12 => 8,
        _ => 0,
    }
}

// ----------------------------------------------------------------------- JPEG

fn check_jpeg(d: &[u8]) -> Option<&'static str> {
    let mut p = 2usize; // SOI
    let mut seen_sof = false;
    let (mut jfif, mut exif, mut spiff) = (0u32, 0u32, 0u32);
    let mut segment_index = 0u32;
    loop {
        // Markers may be preceded by fill bytes (0xFF), but arbitrary data
        // between segments is not legal.
        let Some(&b0) = d.get(p) else {
            return Some(if seen_sof {
                "Heuristics.Broken.Media.JPEG.NoImages"
            } else {
                "Heuristics.Broken.Media.JPEG.CantReadMarker"
            });
        };
        if b0 != 0xFF {
            return Some("Heuristics.Broken.Media.JPEG.SpuriousBytesBeforeSegment");
        }
        let mut q = p;
        while d.get(q) == Some(&0xFF) {
            q += 1;
        }
        let Some(&marker) = d.get(q) else {
            return Some("Heuristics.Broken.Media.JPEG.CantReadMarker");
        };
        p = q + 1;
        segment_index += 1;
        match marker {
            0xD9 => break,                         // EOI
            0xD8 | 0x01 | 0xD0..=0xD7 => continue, // standalone markers
            0xDA => {
                // Start of scan: entropy-coded data follows, whose extent is not
                // declared. Structural validation ends here.
                seen_sof = true;
                break;
            }
            _ => {}
        }
        let Some(lb) = d.get(p..p + 2) else {
            return Some("Heuristics.Broken.Media.JPEG.CantReadSegmentSize");
        };
        let len = u16::from_be_bytes([lb[0], lb[1]]) as usize;
        // The length field includes its own two bytes, so anything under 2 is
        // impossible.
        if len < 2 {
            return Some("Heuristics.Broken.Media.JPEG.InvalidSegmentSize");
        }
        if p + len > d.len() {
            return Some("Heuristics.Broken.Media.JPEG.SegmentDataOutOfFile");
        }
        let body = &d[p + 2..p + len];
        match marker {
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => seen_sof = true,
            0xE0 => {
                // APP0 — JFIF. Long enough to hold the identifier plus version
                // and density fields.
                //
                // Its POSITION is deliberately not checked. JPEG permits APPn
                // markers in any order and mainstream writers use that latitude:
                // Adobe emits APP1 Exif before APP0 JFIF, which put JFIF at index
                // 2 and reported ordinary Photoshop and Office output as broken
                // media. clamd, which has the same machinery, emits this name
                // zero times over 8,978 samples while emitting other Broken.Media
                // names 29 times — it declines to make this check, and is right
                // to. A marker order the format allows is not evidence of
                // tampering.
                jfif += 1;
                if jfif > 1 {
                    return Some("Heuristics.Broken.Media.JPEG.JFIFdupAppMarker");
                }
                if body.starts_with(b"JFIF\0") && len < 16 {
                    return Some("Heuristics.Broken.Media.JPEG.JFIFheaderTooShort");
                }
            }
            0xE1 => {
                // APP1 — Exif.
                if body.starts_with(b"Exif\0") {
                    exif += 1;
                    if exif > 1 {
                        return Some("Heuristics.Broken.Media.JPEG.ExifDupAppMarker");
                    }
                    // Position deliberately unchecked — see the APP0 arm above.
                    // An ICC profile (APP2) or a Photoshop resource block (APP13)
                    // sitting between JFIF and Exif is ordinary, and requiring
                    // Exif at index <= 2 reported Office `docProps/thumbnail.jpeg`
                    // and every Photoshop export as broken.
                    if len < 16 {
                        return Some("Heuristics.Broken.Media.JPEG.ExifHeaderTooShort");
                    }
                }
            }
            0xE8 => {
                // APP8 — SPIFF.
                spiff += 1;
                if spiff > 1 {
                    return Some("Heuristics.Broken.Media.JPEG.SPIFFdupAppMarker");
                }
                if segment_index != 1 {
                    return Some("Heuristics.Broken.Media.JPEG.SPIFFmarkerBadPosition");
                }
                if len < 32 {
                    return Some("Heuristics.Broken.Media.JPEG.SPIFFheaderTooShort");
                }
            }
            _ => {}
        }
        p += len;
    }
    if !seen_sof {
        return Some("Heuristics.Broken.Media.JPEG.NoImages");
    }
    None
}
