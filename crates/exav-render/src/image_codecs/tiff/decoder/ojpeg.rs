//! exav: old-style JPEG (compression 6, TIFF 6.0's first JPEG), for the viewer's
//! reader only (see `with_viewer_codecs`). A strip holds the entropy-coded
//! scan of a JPEG and nothing else, or a whole JPEG; the tables and the frame
//! are in tags (512 to 521), or in a JPEG stream the file points to
//! (`JPEGInterchangeFormat`). The header is built once from them, and each
//! strip decoded as a JPEG of its own: the header, with its frame as high as
//! the strip, then the strip's bytes. libtiff's `tif_ojpeg.c` is the reference.

use std::io::{self, Read, Seek, SeekFrom};

/// The tags of old-style JPEG that a header is made from. (A first strip that
/// the stream the file points to holds, and whose byte count stops short of the
/// stream's end, runs to it, as libtiff reads it: `header` says where.)
pub(super) struct Tags {
    /// `JPEGInterchangeFormat`: where a JPEG stream starts, and how long it is.
    pub interchange: Option<(u64, u64)>,
    /// `JPEGQTables`, `JPEGDCTables`, `JPEGACTables`: where each component's table is.
    pub q: Vec<u64>,
    pub dc: Vec<u64>,
    pub ac: Vec<u64>,
    /// `JPEGRestartInterval`.
    pub restart: u16,
    /// `YCbCrSubSampling` of a three-sample image.
    pub subsampling: (u16, u16),
}

/// The most of a JPEG stream looked at for its headers.
const MAX_STREAM: u64 = 1 << 20;

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("ojpeg: {what}"))
}

fn read_at<R: Read + Seek>(r: &mut R, at: u64, n: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    r.seek(SeekFrom::Start(at))?;
    r.read_exact(&mut out)?;
    Ok(out)
}

fn segment(out: &mut Vec<u8>, marker: u8, body: &[u8]) {
    out.extend_from_slice(&[0xFF, marker]);
    out.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// The JPEG up to and including the header of its scan, for a frame `width`
/// wide and of `samples` components. Where the stream the file points to has
/// a table, a frame or a scan header, it is used; the rest comes from the tags.
pub(super) fn header<R: Read + Seek>(
    r: &mut R,
    tags: &Tags,
    width: u32,
    rows: u32,
    samples: u16,
) -> io::Result<(Vec<u8>, u64, u64)> {
    let samples = usize::from(samples);
    if samples != 1 && samples != 3 {
        return Err(bad("components"));
    }
    // What the stream has, as its segments up to the scan header, and where in
    // the file that header ends.
    let (mut kept, mut scan, mut scan_end, mut stream_end) = (Vec::new(), None, 0, 0);
    let (mut has_q, mut has_dc_ac, mut has_frame, mut has_restart) = (false, false, false, false);
    if let Some((at, len)) = tags.interchange {
        let len = len.min(MAX_STREAM);
        let mut stream = Vec::new();
        r.seek(SeekFrom::Start(at))?;
        r.by_ref().take(len).read_to_end(&mut stream)?;
        stream_end = at + stream.len() as u64;
        let mut p = 2;
        if !stream.starts_with(&[0xFF, 0xD8]) {
            p = stream.len();
        }
        while p + 4 <= stream.len() {
            if stream[p] != 0xFF {
                break;
            }
            let marker = stream[p + 1];
            if marker == 0xFF {
                p += 1;
                continue;
            }
            let size = usize::from(u16::from_be_bytes([stream[p + 2], stream[p + 3]]));
            let Some(end) = p.checked_add(2 + size).filter(|&e| size >= 2 && e <= stream.len())
            else {
                break;
            };
            let body = &stream[p..end];
            match marker {
                0xDA => {
                    scan = Some(body.to_vec());
                    scan_end = at + end as u64;
                    break;
                }
                0xDB => has_q = true,
                0xC4 => has_dc_ac = true,
                0xC0..=0xC3 => has_frame = true,
                0xDD => has_restart = true,
                _ => {}
            }
            kept.extend_from_slice(body);
            p = end;
        }
    }

    let mut out = vec![0xFF, 0xD8];
    out.extend_from_slice(&kept);
    // The tables each component uses: where each is, and its number among the
    // distinct ones (components that name one table share it). Without tags,
    // the first component has table 0 and the others table 1.
    let q = distinct(&tags.q, samples);
    let dc = distinct(&tags.dc, samples);
    let ac = distinct(&tags.ac, samples);
    if !has_q {
        for (id, &at) in q.0.iter().enumerate() {
            let mut body = vec![id as u8];
            body.extend_from_slice(&read_at(r, at, 64)?);
            segment(&mut out, 0xDB, &body);
        }
        if q.0.is_empty() {
            return Err(bad("quantisation tables"));
        }
    }
    if !has_dc_ac {
        for (class, tables) in [(0u8, &dc.0), (1, &ac.0)] {
            if tables.is_empty() {
                return Err(bad("Huffman tables"));
            }
            for (id, &at) in tables.iter().enumerate() {
                let counts = read_at(r, at, 16)?;
                let n: usize = counts.iter().map(|&c| usize::from(c)).sum();
                if n > 256 {
                    return Err(bad("Huffman table"));
                }
                let mut body = vec![class << 4 | id as u8];
                body.extend_from_slice(&counts);
                body.extend_from_slice(&read_at(r, at + 16, n)?);
                segment(&mut out, 0xC4, &body);
            }
        }
    }
    if !has_restart && tags.restart > 0 {
        segment(&mut out, 0xDD, &tags.restart.to_be_bytes());
    }
    if !has_frame {
        let (h, v) = if samples == 3 { tags.subsampling } else { (1, 1) };
        if !(1..=4).contains(&h) || !(1..=4).contains(&v) {
            return Err(bad("subsampling"));
        }
        let mut body = vec![8];
        body.extend_from_slice(&(rows.min(0xFFFF) as u16).to_be_bytes());
        body.extend_from_slice(&(width.min(0xFFFF) as u16).to_be_bytes());
        body.push(samples as u8);
        for i in 0..samples {
            let hv = if i == 0 { (h << 4 | v) as u8 } else { 0x11 };
            body.extend_from_slice(&[i as u8 + 1, hv, q.1[i]]);
        }
        segment(&mut out, 0xC0, &body);
    }
    match scan {
        Some(scan) => out.extend_from_slice(&scan),
        None => {
            let mut body = vec![samples as u8];
            for i in 0..samples {
                body.extend_from_slice(&[i as u8 + 1, dc.1[i] << 4 | ac.1[i]]);
            }
            body.extend_from_slice(&[0, 63, 0]);
            segment(&mut out, 0xDA, &body);
        }
    }
    Ok((out, scan_end, stream_end))
}

/// The distinct tables a tag names for `samples` components (the last one
/// serves the components after it), in order of first use, and each
/// component's index among them.
fn distinct(list: &[u64], samples: usize) -> (Vec<u64>, Vec<u8>) {
    let mut tables: Vec<u64> = Vec::new();
    let mut ids = Vec::new();
    for i in 0..samples {
        let Some(&at) = list.get(i).or(list.last()) else {
            // No tag: the usual numbering, luminance and then chrominance.
            ids.push(u8::from(i > 0));
            continue;
        };
        let id = tables.iter().position(|&t| t == at).unwrap_or_else(|| {
            tables.push(at);
            tables.len() - 1
        });
        ids.push(id as u8);
    }
    (tables, ids)
}

/// The JPEG of one strip: `header` with its frame `rows` high, then the strip's
/// bytes and an end marker. A strip that is a whole JPEG itself (it starts with
/// the start-of-image marker) is that JPEG. A first strip may be named from
/// inside the stream's own header (from `skip` bytes before its end), and those
/// bytes are not scan data.
pub(super) fn strip_jpeg(header: &[u8], mut strip: Vec<u8>, rows: u32, skip: u64) -> Vec<u8> {
    if strip.starts_with(&[0xFF, 0xD8]) {
        return strip;
    }
    strip.drain(..usize::try_from(skip).unwrap_or(usize::MAX).min(strip.len()));
    // Or the strip starts with the scan header, which the header ends with.
    if strip.starts_with(&[0xFF, 0xDA]) && strip.len() >= 4 {
        let n = 2 + usize::from(u16::from_be_bytes([strip[2], strip[3]]));
        strip.drain(..n.min(strip.len()));
    }
    let mut jpeg = header.to_vec();
    // The frame's height sits after its marker (FFC0 to FFC3), length and precision.
    let mut p = 2;
    while p + 4 <= jpeg.len() && jpeg[p] == 0xFF {
        let marker = jpeg[p + 1];
        let size = usize::from(u16::from_be_bytes([jpeg[p + 2], jpeg[p + 3]]));
        if (0xC0..=0xC3).contains(&marker) && p + 9 <= jpeg.len() {
            jpeg[p + 5..p + 7].copy_from_slice(&(rows.min(0xFFFF) as u16).to_be_bytes());
            break;
        }
        p += 2 + size;
    }
    jpeg.extend_from_slice(&strip);
    if !jpeg.ends_with(&[0xFF, 0xD9]) {
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
    }
    jpeg
}
