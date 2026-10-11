//! The files a DXF drawing carries in binary chunks (group 310).
//!
//! An ASCII DXF holds them as hexadecimal text, which a pattern scan of the
//! file reads as text, not as the file it encodes. An OLE2FRAME's chunks are
//! the embedded object (ODA's DWG specification, OLE2FRAME: "the OLE2
//! data"), led by a header of its own before the compound file; other
//! records' chunks (proxy entity graphics and data, the preview image, ACIS
//! data) are emitted only when they are a whole file of a kind recognised by
//! its first bytes, since they are otherwise AutoCAD's own encodings.

use super::{Parts, Records, Stop};
use crate::*;

/// The compound file signature (MS-CFB 2.2).
const OLE2: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Whole files a chunk may be, by their first bytes, and the extension that
/// names them.
const WHOLE_FILES: &[(&[u8], &str)] = &[
    (OLE2, "ole"),
    (b"PK\x03\x04", "zip"),
    (b"MZ", "exe"),
    (b"%PDF-", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xFF\xD8\xFF", "jpg"),
    (b"GIF8", "gif"),
    (b"\x7FELF", "elf"),
];

fn whole_file_extension(data: &[u8]) -> Option<&'static str> {
    WHOLE_FILES
        .iter()
        .find(|(magic, _)| data.starts_with(magic))
        .map(|(_, ext)| *ext)
}

fn emit<R>(
    name: String,
    bytes: Vec<u8>,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    if bytes.len() as u64 > cap {
        return Err(LimitHit::new(format!(
            "dxf: {name} ({} bytes) exceeds the per-member budget",
            bytes.len()
        )));
    }
    budget.commit(bytes.len() as u64);
    Ok(visit(Entry::new(name, bytes), budget))
}

pub(crate) fn extract_dxf<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let mut records = Records::new(data);
    let mut unnamed = 0usize;
    while let Some(rec) = records.next() {
        if rec.is("EOF") {
            return Ok(None);
        }
        if !rec.tags.iter().any(|t| (310..=319).contains(&t.code)) {
            continue;
        }
        // The preview image is the THUMBNAILIMAGE section's own pairs.
        let section = rec.is("SECTION").then(|| {
            rec.tags
                .iter()
                .find(|t| t.code == 2)
                .map(|t| {
                    String::from_utf8_lossy(t.bytes())
                        .trim()
                        .to_ascii_uppercase()
                })
                .unwrap_or_default()
        });
        let parts = Parts::new(&rec.tags, false);
        let mut chunks = Vec::new();
        let mut bad_hex = false;
        for t in parts.tags.iter().filter(|t| t.code == 310) {
            if !t.chunk_into(&mut chunks) {
                bad_hex = true;
            }
        }
        let ole2frame = rec.is("OLE2FRAME");
        let handle = parts.handle();
        let label = match (&section, handle) {
            (Some(s), _) if s == "THUMBNAILIMAGE" => "thumbnail".to_string(),
            (_, 0) => {
                unnamed += 1;
                format!("{}-{unnamed}", rec.type_name().to_ascii_lowercase())
            }
            (_, h) => format!("{}-{h:X}", rec.type_name().to_ascii_lowercase()),
        };
        if bad_hex && ole2frame {
            // The object is there; what it holds could not be read.
            budget.count_entry()?;
            if let Some(r) = visit(
                Entry::unsupported(
                    label,
                    chunks.len() as u64,
                    false,
                    "OLE2FRAME data is not hexadecimal",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            continue;
        }
        let out = if ole2frame {
            match find(&chunks, OLE2) {
                Some(at) => Some((format!("{label}.ole"), chunks.split_off(at))),
                None if chunks.is_empty() => None,
                None => Some((format!("{label}.bin"), chunks)),
            }
        } else {
            whole_file_extension(&chunks).map(|ext| (format!("{label}.{ext}"), chunks))
        };
        if let Some((name, bytes)) = out {
            if let Some(r) = emit(name, bytes, budget, visit)? {
                return Ok(Some(r));
            }
        }
    }
    // A pair that is not one leaves the rest of the file undecoded: whatever
    // chunks follow were not read. Running out of bytes is the end of what
    // exists, not something hidden.
    if let Some(Stop::BadCode(at)) = records.stop() {
        budget.count_entry()?;
        if let Some(r) = visit(
            Entry::unsupported(
                format!("dxf-after-{at}"),
                (data.len() as u64).saturating_sub(*at),
                false,
                "DXF stops being group code and value pairs before its end",
            ),
            budget,
        ) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// An ASCII DXF of one entity whose 310 chunks hold `payload`, split as
    /// AutoCAD splits them (127 bytes a line).
    fn dxf_with(entity: &str, handle: &str, payload: &[u8]) -> Vec<u8> {
        let mut s = format!("0\nSECTION\n2\nENTITIES\n0\n{entity}\n5\n{handle}\n8\n0\n");
        for line in payload.chunks(127) {
            s.push_str(&format!("310\n{}\n", hex(line)));
        }
        s.push_str("0\nENDSEC\n0\nEOF\n");
        s.into_bytes()
    }

    fn members(data: &[u8]) -> Vec<Entry> {
        let mut budget = Budget::new(Limits::default());
        extract(Format::Dxf, &data, &mut budget).expect("extracts")
    }

    #[test]
    fn an_ole2frame_yields_its_compound_file_byte_for_byte() {
        let mut ole = OLE2.to_vec();
        ole.extend((0..2000u32).map(|i| (i * 7) as u8));
        let mut data = vec![0x80, 0, 0x55, 0x01];
        data.extend_from_slice(&ole);
        let m = members(&dxf_with("OLE2FRAME", "2D", &data));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "ole2frame-2D.ole");
        assert_eq!(m[0].data, ole);
    }

    #[test]
    fn an_ole2frame_without_a_compound_file_yields_its_data() {
        let m = members(&dxf_with("OLE2FRAME", "2E", b"just some bytes"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "ole2frame-2E.bin");
        assert_eq!(m[0].data, b"just some bytes");
    }

    #[test]
    fn other_chunks_are_members_only_when_a_whole_file() {
        let m = members(&dxf_with("ACAD_PROXY_ENTITY", "40", b"PK\x03\x04zipped"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "acad_proxy_entity-40.zip");
        assert!(members(&dxf_with("ACAD_PROXY_ENTITY", "41", b"\x01\x02graphics")).is_empty());
    }

    #[test]
    fn bad_hex_in_an_ole2frame_is_reported() {
        let mut d = dxf_with("OLE2FRAME", "2F", b"abc");
        let at = d.windows(6).position(|w| w == b"616263").unwrap();
        d[at] = b'Z';
        let m = members(&d);
        assert_eq!(m.len(), 1);
        assert!(m[0].unsupported.is_some());
    }

    #[test]
    fn a_file_that_stops_making_sense_is_reported() {
        let mut d = b"0\nSECTION\n2\nENTITIES\n0\nLINE\nnot a code\n".to_vec();
        d.extend_from_slice(b"310\nD0CF\n0\nEOF\n");
        let m = members(&d);
        assert!(m.iter().any(|e| e.unsupported.is_some()), "{m:?}");
        // A file cut short is not.
        assert!(members(b"0\nSECTION\n2\nENTITIES\n0\nLINE\n8").is_empty());
    }
}
