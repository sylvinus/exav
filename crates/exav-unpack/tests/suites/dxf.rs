//! DXF as a container: the files a drawing embeds, and nothing else.
//!
//! The compound files are written by the `cfb` crate, an implementation
//! independent of exav's OLE reader, and the drawings around them are built
//! here as AutoCAD lays out an OLE2FRAME (DXF reference, OLE2FRAME: the data
//! in 310 chunks of up to 127 bytes). The real drawings in `fixtures/dxf/`
//! were written by ezdxf (`exav-render/tests/fixtures/cad/make.py`) and saved
//! by the ODA File Converter; they embed nothing.

#![cfg(feature = "dxf")]

use std::io::{Read, Write};

use exav_unpack::{detect, extract, Budget, Entry, Format, Limits};

fn members(data: &[u8]) -> Vec<Entry> {
    let mut budget = Budget::new(Limits::default());
    extract(Format::Dxf, &data, &mut budget).expect("extracts")
}

/// A compound file with one stream, as `cfb` writes it.
fn compound_file(stream: &[u8]) -> Vec<u8> {
    let mut doc = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    doc.create_stream("/payload")
        .unwrap()
        .write_all(stream)
        .unwrap();
    doc.flush().unwrap();
    doc.into_inner().into_inner()
}

/// What an OLE2FRAME's chunks hold: a header of AutoCAD's, then the object.
fn frame_data(object: &[u8]) -> Vec<u8> {
    let mut data = vec![0x80, 0x00, 0x55, 0x01, 0x00, 0x00, 0x00, 0x00];
    data.extend_from_slice(object);
    data
}

fn ascii_drawing(handle: &str, data: &[u8]) -> Vec<u8> {
    let mut s = String::from("  0\r\nSECTION\r\n  2\r\nENTITIES\r\n");
    s.push_str(&format!(
        "  0\r\nOLE2FRAME\r\n  5\r\n{handle}\r\n100\r\nAcDbEntity\r\n  8\r\n0\r\n\
         100\r\nAcDbOle2Frame\r\n 70\r\n2\r\n  3\r\nPackage\r\n 10\r\n0.0\r\n 20\r\n1.0\r\n\
         30\r\n0.0\r\n 11\r\n1.0\r\n 21\r\n0.0\r\n 31\r\n0.0\r\n 71\r\n2\r\n 72\r\n0\r\n\
         90\r\n{}\r\n",
        data.len()
    ));
    for line in data.chunks(127) {
        let hex: String = line.iter().map(|b| format!("{b:02X}")).collect();
        s.push_str(&format!("310\r\n{hex}\r\n"));
    }
    s.push_str("  1\r\nOLE\r\n  0\r\nENDSEC\r\n  0\r\nEOF\r\n");
    s.into_bytes()
}

fn binary_drawing(handle: &str, data: &[u8]) -> Vec<u8> {
    let mut b = exav_unpack::dxf::BINARY_SENTINEL.to_vec();
    let text = |b: &mut Vec<u8>, code: i16, s: &str| {
        b.extend_from_slice(&code.to_le_bytes());
        b.extend_from_slice(s.as_bytes());
        b.push(0);
    };
    text(&mut b, 0, "SECTION");
    text(&mut b, 2, "ENTITIES");
    text(&mut b, 0, "OLE2FRAME");
    text(&mut b, 5, handle);
    text(&mut b, 100, "AcDbEntity");
    text(&mut b, 8, "0");
    text(&mut b, 100, "AcDbOle2Frame");
    b.extend_from_slice(&90i16.to_le_bytes());
    b.extend_from_slice(&(data.len() as i32).to_le_bytes());
    for chunk in data.chunks(127) {
        b.extend_from_slice(&310i16.to_le_bytes());
        b.push(chunk.len() as u8);
        b.extend_from_slice(chunk);
    }
    text(&mut b, 1, "OLE");
    text(&mut b, 0, "ENDSEC");
    text(&mut b, 0, "EOF");
    b
}

fn gunzip(gz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .expect("a gzip fixture");
    out
}

macro_rules! fixture {
    ($name:literal) => {
        gunzip(include_bytes!(concat!("../fixtures/dxf/", $name)))
    };
}

#[test]
fn an_ole2frame_yields_its_compound_file_byte_for_byte() {
    let ole = compound_file(&vec![0x42u8; 5000]);
    for drawing in [
        ascii_drawing("2D", &frame_data(&ole)),
        binary_drawing("2D", &frame_data(&ole)),
    ] {
        assert_eq!(detect(&drawing), Some(Format::Dxf));
        let m = members(&drawing);
        assert_eq!(
            m.len(),
            1,
            "{:?}",
            m.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        assert_eq!(m[0].name, "ole2frame-2D.ole");
        assert!(m[0].unsupported.is_none());
        assert!(m[0].data == ole, "the compound file, byte for byte");
        // And it is one: the extracted member opens as OLE.
        assert_eq!(detect(&m[0].data), Some(Format::Ole));
    }
}

#[test]
fn a_drawing_that_embeds_nothing_has_no_member() {
    for (name, data) in [
        ("ascii R12", fixture!("ascii-R12.dxf.gz")),
        ("ascii 2018", fixture!("ascii-R2018.dxf.gz")),
        ("binary R12", fixture!("binary-R12.dxf.gz")),
        ("binary 2018", fixture!("binary-R2018.dxf.gz")),
    ] {
        assert_eq!(detect(&data), Some(Format::Dxf), "{name}");
        let m = members(&data);
        assert!(
            m.is_empty(),
            "{name}: {:?}",
            m.iter()
                .map(|e| (&e.name, e.unsupported))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn records_and_strings_read_from_a_real_drawing() {
    use exav_unpack::dxf::{Decoder, Records};
    for data in [
        fixture!("ascii-R2018.dxf.gz"),
        fixture!("binary-R2018.dxf.gz"),
    ] {
        let mut records = Records::new(&data);
        let mut layers = Vec::new();
        let mut eof = false;
        while let Some(rec) = records.next() {
            if rec.is("EOF") {
                eof = true;
            }
            if rec.is("LAYER") {
                let name = rec.tags.iter().find(|t| t.code == 2).expect("a name");
                layers.push(Decoder::UTF8.decode(name.bytes()));
            }
        }
        assert!(eof && records.stop().is_none());
        // The layers make.py adds, among the converter's own.
        for want in ["WALLS", "GLASS", "HIDDEN_OFF", "FROZEN"] {
            assert!(layers.iter().any(|l| l == want), "{want} in {layers:?}");
        }
    }
}

#[test]
fn a_damaged_drawing_never_panics() {
    let ole = compound_file(b"some stream");
    let base = binary_drawing("2E", &frame_data(&ole));
    let ascii = ascii_drawing("2E", &frame_data(&ole));
    for data in [base, ascii, fixture!("binary-R2018.dxf.gz")] {
        for cut in (0..data.len()).step_by((data.len() / 300).max(1)) {
            let mut budget = Budget::new(Limits::default());
            let _ = extract(Format::Dxf, &&data[..cut], &mut budget);
        }
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..100 {
            let mut b = data.clone();
            for _ in 0..6 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let i = (state as usize) % b.len();
                b[i] ^= 1 << (state >> 61);
            }
            let mut budget = Budget::new(Limits::default());
            let _ = extract(Format::Dxf, &b, &mut budget);
        }
    }
}
