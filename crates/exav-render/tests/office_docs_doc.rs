//! Word 97 documents built from their structures, converted.

#[path = "office_common/mod.rs"]
mod common;

use common::*;
use exav_render::docs::{convert, Error, Format, Limits};

fn bold(a: usize, b: usize) -> (usize, usize, Vec<u8>) {
    (a, b, vec![0x35, 0x08, 1])
}

fn sample() -> Vec<u8> {
    doc(
        &[
            Para {
                text: b"Plain bold words\r".to_vec(),
                // "bold" is characters 6 to 10.
                runs: vec![
                    bold(6, 10),
                    (11, 16, vec![0x43, 0x4A, 48, 0, 0x3E, 0x2A, 1]),
                ],
                // Centered, 360 twips of space after.
                grpprl: vec![0x61, 0x24, 1, 0x14, 0xA4, 0x68, 0x01],
            },
            Para {
                text: b"Second\x09tab and\x0Bbreak\r".to_vec(),
                runs: vec![],
                grpprl: vec![],
            },
        ],
        &Options::default(),
    )
}

#[test]
fn text_runs_and_paragraph_properties_come_through() {
    let c = convert(&sample(), Format::Doc, &Limits::default()).unwrap();
    assert_eq!(c.paragraphs, 2);
    let d = part(&c.docx, "word/document.xml");
    assert!(d.contains("<w:jc w:val=\"center\"/>"), "{d}");
    assert!(d.contains("<w:spacing w:after=\"360\"/>"), "{d}");
    // The bold run is "bold", the underlined 24 pt run "words".
    assert!(
        d.contains("<w:rPr><w:b/></w:rPr><w:t xml:space=\"preserve\">bold</w:t>"),
        "{d}"
    );
    assert!(
        d.contains("<w:rPr><w:sz w:val=\"48\"/><w:u w:val=\"single\"/></w:rPr><w:t xml:space=\"preserve\">words</w:t>"),
        "{d}"
    );
    assert!(d.contains(">Plain </w:t>"), "{d}");
    // A tab and a line break in the second paragraph.
    assert!(
        d.contains("Second</w:t><w:tab/><w:t xml:space=\"preserve\">tab and</w:t><w:br/><w:t xml:space=\"preserve\">break</w:t>"),
        "{d}"
    );
    // The default page, since the section has no properties of its own.
    assert!(d.contains("<w:pgSz w:w=\"12240\" w:h=\"15840\"/>"), "{d}");
}

#[test]
fn the_package_has_the_parts_a_reader_needs() {
    let c = convert(&sample(), Format::Doc, &Limits::default()).unwrap();
    for p in [
        "[Content_Types].xml",
        "_rels/.rels",
        "word/document.xml",
        "word/_rels/document.xml.rels",
        "word/styles.xml",
        "word/settings.xml",
    ] {
        assert!(has_part(&c.docx, p), "{p}");
    }
    let styles = part(&c.docx, "word/styles.xml");
    assert!(styles.contains("w:styleId=\"Normal\""));
}

#[test]
fn encrypted_and_old_files_are_refused_with_their_kinds() {
    let enc = doc(
        &[Para {
            text: b"x\r".to_vec(),
            runs: vec![],
            grpprl: vec![],
        }],
        &Options {
            encrypted: true,
            ..Options::default()
        },
    );
    assert_eq!(
        convert(&enc, Format::Doc, &Limits::default()).unwrap_err(),
        Error::Encrypted
    );
    let old = doc(
        &[Para {
            text: b"x\r".to_vec(),
            runs: vec![],
            grpprl: vec![],
        }],
        &Options {
            fib_version: 0x0065,
            ..Options::default()
        },
    );
    assert_eq!(
        convert(&old, Format::Doc, &Limits::default())
            .unwrap_err()
            .kind(),
        "unsupported"
    );
    assert_eq!(
        convert(b"not a compound file", Format::Doc, &Limits::default())
            .unwrap_err()
            .kind(),
        "not-format"
    );
}

#[test]
fn header_story_positions_at_the_end_of_the_range_are_ignored() {
    // Found by fuzzing: the first header story starts at 0xFFFFFFFF.
    let p = Para {
        text: b"x\r".to_vec(),
        runs: vec![],
        grpprl: vec![],
    };
    let d = doc(
        &[p],
        &Options {
            hdd: vec![0, 0, 0, 0, 0, 0, u32::MAX, u32::MAX],
            ..Options::default()
        },
    );
    let c = convert(&d, Format::Doc, &Limits::default()).unwrap();
    assert_eq!(c.paragraphs, 1);
}

#[test]
fn a_section_without_text_gives_its_headers_to_the_next() {
    let p = Para {
        text: b"body\r".to_vec(),
        runs: vec![],
        grpprl: vec![],
    };
    // The first section's default header (story 1) is "head\r" and the
    // extra paragraph mark every story ends with; the second has none.
    // Stories 0 to 5 are the note separators.
    let mut hdd = vec![0u32; 8];
    hdd.extend([6; 6]);
    hdd.extend([6; 7]);
    let d = doc(
        &[p],
        &Options {
            hdd,
            header: b"head\r\r".to_vec(),
            empty_first_section: true,
            ..Options::default()
        },
    );
    let c = convert(&d, Format::Doc, &Limits::default()).unwrap();
    assert!(part(&c.docx, "word/header1.xml").contains("head"));
    let b = part(&c.docx, "word/document.xml");
    assert_eq!(b.matches("<w:headerReference").count(), 1, "{b}");
}

#[test]
fn tracked_changes_are_drawn_as_marked_text() {
    let p = Para {
        text: b"gone new kept\r".to_vec(),
        // sprmCFRMarkDel on "gone", sprmCFRMark (inserted) on "new".
        runs: vec![(0, 4, vec![0x00, 0x08, 1]), (5, 8, vec![0x01, 0x08, 1])],
        grpprl: vec![],
    };
    let d = doc(&[p], &Options::default());
    let c = convert(&d, Format::Doc, &Limits::default()).unwrap();
    let b = part(&c.docx, "word/document.xml");
    assert!(
        b.contains("<w:color w:val=\"C00000\"/></w:rPr><w:t xml:space=\"preserve\">gone</w:t>")
            && b.contains("<w:strike/>"),
        "{b}"
    );
    assert!(
        b.contains("<w:u w:val=\"single\"/></w:rPr><w:t xml:space=\"preserve\">new</w:t>"),
        "{b}"
    );
    assert!(b.contains("<w:t xml:space=\"preserve\"> kept</w:t>"), "{b}");
}

fn sample6(six: &Six) -> Vec<u8> {
    doc6(
        &[
            Para {
                text: b"Plain bold words\r".to_vec(),
                // Bold on "bold" (sprmCFBold), 12 pt on "words" (sprmCHps).
                runs: vec![(6, 10, vec![85, 1]), (11, 16, vec![99, 24])],
                // Centered (sprmPJc), 360 twips of space after (sprmPDyaAfter).
                grpprl: vec![5, 1, 22, 0x68, 0x01],
            },
            Para {
                text: b"Second\x09tab and\x0Bbreak\r".to_vec(),
                // The first font of the table (sprmCFtc), whose name is Arial.
                runs: vec![(0, 6, vec![93, 0, 0])],
                grpprl: vec![],
            },
        ],
        six,
    )
}

#[test]
fn word_6_text_and_formatting_come_through() {
    let c = convert(&sample6(&Six::default()), Format::Doc, &Limits::default()).unwrap();
    assert_eq!(c.paragraphs, 2);
    let d = part(&c.docx, "word/document.xml");
    assert!(d.contains("<w:jc w:val=\"center\"/>"), "{d}");
    assert!(d.contains("<w:spacing w:after=\"360\"/>"), "{d}");
    assert!(
        d.contains("<w:rPr><w:b/></w:rPr><w:t xml:space=\"preserve\">bold</w:t>"),
        "{d}"
    );
    assert!(
        d.contains("<w:rPr><w:sz w:val=\"24\"/></w:rPr><w:t xml:space=\"preserve\">words</w:t>"),
        "{d}"
    );
    assert!(
        d.contains("<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr><w:t xml:space=\"preserve\">Second</w:t></w:r>"),
        "{d}"
    );
    assert!(
        d.contains("<w:tab/><w:t xml:space=\"preserve\">tab and</w:t><w:br/>"),
        "{d}"
    );
}

#[test]
fn word_6_headers_are_the_stories_the_section_says_it_has() {
    let six = Six {
        header: Some(b"head\r\r".to_vec()),
        ..Six::default()
    };
    let c = convert(&sample6(&six), Format::Doc, &Limits::default()).unwrap();
    assert!(part(&c.docx, "word/header1.xml").contains("head"));
    assert!(!part(&c.docx, "word/settings.xml").contains("evenAndOddHeaders"));
    // The document's facing pages setting is the file's.
    let six = Six {
        facing: true,
        ..six
    };
    let c = convert(&sample6(&six), Format::Doc, &Limits::default()).unwrap();
    assert!(part(&c.docx, "word/settings.xml").contains("evenAndOddHeaders"));
}

#[test]
fn a_word_6_picture_is_its_metafile_at_the_size_its_header_gives() {
    // The picture character, with sprmCPicLocation to the PIC at 0x600: a
    // 58-byte header (mm 8 or the TIFF file name's 98, 1440 x 720 twips,
    // scaled to `scale` of a thousand) and a metafile.
    let wmf = [1u8, 0, 9, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let with = |mm: u16, scale: u16| {
        let mut pic = vec![0u8; 58];
        pic[..4].copy_from_slice(&(58 + wmf.len() as u32).to_le_bytes());
        pic[4..6].copy_from_slice(&58u16.to_le_bytes());
        pic[6..8].copy_from_slice(&mm.to_le_bytes());
        pic[28..30].copy_from_slice(&1440u16.to_le_bytes());
        pic[30..32].copy_from_slice(&720u16.to_le_bytes());
        pic[32..34].copy_from_slice(&scale.to_le_bytes());
        pic[34..36].copy_from_slice(&scale.to_le_bytes());
        pic.extend_from_slice(&wmf);
        let p = Para {
            text: b"a\x01b\r".to_vec(),
            runs: vec![(1, 2, vec![68, 4, 0x00, 0x06, 0, 0])],
            grpprl: vec![],
        };
        let six = Six {
            extra: vec![(0x600, pic)],
            ..Six::default()
        };
        convert(&doc6(&[p], &six), Format::Doc, &Limits::default()).unwrap()
    };
    let c = with(8, 1000);
    assert!(has_part(&c.docx, "word/media/image1.wmf"));
    let b = part(&c.docx, "word/document.xml");
    assert!(
        b.contains("<wp:extent cx=\"914400\" cy=\"457200\"/>"),
        "{b}"
    );
    // At half the size.
    let b = part(&with(8, 500).docx, "word/document.xml");
    assert!(
        b.contains("<wp:extent cx=\"457200\" cy=\"228600\"/>"),
        "{b}"
    );
    // A TIFF file's name is no picture.
    assert!(!has_part(&with(98, 1000).docx, "word/media/image1.wmf"));
}

#[test]
fn story_lengths_that_add_up_past_what_a_position_holds_are_cut() {
    // Found by fuzzing: footnote, annotation and endnote stories of 2^31 - 1
    // characters and a macro story of 2^32 - 1 overflowed the base of the
    // endnote text.
    let big = |v: u32| v.to_le_bytes().to_vec();
    let six = Six {
        extra: vec![
            (56, big(0x7FFF_FFFF)),
            (64, big(u32::MAX)),
            (68, big(0x7FFF_FFFF)),
            (72, big(0x7FFF_FFFF)),
        ],
        ..Six::default()
    };
    let _ = convert(&sample6(&six), Format::Doc, &Limits::default());
}

#[test]
fn word_6_files_that_are_encrypted_or_damaged_are_told_so() {
    let six = Six {
        flags: 0x0100,
        ..Six::default()
    };
    let e = convert(&sample6(&six), Format::Doc, &Limits::default()).unwrap_err();
    assert_eq!(e, Error::Encrypted);
    let six = Six {
        header: Some(b"head\r\r".to_vec()),
        ..Six::default()
    };
    let d = sample6(&six);
    for cut in [100usize, 600, 1500, 3000] {
        let _ = convert(&d[..cut.min(d.len())], Format::Doc, &Limits::default());
    }
    let mut m = d.clone();
    for i in (0..m.len()).step_by(7) {
        let was = m[i];
        m[i] ^= 0xFF;
        let _ = convert(&m, Format::Doc, &Limits::default());
        m[i] = was;
    }
}

#[test]
fn check_boxes_show_their_state_from_the_form_field_data() {
    // Two FORMCHECKBOX fields; the begin mark of each has sprmCFData and
    // sprmCPicLocation to an FFData in the data stream: version, then the
    // bits (type 1, state 1 or 0).
    let field = |at: u32| {
        let mut g = vec![0x06, 0x08, 1, 0x03, 0x6A];
        g.extend_from_slice(&at.to_le_bytes());
        g
    };
    // A checked and an unchecked check box, then a text box (type 0) whose
    // state bits say 1, then a check box begin mark that has the location
    // but not the data flag.
    let mut data = vec![];
    for (kind, state) in [(1u16, 1u16), (1, 0), (0, 1)] {
        data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        data.extend_from_slice(&(kind | state << 2).to_le_bytes());
        data.extend_from_slice(&[0; 10]);
    }
    let unit = b"\x13 FORMCHECKBOX \x15 ";
    let mut text = unit.repeat(4);
    text.push(b'\r');
    let p = Para {
        text,
        runs: vec![
            (0, 1, field(0)),
            (17, 18, field(16)),
            (34, 35, field(32)),
            (51, 52, vec![0x03, 0x6A, 0, 0, 0, 0]),
        ],
        grpprl: vec![],
    };
    let d = doc(
        &[p],
        &Options {
            data,
            ..Options::default()
        },
    );
    let c = convert(&d, Format::Doc, &Limits::default()).unwrap();
    let b = part(&c.docx, "word/document.xml");
    assert!(
        b.matches('\u{2612}').count() == 1 && b.matches('\u{2610}').count() == 3,
        "{b}"
    );
    assert!(b.find('\u{2612}') < b.find('\u{2610}'), "{b}");
}

#[test]
fn cells_of_a_table_whose_row_never_ends_are_paragraphs() {
    // sprmPFInTable on three paragraphs, the second ending a cell, and no
    // row mark: a table with no row is not a table (a DOCX needs a row in
    // it), the text stays, in order.
    let p = |t: &[u8]| Para {
        text: t.to_vec(),
        runs: vec![],
        grpprl: vec![0x16, 0x24, 1],
    };
    let d = doc(
        &[p(b"one\x07"), p(b"two\r"), p(b"three\r")],
        &Options::default(),
    );
    let c = convert(&d, Format::Doc, &Limits::default()).unwrap();
    let b = part(&c.docx, "word/document.xml");
    assert!(!b.contains("<w:tbl>"), "{b}");
    let at = |s: &str| b.find(s).unwrap_or_else(|| panic!("{s}: {b}"));
    assert!(
        at(">one<") < at(">two<") && at(">two<") < at(">three<"),
        "{b}"
    );
}

#[test]
fn table_depth_is_bounded() {
    // Found by fuzzing: sprmPTableDepth (a four-byte operand) of 2^31
    // opened that many table builders.
    let p = Para {
        text: b"x\r".to_vec(),
        runs: vec![],
        grpprl: vec![0x49, 0x66, 0, 0, 0, 0x80],
    };
    let d = doc(&[p], &Options::default());
    let c = convert(
        &d,
        Format::Doc,
        &Limits::default().with_max_memory(64 << 20),
    )
    .unwrap();
    // Word nests tables 15 deep; the reader stops at 63.
    let tables = part(&c.docx, "word/document.xml")
        .matches("<w:tbl>")
        .count();
    assert!(tables <= 63, "{tables}");
    assert!(part(&c.docx, "word/document.xml").contains(">x</w:t>"));
}

#[test]
fn damaged_files_fail_without_panicking() {
    let d = sample();
    for cut in [0, 100, 512, 1500, 3000, d.len() / 2] {
        let _ = convert(&d[..cut.min(d.len())], Format::Doc, &Limits::default());
    }
    // Every byte of the file flipped in turn: an answer, never a panic.
    let mut m = d.clone();
    for i in (0..m.len()).step_by(37) {
        let was = m[i];
        m[i] ^= 0xFF;
        let _ = convert(&m, Format::Doc, &Limits::default());
        m[i] = was;
    }
}

#[test]
fn the_limits_bound_the_conversion() {
    let d = sample();
    let e = convert(&d, Format::Doc, &Limits::default().with_max_paragraphs(1)).unwrap_err();
    assert_eq!(e, Error::TooLarge("paragraphs"));
    let e = convert(&d, Format::Doc, &Limits::default().with_max_memory(100)).unwrap_err();
    assert_eq!(e.kind(), "too-large");
    let mut small = Limits::default();
    small.max_input = 10;
    assert_eq!(
        convert(&d, Format::Doc, &small).unwrap_err(),
        Error::TooLarge("input")
    );
}
