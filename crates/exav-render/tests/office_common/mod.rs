//! Helpers of the integration tests: a DOCX read back, and a Word 97 file
//! written from its structures.

// Each test crate uses some of these.
#![allow(dead_code)]

use exav_render::formats::office::test_util::build_cfb as cfb;
use exav_render::formats::office::test_util::Zip;

/// A part of a DOCX.
pub fn part(docx: &[u8], name: &str) -> String {
    let mut z = Zip::open(docx).expect("a ZIP package");
    let d = z.read(name, 1 << 28).expect("readable").unwrap_or_default();
    String::from_utf8(d).expect("UTF-8")
}

pub fn has_part(docx: &[u8], name: &str) -> bool {
    Zip::open(docx)
        .expect("a ZIP package")
        .names()
        .iter()
        .any(|n| n == name)
}

fn put16(v: &mut [u8], at: usize, x: u16) {
    v[at..at + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}

/// One paragraph: its text (8-bit, ending with the paragraph mark), the
/// character runs (start, end, grpprl) and the paragraph's grpprl.
pub struct Para {
    pub text: Vec<u8>,
    pub runs: Vec<(usize, usize, Vec<u8>)>,
    pub grpprl: Vec<u8>,
}

/// A Word 97 document of paragraphs, as the file a writer would make: FIB,
/// piece table with one compressed piece, one character and one paragraph
/// FKP, a stylesheet with no styles, one font and one section.
pub struct Options {
    pub encrypted: bool,
    pub fib_version: u16,
    /// The character positions of the header story table (PlcfHdd).
    pub hdd: Vec<u32>,
    /// Text of the header stories, after the main text.
    pub header: Vec<u8>,
    /// A first section of no text, then the section of the paragraphs.
    pub empty_first_section: bool,
    /// The `Data` stream, when not empty.
    pub data: Vec<u8>,
    /// The text of each footnote, ending with its paragraph mark, and the
    /// character positions in the main text of the marks that refer to them.
    pub footnotes: Vec<Vec<u8>>,
    pub footnote_refs: Vec<u32>,
    /// The same for comments.
    pub comments: Vec<Vec<u8>>,
    pub comment_refs: Vec<u32>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            encrypted: false,
            fib_version: 0x00C1,
            hdd: vec![],
            header: vec![],
            empty_first_section: false,
            data: vec![],
            footnotes: vec![],
            footnote_refs: vec![],
            comments: vec![],
            comment_refs: vec![],
        }
    }
}

pub fn doc(paras: &[Para], opt: &Options) -> Vec<u8> {
    const TEXT_AT: usize = 0x400;
    let mut text = vec![];
    let mut starts = vec![];
    for p in paras {
        starts.push(text.len());
        text.extend_from_slice(&p.text);
    }
    let n = text.len();
    // The footnotes, the header stories and the comments follow the main text,
    // in that order.
    let ftn = opt.footnotes.concat();
    let atn = opt.comments.concat();
    text.extend_from_slice(&ftn);
    text.extend_from_slice(&opt.header);
    text.extend_from_slice(&atn);
    let total = text.len();
    // WordDocument: FIB, text, character FKP, paragraph FKP.
    let mut wd = vec![0u8; 0x1000];
    wd[TEXT_AT..TEXT_AT + total].copy_from_slice(&text);
    // The character FKP is page 4 (0x800), the paragraph FKP page 5 (0xA00).
    let chpx_pn = (0x800 / 512) as u32;
    let papx_pn = (0xA00 / 512) as u32;
    // Character runs, with gaps filled by runs without properties.
    let mut edges = vec![0usize];
    let mut props: Vec<Vec<u8>> = vec![];
    let mut cur = 0usize;
    let mut all: Vec<(usize, usize, Vec<u8>)> = vec![];
    for (p, s) in paras.iter().zip(&starts) {
        for (a, b, g) in &p.runs {
            all.push((s + a, s + b, g.clone()));
        }
    }
    all.sort_by_key(|r| r.0);
    for (a, b, g) in all {
        if a > cur {
            edges.push(a);
            props.push(vec![]);
        }
        edges.push(b);
        props.push(g);
        cur = b;
    }
    if cur < n {
        edges.push(n);
        props.push(vec![]);
    }
    let crun = props.len();
    let page = 0x800;
    for (i, e) in edges.iter().enumerate() {
        put32(&mut wd, page + 4 * i, (TEXT_AT + e) as u32);
    }
    let mut tail = page + 4 * (crun + 1) + crun;
    for (i, g) in props.iter().enumerate() {
        if g.is_empty() {
            wd[page + 4 * (crun + 1) + i] = 0;
            continue;
        }
        if tail % 2 == 1 {
            tail += 1;
        }
        wd[page + 4 * (crun + 1) + i] = ((tail - page) / 2) as u8;
        wd[tail] = g.len() as u8;
        wd[tail + 1..tail + 1 + g.len()].copy_from_slice(g);
        tail += 1 + g.len();
    }
    wd[page + 511] = crun as u8;
    // Paragraph FKP.
    let page = 0xA00;
    let cpara = paras.len();
    for (i, s) in starts.iter().enumerate() {
        put32(&mut wd, page + 4 * i, (TEXT_AT + s) as u32);
    }
    put32(&mut wd, page + 4 * cpara, (TEXT_AT + n) as u32);
    let mut tail = page + 4 * (cpara + 1) + 13 * cpara;
    for (i, p) in paras.iter().enumerate() {
        if tail % 2 == 1 {
            tail += 1;
        }
        // istd 0 and the modifiers, to an even size.
        let mut body = vec![0u8, 0];
        body.extend_from_slice(&p.grpprl);
        if body.len() % 2 == 0 {
            body.push(0);
        }
        wd[page + 4 * (cpara + 1) + 13 * i] = ((tail - page) / 2) as u8;
        wd[tail] = body.len().div_ceil(2) as u8;
        wd[tail + 1..tail + 1 + body.len()].copy_from_slice(&body);
        tail += 1 + body.len();
    }
    wd[page + 511] = cpara as u8;

    // Table stream.
    let mut tbl: Vec<u8> = vec![];
    let place = |data: &[u8], tbl: &mut Vec<u8>| -> (u32, u32) {
        let at = tbl.len();
        tbl.extend_from_slice(data);
        (at as u32, data.len() as u32)
    };
    // Piece table.
    let mut plc = vec![];
    for cp in [0u32, total as u32] {
        plc.extend_from_slice(&cp.to_le_bytes());
    }
    plc.extend_from_slice(&[0, 0]);
    plc.extend_from_slice(&(((TEXT_AT as u32) * 2) | 0x4000_0000).to_le_bytes());
    plc.extend_from_slice(&[0, 0]);
    let mut clx = vec![2u8];
    clx.extend_from_slice(&(plc.len() as u32).to_le_bytes());
    clx.extend_from_slice(&plc);
    let clx_at = place(&clx, &mut tbl);
    let bte = |fkp_pn: u32| {
        let mut v = vec![];
        for fc in [TEXT_AT as u32, (TEXT_AT + n) as u32] {
            v.extend_from_slice(&fc.to_le_bytes());
        }
        v.extend_from_slice(&fkp_pn.to_le_bytes());
        v
    };
    let chpx_at = place(&bte(chpx_pn), &mut tbl);
    let papx_at = place(&bte(papx_pn), &mut tbl);
    // A stylesheet: 18 bytes of general information, no styles.
    let mut stsh = vec![];
    let mut stshi = vec![0u8; 18];
    put16(&mut stshi, 2, 10);
    stsh.extend_from_slice(&18u16.to_le_bytes());
    stsh.extend_from_slice(&stshi);
    let stsh_at = place(&stsh, &mut tbl);
    // One font: cData, cbExtra, then the FFN.
    let name: Vec<u8> = "Arial\0"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let mut ffn = vec![(39 + name.len()) as u8];
    ffn.extend_from_slice(&[0u8; 39]);
    ffn.extend_from_slice(&name);
    let mut fonts = vec![1, 0, 0, 0];
    fonts.extend_from_slice(&ffn);
    let fonts_at = place(&fonts, &mut tbl);
    // One section with no properties, or two when the first has no text.
    let mut sed = vec![];
    let cps: &[u32] = if opt.empty_first_section {
        &[0, 0, n as u32]
    } else {
        &[0, n as u32]
    };
    for cp in cps {
        sed.extend_from_slice(&cp.to_le_bytes());
    }
    for _ in 1..cps.len() {
        sed.extend_from_slice(&[0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
    }
    let sed_at = place(&sed, &mut tbl);

    // The FIB.
    put16(&mut wd, 0, 0xA5EC);
    put16(&mut wd, 2, opt.fib_version);
    let flags = 0x0200 | if opt.encrypted { 0x0100 } else { 0 };
    put16(&mut wd, 10, flags);
    put16(&mut wd, 32, 14);
    put16(&mut wd, 62, 22);
    put32(&mut wd, 64 + 12, n as u32);
    put16(&mut wd, 152, 93);
    let pair = |i: usize, v: (u32, u32), wd: &mut Vec<u8>| {
        put32(wd, 154 + 8 * i, v.0);
        put32(wd, 154 + 8 * i + 4, v.1);
    };
    pair(1, stsh_at, &mut wd);
    pair(6, sed_at, &mut wd);
    pair(12, chpx_at, &mut wd);
    pair(13, papx_at, &mut wd);
    pair(15, fonts_at, &mut wd);
    pair(33, clx_at, &mut wd);
    if let Some(&last) = opt.hdd.last() {
        let plc: Vec<u8> = opt.hdd.iter().flat_map(|c| c.to_le_bytes()).collect();
        let at = tbl.len() as u32;
        tbl.extend_from_slice(&plc);
        pair(11, (at, plc.len() as u32), &mut wd);
        put32(&mut wd, 64 + 20, last);
    }
    // Footnotes (pairs 2 and 3) and comments (4 and 5): the marks' positions
    // and a record each, and the positions of the texts in their story.
    let ends = |stories: &[Vec<u8>]| -> Vec<u8> {
        let mut at = 0u32;
        let mut v = vec![0u8; 4];
        for s in stories {
            at += s.len() as u32;
            v.extend_from_slice(&at.to_le_bytes());
        }
        v
    };
    for (refs, stories, size, first) in [
        (&opt.footnote_refs, &opt.footnotes, 2usize, 2usize),
        (&opt.comment_refs, &opt.comments, 30, 4),
    ] {
        if stories.is_empty() {
            continue;
        }
        let mut plc: Vec<u8> = refs
            .iter()
            .copied()
            .chain([n as u32])
            .flat_map(u32::to_le_bytes)
            .collect();
        plc.extend(std::iter::repeat_n(0u8, size * refs.len()));
        let at = tbl.len() as u32;
        tbl.extend_from_slice(&plc);
        pair(first, (at, plc.len() as u32), &mut wd);
        let txt = ends(stories);
        let at = tbl.len() as u32;
        tbl.extend_from_slice(&txt);
        pair(first + 1, (at, txt.len() as u32), &mut wd);
    }
    put32(&mut wd, 64 + 16, ftn.len() as u32);
    put32(&mut wd, 64 + 28, atn.len() as u32);
    if opt.data.is_empty() {
        cfb(&[("WordDocument", &wd), ("1Table", &tbl)])
    } else {
        cfb(&[("WordDocument", &wd), ("1Table", &tbl), ("Data", &opt.data)])
    }
}

/// What a Word 6 document has besides its paragraphs.
#[derive(Default)]
pub struct Six {
    /// The text of one default header, with its extra paragraph mark.
    pub header: Option<Vec<u8>>,
    /// The FIB's flags.
    pub flags: u16,
    /// Bytes to put in the stream, such as a picture, by offset.
    pub extra: Vec<(usize, Vec<u8>)>,
    /// Facing pages (the document properties).
    pub facing: bool,
}

/// A Word 6 document of paragraphs: one stream with the FIB, the text, a
/// character and a paragraph FKP, and the tables behind them, with the
/// modifiers in Word 6's form (one-byte opcodes).
pub fn doc6(paras: &[Para], six: &Six) -> Vec<u8> {
    let (header, flags, extra) = (six.header.as_deref(), six.flags, &six.extra);
    const TEXT_AT: usize = 0x400;
    let mut text = vec![];
    let mut starts = vec![];
    for p in paras {
        starts.push(text.len());
        text.extend_from_slice(&p.text);
    }
    let n = text.len();
    if let Some(h) = header {
        text.extend_from_slice(h);
    }
    let mut wd = vec![0u8; 0x1000];
    wd[TEXT_AT..TEXT_AT + text.len()].copy_from_slice(&text);
    for (at, bytes) in extra {
        wd[*at..*at + bytes.len()].copy_from_slice(bytes);
    }
    // Character runs, with the gaps between them filled.
    let mut all: Vec<(usize, usize, Vec<u8>)> = vec![];
    for (p, s) in paras.iter().zip(&starts) {
        for (a, b, g) in &p.runs {
            all.push((s + a, s + b, g.clone()));
        }
    }
    all.sort_by_key(|r| r.0);
    let (mut edges, mut props, mut cur) = (vec![0usize], vec![] as Vec<Vec<u8>>, 0usize);
    for (a, b, g) in all {
        if a > cur {
            edges.push(a);
            props.push(vec![]);
        }
        edges.push(b);
        props.push(g);
        cur = b;
    }
    if cur < n {
        edges.push(n);
        props.push(vec![]);
    }
    let page = 0x800;
    let crun = props.len();
    for (i, e) in edges.iter().enumerate() {
        put32(&mut wd, page + 4 * i, (TEXT_AT + e) as u32);
    }
    let mut tail = page + 4 * (crun + 1) + crun;
    for (i, g) in props.iter().enumerate() {
        if g.is_empty() {
            continue;
        }
        tail += tail % 2;
        wd[page + 4 * (crun + 1) + i] = ((tail - page) / 2) as u8;
        wd[tail] = g.len() as u8;
        wd[tail + 1..tail + 1 + g.len()].copy_from_slice(g);
        tail += 1 + g.len();
    }
    wd[page + 511] = crun as u8;
    // Paragraphs: seven-byte entries; the PAPX is a count of words, the
    // style code and the modifiers.
    let page = 0xA00;
    let cpara = paras.len();
    for (i, s) in starts.iter().enumerate() {
        put32(&mut wd, page + 4 * i, (TEXT_AT + s) as u32);
    }
    put32(&mut wd, page + 4 * cpara, (TEXT_AT + n) as u32);
    let mut tail = page + 4 * (cpara + 1) + 7 * cpara;
    for (i, p) in paras.iter().enumerate() {
        tail += tail % 2;
        let mut body = vec![0u8, 0];
        body.extend_from_slice(&p.grpprl);
        if body.len() % 2 == 0 {
            body.push(0);
        }
        wd[page + 4 * (cpara + 1) + 7 * i] = ((tail - page) / 2) as u8;
        wd[tail] = body.len().div_ceil(2) as u8;
        wd[tail + 1..tail + 1 + body.len()].copy_from_slice(&body);
        tail += 1 + body.len();
    }
    wd[page + 511] = cpara as u8;

    // The tables, after the pages.
    let mut at = 0xC00usize;
    let mut place = |data: &[u8], wd: &mut Vec<u8>| -> (u32, u32) {
        let o = at;
        if wd.len() < o + data.len() {
            wd.resize(o + data.len(), 0);
        }
        wd[o..o + data.len()].copy_from_slice(data);
        at += data.len() + data.len() % 2;
        (o as u32, data.len() as u32)
    };
    let bte = |pn: u16| {
        let mut v = vec![];
        for fc in [TEXT_AT as u32, (TEXT_AT + n) as u32] {
            v.extend_from_slice(&fc.to_le_bytes());
        }
        v.extend_from_slice(&pn.to_le_bytes());
        v
    };
    let chpx_at = place(&bte(4), &mut wd);
    let papx_at = place(&bte(5), &mut wd);
    // The stylesheet: 14 bytes of general information, one paragraph style
    // "Normal" with an empty paragraph and character UPX.
    let mut stshi = vec![0u8; 14];
    stshi[0] = 1;
    stshi[2] = 8;
    let mut std = vec![0u8; 8];
    std[0..2].copy_from_slice(&0x1000u16.to_le_bytes());
    std[2..4].copy_from_slice(&(0x0FFFu16 | 2 << 12).to_le_bytes());
    std.extend_from_slice(&[6, b'N', b'o', b'r', b'm', b'a', b'l', 0]);
    std.extend_from_slice(&2u16.to_le_bytes());
    std.extend_from_slice(&[0, 0]);
    std.extend_from_slice(&0u16.to_le_bytes());
    let mut stsh = (stshi.len() as u16).to_le_bytes().to_vec();
    stsh.extend_from_slice(&stshi);
    stsh.extend_from_slice(&(std.len() as u16).to_le_bytes());
    stsh.extend_from_slice(&std);
    let stsh_at = place(&stsh, &mut wd);
    // One font, its table starting with its own size.
    let mut ffn = vec![5 + 6, 0x16, 0x90, 0x01, 0, 0];
    ffn.extend_from_slice(b"Arial\0");
    let mut fonts = ((ffn.len() + 2) as u16).to_le_bytes().to_vec();
    fonts.extend_from_slice(&ffn);
    let fonts_at = place(&fonts, &mut wd);
    // One section; and a header story's text, when there is one.
    let mut sed = vec![];
    for cp in [0u32, n as u32] {
        sed.extend_from_slice(&cp.to_le_bytes());
    }
    sed.extend_from_slice(&[0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
    let sed_at = place(&sed, &mut wd);
    let mut dop = [0u8; 84];
    dop[0] = u8::from(six.facing);
    let dop_at = place(&dop, &mut wd);
    if let Some(h) = header {
        // The header's section bits: an odd-page (default) header.
        let sepx = [1u8 + 1, 153, 0x40];
        let sepx_at = place(&sepx, &mut wd);
        let sed_fc = sepx_at.0.to_le_bytes();
        let sed_pos = sed_at.0 as usize + 8 + 2;
        wd[sed_pos..sed_pos + 4].copy_from_slice(&sed_fc);
        let hdd: Vec<u8> = [0u32, h.len() as u32]
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let hdd_at = place(&hdd, &mut wd);
        put32(&mut wd, 176, hdd_at.0);
        put32(&mut wd, 180, hdd_at.1);
        put32(&mut wd, 60, h.len() as u32);
    }
    put16(&mut wd, 0, 0xA5DC);
    put16(&mut wd, 2, 101);
    put16(&mut wd, 10, flags);
    put32(&mut wd, 24, TEXT_AT as u32);
    put32(&mut wd, 28, (TEXT_AT + text.len()) as u32);
    put32(&mut wd, 52, n as u32);
    for (pos, v) in [
        (96, stsh_at),
        (136, sed_at),
        (184, chpx_at),
        (192, papx_at),
        (208, fonts_at),
        (336, dop_at),
    ] {
        put32(&mut wd, pos, v.0);
        put32(&mut wd, pos + 4, v.1);
    }
    cfb(&[("WordDocument", &wd)])
}
