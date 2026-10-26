//! Word 6 and Word 95 documents (nFib 101 and 104): the compound file of
//! Word 97, but with one `WordDocument` stream that holds the tables too,
//! 8-bit text, one-byte modifier opcodes and FKP entries of other sizes. The
//! modifiers are translated to Word 97's here, so that the rest of the reader
//! knows nothing of the old form.

use super::fib::{self, Clx, Fib, Piece};
use super::props::ico;
use super::styles::{Std, Stsh};
use super::{read_plc, Reader, Run, SectionSpan};
use crate::formats::office::common::bytes::{u16_at, u32_at};
use crate::formats::office::common::image;
use crate::formats::office::docs::error::{Error, Result};
use crate::formats::office::docs::limits::Budget;
use crate::formats::office::docs::model::*;

/// Positions of the (fc, lcb) pairs in the FIB.
mod at {
    pub const STSHF: usize = 96;
    pub const FND_REF: usize = 104;
    pub const FND_TXT: usize = 112;
    pub const SED: usize = 136;
    pub const HDD: usize = 176;
    pub const BTE_CHPX: usize = 184;
    pub const BTE_PAPX: usize = 192;
    pub const FFN: usize = 208;
    pub const BKMK: usize = 256;
    pub const BKF: usize = 264;
    pub const BKL: usize = 272;
    pub const DOP: usize = 336;
    pub const CLX: usize = 352;
    pub const END_REF: usize = 466;
    pub const END_TXT: usize = 474;
}

/// The (offset, size) of a structure of the main stream, by its place in the FIB.
fn pair(wd: &[u8], pos: usize) -> (usize, usize) {
    (u32_at(wd, pos) as usize, u32_at(wd, pos + 4) as usize)
}

fn part(wd: &[u8], pos: usize) -> &[u8] {
    let (o, l) = pair(wd, pos);
    wd.get(o..o.saturating_add(l).min(wd.len())).unwrap_or(&[])
}

/// How a modifier's operand is sized.
enum Size {
    /// This many bytes.
    Fixed(usize),
    /// A length byte, then that many.
    Counted,
    /// Two bytes of length (the operand's size plus one), then the operand.
    Long,
}

fn size(op: u8) -> Option<Size> {
    use Size::*;
    Some(match op {
        4..=11
        | 13
        | 14
        | 24
        | 25
        | 29
        | 37
        | 44
        | 50
        | 51
        | 65
        | 66
        | 67
        | 71
        | 75
        | 85..=92
        | 94
        | 98..=102
        | 104
        | 117..=119
        | 131
        | 132
        | 138
        | 139
        | 142
        | 143
        | 146
        | 147
        | 150..=153
        | 158
        | 159
        | 162
        | 185
        | 186 => Fixed(1),
        2
        | 16..=19
        | 21
        | 22
        | 26..=28
        | 30..=36
        | 38..=43
        | 45..=49
        | 69
        | 72
        | 80
        | 93
        | 96
        | 97
        | 107
        | 109
        | 110
        | 121..=124
        | 140
        | 141
        | 144
        | 145
        | 148
        | 149
        | 154..=157
        | 160
        | 161
        | 164..=171
        | 182..=184
        | 189
        | 195
        | 197
        | 198 => Fixed(2),
        73 | 95 | 136 | 137 => Fixed(3),
        20 | 70 | 192 | 194 | 196 | 200 => Fixed(4),
        193 | 199 => Fixed(5),
        187 => Fixed(12),
        83 => Fixed(0),
        3 | 12 | 15 | 23 | 52 | 68 | 74 | 81 | 82 | 103 | 105 | 106 | 108 | 120 | 133 | 163 => {
            Counted
        }
        188 | 190 | 191 => Long,
        _ => return None,
    })
}

fn put1(o: &mut Vec<u8>, op: u16, v: u8) {
    o.extend_from_slice(&op.to_le_bytes());
    o.push(v);
}

fn put2(o: &mut Vec<u8>, op: u16, v: u16) {
    o.extend_from_slice(&op.to_le_bytes());
    o.extend_from_slice(&v.to_le_bytes());
}

fn put4(o: &mut Vec<u8>, op: u16, v: &[u8]) {
    o.extend_from_slice(&op.to_le_bytes());
    o.extend_from_slice(v);
}

fn put_var(o: &mut Vec<u8>, op: u16, v: &[u8]) {
    o.extend_from_slice(&op.to_le_bytes());
    o.push(v.len().min(255) as u8);
    o.extend_from_slice(&v[..v.len().min(255)]);
}

/// A Word 6 border (a word) as Word 97's Brc80: line width in eighths of a
/// point, type, colour, space and shadow.
fn brc(w: u16) -> [u8; 4] {
    let units = (w & 7) as u8;
    let kind = ((w >> 3) & 3) as u8;
    let shadow = (w >> 5) & 1;
    let color = ((w >> 6) & 0x1F) as u8;
    let space = ((w >> 11) & 0x1F) as u8;
    if kind == 0 {
        return [0, 0, 0, 0];
    }
    // 0.75 point units; 6 and 7 are dotted and dashed lines.
    let (width, style) = match units {
        6 => (6, 6),
        7 => (6, 7),
        u => (
            (u.max(1) * 6).saturating_mul(if kind == 2 { 2 } else { 1 }),
            if kind == 3 { 3 } else { 1 },
        ),
    };
    [width, style, color, space | (shadow as u8) << 5]
}

/// The key of an autonumber, for lists.
const ANLD_LEN: usize = 52;

/// Translates a Word 6 modifier list to Word 97's. Autonumber descriptors
/// are collected in `anlds`; a paragraph gets the list of its descriptor.
pub(super) fn translate(g: &[u8], anlds: &mut Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = vec![];
    let mut p = 0usize;
    while p < g.len() {
        let op = g[p];
        let Some(sz) = size(op) else { break };
        let (b0, n, cb): (usize, usize, u8) = match sz {
            Size::Fixed(n) => (p + 1, n, 0),
            Size::Counted => {
                let Some(&c) = g.get(p + 1) else { break };
                if op == 23 && c == 255 {
                    // The tabs to delete and to add give the size.
                    let del = usize::from(g.get(p + 2).copied().unwrap_or(0));
                    let add = usize::from(g.get(p + 3 + 4 * del).copied().unwrap_or(0));
                    (p + 2, 2 + 4 * del + 3 * add, 255)
                } else {
                    (p + 2, usize::from(c), c)
                }
            }
            Size::Long => {
                let len = usize::from(u16_at(g, p + 1));
                (p + 3, len.saturating_sub(1), 0)
            }
        };
        let Some(b) = g.get(b0..b0 + n) else { break };
        p = b0 + n;
        modifier(op, b, cb, &mut out, anlds);
    }
    out
}

fn modifier(op: u8, b: &[u8], cb: u8, o: &mut Vec<u8>, anlds: &mut Vec<Vec<u8>>) {
    let w = || u16_at(b, 0);
    let b0 = b.first().copied().unwrap_or(0);
    match op {
        // ---- paragraphs ----
        2 => put2(o, 0x4600, w()),
        5 => put1(o, 0x2403, b0),
        7 => put1(o, 0x2405, b0),
        8 => put1(o, 0x2406, b0),
        9 => put1(o, 0x2407, b0),
        12 => {
            if b.len() >= ANLD_LEN {
                let key = b[..ANLD_LEN].to_vec();
                let at = anlds.iter().position(|a| *a == key).unwrap_or_else(|| {
                    anlds.push(key);
                    anlds.len() - 1
                });
                put2(o, 0x460B, at as u16 + 1);
                put1(o, 0x260A, 0);
            }
        }
        14 => put1(o, 0x240C, b0),
        15 => put_var(o, 0xC60D, b),
        16 => put2(o, 0x845D, w()),
        17 => put2(o, 0x845E, w()),
        19 => put2(o, 0x8460, w()),
        20 => put4(o, 0x6412, b),
        21 => put2(o, 0xA413, w()),
        22 => put2(o, 0xA414, w()),
        23 => {
            o.extend_from_slice(&0xC615u16.to_le_bytes());
            o.push(cb);
            o.extend_from_slice(b);
        }
        24 => put1(o, 0x2416, b0),
        25 => put1(o, 0x2417, b0),
        38..=42 => put4(o, 0x6424 + u16::from(op - 38), &brc(w())),
        47 => put2(o, 0x442D, w()),
        51 => put1(o, 0x2431, b0),
        // ---- characters ----
        65 => put1(o, 0x0800, b0),
        66 => put1(o, 0x0801, b0),
        67 => put1(o, 0x0802, b0),
        68 => {
            put4(o, 0x6A03, b.get(..4).unwrap_or(&[0; 4]));
            put1(o, 0x0855, 1);
        }
        71 => put1(o, 0x0806, b0),
        74 => {
            put4(
                o,
                0x6A09,
                &[
                    b0,
                    b.get(1).copied().unwrap_or(0),
                    b.get(2).copied().unwrap_or(0),
                    0,
                ],
            );
            put1(o, 0x0855, 1);
        }
        75 => put1(o, 0x080A, b0),
        80 => put2(o, 0x4A30, w()),
        82 | 83 => put1(o, 0x2A33, 0),
        85..=92 => put1(o, 0x0835 + u16::from(op - 85), b0),
        93 => {
            put2(o, 0x4A4F, w());
            put2(o, 0x4A51, w());
        }
        94 => put1(o, 0x2A3E, b0),
        95 => {
            if b0 != 0 {
                put2(o, 0x4A43, u16::from(b0));
            }
            let pos = b.get(2).copied().unwrap_or(128);
            if pos != 128 {
                put2(o, 0x4845, i16::from(pos as i8) as u16);
            }
        }
        96 => put2(o, 0x8840, w()),
        98 => put1(o, 0x2A42, b0),
        99 => put2(o, 0x4A43, u16::from(b0)),
        101 => put2(o, 0x4845, i16::from(b0 as i8) as u16),
        104 => put1(o, 0x2A48, b0),
        105 => put2(o, 0x4A43, w()),
        107 => put2(o, 0x484B, w()),
        117 => put1(o, 0x0855, b0),
        118 => put1(o, 0x0856, b0),
        // ---- sections ----
        136 => put4(o, 0xF203, b),
        137 => put4(o, 0xF204, b),
        142 => put1(o, 0x3009, b0),
        143 => put1(o, 0x300A, b0),
        144 => put2(o, 0x500B, w()),
        145 => put2(o, 0x900C, w()),
        147 => put1(o, 0x300E, b0),
        150 => put1(o, 0x3011, b0),
        154 => put2(o, 0x5015, w()),
        155 => put2(o, 0x9016, w()),
        156 => put2(o, 0xB017, w()),
        157 => put2(o, 0xB018, w()),
        158 => put1(o, 0x3019, b0),
        159 => put1(o, 0x301A, b0),
        160 => put2(o, 0x501B, w()),
        161 => put2(o, 0x501C, w()),
        162 => put1(o, 0x301D, b0),
        164 => put2(o, 0xB01F, w()),
        165 => put2(o, 0xB020, w()),
        166 => put2(o, 0xB021, w()),
        167 => put2(o, 0xB022, w()),
        168 => put2(o, 0x9023, w()),
        169 => put2(o, 0x9024, w()),
        170 => put2(o, 0xB025, w()),
        // ---- tables ----
        182 => put2(o, 0x5400, w()),
        183 => put2(o, 0x9601, w()),
        184 => put2(o, 0x9602, w()),
        185 => put1(o, 0x3403, b0),
        186 => put1(o, 0x3404, b0),
        187 => {
            let mut v = vec![];
            for k in 0..6 {
                v.extend_from_slice(&brc(u16_at(b, 2 * k)));
            }
            put_var(o, 0xD605, &v);
        }
        189 => put2(o, 0x9407, w()),
        190 => table_definition(b, o),
        191 => {
            let n = usize::from(b0);
            let mut v = vec![];
            for k in 0..n {
                v.extend_from_slice(b.get(1 + 2 * k..3 + 2 * k).unwrap_or(&[0, 0]));
            }
            put_var(o, 0xD609, &v);
        }
        193 => {
            let mut v = vec![
                b0,
                b.get(1).copied().unwrap_or(0),
                b.get(2).copied().unwrap_or(0),
            ];
            v.extend_from_slice(&brc(u16_at(b, 3)));
            put_var(o, 0xD620, &v);
        }
        194 => put4(o, 0x7621, b),
        195 => put2(o, 0x5622, w()),
        196 => put4(o, 0x7623, b),
        197 => put2(o, 0x5624, w()),
        198 => put2(o, 0x5625, w()),
        200 => {
            // A Shd80 over a range of cells, as the long form.
            let (f, l) = (b0, b.get(1).copied().unwrap_or(0));
            let s = u16_at(b, 2);
            let color = |c: u8| match ico(c) {
                Color::Rgb(v) => (v >> 16 & 0xFF, v >> 8 & 0xFF, v & 0xFF),
                Color::Auto => (0xFF, 0xFF, 0xFF),
            };
            let (fr, fg, fb) = color((s & 0x1F) as u8);
            let (br, bg, bb) = color(((s >> 5) & 0x1F) as u8);
            let mut v = vec![
                f, l, fr as u8, fg as u8, fb as u8, 0, br as u8, bg as u8, bb as u8, 0,
            ];
            v.extend_from_slice(&(s >> 10 & 0x3F).to_le_bytes());
            put_var(o, 0xD62D, &v);
        }
        _ => {}
    }
}

/// sprmTDefTable: the cell edges and each cell's flags and borders, as
/// Word 97's TC80 of 20 bytes.
fn table_definition(b: &[u8], o: &mut Vec<u8>) {
    let n = usize::from(b.first().copied().unwrap_or(0)).min(32);
    let mut v = vec![n as u8];
    for k in 0..=n {
        v.extend_from_slice(b.get(1 + 2 * k..3 + 2 * k).unwrap_or(&[0, 0]));
    }
    let base = 1 + 2 * (n + 1);
    for k in 0..n {
        let tc = b.get(base + 10 * k..base + 10 * k + 10).unwrap_or(&[0; 10]);
        let rgf = u16_at(tc, 0);
        // Merged with the cell before is 1, the first of a set 2.
        let merge: u16 = if rgf & 1 != 0 {
            2
        } else if rgf & 2 != 0 {
            1
        } else {
            0
        };
        v.extend_from_slice(&merge.to_le_bytes());
        v.extend_from_slice(&[0, 0]);
        for e in 0..4 {
            v.extend_from_slice(&brc(u16_at(tc, 2 + 2 * e)));
        }
    }
    o.extend_from_slice(&0xD608u16.to_le_bytes());
    o.extend_from_slice(&(v.len() as u16 + 1).to_le_bytes());
    o.extend_from_slice(&v);
}

/// The modifiers `g` (Word 6 form) as a list at the end of the main stream.
struct Lists<'a> {
    wd: &'a mut Vec<u8>,
    b: &'a mut Budget,
    anlds: Vec<Vec<u8>>,
}

impl Lists<'_> {
    /// Translates `g` and keeps it, against the memory budget; `prefix`
    /// leads it (a style code).
    fn keep(&mut self, prefix: &[u8], g: &[u8]) -> Result<(u32, u16)> {
        let mut v = prefix.to_vec();
        v.extend(translate(g, &mut self.anlds));
        let len = v.len().min(0xFFFF);
        self.b.alloc(len as u64)?;
        let off = self.wd.len();
        self.wd.extend_from_slice(&v[..len]);
        Ok((off as u32, len as u16))
    }
}

pub(crate) fn read(wd: Vec<u8>, budget: &mut Budget) -> Result<Document> {
    if wd.len() < 0x200 {
        return Err(Error::Malformed(
            "the WordDocument stream is too short".into(),
        ));
    }
    let flags = u16_at(&wd, 10);
    if flags & 0x0100 != 0 {
        return Err(Error::Encrypted);
    }
    let lw = |o: usize| i64::from(u32_at(&wd, o) as i32).max(0);
    let fib = Fib {
        n_fib: u16_at(&wd, 2),
        which_table: false,
        encrypted: false,
        ccp_text: lw(52),
        ccp_ftn: lw(56),
        ccp_hdd: lw(60),
        ccp_atn: lw(68),
        ccp_edn: lw(72),
        ccp_txbx: lw(76),
        ccp_hdr_txbx: lw(80),
        pairs: vec![],
    };
    let fc_min = u32_at(&wd, 24);
    let fc_mac = u32_at(&wd, 28);
    let total_cp = (fib.total_cp() + lw(64)).max(fib.ccp_text);
    budget.alloc(wd.len() as u64)?;
    // The pieces: the whole text from fcMin, or the piece table of a file
    // that was fast-saved.
    let complex = flags & 0x0004 != 0;
    let mut clx = Clx {
        pieces: vec![],
        prcs: vec![],
    };
    if complex {
        clx = read_clx(&wd)?;
    }
    if clx.pieces.is_empty() {
        let avail = i64::from(fc_mac.saturating_sub(fc_min));
        let total = total_cp.min(avail).max(fib.ccp_text.min(avail)).max(1) as u32;
        clx.pieces.push(Piece {
            cp0: 0,
            cp1: total,
            fc: fc_min,
            compressed: true,
            prm: 0,
        });
    }
    let last = clx.pieces.iter().map(|p| p.cp1 as usize).max().unwrap_or(1);
    let total = usize::try_from(total_cp)
        .unwrap_or(usize::MAX)
        .min(last)
        .max(fib.ccp_text.max(0) as usize)
        .min(last.max(1));
    if total > 1 << 28 {
        return Err(Error::TooLarge("characters"));
    }
    budget.alloc(2 * total as u64)?;
    let table = codepage(&wd).map(|cp| {
        std::array::from_fn(|b| {
            crate::formats::office::common::codepage::decode(&[b as u8], cp)
                .encode_utf16()
                .next()
                .unwrap_or(0xFFFD)
        })
    });
    let text = fib::read_text_in(&wd, &clx.pieces, total, table.as_ref());
    // A modifier of a piece, or an index to a list of them, in Word 97's form.
    let mut anlds = vec![];
    let mut prcs: Vec<Vec<u8>> = vec![];
    for g in &clx.prcs {
        prcs.push(translate(g, &mut anlds));
    }
    for p in &mut clx.pieces {
        if p.prm & 1 == 0 && p.prm != 0 {
            // One modifier: its opcode (7 bits) and its operand byte.
            let g = [((p.prm >> 1) & 0x7F) as u8, (p.prm >> 8) as u8];
            prcs.push(translate(&g, &mut anlds));
            p.prm = ((prcs.len() - 1) as u16) << 1 | 1;
        }
    }
    clx.prcs = prcs;
    let mut r = Reader::new(budget, wd, vec![], vec![], fib, clx, text);
    r.word6 = true;
    r.load6(anlds)?;
    r.convert()?;
    Ok(r.doc)
}

/// The Windows code page of a Word 6 or 95 document other than 1252, from
/// the language in its header (the text is in the code page of the system
/// that wrote it), or Mac Roman for a Macintosh one.
fn codepage(wd: &[u8]) -> Option<u16> {
    if u16_at(wd, 0x14) == 256 {
        return Some(10000);
    }
    Some(match u16_at(wd, 6) & 0x3FF {
        0x19 | 0x22 | 0x02 | 0x23 | 0x2F | 0x3F | 0x40 | 0x44 | 0x50 => 1251,
        0x15 | 0x05 | 0x0E | 0x1B | 0x24 | 0x1A | 0x18 | 0x1C => 1250,
        0x08 => 1253,
        0x1F | 0x2C => 1254,
        0x0D => 1255,
        0x01 | 0x29 | 0x20 => 1256,
        0x25..=0x27 => 1257,
        0x2A => 1258,
        0x1E => 874,
        _ => return None,
    })
}

/// The grpprls and the piece table of a fast-saved file: the length of each
/// group is two bytes, that of the piece table four.
fn read_clx(wd: &[u8]) -> Result<Clx> {
    let d = part(wd, at::CLX);
    let mut p = 0usize;
    let mut prcs = vec![];
    loop {
        match d.get(p).copied() {
            Some(1) => {
                let n = usize::from(u16_at(d, p + 1));
                prcs.push(d.get(p + 3..p + 3 + n).unwrap_or(&[]).to_vec());
                p += 3 + n;
                if prcs.len() > 1 << 15 {
                    return Err(Error::Malformed("too many property modifier groups".into()));
                }
            }
            Some(2) => {
                // The piece table's length is four bytes, the groups' two.
                let n = u32_at(d, p + 1) as usize;
                let plc = d
                    .get(p + 5..p.saturating_add(5).saturating_add(n))
                    .unwrap_or(&[]);
                let count = plc.len().saturating_sub(4) / 12;
                let mut pieces = Vec::with_capacity(count);
                for i in 0..count {
                    let (cp0, cp1) = (u32_at(plc, 4 * i), u32_at(plc, 4 * (i + 1)));
                    if cp1 < cp0 {
                        return Err(Error::Malformed("pieces out of order".into()));
                    }
                    let pcd = 4 * (count + 1) + 8 * i;
                    pieces.push(Piece {
                        cp0,
                        cp1,
                        fc: u32_at(plc, pcd + 2),
                        compressed: true,
                        prm: u16_at(plc, pcd + 6),
                    });
                }
                return Ok(Clx { pieces, prcs });
            }
            _ => return Err(Error::Malformed("no piece table in the file".into())),
        }
    }
}

impl Reader<'_> {
    pub(crate) fn load6(&mut self, anlds: Vec<Vec<u8>>) -> Result<()> {
        let mut lists = Lists {
            wd: &mut self.wd,
            b: &mut *self.b,
            anlds,
        };
        let (fonts, stsh) = (read_fonts(lists.wd), read_styles(&mut lists)?);
        let (chpx, papx) = (
            read_fkps(&mut lists, at::BTE_CHPX, false)?,
            read_fkps(&mut lists, at::BTE_PAPX, true)?,
        );
        let sections = read_sections(&mut lists)?;
        let anlds = std::mem::take(&mut lists.anlds);
        self.fonts = fonts;
        self.stsh = stsh;
        self.chpx = chpx;
        self.papx = papx;
        let (heads, ihdt) = (sections.0, sections.1);
        self.sections = heads;
        self.read_dop6();
        self.read_notes6();
        self.read_bookmarks6();
        self.hdd = story_table(&self.wd, &ihdt);
        self.doc.numbering = numbering(&anlds, &self.fonts);
        Ok(())
    }

    fn read_dop6(&mut self) {
        let d = part(&self.wd, at::DOP);
        if d.len() < 12 {
            return;
        }
        self.facing = d[0] & 1 != 0;
        self.doc.settings.even_and_odd_headers = self.facing;
        let tab = i32::from(u16_at(d, 10));
        if tab > 0 {
            self.doc.settings.default_tab_stop = Some(tab);
        }
    }

    fn read_notes6(&mut self) {
        let base_ftn = self.fib.ccp_text as u32;
        let (o, l) = pair(&self.wd, at::FND_REF);
        self.ftn_ref = read_plc(&self.wd, o, l, 2).cps;
        self.ftn_ref.pop();
        let (o, l) = pair(&self.wd, at::FND_TXT);
        self.ftn_txt = read_plc(&self.wd, o, l, 0)
            .cps
            .iter()
            .map(|c| c.saturating_add(base_ftn))
            .collect();
        let f = &self.fib;
        // The macro story (ccpMcr) sits between the headers and the annotations.
        let mcr = i64::from(u32_at(&self.wd, 64));
        let base_edn = fib::cp(f.ccp_text + f.ccp_ftn + f.ccp_hdd + mcr + f.ccp_atn);
        let (o, l) = pair(&self.wd, at::END_REF);
        self.edn_ref = read_plc(&self.wd, o, l, 2).cps;
        self.edn_ref.pop();
        let (o, l) = pair(&self.wd, at::END_TXT);
        self.edn_txt = read_plc(&self.wd, o, l, 0)
            .cps
            .iter()
            .map(|c| c.saturating_add(base_edn))
            .collect();
    }

    fn read_bookmarks6(&mut self) {
        let d = part(&self.wd, at::BKMK);
        let mut p = 2usize;
        while p < d.len() && self.bookmark_names.len() < 1 << 16 {
            let n = usize::from(d[p]);
            let s = d.get(p + 1..p + 1 + n).unwrap_or(&[]);
            self.bookmark_names
                .push(s.iter().map(|&c| char::from(c)).collect());
            p += 1 + n;
        }
        let (o, l) = pair(&self.wd, at::BKF);
        let bkf = read_plc(&self.wd, o, l, 4);
        let (o, l) = pair(&self.wd, at::BKL);
        let bkl = read_plc(&self.wd, o, l, 0);
        for (i, d) in bkf.data.iter().enumerate() {
            let Some(name) = self.bookmark_names.get(i) else {
                continue;
            };
            if name.starts_with('_') && !name.starts_with("_Toc") && !name.starts_with("_Ref") {
                continue;
            }
            let ibkl = usize::from(u16_at(d, 0));
            let (Some(&start), Some(&end)) = (bkf.cps.get(i), bkl.cps.get(ibkl)) else {
                continue;
            };
            self.marks.push((start, 0, i as u32));
            self.marks.push((end.max(start), 1, i as u32));
        }
        self.marks.sort_by_key(|m| (m.0, m.1));
    }

    /// A picture character's picture: a metafile after its PIC, in the main
    /// stream.
    pub(crate) fn word6_picture(&mut self, loc: i32) -> Result<Option<Drawing>> {
        let at = loc as usize;
        if loc < 0 || at + 58 > self.wd.len() {
            return Ok(None);
        }
        let lcb = u32_at(&self.wd, at) as usize;
        let cb_header = usize::from(u16_at(&self.wd, at + 4));
        let mm = u16_at(&self.wd, at + 6);
        if cb_header < 58 || lcb < cb_header || mm == 98 || mm == 99 {
            // A TIFF file's name, or a device bitmap.
            return Ok(None);
        }
        let (gx, gy) = (
            i64::from(u16_at(&self.wd, at + 28)),
            i64::from(u16_at(&self.wd, at + 30)),
        );
        let (mx, my) = (
            i64::from(u16_at(&self.wd, at + 32)),
            i64::from(u16_at(&self.wd, at + 34)),
        );
        let end = at.saturating_add(lcb).min(self.wd.len());
        let Some(body) = self.wd.get(at + cb_header..end) else {
            return Ok(None);
        };
        if body.len() < 18 {
            return Ok(None);
        }
        let data = placeable(body, gx, gy);
        self.b.alloc(data.len() as u64)?;
        let media = self.doc.add_media("wmf", data);
        let (mut cx, mut cy) = (gx * mx / 1000 * TWIP_EMU, gy * my / 1000 * TWIP_EMU);
        if cx <= 0 || cy <= 0 {
            let (nx, ny) =
                image::natural_emu(&self.doc.media[media].data).unwrap_or((914_400, 914_400));
            cx = nx;
            cy = ny;
        }
        Ok(Some(Drawing {
            anchor: None,
            cx,
            cy,
            name: "Picture".into(),
            descr: None,
            kind: DrawingKind::Picture {
                media,
                crop: Crop::default(),
            },
        }))
    }
}

/// EMU in a twip.
const TWIP_EMU: i64 = 635;

/// A metafile with the header that says its size, from twips.
fn placeable(wmf: &[u8], gx: i64, gy: i64) -> Vec<u8> {
    if wmf.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A]) {
        return wmf.to_vec();
    }
    let mut h = vec![0xD7, 0xCD, 0xC6, 0x9A, 0, 0];
    for v in [0i64, 0, gx.clamp(1, 32767), gy.clamp(1, 32767)] {
        h.extend_from_slice(&(v as i16).to_le_bytes());
    }
    h.extend_from_slice(&1440u16.to_le_bytes());
    h.extend_from_slice(&[0, 0, 0, 0]);
    let mut sum = 0u16;
    for k in 0..10 {
        sum ^= u16::from_le_bytes([h[2 * k], h[2 * k + 1]]);
    }
    h.extend_from_slice(&sum.to_le_bytes());
    h.extend_from_slice(wmf);
    h
}

/// The font names: a size, then FFNs (a length, flags, weight, character
/// set, the name from byte 6).
fn read_fonts(wd: &[u8]) -> Vec<String> {
    let d = part(wd, at::FFN);
    let mut out = vec![];
    let mut p = 2usize;
    while p < d.len() && out.len() < 4096 {
        let cb = usize::from(d[p]);
        let ffn = d.get(p + 1..p + 1 + cb).unwrap_or(&[]);
        let name = ffn.get(5..).unwrap_or(&[]);
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        out.push(name[..end].iter().map(|&c| char::from(c)).collect());
        p += 1 + cb;
    }
    out
}

fn read_styles(l: &mut Lists) -> Result<Stsh> {
    let mut out = Stsh::default();
    let d = part(l.wd, at::STSHF).to_vec();
    let cb_stshi = usize::from(u16_at(&d, 0));
    let Some(stshi) = d.get(2..2 + cb_stshi) else {
        return Ok(out);
    };
    if stshi.len() < 12 {
        return Ok(out);
    }
    let cstd = usize::from(u16_at(stshi, 0));
    let cb_base = usize::from(u16_at(stshi, 2));
    out.ftc_ascii = u16_at(stshi, 12) as i16;
    out.ftc_other = out.ftc_ascii;
    out.ftc_fe = out.ftc_ascii;
    let mut p = 2 + cb_stshi;
    for _ in 0..cstd.min(4096) {
        let cb = usize::from(u16_at(&d, p));
        if p + 2 > d.len() {
            break;
        }
        let std = d.get(p + 2..p + 2 + cb).unwrap_or(&[]);
        p += 2 + cb + (cb & 1);
        if cb == 0 {
            out.stds.push(None);
            continue;
        }
        out.stds.push(read_std(std, cb_base, l));
    }
    Ok(out)
}

fn read_std(d: &[u8], cb_base: usize, l: &mut Lists) -> Option<Std> {
    if cb_base < 8 || d.len() < cb_base + 1 {
        return None;
    }
    let w0 = u16_at(d, 0);
    let w1 = u16_at(d, 2);
    let w2 = u16_at(d, 4);
    let sti = w0 & 0x0FFF;
    let kind = ((w0 >> 12) & 0xF) as u8;
    let base = w1 & 0x0FFF;
    let cupx = usize::from(w1 >> 12);
    let next = w2 & 0x0FFF;
    // The name, a counted string, then each part on an even offset.
    let n = usize::from(d[cb_base]);
    let name: String = d
        .get(cb_base + 1..cb_base + 1 + n)
        .unwrap_or(&[])
        .iter()
        .map(|&c| char::from(c))
        .collect();
    let mut p = cb_base + 1 + n + 1;
    p += p & 1;
    let mut upx: Vec<&[u8]> = vec![];
    for _ in 0..cupx {
        if p + 2 > d.len() {
            break;
        }
        let cb = usize::from(u16_at(d, p));
        upx.push(d.get(p + 2..p + 2 + cb).unwrap_or(&[]));
        p += 2 + cb + (cb & 1);
    }
    let mut keep = |prefix: &[u8], g: &[u8]| {
        let mut v = prefix.to_vec();
        v.extend(translate(g, &mut l.anlds));
        v
    };
    let (papx, chpx) = match kind {
        1 => {
            let u = upx.first().copied().unwrap_or(&[]);
            let istd = u.get(..2).unwrap_or(&[0, 0]).to_vec();
            (
                keep(&istd, u.get(2..).unwrap_or(&[])),
                keep(&[], upx.get(1).copied().unwrap_or(&[])),
            )
        }
        2 => (vec![], keep(&[], upx.first().copied().unwrap_or(&[]))),
        _ => return None,
    };
    Some(Std {
        name,
        sti,
        kind,
        base,
        next,
        link: 0,
        papx,
        chpx,
    })
}

/// The runs of the character or paragraph FKPs, their modifier lists
/// translated and kept.
fn read_fkps(l: &mut Lists, pos: usize, para: bool) -> Result<Vec<Run>> {
    let (o, len) = pair(l.wd, pos);
    let plc = read_plc(l.wd, o, len, 2);
    let mut runs = vec![];
    // A page the bin table names twice is read once, and a modifier list
    // several runs share is kept once: neither is more memory than the file.
    let mut seen = std::collections::HashSet::new();
    for d in &plc.data {
        let base = usize::from(u16_at(d, 0)) * 512;
        if !seen.insert(base) {
            continue;
        }
        let page = match l.wd.get(base..base + 512) {
            Some(p) => p.to_vec(),
            None => continue,
        };
        let mut kept: std::collections::HashMap<usize, (u32, u16)> =
            std::collections::HashMap::new();
        let n = usize::from(page[511]);
        let entry = if para { 7 } else { 1 };
        if n == 0 || 4 * (n + 1) + entry * n > 511 {
            continue;
        }
        for k in 0..n {
            let (lo, hi) = (u32_at(&page, 4 * k), u32_at(&page, 4 * (k + 1)));
            let at = usize::from(page[4 * (n + 1) + entry * k]) * 2;
            let (off, len) = if at == 0 || at >= 511 {
                (0, 0)
            } else if let Some(&k) = kept.get(&at) {
                k
            } else {
                let k = if para {
                    // Words, the style code, then the modifiers.
                    let cw = usize::from(page[at]);
                    let g = page.get(at + 3..(at + 2 * cw).min(511)).unwrap_or(&[]);
                    let istd = page.get(at + 1..at + 3).unwrap_or(&[0, 0]);
                    l.keep(istd, g)?
                } else {
                    let cb = usize::from(page[at]);
                    l.keep(&[], page.get(at + 1..(at + 1 + cb).min(511)).unwrap_or(&[]))?
                };
                kept.insert(at, k);
                k
            };
            if hi > lo {
                runs.push(Run { lo, hi, off, len });
            }
        }
    }
    runs.sort_by_key(|r| r.lo);
    Ok(runs)
}

/// The sections, with their modifiers translated, and the header stories
/// each has (its `grpfIhdt`).
fn read_sections(l: &mut Lists) -> Result<(Vec<SectionSpan>, Vec<u8>)> {
    let (o, len) = pair(l.wd, at::SED);
    let plc = read_plc(l.wd, o, len, 12);
    let mut out = vec![];
    let mut ihdt = vec![];
    for (i, d) in plc.data.iter().enumerate() {
        let fc = u32_at(d, 2);
        let raw = if fc == 0xFFFF_FFFF {
            vec![]
        } else {
            let cb = usize::from(l.wd.get(fc as usize).copied().unwrap_or(0));
            l.wd.get(fc as usize + 1..fc as usize + 1 + cb)
                .unwrap_or(&[])
                .to_vec()
        };
        ihdt.push(headers_of(&raw));
        let grpprl = translate(&raw, &mut l.anlds);
        out.push(SectionSpan {
            cp1: plc.cps.get(i + 1).copied().unwrap_or(0),
            grpprl,
        });
    }
    if out.is_empty() {
        out.push(SectionSpan {
            cp1: u32::MAX,
            grpprl: vec![],
        });
        ihdt.push(0);
    }
    Ok((out, ihdt))
}

/// The `grpfIhdt` of a section's modifiers (sprmSGprfIhdt).
fn headers_of(g: &[u8]) -> u8 {
    let mut p = 0usize;
    let mut out = 0;
    while p < g.len() {
        let op = g[p];
        let Some(sz) = size(op) else { break };
        let (b0, n) = match sz {
            Size::Fixed(n) => (p + 1, n),
            Size::Counted => (p + 2, usize::from(g.get(p + 1).copied().unwrap_or(0))),
            Size::Long => (p + 3, usize::from(u16_at(g, p + 1)).saturating_sub(1)),
        };
        if op == 153 {
            out = g.get(b0).copied().unwrap_or(0);
        }
        p = b0 + n;
    }
    out
}

/// The header stories in the layout of Word 97: six for the notes'
/// separators, then six for each section (even header, default header, even
/// footer, default footer, first header, first footer), the ones the file
/// has taken in order from its list.
fn story_table(wd: &[u8], ihdt: &[u8]) -> super::Plc {
    let (o, l) = pair(wd, at::HDD);
    let have = read_plc(wd, o, l, 0).cps;
    let dop_bits = part(wd, at::DOP).get(1).copied().unwrap_or(0);
    let mut cps = vec![have.first().copied().unwrap_or(0)];
    let mut next = 0usize;
    let mut slot = |present: bool, cps: &mut Vec<u32>| {
        let last = *cps.last().unwrap_or(&0);
        if present {
            if let Some(&end) = have.get(next + 1) {
                cps.push(end);
            } else {
                cps.push(last);
            }
            next += 1;
        } else {
            cps.push(last);
        }
    };
    // The footnote separator, its continuation separator and notice.
    for k in 0..6u8 {
        slot(k < 3 && dop_bits & (0x80 >> k) != 0, &mut cps);
    }
    for bits in ihdt {
        for k in 0..6u8 {
            slot(bits & (0x80 >> k) != 0, &mut cps);
        }
    }
    super::Plc { cps, data: vec![] }
}

/// One list per autonumber descriptor: the number format, the text around
/// it, and the indents.
fn numbering(anlds: &[Vec<u8>], fonts: &[String]) -> Numbering {
    let mut out = Numbering::default();
    for (i, a) in anlds.iter().enumerate() {
        let nfc = a[0];
        let before = usize::from(a[1]);
        let after = usize::from(a[2]);
        let text = a.get(20..52).unwrap_or(&[]);
        let pre: String = text
            .get(..before.min(32))
            .unwrap_or(&[])
            .iter()
            .map(|&c| char::from(c))
            .collect();
        let post: String = text
            .get(before.min(32)..(before + after).min(32))
            .unwrap_or(&[])
            .iter()
            .map(|&c| char::from(c))
            .collect();
        let fmt = match nfc {
            0 => "decimal",
            1 => "upperRoman",
            2 => "lowerRoman",
            3 => "upperLetter",
            4 => "lowerLetter",
            5 => "ordinal",
            _ => "bullet",
        };
        let hang = a[3] & 0x08 != 0;
        let dxa_indent = i32::from(u16_at(a, 12));
        let dxa_space = i32::from(u16_at(a, 14));
        let mut level = Level {
            start: i64::from(u16_at(a, 10).max(1)),
            fmt,
            jc: match a[3] & 3 {
                1 => Jc::Center,
                2 => Jc::Right,
                _ => Jc::Left,
            },
            ..Level::default()
        };
        level.text = if fmt == "bullet" {
            // A bullet is the text before the number, in a symbol font.
            let font = fonts
                .get(usize::from(u16_at(a, 6)))
                .map(String::as_str)
                .unwrap_or("");
            let symbolic = font.eq_ignore_ascii_case("symbol")
                || font.to_ascii_lowercase().contains("wingdings");
            match pre.chars().next() {
                Some(_) if symbolic => "\u{2022}".to_string(),
                Some(c) => c.to_string(),
                None => "\u{2022}".to_string(),
            }
        } else {
            format!("{pre}%1{post}")
        };
        if hang {
            level.ppr.ind_left = Some(dxa_indent.max(dxa_space));
            level.ppr.ind_hanging = Some(dxa_indent.max(dxa_space));
        }
        out.abstracts.push(AbstractNum {
            id: i as u32,
            multi_level: false,
            levels: vec![level],
        });
        out.nums.push(Num {
            id: i as u32 + 1,
            abstract_id: i as u32,
            overrides: vec![],
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tr(g: &[u8]) -> Vec<u8> {
        translate(g, &mut vec![])
    }

    #[test]
    fn every_modifier_of_the_format_has_a_size() {
        for op in (2..=52u8)
            .chain(65..=75)
            .chain(80..=83)
            .chain(85..=110)
            .chain(117..=124)
            .chain(131..=133)
            .chain(136..=171)
            .chain(182..=200)
        {
            assert!(size(op).is_some(), "{op}");
        }
        assert!(size(60).is_none());
        assert!(size(250).is_none());
    }

    #[test]
    fn modifiers_become_word_97s() {
        // Bold, 12 pt, centered, 360 after: the opcodes and operands.
        assert_eq!(tr(&[85, 1, 99, 24]), [0x35, 0x08, 1, 0x43, 0x4A, 24, 0]);
        assert_eq!(
            tr(&[5, 1, 22, 0x68, 1]),
            [0x03, 0x24, 1, 0x14, 0xA4, 0x68, 1]
        );
        // A symbol sets the special flag; a picture location too.
        assert_eq!(
            tr(&[74, 3, 7, 0, 0xB7]),
            [0x09, 0x6A, 7, 0, 0xB7, 0, 0x55, 0x08, 1]
        );
        // A modifier of no known size ends the list.
        assert_eq!(tr(&[85, 1, 60, 1, 86, 1]), [0x35, 0x08, 1]);
        // A truncated operand ends it too.
        assert_eq!(tr(&[85, 1, 99]), [0x35, 0x08, 1]);
    }

    #[test]
    fn borders_keep_their_width_type_colour_and_space() {
        // 1 unit (0.75 pt) single, red, 2 points of space, shadow.
        let w = 1 | 1 << 3 | 1 << 5 | 6 << 6 | 2 << 11;
        assert_eq!(brc(w), [6, 1, 6, 2 | 0x20]);
        // Thick doubles the width; double is its own type; none is nothing.
        assert_eq!(brc(1 | 2 << 3), [12, 1, 0, 0]);
        assert_eq!(brc(2 | 3 << 3)[1], 3);
        assert_eq!(brc(0), [0, 0, 0, 0]);
        // Dotted and dashed lines are the widths 6 and 7.
        assert_eq!(brc(6 | 1 << 3), [6, 6, 0, 0]);
        assert_eq!(brc(7 | 1 << 3), [6, 7, 0, 0]);
    }

    #[test]
    fn table_cells_are_two_edges_and_ten_bytes_each() {
        // Two cells: edges 0, 1000, 2000; the first the first of a merged
        // set (bit 0), the second merged with it (bit 1).
        let mut g = vec![190, 0, 0, 2];
        for e in [0i16, 1000, 2000] {
            g.extend_from_slice(&e.to_le_bytes());
        }
        let len = g.len() as u16 - 3 + 20 + 1;
        g.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        g[1..3].copy_from_slice(&len.to_le_bytes());
        g.extend_from_slice(&[85, 1]);
        let o = tr(&g);
        // The edges, then 20 bytes a cell: the merge in the first word.
        assert_eq!(&o[..2], [0x08, 0xD6]);
        // The size is one more than what follows it: the cell count, the
        // three edges and the two cells.
        assert_eq!(u16::from_le_bytes([o[2], o[3]]) as usize, 1 + 6 + 40 + 1);
        assert_eq!(o[4], 2);
        let cells = &o[4 + 1 + 6..];
        assert_eq!(u16::from_le_bytes([cells[0], cells[1]]), 2);
        assert_eq!(u16::from_le_bytes([cells[20], cells[21]]), 1);
        // And the modifier after it is still read.
        assert_eq!(&o[o.len() - 3..], [0x35, 0x08, 1]);
    }

    #[test]
    fn an_autonumber_is_a_list_shared_by_equal_descriptors() {
        let mut a = vec![0u8; ANLD_LEN];
        a[0] = 4;
        let mut b = a.clone();
        b[0] = 0;
        let mut anlds = vec![];
        let mut g = vec![12, ANLD_LEN as u8];
        g.extend_from_slice(&a);
        let first = translate(&g, &mut anlds);
        let again = translate(&g, &mut anlds);
        assert_eq!(first, again);
        assert_eq!(anlds.len(), 1);
        // The list number is one-based.
        assert_eq!(&first[..4], [0x0B, 0x46, 1, 0]);
        let mut g = vec![12, ANLD_LEN as u8];
        g.extend_from_slice(&b);
        let other = translate(&g, &mut anlds);
        assert_eq!(&other[..4], [0x0B, 0x46, 2, 0]);
        let n = numbering(&anlds, &[]);
        assert_eq!(n.nums.len(), 2);
        assert_eq!(n.abstracts[0].levels[0].fmt, "lowerLetter");
        assert_eq!(n.abstracts[1].levels[0].fmt, "decimal");
    }

    #[test]
    fn the_text_of_a_word_6_file_is_in_the_code_page_of_its_language() {
        let mut wd = vec![0u8; 0x20];
        assert_eq!(codepage(&wd), None);
        // Russian, 0x0419: Windows 1251; Greek: 1253; Mac: Roman.
        wd[6..8].copy_from_slice(&0x0419u16.to_le_bytes());
        assert_eq!(codepage(&wd), Some(1251));
        wd[6..8].copy_from_slice(&0x0408u16.to_le_bytes());
        assert_eq!(codepage(&wd), Some(1253));
        wd[0x14] = 0;
        wd[0x15] = 1;
        assert_eq!(codepage(&wd), Some(10000));
        // The bytes of "Привет" in 1251 come out as Cyrillic.
        let pieces = [Piece {
            cp0: 0,
            cp1: 6,
            fc: 0x20,
            compressed: true,
            prm: 0,
        }];
        let mut wd = vec![0u8; 0x30];
        wd[0x20..0x26].copy_from_slice(&[0xCF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2]);
        let table = std::array::from_fn(|b| {
            crate::formats::office::common::codepage::decode(&[b as u8], 1251)
                .encode_utf16()
                .next()
                .unwrap()
        });
        let t = fib::read_text_in(&wd, &pieces, 6, Some(&table));
        assert_eq!(String::from_utf16(&t).unwrap(), "Привет");
        // Without a table it is Windows 1252, as before.
        let t = fib::read_text_in(&wd, &pieces, 6, None);
        assert_eq!(String::from_utf16(&t).unwrap(), "Ïðèâåò");
    }

    #[test]
    fn a_fast_saved_file_has_its_pieces_and_modifier_lists_in_the_complex_part() {
        // A list of one modifier (bold), then a piece table of two pieces: the
        // first at byte 0x500 with a list, the second at 0x600 with a single
        // modifier (italic, 1) in its prm.
        let mut clx = vec![1u8, 2, 0, 85, 1, 2];
        let mut plc = vec![];
        for cp in [0u32, 5, 9] {
            plc.extend_from_slice(&cp.to_le_bytes());
        }
        for (fc, prm) in [(0x500u32, 1u16), (0x600, (86 << 1) | (1 << 8))] {
            plc.extend_from_slice(&[0, 0]);
            plc.extend_from_slice(&fc.to_le_bytes());
            plc.extend_from_slice(&prm.to_le_bytes());
        }
        clx.extend_from_slice(&(plc.len() as u32).to_le_bytes());
        clx.extend_from_slice(&plc);
        let mut wd = vec![0u8; 0x300];
        wd[0x100..0x100 + clx.len()].copy_from_slice(&clx);
        wd[352..356].copy_from_slice(&0x100u32.to_le_bytes());
        wd[356..360].copy_from_slice(&(clx.len() as u32).to_le_bytes());
        let c = read_clx(&wd).unwrap();
        assert_eq!(c.prcs, vec![vec![85, 1]]);
        assert_eq!(c.pieces.len(), 2);
        assert_eq!(
            (c.pieces[0].cp0, c.pieces[0].cp1, c.pieces[0].fc),
            (0, 5, 0x500)
        );
        assert_eq!(
            (c.pieces[1].cp0, c.pieces[1].cp1, c.pieces[1].fc),
            (5, 9, 0x600)
        );
        assert!(c.pieces.iter().all(|p| p.compressed));
        assert_eq!(c.pieces[1].prm, (86 << 1) | (1 << 8));
        // Neither a list nor a piece table: refused.
        wd[0x100] = 9;
        assert!(read_clx(&wd).is_err());
    }

    #[test]
    fn translated_modifier_lists_are_kept_once_and_count_against_the_memory_limit() {
        use crate::formats::office::docs::limits::Limits;
        // A character FKP at 0x200 of three runs that all point at one CHPX
        // (bold), twice named by the bin table.
        let mut wd = vec![0u8; 0x400];
        let page = 0x200;
        for (i, fc) in [0x100u32, 0x110, 0x120, 0x130].iter().enumerate() {
            wd[page + 4 * i..page + 4 * i + 4].copy_from_slice(&fc.to_le_bytes());
        }
        // One word offset (0x80) for each of the three runs: the CHPX at
        // page + 0x100 is a count of 2 and bold on.
        wd[page + 16..page + 19].copy_from_slice(&[0x80, 0x80, 0x80]);
        wd[page + 0x100..page + 0x103].copy_from_slice(&[2, 85, 1]);
        wd[page + 511] = 3;
        let bte: Vec<u8> = [0x100u32, 0x120, 0x130]
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .chain([1, 0, 1, 0])
            .collect();
        wd[0x20..0x20 + bte.len()].copy_from_slice(&bte);
        // Both entries name page 1 (0x200 / 512 = 1).
        wd[184..188].copy_from_slice(&0x20u32.to_le_bytes());
        wd[188..192].copy_from_slice(&(bte.len() as u32).to_le_bytes());
        let mut b = Budget::new(Limits::default());
        let mut l = Lists {
            wd: &mut wd,
            b: &mut b,
            anlds: vec![],
        };
        let runs = read_fkps(&mut l, at::BTE_CHPX, false).unwrap();
        assert_eq!(runs.len(), 3);
        // One list of the three bytes of Word 97's bold, shared.
        assert_eq!(l.wd.len(), 0x400 + 3);
        assert!(runs.iter().all(|r| r.off == runs[0].off && r.len == 3));
        // The memory is the budget's.
        let mut b = Budget::new(Limits::default().with_max_memory(4));
        let mut wd = vec![];
        let mut l = Lists {
            wd: &mut wd,
            b: &mut b,
            anlds: vec![],
        };
        assert!(l.keep(&[], &[85, 1]).is_ok());
        assert!(l.keep(&[], &[85, 1]).is_err());
    }

    #[test]
    fn a_metafile_gets_the_header_that_gives_its_size() {
        let wmf = [1u8, 0, 9, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let h = placeable(&wmf, 1440, 720);
        assert_eq!(&h[..4], [0xD7, 0xCD, 0xC6, 0x9A]);
        // Bounds 0, 0, 1440, 720 at 1440 units to the inch.
        assert_eq!(&h[6..14], [0, 0, 0, 0, 0xA0, 5, 0xD0, 2]);
        assert_eq!(&h[14..16], 1440u16.to_le_bytes());
        assert!(h.ends_with(&wmf));
        // One that has it is left alone.
        assert_eq!(placeable(&h, 1, 1), h);
    }

    #[test]
    fn a_section_says_which_headers_it_has() {
        assert_eq!(headers_of(&[142, 2, 153, 0x44, 143, 1]), 0x44);
        assert_eq!(headers_of(&[]), 0);
        // Each story the section's bits name is the next of the file's list;
        // the first slots are the notes' separators.
        let mut wd = vec![0u8; 0x400];
        let hdd: Vec<u8> = [0u32, 4, 9, 12]
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        wd[0x100..0x100 + hdd.len()].copy_from_slice(&hdd);
        wd[176..180].copy_from_slice(&0x100u32.to_le_bytes());
        wd[180..184].copy_from_slice(&(hdd.len() as u32).to_le_bytes());
        // A default header (bit 6) and a first-page footer (bit 2).
        let t = story_table(&wd, &[0x40 | 0x04]);
        assert_eq!(t.cps.len(), 13);
        // Slots 0 to 5 are empty, then the section's: even header (empty),
        // default header 0..4, even footer, odd footer (empty), first header,
        // first footer 4..9.
        assert_eq!(t.cps[6], 0);
        assert_eq!(&t.cps[7..9], [0, 4]);
        assert_eq!(&t.cps[9..13], [4, 4, 4, 9]);
        // The document's own bits (7, 6 and 5) name the notes' separators, the
        // first stories of the list: here the footnote separator.
        wd[0x200 + 1] = 0x80;
        wd[336..340].copy_from_slice(&0x200u32.to_le_bytes());
        wd[340..344].copy_from_slice(&84u32.to_le_bytes());
        let t = story_table(&wd, &[0]);
        assert_eq!(&t.cps[..3], [0, 4, 4]);
        // A section with none: every slot is empty after it.
        assert_eq!(t.cps.len(), 13);
        assert!(t.cps[1..].iter().all(|&c| c == 4));
    }
}
