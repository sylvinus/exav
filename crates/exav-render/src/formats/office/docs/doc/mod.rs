//! Word 6 to 2003 binary documents ([MS-DOC]; Word 6 and 95 in `word6`) to the
//! document model.

mod draw;
mod fib;
pub(crate) mod lists;
mod props;
mod sprm;
mod story;
mod styles;
mod tables;
mod word6;

use crate::formats::office::common::bytes::{u16_at, u32_at};
use crate::formats::office::common::cfb::Compound;
use crate::formats::office::docs::error::{Error, Result};
use crate::formats::office::docs::limits::Budget;
use crate::formats::office::docs::model::*;
use fib::{idx, Fib, Piece};
use std::collections::HashMap;

/// An FKP entry: the bytes `lo..hi` of the WordDocument stream and the
/// modifier list that applies to them.
#[derive(Clone, Copy)]
pub(crate) struct Run {
    pub lo: u32,
    pub hi: u32,
    pub off: u32,
    pub len: u16,
}

/// A Plc: positions and the fixed-size data between them.
pub(crate) struct Plc {
    pub cps: Vec<u32>,
    pub data: Vec<Vec<u8>>,
}

pub(crate) fn read_plc(tbl: &[u8], off: usize, len: usize, size: usize) -> Plc {
    let d = tbl
        .get(off..off.saturating_add(len).min(tbl.len()))
        .unwrap_or(&[]);
    let n = if size == 0 {
        (d.len() / 4).saturating_sub(1)
    } else {
        d.len().saturating_sub(4) / (4 + size)
    };
    let n = n.min(1 << 22);
    let cps = (0..=n).map(|i| u32_at(d, 4 * i)).collect();
    let data = if size == 0 {
        vec![]
    } else {
        (0..n)
            .map(|i| {
                let s = 4 * (n + 1) + size * i;
                d.get(s..s + size).unwrap_or(&[]).to_vec()
            })
            .collect()
    };
    Plc { cps, data }
}

/// A shape anchor ([MS-DOC] 2.9.253).
#[derive(Clone, Debug)]
pub(crate) struct Spa {
    pub cp: u32,
    pub lid: u32,
    pub rect: [i32; 4],
    pub flags: u16,
}

pub(crate) struct SectionSpan {
    pub cp1: u32,
    pub grpprl: Vec<u8>,
}

pub(crate) struct Reader<'a> {
    pub b: &'a mut Budget,
    pub doc: Document,
    pub wd: Vec<u8>,
    pub tbl: Vec<u8>,
    pub data: Vec<u8>,
    pub fib: Fib,
    pub pieces: Vec<Piece>,
    pub prcs: Vec<Vec<u8>>,
    pub text: Vec<u16>,
    pub chpx: Vec<Run>,
    pub papx: Vec<Run>,
    pub fonts: Vec<String>,
    pub stsh: styles::Stsh,
    pub style_ids: Vec<Option<String>>,
    pub rpr_cache: HashMap<u16, RunProps>,
    pub ppr_cache: HashMap<u16, ParaProps>,
    pub sections: Vec<SectionSpan>,
    pub ftn_ref: Vec<u32>,
    pub ftn_txt: Vec<u32>,
    pub edn_ref: Vec<u32>,
    pub edn_txt: Vec<u32>,
    pub atn_ref: Vec<(u32, String, usize)>,
    pub atn_txt: Vec<u32>,
    pub owners: Vec<String>,
    /// (cp, is end, id) of bookmark and comment-range marks, by cp.
    pub marks: Vec<(u32, u8, u32)>,
    pub spa_main: Vec<Spa>,
    pub spa_hdr: Vec<Spa>,
    pub txbx_main: Plc,
    pub txbx_hdr: Plc,
    pub hdd: Plc,
    pub bookmark_names: Vec<String>,
    pub depth: u32,
    pub facing: bool,
    pub rpr_delta: HashMap<u16, RunProps>,
    /// Sections not yet put on the paragraph that ends them.
    pub sect_ready: Vec<Option<Section>>,
    /// A Word 6 or 95 file, whose pictures and tables sit in the main stream.
    pub word6: bool,
}

pub(crate) fn read(input: &[u8], budget: &mut Budget) -> Result<Document> {
    let cf = Compound::open(input).ok_or_else(|| Error::NotFormat("not a compound file".into()))?;
    let max = budget.limits.max_part as usize;
    let wd = cf
        .stream(&["WordDocument"])
        .ok_or_else(|| Error::NotFormat("no WordDocument stream".into()))?;
    if wd.len() > max {
        return Err(Error::TooLarge("the WordDocument stream"));
    }
    if matches!(u16_at(&wd, 0), 0xA5DB | 0xA5DC) {
        return word6::read(wd, budget);
    }
    let fib = Fib::read(&wd)?;
    // XOR obfuscation (fObfuscated) is only set together with fEncrypted.
    if fib.encrypted {
        return Err(Error::Encrypted);
    }
    if fib.n_fib < 0xC1 {
        return Err(Error::Unsupported(format!(
            "Word version {:#06x}",
            fib.n_fib
        )));
    }
    let tbl = cf
        .stream(&[if fib.which_table { "1Table" } else { "0Table" }])
        .ok_or_else(|| Error::Malformed("no table stream".into()))?;
    if tbl.len() > max {
        return Err(Error::TooLarge("the table stream"));
    }
    let data = cf.stream(&["Data"]).unwrap_or_default();
    budget.alloc((wd.len() + tbl.len() + data.len()) as u64)?;
    let (clx_off, clx_len) = fib.at(idx::CLX);
    let clx = fib::read_clx(&tbl, clx_off, clx_len)?;
    let total = usize::try_from(fib.total_cp()).unwrap_or(usize::MAX);
    let last = clx.pieces.iter().map(|p| p.cp1 as usize).max().unwrap_or(0);
    let total = total
        .min(last)
        .max(fib.ccp_text.max(0) as usize)
        .min(last.max(1));
    if total > 1 << 28 {
        return Err(Error::TooLarge("characters"));
    }
    budget.alloc(2 * total as u64)?;
    let text = fib::read_text(&wd, &clx.pieces, total);
    let mut r = Reader::new(budget, wd, tbl, data, fib, clx, text);
    r.load()?;
    r.convert()?;
    Ok(r.doc)
}

impl<'a> Reader<'a> {
    /// A reader of the streams and text, with nothing else read yet.
    pub(crate) fn new(
        b: &'a mut Budget,
        wd: Vec<u8>,
        tbl: Vec<u8>,
        data: Vec<u8>,
        fib: Fib,
        clx: fib::Clx,
        text: Vec<u16>,
    ) -> Reader<'a> {
        let empty = || Plc {
            cps: vec![],
            data: vec![],
        };
        Reader {
            b,
            doc: Document::default(),
            wd,
            tbl,
            data,
            fib,
            pieces: clx.pieces,
            prcs: clx.prcs,
            text,
            chpx: vec![],
            papx: vec![],
            fonts: vec![],
            stsh: styles::Stsh::default(),
            style_ids: vec![],
            rpr_cache: HashMap::new(),
            ppr_cache: HashMap::new(),
            sections: vec![],
            ftn_ref: vec![],
            ftn_txt: vec![],
            edn_ref: vec![],
            edn_txt: vec![],
            atn_ref: vec![],
            atn_txt: vec![],
            owners: vec![],
            marks: vec![],
            spa_main: vec![],
            spa_hdr: vec![],
            txbx_main: empty(),
            txbx_hdr: empty(),
            hdd: empty(),
            bookmark_names: vec![],
            depth: 0,
            facing: false,
            rpr_delta: HashMap::new(),
            sect_ready: vec![],
            word6: false,
        }
    }
}

fn utf16(b: &[u8]) -> String {
    let u: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|x| u16::from_le_bytes(*x))
        .collect();
    String::from_utf16_lossy(&u)
}

impl Reader<'_> {
    fn load(&mut self) -> Result<()> {
        self.read_fonts();
        let (o, l) = self.fib.at(idx::STSHF);
        self.stsh = styles::read(&self.tbl, o, l);
        self.read_fkps();
        self.read_dop();
        self.read_sections();
        self.read_notes();
        self.read_bookmarks();
        self.read_shapes_table();
        let (o, l) = self.fib.at(idx::PLCF_HDD);
        self.hdd = read_plc(&self.tbl, o, l, 0);
        Ok(())
    }

    fn read_fonts(&mut self) {
        let (o, l) = self.fib.at(idx::STTBF_FFN);
        let Some(d) = self.tbl.get(o..o.saturating_add(l).min(self.tbl.len())) else {
            return;
        };
        if d.len() < 4 {
            return;
        }
        // An STTB without the extended header: cData, cbExtra, then FFNs.
        let n = usize::from(u16_at(d, 0));
        let mut p = 2usize;
        let cb_extra = usize::from(u16_at(d, 2));
        let _ = cb_extra;
        p += 2;
        for _ in 0..n.min(4096) {
            let Some(&cb) = d.get(p) else { break };
            let cb = usize::from(cb);
            let ffn = d.get(p + 1..p + 1 + cb).unwrap_or(&[]);
            // FFN: flags, weight (2), charset, alt name index, panose (10),
            // font signature (24), then the name.
            let name = ffn.get(39..).unwrap_or(&[]);
            let end = name
                .as_chunks::<2>()
                .0
                .iter()
                .position(|c| *c == [0, 0])
                .map(|k| k * 2)
                .unwrap_or(name.len() & !1);
            self.fonts.push(utf16(&name[..end]));
            p += 1 + cb;
        }
    }

    /// The FKP pages of character and paragraph formatting, as sorted runs.
    fn read_fkps(&mut self) {
        for (which, para) in [(idx::PLCF_BTE_CHPX, false), (idx::PLCF_BTE_PAPX, true)] {
            let (o, l) = self.fib.at(which);
            let plc = read_plc(&self.tbl, o, l, 4);
            let mut runs = vec![];
            for pn in plc.data.iter().map(|d| u32_at(d, 0) & 0x3F_FFFF) {
                let base = pn as usize * 512;
                let Some(page) = self.wd.get(base..base + 512) else {
                    continue;
                };
                let n = usize::from(page[511]);
                if n == 0 || 4 * (n + 1) + n > 511 {
                    continue;
                }
                for k in 0..n {
                    let lo = u32_at(page, 4 * k);
                    let hi = u32_at(page, 4 * (k + 1));
                    // The modifier list's place in the page, if it has one.
                    let at = if para {
                        let bx = 4 * (n + 1) + 13 * k;
                        let o2 = usize::from(page.get(bx).copied().unwrap_or(0)) * 2;
                        if o2 == 0 || o2 >= 511 {
                            None
                        } else {
                            let cb = usize::from(page[o2]);
                            if cb == 0 {
                                let cb2 = usize::from(page.get(o2 + 1).copied().unwrap_or(0));
                                Some((o2 + 2, cb2 * 2))
                            } else {
                                Some((o2 + 1, cb * 2 - 1))
                            }
                        }
                    } else {
                        let o2 = usize::from(page[4 * (n + 1) + k]) * 2;
                        if o2 == 0 || o2 >= 511 {
                            None
                        } else {
                            Some((o2 + 1, usize::from(page[o2])))
                        }
                    };
                    let (off, len) = match at {
                        // The list must lie in the page.
                        Some((o, l)) => (base + o, l.min(512 - o)),
                        None => (0, 0),
                    };
                    if hi > lo {
                        runs.push(Run {
                            lo,
                            hi,
                            off: off as u32,
                            len: len as u16,
                        });
                    }
                }
            }
            runs.sort_by_key(|r| r.lo);
            if para {
                self.papx = runs;
            } else {
                self.chpx = runs;
            }
        }
    }

    fn read_dop(&mut self) {
        let (o, l) = self.fib.at(idx::DOP);
        let Some(d) = self.tbl.get(o..o.saturating_add(l).min(self.tbl.len())) else {
            return;
        };
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

    fn read_sections(&mut self) {
        let (o, l) = self.fib.at(idx::PLCF_SED);
        let plc = read_plc(&self.tbl, o, l, 12);
        for (i, d) in plc.data.iter().enumerate() {
            let fc = u32_at(d, 2);
            let grpprl = if fc == 0xFFFF_FFFF {
                vec![]
            } else {
                let cb = usize::from(u16_at(&self.wd, fc as usize));
                self.wd
                    .get(fc as usize + 2..fc as usize + 2 + cb)
                    .unwrap_or(&[])
                    .to_vec()
            };
            self.sections.push(SectionSpan {
                cp1: plc.cps[i + 1],
                grpprl,
            });
        }
        if self.sections.is_empty() {
            self.sections.push(SectionSpan {
                cp1: self.fib.ccp_text as u32,
                grpprl: vec![],
            });
        }
    }

    fn read_notes(&mut self) {
        let f = &self.fib;
        let base_ftn = fib::cp(f.ccp_text);
        let base_atn = fib::cp(f.ccp_text + f.ccp_ftn + f.ccp_hdd);
        let base_edn = fib::cp(f.ccp_text + f.ccp_ftn + f.ccp_hdd + f.ccp_atn);
        let (o, l) = self.fib.at(idx::PLCFFND_REF);
        self.ftn_ref = read_plc(&self.tbl, o, l, 2).cps;
        self.ftn_ref.pop();
        let (o, l) = self.fib.at(idx::PLCFFND_TXT);
        self.ftn_txt = read_plc(&self.tbl, o, l, 0)
            .cps
            .iter()
            .map(|c| c.saturating_add(base_ftn))
            .collect();
        let (o, l) = self.fib.at(idx::PLCFEND_REF);
        self.edn_ref = read_plc(&self.tbl, o, l, 2).cps;
        self.edn_ref.pop();
        let (o, l) = self.fib.at(idx::PLCFEND_TXT);
        self.edn_txt = read_plc(&self.tbl, o, l, 0)
            .cps
            .iter()
            .map(|c| c.saturating_add(base_edn))
            .collect();
        // Comments: reference marks with initials and author index.
        let (o, l) = self.fib.at(idx::GRP_XST_ATN_OWNERS);
        if let Some(d) = self.tbl.get(o..o.saturating_add(l).min(self.tbl.len())) {
            let mut p = 0usize;
            // An STTB of authors: the extended header, then strings.
            if u16_at(d, 0) == 0xFFFF {
                let n = usize::from(u16_at(d, 2));
                p = 6;
                for _ in 0..n.min(1024) {
                    let cch = usize::from(u16_at(d, p));
                    let s = d.get(p + 2..p + 2 + cch * 2).unwrap_or(&[]);
                    self.owners.push(utf16(s));
                    p += 2 + cch * 2;
                }
            } else {
                while p + 2 <= d.len() && self.owners.len() < 1024 {
                    let cch = usize::from(u16_at(d, p));
                    let s = d.get(p + 2..p + 2 + cch * 2).unwrap_or(&[]);
                    self.owners.push(utf16(s));
                    p += 2 + cch * 2;
                }
            }
        }
        let (o, l) = self.fib.at(idx::PLCFAND_REF);
        let plc = read_plc(&self.tbl, o, l, 30);
        for (i, d) in plc.data.iter().enumerate() {
            let cch = usize::from(u16_at(d, 0)).min(9);
            let initials = utf16(d.get(2..2 + cch * 2).unwrap_or(&[]));
            let ibst = usize::from(u16_at(d, 20));
            self.atn_ref.push((plc.cps[i], initials, ibst));
        }
        let (o, l) = self.fib.at(idx::PLCFAND_TXT);
        self.atn_txt = read_plc(&self.tbl, o, l, 0)
            .cps
            .iter()
            .map(|c| c.saturating_add(base_atn))
            .collect();
    }

    fn read_bookmarks(&mut self) {
        let (o, l) = self.fib.at(idx::STTBF_BKMK);
        if let Some(d) = self.tbl.get(o..o.saturating_add(l).min(self.tbl.len())) {
            if u16_at(d, 0) == 0xFFFF && d.len() >= 6 {
                let n = usize::from(u16_at(d, 2));
                let extra = usize::from(u16_at(d, 4));
                let mut p = 6usize;
                for _ in 0..n.min(1 << 16) {
                    let cch = usize::from(u16_at(d, p));
                    let s = d.get(p + 2..p + 2 + cch * 2).unwrap_or(&[]);
                    self.bookmark_names.push(utf16(s));
                    p += 2 + cch * 2 + extra;
                }
            }
        }
        let (o, l) = self.fib.at(idx::PLCF_BKF);
        let bkf = read_plc(&self.tbl, o, l, 6);
        let (o, l) = self.fib.at(idx::PLCF_BKL);
        let bkl = read_plc(&self.tbl, o, l, 0);
        for (i, d) in bkf.data.iter().enumerate() {
            let Some(name) = self.bookmark_names.get(i) else {
                continue;
            };
            if name.starts_with('_') && !name.starts_with("_Toc") && !name.starts_with("_Ref") {
                continue;
            }
            let ibkl = u32_at(d, 0) as usize;
            let (Some(&start), Some(&end)) = (bkf.cps.get(i), bkl.cps.get(ibkl)) else {
                continue;
            };
            let id = i as u32;
            self.marks.push((start, 0, id));
            self.marks.push((end.max(start), 1, id));
        }
        // Comment ranges.
        let (o, l) = self.fib.at(idx::PLCF_ATN_BKF);
        let bkf = read_plc(&self.tbl, o, l, 6);
        let (o, l) = self.fib.at(idx::PLCF_ATN_BKL);
        let bkl = read_plc(&self.tbl, o, l, 0);
        for (i, d) in bkf.data.iter().enumerate() {
            let ibkl = u32_at(d, 0) as usize;
            let (Some(&start), Some(&end)) = (bkf.cps.get(i), bkl.cps.get(ibkl)) else {
                continue;
            };
            // The i-th range belongs to the comment with the same bookmark tag;
            // the files pair them by index in practice.
            let id = 1_000_000 + i as u32;
            self.marks.push((start, 2, id));
            self.marks.push((end.max(start), 3, id));
        }
        self.marks.sort_by_key(|m| (m.0, m.1));
    }

    fn read_shapes_table(&mut self) {
        for (which, hdr) in [(idx::PLC_SPA_MOM, false), (idx::PLC_SPA_HDR, true)] {
            let (o, l) = self.fib.at(which);
            let plc = read_plc(&self.tbl, o, l, 26);
            let mut v = vec![];
            for (i, d) in plc.data.iter().enumerate() {
                let rect = [
                    u32_at(d, 4) as i32,
                    u32_at(d, 8) as i32,
                    u32_at(d, 12) as i32,
                    u32_at(d, 16) as i32,
                ];
                v.push(Spa {
                    cp: plc.cps[i],
                    lid: u32_at(d, 0),
                    rect,
                    flags: u16_at(d, 20),
                });
            }
            if hdr {
                self.spa_hdr = v;
            } else {
                self.spa_main = v;
            }
        }
        let (o, l) = self.fib.at(idx::PLCFTXBX_TXT);
        self.txbx_main = read_plc(&self.tbl, o, l, 22);
        let (o, l) = self.fib.at(idx::PLCF_HDR_TXBX_TXT);
        self.txbx_hdr = read_plc(&self.tbl, o, l, 22);
    }

    /// Base of each document part in CP space.
    pub(crate) fn base_hdd(&self) -> u32 {
        (self.fib.ccp_text + self.fib.ccp_ftn) as u32
    }

    pub(crate) fn base_txbx(&self) -> u32 {
        (self.fib.ccp_text
            + self.fib.ccp_ftn
            + self.fib.ccp_hdd
            + self.fib.ccp_atn
            + self.fib.ccp_edn) as u32
    }

    pub(crate) fn base_hdr_txbx(&self) -> u32 {
        self.base_txbx() + self.fib.ccp_txbx as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plc_splits_positions_and_data() {
        let mut d = vec![];
        for cp in [0u32, 5, 9] {
            d.extend_from_slice(&cp.to_le_bytes());
        }
        d.extend_from_slice(&[1, 2, 3, 4]);
        let p = read_plc(&d, 0, d.len(), 2);
        assert_eq!(p.cps, vec![0, 5, 9]);
        assert_eq!(p.data, vec![vec![1, 2], vec![3, 4]]);
        let p = read_plc(&d[..12], 0, 12, 0);
        assert_eq!(p.cps, vec![0, 5, 9]);
    }
}
