//! The text of the document parts: paragraphs, runs, fields, tables and the
//! notes, comments, headers and footers around them.

use super::fib::{self, idx};
use super::props::*;
use super::sprm::parse;
use super::tables::{Tap, parse_tap};
use super::{Reader, Run as FkpRun};
use crate::formats::office::common::bytes::u16_at;
use crate::formats::office::docs::error::Result;
use crate::formats::office::docs::fields::parse_hyperlink;
use crate::formats::office::docs::limits::PARA_BYTES;
use crate::formats::office::docs::model::*;
use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Story {
    Main,
    Footnote,
    Endnote,
    Header,
    Comment,
    Textbox,
}

/// The sprm that a Prm0 stands for.
fn prm0_opcode(isprm: u8) -> Option<u16> {
    Some(match isprm {
        0x00 => 0x2879,
        0x04 => 0x2602,
        0x05 => 0x2461,
        0x07 => 0x2405,
        0x08 => 0x2406,
        0x09 => 0x2407,
        0x0C => 0x260A,
        0x0D => 0x2470,
        0x0E => 0x240C,
        0x0F => 0x2471,
        0x18 => 0x2416,
        0x19 => 0x2417,
        0x1D => 0x261B,
        0x25 => 0x2423,
        0x2C => 0x242A,
        0x32 => 0x2430,
        0x33 => 0x2431,
        0x35 => 0x2433,
        0x36 => 0x2434,
        0x37 => 0x2435,
        0x38 => 0x2436,
        0x39 => 0x2437,
        0x3A => 0x2438,
        0x41 => 0x0800,
        0x42 => 0x0801,
        0x43 => 0x0802,
        0x47 => 0x0806,
        0x4B => 0x080A,
        0x4D => 0x2A0C,
        0x4E => 0x0858,
        0x4F => 0x2859,
        0x50 => 0x0811,
        0x51 => 0x0818,
        0x53 => 0x2A33,
        0x55 => 0x0835,
        0x56 => 0x0836,
        0x57 => 0x0837,
        0x58 => 0x0838,
        0x59 => 0x0839,
        0x5A => 0x083A,
        0x5B => 0x083B,
        0x5C => 0x083C,
        0x5E => 0x2A3E,
        0x62 => 0x2A42,
        0x68 => 0x2A48,
        0x73 => 0x2A53,
        0x74 => 0x0854,
        0x75 => 0x0855,
        0x76 => 0x0856,
        0x78 => 0x2640,
        0x7B => 0x2A90,
        0x7C => 0x2A86,
        0x7E => 0x2443,
        _ => return None,
    })
}

struct Span {
    rp: RunProps,
    aux: ChpAux,
}

struct Atom {
    cp: u32,
    ch: u16,
    span: usize,
}

/// A paragraph found in the text.
struct ParaRec {
    depth: u32,
    role: Role,
    para: Option<Para>,
    tap: Option<Tap>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Role {
    Normal,
    CellEnd,
    RowEnd,
}

struct TableBuilder {
    rows: Vec<(Tap, Vec<Vec<Block>>)>,
    cells: Vec<Vec<Block>>,
    cur: Vec<Block>,
}

/// Deleted and inserted text is drawn in this colour, whoever made the change.
const REVISION_COLOR: u32 = 0xC00000;

/// The headers or footers `src` has that `dst` has not.
fn inherit(dst: &mut HeaderFooter, src: HeaderFooter, title_page: bool, facing: bool) {
    dst.default = dst.default.take().or(src.default);
    if title_page {
        dst.first = dst.first.take().or(src.first);
    }
    if facing {
        dst.even = dst.even.take().or(src.even);
    }
}

impl Reader<'_> {
    pub(crate) fn convert(&mut self) -> Result<()> {
        self.build_styles();
        self.build_lists();
        // Sections and their headers first: the body puts each on the
        // paragraph that ends it.
        let n = self.sections.len();
        for i in 0..n {
            let mut s = self.section_props(i);
            self.section_stories(i, &mut s)?;
            self.sect_ready.push(Some(s));
        }
        // A section with no text has no paragraph to carry its headers; the
        // next section, which links to them when it has none, takes them.
        let mut start = 0;
        for i in 0..n.saturating_sub(1) {
            let end = self.sections[i].cp1;
            if end <= start
                && let Some(src) = self.sect_ready[i].take()
                && let Some(dst) = self.sect_ready[i + 1].as_mut()
            {
                inherit(&mut dst.headers, src.headers, dst.title_page, self.facing);
                inherit(&mut dst.footers, src.footers, dst.title_page, self.facing);
            }
            start = end;
        }
        let ccp = self.fib.ccp_text as u32;
        let ccp = ccp.min(self.text.len() as u32);
        let body = self.story_blocks(0, ccp, Story::Main)?;
        self.doc.body = body;
        self.doc.section = self
            .sect_ready
            .last_mut()
            .and_then(|s| s.take())
            .unwrap_or_default();
        self.read_note_stories()?;
        self.apply_defaults();
        Ok(())
    }

    fn apply_defaults(&mut self) {
        let f = |me: &Reader, i: i16| {
            me.fonts
                .get(usize::try_from(i).unwrap_or(usize::MAX))
                .cloned()
        };
        let s = &self.stsh;
        let fonts = Fonts {
            ascii: f(self, s.ftc_ascii),
            hansi: f(self, s.ftc_other),
            east_asia: f(self, s.ftc_fe),
            cs: s.ftc_bi.and_then(|b| f(self, b)),
        };
        self.doc.defaults_run.fonts = fonts;
    }

    // ---- styles ----

    fn style_id_for(&self, istd: u16) -> Option<String> {
        self.style_ids.get(usize::from(istd)).cloned().flatten()
    }

    fn build_styles(&mut self) {
        let n = self.stsh.stds.len();
        let mut used: HashSet<String> = HashSet::new();
        let mut ids = vec![None; n];
        for (i, s) in self.stsh.stds.iter().enumerate() {
            let Some(s) = s else { continue };
            let base = match (i, s.sti) {
                (_, 0) => "Normal".to_string(),
                (_, 1..=9) => format!("Heading{}", s.sti),
                (_, 65) => "DefaultParagraphFont".to_string(),
                (_, 105) => "TableNormal".to_string(),
                (_, 107) => "NoList".to_string(),
                _ => {
                    let c: String = s
                        .name
                        .split(',')
                        .next()
                        .unwrap_or("")
                        .chars()
                        .filter(|c| c.is_alphanumeric())
                        .collect();
                    if c.is_empty() {
                        format!("Style{i}")
                    } else if c.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                        format!("S{c}")
                    } else {
                        c
                    }
                }
            };
            let mut id = base.clone();
            let mut k = 2;
            while !used.insert(id.clone()) {
                id = format!("{base}{k}");
                k += 1;
            }
            ids[i] = Some(id);
        }
        self.style_ids = ids;
        let mut out = vec![];
        for i in 0..n {
            let Some(std) = self.stsh.stds[i].as_ref() else {
                continue;
            };
            let kind = match std.kind {
                1 => StyleKind::Paragraph,
                2 => StyleKind::Character,
                3 => StyleKind::Table,
                4 => StyleKind::Numbering,
                _ => continue,
            };
            let name = std.name.split(',').next().unwrap_or("").to_string();
            let name = match std.sti {
                0 => "Normal".to_string(),
                1..=9 => format!("heading {}", std.sti),
                65 => "Default Paragraph Font".to_string(),
                105 => "Normal Table".to_string(),
                107 => "No List".to_string(),
                _ => name,
            };
            let (std_base, std_next, std_link, std_sti) = (std.base, std.next, std.link, std.sti);
            let id = self.style_ids[i].clone().unwrap_or_default();
            let mut st = Style::new(&id, &name, kind);
            st.based_on = (std_base != 0x0FFF && usize::from(std_base) != i)
                .then(|| self.style_id_for(std_base))
                .flatten();
            st.next = (usize::from(std_next) != i)
                .then(|| self.style_id_for(std_next))
                .flatten();
            st.link = (std_link != 0)
                .then(|| self.style_id_for(std_link))
                .flatten();
            st.default = matches!(
                (std_sti, kind),
                (0, StyleKind::Paragraph)
                    | (65, StyleKind::Character)
                    | (105, StyleKind::Table)
                    | (107, StyleKind::Numbering)
            );
            st.q_format = std_sti <= 9;
            let (_, delta) = self.style_rpr(i as u16, 0);
            st.rpr = delta;
            st.ppr = self.style_ppr(i as u16);
            if kind == StyleKind::Table {
                st.tbl = Some(TableProps::default());
            }
            out.push(st);
        }
        self.doc.styles = out;
    }

    /// The character properties of a style: all of them (own and inherited),
    /// and the ones it sets itself.
    fn style_rpr(&mut self, istd: u16, depth: u32) -> (RunProps, RunProps) {
        if let Some(r) = self.rpr_cache.get(&istd) {
            let d = self.rpr_delta.get(&istd).cloned().unwrap_or_default();
            return (r.clone(), d);
        }
        let Some(std) = self
            .stsh
            .stds
            .get(usize::from(istd))
            .and_then(|s| s.as_ref())
        else {
            return (RunProps::default(), RunProps::default());
        };
        let (base_istd, chpx, kind) = (std.base, std.chpx.clone(), std.kind);
        let base = if base_istd != 0x0FFF && base_istd != istd && depth < 32 {
            self.style_rpr(base_istd, depth + 1).0
        } else {
            RunProps::default()
        };
        let fonts = self.fonts.clone();
        let cx = Ctx {
            fonts: &fonts,
            base: &base,
        };
        let mut delta = RunProps::default();
        let mut aux = ChpAux::default();
        apply_chp_list(&mut delta, &mut aux, &chpx, &cx);
        let _ = kind;
        let mut all = base;
        all.overlay(&delta);
        self.rpr_cache.insert(istd, all.clone());
        self.rpr_delta.insert(istd, delta.clone());
        (all, delta)
    }

    /// The paragraph properties a style sets itself.
    fn style_ppr(&mut self, istd: u16) -> ParaProps {
        let Some(std) = self
            .stsh
            .stds
            .get(usize::from(istd))
            .and_then(|s| s.as_ref())
        else {
            return ParaProps::default();
        };
        let papx = std.papx.clone();
        let mut pp = ParaProps::default();
        let mut aux = PapAux::default();
        let g = papx.get(2..).unwrap_or(&[]);
        apply_pap_list(&mut pp, &mut aux, g);
        if let Some(l) = aux.ilfo_set {
            if l > 0 {
                pp.num_id = Some(l as u32);
                pp.num_level = Some(u32::from(aux.ilvl));
            } else if l == 0 {
                pp.num_id = Some(0);
            }
        }
        self.ppr_cache.insert(istd, pp.clone());
        pp
    }

    fn style_numbered(&self, istd: u16, depth: u32) -> bool {
        let Some(pp) = self.ppr_cache.get(&istd) else {
            return false;
        };
        if pp.num_id.is_some_and(|n| n > 0) {
            return true;
        }
        if pp.num_id == Some(0) || depth > 32 {
            return false;
        }
        match self
            .stsh
            .stds
            .get(usize::from(istd))
            .and_then(|s| s.as_ref())
        {
            Some(s) if s.base != 0x0FFF && s.base != istd => self.style_numbered(s.base, depth + 1),
            _ => false,
        }
    }

    fn build_lists(&mut self) {
        let (lo, ll) = self.fib.at(idx::PLF_LST);
        let (fo, fl) = self.fib.at(idx::PLF_LFO);
        let base = RunProps::default();
        let fonts = self.fonts.clone();
        let ids = self.style_ids.clone();
        let cx = Ctx {
            fonts: &fonts,
            base: &base,
        };
        let lists = super::lists::read(&self.tbl, (lo, ll), (fo, fl), &cx, &|i| {
            ids.get(usize::from(i)).cloned().flatten()
        });
        self.doc.numbering = lists.numbering;
    }

    // ---- sections ----

    fn section_props(&mut self, i: usize) -> Section {
        let mut s = Section {
            left: 1800,
            right: 1800,
            ..Section::default()
        };
        let g = self.sections[i].grpprl.clone();
        apply_sep(&mut s, &g);
        s.top = s.top.abs();
        s.bottom = s.bottom.abs();
        s
    }

    fn section_stories(&mut self, i: usize, s: &mut Section) -> Result<()> {
        let base = self.base_hdd();
        for k in 0..6usize {
            let n = 6 + 6 * i + k;
            let (Some(&a), Some(&b)) = (self.hdd.cps.get(n), self.hdd.cps.get(n + 1)) else {
                continue;
            };
            if b <= a.saturating_add(1) {
                continue;
            }
            let (Some(lo), Some(hi)) = (base.checked_add(a), base.checked_add(b - 1)) else {
                continue;
            };
            if hi as usize > self.text.len() {
                continue;
            }
            let blocks = self.story_blocks(lo, hi, Story::Header)?;
            if blocks.is_empty() {
                continue;
            }
            match k {
                0 => s.headers.even = Some(blocks),
                1 => s.headers.default = Some(blocks),
                2 => s.footers.even = Some(blocks),
                3 => s.footers.default = Some(blocks),
                4 => s.headers.first = Some(blocks),
                _ => s.footers.first = Some(blocks),
            }
        }
        if !s.title_page {
            s.headers.first = None;
            s.footers.first = None;
        }
        if !self.facing {
            s.headers.even = None;
            s.footers.even = None;
        }
        Ok(())
    }

    // ---- notes and comments ----

    fn read_note_stories(&mut self) -> Result<()> {
        let limit_ftn = (self.fib.ccp_text + self.fib.ccp_ftn) as u32;
        for i in 0..self.ftn_ref.len() {
            let (Some(&a), Some(&b)) = (self.ftn_txt.get(i), self.ftn_txt.get(i + 1)) else {
                break;
            };
            let b = b.min(limit_ftn).min(self.text.len() as u32);
            if a >= b {
                continue;
            }
            let content = self.story_blocks(a, b, Story::Footnote)?;
            self.doc.footnotes.push(Note {
                id: i as u32 + 1,
                content,
            });
        }
        let f = &self.fib;
        let limit_edn = fib::cp(f.ccp_text + f.ccp_ftn + f.ccp_hdd + f.ccp_atn + f.ccp_edn);
        let limit_atn = fib::cp(f.ccp_text + f.ccp_ftn + f.ccp_hdd + f.ccp_atn);
        for i in 0..self.edn_ref.len() {
            let (Some(&a), Some(&b)) = (self.edn_txt.get(i), self.edn_txt.get(i + 1)) else {
                break;
            };
            let b = b.min(limit_edn).min(self.text.len() as u32);
            if a >= b {
                continue;
            }
            let content = self.story_blocks(a, b, Story::Endnote)?;
            self.doc.endnotes.push(Note {
                id: i as u32 + 1,
                content,
            });
        }
        for i in 0..self.atn_ref.len() {
            let (Some(&a), Some(&b)) = (self.atn_txt.get(i), self.atn_txt.get(i + 1)) else {
                break;
            };
            let b = b.min(limit_atn).min(self.text.len() as u32);
            if a >= b {
                continue;
            }
            let content = self.story_blocks(a, b, Story::Comment)?;
            let (_, initials, ibst) = self.atn_ref[i].clone();
            self.doc.comments.push(Comment {
                id: i as u32,
                author: self.owners.get(ibst).cloned().unwrap_or_default(),
                initials,
                date: None,
                content,
            });
        }
        Ok(())
    }

    // ---- paragraphs ----

    fn piece_index(&self, cp: u32) -> Option<usize> {
        let i = self.pieces.partition_point(|p| p.cp1 <= cp);
        (i < self.pieces.len() && self.pieces[i].cp0 <= cp).then_some(i)
    }

    /// The byte offset in the WordDocument stream of text at `cp`.
    fn fc_at(&self, cp: u32) -> Option<u32> {
        let i = self.piece_index(cp)?;
        Some(self.pieces[i].fc_of(cp))
    }

    fn lookup(runs: &[FkpRun], fc: u32) -> Option<&FkpRun> {
        let i = runs.partition_point(|r| r.lo <= fc);
        if i == 0 {
            return None;
        }
        let r = &runs[i - 1];
        (fc < r.hi).then_some(r)
    }

    /// The modifiers a piece's Prm adds, as a list.
    fn prm_grpprl(&self, piece: usize) -> Vec<u8> {
        let prm = self.pieces[piece].prm;
        if prm == 0 {
            return vec![];
        }
        if prm & 1 != 0 {
            return self
                .prcs
                .get(usize::from(prm >> 1))
                .cloned()
                .unwrap_or_default();
        }
        let isprm = ((prm >> 1) & 0x7F) as u8;
        let val = (prm >> 8) as u8;
        match prm0_opcode(isprm) {
            Some(op) => vec![op as u8, (op >> 8) as u8, val],
            None => vec![],
        }
    }

    /// Paragraph modifiers at `cp` (the paragraph's last character) and the
    /// style they start with.
    fn para_grpprl(&self, cp: u32) -> (u16, Vec<u8>) {
        let Some(fc) = self.fc_at(cp) else {
            return (0, vec![]);
        };
        let mut istd = 0u16;
        let mut g = vec![];
        if let Some(r) = Self::lookup(&self.papx, fc)
            && r.len >= 2
        {
            let b = &self.wd[r.off as usize..r.off as usize + usize::from(r.len)];
            istd = u16_at(b, 0);
            g.extend_from_slice(&b[2..]);
        }
        if let Some(pi) = self.piece_index(cp) {
            g.extend(self.prm_grpprl(pi));
        }
        (istd, g)
    }

    /// Runs of `a..b` with their character modifier lists.
    fn char_runs(&self, a: u32, b: u32) -> Vec<(u32, u32, Vec<u8>)> {
        let mut out = vec![];
        let mut cp = a;
        while cp < b {
            let Some(pi) = self.piece_index(cp) else {
                break;
            };
            let p = &self.pieces[pi];
            let end = b.min(p.cp1);
            let prm = self.prm_grpprl(pi);
            let mut c = cp;
            while c < end {
                let fc = p.fc_of(c);
                let ri = self.chpx.partition_point(|r| r.hi <= fc);
                let (run_end_fc, g) = match self.chpx.get(ri) {
                    Some(r) if r.lo <= fc => (
                        r.hi,
                        self.wd[r.off as usize..r.off as usize + usize::from(r.len)].to_vec(),
                    ),
                    Some(r) => (r.lo, vec![]),
                    None => (u32::MAX, vec![]),
                };
                let n = if run_end_fc == u32::MAX {
                    end - c
                } else {
                    ((run_end_fc - fc) / p.unit()).max(1).min(end - c)
                };
                let mut g = g;
                g.extend_from_slice(&prm);
                out.push((c, c + n, g));
                c += n;
            }
            cp = end;
        }
        out
    }

    fn is_section_end(&self, cp_after: u32) -> bool {
        self.section_ending_at(cp_after).is_some()
    }

    /// The blocks of the text `lo..hi` of one part of the document.
    pub(crate) fn story_blocks(&mut self, lo: u32, hi: u32, story: Story) -> Result<Vec<Block>> {
        if self.depth > 8 {
            return Ok(vec![]);
        }
        self.depth += 1;
        let r = self.story_blocks_inner(lo, hi, story);
        self.depth -= 1;
        r
    }

    fn story_blocks_inner(&mut self, lo: u32, hi: u32, story: Story) -> Result<Vec<Block>> {
        let hi = hi.min(self.text.len() as u32);
        let mut out: Vec<Block> = vec![];
        let mut stack: Vec<TableBuilder> = vec![];
        let mut p = lo;
        let in_main = story == Story::Main;
        while p < hi {
            let mut e = p;
            while e < hi {
                let c = self.text[e as usize];
                if c == 0x0D || c == 0x07 || (c == 0x0C && in_main && self.is_section_end(e + 1)) {
                    break;
                }
                e += 1;
            }
            let end = e.min(hi - 1);
            let mut rec = self.para_rec(p, end, story)?;
            if in_main
                && let Some(i) = self.section_ending_at(end + 1)
                && let (Some(para), Some(s)) = (rec.para.as_mut(), self.sect_ready[i].take())
            {
                para.section = Some(Box::new(s));
            }
            let first_depth = rec.depth;
            // Close tables deeper than this paragraph; open new ones.
            while stack.len() as u32 > first_depth {
                let Some(t) = stack.pop() else { break };
                let blocks = self.close_table(t);
                match stack.last_mut() {
                    Some(parent) => parent.cur.extend(blocks),
                    None => out.extend(blocks),
                }
            }
            while (stack.len() as u32) < first_depth {
                stack.push(TableBuilder {
                    rows: vec![],
                    cells: vec![],
                    cur: vec![],
                });
            }
            match (rec.role, rec.para, rec.tap) {
                (Role::RowEnd, _, tap) => {
                    if let Some(t) = stack.last_mut() {
                        let cells = std::mem::take(&mut t.cells);
                        t.cur.clear();
                        t.rows.push((tap.unwrap_or_default(), cells));
                    }
                }
                (role, Some(para), _) => {
                    let block = Block::Para(para);
                    match stack.last_mut() {
                        Some(t) => {
                            t.cur.push(block);
                            if role == Role::CellEnd {
                                self.b.cell()?;
                                let cell = std::mem::take(&mut t.cur);
                                t.cells.push(cell);
                            }
                        }
                        None => out.push(block),
                    }
                }
                _ => {}
            }
            p = end + 1;
        }
        while let Some(t) = stack.pop() {
            let blocks = self.close_table(t);
            match stack.last_mut() {
                Some(parent) => parent.cur.extend(blocks),
                None => out.extend(blocks),
            }
        }
        Ok(out)
    }

    /// The section (but the last) that ends before `cp_after`.
    fn section_ending_at(&self, cp_after: u32) -> Option<usize> {
        let n = self.sections.len();
        self.sections
            .iter()
            .take(n.saturating_sub(1))
            .position(|s| s.cp1 == cp_after)
    }

    fn para_rec(&mut self, ps: u32, pe: u32, story: Story) -> Result<ParaRec> {
        let (istd_papx, g) = self.para_grpprl(pe);
        let mut pp = ParaProps::default();
        let mut aux = PapAux::default();
        apply_pap_list(&mut pp, &mut aux, &g);
        // A huge PAPX keeps its modifiers in the data stream.
        if let Some(off) = aux.huge {
            let o = off as usize;
            let n = usize::from(u16_at(&self.data, o));
            if let Some(extra) = self.data.get(o + 2..o + 2 + n) {
                let extra = extra.to_vec();
                apply_pap_list(&mut pp, &mut aux, &extra);
            }
        }
        let istd = aux.istd.unwrap_or(istd_papx);
        let mark = self.text[pe as usize];
        let depth = match aux.depth {
            Some(d) => d,
            None => u32::from(aux.in_table),
        };
        let depth = if depth == 0 && (aux.in_table || aux.ttp) {
            1
        } else {
            depth
        };
        let ttp = (mark == 0x07 && aux.ttp) || aux.inner_ttp;
        let cell_end = depth > 0 && !ttp && (mark == 0x07 || aux.inner_cell);
        let role = if ttp {
            Role::RowEnd
        } else if cell_end {
            Role::CellEnd
        } else {
            Role::Normal
        };
        if role == Role::RowEnd {
            let tap = parse_tap(&g);
            return Ok(ParaRec {
                depth,
                role,
                para: None,
                tap: Some(tap),
            });
        }
        self.b
            .paragraph((pe - ps) as usize * 2 + PARA_BYTES as usize / 4)?;
        // Style and numbering.
        if istd != 0 {
            pp.style = self.style_id_for(istd);
        }
        match aux.ilfo_set {
            Some(l) if l > 0 => {
                pp.num_id = Some(l as u32);
                pp.num_level = Some(u32::from(aux.ilvl));
            }
            Some(l) if l < 0 && l > -0x7FE => {
                pp.num_id = Some((-l) as u32);
                pp.num_level = Some(u32::from(aux.ilvl));
            }
            Some(0) => {
                if self.style_numbered(istd, 0) {
                    pp.num_id = Some(0);
                }
            }
            _ => {
                if aux.ilvl != 0 && self.style_numbered(istd, 0) {
                    pp.num_level = Some(u32::from(aux.ilvl));
                }
            }
        }
        if let Some((kind, lines)) = aux.drop_cap {
            if kind != 0 {
                let f = pp.frame.get_or_insert_with(Frame::default);
                f.drop_cap = Some(if kind == 2 { "margin" } else { "drop" });
                f.lines = Some(u32::from(lines.max(1)));
                f.wrap = Some("around");
                f.h_anchor = Some("text");
                f.v_anchor = Some("text");
            }
        } else if let Some(f) = aux.frame
            && (f.width.is_some() || f.x.is_some() || f.x_align.is_some() || f.y.is_some())
        {
            pp.frame = Some(f);
        }
        // The paragraph mark's formatting.
        let base = self.base_rpr(istd, None);
        let mut mark_rp = RunProps::default();
        let mut mark_aux = ChpAux::default();
        {
            let g = self.char_runs(pe, pe + 1);
            let fonts = self.fonts.clone();
            let cx = Ctx {
                fonts: &fonts,
                base: &base,
            };
            if let Some((_, _, gr)) = g.first() {
                apply_chp_list(&mut mark_rp, &mut mark_aux, gr, &cx);
            }
        }
        if let Some(c) = mark_aux.istd {
            mark_rp.style = self.style_id_for(c);
        }
        // Content.
        let content = if pe > ps {
            self.inlines_of(ps, pe, istd, story)?
        } else {
            vec![]
        };
        let para = Para {
            props: pp,
            mark: mark_rp,
            content,
            section: None,
        };
        Ok(ParaRec {
            depth,
            role,
            para: Some(para),
            tap: None,
        })
    }

    fn base_rpr(&mut self, para_istd: u16, char_istd: Option<u16>) -> RunProps {
        let mut base = self.style_rpr(para_istd, 0).0;
        if let Some(c) = char_istd {
            let cr = self.style_rpr(c, 0).0;
            base.overlay(&cr);
        }
        base
    }

    // ---- runs ----

    fn inlines_of(
        &mut self,
        ps: u32,
        pe: u32,
        para_istd: u16,
        story: Story,
    ) -> Result<Vec<Inline>> {
        let runs = self.char_runs(ps, pe);
        let mut spans = vec![];
        let mut atoms: Vec<Atom> = Vec::with_capacity((pe - ps) as usize);
        let pbase = self.base_rpr(para_istd, None);
        let fonts = self.fonts.clone();
        for (a, b, g) in &runs {
            let mut rp = RunProps::default();
            let mut aux = ChpAux::default();
            // The character style first: its toggles are the base of the rest.
            let istd = parse(g)
                .iter()
                .rev()
                .find(|p| p.op == 0x4A30)
                .map(|p| p.u16());
            let base = match istd {
                Some(c) => self.base_rpr(para_istd, Some(c)),
                None => pbase.clone(),
            };
            let cx = Ctx {
                fonts: &fonts,
                base: &base,
            };
            apply_chp_list(&mut rp, &mut aux, g, &cx);
            // Tracked changes, as an editor shows them.
            if aux.deleted || aux.inserted {
                rp.color = Some(Color::Rgb(REVISION_COLOR));
                if aux.deleted {
                    rp.strike = Some(true);
                } else {
                    rp.underline = Some("single");
                }
            }
            if let Some(c) = aux.istd {
                rp.style = self.style_id_for(c);
            }
            spans.push(Span { rp, aux });
            let si = spans.len() - 1;
            for cp in *a..*b {
                atoms.push(Atom {
                    cp,
                    ch: self.text[cp as usize],
                    span: si,
                });
            }
        }
        let mut out = vec![];
        let mut mark = self.marks.partition_point(|m| m.0 < ps);
        self.emit(&atoms, &spans, story, &mut out, &mut mark, pe)?;
        // Marks at the end of the paragraph.
        self.flush_marks(pe, &mut mark, &mut out, true);
        Ok(out)
    }

    fn flush_marks(&mut self, upto: u32, mark: &mut usize, out: &mut Vec<Inline>, inclusive: bool) {
        while let Some(&(cp, kind, id)) = self.marks.get(*mark) {
            if cp > upto || (cp == upto && !inclusive) {
                break;
            }
            *mark += 1;
            match kind {
                0 => {
                    if let Some(n) = self.bookmark_names.get(id as usize) {
                        out.push(Inline::BookmarkStart {
                            id,
                            name: n.clone(),
                        });
                    }
                }
                1 => out.push(Inline::BookmarkEnd(id)),
                2 => out.push(Inline::CommentStart(id - 1_000_000)),
                _ => out.push(Inline::CommentEnd(id - 1_000_000)),
            }
        }
    }

    fn emit(
        &mut self,
        atoms: &[Atom],
        spans: &[Span],
        story: Story,
        out: &mut Vec<Inline>,
        mark: &mut usize,
        pe: u32,
    ) -> Result<()> {
        let mut items: Vec<RunItem> = vec![];
        let mut text = String::new();
        let mut cur: Option<usize> = None;
        macro_rules! flush {
            () => {
                if !text.is_empty() {
                    items.push(RunItem::Text(std::mem::take(&mut text)));
                }
                if !items.is_empty() {
                    if let Some(s) = cur {
                        out.push(Inline::Run(Run {
                            props: spans[s].rp.clone(),
                            items: std::mem::take(&mut items),
                        }));
                    } else {
                        items.clear();
                    }
                }
            };
        }
        let mut i = 0;
        while i < atoms.len() {
            let a = &atoms[i];
            if self.marks.get(*mark).is_some_and(|m| m.0 <= a.cp) {
                flush!();
                self.flush_marks(a.cp, mark, out, true);
            }
            if cur != Some(a.span) {
                flush!();
                cur = Some(a.span);
            }
            let span = &spans[a.span];
            match a.ch {
                0x13 => {
                    flush!();
                    let (consumed, inl) = self.field(&atoms[i..], spans, story, pe)?;
                    out.extend(inl);
                    i += consumed.max(1);
                    cur = None;
                    continue;
                }
                0x14 => {
                    flush!();
                    out.push(Inline::FieldChar(FieldCharKind::Separate));
                }
                0x15 => {
                    flush!();
                    out.push(Inline::FieldChar(FieldCharKind::End));
                }
                0x01 if span.aux.spec
                    && !span.aux.data
                    && let Some(loc) = span.aux.pic_loc =>
                {
                    if let Some(d) = self.inline_picture(loc)? {
                        items.push(RunItem::Drawing(Box::new(d)));
                    }
                }
                0x02 if span.aux.spec || story == Story::Footnote || story == Story::Endnote => {
                    if let Ok(k) = self.ftn_ref.binary_search(&a.cp) {
                        items.push(RunItem::FootnoteRef(k as u32 + 1));
                    } else if let Ok(k) = self.edn_ref.binary_search(&a.cp) {
                        items.push(RunItem::EndnoteRef(k as u32 + 1));
                    } else if story == Story::Footnote {
                        items.push(RunItem::NoteMark(false));
                    } else if story == Story::Endnote {
                        items.push(RunItem::NoteMark(true));
                    }
                }
                0x05 if span.aux.spec => {
                    if let Some(k) = self.atn_ref.iter().position(|r| r.0 == a.cp) {
                        items.push(RunItem::CommentRef(k as u32));
                    }
                }
                0x08 if span.aux.spec => {
                    if let Some(d) = self.floating_shape(a.cp, story)? {
                        items.push(RunItem::Drawing(Box::new(d)));
                    }
                }
                0x28 if span.aux.spec
                    && let Some((ftc, ch)) = span.aux.symbol =>
                {
                    let font = self
                        .fonts
                        .get(usize::from(ftc))
                        .cloned()
                        .unwrap_or_else(|| "Symbol".into());
                    items.push(RunItem::Symbol { font, ch });
                }
                0x09 => {
                    if !text.is_empty() {
                        items.push(RunItem::Text(std::mem::take(&mut text)));
                    }
                    items.push(RunItem::Tab);
                }
                0x0B | 0x0A => {
                    if !text.is_empty() {
                        items.push(RunItem::Text(std::mem::take(&mut text)));
                    }
                    items.push(RunItem::Break(BreakKind::Line));
                }
                0x0C => {
                    if !text.is_empty() {
                        items.push(RunItem::Text(std::mem::take(&mut text)));
                    }
                    items.push(RunItem::Break(BreakKind::Page));
                }
                0x0E => {
                    if !text.is_empty() {
                        items.push(RunItem::Text(std::mem::take(&mut text)));
                    }
                    items.push(RunItem::Break(BreakKind::Column));
                }
                0x1E => {
                    if !text.is_empty() {
                        items.push(RunItem::Text(std::mem::take(&mut text)));
                    }
                    items.push(RunItem::NoBreakHyphen);
                }
                0x1F => {
                    if !text.is_empty() {
                        items.push(RunItem::Text(std::mem::take(&mut text)));
                    }
                    items.push(RunItem::SoftHyphen);
                }
                0x00..=0x1F | 0xFFFE | 0xFFFF => {}
                c => {
                    // A surrogate pair stays whole across atoms.
                    if (0xD800..0xDC00).contains(&c) {
                        if let Some(n) = atoms.get(i + 1)
                            && (0xDC00..0xE000).contains(&n.ch)
                        {
                            let ch = char::decode_utf16([c, n.ch])
                                .next()
                                .and_then(|r| r.ok())
                                .unwrap_or('\u{FFFD}');
                            text.push(ch);
                            i += 2;
                            continue;
                        }
                        text.push('\u{FFFD}');
                    } else if let Some(ch) = char::from_u32(u32::from(c)) {
                        text.push(ch);
                    }
                }
            }
            i += 1;
        }
        flush!();
        Ok(())
    }

    /// A field starting at `atoms[0]` (a field begin mark). Returns the
    /// atoms consumed and what to emit.
    fn field(
        &mut self,
        atoms: &[Atom],
        spans: &[Span],
        story: Story,
        pe: u32,
    ) -> Result<(usize, Vec<Inline>)> {
        // The matching separator and end.
        let mut depth = 0i32;
        let mut sep = None;
        let mut end = None;
        for (k, a) in atoms.iter().enumerate() {
            match a.ch {
                0x13 => depth += 1,
                0x14 if depth == 1 && sep.is_none() => sep = Some(k),
                0x15 => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(k);
                        break;
                    }
                }
                _ => {}
            }
        }
        let props = spans[atoms[0].span].rp.clone();
        let instr_end = sep.or(end).unwrap_or(atoms.len());
        let mut instr = String::new();
        let mut d = 0;
        for a in &atoms[1..instr_end] {
            match a.ch {
                0x13 => d += 1,
                0x15 => d -= 1,
                0x14 => {}
                c if d == 0 && c >= 0x20 => {
                    if let Some(ch) = char::from_u32(u32::from(c)) {
                        instr.push(ch);
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            // The field ends in a later paragraph: its marks are kept as they
            // are.
            let mut v = vec![Inline::FieldChar(FieldCharKind::Begin)];
            v.push(Inline::InstrText(instr));
            if sep.is_some() {
                v.push(Inline::FieldChar(FieldCharKind::Separate));
            }
            return Ok((instr_end + usize::from(sep.is_some()), v));
        };
        let result_atoms = match sep {
            Some(s) => &atoms[s + 1..end],
            None => &atoms[end..end],
        };
        let mut result = vec![];
        let mut m = usize::MAX;
        self.emit(result_atoms, spans, story, &mut result, &mut m, pe)?;
        let instr_trim = instr.trim();
        let word = instr_trim
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let inl = match word.as_str() {
            "HYPERLINK" => {
                let (target, anchor, tip) = parse_hyperlink(instr_trim);
                vec![Inline::Hyperlink {
                    target,
                    anchor,
                    tooltip: tip,
                    content: result,
                }]
            }
            "XE" | "TC" | "TA" | "RD" => vec![],
            // A check box has no result text; its state is in the field's
            // form field data.
            "FORMCHECKBOX" => {
                let aux = &spans[atoms[0].span].aux;
                let checked = aux
                    .pic_loc
                    .filter(|_| aux.data)
                    .is_some_and(|at| self.checkbox_checked(at));
                vec![Inline::Run(Run {
                    props,
                    items: vec![RunItem::Text(
                        if checked { "\u{2612}" } else { "\u{2610}" }.into(),
                    )],
                })]
            }
            _ => vec![Inline::Field {
                instr,
                props,
                result,
            }],
        };
        Ok((end + 1, inl))
    }

    // ---- tables ----

    /// Whether the check box whose FFData is at `at` of the data stream is
    /// checked ([MS-DOC] 2.9.78, 2.9.79: a type of 1 and a state of 1).
    fn checkbox_checked(&self, at: i32) -> bool {
        let Some(d) = usize::try_from(at)
            .ok()
            .and_then(|a| self.data.get(a..a + 6))
        else {
            return false;
        };
        let bits = u16_at(d, 4);
        bits & 3 == 1 && (bits >> 2) & 0x1F == 1
    }

    /// The blocks of a table whose end was reached: the table, if it has a
    /// row, and the paragraphs of the cell that was left open (or of cells
    /// whose row never ended) as the plain paragraphs they are.
    fn close_table(&mut self, t: TableBuilder) -> Vec<Block> {
        let TableBuilder { rows, cells, cur } = t;
        let loose = cells.into_iter().flatten().chain(cur);
        if rows.is_empty() {
            return loose.collect();
        }
        let table = super::tables::build(rows);
        if table.rows.is_empty() {
            return loose.collect();
        }
        std::iter::once(Block::Table(table)).chain(loose).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prm0_maps_to_sprms() {
        assert_eq!(prm0_opcode(0x55), Some(0x0835));
        assert_eq!(prm0_opcode(0x01), None);
    }

    #[test]
    fn a_section_takes_the_headers_it_lacks_that_it_shows() {
        let story = || Some(vec![Block::Para(Para::default())]);
        let src = HeaderFooter {
            default: story(),
            first: story(),
            even: story(),
        };
        // No title page and no facing pages: only the default one is taken.
        let mut dst = HeaderFooter::default();
        inherit(&mut dst, src.clone(), false, false);
        assert!(dst.default.is_some() && dst.first.is_none() && dst.even.is_none());
        // Both: all are, but not over what the section has of its own.
        let mut dst = HeaderFooter {
            first: Some(vec![]),
            ..HeaderFooter::default()
        };
        inherit(&mut dst, src, true, true);
        assert!(dst.default.is_some() && dst.even.is_some());
        assert_eq!(dst.first.map(|b| b.len()), Some(0));
    }
}
