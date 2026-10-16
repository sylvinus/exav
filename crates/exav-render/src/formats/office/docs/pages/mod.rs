//! Apple Pages documents of Pages 5 (2013) and later: a ZIP of
//! `Index/*.iwa` streams holding protocol buffer archives. Messages are read
//! by field number; the numbers used are written where they are read, after
//! what the Keynote reader of the `slides` module (itself after
//! keynote-parser's message definitions, MIT) uses for the text messages the
//! two applications share.
//!
//! TP.DocumentArchive (type 10000): body storage 4, page width 30, height 31,
//! margins 32 to 35 (points). TSWP.StorageArchive (2001): text 3,
//! table_para_style 5, table_para_data 6, table_list_style 7,
//! table_char_style 8, table_attachment 9. Each table's entries hold a
//! character index 1 and an object 2.

use crate::formats::office::common::iwa::proto::{Msg, Val};
use crate::formats::office::common::iwa::Store;
use crate::formats::office::common::package::Zip;
use crate::formats::office::docs::error::{Error, Result};
use crate::formats::office::docs::limits::Budget;
use crate::formats::office::docs::model::*;
use std::collections::HashMap;

const DOCUMENT: u32 = 10000;
const STORAGE: u32 = 2001;
const CHARACTER_STYLE: u32 = 2021;
const PARAGRAPH_STYLE: u32 = 2022;
const LIST_STYLE: u32 = 2023;

pub(crate) fn read(mut z: Zip<'_>, budget: &mut Budget) -> Result<Document> {
    let names = z.names();
    let max = budget.limits.max_part;
    let mut store = Store::default();
    let mut any = false;
    for n in &names {
        if n.ends_with(".iwa") {
            let Some(d) = z.read(n, max)? else { continue };
            budget.alloc(d.len() as u64)?;
            let left = budget
                .limits
                .max_memory
                .saturating_sub(budget.used())
                .min(max) as usize;
            let used = store.add(&d, left);
            budget.alloc(used as u64)?;
            any = true;
        }
    }
    if !any {
        if names
            .iter()
            .any(|n| n == "index.xml" || n == "index.xml.gz")
        {
            return Err(Error::Unsupported("Pages '09 and earlier (XML)".into()));
        }
        return Err(Error::NotFormat("no Index/*.iwa members".into()));
    }
    let doc_id = store
        .ids_of(DOCUMENT)
        .first()
        .copied()
        .ok_or(Error::Encrypted)?;
    let Some((_, d)) = store.get(doc_id) else {
        return Err(Error::Malformed("no document archive".into()));
    };
    let mut r = Pages {
        store: &store,
        b: budget,
        doc: Document::default(),
        nums: HashMap::new(),
    };
    r.document(d)?;
    Ok(r.doc)
}

/// A table's entries: (character index, object reference).
fn table(m: Option<Msg>) -> Vec<(u32, Option<u64>)> {
    m.map(|t| {
        t.msgs(1)
            .take(1 << 20)
            .map(|e| (e.uint(1).unwrap_or(0) as u32, e.reference(2)))
            .collect()
    })
    .unwrap_or_default()
}

fn data_table(m: Option<Msg>) -> Vec<(u32, u32)> {
    m.map(|t| {
        t.msgs(1)
            .take(1 << 20)
            .map(|e| (e.uint(1).unwrap_or(0) as u32, e.uint(2).unwrap_or(0) as u32))
            .collect()
    })
    .unwrap_or_default()
}

/// The entry in force at character `at`. An entry with no object keeps the
/// one before it.
fn at(t: &[(u32, Option<u64>)], at: u32) -> Option<u64> {
    t.iter()
        .take_while(|e| e.0 <= at)
        .fold(None, |acc, e| e.1.or(acc))
}

/// A PostScript font name to a family and its weight and slant.
fn ps_font(name: &str) -> (String, bool, bool) {
    let (base, style) = name.split_once('-').unwrap_or((name, ""));
    // "...PSMT" is TrueType's PostScript name suffix, "...PS" Type 1's.
    let base = base.trim_end_matches("MT").trim_end_matches("PS");
    let mut fam = String::new();
    let chars: Vec<char> = base.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
        let prev_lower = i > 0 && chars[i - 1].is_lowercase();
        if i > 0 && c.is_uppercase() && (prev_lower || next_lower && chars[i - 1].is_uppercase()) {
            fam.push(' ');
        }
        fam.push(c);
    }
    let s = style.to_ascii_lowercase();
    (
        fam,
        s.contains("bold") || s.contains("black") || s.contains("heavy"),
        s.contains("italic") || s.contains("oblique"),
    )
}

fn color(c: Msg) -> Color {
    let ch = |n: u32| (f64::from(c.float(n).unwrap_or(0.0)).clamp(0.0, 1.0) * 255.0).round() as u32;
    Color::Rgb(ch(3) << 16 | ch(4) << 8 | ch(5))
}

struct Pages<'a> {
    store: &'a Store,
    b: &'a mut Budget,
    doc: Document,
    /// List style object to numbering instance.
    nums: HashMap<u64, u32>,
}

impl<'a> Pages<'a> {
    /// A style and its parents (TSS.StyleArchive parent 3, in the style's
    /// super 1).
    fn chain(&self, style: Option<u64>) -> Vec<(u32, Msg<'a>)> {
        let mut out = vec![];
        let mut cur = style;
        while let Some(id) = cur {
            if out.len() >= 32 {
                break;
            }
            let Some((k, m)) = self.store.get(id) else {
                break;
            };
            out.push((k, m));
            cur = m.msg(1).and_then(|s| s.reference(3)).filter(|&p| p != id);
        }
        out
    }

    /// The first value `get` finds in the properties message `field` of a
    /// style or of its nearest parent.
    fn find<T>(
        &self,
        style: Option<u64>,
        field: u32,
        get: impl Fn(Msg<'a>) -> Option<T>,
    ) -> Option<T> {
        self.chain(style).into_iter().find_map(|(k, m)| {
            if k != CHARACTER_STYLE && k != PARAGRAPH_STYLE {
                return None;
            }
            m.msg(field).and_then(&get)
        })
    }

    fn document(&mut self, d: Msg<'a>) -> Result<()> {
        let pt = |n: u32| d.float(n).map(|v| (f64::from(v) * 20.0).round() as i32);
        let s = &mut self.doc.section;
        if let (Some(w), Some(h)) = (pt(30), pt(31)) {
            if w > 100 && h > 100 {
                s.width = w;
                s.height = h;
            }
        }
        for (n, slot) in [
            (32, &mut s.top),
            (33, &mut s.right),
            (34, &mut s.bottom),
            (35, &mut s.left),
        ] {
            if let Some(v) = pt(n) {
                *slot = v.max(0);
            }
        }
        if let Some(v) = pt(36) {
            s.header = v.max(0);
        }
        if let Some(v) = pt(37) {
            s.footer = v.max(0);
        }
        let Some(body) = d.reference(4) else {
            return Err(Error::Malformed("no body text".into()));
        };
        let Some((STORAGE, st)) = self.store.get(body) else {
            return Err(Error::Malformed("the body is not a text storage".into()));
        };
        self.storage(st)?;
        self.doc
            .warn("tables, pictures, headers and footers are not converted");
        Ok(())
    }

    fn run_props(&self, para: Option<u64>, chr: Option<u64>) -> RunProps {
        let get = |f: &dyn Fn(Msg<'a>) -> bool| -> Option<Msg<'a>> {
            self.find(chr, 11, |p| f(p).then_some(p))
                .or_else(|| self.find(para, 11, |p| f(p).then_some(p)))
        };
        let num = |n: u32| get(&|p: Msg| p.get(n).is_some());
        let mut rp = RunProps::default();
        if let Some(name) = num(5).and_then(|p| p.string(5)) {
            let (fam, b, i) = ps_font(&name);
            rp.fonts = Fonts {
                ascii: Some(fam.clone()),
                hansi: Some(fam.clone()),
                east_asia: Some(fam.clone()),
                cs: Some(fam),
            };
            if b {
                rp.bold = Some(true);
            }
            if i {
                rp.italic = Some(true);
            }
        }
        if let Some(b) = num(1).and_then(|p| p.boolean(1)) {
            rp.bold = Some(b || rp.bold == Some(true));
        }
        if let Some(i) = num(2).and_then(|p| p.boolean(2)) {
            rp.italic = Some(i || rp.italic == Some(true));
        }
        let size = num(3)
            .and_then(|p| p.float(3))
            .map(f64::from)
            .unwrap_or(12.0)
            .clamp(1.0, 1600.0);
        rp.size = Some((size * 2.0).round() as u32);
        rp.size_cs = rp.size;
        if let Some(c) = num(7).and_then(|p| p.msg(7)) {
            rp.color = Some(color(c));
        }
        rp.vert_align = match num(10).and_then(|p| p.uint(10)) {
            Some(1) => Some(VertAlign::Superscript),
            Some(2) => Some(VertAlign::Subscript),
            _ => None,
        };
        rp.underline = num(11).and_then(|p| p.uint(11)).and_then(|u| match u {
            0 => None,
            2 => Some("double"),
            3 => Some("wave"),
            _ => Some("single"),
        });
        rp.strike = num(12).and_then(|p| p.uint(12)).map(|s| s != 0);
        rp.caps = match num(13).and_then(|p| p.uint(13)) {
            Some(1) => Some(true),
            _ => None,
        };
        if let Some(c) = num(26).and_then(|p| p.msg(26)) {
            rp.shading = Some(Shading::fill(color(c)));
        }
        rp
    }

    fn para_props(&mut self, para: Option<u64>, level: u32, list: Option<u64>) -> ParaProps {
        let p = |n: u32| self.find(para, 12, |m| m.get(n).is_some().then_some(m));
        let tw = |v: f32| (f64::from(v) * 20.0).round() as i32;
        let mut pp = ParaProps {
            jc: p(1).and_then(|m| m.uint(1)).map(|a| match a {
                1 => Jc::Right,
                2 => Jc::Center,
                3 => Jc::Both,
                _ => Jc::Left,
            }),
            ..ParaProps::default()
        };
        let left = p(11).and_then(|m| m.float(11)).map(tw);
        let first = p(7).and_then(|m| m.float(7)).map(tw);
        pp.ind_left = left;
        match first {
            Some(f) if f >= 0 => pp.ind_first_line = Some(f),
            Some(f) => pp.ind_hanging = Some(-f),
            None => {}
        }
        pp.space_after = p(20).and_then(|m| m.float(20)).map(tw);
        pp.space_before = p(21).and_then(|m| m.float(21)).map(tw);
        if let Some(ls) = p(13).and_then(|m| m.msg(13)) {
            let amount = f64::from(ls.float(2).unwrap_or(1.0));
            match ls.uint(1).unwrap_or(0) {
                0 => {
                    pp.line = Some((amount * 240.0).round() as i32);
                    pp.line_rule = Some(LineRule::Auto);
                }
                _ => {
                    pp.line = Some((amount * 20.0).round() as i32);
                    pp.line_rule = Some(LineRule::AtLeast);
                }
            }
        }
        if let Some(l) = list {
            if let Some(id) = self.list_num(l) {
                pp.num_id = Some(id);
                pp.num_level = Some(level.min(8));
            }
        }
        pp
    }

    /// The numbering of a list style: labels at label_types 11 (1 bullet, 2
    /// text bullet, 3 number), text_indents 12, indents 13, number_types 15,
    /// strings 16.
    fn list_num(&mut self, id: u64) -> Option<u32> {
        if let Some(n) = self.nums.get(&id) {
            return Some(*n);
        }
        let (LIST_STYLE, l) = self.store.get(id)? else {
            return None;
        };
        let rep_u = |n: u32| -> Vec<u64> {
            let mut v = vec![];
            for x in l.all(n) {
                match x {
                    Val::Varint(u) => v.push(u),
                    Val::Bytes(b) => {
                        let mut p = 0;
                        while let Some(u) =
                            crate::formats::office::common::iwa::proto::varint(b, &mut p)
                        {
                            v.push(u);
                        }
                    }
                    _ => {}
                }
            }
            v
        };
        let rep_f = |n: u32| -> Vec<f32> {
            let mut v = vec![];
            for x in l.all(n) {
                match x {
                    Val::Fixed32(u) => v.push(f32::from_bits(u)),
                    Val::Bytes(b) => {
                        v.extend(b.as_chunks::<4>().0.iter().map(|c| f32::from_le_bytes(*c)))
                    }
                    _ => {}
                }
            }
            v
        };
        let kinds = rep_u(11);
        let numbers = rep_u(15);
        let strings: Vec<String> = l
            .all(16)
            .filter_map(|v| match v {
                Val::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            })
            .collect();
        let indents = rep_f(13);
        let text_indents = rep_f(12);
        let mut levels = vec![];
        for lv in 0..9usize {
            let kind = kinds.get(lv).or(kinds.last()).copied().unwrap_or(0);
            let mut level = Level::default();
            match kind {
                1 | 2 => {
                    level.fmt = "bullet";
                    level.text = strings
                        .get(lv)
                        .or(strings.last())
                        .and_then(|s| s.chars().next())
                        .filter(|_| kind == 2)
                        .unwrap_or('\u{2022}')
                        .to_string();
                }
                3 => {
                    let n = numbers.get(lv).or(numbers.last()).copied().unwrap_or(0);
                    level.fmt = match n {
                        3..=5 => "upperRoman",
                        6..=8 => "lowerRoman",
                        9..=11 => "upperLetter",
                        12..=14 => "lowerLetter",
                        _ => "decimal",
                    };
                    level.text = match n {
                        1 | 4 | 7 | 10 | 13 => format!("(%{})", lv + 1),
                        2 | 5 | 8 | 11 | 14 => format!("%{})", lv + 1),
                        _ => format!("%{}.", lv + 1),
                    };
                }
                _ => level.fmt = "none",
            }
            if kind != 0 {
                let ind = f64::from(indents.get(lv).or(indents.last()).copied().unwrap_or(0.0));
                let txt = f64::from(
                    text_indents
                        .get(lv)
                        .or(text_indents.last())
                        .copied()
                        .unwrap_or(20.0),
                );
                level.ppr.ind_left = Some(((ind + txt) * 20.0).round() as i32);
                level.ppr.ind_hanging = Some((txt * 20.0).round() as i32);
            }
            levels.push(level);
        }
        let abs = self.doc.numbering.abstracts.len() as u32;
        self.doc.numbering.abstracts.push(AbstractNum {
            id: abs,
            multi_level: true,
            levels,
        });
        let num = self.doc.numbering.nums.len() as u32 + 1;
        self.doc.numbering.nums.push(Num {
            id: num,
            abstract_id: abs,
            overrides: vec![],
        });
        self.nums.insert(id, num);
        Some(num)
    }

    fn storage(&mut self, st: Msg<'a>) -> Result<()> {
        let text: String = st
            .all(3)
            .filter_map(|v| match v {
                Val::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            })
            .collect();
        let chars: Vec<char> = text.chars().take(1 << 24).collect();
        self.b.alloc(chars.len() as u64 * 4)?;
        let para_styles = table(st.msg(5));
        let list_styles = table(st.msg(7));
        let char_styles = table(st.msg(8));
        let levels = data_table(st.msg(6));
        let mut start = 0usize;
        loop {
            let end = (start..chars.len())
                .find(|&i| matches!(chars[i], '\n' | '\u{2029}'))
                .unwrap_or(chars.len());
            self.b.paragraph(end - start)?;
            let ps = at(&para_styles, start as u32);
            let level = levels
                .iter()
                .take_while(|e| e.0 <= start as u32)
                .last()
                .map(|e| e.1)
                .unwrap_or(0)
                .min(8);
            let list = at(&list_styles, start as u32);
            let mut para = Para {
                props: self.para_props(ps, level, list),
                mark: self.run_props(ps, None),
                ..Para::default()
            };
            let mut text = String::new();
            let mut cur: Option<(u32, RunProps)> = None;
            let mut runs: Vec<Inline> = vec![];
            let flush =
                |text: &mut String, cur: &Option<(u32, RunProps)>, runs: &mut Vec<Inline>| {
                    if !text.is_empty() {
                        if let Some((_, rp)) = cur {
                            runs.push(Inline::Run(Run::text(rp.clone(), std::mem::take(text))));
                        }
                    }
                };
            for (i, &c) in chars.iter().enumerate().take(end).skip(start) {
                let cs = at(&char_styles, i as u32);
                let key = cs.map(|c| c as u32).unwrap_or(0);
                if cur.as_ref().is_none_or(|(k, _)| *k != key) {
                    flush(&mut text, &cur, &mut runs);
                    cur = Some((key, self.run_props(ps, cs)));
                }
                match c {
                    '\u{2028}' | '\u{000B}' => {
                        flush(&mut text, &cur, &mut runs);
                        if let Some((_, rp)) = &cur {
                            runs.push(Inline::Run(Run {
                                props: rp.clone(),
                                items: vec![RunItem::Break(BreakKind::Line)],
                            }));
                        }
                    }
                    '\t' => {
                        flush(&mut text, &cur, &mut runs);
                        if let Some((_, rp)) = &cur {
                            runs.push(Inline::Run(Run {
                                props: rp.clone(),
                                items: vec![RunItem::Tab],
                            }));
                        }
                    }
                    '\u{FFFC}' => {}
                    c if (c as u32) < 0x20 => {}
                    c => text.push(c),
                }
            }
            flush(&mut text, &cur, &mut runs);
            para.content = runs;
            self.doc.body.push(Block::Para(para));
            if end >= chars.len() {
                break;
            }
            start = end + 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_entries_without_an_object_keep_the_style_before() {
        let t = vec![(0, Some(7)), (5, None), (9, Some(8))];
        assert_eq!(at(&t, 0), Some(7));
        assert_eq!(at(&t, 6), Some(7));
        assert_eq!(at(&t, 9), Some(8));
        assert_eq!(at(&t, 100), Some(8));
        assert_eq!(at(&[], 3), None);
    }

    #[test]
    fn postscript_names() {
        assert_eq!(
            ps_font("HelveticaNeue-Bold"),
            ("Helvetica Neue".into(), true, false)
        );
        assert_eq!(
            ps_font("TimesNewRomanPSMT"),
            ("Times New Roman".into(), false, false)
        );
    }
}
