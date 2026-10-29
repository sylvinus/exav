//! Keynote text (TSWP.StorageArchive) to paragraphs: the text with its
//! paragraph, character and list style runs and paragraph levels, every
//! property resolved through the styles' parents.
//!
//! TSWP.StorageArchive: text 3, table_para_style 5, table_para_data 6,
//! table_list_style 7, table_char_style 8, table_attachment 9,
//! table_smartfield 11; each table's entries 1 hold a character index 1
//! and an object 2 (or, for paragraph data, first 2 and second 3).

use super::shapes::{color, shadow};
use super::{Props, Reader, ty};
use crate::formats::office::common::iwa::proto::Msg;
use crate::formats::office::slides::error::Result;
use crate::formats::office::slides::limits::Budget;
use crate::formats::office::slides::model::*;

const PT: f64 = 12700.0;

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

/// The entry in force at character `at`.
fn at<T: Copy>(t: &[(u32, T)], at: u32) -> Option<T> {
    t.iter().take_while(|e| e.0 <= at).last().map(|e| e.1)
}

/// A PostScript font name to a family and its weight and slant:
/// "HelveticaNeue-Bold" is Helvetica Neue, bold.
pub fn ps_font(name: &str) -> (String, bool, bool) {
    let (base, style) = name.split_once('-').unwrap_or((name, ""));
    let base = base
        .trim_end_matches("PSMT")
        .trim_end_matches("MT")
        .trim_end_matches("PS");
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
    let bold = s.contains("bold") || s.contains("black") || s.contains("heavy");
    let italic = s.contains("italic") || s.contains("oblique");
    for w in [
        "Light",
        "Thin",
        "Medium",
        "UltraLight",
        "Condensed",
        "Semibold",
    ] {
        if style.contains(w) && !fam.ends_with(w) {
            fam.push(' ');
            fam.push_str(w);
            break;
        }
    }
    (fam, bold, italic)
}

/// Run properties from a character style over a paragraph style.
pub(super) fn run_props(r: &Reader, para: Option<u64>, chr: Option<u64>) -> RunProps {
    let get = |f: &dyn Fn(Msg) -> bool| -> Option<Msg> {
        r.find(chr, Props::Char, |p| f(p).then_some(p))
            .or_else(|| r.find(para, Props::Char, |p| f(p).then_some(p)))
    };
    let num = |n: u32| get(&|p: Msg| p.get(n).is_some());
    let mut rp = RunProps::default();
    if let Some(name) = num(5).and_then(|p| p.string(5)) {
        let (fam, b, i) = ps_font(&name);
        rp.font = Some(fam);
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
        .unwrap_or(24.0)
        .clamp(1.0, 4000.0);
    rp.size = Some((size * 100.0).round() as u32);
    rp.color = Some(
        num(7)
            .and_then(|p| p.msg(7))
            .map(color)
            .unwrap_or(Color::rgb(0)),
    );
    rp.baseline = match num(10).and_then(|p| p.uint(10)) {
        Some(1) => Some(30_000),
        Some(2) => Some(-25_000),
        _ => None,
    };
    rp.underline = num(11).and_then(|p| p.uint(11)).map(|u| match u {
        1 => "sng",
        2 => "dbl",
        3 => "wavy",
        _ => "none",
    });
    rp.strike = num(12).and_then(|p| p.uint(12)).map(|s| match s {
        0 => "noStrike",
        2 | 3 => "dblStrike",
        _ => "sngStrike",
    });
    rp.caps = match num(13).and_then(|p| p.uint(13)) {
        Some(1) => Some("all"),
        Some(2) => Some("small"),
        _ => None,
    };
    if let Some(t) = num(27).and_then(|p| p.float(27)) {
        // Tracking: thousandths of an em.
        rp.spacing = Some((f64::from(t) * size / 10.0).round() as i32).filter(|&s| s != 0);
    }
    rp.shadow = num(21).and_then(|p| p.msg(21)).and_then(shadow);
    rp.highlight = num(26).and_then(|p| p.msg(26)).map(color);
    rp
}

pub(super) fn para_props(
    r: &Reader,
    para: Option<u64>,
    level: u32,
    list: Option<u64>,
    color: Option<Color>,
) -> ParaProps {
    let p = |n: u32| r.find(para, Props::Para, |m| m.get(n).is_some().then_some(m));
    let pts = |v: f32| (f64::from(v) * PT).round() as Emu;
    let mut pp = ParaProps {
        level: level.min(8) as u8,
        align: p(1).and_then(|m| m.uint(1)).map(|a| match a {
            1 => "r",
            2 => "ctr",
            3 => "just",
            _ => "l",
        }),
        margin: p(11).and_then(|m| m.float(11)).map(pts),
        indent: p(7).and_then(|m| m.float(7)).map(pts),
        space_after: p(20)
            .and_then(|m| m.float(20))
            .map(|v| Spacing::Pts((f64::from(v) * 100.0).round() as i32)),
        space_before: p(21)
            .and_then(|m| m.float(21))
            .map(|v| Spacing::Pts((f64::from(v) * 100.0).round() as i32)),
        line_spacing: p(13).and_then(|m| m.msg(13)).map(|ls| {
            let amount = f64::from(ls.float(2).unwrap_or(1.0));
            match ls.uint(1).unwrap_or(0) {
                0 => Spacing::Pct((amount * 100_000.0).round() as i32),
                _ => Spacing::Pts((amount * 100.0).round() as i32),
            }
        }),
        default_tab: p(4).and_then(|m| m.float(4)).map(pts),
        bullet: Some(Bullet::None),
        ..ParaProps::default()
    };
    // The list style's label at this level: label_types 11, text_indents 12,
    // indents 13, number_types 15, strings 16, font_color 21.
    if let Some((ty::LIST_STYLE, l)) = list.and_then(|id| r.store.get(id)) {
        let lv = level as usize;
        let rep_u = |n: u32| -> Vec<u64> {
            let mut v = vec![];
            for x in l.all(n) {
                match x {
                    crate::formats::office::common::iwa::proto::Val::Varint(u) => v.push(u),
                    crate::formats::office::common::iwa::proto::Val::Bytes(b) => {
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
                    crate::formats::office::common::iwa::proto::Val::Fixed32(u) => {
                        v.push(f32::from_bits(u))
                    }
                    crate::formats::office::common::iwa::proto::Val::Bytes(b) => {
                        v.extend(b.as_chunks::<4>().0.iter().map(|c| f32::from_le_bytes(*c)))
                    }
                    _ => {}
                }
            }
            v
        };
        let types = rep_u(11);
        let kind = types.get(lv).or(types.last()).copied().unwrap_or(0);
        let strings: Vec<String> = l
            .all(16)
            .filter_map(|v| match v {
                crate::formats::office::common::iwa::proto::Val::Bytes(b) => {
                    Some(String::from_utf8_lossy(b).into_owned())
                }
                _ => None,
            })
            .collect();
        let lcolor = l.msg(21).map(super::shapes::color).or(color);
        pp.bullet = Some(match kind {
            2 => Bullet::Char {
                ch: strings
                    .get(lv)
                    .or(strings.last())
                    .and_then(|s| s.chars().next())
                    .unwrap_or('\u{2022}'),
                font: None,
                color: lcolor,
                size: None,
            },
            1 => Bullet::Char {
                ch: '\u{2022}',
                font: None,
                color: lcolor,
                size: None,
            },
            3 => {
                let nt = rep_u(15);
                let n = nt.get(lv).or(nt.last()).copied().unwrap_or(0);
                Bullet::AutoNum {
                    scheme: match n {
                        1 => "arabicParenBoth",
                        2 => "arabicParenR",
                        3 => "romanUcPeriod",
                        4 => "romanUcParenBoth",
                        5 => "romanUcParenR",
                        6 => "romanLcPeriod",
                        7 => "romanLcParenBoth",
                        8 => "romanLcParenR",
                        9 => "alphaUcPeriod",
                        10 => "alphaUcParenBoth",
                        11 => "alphaUcParenR",
                        12 => "alphaLcPeriod",
                        13 => "alphaLcParenBoth",
                        14 => "alphaLcParenR",
                        _ => "arabicPeriod",
                    },
                    start: 1,
                    font: None,
                    color: lcolor,
                    size: None,
                }
            }
            _ => Bullet::None,
        });
        if kind != 0 {
            let indents = rep_f(13);
            let text_indents = rep_f(12);
            let ind = f64::from(indents.get(lv).or(indents.last()).copied().unwrap_or(0.0));
            let txt = f64::from(
                text_indents
                    .get(lv)
                    .or(text_indents.last())
                    .copied()
                    .unwrap_or(20.0),
            );
            pp.margin = Some(((ind + txt) * PT).round() as Emu + pp.margin.unwrap_or(0));
            pp.indent = Some((-txt * PT).round() as Emu);
        }
    }
    pp
}

/// A storage's text as a text body, in a shape of style `shape_style`.
pub fn body(
    r: &mut Reader,
    st: Msg,
    shape_style: Option<u64>,
    number: usize,
    budget: &mut Budget,
) -> Result<Option<TextBody>> {
    let text: String = st
        .all(3)
        .filter_map(|v| match v {
            crate::formats::office::common::iwa::proto::Val::Bytes(b) => {
                Some(String::from_utf8_lossy(b).into_owned())
            }
            _ => None,
        })
        .collect();
    let chars: Vec<char> = text.chars().take(1 << 20).collect();
    budget.alloc(chars.len() as u64 * 16)?;
    let para_styles = table(st.msg(5));
    let list_styles = table(st.msg(7));
    let char_styles = table(st.msg(8));
    let attachments = table(st.msg(9));
    let fields = table(st.msg(11));
    let levels = data_table(st.msg(6));
    let default_para = r.find(shape_style, Props::Text, |p| p.reference(10));

    let mut paras = vec![];
    let mut start = 0usize;
    loop {
        let end = (start..chars.len())
            .find(|&i| matches!(chars[i], '\n' | '\u{2029}'))
            .unwrap_or(chars.len());
        let ps = at(&para_styles, start as u32).flatten().or(default_para);
        let level = at(&levels, start as u32).unwrap_or(0).min(8);
        let list = at(&list_styles, start as u32).flatten();
        let base = run_props(r, ps, None);
        let props = para_props(r, ps, level, list, base.color);
        let mut runs: Vec<Run> = vec![];
        let mut i = start;
        while i < end {
            let cs = at(&char_styles, i as u32).flatten();
            let mut rp = run_props(r, ps, cs);
            let link = at(&fields, i as u32)
                .flatten()
                .and_then(|id| match r.store.get(id) {
                    Some((2032, f)) => f.string(2).and_then(|u| Link::url(&u)),
                    _ => None,
                });
            if link.is_some() {
                rp.link = link;
            }
            let c = chars[i];
            let kind = match c {
                '\u{2028}' | '\u{000B}' => RunKind::Break,
                '\u{FFFC}' => match at(&attachments, i as u32)
                    .flatten()
                    .and_then(|id| r.store.get(id))
                {
                    Some((22, _)) => RunKind::Field("slidenum", number.to_string()),
                    _ => RunKind::Text(String::new()),
                },
                '\t' => RunKind::Text("\t".into()),
                c if (c as u32) < 0x20 => RunKind::Text(String::new()),
                c => RunKind::Text(c.to_string()),
            };
            match (&kind, runs.last_mut()) {
                (
                    RunKind::Text(t),
                    Some(Run {
                        kind: RunKind::Text(prev),
                        props,
                    }),
                ) if *props == rp => prev.push_str(t),
                _ => runs.push(Run { kind, props: rp }),
            }
            i += 1;
        }
        paras.push(Paragraph {
            props,
            runs,
            end: base,
        });
        if end >= chars.len() || paras.len() >= 1 << 16 {
            break;
        }
        start = end + 1;
    }
    let pad = r.find(shape_style, Props::Text, |p| p.msg(6));
    let ins = |n: u32| {
        pad.and_then(|p| p.float(n))
            .map(|v| (f64::from(v) * PT).round() as Emu)
            .unwrap_or(0)
            .max(0)
    };
    let valign = r.find(shape_style, Props::Text, |p| p.uint(2)).unwrap_or(0);
    let shrink = r
        .find(shape_style, Props::Text, |p| p.boolean(1))
        .unwrap_or(false);
    Ok(Some(TextBody {
        body: BodyProps {
            insets: [ins(1), ins(2), ins(3), ins(4)],
            anchor: match valign {
                1 => "ctr",
                2 => "b",
                _ => "t",
            },
            autofit: if shrink {
                Autofit::Normal(100_000, 0)
            } else {
                Autofit::None
            },
            ..BodyProps::default()
        },
        paras,
        levels: ListStyle::default(),
    }))
}

#[cfg(test)]
mod tests {
    use super::ps_font;

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
        assert_eq!(
            ps_font("GillSans-LightItalic"),
            ("Gill Sans Light".into(), false, true)
        );
        assert_eq!(ps_font("Arial"), ("Arial".into(), false, false));
    }
}
