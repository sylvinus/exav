//! The text of a shape ([MS-VSDX] 2.2.8): runs formatted by the rows of the
//! Character section, paragraphs by those of Paragraph, in a text block
//! with margins and a vertical alignment.

use super::resolve::{RowKey, Tree};
use super::sheet::Piece;
use crate::formats::office::slides::model::{
    BodyProps, Bullet, Color, ParaProps, Paragraph, Run, RunKind, RunProps, Spacing, TextBody,
};

const EMU_PER_INCH: f64 = 914_400.0;
/// Hundredths of a point per inch.
const CPT_PER_INCH: f64 = 7_200.0;

fn emu(v: f64) -> i64 {
    (v.clamp(-1e5, 1e5) * EMU_PER_INCH).round() as i64
}

/// The text of shape `n`, or `None` when it has none or hides it. `k` is
/// the paper inches to each of a scaled drawing, which the margins are in.
pub fn build(t: &Tree, n: usize, k: f64) -> Option<TextBody> {
    if t.num(n, "HideText") == Some(1.0) {
        return None;
    }
    let pieces = t.pieces(n)?;
    let mut paras: Vec<Paragraph> = vec![];
    let (mut cp, mut pp) = (0u32, 0u32);
    let mut cur: Vec<Run> = vec![];
    let mut cur_pp = 0u32;
    let mut cur_cp = 0u32;
    let mut buf = String::new();
    let mut text = false;
    macro_rules! push_text {
        () => {
            if !buf.is_empty() {
                cur.push(Run {
                    kind: RunKind::Text(std::mem::take(&mut buf)),
                    props: run_props(t, n, cp),
                });
                cur_cp = cp;
            }
        };
    }
    macro_rules! end_para {
        () => {
            paras.push(Paragraph {
                props: para_props(t, n, cur_pp),
                runs: std::mem::take(&mut cur),
                end: run_props(t, n, cur_cp),
            });
            cur_pp = pp;
            cur_cp = cp;
        };
    }
    for piece in pieces {
        match piece {
            Piece::Cp(i) => {
                push_text!();
                cp = *i;
                if cur.is_empty() {
                    cur_cp = cp;
                }
            }
            Piece::Pp(i) => {
                push_text!();
                pp = *i;
                if cur.is_empty() {
                    cur_pp = pp;
                }
            }
            Piece::Tp(_) => {}
            Piece::Fld(_, s) => {
                for c in s.chars().filter(|c| !c.is_control()) {
                    buf.push(c);
                }
                text |= !buf.is_empty();
                push_text!();
            }
            Piece::Text(s) => {
                let mut chars = s.chars().peekable();
                while let Some(c) = chars.next() {
                    match c {
                        '\r' if chars.peek() == Some(&'\n') => {}
                        '\n' | '\r' => {
                            push_text!();
                            end_para!();
                        }
                        '\u{2028}' | '\u{b}' => {
                            push_text!();
                            cur.push(Run {
                                kind: RunKind::Break,
                                props: run_props(t, n, cp),
                            });
                        }
                        c if c.is_control() && c != '\t' => {}
                        c => {
                            buf.push(c);
                            text = true;
                        }
                    }
                }
                push_text!();
            }
        }
    }
    push_text!();
    if !cur.is_empty() || paras.is_empty() {
        paras.push(Paragraph {
            props: para_props(t, n, cur_pp),
            runs: cur,
            end: run_props(t, n, cur_cp),
        });
    }
    if !text {
        return None;
    }
    let side = |name: &str| emu(t.num(n, name).unwrap_or(0.0).max(0.0) * k);
    Some(TextBody {
        body: BodyProps {
            insets: [
                side("LeftMargin"),
                side("TopMargin"),
                side("RightMargin"),
                side("BottomMargin"),
            ],
            anchor: match t.num(n, "VerticalAlign").map(|v| v as i64) {
                Some(1) => "ctr",
                Some(2) => "b",
                _ => "t",
            },
            ..BodyProps::default()
        },
        paras,
        ..TextBody::default()
    })
}

/// A Character cell of row `cp`, else of row 0, which is what the rows
/// after it start from.
fn char_val(t: &Tree, n: usize, cp: u32, cell: &str) -> Option<super::formula::Val> {
    t.row_val(n, "Character", None, &RowKey::Ix(cp), cell)
        .or_else(|| t.row_val(n, "Character", None, &RowKey::Ix(0), cell))
}

fn run_props(t: &Tree, n: usize, cp: u32) -> RunProps {
    let num = |cell: &str| char_val(t, n, cp, cell).and_then(|v| v.num());
    let style = num("Style").map_or(0, |v| v as i64);
    let size = num("Size")
        .filter(|v| *v > 0.0)
        .map_or(1000, |v| (v.min(100.0) * CPT_PER_INCH).round() as u32);
    let color = char_val(t, n, cp, "Color")
        .and_then(|v| t.to_color(&v))
        .map(|rgb| {
            let tr = num("ColorTrans").unwrap_or(0.0).clamp(0.0, 1.0);
            Color {
                rgb,
                alpha: (tr > 0.0).then(|| ((1.0 - tr) * 100_000.0).round() as u32),
            }
        });
    RunProps {
        size: Some(size.clamp(100, 400_000)),
        bold: Some(style & 1 != 0),
        italic: Some(style & 2 != 0),
        underline: if num("DblUnderline").unwrap_or(0.0) != 0.0 {
            Some("dbl")
        } else if style & 4 != 0 {
            Some("sng")
        } else {
            None
        },
        strike: if num("DoubleStrikethrough").unwrap_or(0.0) != 0.0 {
            Some("dblStrike")
        } else if num("Strikethru").unwrap_or(0.0) != 0.0 {
            Some("sngStrike")
        } else {
            None
        },
        color,
        font: char_val(t, n, cp, "Font").and_then(|v| t.font(&v)),
        baseline: match num("Pos").map(|v| v as i64) {
            Some(1) => Some(30_000),
            Some(2) => Some(-25_000),
            _ => None,
        },
        caps: match (num("Case").map(|v| v as i64), style & 8 != 0) {
            (Some(1), _) => Some("all"),
            (_, true) => Some("small"),
            _ => None,
        },
        spacing: num("Letterspace")
            .filter(|v| *v != 0.0)
            .map(|v| (v.clamp(-10.0, 10.0) * CPT_PER_INCH).round() as i32),
        ..RunProps::default()
    }
}

fn para_props(t: &Tree, n: usize, pp: u32) -> ParaProps {
    let val = |cell: &str| {
        t.row_val(n, "Paragraph", None, &RowKey::Ix(pp), cell)
            .or_else(|| t.row_val(n, "Paragraph", None, &RowKey::Ix(0), cell))
    };
    let num = |cell: &str| val(cell).and_then(|v| v.num());
    let space =
        |v: f64| (v > 0.0).then(|| Spacing::Pts((v.min(100.0) * CPT_PER_INCH).round() as i32));
    let bullet = if num("Bullet").is_some_and(|b| b > 0.0) {
        let ch = match val("BulletStr") {
            Some(super::formula::Val::Str(s)) => s.chars().next(),
            _ => None,
        };
        Bullet::Char {
            ch: ch.unwrap_or('\u{2022}'),
            font: None,
            color: None,
            size: None,
        }
    } else {
        Bullet::None
    };
    ParaProps {
        align: Some(match num("HorzAlign").map(|v| v as i64) {
            Some(1) => "ctr",
            Some(2) => "r",
            Some(3) => "just",
            Some(4) => "dist",
            _ => "l",
        }),
        margin: Some(emu(num("IndLeft").unwrap_or(0.0).max(0.0))),
        indent: Some(emu(num("IndFirst").unwrap_or(0.0))),
        // A negative spacing is a multiple of the line, a positive one a
        // distance.
        line_spacing: num("SpLine").and_then(|v| {
            if v < 0.0 {
                Some(Spacing::Pct(
                    (-v * 100_000.0).clamp(1000.0, 1_000_000.0) as i32
                ))
            } else {
                space(v)
            }
        }),
        space_before: num("SpBefore").and_then(space),
        space_after: num("SpAfter").and_then(space),
        bullet: Some(bullet),
        ..ParaProps::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::slides::limits::{Budget, Limits};
    use crate::formats::office::slides::vsdx::resolve::{tests::shapes, Doc, Master};
    use std::collections::HashMap;

    fn body(shape: &str) -> Option<TextBody> {
        let d = Doc {
            faces: vec!["Arial".into(), "Calibri".into()],
            ..Doc::default()
        };
        let page = shapes(&format!("<S>{shape}</S>"));
        let m: HashMap<u32, Master> = HashMap::new();
        let t = Tree::build(&d, &m, &page, &mut Budget::new(Limits::default())).unwrap();
        build(&t, t.roots[0], 1.0)
    }

    fn texts(p: &Paragraph) -> Vec<String> {
        p.runs
            .iter()
            .map(|r| match &r.kind {
                RunKind::Text(s) => s.clone(),
                RunKind::Break => "<br>".into(),
                RunKind::Field(_, s) => s.clone(),
            })
            .collect()
    }

    const CHARS: &str = "<Section N='Character'>
        <Row IX='0'><Cell N='Size' V='0.1666666667'/><Cell N='Font' V='1'/><Cell N='Color' V='#ff0000'/><Cell N='Style' V='0'/></Row>
        <Row IX='1'><Cell N='Size' V='0.25'/><Cell N='Style' V='7'/><Cell N='Pos' V='1'/><Cell N='Case' V='1'/></Row></Section>";

    #[test]
    fn runs_take_the_properties_of_their_character_rows() {
        let b = body(&format!(
            "<Shape ID='1'>{CHARS}<Text><cp IX='0'/>plain <cp IX='1'/>loud</Text></Shape>"
        ))
        .unwrap();
        assert_eq!(b.paras.len(), 1);
        let p = &b.paras[0];
        assert_eq!(texts(p), vec!["plain ", "loud"]);
        let (a, l) = (&p.runs[0].props, &p.runs[1].props);
        assert_eq!(a.size, Some(1200));
        assert_eq!(a.font.as_deref(), Some("Calibri"));
        assert_eq!(a.color, Some(Color::rgb(0xFF0000)));
        assert_eq!(
            (a.bold, a.italic, a.underline),
            (Some(false), Some(false), None)
        );
        assert_eq!(l.size, Some(1800));
        assert_eq!(
            (l.bold, l.italic, l.underline),
            (Some(true), Some(true), Some("sng"))
        );
        assert_eq!((l.baseline, l.caps), (Some(30_000), Some("all")));
        // Row 1 has no colour: row 0's.
        assert_eq!(l.color, Some(Color::rgb(0xFF0000)));
    }

    #[test]
    fn newlines_start_paragraphs_with_their_properties() {
        let b = body(
            "<Shape ID='1'>
              <Section N='Paragraph'>
               <Row IX='0'><Cell N='HorzAlign' V='1'/><Cell N='SpLine' V='-1.2'/><Cell N='IndLeft' V='0.5'/></Row>
               <Row IX='1'><Cell N='HorzAlign' V='2'/><Cell N='SpAfter' V='0.0833333333'/><Cell N='Bullet' V='1'/><Cell N='BulletStr' V='-'/></Row></Section>
              <Text><pp IX='0'/><cp IX='0'/>one
<pp IX='1'/><cp IX='0'/>two<cp IX='0'/>
x&#8232;y</Text></Shape>",
        )
        .unwrap();
        assert_eq!(b.paras.len(), 3);
        assert_eq!(texts(&b.paras[0]), vec!["one"]);
        assert_eq!(b.paras[0].props.align, Some("ctr"));
        assert_eq!(b.paras[0].props.line_spacing, Some(Spacing::Pct(120_000)));
        assert_eq!(b.paras[0].props.margin, Some(457_200));
        assert_eq!(texts(&b.paras[1]), vec!["two"]);
        assert_eq!(b.paras[1].props.align, Some("r"));
        assert_eq!(b.paras[1].props.space_after, Some(Spacing::Pts(600)));
        assert!(matches!(
            b.paras[1].props.bullet,
            Some(Bullet::Char { ch: '-', .. })
        ));
        // The third keeps the last paragraph row; a line break is a break.
        assert_eq!(texts(&b.paras[2]), vec!["x", "<br>", "y"]);
        assert_eq!(b.paras[2].props.align, Some("r"));
    }

    #[test]
    fn fields_are_their_saved_text_and_blank_text_is_none() {
        let b = body("<Shape ID='1'><Text>Page <fld IX='0'>3</fld></Text></Shape>").unwrap();
        assert_eq!(texts(&b.paras[0]), vec!["Page ", "3"]);
        assert!(body("<Shape ID='1'><Text><cp IX='0'/></Text></Shape>").is_none());
        assert!(body("<Shape ID='1'/>").is_none());
        assert!(body("<Shape ID='1'><Cell N='HideText' V='1'/><Text>x</Text></Shape>").is_none());
    }

    #[test]
    fn margins_and_the_vertical_alignment_make_the_text_block() {
        let b = body(
            "<Shape ID='1'><Cell N='LeftMargin' V='0.1'/><Cell N='TopMargin' V='0.05'/><Cell N='VerticalAlign' V='1'/><Text>x</Text></Shape>",
        )
        .unwrap();
        assert_eq!(b.body.insets, [91_440, 45_720, 0, 0]);
        assert_eq!(b.body.anchor, "ctr");
    }

    #[test]
    fn a_carriage_return_and_a_newline_are_one_paragraph_break() {
        let b = body("<Shape ID='1'><Text>a&#13;&#10;b&#13;c</Text></Shape>").unwrap();
        assert_eq!(b.paras.len(), 3);
        assert_eq!(texts(&b.paras[0]), vec!["a"]);
        assert_eq!(texts(&b.paras[2]), vec!["c"]);
    }
}
