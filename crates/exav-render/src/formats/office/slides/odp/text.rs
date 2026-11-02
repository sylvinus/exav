//! ODF text in drawing shapes ([ODF 1.2] part 1, 5 and 6): paragraphs,
//! spans, lists and fields, with paragraph, text and list styles resolved
//! into explicit DrawingML properties.

use super::styles::{ListDef, ListLevel, Props, Styles, len, percent};
use crate::formats::office::common::xml::{Child, Node};
use crate::formats::office::slides::model::*;

/// What a shape's text is resolved against.
pub struct TextCtx<'a> {
    pub styles: &'a Styles,
    /// The shape's own style, text and paragraph properties included.
    pub base: &'a Props,
    /// Per outline level (1-based) presentation styles, for outlines.
    pub levels: &'a dyn Fn(usize) -> Option<Props>,
    /// The shape style's list style.
    pub list: Option<&'a ListDef>,
    pub slide_number: usize,
    pub footer: &'a str,
    pub date: &'a str,
    pub header: &'a str,
    /// The automatic font colour: black, or white on a dark background.
    pub auto_color: Rgb,
    /// The pictures of the image bullets the paragraphs use, in the order
    /// their `Bullet::Picture` indexes name; the caller reads them.
    pub pictures: Vec<String>,
}

fn font_size(p: &Props, inherited: f64) -> f64 {
    let mut size = inherited;
    // Each property set once per level, so the last value is the one.
    if let Some(v) = p.get("fo:font-size") {
        if let Some(f) = percent(v) {
            size *= f;
        } else if let Some(e) = len(v) {
            size = e as f64 / 12_700.0;
        }
    }
    size.clamp(1.0, 4000.0)
}

/// Text properties as run properties, `size` already resolved.
pub fn run_props(p: &Props, size: f64, styles: &Styles, auto_color: Rgb) -> RunProps {
    let font = p
        .get("style:font-name")
        .map(|n| styles.font(n))
        .or_else(|| {
            p.get("fo:font-family")
                .map(|f| f.trim_matches(['\'', '"']).to_string())
        });
    let bold = p.get("fo:font-weight").map(|w| match w {
        "bold" => true,
        "normal" => false,
        n => n.parse::<u32>().map(|v| v >= 600).unwrap_or(false),
    });
    let italic = p
        .get("fo:font-style")
        .map(|s| s == "italic" || s == "oblique");
    let underline = p.get("style:text-underline-style").map(|u| {
        let double = p.is("style:text-underline-type", "double");
        match (u, double) {
            ("none", _) => "none",
            (_, true) => "dbl",
            ("dotted", _) => "dotted",
            ("dash", _) => "dash",
            ("long-dash", _) => "dashLong",
            ("dot-dash", _) => "dotDash",
            ("dot-dot-dash", _) => "dotDotDash",
            ("wave", _) => "wavy",
            _ => "sng",
        }
    });
    let strike = p.get("style:text-line-through-style").map(|s| {
        if s == "none" {
            "noStrike"
        } else if p.is("style:text-line-through-type", "double") {
            "dblStrike"
        } else {
            "sngStrike"
        }
    });
    let auto = p.is("style:use-window-font-color", "true");
    let color = p
        .color("fo:color")
        .filter(|_| !auto || p.get("fo:color").is_some())
        .map(Color::rgb)
        .or(auto.then(|| Color::rgb(auto_color)));
    let baseline = p.get("style:text-position").and_then(|t| {
        let first = t.split_whitespace().next()?;
        match first {
            "super" => Some(33_000),
            "sub" => Some(-33_000),
            v => percent(v)
                .map(|f| (f * 100_000.0).round() as i32)
                .filter(|&b| b != 0),
        }
    });
    let caps = if p.is("fo:font-variant", "small-caps") {
        Some("small")
    } else if p.is("fo:text-transform", "uppercase") {
        Some("all")
    } else {
        None
    };
    let shadow = p
        .get("fo:text-shadow")
        .filter(|s| *s != "none")
        .map(|_| Shadow {
            color: Color {
                rgb: 0,
                alpha: Some(50_000),
            },
            blur: 0,
            dist: 25400,
            dir: 45.0,
        });
    RunProps {
        size: Some((size * 100.0).round() as u32),
        bold,
        italic,
        underline,
        strike,
        color,
        font,
        ea_font: p.get("style:font-name-asian").map(|n| styles.font(n)),
        cs_font: p.get("style:font-name-complex").map(|n| styles.font(n)),
        baseline,
        caps,
        spacing: p
            .get("fo:letter-spacing")
            .filter(|s| *s != "normal")
            .and_then(len)
            .map(|e| (e as f64 / 127.0).round() as i32),
        shadow,
        highlight: p
            .get("fo:background-color")
            .filter(|c| *c != "transparent")
            .and_then(super::styles::color)
            .map(Color::rgb),
        ..RunProps::default()
    }
}

fn spacing_of(p: &Props, k: &str) -> Option<Spacing> {
    let e = p.len(k)?;
    Some(Spacing::Pts((e as f64 / 127.0).round().max(0.0) as i32))
}

/// Paragraph properties without list properties.
pub fn para_props(p: &Props) -> ParaProps {
    let line = p.get("fo:line-height").and_then(|v| {
        if v == "normal" {
            Some(Spacing::Pct(100_000))
        } else if let Some(f) = percent(v) {
            Some(Spacing::Pct((f * 100_000.0).round() as i32))
        } else {
            len(v).map(|e| Spacing::Pts((e as f64 / 127.0).round() as i32))
        }
    });
    let line = line.or_else(|| {
        p.len("style:line-height-at-least")
            .map(|e| Spacing::Pts((e as f64 / 127.0).round() as i32))
    });
    ParaProps {
        align: p.get("fo:text-align").map(|a| match a {
            "center" => "ctr",
            "end" | "right" => "r",
            "justify" => "just",
            _ => "l",
        }),
        margin: p.len("fo:margin-left"),
        indent: p.len("fo:text-indent"),
        line_spacing: line,
        space_before: spacing_of(p, "fo:margin-top"),
        space_after: spacing_of(p, "fo:margin-bottom"),
        rtl: p
            .get("style:writing-mode")
            .is_some_and(|m| m.starts_with("rl")),
        ..ParaProps::default()
    }
}

fn scheme(fmt: &str, suffix: &str, prefix_paren: bool) -> &'static str {
    let paren = suffix == ")";
    let both = paren && prefix_paren;
    match (fmt, both, paren) {
        ("a", true, _) => "alphaLcParenBoth",
        ("a", _, true) => "alphaLcParenR",
        ("a", _, _) => "alphaLcPeriod",
        ("A", true, _) => "alphaUcParenBoth",
        ("A", _, true) => "alphaUcParenR",
        ("A", _, _) => "alphaUcPeriod",
        ("i", true, _) => "romanLcParenBoth",
        ("i", _, true) => "romanLcParenR",
        ("i", _, _) => "romanLcPeriod",
        ("I", true, _) => "romanUcParenBoth",
        ("I", _, true) => "romanUcParenR",
        ("I", _, _) => "romanUcPeriod",
        (_, true, _) => "arabicParenBoth",
        (_, _, true) => "arabicParenR",
        (_, _, _) => {
            if suffix.is_empty() {
                "arabicPlain"
            } else {
                "arabicPeriod"
            }
        }
    }
}

/// A list level's bullet and the margins it sets.
fn bullet(lv: &ListLevel, styles: &Styles) -> (Option<Bullet>, Option<Emu>, Option<Emu>) {
    let p = &lv.props;
    let font = p
        .get("style:font-name")
        .map(|n| styles.font(n))
        .or_else(|| {
            p.get("fo:font-family")
                .map(|f| f.trim_matches(['\'', '"']).to_string())
        });
    let color = p
        .color("fo:color")
        .filter(|_| !p.is("style:use-window-font-color", "true"))
        .map(Color::rgb);
    let size = p
        .get("fo:font-size")
        .and_then(percent)
        .map(|f| (f * 100_000.0).round().clamp(25_000.0, 400_000.0) as u32);
    let b = match lv.kind {
        "bullet" => Some(Bullet::Char {
            ch: lv.bullet.filter(|c| !c.is_control()).unwrap_or('\u{2022}'),
            font,
            color,
            size,
        }),
        "number" if !lv.num_format.is_empty() => Some(Bullet::AutoNum {
            scheme: scheme(
                &lv.num_format,
                &lv.num_suffix,
                p.is("style:num-prefix", "("),
            ),
            start: lv.start.max(1),
            font,
            color,
            size,
        }),
        // A picture bullet whose picture is missing is a round one.
        "image" => Some(Bullet::Char {
            ch: '\u{2022}',
            font: None,
            color,
            size,
        }),
        _ => Some(Bullet::None),
    };
    // Label width and position, or label alignment.
    let (margin, indent) = if let Some(m) = p
        .len("fo:margin-left")
        .filter(|_| p.get("text:list-level-position-and-space-mode") == Some("label-alignment"))
    {
        (Some(m), p.len("fo:text-indent"))
    } else {
        let before = p.len("text:space-before").unwrap_or(0);
        let width = p.len("text:min-label-width").unwrap_or(0);
        if p.get("text:space-before").is_some() || p.get("text:min-label-width").is_some() {
            (Some(before + width), Some(-width))
        } else {
            (None, None)
        }
    };
    (b, margin, indent)
}

/// Collapses runs of white space ([ODF 1.2] 6.1.2).
fn collapse(s: &str, at_start: bool) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = at_start;
    for c in s.chars() {
        if matches!(c, ' ' | '\t' | '\n' | '\r') {
            if !space {
                out.push(' ');
                space = true;
            }
        } else {
            out.push(c);
            space = false;
        }
    }
    out
}

struct Inline<'c, 'a> {
    ctx: &'c mut TextCtx<'a>,
    runs: Vec<Run>,
    at_start: bool,
    /// The next text starts a run of its own: a link's label, which is given
    /// its link after it is read, is not merged into the run before it.
    fresh: bool,
}

impl Inline<'_, '_> {
    fn text(&mut self, s: String, props: &RunProps) {
        if s.is_empty() {
            return;
        }
        self.at_start = s.ends_with(' ');
        let fresh = std::mem::take(&mut self.fresh);
        if let Some(Run {
            kind: RunKind::Text(t),
            props: p,
        }) = self.runs.last_mut()
            && !fresh
            && p == props
        {
            t.push_str(&s);
            return;
        }
        self.runs.push(Run {
            kind: RunKind::Text(s),
            props: props.clone(),
        });
    }

    fn walk(&mut self, n: &Node, props: &Props, size: f64, depth: u32) {
        if depth > 32 {
            return;
        }
        let rp = run_props(props, size, self.ctx.styles, self.ctx.auto_color);
        for c in &n.children {
            match c {
                Child::Text(t) => {
                    let s = collapse(t, self.at_start);
                    self.text(s, &rp);
                }
                Child::Node(k) => match k.name.as_str() {
                    "text:s" => {
                        let n = k
                            .attr("text:c")
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(1)
                            .min(1000);
                        self.text(" ".repeat(n), &rp);
                        self.at_start = false;
                    }
                    "text:tab" => {
                        self.text("\t".into(), &rp);
                        self.at_start = false;
                    }
                    "text:line-break" => {
                        self.runs.push(Run {
                            kind: RunKind::Break,
                            props: rp.clone(),
                        });
                        self.at_start = true;
                    }
                    "text:span" => {
                        let mut p = props.clone();
                        let sp = self.ctx.styles.chain("text", k.attr("text:style-name"));
                        p.overlay(&sp.0);
                        let size = font_size(&sp, size);
                        self.walk(k, &p, size, depth + 1);
                    }
                    "text:a" => {
                        let start = self.runs.len();
                        self.fresh = true;
                        self.walk(k, props, size, depth + 1);
                        if let Some(link) = k.attr("xlink:href").and_then(Link::url) {
                            for r in &mut self.runs[start..] {
                                r.props.link = Some(link.clone());
                            }
                        }
                    }
                    "text:page-number" => {
                        let n = self.ctx.slide_number.to_string();
                        self.runs.push(Run {
                            kind: RunKind::Field("slidenum", n),
                            props: rp.clone(),
                        });
                        self.at_start = false;
                    }
                    "text:date" | "text:time" | "presentation:date-time" => {
                        let t = if k.name == "presentation:date-time" {
                            self.ctx.date.to_string()
                        } else {
                            super::styles::text_of(k)
                        };
                        self.text(t, &rp);
                    }
                    "presentation:footer" => {
                        let t = self.ctx.footer.to_string();
                        self.text(t, &rp);
                    }
                    "presentation:header" => {
                        let t = self.ctx.header.to_string();
                        self.text(t, &rp);
                    }
                    "text:note" | "office:annotation" | "text:soft-page-break" | "draw:frame" => {}
                    _ => self.walk(k, props, size, depth + 1),
                },
            }
        }
    }
}

/// The text of a shape node (a text box, or a shape holding text:p and
/// text:list directly) as paragraphs.
pub fn paragraphs(n: &Node, ctx: &mut TextCtx) -> Vec<Paragraph> {
    let mut out = vec![];
    collect(n, ctx, 0, None, &mut out, 0);
    out
}

fn collect(
    n: &Node,
    ctx: &mut TextCtx,
    level: usize,
    list: Option<&ListDef>,
    out: &mut Vec<Paragraph>,
    depth: u32,
) {
    for c in n.nodes() {
        collect_one(c, ctx, level, list, out, depth);
    }
}

fn collect_one(
    c: &Node,
    ctx: &mut TextCtx,
    level: usize,
    list: Option<&ListDef>,
    out: &mut Vec<Paragraph>,
    depth: u32,
) {
    if depth > 32 || out.len() > 1 << 16 {
        return;
    }
    match c.name.as_str() {
        "text:p" | "text:h" => out.push(paragraph(c, ctx, level, list)),
        "text:list" => {
            let own_list = c
                .attr("text:style-name")
                .and_then(|s| ctx.styles.list_names.get(s))
                .and_then(|&i| ctx.styles.lists.get(i));
            // A list's style holds for its nested lists too.
            let l = own_list.or(list).or(ctx.list);
            for item in c.nodes() {
                if item.name == "text:list-header" {
                    // The header's own paragraphs have no bullet; the lists
                    // nested in it do.
                    for k in item.nodes() {
                        let before = out.len();
                        collect_one(k, ctx, level + 1, l, out, depth + 1);
                        if matches!(k.name.as_str(), "text:p" | "text:h") {
                            for p in &mut out[before..] {
                                p.props.bullet = Some(Bullet::None);
                            }
                        }
                    }
                } else if item.name == "text:list-item" {
                    collect(item, ctx, level + 1, l, out, depth + 1);
                }
            }
        }
        "draw:text-box" => collect(c, ctx, level, list, out, depth + 1),
        _ => {}
    }
}

fn paragraph(p: &Node, ctx: &mut TextCtx, list_level: usize, list: Option<&ListDef>) -> Paragraph {
    let lv = list_level.max(1);
    // Shape style, outline level style, then the paragraph's own style.
    let mut props = ctx.base.clone();
    if list_level > 0
        && let Some(l) = (ctx.levels)(lv)
    {
        props.overlay(&l.0);
    }
    let ps = ctx.styles.chain("paragraph", p.attr("text:style-name"));
    props.overlay(&ps.0);
    let mut size = font_size(ctx.base, 18.0);
    if list_level > 0
        && let Some(l) = (ctx.levels)(lv)
    {
        size = font_size(&l, size);
    }
    size = font_size(&ps, size);
    let mut pp = para_props(&props);
    pp.level = (lv - 1).min(8) as u8;
    if list_level > 0 {
        let level = list.and_then(|l| {
            l.levels
                .iter()
                .find(|x| x.0 == lv)
                .or_else(|| l.levels.iter().rev().find(|x| x.0 < lv))
        });
        match level {
            Some((_, lvl)) => {
                let (mut b, margin, indent) = bullet(lvl, ctx.styles);
                if let (Some(img), "image") = (&lvl.image, lvl.kind) {
                    let size = match &b {
                        Some(Bullet::Char { size, .. }) => *size,
                        _ => None,
                    };
                    ctx.pictures.push(img.clone());
                    b = Some(Bullet::Picture {
                        media: ctx.pictures.len() - 1,
                        size,
                    });
                }
                pp.bullet = b;
                let base_margin = pp.margin.unwrap_or(0);
                if let Some(m) = margin {
                    pp.margin = Some(base_margin + m);
                    pp.indent = indent;
                }
            }
            None => pp.bullet = Some(Bullet::None),
        }
    } else {
        pp.bullet = Some(Bullet::None);
    }
    let end = run_props(&props, size, ctx.styles, ctx.auto_color);
    let mut il = Inline {
        ctx,
        runs: vec![],
        at_start: true,
        fresh: false,
    };
    il.walk(p, &props, size, 0);
    let mut runs = il.runs;
    // Trailing collapsed space at the paragraph's end is dropped.
    if let Some(Run {
        kind: RunKind::Text(t),
        ..
    }) = runs.last_mut()
    {
        let trimmed = t.trim_end_matches(' ').len();
        if trimmed > 0 {
            t.truncate(trimmed);
        }
    }
    Paragraph {
        props: pp,
        runs,
        end,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn white_space_collapses() {
        assert_eq!(collapse("  a \n  b ", true), "a b ");
        assert_eq!(collapse(" a", false), " a");
    }

    #[test]
    fn number_schemes() {
        assert_eq!(scheme("1", ".", false), "arabicPeriod");
        assert_eq!(scheme("a", ")", true), "alphaLcParenBoth");
        assert_eq!(scheme("I", ".", false), "romanUcPeriod");
    }
}
