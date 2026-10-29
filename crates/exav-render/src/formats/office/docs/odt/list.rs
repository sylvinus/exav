//! List styles as numbering definitions.

use super::{Odt, props};
use crate::formats::office::common::odf::{self, ListDef, Props};
use crate::formats::office::docs::model::*;

fn num_fmt(f: &str) -> &'static str {
    match f {
        "1" => "decimal",
        "a" => "lowerLetter",
        "A" => "upperLetter",
        "i" => "lowerRoman",
        "I" => "upperRoman",
        "" => "none",
        _ => "decimal",
    }
}

/// A bullet written in a private-use code point of a symbol font.
fn bullet_char(c: char) -> String {
    match c {
        '\u{E000}'..='\u{F8FF}' => "\u{2022}".to_string(),
        c => c.to_string(),
    }
}

impl Odt<'_> {
    fn list_def(&self, name: &str) -> Option<ListDef> {
        let (s, k) = (&self.cs, &self.ms);
        s.list_names
            .get(name)
            .map(|i| s.lists[*i].clone())
            .or_else(|| k.list_names.get(name).map(|i| k.lists[*i].clone()))
    }

    fn abstract_of(&mut self, style: &str) -> Option<u32> {
        if let Some(i) = self.abstracts.get(style) {
            return Some(*i);
        }
        let def = self.list_def(style)?;
        let mut levels: Vec<Level> = vec![];
        for lvl in 1..=9usize {
            let l = def
                .levels
                .iter()
                .rev()
                .find(|(n, _)| *n == lvl)
                .map(|x| &x.1);
            levels.push(match l {
                Some(x) => self.level_of(x, lvl),
                None => Level {
                    fmt: "none",
                    ..Level::default()
                },
            });
        }
        let id = self.doc.numbering.abstracts.len() as u32;
        self.doc.numbering.abstracts.push(AbstractNum {
            id,
            multi_level: true,
            levels,
        });
        self.abstracts.insert(style.to_string(), id);
        Some(id)
    }

    fn level_of(&self, x: &odf::ListLevel, lvl: usize) -> Level {
        let mut l = Level {
            start: x
                .attr("text:start-value")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            ..Level::default()
        };
        let prefix = x.attr("style:num-prefix").unwrap_or("");
        let suffix = x.attr("style:num-suffix").unwrap_or("");
        match x.kind {
            "number" => {
                l.fmt = num_fmt(x.attr("style:num-format").unwrap_or("1"));
                let show = x
                    .attr("text:display-levels")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(1)
                    .clamp(1, lvl);
                let mut t = String::from(prefix);
                if l.fmt != "none" {
                    for k in (lvl - show + 1)..=lvl {
                        if k > lvl - show + 1 {
                            t.push('.');
                        }
                        t.push_str(&format!("%{k}"));
                    }
                    t.push_str(suffix);
                } else {
                    t.clear();
                }
                l.text = t;
                l.legal = false;
            }
            "bullet" => {
                l.fmt = "bullet";
                l.text = x
                    .attr("text:bullet-char")
                    .and_then(|s| s.chars().next())
                    .map(bullet_char)
                    .unwrap_or_else(|| "\u{2022}".into());
            }
            "image" => {
                l.fmt = "bullet";
                l.text = "\u{2022}".into();
            }
            _ => l.fmt = "none",
        }
        // Where the label and the text sit.
        let p = &x.props;
        let (left, hanging, tab, suff);
        if p.get("label-alignment/fo:margin-left").is_some()
            || p.get("label-alignment/text:label-followed-by").is_some()
        {
            left = p.twips("label-alignment/fo:margin-left").unwrap_or(0);
            let indent = p.twips("label-alignment/fo:text-indent").unwrap_or(0);
            hanging = -indent;
            suff = match p.get("label-alignment/text:label-followed-by") {
                Some("space") => "space",
                Some("nothing") => "nothing",
                _ => "tab",
            };
            tab = p.twips("label-alignment/text:list-tab-stop-position");
        } else {
            let before = p.twips("list-level/text:space-before").unwrap_or(0);
            let width = p.twips("list-level/text:min-label-width").unwrap_or(0);
            left = before + width;
            hanging = width;
            tab = None;
            suff = "tab";
        }
        l.suff = suff;
        l.ppr.ind_left = Some(left);
        if hanging > 0 {
            l.ppr.ind_hanging = Some(hanging);
        } else if hanging < 0 {
            l.ppr.ind_first_line = Some(-hanging);
        } else {
            l.ppr.ind_first_line = Some(0);
        }
        if let Some(t) = tab.filter(|t| *t > left) {
            l.ppr.tabs.push(Tab {
                pos: t,
                kind: TabKind::Left,
                leader: TabLeader::None,
            });
        }
        // The label's own character formatting.
        let mut rpr = props::run_props(&Props(p.0.clone()), &self.cs, 24);
        if rpr
            .fonts
            .ascii
            .as_deref()
            .is_some_and(|f| f.eq_ignore_ascii_case("OpenSymbol"))
        {
            rpr.fonts = Fonts::default();
        }
        l.rpr = rpr;
        if x.kind == "bullet" {
            // The text style of a bullet is its own; keep colour and size only.
            l.rpr.fonts = Fonts::default();
        }
        l
    }

    /// The instance of list style `style` for a list that starts here.
    pub(crate) fn list_num(&mut self, style: &str, continue_: bool, restart: bool) -> Option<u32> {
        let abs = self.abstract_of(style)?;
        if (continue_ || restart)
            && let Some(n) = self.last_num.get(style)
            && !restart
        {
            return Some(*n);
        }
        let id = self.doc.numbering.nums.len() as u32 + 1;
        let seen = self.last_num.contains_key(style);
        let mut overrides = vec![];
        if seen {
            // A list that does not continue starts again at its first number.
            let starts: Vec<i64> = self.doc.numbering.abstracts[abs as usize]
                .levels
                .iter()
                .map(|l| l.start)
                .collect();
            for (lvl, s) in starts.into_iter().enumerate() {
                overrides.push((lvl as u32, Some(s), None));
            }
        }
        self.doc.numbering.nums.push(Num {
            id,
            abstract_id: abs,
            overrides,
        });
        self.last_num.insert(style.to_string(), id);
        Some(id)
    }

    /// The numbering of headings, when the outline style numbers any level.
    pub(crate) fn outline_num_id(&mut self) -> Option<u32> {
        if self.outline_num.is_none() {
            let numbered = self.cs.list_names.get("<outline>").is_some_and(|i| {
                self.cs.lists[*i].levels.iter().any(|(_, l)| {
                    l.kind == "number" && !l.attr("style:num-format").unwrap_or("").is_empty()
                })
            });
            self.outline_num = Some(if numbered {
                self.list_num("<outline>", true, false).unwrap_or(0)
            } else {
                0
            });
        }
        self.outline_num.filter(|n| *n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_bullets() {
        assert_eq!(num_fmt("a"), "lowerLetter");
        assert_eq!(num_fmt(""), "none");
        assert_eq!(bullet_char('\u{E00A}'), "\u{2022}");
        assert_eq!(bullet_char('-'), "-");
    }
}
