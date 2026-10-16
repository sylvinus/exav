//! Control words: character, paragraph, section and document formatting,
//! destinations and special characters.

use super::{Dest, Font, ListDef, ListLevelDef, Parser, RStyle, St, Target};
use crate::formats::office::docs::error::Result;
use crate::formats::office::docs::model::*;

fn flag(n: Option<i32>) -> bool {
    n != Some(0)
}

fn cp_of_charset(c: i32) -> Option<u16> {
    Some(match c {
        0 => 1252,
        1 => 1252,
        2 => 42,
        77 => 10000,
        128 => 932,
        129 => 949,
        130 => 1361,
        134 => 936,
        136 => 950,
        161 => 1253,
        162 => 1254,
        163 => 1258,
        177 => 1255,
        178 => 1256,
        186 => 1257,
        204 => 1251,
        222 => 874,
        238 => 1250,
        254 => 437,
        255 => 850,
        _ => return None,
    })
}

fn border_style(w: &str) -> Option<&'static str> {
    Some(match w {
        "brdrs" => "single",
        "brdrth" => "thick",
        "brdrsh" => "single",
        "brdrdb" => "double",
        "brdrdot" => "dotted",
        "brdrdash" => "dashed",
        "brdrhair" => "single",
        "brdrdashsm" => "dashSmallGap",
        "brdrdashd" => "dotDash",
        "brdrdashdd" => "dotDotDash",
        "brdrtriple" => "triple",
        "brdrtnthsg" => "thinThickSmallGap",
        "brdrthtnsg" => "thickThinSmallGap",
        "brdrtnthtnsg" => "thinThickThinSmallGap",
        "brdrtnthmg" => "thinThickMediumGap",
        "brdrthtnmg" => "thickThinMediumGap",
        "brdrtnthtnmg" => "thinThickThinMediumGap",
        "brdrtnthlg" => "thinThickLargeGap",
        "brdrthtnlg" => "thickThinLargeGap",
        "brdrtnthtnlg" => "thinThickThinLargeGap",
        "brdrwavy" => "wave",
        "brdrwavydb" => "doubleWave",
        "brdrdashdotstr" => "dashDotStroked",
        "brdremboss" => "threeDEmboss",
        "brdrengrave" => "threeDEngrave",
        "brdroutset" => "outset",
        "brdrinset" => "inset",
        _ => return None,
    })
}

fn underline_of(w: &str) -> Option<&'static str> {
    Some(match w {
        "ul" => "single",
        "uld" => "dotted",
        "uldash" => "dash",
        "uldashd" => "dotDash",
        "uldashdd" => "dotDotDash",
        "uldb" => "double",
        "ulth" => "thick",
        "ulthd" => "dottedHeavy",
        "ulthdash" => "dashedHeavy",
        "ulw" => "words",
        "ulwave" => "wave",
        "ulhwave" => "wavyHeavy",
        "ulldash" => "dashLong",
        "ululdbwave" => "wavyDouble",
        _ => return None,
    })
}

/// A destination written `\*\word`: whether it is one read here.
pub(crate) fn star_destination(p: &mut Parser<'_>, w: &str, n: Option<i32>) -> bool {
    match w {
        "bkmkstart" => {
            p.buf.clear();
            p.top().dest = Dest::Bookmark(true);
            true
        }
        "bkmkend" => {
            p.buf.clear();
            p.top().dest = Dest::Bookmark(false);
            true
        }
        "fldinst" => {
            p.top().dest = Dest::FldInst;
            true
        }
        "listtable" => {
            p.top().dest = Dest::ListTable;
            true
        }
        "listoverridetable" => {
            p.top().dest = Dest::ListOverrideTable;
            true
        }
        "shppict" => {
            p.top().dest = Dest::Body;
            true
        }
        "shpinst" => {
            p.top().dest = Dest::Body;
            true
        }
        "ud" => {
            p.top().dest = Dest::Body;
            true
        }
        "cs" | "ts" => {
            style_entry(p, w, n);
            true
        }
        "ftnalt" => {
            p.note_endnote = true;
            true
        }
        _ => false,
    }
}

fn style_entry(p: &mut Parser<'_>, w: &str, n: Option<i32>) {
    let kind = match w {
        "cs" => StyleKind::Character,
        "ts" => StyleKind::Table,
        _ => StyleKind::Paragraph,
    };
    p.buf.clear();
    p.styles.push(RStyle {
        num: n.unwrap_or(0),
        kind,
        name: String::new(),
        based: None,
        next: None,
        chp: RunProps::default(),
        pap: ParaProps::default(),
        ls: None,
        ilvl: 0,
    });
    let i = p.styles.len() - 1;
    p.top().dest = Dest::StyleEntry(i);
}

pub(crate) fn finish_level(p: &mut Parser<'_>, st: &St) {
    let Some(Dest::List(li)) = p.stack.last().map(|s| s.dest.clone()) else {
        return;
    };
    let mut l = st.level_tmp.clone().unwrap_or_default();
    l.ppr = st.pap.clone();
    l.ppr.num_id = None;
    l.ppr.num_level = None;
    l.ppr.style = None;
    l.rpr = st.chp.clone();
    let text = std::mem::take(&mut p.list_text);
    let numbers = std::mem::take(&mut p.list_numbers);
    if let Some(def) = p.lists.get_mut(li) {
        def.levels.push(ListLevelDef {
            level: l,
            text,
            numbers,
        });
    }
}

impl Parser<'_> {
    /// One control word.
    pub(crate) fn word(&mut self, w: &str, n: Option<i32>, max: u64) -> Result<()> {
        let dest = self.top().dest.clone();
        // Destinations first.
        match w {
            "fonttbl" => {
                self.top().dest = Dest::FontTable;
                return Ok(());
            }
            "colortbl" => {
                self.top().dest = Dest::ColorTable;
                self.color_cur = [0; 3];
                self.color_any = false;
                return Ok(());
            }
            "stylesheet" => {
                self.top().dest = Dest::StyleSheet;
                return Ok(());
            }
            "info" | "private" | "xmlnstbl" | "rsidtbl" | "generator" | "revtbl" | "themedata"
            | "colorschememapping" | "datastore" | "latentstyles" | "mmathPr" | "mmath"
            | "pgptbl" | "protusertbl" | "userprops" | "listtext" | "pntext" | "pn"
            | "pnseclvl" | "objdata" | "objclass" | "objname" | "falt" | "fldtype"
            | "nonshppict" | "template" | "passwordhash" | "wgrffmtfilter" | "factoidname"
            | "background" | "docvar" | "mmathPict" | "oleclsid" | "blipuid" | "picprop"
            | "formfield" | "datafield" | "ftnsep" | "ftnsepc" | "aftnsep" | "aftnsepc"
            | "footnotesep" | "txfieldtext" | "fchars" | "lchars" | "nesttableprops"
            | "nonesttables" | "keycode" | "stylesheetx" | "ffname" | "ffl" | "ffhelptext"
            | "ffstattext" | "ffentrymcr" | "ffexitmcr" => {
                if w == "falt" || w == "ffname" {
                    // Alternate names do not name the font.
                }
                self.top().dest = Dest::Skip;
                return Ok(());
            }
            "upr" => {
                self.top().dest = Dest::Upr;
                return Ok(());
            }
            "pict" => {
                self.top().dest = Dest::Pict;
                self.pict = Some(super::pict::Pict::default());
                return Ok(());
            }
            "field" => {
                self.top().dest = Dest::Field;
                self.begin_field();
                return Ok(());
            }
            "fldinst" => {
                self.top().dest = Dest::FldInst;
                return Ok(());
            }
            "fldrslt" => {
                self.top().dest = Dest::FldRslt;
                if let Some(f) = self.fields.last_mut() {
                    f.in_result = true;
                }
                return Ok(());
            }
            "footnote" => {
                self.flush_text();
                self.note_endnote = false;
                self.push_story();
                self.top().dest = Dest::Note;
                return Ok(());
            }
            "header" | "headerl" | "headerr" | "headerf" | "footer" | "footerl" | "footerr"
            | "footerf" => {
                let which = match w {
                    "headerl" | "footerl" => 1,
                    "headerr" | "footerr" => 2,
                    "headerf" | "footerf" => 3,
                    _ => 0,
                };
                self.push_story();
                self.top().dest = Dest::HeaderFooter(w.starts_with("header"), which);
                return Ok(());
            }
            // Shapes: their properties are not read, their text and pictures
            // flow with the text around them.
            "sp" => {
                self.top().dest = Dest::Skip;
                return Ok(());
            }
            "listlevel" => {
                if matches!(dest, Dest::List(_)) {
                    self.top().dest = Dest::ListLevel;
                    self.top().level_tmp = Some(Level::default());
                    // A level inherits nothing: its words start clean.
                    let st = self.top();
                    st.pap = ParaProps::default();
                    st.chp = RunProps::default();
                    return Ok(());
                }
            }
            "list" => {
                if matches!(dest, Dest::ListTable) {
                    self.lists.push(ListDef {
                        id: 0,
                        levels: vec![],
                        simple: false,
                    });
                    let i = self.lists.len() - 1;
                    self.top().dest = Dest::List(i);
                    return Ok(());
                }
            }
            "listoverride" => {
                if matches!(dest, Dest::ListOverrideTable) {
                    self.overrides.push((0, 0, vec![]));
                    self.top().dest = Dest::ListOverride;
                    return Ok(());
                }
            }
            "leveltext" => {
                self.list_text.clear();
                self.top().dest = Dest::LevelText;
                return Ok(());
            }
            "levelnumbers" => {
                self.list_numbers.clear();
                self.top().dest = Dest::LevelNumbers;
                return Ok(());
            }
            _ => {}
        }
        // Words of the destination being read.
        match &dest {
            Dest::Skip | Dest::Pict if !matches!(w, "bin") => {
                if dest == Dest::Pict {
                    return self.pict_word(w, n, max);
                }
                return Ok(());
            }
            Dest::FontTable | Dest::FontEntry(_) => {
                return self.font_word(w, n);
            }
            Dest::ColorTable => {
                match w {
                    "red" => {
                        self.color_cur[0] = n.unwrap_or(0);
                        self.color_any = true;
                    }
                    "green" => {
                        self.color_cur[1] = n.unwrap_or(0);
                        self.color_any = true;
                    }
                    "blue" => {
                        self.color_cur[2] = n.unwrap_or(0);
                        self.color_any = true;
                    }
                    _ => {}
                }
                return Ok(());
            }
            Dest::StyleSheet => {
                if matches!(w, "s" | "cs" | "ts") {
                    style_entry(self, w, n);
                    return Ok(());
                }
            }
            Dest::StyleEntry(i) => {
                let i = *i;
                match w {
                    "sbasedon" => {
                        self.styles[i].based = n;
                        return Ok(());
                    }
                    "snext" => {
                        self.styles[i].next = n;
                        return Ok(());
                    }
                    "s" | "cs" | "ts" => {
                        self.styles[i].num = n.unwrap_or(0);
                        return Ok(());
                    }
                    "additive" | "sautoupd" | "slink" | "slocked" | "ssemihidden" | "sqformat"
                    | "spriority" | "styrsid" | "shidden" | "sunhideused" => return Ok(()),
                    _ => {}
                }
            }
            Dest::ListTable | Dest::ListOverrideTable => return Ok(()),
            Dest::List(i) => {
                let i = *i;
                match w {
                    "listid" => self.lists[i].id = n.unwrap_or(0),
                    "listsimple" => self.lists[i].simple = n != Some(0),
                    _ => {}
                }
                return Ok(());
            }
            Dest::ListOverride => {
                if let Some(o) = self.overrides.last_mut() {
                    match w {
                        "listid" => o.0 = n.unwrap_or(0),
                        "ls" => o.1 = n.unwrap_or(0),
                        "lfolevel" => {}
                        "listoverridestartat" => {}
                        "levelstartat" => {
                            let lvl = o.2.len() as u32;
                            o.2.push((lvl, i64::from(n.unwrap_or(1))));
                        }
                        _ => {}
                    }
                }
                return Ok(());
            }
            Dest::ListLevel => {
                if self.level_word(w, n) {
                    return Ok(());
                }
            }
            Dest::LevelText | Dest::LevelNumbers => {
                if w == "u" {
                    let v = n.unwrap_or(0);
                    let c = if v < 0 { v + 65536 } else { v } as u32;
                    if matches!(dest, Dest::LevelText) {
                        self.list_text.push(c);
                    }
                    let uc = self.top().uc;
                    self.lex.skip_fallback(uc);
                }
                return Ok(());
            }
            Dest::Bookmark(_) | Dest::FldInst => {
                if w == "u" {
                    self.unicode(n);
                }
                return Ok(());
            }
            _ => {}
        }
        self.format_word(w, n, &dest, max)
    }

    fn unicode(&mut self, n: Option<i32>) {
        let v = n.unwrap_or(0);
        let c = if v < 0 { v + 65536 } else { v } as u32;
        let uc = self.top().uc;
        self.lex.skip_fallback(uc);
        self.flush_text();
        let ch = char::from_u32(c).unwrap_or('\u{FFFD}');
        let ch = if (0xF020..=0xF0FF).contains(&c) {
            // Symbol-font code points keep their private-use form.
            ch
        } else {
            ch
        };
        let s = ch.to_string();
        self.put_str_pub(&s);
    }

    fn font_word(&mut self, w: &str, n: Option<i32>) -> Result<()> {
        match w {
            "f" => {
                let id = n.unwrap_or(0);
                self.buf.clear();
                self.fonts.entry(id).or_insert(Font {
                    name: String::new(),
                    cp: self.default_cp,
                });
                self.top().dest = Dest::FontEntry(id);
            }
            "fcharset" => {
                if let (Dest::FontEntry(id), Some(cp)) =
                    (self.top().dest.clone(), cp_of_charset(n.unwrap_or(0)))
                {
                    if let Some(f) = self.fonts.get_mut(&id) {
                        f.cp = cp;
                    }
                }
            }
            "cpg" => {
                if let Dest::FontEntry(id) = self.top().dest.clone() {
                    if let Some(f) = self.fonts.get_mut(&id) {
                        f.cp = n.unwrap_or(1252).clamp(0, 65535) as u16;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn level_word(&mut self, w: &str, n: Option<i32>) -> bool {
        let st = self.top();
        let l = st.level_tmp.get_or_insert_with(Level::default);
        match w {
            "levelnfc" | "levelnfcn" => {
                let nfc = n.unwrap_or(0);
                l.fmt = crate::formats::office::docs::doc::lists::number_format(
                    nfc.clamp(0, 255) as u8
                );
            }
            "leveljc" | "leveljcn" => {
                l.jc = match n.unwrap_or(0) {
                    1 => Jc::Center,
                    2 => Jc::Right,
                    _ => Jc::Left,
                }
            }
            "levelfollow" => {
                l.suff = match n.unwrap_or(0) {
                    1 => "space",
                    2 => "nothing",
                    _ => "tab",
                }
            }
            "levelstartat" => l.start = i64::from(n.unwrap_or(1)),
            "levelnorestart" => l.restart = Some(0),
            "levellegal" => l.legal = flag(n),
            "levelspace" | "levelindent" | "levelold" | "levelprev" | "levelprevspace"
            | "levelpicture" => {}
            _ => return false,
        }
        true
    }

    // ---- formatting ----

    fn color_at(&self, i: i32) -> Option<Color> {
        usize::try_from(i)
            .ok()
            .and_then(|i| self.colors.get(i))
            .copied()
    }

    fn border_target(&mut self) -> Option<&mut Border> {
        let t = self.top().target;
        let new = || Border::single(4, Color::Auto);
        match t {
            Target::None => None,
            Target::Para(s) => {
                let b = &mut self.stack.last_mut()?.pap.borders;
                let slot = match s {
                    0 => &mut b.top,
                    1 => &mut b.left,
                    2 => &mut b.bottom,
                    3 => &mut b.right,
                    _ => &mut b.between,
                };
                Some(slot.get_or_insert_with(new))
            }
            Target::Cell(s) => {
                let c = &mut self.row.cur;
                let slot = c.borders.get_mut(usize::from(s))?;
                let inner = slot.get_or_insert(None);
                Some(inner.get_or_insert_with(new))
            }
            Target::Row(s) => {
                let b = &mut self.row.borders;
                let slot = match s {
                    0 => &mut b.top,
                    1 => &mut b.left,
                    2 => &mut b.bottom,
                    3 => &mut b.right,
                    4 => &mut b.inside_h,
                    _ => &mut b.inside_v,
                };
                Some(slot.get_or_insert_with(new))
            }
        }
    }

    fn format_word(&mut self, w: &str, n: Option<i32>, dest: &Dest, max: u64) -> Result<()> {
        let _ = max;
        let v = n.unwrap_or(0);
        // Borders first: their words are modifiers of the side selected.
        if let Some(rest) = w.strip_prefix("brdr") {
            let side = match rest {
                "t" => Some(Target::Para(0)),
                "l" => Some(Target::Para(1)),
                "b" => Some(Target::Para(2)),
                "r" => Some(Target::Para(3)),
                "btw" => Some(Target::Para(4)),
                "bar" | "box" => None,
                _ => None,
            };
            if rest == "box" {
                // All four sides get the settings that follow.
                self.top().target = Target::Para(9);
                for s in 0..4 {
                    self.top().target = Target::Para(s);
                    self.border_target();
                }
                self.top().target = Target::Para(0);
                return Ok(());
            }
            if let Some(t) = side {
                self.top().target = t;
                self.border_target();
                return Ok(());
            }
            if rest == "nil" || rest == "none" {
                self.clear_border();
                return Ok(());
            }
            if let Some(s) = border_style(w) {
                if let Some(b) = self.border_target() {
                    b.style = s;
                    if w == "brdrth" {
                        b.size = b.size.max(12);
                    }
                }
                return Ok(());
            }
            match w {
                "brdrw" => {
                    if let Some(b) = self.border_target() {
                        b.size = ((v.max(0) as u32 * 8 + 10) / 20).clamp(2, 96);
                    }
                    return Ok(());
                }
                "brdrcf" => {
                    let c = self.color_at(v);
                    if let Some(b) = self.border_target() {
                        b.color = c.unwrap_or(Color::Auto);
                    }
                    return Ok(());
                }
                "brdrsh" => return Ok(()),
                _ => return Ok(()),
            }
        }
        if w == "brsp" {
            if let Some(b) = self.border_target() {
                b.space = (v.max(0) as u32 / 20).min(31);
            }
            return Ok(());
        }
        if let Some(u) = underline_of(w) {
            self.top().chp.underline = Some(if flag(n) { u } else { "none" });
            return Ok(());
        }
        let is_text =
            dest.is_text() || matches!(dest, Dest::StyleEntry(_) | Dest::ListLevel | Dest::Upr);
        let st = self.stack.last_mut().expect("a group is open");
        match w {
            // ---- character ----
            "plain" => {
                st.chp = RunProps::default();
            }
            "b" => st.chp.bold = Some(flag(n)),
            "i" => st.chp.italic = Some(flag(n)),
            "ab" => st.chp.bold_cs = Some(flag(n)),
            "ai" => st.chp.italic_cs = Some(flag(n)),
            "strike" => st.chp.strike = Some(flag(n)),
            "striked" => {
                if flag(n) {
                    st.chp.dstrike = Some(true);
                } else {
                    st.chp.dstrike = Some(false);
                }
            }
            "scaps" => st.chp.small_caps = Some(flag(n)),
            "caps" => st.chp.caps = Some(flag(n)),
            "v" => st.chp.vanish = Some(flag(n)),
            "outl" => st.chp.outline = Some(flag(n)),
            "shad" => st.chp.shadow = Some(flag(n)),
            "embo" => st.chp.emboss = Some(flag(n)),
            "impr" => st.chp.imprint = Some(flag(n)),
            "ulnone" => st.chp.underline = Some("none"),
            "ulc" => {
                let c = self
                    .colors
                    .get(usize::try_from(v).unwrap_or(usize::MAX))
                    .copied();
                self.top().chp.underline_color = c;
            }
            "super" => st.chp.vert_align = Some(VertAlign::Superscript),
            "sub" => st.chp.vert_align = Some(VertAlign::Subscript),
            "nosupersub" => st.chp.vert_align = Some(VertAlign::Baseline),
            "up" => st.chp.position = Some(v),
            "dn" => st.chp.position = Some(-v),
            "fs" => {
                st.chp.size = Some(v.clamp(1, 3277) as u32);
                st.chp.size_cs = st.chp.size;
            }
            "expnd" => st.chp.spacing = Some(v * 5),
            "expndtw" => st.chp.spacing = Some(v),
            "charscalex" => st.chp.scale = Some(v.clamp(1, 600) as u32),
            "kerning" => st.chp.kerning = Some(v.max(0) as u32),
            "rtlch" => st.chp.rtl = Some(true),
            "ltrch" => st.chp.rtl = Some(false),
            "cf" => {
                let c = self.color_at(v);
                self.top().chp.color = c;
            }
            "highlight" => {
                let c = self.color_at(v);
                let st = self.top();
                st.chp.shading = match c {
                    Some(Color::Rgb(_)) => c.map(Shading::fill),
                    _ => None,
                };
            }
            "cb" | "chcbpat" => {
                let c = self.color_at(v);
                self.top().chp.shading = match c {
                    Some(Color::Rgb(_)) => c.map(Shading::fill),
                    _ => None,
                };
            }
            "f" | "loch" | "hich" | "dbch" | "af" => {
                // \f selects the font; \af the one for complex scripts.
                if w == "f" {
                    self.set_font(v);
                } else if w == "af" {
                    let name = self.fonts.get(&v).map(|f| f.name.clone());
                    self.top().chp.fonts.cs = name;
                }
            }
            "lang" | "langnp" => {
                self.top().chp.lang = lang_tag(v);
            }
            "langfe" | "langfenp" => {
                self.top().chp.lang_east_asia = lang_tag(v);
            }
            "uc" => st.uc = v.max(0) as u32,
            "u" => {
                if is_text || matches!(dest, Dest::Field) {
                    self.unicode(n);
                }
            }
            "cs" => {
                if let Some(id) = self.style_id_of(v, StyleKind::Character) {
                    self.top().chp.style = Some(id);
                }
            }
            "ansicpg" => {
                self.default_cp = v.clamp(0, 65535) as u16;
                st.cp = self.default_cp;
            }
            "deff" => self.deff = v,
            "deflang" => {}
            "ansi" | "mac" | "pc" | "pca" => {}
            // ---- paragraph ----
            "pard" => {
                st.pap = ParaProps::default();
                st.ls = None;
                st.ilvl = 0;
                st.intbl = false;
                st.cbpat = None;
                st.cfpat = None;
                st.shading = 0;
                st.target = Target::None;
            }
            "s" => {
                let id = self.style_id_of(v, StyleKind::Paragraph);
                self.top().pap.style = id;
            }
            "ql" => st.pap.jc = Some(Jc::Left),
            "qr" => st.pap.jc = Some(Jc::Right),
            "qc" => st.pap.jc = Some(Jc::Center),
            "qj" => st.pap.jc = Some(Jc::Both),
            "qd" | "qt" => st.pap.jc = Some(Jc::Distribute),
            "li" | "lin" => st.pap.ind_left = Some(v),
            "ri" | "rin" => st.pap.ind_right = Some(v),
            "fi" => {
                if v >= 0 {
                    st.pap.ind_first_line = Some(v);
                    st.pap.ind_hanging = None;
                } else {
                    st.pap.ind_first_line = None;
                    st.pap.ind_hanging = Some(-v);
                }
            }
            "sb" => st.pap.space_before = Some(v.max(0)),
            "sa" => st.pap.space_after = Some(v.max(0)),
            "sbauto" => st.pap.before_auto = Some(flag(n)),
            "saauto" => st.pap.after_auto = Some(flag(n)),
            "sl" => {
                if v < 0 {
                    st.pap.line = Some(-v);
                    st.pap.line_rule = Some(LineRule::Exact);
                } else if v == 0 {
                    st.pap.line = None;
                    st.pap.line_rule = None;
                } else {
                    st.pap.line = Some(v);
                    st.pap.line_rule = Some(LineRule::AtLeast);
                }
            }
            "slmult" => {
                if v == 1 && st.pap.line_rule == Some(LineRule::AtLeast) {
                    st.pap.line_rule = Some(LineRule::Auto);
                }
            }
            // A positioned paragraph: its frame.
            "absw" | "absh" | "posx" | "posy" | "posxc" | "posxr" | "posxi" | "posxo" | "posyt"
            | "posyc" | "posyb" | "posyin" | "posyout" | "phmrg" | "phpg" | "phcol" | "pvmrg"
            | "pvpg" | "pvpara" | "dxfrtext" | "dfrmtxtx" | "dfrmtxty" | "nowrap"
            | "wraparound" => {
                let f = st.pap.frame.get_or_insert_with(Frame::default);
                match w {
                    "absw" if v > 0 => f.width = Some(v),
                    "absh" if v != 0 => {
                        f.height = Some(v.abs());
                        f.height_exact = v < 0;
                    }
                    "posx" => f.x = Some(v),
                    "posy" => f.y = Some(v),
                    "posxc" => f.x_align = Some("center"),
                    "posxr" => f.x_align = Some("right"),
                    "posxi" => f.x_align = Some("inside"),
                    "posxo" => f.x_align = Some("outside"),
                    "posyt" => f.y_align = Some("top"),
                    "posyc" => f.y_align = Some("center"),
                    "posyb" => f.y_align = Some("bottom"),
                    "posyin" => f.y_align = Some("inside"),
                    "posyout" => f.y_align = Some("outside"),
                    "phmrg" => f.h_anchor = Some("margin"),
                    "phpg" => f.h_anchor = Some("page"),
                    "phcol" => f.h_anchor = Some("text"),
                    "pvmrg" => f.v_anchor = Some("margin"),
                    "pvpg" => f.v_anchor = Some("page"),
                    "pvpara" => f.v_anchor = Some("text"),
                    "dxfrtext" | "dfrmtxtx" => f.h_space = Some(v),
                    "dfrmtxty" => f.v_space = Some(v),
                    "nowrap" => f.wrap = Some("notBeside"),
                    "wraparound" => f.wrap = Some("around"),
                    _ => {}
                }
            }
            "keep" => st.pap.keep_lines = Some(flag(n)),
            "keepn" => st.pap.keep_next = Some(flag(n)),
            "pagebb" => st.pap.page_break_before = Some(flag(n)),
            "widctlpar" => st.pap.widow_control = Some(true),
            "nowidctlpar" => st.pap.widow_control = Some(false),
            "noline" => st.pap.suppress_line_numbers = Some(true),
            "rtlpar" => st.pap.bidi = Some(true),
            "ltrpar" => st.pap.bidi = Some(false),
            "contextualspace" => st.pap.contextual_spacing = Some(true),
            "outlinelevel" => st.pap.outline_level = Some(v.clamp(0, 9) as u32),
            "intbl" => st.intbl = true,
            "itap" => {
                if v > 0 {
                    st.intbl = true;
                }
            }
            "ls" => st.ls = Some(v),
            "ilvl" => st.ilvl = v.clamp(0, 8) as u32,
            "cbpat" => st.cbpat = usize::try_from(v).ok().filter(|v| *v > 0),
            "cfpat" => st.cfpat = usize::try_from(v).ok().filter(|v| *v > 0),
            "shading" => st.shading = v,
            "tx" | "tb" => {
                let kind = if w == "tb" { TabKind::Bar } else { st.tab_kind };
                let t = Tab {
                    pos: v,
                    kind,
                    leader: st.tab_leader,
                };
                st.pap.tabs.retain(|x| x.pos != v);
                st.pap.tabs.push(t);
                st.pap.tabs.sort_by_key(|t| t.pos);
                st.tab_kind = TabKind::Left;
                st.tab_leader = TabLeader::None;
            }
            "tqr" => st.tab_kind = TabKind::Right,
            "tqc" => st.tab_kind = TabKind::Center,
            "tqdec" => st.tab_kind = TabKind::Decimal,
            "tldot" => st.tab_leader = TabLeader::Dot,
            "tlmdot" => st.tab_leader = TabLeader::MiddleDot,
            "tlhyph" => st.tab_leader = TabLeader::Hyphen,
            "tlul" => st.tab_leader = TabLeader::Underscore,
            "tlth" => st.tab_leader = TabLeader::Heavy,
            "tlnone" => st.tab_leader = TabLeader::None,
            // ---- special characters ----
            "par" | "sect" | "row" | "cell" | "nestcell" | "nestrow" | "line" | "tab" | "page"
            | "column" | "emdash" | "endash" | "emspace" | "enspace" | "qmspace" | "bullet"
            | "lquote" | "rquote" | "ldblquote" | "rdblquote" | "chpgn" | "chftn" | "zwbo"
            | "zwnbo" | "zwj" | "zwnj" | "ltrmark" | "rtlmark" | "softline" | "sectd" | "trowd"
            | "page_" => {
                return self.special_word(w, n, dest);
            }
            // ---- tables ----
            "trleft" => self.row.left = v,
            "trgaph" => self.row.gap = v,
            "trrh" => self.row.height = v,
            "trhdr" => self.row.header = true,
            "trkeep" => self.row.keep = true,
            "trqc" => self.row.jc = Some(Jc::Center),
            "trqr" => self.row.jc = Some(Jc::Right),
            "trql" => self.row.jc = Some(Jc::Left),
            "rtlrow" => self.row.bidi = true,
            "trbrdrt" => self.top().target = Target::Row(0),
            "trbrdrl" => self.top().target = Target::Row(1),
            "trbrdrb" => self.top().target = Target::Row(2),
            "trbrdrr" => self.top().target = Target::Row(3),
            "trbrdrh" => self.top().target = Target::Row(4),
            "trbrdrv" => self.top().target = Target::Row(5),
            "clbrdrt" => self.top().target = Target::Cell(0),
            "clbrdrl" => self.top().target = Target::Cell(1),
            "clbrdrb" => self.top().target = Target::Cell(2),
            "clbrdrr" => self.top().target = Target::Cell(3),
            "clcbpat" => {
                let c = self.color_at(v);
                self.row.cur.shading = match c {
                    Some(Color::Rgb(_)) => c.map(Shading::fill),
                    _ => None,
                };
            }
            "clvmgf" => self.row.cur.vmerge = 1,
            "clvmrg" => self.row.cur.vmerge = 2,
            "clmgf" => self.row.cur.hmerge = 1,
            "clmrg" => self.row.cur.hmerge = 2,
            "clvertalt" => self.row.cur.valign = 0,
            "clvertalc" => self.row.cur.valign = 1,
            "clvertalb" => self.row.cur.valign = 2,
            "cltxlrtb" => self.row.cur.text_flow = 0,
            "cltxbtlr" => self.row.cur.text_flow = 1,
            "cltxtbrl" => self.row.cur.text_flow = 2,
            "clNoWrap" => self.row.cur.no_wrap = true,
            "cellx" => {
                self.row.cur.right = v;
                let c = std::mem::take(&mut self.row.cur);
                if self.row.cells.len() < 64 {
                    self.row.cells.push(c);
                }
                self.top().target = Target::None;
            }
            // ---- sections and the document ----
            "sbknone" => self.cur_sect.kind = SectionType::Continuous,
            "sbkcol" => self.cur_sect.kind = SectionType::NextColumn,
            "sbkpage" => self.cur_sect.kind = SectionType::NextPage,
            "sbkeven" => self.cur_sect.kind = SectionType::EvenPage,
            "sbkodd" => self.cur_sect.kind = SectionType::OddPage,
            "pgwsxn" => self.cur_sect.width = v,
            "pghsxn" => self.cur_sect.height = v,
            "marglsxn" => self.cur_sect.left = v,
            "margrsxn" => self.cur_sect.right = v,
            "margtsxn" => self.cur_sect.top = v,
            "margbsxn" => self.cur_sect.bottom = v,
            "guttersxn" => self.cur_sect.gutter = v,
            "headery" => self.cur_sect.header = v,
            "footery" => self.cur_sect.footer = v,
            "lndscpsxn" => self.cur_sect.landscape = true,
            "titlepg" => self.cur_sect.title_page = true,
            "cols" => self.cur_sect.columns.num = v.max(1) as u32,
            "colsx" => self.cur_sect.columns.space = v,
            "linebetcol" => self.cur_sect.columns.separator = true,
            "pgnstarts" => self.cur_sect.page_start = Some(v.max(0) as u32),
            "pgnrestart" => {
                self.cur_sect.page_start.get_or_insert(1);
            }
            "pgnlcrm" => self.cur_sect.page_fmt = Some("lowerRoman"),
            "pgnucrm" => self.cur_sect.page_fmt = Some("upperRoman"),
            "pgnlcltr" => self.cur_sect.page_fmt = Some("lowerLetter"),
            "pgnucltr" => self.cur_sect.page_fmt = Some("upperLetter"),
            "pgndec" => self.cur_sect.page_fmt = Some("decimal"),
            "vertalc" => self.cur_sect.v_align = Some("center"),
            "vertalb" => self.cur_sect.v_align = Some("bottom"),
            "vertalj" => self.cur_sect.v_align = Some("both"),
            "paperw" => {
                self.defaults.width = v;
                self.cur_sect.width = v;
            }
            "paperh" => {
                self.defaults.height = v;
                self.cur_sect.height = v;
            }
            "margl" => {
                self.defaults.left = v;
                self.cur_sect.left = v;
            }
            "margr" => {
                self.defaults.right = v;
                self.cur_sect.right = v;
            }
            "margt" => {
                self.defaults.top = v;
                self.cur_sect.top = v;
            }
            "margb" => {
                self.defaults.bottom = v;
                self.cur_sect.bottom = v;
            }
            "gutter" => {
                self.defaults.gutter = v;
                self.cur_sect.gutter = v;
            }
            "landscape" => {
                self.defaults.landscape = true;
                self.cur_sect.landscape = true;
            }
            "facingp" => self.facing = true,
            "deftab" => self.doc.settings.default_tab_stop = Some(v.max(1)),
            "ftnbj" => self.doc.settings.footnote_pos = Some("pageBottom"),
            "ftntj" => self.doc.settings.footnote_pos = Some("beneathText"),
            "ftnstart" => self.doc.settings.footnote_start = Some(v.max(0) as u32),
            "ftnnar" => self.doc.settings.footnote_fmt = Some("decimal"),
            "ftnnalc" => self.doc.settings.footnote_fmt = Some("lowerLetter"),
            "ftnnauc" => self.doc.settings.footnote_fmt = Some("upperLetter"),
            "ftnnrlc" => self.doc.settings.footnote_fmt = Some("lowerRoman"),
            "ftnnruc" => self.doc.settings.footnote_fmt = Some("upperRoman"),
            "bin" => {
                let data = self.lex.take_bin(v.max(0) as usize);
                if self.top().dest == Dest::Pict {
                    self.pict_bin(data);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn style_id_of(&self, num: i32, kind: StyleKind) -> Option<String> {
        if kind == StyleKind::Paragraph && num == 0 {
            return None;
        }
        Some(style_id(kind, num))
    }

    fn set_font(&mut self, v: i32) {
        let (name, cp) = match self.fonts.get(&v) {
            Some(f) => (f.name.clone(), f.cp),
            None => (String::new(), self.default_cp),
        };
        let st = self.top();
        st.cp = if cp == 42 { st.cp } else { cp };
        if !name.is_empty() {
            st.chp.fonts = Fonts {
                ascii: Some(name.clone()),
                hansi: Some(name.clone()),
                east_asia: Some(name.clone()),
                cs: st.chp.fonts.cs.take().or(Some(name)),
            };
        }
    }

    fn clear_border(&mut self) {
        match self.top().target {
            Target::Para(s) => {
                let b = &mut self.stack.last_mut().expect("a group is open").pap.borders;
                match s {
                    0 => b.top = None,
                    1 => b.left = None,
                    2 => b.bottom = None,
                    3 => b.right = None,
                    _ => b.between = None,
                }
            }
            Target::Cell(s) => {
                if let Some(slot) = self.row.cur.borders.get_mut(usize::from(s)) {
                    *slot = Some(None);
                }
            }
            _ => {}
        }
    }

    fn special_word(&mut self, w: &str, n: Option<i32>, dest: &Dest) -> Result<()> {
        let _ = n;
        match w {
            "par" => {
                if dest.is_text() {
                    self.flush_text();
                    self.close_para(true)?;
                }
            }
            "sect" => {
                self.flush_text();
                self.end_section()?;
            }
            "sectd" => {
                let keep = std::mem::take(&mut self.cur_sect.headers);
                let keep_f = std::mem::take(&mut self.cur_sect.footers);
                self.cur_sect = self.defaults.clone();
                self.cur_sect.headers = keep;
                self.cur_sect.footers = keep_f;
            }
            "trowd" => {
                let gap = self.row.gap;
                self.row = super::RowDef::default();
                self.row.gap = gap;
            }
            "cell" | "nestcell" => {
                self.flush_text();
                self.end_cell()?;
            }
            "row" | "nestrow" => {
                self.flush_text();
                if w == "row" {
                    self.end_row()?;
                }
            }
            "line" => self.char_item_pub(RunItem::Break(BreakKind::Line), dest),
            "tab" => self.char_item_pub(RunItem::Tab, dest),
            "page" => self.char_item_pub(RunItem::Break(BreakKind::Page), dest),
            "column" => self.char_item_pub(RunItem::Break(BreakKind::Column), dest),
            "chpgn" => {
                if dest.is_text() {
                    self.flush_text();
                    self.add_item(RunItem::PageNumber);
                }
            }
            "chftn" => {
                if matches!(dest, Dest::Note) {
                    self.flush_text();
                    let endnote = self.note_endnote;
                    self.add_item(RunItem::NoteMark(endnote));
                }
                // In the text the mark is the reference: the note group puts it.
            }
            _ => {
                let s = match w {
                    "emdash" => "\u{2014}",
                    "endash" => "\u{2013}",
                    "emspace" => "\u{2003}",
                    "enspace" => "\u{2002}",
                    "qmspace" => "\u{2005}",
                    "bullet" => "\u{2022}",
                    "lquote" => "\u{2018}",
                    "rquote" => "\u{2019}",
                    "ldblquote" => "\u{201C}",
                    "rdblquote" => "\u{201D}",
                    _ => "",
                };
                self.flush_text();
                self.put_str_pub(s);
            }
        }
        Ok(())
    }

    pub(crate) fn char_item_pub(&mut self, item: RunItem, dest: &Dest) {
        self.char_item(item, Some(dest.clone()));
    }

    pub(crate) fn put_str_pub(&mut self, s: &str) {
        self.flush_text();
        self.put_str(s);
    }
}

pub(crate) fn lang_tag(lcid: i32) -> Option<String> {
    Some(
        match lcid & 0xFFFF {
            0x0409 => "en-US",
            0x0809 => "en-GB",
            0x0C09 => "en-AU",
            0x040C => "fr-FR",
            0x0C0C => "fr-CA",
            0x0407 => "de-DE",
            0x0C07 => "de-AT",
            0x0807 => "de-CH",
            0x0410 => "it-IT",
            0x0C0A | 0x040A => "es-ES",
            0x0416 => "pt-BR",
            0x0816 => "pt-PT",
            0x0413 => "nl-NL",
            0x0419 => "ru-RU",
            0x0405 => "cs-CZ",
            0x0415 => "pl-PL",
            0x040E => "hu-HU",
            0x041D => "sv-SE",
            0x0414 => "nb-NO",
            0x040B => "fi-FI",
            0x0406 => "da-DK",
            0x0408 => "el-GR",
            0x041F => "tr-TR",
            0x0411 => "ja-JP",
            0x0412 => "ko-KR",
            0x0804 => "zh-CN",
            0x0404 => "zh-TW",
            0x040D => "he-IL",
            0x0401 => "ar-SA",
            0x0422 => "uk-UA",
            0x0426 => "lv-LV",
            0x0427 => "lt-LT",
            0x0425 => "et-EE",
            _ => return None,
        }
        .to_string(),
    )
}

pub(crate) fn style_id(kind: StyleKind, num: i32) -> String {
    match (kind, num) {
        (StyleKind::Paragraph, 0) => "Normal".into(),
        (StyleKind::Paragraph, n) => format!("S{n}"),
        (StyleKind::Character, n) => format!("CS{n}"),
        (_, n) => format!("TS{n}"),
    }
}

/// Styles from the stylesheet.
pub(crate) fn build_styles(p: &mut Parser<'_>) {
    let mut out = vec![];
    let mut has_normal = false;
    for s in std::mem::take(&mut p.styles) {
        let id = style_id(s.kind, s.num);
        let mut st = Style::new(&id, if s.name.is_empty() { &id } else { &s.name }, s.kind);
        if s.kind == StyleKind::Paragraph && s.num == 0 {
            st.default = true;
            has_normal = true;
            if st.name.is_empty() || st.name == id {
                st.name = "Normal".into();
            }
        }
        st.based_on = s.based.filter(|b| *b != s.num).map(|b| style_id(s.kind, b));
        st.next = s
            .next
            .filter(|b| *b != s.num && s.kind == StyleKind::Paragraph)
            .map(|b| style_id(s.kind, b));
        st.q_format = s.kind == StyleKind::Paragraph;
        st.rpr = s.chp;
        st.ppr = s.pap;
        st.ppr.style = None;
        st.rpr.style = None;
        if let Some(ls) = s.ls.filter(|l| *l > 0) {
            st.ppr.num_id = Some(ls as u32);
            st.ppr.num_level = Some(s.ilvl);
        }
        if s.kind == StyleKind::Table {
            st.tbl = Some(TableProps::default());
        }
        if s.kind == StyleKind::Paragraph && s.name.to_ascii_lowercase().starts_with("heading ") {
            if let Some(n) = s.name[8..]
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|n| (1..=9).contains(n))
            {
                st.name = format!("heading {n}");
                st.ppr.outline_level = Some(n - 1);
            }
        }
        out.push(st);
    }
    let _ = has_normal;
    p.doc.styles = out;
}

/// Numbering from the list table and its overrides.
pub(crate) fn build_lists(p: &mut Parser<'_>) {
    for (i, l) in std::mem::take(&mut p.lists).into_iter().enumerate() {
        let mut levels = vec![];
        for d in l.levels.into_iter().take(9) {
            let mut lv = d.level;
            // The text: the first element is its length; placeholders are
            // the level numbers listed in `numbers`.
            let chars: Vec<u32> = d.text.into_iter().skip(1).collect();
            if lv.fmt == "bullet" {
                let c = chars.first().copied().unwrap_or(0x2022);
                lv.text = bullet(c);
            } else {
                let mut s = String::new();
                for (k, c) in chars.iter().enumerate() {
                    if *c < 9 && d.numbers.contains(&((k + 1) as u8)) {
                        s.push_str(&format!("%{}", c + 1));
                    } else if let Some(ch) = char::from_u32(*c) {
                        s.push(ch);
                    }
                }
                lv.text = s;
            }
            levels.push(lv);
        }
        while levels.len() < 9 && !l.simple {
            levels.push(Level {
                fmt: "none",
                ..Level::default()
            });
        }
        p.doc.numbering.abstracts.push(AbstractNum {
            id: i as u32,
            multi_level: !l.simple,
            levels,
        });
        p.list_ids.push(l.id);
    }
    for (listid, ls, starts) in std::mem::take(&mut p.overrides) {
        let abs = p
            .list_ids
            .iter()
            .position(|x| *x == listid)
            .map(|x| x as u32)
            .unwrap_or(0);
        p.doc.numbering.nums.push(Num {
            id: ls.max(0) as u32,
            abstract_id: abs,
            overrides: starts
                .into_iter()
                .map(|(l, s)| (l, Some(s), None))
                .collect(),
        });
    }
}

fn bullet(c: u32) -> String {
    match c {
        0xF0B7 | 0xB7 => "\u{2022}".into(),
        0xF0A7 | 0xA7 => "\u{25AA}".into(),
        0xF076 => "\u{2756}".into(),
        0xF0D8 => "\u{27A2}".into(),
        0xF0FC => "\u{2714}".into(),
        0xE000..=0xF8FF => "\u{2022}".into(),
        c => char::from_u32(c)
            .map(|c| c.to_string())
            .unwrap_or_else(|| "\u{2022}".into()),
    }
}
