//! Lists ([MS-DOC] 2.9.147 to 2.9.150, 2.9.200, 2.9.201): list definitions
//! and the list instances paragraphs refer to.

use super::props::{apply_chp_list, apply_pap_list, ChpAux, Ctx, PapAux};
use crate::formats::office::common::bytes::{u16_at, u32_at, Cur};
use crate::formats::office::docs::model::*;

/// The ST_NumberFormat of an MSONFC ([MS-OSHARED] 2.2.1.3).
pub fn number_format(nfc: u8) -> &'static str {
    const NAMES: [&str; 0x3C] = [
        "decimal",
        "upperRoman",
        "lowerRoman",
        "upperLetter",
        "lowerLetter",
        "ordinal",
        "cardinalText",
        "ordinalText",
        "hex",
        "chicago",
        "ideographDigital",
        "japaneseCounting",
        "aiueo",
        "iroha",
        "decimalFullWidth",
        "decimalHalfWidth",
        "japaneseLegal",
        "japaneseDigitalTenThousand",
        "decimalEnclosedCircle",
        "decimalFullWidth2",
        "aiueoFullWidth",
        "irohaFullWidth",
        "decimalZero",
        "bullet",
        "ganada",
        "chosung",
        "decimalEnclosedFullstop",
        "decimalEnclosedParen",
        "decimalEnclosedCircleChinese",
        "ideographEnclosedCircle",
        "ideographTraditional",
        "ideographZodiac",
        "ideographZodiacTraditional",
        "taiwaneseCounting",
        "ideographLegalTraditional",
        "taiwaneseCountingThousand",
        "taiwaneseDigital",
        "chineseCounting",
        "chineseLegalSimplified",
        "chineseCountingThousand",
        "decimal",
        "koreanDigital",
        "koreanCounting",
        "koreanLegal",
        "koreanDigital2",
        "hebrew1",
        "arabicAlpha",
        "hebrew2",
        "arabicAbjad",
        "hindiVowels",
        "hindiConsonants",
        "hindiNumbers",
        "hindiCounting",
        "thaiLetters",
        "thaiNumbers",
        "thaiCounting",
        "vietnameseCounting",
        "numberInDash",
        "russianLower",
        "russianUpper",
    ];
    match nfc {
        0xFF => "none",
        n => NAMES.get(usize::from(n)).copied().unwrap_or("decimal"),
    }
}

/// A bullet written in a symbol font, as Unicode text a font of any kind
/// can show.
fn bullet(ch: u16, font: Option<&str>) -> (String, bool) {
    let low = ch & 0x0FFF;
    let f = font.unwrap_or("").to_ascii_lowercase();
    let map = |c: u16| -> Option<char> {
        Some(match (f.as_str(), c) {
            ("symbol", 0xB7) => '\u{2022}',
            ("symbol", 0xA8) => '\u{2666}',
            ("symbol", 0xD8) => '\u{21D2}',
            ("symbol", 0xAE) => '\u{2192}',
            ("wingdings", 0xA7) => '\u{25AA}',
            ("wingdings", 0xA8) => '\u{25FB}',
            ("wingdings", 0x76) => '\u{2756}',
            ("wingdings", 0xD8) => '\u{27A2}',
            ("wingdings", 0xFC) => '\u{2714}',
            ("wingdings", 0x6E) => '\u{25A0}',
            ("wingdings", 0x71) => '\u{2751}',
            ("wingdings", 0x6C) => '\u{25CF}',
            ("wingdings", 0xFB) => '\u{2717}',
            ("wingdings", 0x9F) => '\u{2022}',
            ("wingdings", 0xA1) => '\u{25CB}',
            ("wingdings", 0x77) => '\u{2B27}',
            _ => return None,
        })
    };
    if ch & 0xF000 != 0 || f == "symbol" || f == "wingdings" {
        if let Some(c) = map(low) {
            return (c.to_string(), true);
        }
    }
    (
        char::from_u32(u32::from(if ch & 0xF000 != 0 { low } else { ch }))
            .unwrap_or('\u{2022}')
            .to_string(),
        false,
    )
}

fn read_lvl(d: &[u8], p: &mut usize, cx: &Ctx, style: Option<String>) -> Option<Level> {
    let b = d.get(*p..*p + 28)?;
    let start = i64::from(u32_at(b, 0) as i32);
    let nfc = b[4];
    let flags = b[5];
    let nums = &b[6..15];
    let follow = b[15];
    let cb_chpx = usize::from(b[24]);
    let cb_papx = usize::from(b[25]);
    let restart_lim = b[26];
    let mut c = Cur::at(d, *p + 28);
    let papx = c.bytes(cb_papx);
    let chpx = c.bytes(cb_chpx);
    let cch = usize::from(c.u16());
    let xst = c.bytes(cch * 2);
    if c.short {
        return None;
    }
    *p = c.p;
    let units: Vec<u16> = xst
        .as_chunks::<2>()
        .0
        .iter()
        .map(|x| u16::from_le_bytes(*x))
        .collect();
    let mut rpr = RunProps::default();
    let mut caux = ChpAux::default();
    apply_chp_list(&mut rpr, &mut caux, chpx, cx);
    let mut ppr = ParaProps::default();
    let mut paux = PapAux::default();
    apply_pap_list(&mut ppr, &mut paux, papx);
    let fmt = number_format(nfc);
    let text = if nfc == 0x17 {
        let (t, mapped) = bullet(
            units.first().copied().unwrap_or(0x2022),
            rpr.fonts.ascii.as_deref().or(rpr.fonts.hansi.as_deref()),
        );
        if mapped {
            rpr.fonts = Fonts::default();
        }
        t
    } else {
        let mut s = String::new();
        for (k, u) in units.iter().enumerate() {
            let mark = (k + 1) as u8;
            if nums.contains(&mark) && *u < 9 {
                s.push_str(&format!("%{}", u + 1));
            } else if let Some(ch) = char::from_u32(u32::from(*u)) {
                s.push(ch);
            }
        }
        s
    };
    Some(Level {
        start,
        fmt: if nfc == 0xFF { "none" } else { fmt },
        text,
        jc: match flags & 3 {
            1 => Jc::Center,
            2 => Jc::Right,
            _ => Jc::Left,
        },
        suff: match follow {
            1 => "space",
            2 => "nothing",
            _ => "tab",
        },
        style,
        ppr,
        rpr,
        legal: flags & 4 != 0,
        // Restarts after the levels more significant than the limit.
        restart: (flags & 8 != 0).then_some(u32::from(restart_lim)),
    })
}

pub struct Lists {
    pub numbering: Numbering,
}

/// Reads the list definitions and instances. `style_id` names the style an
/// istd stands for.
pub fn read(
    tbl: &[u8],
    lst: (usize, usize),
    lfo: (usize, usize),
    cx: &Ctx,
    style_id: &dyn Fn(u16) -> Option<String>,
) -> Lists {
    let mut out = Numbering::default();
    let mut lsids = vec![];
    if lst.1 >= 2 {
        // The level definitions follow the list definitions, past the size
        // the file's pair gives.
        let d = tbl.get(lst.0..).unwrap_or(&[]);
        let n = usize::from(u16_at(d, 0)).min(4096);
        let mut p = 2 + 28 * n;
        for i in 0..n {
            let b = match d.get(2 + 28 * i..2 + 28 * i + 28) {
                Some(b) => b,
                None => break,
            };
            let lsid = u32_at(b, 0) as i32;
            let simple = b[26] & 1 != 0;
            let styles: Vec<u16> = (0..9).map(|k| u16_at(b, 8 + 2 * k)).collect();
            let nlvl = if simple { 1 } else { 9 };
            let mut levels = vec![];
            for k in 0..nlvl {
                let st = styles
                    .get(k)
                    .filter(|s| **s != 0x0FFF)
                    .and_then(|s| style_id(*s));
                match read_lvl(d, &mut p, cx, st) {
                    Some(l) => levels.push(l),
                    None => break,
                }
            }
            lsids.push(lsid);
            out.abstracts.push(AbstractNum {
                id: i as u32,
                multi_level: !simple,
                levels,
            });
        }
    }
    if lfo.1 >= 4 {
        let d = tbl
            .get(lfo.0..lfo.0.saturating_add(lfo.1).min(tbl.len()))
            .unwrap_or(&[]);
        let n = (u32_at(d, 0) as usize).min(8192);
        let mut p = 4 + 16 * n;
        for i in 0..n {
            let Some(b) = d.get(4 + 16 * i..4 + 16 * i + 16) else {
                break;
            };
            let lsid = u32_at(b, 0) as i32;
            let clfolvl = usize::from(b[12]);
            let abstract_id = lsids
                .iter()
                .position(|l| *l == lsid)
                .map(|x| x as u32)
                .unwrap_or(0);
            p += 4;
            let mut overrides = vec![];
            for _ in 0..clfolvl {
                if p + 8 > d.len() {
                    break;
                }
                let start = i64::from(u32_at(d, p) as i32);
                let fl = u32_at(d, p + 4);
                let lvl_no = fl & 0xF;
                p += 8;
                let has_start = fl & 0x10 != 0;
                let has_fmt = fl & 0x20 != 0;
                let def = if has_fmt {
                    read_lvl(d, &mut p, cx, None)
                } else {
                    None
                };
                let start_over = (has_start && !has_fmt).then_some(start);
                overrides.push((lvl_no, start_over, def));
            }
            out.nums.push(Num {
                id: i as u32 + 1,
                abstract_id,
                overrides,
            });
        }
    }
    Lists { numbering: out }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lvl(nfc: u8, text: &[u16], nums: &[u8], follow: u8) -> Vec<u8> {
        let mut b = vec![0u8; 28];
        b[0] = 1;
        b[4] = nfc;
        b[6..6 + nums.len()].copy_from_slice(nums);
        b[15] = follow;
        let mut v = b;
        v.extend_from_slice(&(text.len() as u16).to_le_bytes());
        for u in text {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    #[test]
    fn levels_become_number_text() {
        let fonts = vec![];
        let base = RunProps::default();
        let cx = Ctx {
            fonts: &fonts,
            base: &base,
        };
        let v = lvl(0, &[0, 0x2E, 1], &[1], 0);
        let mut p = 0;
        let l = read_lvl(&v, &mut p, &cx, None).unwrap();
        assert_eq!(l.text, "%1.\u{1}");
        let v = lvl(0, &[0, b'.' as u16], &[1], 1);
        let mut p = 0;
        let l = read_lvl(&v, &mut p, &cx, None).unwrap();
        assert_eq!(
            (l.text.as_str(), l.fmt, l.suff),
            ("%1.", "decimal", "space")
        );
        let v = lvl(0x17, &[0xF0B7], &[], 0);
        let mut p = 0;
        let l = read_lvl(&v, &mut p, &cx, None).unwrap();
        assert_eq!(l.fmt, "bullet");
        assert_eq!(l.text, "\u{B7}");
    }

    #[test]
    fn definitions_and_instances() {
        let fonts = vec![];
        let base = RunProps::default();
        let cx = Ctx {
            fonts: &fonts,
            base: &base,
        };
        // One simple list (lsid 7) with one level; one LFO using it with a start override.
        let mut lst = 1u16.to_le_bytes().to_vec();
        let mut lstf = vec![0u8; 28];
        lstf[0] = 7;
        lstf[26] = 1;
        for k in 0..9 {
            lstf[8 + 2 * k] = 0xFF;
            lstf[9 + 2 * k] = 0x0F;
        }
        lst.extend_from_slice(&lstf);
        lst.extend_from_slice(&lvl(4, &[0, b')' as u16], &[1], 0));
        let mut lfo = 1u32.to_le_bytes().to_vec();
        let mut e = vec![0u8; 16];
        e[0] = 7;
        e[12] = 1;
        lfo.extend_from_slice(&e);
        lfo.extend_from_slice(&[0xFF; 4]);
        lfo.extend_from_slice(&5u32.to_le_bytes());
        lfo.extend_from_slice(&0x10u32.to_le_bytes());
        let mut t = lst.clone();
        let lfo_at = t.len();
        t.extend_from_slice(&lfo);
        let l = read(&t, (0, lst.len()), (lfo_at, lfo.len()), &cx, &|_| None);
        assert_eq!(l.numbering.abstracts.len(), 1);
        assert_eq!(l.numbering.abstracts[0].levels[0].fmt, "lowerLetter");
        assert_eq!(l.numbering.nums.len(), 1);
        assert_eq!(l.numbering.nums[0].abstract_id, 0);
        assert_eq!(l.numbering.nums[0].overrides[0].1, Some(5));
    }
}
