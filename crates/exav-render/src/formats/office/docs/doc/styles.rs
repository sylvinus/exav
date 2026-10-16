//! The stylesheet ([MS-DOC] 2.9.271): style definitions as their raw
//! modifier lists.

use crate::formats::office::common::bytes::{u16_at, Cur};

pub struct Std {
    pub name: String,
    pub sti: u16,
    /// 1 paragraph, 2 character, 3 table, 4 numbering.
    pub kind: u8,
    pub base: u16,
    pub next: u16,
    pub link: u16,
    pub papx: Vec<u8>,
    pub chpx: Vec<u8>,
}

#[derive(Default)]
pub struct Stsh {
    pub stds: Vec<Option<Std>>,
    pub ftc_ascii: i16,
    pub ftc_fe: i16,
    pub ftc_other: i16,
    pub ftc_bi: Option<i16>,
}

pub fn read(tbl: &[u8], off: usize, len: usize) -> Stsh {
    let mut out = Stsh::default();
    let Some(d) = tbl.get(off..off.saturating_add(len).min(tbl.len())) else {
        return out;
    };
    let mut c = Cur::new(d);
    let cb_stshi = usize::from(c.u16());
    let stshi = c.bytes(cb_stshi);
    if stshi.len() < 18 || c.short {
        return out;
    }
    let cstd = usize::from(u16_at(stshi, 0));
    let cb_base = usize::from(u16_at(stshi, 2));
    out.ftc_ascii = u16_at(stshi, 12) as i16;
    out.ftc_fe = u16_at(stshi, 14) as i16;
    out.ftc_other = u16_at(stshi, 16) as i16;
    if stshi.len() >= 20 {
        out.ftc_bi = Some(u16_at(stshi, 18) as i16);
    }
    for _ in 0..cstd.min(4096) {
        let cb = usize::from(c.u16());
        if c.short {
            break;
        }
        let std = c.bytes(cb);
        if cb % 2 == 1 {
            c.skip(1);
        }
        if cb == 0 {
            out.stds.push(None);
            continue;
        }
        out.stds.push(parse_std(std, cb_base));
    }
    out
}

fn parse_std(d: &[u8], cb_base: usize) -> Option<Std> {
    if cb_base < 10 || d.len() < cb_base + 2 {
        return None;
    }
    let w0 = u16_at(d, 0);
    let w1 = u16_at(d, 2);
    let w2 = u16_at(d, 4);
    let link = if cb_base >= 18 {
        u16_at(d, 10) & 0x0FFF
    } else {
        0
    };
    let sti = w0 & 0x0FFF;
    let kind = (w1 & 0xF) as u8;
    let base = w1 >> 4;
    let cupx = usize::from(w2 & 0xF);
    let next = w2 >> 4;
    let mut c = Cur::at(d, cb_base);
    let cch = usize::from(c.u16());
    let name_bytes = c.bytes(cch * 2);
    c.skip(2);
    let units: Vec<u16> = name_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|x| u16::from_le_bytes(*x))
        .collect();
    let name = String::from_utf16_lossy(&units);
    if c.p % 2 == 1 {
        c.skip(1);
    }
    let mut upx = vec![];
    for _ in 0..cupx {
        let n = usize::from(c.u16());
        if c.short {
            break;
        }
        upx.push(c.bytes(n).to_vec());
        if n % 2 == 1 {
            c.skip(1);
        }
    }
    let take =
        |v: &mut Vec<Vec<u8>>, i: usize| v.get_mut(i).map(std::mem::take).unwrap_or_default();
    let (mut papx, mut chpx) = (vec![], vec![]);
    match kind {
        1 => {
            papx = take(&mut upx, 0);
            chpx = take(&mut upx, 1);
        }
        2 => chpx = take(&mut upx, 0),
        3 => {
            // The table properties (UPX 0) are not used.
            papx = take(&mut upx, 1);
            chpx = take(&mut upx, 2);
        }
        4 => papx = take(&mut upx, 0),
        _ => return None,
    }
    Some(Std {
        name,
        sti,
        kind,
        base,
        next,
        link,
        papx,
        chpx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stylesheet with one paragraph style "Body" based on style 0xFFF.
    pub fn sample() -> Vec<u8> {
        let mut stshi = vec![0u8; 18];
        stshi[0] = 1;
        stshi[2] = 10;
        let mut std = vec![0u8; 10];
        std[0] = 0xFE;
        std[1] = 0x0F;
        // stk 1, istdBase 0x0FFF.
        std[2..4].copy_from_slice(&(1u16 | 0x0FFF << 4).to_le_bytes());
        std[4..6].copy_from_slice(&(2u16).to_le_bytes());
        let name: Vec<u8> = "Body"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        std.extend_from_slice(&4u16.to_le_bytes());
        std.extend_from_slice(&name);
        std.extend_from_slice(&[0, 0]);
        // papx: istd 0 and sprmPJc centered (3 bytes: no padding needed beyond one).
        let papx = [0u8, 0, 0x61, 0x24, 1];
        std.extend_from_slice(&(papx.len() as u16).to_le_bytes());
        std.extend_from_slice(&papx);
        std.push(0);
        let chpx = [0x35u8, 0x08, 1];
        std.extend_from_slice(&(chpx.len() as u16).to_le_bytes());
        std.extend_from_slice(&chpx);
        std.push(0);
        let mut d = (stshi.len() as u16).to_le_bytes().to_vec();
        d.extend_from_slice(&stshi);
        d.extend_from_slice(&(std.len() as u16).to_le_bytes());
        d.extend_from_slice(&std);
        d
    }

    #[test]
    fn style_definitions_are_split_into_their_modifier_lists() {
        let d = sample();
        let s = read(&d, 0, d.len());
        assert_eq!(s.stds.len(), 1);
        let std = s.stds[0].as_ref().unwrap();
        assert_eq!(std.name, "Body");
        assert_eq!((std.kind, std.base), (1, 0x0FFF));
        assert_eq!(std.papx, vec![0, 0, 0x61, 0x24, 1]);
        assert_eq!(std.chpx, vec![0x35, 0x08, 1]);
    }
}
