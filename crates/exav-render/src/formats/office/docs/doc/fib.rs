//! The file information block and the text it locates: the piece table
//! ([MS-DOC] 2.5, 2.9.38).

use crate::formats::office::common::bytes::{Cur, u16_at, u32_at};
use crate::formats::office::docs::error::{Error, Result};

pub struct Fib {
    pub n_fib: u16,
    pub which_table: bool,
    pub encrypted: bool,
    pub ccp_text: i64,
    pub ccp_ftn: i64,
    pub ccp_hdd: i64,
    pub ccp_atn: i64,
    pub ccp_edn: i64,
    pub ccp_txbx: i64,
    pub ccp_hdr_txbx: i64,
    /// The (fc, lcb) pairs of FibRgFcLcb97, as many as the file has.
    pub pairs: Vec<(u32, u32)>,
}

/// A sum of character counts as a character position, saturating.
pub fn cp(sum: i64) -> u32 {
    u32::try_from(sum).unwrap_or(u32::MAX)
}

/// Indexes into FibRgFcLcb97's pairs.
pub mod idx {
    pub const STSHF: usize = 1;
    pub const PLCFFND_REF: usize = 2;
    pub const PLCFFND_TXT: usize = 3;
    pub const PLCFAND_REF: usize = 4;
    pub const PLCFAND_TXT: usize = 5;
    pub const PLCF_SED: usize = 6;
    pub const PLCF_HDD: usize = 11;
    pub const PLCF_BTE_CHPX: usize = 12;
    pub const PLCF_BTE_PAPX: usize = 13;
    pub const STTBF_FFN: usize = 15;
    pub const STTBF_BKMK: usize = 21;
    pub const PLCF_BKF: usize = 22;
    pub const PLCF_BKL: usize = 23;
    pub const DOP: usize = 31;
    pub const CLX: usize = 33;
    pub const GRP_XST_ATN_OWNERS: usize = 36;
    pub const PLC_SPA_MOM: usize = 40;
    pub const PLC_SPA_HDR: usize = 41;
    pub const PLCF_ATN_BKF: usize = 42;
    pub const PLCF_ATN_BKL: usize = 43;
    pub const PLCFEND_REF: usize = 46;
    pub const PLCFEND_TXT: usize = 47;
    pub const DGG_INFO: usize = 50;
    pub const PLCFTXBX_TXT: usize = 56;
    pub const PLCF_HDR_TXBX_TXT: usize = 58;
    pub const PLF_LST: usize = 73;
    pub const PLF_LFO: usize = 74;
}

impl Fib {
    pub fn read(wd: &[u8]) -> Result<Fib> {
        if wd.len() < 154 {
            return Err(Error::Malformed(
                "the WordDocument stream is too short".into(),
            ));
        }
        let w_ident = u16_at(wd, 0);
        if w_ident != 0xA5EC {
            return Err(Error::Unsupported(format!(
                "Word document of an unknown kind (identifier {w_ident:#06x})"
            )));
        }
        let n_fib = u16_at(wd, 2);
        let flags = u16_at(wd, 10);
        let csw = usize::from(u16_at(wd, 32));
        let w_lw = 34 + csw * 2;
        let cslw = usize::from(u16_at(wd, w_lw));
        let lw = w_lw + 2;
        let w_fc = lw + cslw * 4;
        let cb = usize::from(u16_at(wd, w_fc));
        let mut pairs = Vec::with_capacity(cb.min(512));
        for i in 0..cb.min(512) {
            let p = w_fc + 2 + 8 * i;
            if p + 8 > wd.len() {
                break;
            }
            pairs.push((u32_at(wd, p), u32_at(wd, p + 4)));
        }
        let lwv = |i: usize| i64::from(u32_at(wd, lw + 4 * i) as i32);
        if cslw < 15 {
            return Err(Error::Malformed(
                "the file information block is too short".into(),
            ));
        }
        Ok(Fib {
            n_fib,
            which_table: flags & 0x0200 != 0,
            encrypted: flags & 0x0100 != 0,
            ccp_text: lwv(3).max(0),
            ccp_ftn: lwv(4).max(0),
            ccp_hdd: lwv(5).max(0),
            ccp_atn: lwv(7).max(0),
            ccp_edn: lwv(8).max(0),
            ccp_txbx: lwv(9).max(0),
            ccp_hdr_txbx: lwv(10).max(0),
            pairs,
        })
    }

    /// The (offset, size) of a structure in the table stream; (0, 0) when the
    /// file has no such pair.
    pub fn at(&self, i: usize) -> (usize, usize) {
        self.pairs
            .get(i)
            .map(|p| (p.0 as usize, p.1 as usize))
            .unwrap_or((0, 0))
    }

    /// Total characters of all the parts of the document.
    pub fn total_cp(&self) -> i64 {
        let parts = self.ccp_text
            + self.ccp_ftn
            + self.ccp_hdd
            + self.ccp_atn
            + self.ccp_edn
            + self.ccp_txbx
            + self.ccp_hdr_txbx;
        // One more paragraph mark closes the last non-empty part.
        parts + i64::from(parts > self.ccp_text)
    }
}

/// One piece of text: characters `cp0..cp1`, at byte `fc` of the
/// WordDocument stream.
#[derive(Clone, Debug)]
pub struct Piece {
    pub cp0: u32,
    pub cp1: u32,
    pub fc: u32,
    pub compressed: bool,
    pub prm: u16,
}

impl Piece {
    pub fn unit(&self) -> u32 {
        if self.compressed { 1 } else { 2 }
    }

    pub fn fc_of(&self, cp: u32) -> u32 {
        self.fc
            .saturating_add((cp - self.cp0).saturating_mul(self.unit()))
    }
}

pub struct Clx {
    pub pieces: Vec<Piece>,
    /// The grpprls of Prm1 modifiers.
    pub prcs: Vec<Vec<u8>>,
}

pub fn read_clx(tbl: &[u8], off: usize, len: usize) -> Result<Clx> {
    let d = tbl
        .get(off..off.saturating_add(len).min(tbl.len()))
        .ok_or_else(|| Error::Malformed("the piece table is outside the table stream".into()))?;
    let mut c = Cur::new(d);
    let mut prcs = vec![];
    loop {
        match c.u8() {
            1 => {
                let n = usize::from(c.u16());
                prcs.push(c.bytes(n).to_vec());
                if prcs.len() > 1 << 15 {
                    return Err(Error::Malformed("too many property modifier groups".into()));
                }
            }
            2 => break,
            _ => {
                return Err(Error::Malformed(
                    "no piece table in the table stream".into(),
                ));
            }
        }
        if c.short {
            return Err(Error::Malformed("the piece table is cut short".into()));
        }
    }
    let lcb = c.u32() as usize;
    let plc = c.bytes(lcb);
    // n + 1 CPs of 4 bytes and n Pcd of 8 bytes.
    let n = plc.len().saturating_sub(4) / 12;
    let mut pieces = Vec::with_capacity(n);
    for i in 0..n {
        let cp0 = u32_at(plc, 4 * i);
        let cp1 = u32_at(plc, 4 * (i + 1));
        let pcd = 4 * (n + 1) + 8 * i;
        let fcc = u32_at(plc, pcd + 2);
        let prm = u16_at(plc, pcd + 6);
        let compressed = fcc & 0x4000_0000 != 0;
        let fc = fcc & 0x3FFF_FFFF;
        if cp1 < cp0 {
            return Err(Error::Malformed("pieces out of order".into()));
        }
        pieces.push(Piece {
            cp0,
            cp1,
            fc: if compressed { fc / 2 } else { fc },
            compressed,
            prm,
        });
    }
    if pieces.is_empty() {
        return Err(Error::Malformed("the document has no text".into()));
    }
    Ok(Clx { pieces, prcs })
}

const CP1252_HIGH: [u16; 32] = [
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
    0x0152, 0x008D, 0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
];

/// The text of every piece as UTF-16 code units, indexed by CP.
pub fn read_text(wd: &[u8], pieces: &[Piece], total: usize) -> Vec<u16> {
    read_text_in(wd, pieces, total, None)
}

/// [`read_text`], the 8-bit characters in a code page of 256 entries rather
/// than Windows 1252 (a Word 6 or 95 file keeps the document's own).
pub fn read_text_in(
    wd: &[u8],
    pieces: &[Piece],
    total: usize,
    table: Option<&[u16; 256]>,
) -> Vec<u16> {
    let mut out = vec![0x0Du16; total];
    for p in pieces {
        let (a, b) = (p.cp0 as usize, (p.cp1 as usize).min(total));
        if a >= b {
            continue;
        }
        let fc = p.fc as usize;
        for (k, slot) in out[a..b].iter_mut().enumerate() {
            *slot = if p.compressed {
                match wd.get(fc + k) {
                    Some(&c) if table.is_some_and(|_| c >= 0x80) => {
                        table.map_or(u16::from(c), |t| t[usize::from(c)])
                    }
                    Some(&c) if (0x80..0xA0).contains(&c) => CP1252_HIGH[usize::from(c - 0x80)],
                    Some(&c) => u16::from(c),
                    None => 0x0D,
                }
            } else {
                match wd.get(fc + 2 * k..fc + 2 * k + 2) {
                    Some(&[x, y]) => u16::from_le_bytes([x, y]),
                    _ => 0x0D,
                }
            };
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piece_table_with_both_encodings() {
        // Clx: one piece of 3 compressed characters at byte 0x100, one of 2
        // UTF-16 characters at 0x200.
        let mut plc = vec![];
        for cp in [0u32, 3, 5] {
            plc.extend_from_slice(&cp.to_le_bytes());
        }
        for (fc, compressed) in [(0x100u32, true), (0x200, false)] {
            plc.extend_from_slice(&[0, 0]);
            let v = if compressed {
                (fc * 2) | 0x4000_0000
            } else {
                fc
            };
            plc.extend_from_slice(&v.to_le_bytes());
            plc.extend_from_slice(&[0, 0]);
        }
        let mut clx = vec![2u8];
        clx.extend_from_slice(&(plc.len() as u32).to_le_bytes());
        clx.extend_from_slice(&plc);
        let c = read_clx(&clx, 0, clx.len()).unwrap();
        assert_eq!(c.pieces.len(), 2);
        assert_eq!((c.pieces[0].fc, c.pieces[0].compressed), (0x100, true));
        let mut wd = vec![0u8; 0x300];
        wd[0x100..0x103].copy_from_slice(&[b'a', 0x93, b'c']);
        wd[0x200..0x204].copy_from_slice(&[0x41, 0x26, 0x42, 0x00]);
        let t = read_text(&wd, &c.pieces, 5);
        assert_eq!(t, vec![0x61, 0x201C, 0x63, 0x2641, 0x42]);
    }

    #[test]
    fn a_piece_table_without_pieces_is_refused() {
        assert!(read_clx(&[2, 4, 0, 0, 0, 0, 0, 0, 0], 0, 9).is_err());
        assert!(read_clx(&[7], 0, 1).is_err());
    }
}
