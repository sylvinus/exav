//! Records of the PowerPoint Document stream and of OfficeArt ([MS-PPT]
//! 2.3.1, [MS-ODRAW] 2.2.1): an 8-byte header (version and instance, type,
//! length) and the body. A container's children are read within its body;
//! a length past the end is cut to what is there.

use crate::formats::office::common::bytes::Cur;

#[derive(Clone, Copy, Debug)]
pub struct Rec<'a> {
    pub inst: u16,
    pub typ: u16,
    pub data: &'a [u8],
    /// Offset of the header in the slice it was read from.
    pub at: usize,
}

impl<'a> Rec<'a> {
    pub fn children(&self) -> Children<'a> {
        Children::new(self.data)
    }

    /// The first child of type `typ`.
    pub fn child(&self, typ: u16) -> Option<Rec<'a>> {
        self.children().find(|r| r.typ == typ)
    }

    pub fn cur(&self) -> Cur<'a> {
        Cur::new(self.data)
    }
}

/// The record at `at` in `d`.
pub fn read_at(d: &[u8], at: usize) -> Option<Rec<'_>> {
    let mut c = Cur::at(d, at);
    if c.left() < 8 {
        return None;
    }
    let vi = c.u16();
    let typ = c.u16();
    let len = c.u32() as usize;
    let start = at + 8;
    let end = start.saturating_add(len).min(d.len());
    Some(Rec {
        inst: vi >> 4,
        typ,
        data: &d[start..end],
        at,
    })
}

/// The records one after another in a container's body.
pub struct Children<'a> {
    d: &'a [u8],
    p: usize,
    n: usize,
}

impl<'a> Children<'a> {
    pub fn new(d: &'a [u8]) -> Self {
        Children { d, p: 0, n: 0 }
    }
}

/// Records read from one container at most: a bound on hostile files.
const MAX_CHILDREN: usize = 1 << 18;

impl<'a> Iterator for Children<'a> {
    type Item = Rec<'a>;

    fn next(&mut self) -> Option<Rec<'a>> {
        if self.n >= MAX_CHILDREN {
            return None;
        }
        let r = read_at(self.d, self.p)?;
        self.p = self.p + 8 + r.data.len();
        self.n += 1;
        Some(r)
    }
}

#[cfg(test)]
pub mod build {
    //! Records written for tests.

    pub fn rec(ver: u8, inst: u16, typ: u16, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(body.len() + 8);
        v.extend_from_slice(&(u16::from(ver & 0xF) | inst << 4).to_le_bytes());
        v.extend_from_slice(&typ.to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    pub fn container(typ: u16, inst: u16, children: &[Vec<u8>]) -> Vec<u8> {
        rec(0xF, inst, typ, &children.concat())
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    #[test]
    fn children_and_truncation() {
        let c = container(
            0x03E8,
            0,
            &[rec(0, 1, 0x03E9, &[1, 2]), rec(0, 0, 0x0FA0, b"hi")],
        );
        let r = read_at(&c, 0).unwrap();
        let kids: Vec<_> = r
            .children()
            .map(|k| (k.typ, k.inst, k.data.to_vec()))
            .collect();
        assert_eq!(
            kids,
            vec![(0x03E9, 1, vec![1, 2]), (0x0FA0, 0, b"hi".to_vec())]
        );
        // Cut short: the last child is what is there.
        let r = read_at(&c[..c.len() - 1], 0).unwrap();
        assert_eq!(r.children().last().unwrap().data, b"h");
        assert!(read_at(&c, c.len() - 4).is_none());
    }
}
