//! A protocol buffers wire-format reader (the encoding documented at
//! protobuf.dev), schemaless: messages are read field by field, and the
//! field numbers of the messages used are written where they are used.

#[derive(Clone, Copy, Debug)]
pub enum Val<'a> {
    Varint(u64),
    Fixed64(u64),
    Bytes(&'a [u8]),
    Fixed32(u32),
}

/// One message's bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Msg<'a>(pub &'a [u8]);

pub fn varint(d: &[u8], p: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    for shift in (0..64).step_by(7) {
        let b = *d.get(*p)?;
        *p += 1;
        v |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

impl<'a> Msg<'a> {
    /// Every field, in order; stops at the first damaged one.
    pub fn fields(self) -> Fields<'a> {
        Fields { d: self.0, p: 0 }
    }

    pub fn get(self, n: u32) -> Option<Val<'a>> {
        self.fields().find(|f| f.0 == n).map(|f| f.1)
    }

    pub fn all(self, n: u32) -> impl Iterator<Item = Val<'a>> {
        self.fields().filter(move |f| f.0 == n).map(|f| f.1)
    }

    pub fn uint(self, n: u32) -> Option<u64> {
        match self.get(n)? {
            Val::Varint(v) | Val::Fixed64(v) => Some(v),
            Val::Fixed32(v) => Some(u64::from(v)),
            Val::Bytes(_) => None,
        }
    }

    pub fn int(self, n: u32) -> Option<i64> {
        self.uint(n).map(|v| v as i64)
    }

    /// A zigzag-encoded signed integer (sint32, sint64).
    pub fn sint(self, n: u32) -> Option<i64> {
        self.uint(n).map(|v| ((v >> 1) as i64) ^ -((v & 1) as i64))
    }

    pub fn boolean(self, n: u32) -> Option<bool> {
        self.uint(n).map(|v| v != 0)
    }

    pub fn double(self, n: u32) -> Option<f64> {
        match self.get(n)? {
            Val::Fixed64(v) => Some(f64::from_bits(v)),
            _ => None,
        }
    }

    pub fn float(self, n: u32) -> Option<f32> {
        match self.get(n)? {
            Val::Fixed32(v) => Some(f32::from_bits(v)),
            _ => None,
        }
    }

    pub fn bytes(self, n: u32) -> Option<&'a [u8]> {
        match self.get(n)? {
            Val::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn string(self, n: u32) -> Option<String> {
        self.bytes(n)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }

    pub fn msg(self, n: u32) -> Option<Msg<'a>> {
        self.bytes(n).map(Msg)
    }

    pub fn msgs(self, n: u32) -> impl Iterator<Item = Msg<'a>> {
        self.all(n).filter_map(|v| {
            if let Val::Bytes(b) = v {
                Some(Msg(b))
            } else {
                None
            }
        })
    }

    /// A TSP.Reference field's identifier (field 1 of the reference).
    pub fn reference(self, n: u32) -> Option<u64> {
        self.msg(n)?.uint(1)
    }

    pub fn references(self, n: u32) -> impl Iterator<Item = u64> + 'a {
        self.msgs(n).filter_map(|m| m.uint(1))
    }
}

pub struct Fields<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Iterator for Fields<'a> {
    type Item = (u32, Val<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.p >= self.d.len() {
            return None;
        }
        let key = varint(self.d, &mut self.p)?;
        let n = u32::try_from(key >> 3).ok()?;
        let v = match key & 7 {
            0 => Val::Varint(varint(self.d, &mut self.p)?),
            1 => {
                let b = self.d.get(self.p..self.p + 8)?;
                self.p += 8;
                Val::Fixed64(u64::from_le_bytes(b.try_into().ok()?))
            }
            2 => {
                let len = usize::try_from(varint(self.d, &mut self.p)?).ok()?;
                let b = self.d.get(self.p..self.p.checked_add(len)?)?;
                self.p += len;
                Val::Bytes(b)
            }
            5 => {
                let b = self.d.get(self.p..self.p + 4)?;
                self.p += 4;
                Val::Fixed32(u32::from_le_bytes(b.try_into().ok()?))
            }
            _ => {
                // Groups (3, 4) and unknown types end the message.
                self.p = self.d.len();
                return None;
            }
        };
        Some((n, v))
    }
}

/// A protobuf writer, for tests that build documents.
#[cfg(any(test, feature = "office-test-util"))]
pub mod write {
    #[derive(Default, Clone)]
    pub struct W(pub Vec<u8>);

    fn varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    impl W {
        pub fn uint(mut self, n: u32, v: u64) -> Self {
            varint(&mut self.0, u64::from(n) << 3);
            varint(&mut self.0, v);
            self
        }
        pub fn sint(self, n: u32, v: i64) -> Self {
            self.uint(n, ((v << 1) ^ (v >> 63)) as u64)
        }
        pub fn double(mut self, n: u32, v: f64) -> Self {
            varint(&mut self.0, u64::from(n) << 3 | 1);
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        pub fn float(mut self, n: u32, v: f32) -> Self {
            varint(&mut self.0, u64::from(n) << 3 | 5);
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        pub fn fixed32(mut self, n: u32, v: u32) -> Self {
            varint(&mut self.0, u64::from(n) << 3 | 5);
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        pub fn bytes(mut self, n: u32, b: &[u8]) -> Self {
            varint(&mut self.0, u64::from(n) << 3 | 2);
            varint(&mut self.0, b.len() as u64);
            self.0.extend_from_slice(b);
            self
        }
        pub fn msg(self, n: u32, m: W) -> Self {
            self.bytes(n, &m.0)
        }
        pub fn reference(self, n: u32, id: u64) -> Self {
            self.msg(n, W::default().uint(1, id))
        }
        pub fn varint_len(v: u64) -> Vec<u8> {
            let mut out = vec![];
            varint(&mut out, v);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::write::W;
    use super::*;

    #[test]
    fn round_trip() {
        let m = W::default()
            .uint(1, 300)
            .sint(2, -5)
            .string_test(3, "hi")
            .double(4, 1.5)
            .msg(5, W::default().uint(1, 7))
            .0;
        let msg = Msg(&m);
        assert_eq!(msg.uint(1), Some(300));
        assert_eq!(msg.sint(2), Some(-5));
        assert_eq!(msg.string(3).as_deref(), Some("hi"));
        assert_eq!(msg.double(4), Some(1.5));
        assert_eq!(msg.reference(5), Some(7));
        // Truncated: no panic, fields up to the damage.
        assert!(Msg(&m[..m.len() - 1]).fields().count() < 5);
        assert_eq!(
            Msg(&[0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]).fields().count(),
            0
        );
    }

    impl W {
        fn string_test(self, n: u32, s: &str) -> Self {
            self.bytes(n, s.as_bytes())
        }
    }
}
