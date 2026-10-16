//! A bounds-checked little-endian reader: a read past the end gives zeros and
//! sets `short`, so that a truncated record never panics.

#[derive(Clone)]
pub struct Cur<'a> {
    pub d: &'a [u8],
    pub p: usize,
    pub short: bool,
}

impl<'a> Cur<'a> {
    pub fn new(d: &'a [u8]) -> Self {
        Cur {
            d,
            p: 0,
            short: false,
        }
    }

    pub fn at(d: &'a [u8], p: usize) -> Self {
        Cur { d, p, short: false }
    }

    pub fn left(&self) -> usize {
        self.d.len().saturating_sub(self.p)
    }

    pub fn skip(&mut self, n: usize) {
        if self.left() < n {
            self.short = true;
            self.p = self.d.len();
        } else {
            self.p += n;
        }
    }

    /// `n` bytes, or what is left (and `short` set).
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let start = self.p.min(self.d.len());
        if self.left() < n {
            self.short = true;
            self.p = self.d.len();
            &self.d[start..]
        } else {
            self.p += n;
            &self.d[start..start + n]
        }
    }

    pub fn u8(&mut self) -> u8 {
        match self.d.get(self.p) {
            Some(&b) => {
                self.p += 1;
                b
            }
            None => {
                self.short = true;
                0
            }
        }
    }

    pub fn u16(&mut self) -> u16 {
        match *self.bytes(2) {
            [a, b] => u16::from_le_bytes([a, b]),
            _ => 0,
        }
    }

    pub fn i16(&mut self) -> i16 {
        self.u16() as i16
    }

    pub fn u32(&mut self) -> u32 {
        match *self.bytes(4) {
            [a, b, c, d] => u32::from_le_bytes([a, b, c, d]),
            _ => 0,
        }
    }

    pub fn i32(&mut self) -> i32 {
        self.u32() as i32
    }

    pub fn f64(&mut self) -> f64 {
        let b = self.bytes(8);
        let mut a = [0u8; 8];
        if b.len() == 8 {
            a.copy_from_slice(b);
        }
        f64::from_le_bytes(a)
    }
}

pub fn u16_at(d: &[u8], p: usize) -> u16 {
    Cur::at(d, p).u16()
}

pub fn u32_at(d: &[u8], p: usize) -> u32 {
    Cur::at(d, p).u32()
}

#[cfg(test)]
mod tests {
    use super::Cur;

    #[test]
    fn short_reads_give_zero_and_flag() {
        let mut c = Cur::new(&[1, 2, 3]);
        assert_eq!(c.u16(), 0x0201);
        assert!(!c.short);
        assert_eq!(c.u32(), 0);
        assert!(c.short);
        assert_eq!(c.left(), 0);
        let mut c = Cur::at(&[1], 5);
        assert_eq!(c.bytes(3), &[] as &[u8]);
        assert_eq!(c.f64(), 0.0);
    }
}
