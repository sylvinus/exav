//! The parts of a byte-split set read as the file they were cut from.

use std::borrow::Cow;

use crate::source::ByteSource;

/// The parts of a byte-split set (`x.7z.001`, `.002`, ...) end to end, as one
/// source. Nothing is copied or held: a read goes to the part it lies in, and a
/// part may be a block cache over a file of any size.
pub struct ByteSpan {
    parts: Vec<Box<dyn ByteSource>>,
    /// Where each part starts in the joined file.
    bases: Vec<u64>,
    len: u64,
}

impl ByteSpan {
    /// The parts in volume order. Parts that together are longer than `usize`
    /// can address are refused, not cut where the address space ends.
    pub fn new(parts: Vec<Box<dyn ByteSource>>) -> Result<ByteSpan, String> {
        let mut bases = Vec::with_capacity(parts.len());
        let mut len = 0u64;
        for p in &parts {
            bases.push(len);
            len = len.saturating_add(p.len() as u64);
        }
        if usize::try_from(len).is_err() {
            return Err("the parts together are too long to be addressed".to_string());
        }
        Ok(ByteSpan { parts, bases, len })
    }
}

impl ByteSource for ByteSpan {
    fn len(&self) -> usize {
        usize::try_from(self.len).unwrap_or(usize::MAX)
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        let end = (off as u64).saturating_add(len as u64).min(self.len);
        let mut at = off as u64;
        if at >= end {
            return Cow::Borrowed(&[]);
        }
        // The last part that starts at or before `at`: an empty part is passed
        // over by the one after it, which starts in the same place.
        let part_of = |at: u64| self.bases.partition_point(|&b| b <= at) - 1;
        let k = part_of(at);
        let first = &self.parts[k];
        let inner = (at - self.bases[k]) as usize;
        let want = ((end - at) as usize).min(first.len() - inner);
        if at + want as u64 == end {
            return first.window(inner, want);
        }
        let mut out = Vec::with_capacity(crate::cap_prealloc((end - at) as usize));
        while at < end {
            let k = part_of(at);
            let part = &self.parts[k];
            let inner = (at - self.bases[k]) as usize;
            let want = ((end - at) as usize).min(part.len() - inner);
            let w = part.window(inner, want);
            out.extend_from_slice(&w);
            // A part that gives less than it holds failed to read: what follows
            // would not be where it should.
            if w.len() < want {
                break;
            }
            at += want as u64;
        }
        Cow::Owned(out)
    }

    fn read_error(&self) -> Option<String> {
        self.parts.iter().find_map(|p| p.read_error())
    }

    fn identity(&self) -> (usize, usize) {
        (self as *const Self as usize, self.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(parts: &[&[u8]]) -> ByteSpan {
        ByteSpan::new(
            parts
                .iter()
                .map(|p| Box::new(p.to_vec()) as Box<dyn ByteSource>)
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn the_parts_read_as_the_file_they_were_cut_from_wherever_a_read_falls() {
        let whole: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let cuts: [&[usize]; 4] = [&[1], &[100, 700], &[0, 500, 500, 999], &[250, 500, 750]];
        for cuts in cuts {
            let mut parts: Vec<&[u8]> = Vec::new();
            let mut from = 0;
            for &c in cuts.iter().chain(&[1000]) {
                parts.push(&whole[from..c]);
                from = c;
            }
            let s = span(&parts);
            assert_eq!(s.len(), 1000, "{cuts:?}");
            for off in [
                0, 1, 99, 100, 101, 499, 500, 501, 699, 700, 998, 999, 1000, 1500,
            ] {
                for len in [0, 1, 2, 100, 600, 1000, 5000] {
                    let want = &whole[off.min(1000)..(off + len).min(1000)];
                    assert_eq!(&*s.window(off, len), want, "{cuts:?} {off} {len}");
                }
            }
        }
    }

    #[test]
    fn a_read_inside_one_part_borrows_it() {
        let s = span(&[b"abcd", b"efgh"]);
        assert!(matches!(s.window(4, 3), Cow::Borrowed(b"efg")));
        assert!(matches!(s.window(2, 4), Cow::Owned(_)));
    }

    #[test]
    fn a_part_that_cannot_be_read_ends_the_read_and_is_reported() {
        struct Broken;
        impl ByteSource for Broken {
            fn len(&self) -> usize {
                4
            }
            fn window(&self, _: usize, _: usize) -> Cow<'_, [u8]> {
                Cow::Owned(Vec::new())
            }
            fn read_error(&self) -> Option<String> {
                Some("gone".to_string())
            }
            fn identity(&self) -> (usize, usize) {
                (0, 4)
            }
        }
        let s = ByteSpan::new(vec![
            Box::new(b"abcd".to_vec()),
            Box::new(Broken),
            Box::new(b"wxyz".to_vec()),
        ])
        .unwrap();
        assert_eq!(s.len(), 12);
        assert_eq!(&*s.window(2, 10), b"cd");
        assert_eq!(s.read_error().as_deref(), Some("gone"));
        assert_eq!(&*s.window(8, 4), b"wxyz");
    }

    #[test]
    fn no_parts_is_an_empty_file() {
        let s = ByteSpan::new(Vec::new()).unwrap();
        assert_eq!(s.len(), 0);
        assert!(s.window(0, 10).is_empty());
        assert!(s.read_error().is_none());
    }

    /// A source that only has a length.
    #[cfg(target_pointer_width = "32")]
    struct Long(usize);

    #[cfg(target_pointer_width = "32")]
    impl ByteSource for Long {
        fn len(&self) -> usize {
            self.0
        }

        fn window(&self, _: usize, _: usize) -> Cow<'_, [u8]> {
            Cow::Owned(Vec::new())
        }

        fn identity(&self) -> (usize, usize) {
            (0, self.0)
        }
    }

    /// Parts that together are longer than `usize` can address are refused.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn parts_longer_than_the_address_space_are_refused() {
        let parts = (0..2)
            .map(|_| Box::new(Long(3 << 30)) as Box<dyn ByteSource>)
            .collect();
        assert!(ByteSpan::new(parts).is_err());
    }
}
