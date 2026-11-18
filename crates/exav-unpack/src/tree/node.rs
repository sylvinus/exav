//! Where a node's content came from, what it is, and how it ends.

use std::cell::Cell;
use std::io::{Chain, Read};

use crate::{ByteSource, Format};

/// How a node's content ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// To its declared end.
    Complete,
    /// The stream ended early, or a checksum disagreed after a full decode:
    /// what is missing is absent, not hidden.
    Cut(String),
    /// Bytes that are present were not decoded.
    Damaged(String),
}

impl End {
    /// How a stream that failed with `e` ends.
    pub fn from_error(e: &std::io::Error) -> End {
        if crate::decode_error_hides_content(e) {
            End::Damaged(e.to_string())
        } else {
            End::Cut(e.to_string())
        }
    }

    /// Whether the content is all there.
    pub fn is_complete(&self) -> bool {
        matches!(self, End::Complete)
    }
}

/// A second way of reading the bytes of an object that is already read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondReading {
    /// A ZIP appended to the object.
    AppendedZip,
    /// The object read as another format.
    AlsoReadsAs(Format),
}

/// What an encoded payload was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodedKind {
    /// A long base64 run in the text.
    Base64Run,
    /// A `data:` asset of a markup document.
    MarkupAsset,
}

/// How a node came to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// The object the walk was given.
    Root,
    /// A member of its container.
    Member,
    /// The parts of a split set, rejoined.
    Joined { parts: Vec<String> },
    /// The container's own bytes, read a second way.
    Second(SecondReading),
    /// A payload decoded out of the container's text, and its number from 1.
    Encoded(EncodedKind, usize),
    /// An object found at an offset of the container.
    Carved { offset: u64 },
    /// Something a consumer made from the container, by name and index.
    Derived(&'static str, usize),
}

/// A stream a node's content can be read from, once: the bytes already read
/// from it, then the rest.
pub struct StreamCell<'a> {
    head: &'a [u8],
    rest: Cell<Option<&'a mut dyn Read>>,
}

impl<'a> StreamCell<'a> {
    /// A stream that has given `head`, and goes on in `rest`.
    pub fn new(head: &'a [u8], rest: &'a mut dyn Read) -> Self {
        StreamCell {
            head,
            rest: Cell::new(Some(rest)),
        }
    }

    /// The bytes already read from the stream, a look at its start.
    pub fn head(&self) -> &'a [u8] {
        self.head
    }

    /// The stream from its start, the first time it is asked for.
    pub fn take(&self) -> Option<Chain<&'a [u8], &'a mut dyn Read>> {
        self.rest.take().map(|rest| self.head.chain(rest))
    }
}

/// The bytes of a node.
pub enum Content<'a> {
    /// Not decoded, or an entry that only reports.
    None,
    /// Held, or read where they lie, or spilled and read through a cache.
    Source(&'a dyn ByteSource),
    /// Decoded as they are read.
    Stream(StreamCell<'a>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_that_hides_nothing_is_a_cut_and_one_that_does_is_damage() {
        use std::io::{Error, ErrorKind};
        let eof = Error::from(ErrorKind::UnexpectedEof);
        let bad = Error::new(ErrorKind::InvalidData, "bad block");
        let sum = crate::checksum_mismatch("crc");
        assert!(matches!(End::from_error(&eof), End::Cut(_)));
        assert!(matches!(End::from_error(&sum), End::Cut(_)));
        assert_eq!(End::from_error(&bad), End::Damaged("bad block".to_string()));
        assert!(End::Complete.is_complete());
        assert!(!End::from_error(&eof).is_complete());
        assert!(!End::from_error(&bad).is_complete());
    }

    #[test]
    fn a_stream_is_taken_once_from_its_start() {
        let mut rest: &[u8] = b"def";
        let cell = StreamCell::new(b"abc", &mut rest);
        assert_eq!(cell.head(), b"abc");
        let mut out = String::new();
        cell.take()
            .expect("first")
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, "abcdef");
        assert!(cell.take().is_none());
        // The head stays to look at.
        assert_eq!(cell.head(), b"abc");
    }
}
