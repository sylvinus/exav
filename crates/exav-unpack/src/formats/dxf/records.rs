//! Pairs into records: from one group code 0 to the next, one entity,
//! object, table entry or section marker.

use super::pairs::{Stop, Tag, Tags};

/// One record: the value of its group code 0 and the pairs that follow it,
/// comments (999) left out.
pub struct Record<'a> {
    pub name: Tag<'a>,
    pub tags: Vec<Tag<'a>>,
}

impl Record<'_> {
    /// Whether the record's type is `name`, ignoring ASCII case.
    pub fn is(&self, name: &str) -> bool {
        self.name.is(name)
    }

    /// The type as text.
    pub fn type_name(&self) -> String {
        String::from_utf8_lossy(self.name.bytes())
            .trim()
            .to_string()
    }
}

/// The records of a file, with one record of look-ahead. Pairs before the
/// first group code 0 belong to no record and are skipped.
pub struct Records<'a> {
    tags: Tags<'a>,
    next_zero: Option<Tag<'a>>,
    peeked: Option<Record<'a>>,
}

impl<'a> Records<'a> {
    pub fn new(data: &'a [u8]) -> Records<'a> {
        Records {
            tags: Tags::new(data),
            next_zero: None,
            peeked: None,
        }
    }

    fn read(&mut self) -> Option<Record<'a>> {
        let name = match self.next_zero.take() {
            Some(t) => t,
            None => self.tags.by_ref().find(|t| t.code == 0)?,
        };
        let mut tags = Vec::new();
        for tag in self.tags.by_ref() {
            match tag.code {
                0 => {
                    self.next_zero = Some(tag);
                    break;
                }
                999 => {}
                _ => tags.push(tag),
            }
        }
        Some(Record { name, tags })
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Record<'a>> {
        self.peeked.take().or_else(|| self.read())
    }

    pub fn peek(&mut self) -> Option<&Record<'a>> {
        if self.peeked.is_none() {
            self.peeked = self.read();
        }
        self.peeked.as_ref()
    }

    /// The next record, if `f` accepts it.
    pub fn next_if(&mut self, f: impl FnOnce(&Record<'a>) -> bool) -> Option<Record<'a>> {
        if self.peek().is_some_and(f) {
            self.next()
        } else {
            None
        }
    }

    /// Why reading stopped before the end of the data, once it has.
    pub fn stop(&self) -> Option<&Stop> {
        self.tags.stop.as_ref()
    }

    /// Byte offset of the next pair not yet read.
    pub fn offset(&self) -> usize {
        self.tags.offset()
    }

    /// Whether the file is binary DXF.
    pub fn is_binary(&self) -> bool {
        self.tags.is_binary()
    }
}
