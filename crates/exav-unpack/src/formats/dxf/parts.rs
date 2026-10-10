//! A record's tags in their parts: application groups (102) removed, the
//! extended data (from the first 1001) set apart, and subclass markers (100)
//! to find each class's groups by.
//!
//! An R12 file has no subclass markers: all of a record's groups are then
//! one list, which every lookup searches.

use super::pairs::Tag;

pub struct Parts<'a> {
    pub tags: Vec<Tag<'a>>,
    xdata: Vec<Tag<'a>>,
    /// Index of the first subclass marker, when there is one.
    first_marker: Option<usize>,
    dimstyle: bool,
}

impl<'a> Parts<'a> {
    /// `dimstyle`: the record is a DIMSTYLE entry, whose handle is group
    /// 105 because group 5 is DIMBLK there.
    pub fn new(tags: &[Tag<'a>], dimstyle: bool) -> Parts<'a> {
        let mut out = Vec::with_capacity(tags.len());
        let mut xdata = Vec::new();
        let mut iter = tags.iter();
        while let Some(t) = iter.next() {
            match t.code {
                102 if t.bytes().first() == Some(&b'{') => {
                    // Up to and including the closing "}".
                    for inner in iter.by_ref() {
                        if inner.code == 102 && inner.bytes().first() == Some(&b'}') {
                            break;
                        }
                    }
                }
                // A stray closing brace.
                102 => {}
                1001 => {
                    xdata.push(*t);
                    xdata.extend(iter.by_ref().copied());
                }
                _ => out.push(*t),
            }
        }
        let first_marker = out.iter().position(|t| t.code == 100);
        Parts {
            tags: out,
            xdata,
            first_marker,
            dimstyle,
        }
    }

    pub fn has_markers(&self) -> bool {
        self.first_marker.is_some()
    }

    /// The groups before the first subclass marker: handle, owner. All of
    /// them when there are no markers.
    pub fn head(&self) -> &[Tag<'a>] {
        match self.first_marker {
            Some(i) => self.tags.get(..i).unwrap_or(&[]),
            None => &self.tags,
        }
    }

    pub fn handle(&self) -> u64 {
        let code = if self.dimstyle { 105 } else { 5 };
        self.head()
            .iter()
            .find(|t| t.code == code)
            .map_or(0, |t| t.handle())
    }

    pub fn owner(&self) -> u64 {
        self.head()
            .iter()
            .find(|t| t.code == 330)
            .map_or(0, |t| t.handle())
    }

    /// The groups of subclass `name`, up to the next marker.
    pub fn subclass(&self, name: &str) -> Option<&[Tag<'a>]> {
        let start = self.tags.iter().position(|t| t.code == 100 && t.is(name))? + 1;
        let rest = self.tags.get(start..)?;
        let len = rest
            .iter()
            .position(|t| t.code == 100)
            .unwrap_or(rest.len());
        rest.get(..len)
    }

    /// The groups after subclass `name` ends, markers included; all groups
    /// when there are no markers.
    pub fn after(&self, name: &str) -> &[Tag<'a>] {
        if self.first_marker.is_none() {
            return &self.tags;
        }
        let Some(start) = self.tags.iter().position(|t| t.code == 100 && t.is(name)) else {
            // No such class: whatever follows the first marker.
            return self
                .first_marker
                .and_then(|i| self.tags.get(i..))
                .unwrap_or(&[]);
        };
        let from = start + 1;
        let rest = self.tags.get(from..).unwrap_or(&[]);
        let len = rest
            .iter()
            .position(|t| t.code == 100)
            .unwrap_or(rest.len());
        self.tags.get(from + len..).unwrap_or(&[])
    }

    /// An entity's common groups (AcDbEntity), or every group without
    /// markers.
    pub fn common(&self) -> &[Tag<'a>] {
        if self.first_marker.is_none() {
            return &self.tags;
        }
        self.subclass("AcDbEntity").unwrap_or(&[])
    }

    /// The extended data of one application, after its 1001 group.
    pub fn xdata(&self, app: &str) -> Option<&[Tag<'a>]> {
        let start = self
            .xdata
            .iter()
            .position(|t| t.code == 1001 && t.is(app))?
            + 1;
        let rest = self.xdata.get(start..)?;
        let len = rest
            .iter()
            .position(|t| t.code == 1001)
            .unwrap_or(rest.len());
        rest.get(..len)
    }
}
