//! The export table of a PE, read as yara-x reads it: one export per entry of
//! the address table, named when the name tables say so.

use std::collections::BTreeSet;

use goblin::pe::data_directories::DataDirectory;
use goblin::pe::section_table::SectionTable;

use super::{EXPORT_COST, MAX_FUNCTION_NAME, Unread, until_nul};

/// An exported function. `rva`, `offset` and `forwarder` are what yara-x's
/// `export_details` gives; only the comparison with goblin reads them yet.
pub(crate) struct Export<'a> {
    /// The ordinal base of the directory plus the index in the address table.
    pub ordinal: u32,
    #[cfg_attr(not(test), allow(dead_code))]
    pub rva: u32,
    /// Where `rva` is in the object; for a forwarder, where its string is.
    #[cfg_attr(not(test), allow(dead_code))]
    pub offset: Option<usize>,
    /// The name, up to [`MAX_FUNCTION_NAME`] bytes, if the name tables give
    /// one that is UTF-8.
    pub name: Option<&'a str>,
    /// For an address inside the export directory: the string it points to
    /// (`DLL.name` or `DLL.#ordinal`), read as the name is.
    #[cfg_attr(not(test), allow(dead_code))]
    pub forwarder: Option<&'a str>,
}

#[cfg(test)]
thread_local! {
    /// How many export directories were read on this thread.
    pub(super) static READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Maps an RVA to a file offset as goblin's `find_offset` does over the same
/// sections (the first section that holds it wins), in a search that does not
/// walk the sections for each RVA.
pub(super) struct RvaIndex {
    /// Disjoint ranges of RVAs by start: (start, end, offset of the start).
    ranges: Vec<(u64, u64, u64)>,
}

/// How many bytes of a section goblin maps from its RVA. `file_alignment` is a
/// power of two.
fn mapped_size(section: &SectionTable, file_alignment: u32) -> u64 {
    if section.size_of_raw_data == 0 {
        return 0;
    }
    let page = |n: u64| (n + 0xfff) & !0xfff;
    let (raw, pointer) = (u64::from(section.size_of_raw_data), u64::from(section.pointer_to_raw_data));
    let alignment = u64::from(file_alignment);
    let aligned_end = (pointer + raw + alignment - 1) & !(alignment - 1);
    let size = (aligned_end - (pointer & !0x1ff)).min(page(raw));
    match section.virtual_size {
        0 => size,
        virtual_size => size.min(page(u64::from(virtual_size))),
    }
}

impl RvaIndex {
    pub(super) fn new(sections: &[SectionTable], file_alignment: u32) -> RvaIndex {
        // Each section opens and closes a range; between two edges the section
        // that holds the RVAs is the first of those open.
        let mut edges = Vec::with_capacity(sections.len() * 2);
        for (i, section) in sections.iter().enumerate() {
            let size = mapped_size(section, file_alignment);
            if size != 0 {
                let start = u64::from(section.virtual_address);
                edges.push((start, true, i));
                edges.push((start + size, false, i));
            }
        }
        edges.sort_unstable_by_key(|edge| edge.0);
        let mut open = BTreeSet::new();
        let mut ranges = Vec::new();
        let mut at = 0;
        while at < edges.len() {
            let position = edges[at].0;
            while let Some(&(_, opens, i)) = edges.get(at).filter(|edge| edge.0 == position) {
                if opens {
                    open.insert(i);
                } else {
                    open.remove(&i);
                }
                at += 1;
            }
            if let (Some(&first), Some(next)) = (open.first(), edges.get(at)) {
                let section = &sections[first];
                let offset = u64::from(section.pointer_to_raw_data) + position - u64::from(section.virtual_address);
                ranges.push((position, next.0, offset));
            }
        }
        RvaIndex { ranges }
    }

    pub(super) fn offset(&self, rva: u32) -> Option<usize> {
        let rva = u64::from(rva);
        let &(start, end, offset) = self.ranges.get(self.ranges.partition_point(|r| r.0 <= rva).checked_sub(1)?)?;
        if rva >= end {
            return None;
        }
        usize::try_from(offset + rva - start).ok()
    }
}

/// The string at `rva`: up to [`MAX_FUNCTION_NAME`] bytes, ending at a NUL or
/// at the end of the object. `None` if it maps nowhere, is not in the object,
/// or is not UTF-8.
fn string_at<'a>(data: &'a [u8], index: &RvaIndex, rva: u32) -> Option<&'a str> {
    let rest = data.get(index.offset(rva)?..).filter(|rest| !rest.is_empty())?;
    std::str::from_utf8(until_nul(rest, MAX_FUNCTION_NAME)).ok()
}

fn le32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// The functions the export directory `dir` lists, in the order of the address
/// table. The tables are read as far as the object goes.
///
/// The address table sets the functions, with no cap on their number but the
/// room: the first name in the ordinal table that points at an entry names it,
/// and a function with no name is one by ordinal. A directory at RVA 0 or with
/// no address table lists nothing. The name pointer table must lie whole in
/// the object, or there are no names.
///
/// `room` is the memory the caller allows. The tables are sized by the counts in
/// the directory, which a table cannot hold more of than the object has room
/// for: a count that would take more is [`Unread::TooLarge`], and one past the
/// size of the object [`Unread::Malformed`], as is a directory that maps
/// nowhere or runs off the object.
pub(super) fn read_exports<'a>(
    data: &'a [u8],
    dir: DataDirectory,
    sections: &[SectionTable],
    file_alignment: u32,
    room: usize,
) -> Result<Vec<Export<'a>>, Unread> {
    #[cfg(test)]
    READS.with(|reads| reads.set(reads.get() + 1));
    if dir.virtual_address == 0 {
        return Ok(Vec::new());
    }
    let index = RvaIndex::new(sections, file_alignment);
    let header = index
        .offset(dir.virtual_address)
        .and_then(|at| data.get(at..)?.get(..40))
        .ok_or(Unread::Malformed)?;
    let (base, functions, names) = (le32(header, 16), le32(header, 20) as usize, le32(header, 24) as usize);
    if functions.max(names).min(data.len() / 2).saturating_mul(EXPORT_COST) > room {
        return Err(Unread::TooLarge);
    }
    if functions.max(names) > data.len() {
        return Err(Unread::Malformed);
    }
    let table = |rva: u32| index.offset(rva).and_then(|at| data.get(at..)).unwrap_or_default();

    let addresses = table(le32(header, 28));
    let name_rvas = Some(table(le32(header, 32)))
        .filter(|table| table.len() / 4 >= names)
        .map_or(&[][..], |table| &table[..names * 4]);
    let ordinals = table(le32(header, 36));

    // The index in the address table of each name, by position in the name
    // table; the first name of a function names it.
    let mut named = vec![None; functions.min(1 << 16)];
    for (position, ordinal) in ordinals.as_chunks::<2>().0.iter().take(names).enumerate() {
        if let Some(slot) = named.get_mut(usize::from(u16::from_le_bytes(*ordinal)))
            && slot.is_none()
        {
            *slot = Some(position);
        }
    }

    let listed = u64::from(dir.virtual_address)..u64::from(dir.virtual_address) + u64::from(dir.size);
    let mut exports = Vec::with_capacity(functions.min(addresses.len() / 4));
    for (i, address) in addresses.as_chunks::<4>().0.iter().take(functions).enumerate() {
        let Some(ordinal) = u32::try_from(i).ok().and_then(|i| base.checked_add(i)) else {
            break;
        };
        let rva = le32(address, 0);
        let name = named
            .get(i)
            .copied()
            .flatten()
            .and_then(|position| name_rvas.get(position * 4..position * 4 + 4))
            .and_then(|name| string_at(data, &index, le32(name, 0)));
        exports.push(Export {
            ordinal,
            rva,
            offset: index.offset(rva),
            name,
            forwarder: listed.contains(&u64::from(rva)).then(|| string_at(data, &index, rva)).flatten(),
        });
    }
    Ok(exports)
}
