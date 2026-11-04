//! The headers of a PE executable, and where an address in memory is in the
//! file: the one reader of both, for the readers that need only these.
//!
//! The headers are read through a [`Window`], so a reader that holds only
//! part of the file, or a file of any size, reads the same fields as one that
//! holds all of it. Nothing here judges the file: it reports what the headers
//! say, and a caller that needs more (a section count in some range, a
//! magic) checks that where it uses it.
//!
//! The layout is Microsoft's PE format specification. An address in memory
//! is in a section when it is below the section's virtual size (its raw size
//! when that is 0) rounded up to a page of 0x1000 bytes. It is in the file
//! when it is also below the raw size, because the specification says that
//! only the raw size is rounded and that the virtual size past the raw size is
//! zero-filled. An address below the size of headers that no section maps is
//! the same offset in the file: the loader maps the headers there, and the
//! sections over them.
//!
//! The corkami PE notes give two more points: a section with a virtual size
//! of 0 is taken as long as its raw data, and `NumberOfRvaAndSizes` counts at
//! most 16 directories.

use std::borrow::Cow;

/// Up to `len` bytes of the object from `off`, fewer where it ends.
pub type Window<'w> = dyn Fn(usize, usize) -> Cow<'w, [u8]> + 'w;

/// The optional header magic of a PE32 image.
pub const PE32: u16 = 0x10b;
/// The optional header magic of a PE32+ image.
pub const PE32_PLUS: u16 = 0x20b;

/// The unit a section's size in memory is rounded up to.
const PAGE: u64 = 0x1000;
/// The bytes of a section header.
const SECTION: usize = 40;
/// The data directories there are names for.
const MAX_DIRECTORIES: usize = 16;
/// The part of the optional header that is read: it holds the fixed fields
/// and 16 directories of either magic.
const OPTIONAL_READ: usize = 0x100;

pub(crate) fn le16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        crate::bytes::at(d, o, 2)?.try_into().ok()?,
    ))
}

pub(crate) fn le32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        crate::bytes::at(d, o, 4)?.try_into().ok()?,
    ))
}

/// An entry of the data directory table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory {
    /// The address in memory (RVA) of the table.
    pub address: u32,
    pub size: u32,
}

/// A section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
}

impl Section {
    fn parse(s: &[u8; SECTION]) -> Option<Section> {
        Some(Section {
            name: s[..8].try_into().ok()?,
            virtual_size: le32(s, 8)?,
            virtual_address: le32(s, 12)?,
            raw_size: le32(s, 16)?,
            raw_pointer: le32(s, 20)?,
            characteristics: le32(s, 36)?,
        })
    }

    /// How far the section reaches in memory from its address: its virtual
    /// size, or its raw size when it has none, rounded up to a page.
    pub fn extent(&self) -> u64 {
        let size = if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        };
        u64::from(size).next_multiple_of(PAGE)
    }

    /// Whether `rva` is in the section, in memory.
    pub fn holds(&self, rva: u32) -> bool {
        rva.checked_sub(self.virtual_address)
            .is_some_and(|at| u64::from(at) < self.extent())
    }

    /// Where in the file `rva` is, if the section holds it and the file has
    /// the bytes for it: the position inside the section is below the
    /// extent and below the raw size.
    pub fn offset_of(&self, rva: u32) -> Option<usize> {
        let at = rva.checked_sub(self.virtual_address)?;
        if u64::from(at) >= self.extent() || at >= self.raw_size {
            return None;
        }
        (self.raw_pointer as usize).checked_add(at as usize)
    }
}

/// The headers of a PE executable, as far as they are there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    pub machine: u16,
    /// The section count the file header declares. [`Headers::sections`]
    /// has the headers of those that lie in the file, so fewer if it ends
    /// first.
    pub section_count: u16,
    /// [`PE32`] or [`PE32_PLUS`] for the images this reader knows the
    /// optional header of; any other value is reported as it is.
    pub magic: u16,
    /// The fields that follow, 0 where the optional header ends before them
    /// (or, for the alignments and the size of headers, where it has a magic
    /// that is neither of the two).
    pub entry_point: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_headers: u32,
    /// `NumberOfRvaAndSizes` as the file says it. 0 for a magic that is
    /// neither of the two.
    pub directory_count: u32,
    /// The directories that exist: at most 16, and only those whose entry
    /// lies inside the optional header.
    pub directories: Vec<DataDirectory>,
    pub sections: Vec<Section>,
}

impl Headers {
    /// Read the headers of the image `window` shows. `None` if it does not
    /// start with `MZ`, has no `PE\0\0` where `e_lfanew` says, or the
    /// optional header is too short to have a magic.
    pub fn read(window: &Window) -> Option<Headers> {
        if !window(0, 2).starts_with(b"MZ") {
            return None;
        }
        let pe = le32(&window(0x3c, 4), 0)? as usize;
        let h = window(pe, 24);
        if !h.starts_with(b"PE\0\0") {
            return None;
        }
        let machine = le16(&h, 4)?;
        let section_count = le16(&h, 6)?;
        let optional = usize::from(le16(&h, 20)?);
        let optional_at = pe.checked_add(24)?;
        let opt = window(optional_at, optional.min(OPTIONAL_READ));
        let magic = le16(&opt, 0)?;
        let field = |o: usize| le32(&opt, o).unwrap_or(0);
        // Where the directory count is, in PE32 and PE32+.
        let count_at = match magic {
            PE32 => Some(92),
            PE32_PLUS => Some(108),
            _ => None,
        };
        let known = |o: usize| if count_at.is_some() { field(o) } else { 0 };
        let directory_count = count_at.map_or(0, field);
        let mut directories = Vec::new();
        if let Some(first) = count_at.map(|c| c + 4) {
            for i in 0..(directory_count as usize).min(MAX_DIRECTORIES) {
                let at = first + i * 8;
                let (Some(address), Some(size)) = (le32(&opt, at), le32(&opt, at + 4)) else {
                    break;
                };
                directories.push(DataDirectory { address, size });
            }
        }
        let table = window(
            optional_at.checked_add(optional)?,
            usize::from(section_count) * SECTION,
        );
        let sections = table
            .as_chunks::<SECTION>()
            .0
            .iter()
            .filter_map(Section::parse)
            .collect();
        Some(Headers {
            machine,
            section_count,
            magic,
            entry_point: field(16),
            section_alignment: known(32),
            file_alignment: known(36),
            size_of_headers: known(60),
            directory_count,
            directories,
            sections,
        })
    }

    /// The index of the first section that holds `rva` in memory.
    pub fn section_index(&self, rva: u32) -> Option<usize> {
        self.sections.iter().position(|s| s.holds(rva))
    }

    /// Where in the file the address `rva` is: the first section that maps
    /// it, as [`Section::offset_of`] says, else the same offset below the size
    /// of headers. Whether the offset is inside the file is the caller's
    /// check.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        self.sections
            .iter()
            .find_map(|s| s.offset_of(rva))
            .or((rva < self.size_of_headers).then_some(rva as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ByteSource;

    fn put(v: &mut [u8], at: usize, bytes: &[u8]) {
        v[at..at + bytes.len()].copy_from_slice(bytes);
    }

    const PE_AT: usize = 0x40;
    const OPT: usize = PE_AT + 24;

    /// A PE32 with the given sections as `(vsize, vaddr, raw size, raw
    /// pointer)` and an optional header of `optional` bytes.
    fn image(optional: usize, sections: &[(u32, u32, u32, u32)]) -> Vec<u8> {
        let mut f = vec![0u8; OPT + optional + sections.len() * SECTION + 0x20];
        put(&mut f, 0, b"MZ");
        put(&mut f, 0x3c, &(PE_AT as u32).to_le_bytes());
        put(&mut f, PE_AT, b"PE\0\0");
        put(&mut f, PE_AT + 4, &0x14cu16.to_le_bytes());
        put(&mut f, PE_AT + 6, &(sections.len() as u16).to_le_bytes());
        put(&mut f, PE_AT + 20, &(optional as u16).to_le_bytes());
        if optional >= 2 {
            put(&mut f, OPT, &PE32.to_le_bytes());
        }
        for (i, (vsize, vaddr, raw_size, raw)) in sections.iter().enumerate() {
            let s = OPT + optional + i * SECTION;
            put(&mut f, s, b".text");
            put(&mut f, s + 8, &vsize.to_le_bytes());
            put(&mut f, s + 12, &vaddr.to_le_bytes());
            put(&mut f, s + 16, &raw_size.to_le_bytes());
            put(&mut f, s + 20, &raw.to_le_bytes());
        }
        f
    }

    fn read(f: &[u8]) -> Option<Headers> {
        Headers::read(&|off, len| ByteSource::window(f, off, len))
    }

    #[test]
    fn the_fields_are_read() {
        let mut f = image(0xe0, &[(0x300, 0x1000, 0x200, 0x400)]);
        put(&mut f, OPT + 16, &0x1234u32.to_le_bytes());
        put(&mut f, OPT + 32, &0x1000u32.to_le_bytes());
        put(&mut f, OPT + 36, &0x200u32.to_le_bytes());
        put(&mut f, OPT + 60, &0x400u32.to_le_bytes());
        put(&mut f, OPT + 92, &16u32.to_le_bytes());
        put(&mut f, OPT + 96 + 8, &0x5000u32.to_le_bytes());
        put(&mut f, OPT + 96 + 12, &0x77u32.to_le_bytes());
        let h = read(&f).unwrap();
        assert_eq!((h.machine, h.section_count, h.magic), (0x14c, 1, PE32));
        assert_eq!(h.entry_point, 0x1234);
        assert_eq!(
            (h.section_alignment, h.file_alignment, h.size_of_headers),
            (0x1000, 0x200, 0x400)
        );
        assert_eq!(h.directory_count, 16);
        assert_eq!(h.directories.len(), 16);
        assert_eq!(
            h.directories[1],
            DataDirectory {
                address: 0x5000,
                size: 0x77
            }
        );
        let s = &h.sections[0];
        assert_eq!(&s.name, b".text\0\0\0");
        assert_eq!(
            (s.virtual_size, s.virtual_address, s.raw_size, s.raw_pointer),
            (0x300, 0x1000, 0x200, 0x400)
        );
    }

    #[test]
    fn a_pe32_plus_has_its_directories_after_the_count_at_108() {
        let mut f = image(0xf0, &[]);
        put(&mut f, OPT, &PE32_PLUS.to_le_bytes());
        put(&mut f, OPT + 92, &16u32.to_le_bytes());
        put(&mut f, OPT + 108, &2u32.to_le_bytes());
        put(&mut f, OPT + 112 + 8, &0x5000u32.to_le_bytes());
        let h = read(&f).unwrap();
        assert_eq!(h.directory_count, 2);
        assert_eq!(h.directories.len(), 2);
        assert_eq!(h.directories[1].address, 0x5000);
    }

    #[test]
    fn what_is_not_an_image_is_none() {
        let ok = image(0xe0, &[(1, 0x1000, 1, 0x400)]);
        assert!(read(&ok).is_some());
        let mut f = ok.clone();
        f[1] = b'Y';
        assert!(read(&f).is_none());
        let mut f = ok.clone();
        f[PE_AT + 2] = 1;
        assert!(read(&f).is_none());
        let mut f = ok.clone();
        put(&mut f, 0x3c, &u32::MAX.to_le_bytes());
        assert!(read(&f).is_none());
        // No optional header, so no magic.
        assert!(read(&image(0, &[])).is_none());
        assert!(read(&[]).is_none());
        assert!(read(b"MZ").is_none());
    }

    /// Whatever the magic is, the caller decides; the directories are
    /// only those of a magic with a known layout.
    #[test]
    fn another_magic_is_reported_with_no_directories() {
        let mut f = image(0xe0, &[]);
        put(&mut f, OPT, &0x107u16.to_le_bytes());
        put(&mut f, OPT + 16, &0x99u32.to_le_bytes());
        put(&mut f, OPT + 36, &0x200u32.to_le_bytes());
        put(&mut f, OPT + 92, &16u32.to_le_bytes());
        let h = read(&f).unwrap();
        assert_eq!(h.magic, 0x107);
        assert_eq!(h.entry_point, 0x99);
        assert_eq!((h.file_alignment, h.directory_count), (0, 0));
        assert!(h.directories.is_empty());
    }

    /// A field is read only from inside the optional header; the bytes
    /// after it are the section table.
    #[test]
    fn the_optional_header_bounds_what_is_read() {
        let mut f = image(0x60, &[(0x10, 0x1000, 0x10, 0x400)]);
        put(&mut f, OPT + 16, &7u32.to_le_bytes());
        put(&mut f, OPT + 92, &16u32.to_le_bytes());
        let h = read(&f).unwrap();
        assert_eq!(h.entry_point, 7);
        assert_eq!(h.directory_count, 16);
        assert!(h.directories.is_empty());
        assert_eq!(h.sections.len(), 1);

        // An optional header that ends inside a field.
        let f = image(0x12, &[]);
        let h = read(&f).unwrap();
        assert_eq!(h.entry_point, 0);

        // Entries are only those that lie wholly inside.
        let mut f = image(96 + 20, &[]);
        put(&mut f, OPT + 92, &16u32.to_le_bytes());
        assert_eq!(read(&f).unwrap().directories.len(), 2);
    }

    #[test]
    fn a_directory_count_beyond_16_gives_16_entries() {
        let mut f = image(0x100, &[]);
        put(&mut f, OPT + 92, &u32::MAX.to_le_bytes());
        let h = read(&f).unwrap();
        assert_eq!(h.directory_count, u32::MAX);
        assert_eq!(h.directories.len(), 16);
    }

    /// The count is the file's; the sections are those that are there.
    #[test]
    fn a_section_table_cut_by_the_end_of_the_file_has_fewer_sections() {
        let mut f = image(0xe0, &[(1, 0x1000, 1, 0x400), (1, 0x2000, 1, 0x400)]);
        f.truncate(OPT + 0xe0 + SECTION + 10);
        let h = read(&f).unwrap();
        assert_eq!(h.section_count, 2);
        assert_eq!(h.sections.len(), 1);
    }

    /// There is no section count bound: a caller that wants one checks it.
    #[test]
    fn the_section_count_is_not_bounded() {
        let sections = vec![(1, 0x1000, 1, 0x400); 200];
        let h = read(&image(0xe0, &sections)).unwrap();
        assert_eq!(h.sections.len(), 200);
        assert!(read(&image(0xe0, &[])).unwrap().sections.is_empty());
    }

    #[test]
    fn an_rva_maps_inside_the_page_of_the_virtual_size_and_the_raw_size() {
        let h = read(&image(0xe0, &[(0x100, 0x1000, 0x200, 0x400)])).unwrap();
        assert_eq!(h.rva_to_offset(0x1000), Some(0x400));
        assert_eq!(h.rva_to_offset(0x10ff), Some(0x4ff));
        // Past the virtual size, in its page and in the raw data.
        assert_eq!(h.rva_to_offset(0x1100), Some(0x500));
        assert_eq!(h.rva_to_offset(0x11ff), Some(0x5ff));
        // Past the raw data, in the page: zeros in memory.
        assert_eq!(h.rva_to_offset(0x1200), None);
        assert_eq!(h.rva_to_offset(0xfff), None);
        assert_eq!(h.section_index(0x1200), Some(0));
        assert_eq!(h.section_index(0x1fff), Some(0));
        assert_eq!(h.section_index(0x2000), None);

        // Raw data past the page is not in the section.
        let h = read(&image(0xe0, &[(0x100, 0x1000, 0x2000, 0x400)])).unwrap();
        assert_eq!(h.rva_to_offset(0x1fff), Some(0x13ff));
        assert_eq!(h.rva_to_offset(0x2000), None);
        assert_eq!(h.section_index(0x2000), None);

        // Past the raw data, inside the virtual size.
        let h = read(&image(0xe0, &[(0x1800, 0x1000, 0x200, 0x400)])).unwrap();
        assert_eq!(h.rva_to_offset(0x11ff), Some(0x5ff));
        assert_eq!(h.rva_to_offset(0x1200), None);
        assert_eq!(h.section_index(0x27ff), Some(0));
        assert_eq!(h.section_index(0x3000), None);
    }

    #[test]
    fn an_address_below_the_size_of_headers_is_the_same_offset() {
        let mut f = image(0xe0, &[(0x100, 0x1000, 0x200, 0x400)]);
        put(&mut f, OPT + 60, &0x400u32.to_le_bytes());
        let h = read(&f).unwrap();
        assert_eq!(h.rva_to_offset(0), Some(0));
        assert_eq!(h.rva_to_offset(0x3ff), Some(0x3ff));
        // The size of headers is the first address that is not theirs, and
        // the gap up to the first section maps nothing.
        assert_eq!(h.rva_to_offset(0x400), None);
        assert_eq!(h.rva_to_offset(0x1000), Some(0x400));
        // The headers are not a section.
        assert_eq!(h.section_index(0x10), None);

        // No size of headers: no header region.
        put(&mut f, OPT + 60, &0u32.to_le_bytes());
        assert_eq!(read(&f).unwrap().rva_to_offset(0x10), None);
        // Nor for a magic whose layout is not known.
        put(&mut f, OPT + 60, &0x400u32.to_le_bytes());
        put(&mut f, OPT, &0x107u16.to_le_bytes());
        assert_eq!(read(&f).unwrap().rva_to_offset(0x10), None);
    }

    /// A section is mapped over the headers: where one starts inside them,
    /// its answer stands, and the headers answer below it.
    #[test]
    fn a_section_inside_the_headers_is_answered_before_them() {
        let mut f = image(0xe0, &[(0x200, 0x300, 0x200, 0x800)]);
        put(&mut f, OPT + 60, &0x400u32.to_le_bytes());
        let h = read(&f).unwrap();
        assert_eq!(h.rva_to_offset(0x310), Some(0x810));
        assert_eq!(h.rva_to_offset(0x2f0), Some(0x2f0));
        assert_eq!(h.rva_to_offset(0x400), Some(0x900));
    }

    #[test]
    fn a_section_with_no_virtual_size_is_as_long_as_its_raw_data() {
        let h = read(&image(0xe0, &[(0, 0x1000, 0x200, 0x400)])).unwrap();
        assert_eq!(h.rva_to_offset(0x11ff), Some(0x5ff));
        assert_eq!(h.rva_to_offset(0x1200), None);
        assert_eq!(h.section_index(0x1200), Some(0));
        assert_eq!(h.section_index(0x2000), None);
        // Neither: nothing is in it.
        let h = read(&image(0xe0, &[(0, 0x1000, 0, 0x400)])).unwrap();
        assert_eq!(h.rva_to_offset(0x1000), None);
        assert_eq!(h.section_index(0x1000), None);
    }

    #[test]
    fn the_first_section_that_maps_the_address_wins() {
        let h = read(&image(
            0xe0,
            &[(0x100, 0x1000, 0, 0x400), (0x100, 0x1000, 0x100, 0x800)],
        ))
        .unwrap();
        assert_eq!(h.section_index(0x1000), Some(0));
        assert_eq!(h.rva_to_offset(0x1010), Some(0x810));
    }

    /// Offsets sum two `u32` fields: that must not wrap on a 32-bit target.
    #[test]
    fn extreme_values_do_not_overflow() {
        let h = read(&image(
            0xe0,
            &[
                (u32::MAX, 0, u32::MAX, u32::MAX),
                (u32::MAX, u32::MAX, 1, 1),
            ],
        ))
        .unwrap();
        assert_eq!(h.rva_to_offset(0), usize::try_from(u32::MAX).ok());
        let wraps = (u32::MAX as usize).checked_add(5).is_none();
        assert_eq!(h.rva_to_offset(5).is_none(), wraps);
        assert_eq!(h.rva_to_offset(u32::MAX), Some(1));
        let mut f = image(0xe0, &[]);
        put(&mut f, PE_AT + 20, &u16::MAX.to_le_bytes());
        assert!(read(&f).is_some());
        // The PE header at the top of the address space.
        let mut f = image(0xe0, &[]);
        put(&mut f, 0x3c, &(u32::MAX - 3).to_le_bytes());
        assert!(read(&f).is_none());
    }
}
