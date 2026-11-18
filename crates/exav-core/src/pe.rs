//! PE structural analysis: per-section entropy, packer/high-entropy
//! detection, suspicious-import heuristics, and imphash. It parses the PE in
//! memory: the whole object when it is within the object size limit,
//! else its image ([`image_in`]), which is all the structure there is.

use std::borrow::Cow;

use md5::{Digest, Md5};

use crate::byte_source::ByteSource;
use crate::hexsig::encode_hex;

mod exports;
mod ordinals;

pub(crate) use exports::Export;

/// A PE's headers and section table, read without its data directories.
///
/// What signatures, section hashes, icons and bytecode read, and bounded: the
/// section headers must fit in the file. A full parse also walks imports,
/// exports, resources and the certificate table, and refuses the whole file
/// over one malformed entry in any of them (a certificate table sized past
/// the end of the file, say); its permissive mode instead keeps going through
/// them, and a malformed import table took it to gigabytes.
pub(crate) struct Headers<'a> {
    pub header: goblin::pe::header::Header<'a>,
    pub sections: Vec<goblin::pe::section_table::SectionTable>,
}

/// [`Headers`] of `data`, `None` if they do not parse.
///
/// goblin refuses a PE whose header starts before the end of the DOS header
/// (`e_lfanew` under 0x40), which some packers lay out and Windows loads. No
/// check reads the DOS stub, so the header is read without it then.
pub(crate) fn headers(data: &[u8]) -> Option<Headers<'_>> {
    use goblin::pe::header::{DosHeader, Header, SIZEOF_COFF_HEADER, SIZEOF_PE_MAGIC};
    let header = Header::parse(data).ok().or_else(|| {
        let dos = DosHeader::parse(data).ok()?;
        let mut header = Header::parse_without_dos(data.get(dos.pe_pointer as usize..)?).ok()?;
        header.dos_header = dos;
        Some(header)
    })?;
    let mut at = (header.dos_header.pe_pointer as usize)
        .checked_add(SIZEOF_PE_MAGIC + SIZEOF_COFF_HEADER)?
        .checked_add(usize::from(header.coff_header.size_of_optional_header))?;
    let coff = header.coff_header;
    let (pointer, count) = (coff.pointer_to_symbol_table, coff.number_of_symbol_table);
    // A table goblin could not add up is left out, as it was for goblin.
    let strings = if symbol_table_fits(pointer, count, usize::MAX as u64) {
        pointer as usize + 18 * count as usize
    } else {
        0
    };
    let sections = section_table(data, &mut at, usize::from(coff.number_of_sections), strings)?;
    Some(Headers { header, sections })
}

/// The section headers at `at`, `count` of them, as goblin reads them, the
/// COFF string table that holds their long names at `strings`. Each long name
/// is read once, however many headers name it, and the long names read in all
/// stop at the size of the file: a header past that keeps its short form, as
/// one whose name does not read does.
fn section_table(
    data: &[u8],
    at: &mut usize,
    count: usize,
    strings: usize,
) -> Option<Vec<goblin::pe::section_table::SectionTable>> {
    use goblin::pe::section_table::SectionTable;
    if count > data.len() / 40 {
        return None;
    }
    let mut names: std::collections::HashMap<usize, Option<String>> = Default::default();
    let mut left = data.len();
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let h = data.get(*at..)?.first_chunk::<40>()?;
        *at += 40;
        let word = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
        let half = |i: usize| u16::from_le_bytes([h[i], h[i + 1]]);
        let mut s = SectionTable {
            name: *h.first_chunk::<8>()?,
            virtual_size: word(8),
            virtual_address: word(12),
            size_of_raw_data: word(16),
            pointer_to_raw_data: word(20),
            pointer_to_relocations: word(24),
            pointer_to_linenumbers: word(28),
            number_of_relocations: half(32),
            number_of_linenumbers: half(34),
            characteristics: word(36),
            ..Default::default()
        };
        if let Some(index) = long_name_index(&s.name).ok()? {
            s.real_name = match names.get(&index) {
                Some(name) => name.clone(),
                None => {
                    let name = match strings.checked_add(index).and_then(|o| data.get(o..)) {
                        None => None,
                        Some(rest) => {
                            let end = rest.iter().take(left).position(|&b| b == 0);
                            match end.or((rest.len() <= left).then_some(rest.len())) {
                                Some(len) => {
                                    left -= len;
                                    std::str::from_utf8(&rest[..len]).ok().map(String::from)
                                }
                                // Past the size of the file: no more is read.
                                None => {
                                    left = 0;
                                    None
                                }
                            }
                        }
                    };
                    names.insert(index, name.clone());
                    name
                }
            };
        }
        out.push(s);
    }
    Some(out)
}

/// Where a long section name (`/` and its offset, or `//` and its offset in
/// base 64) is in the string table, as goblin reads it; `Err` for a name that
/// says it is one and is not.
fn long_name_index(name: &[u8; 8]) -> Result<Option<usize>, ()> {
    if name[0] != b'/' {
        return Ok(None);
    }
    let text = |from: usize| {
        let rest = &name[from..];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        std::str::from_utf8(&rest[..end]).map_err(|_| ())
    };
    if name[1] != b'/' {
        return text(1)?.parse().map(Some).map_err(|_| ());
    }
    let mut index = 0usize;
    for c in text(2)?.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(()),
        };
        index = index * 64 + usize::from(v);
    }
    Ok(Some(index))
}

/// Whether goblin can add the end of the symbol table to an index, to find the
/// string table that holds the long names of sections, without a sum passing
/// `limit`, the largest `usize`: it adds in `usize`, which a table that ends
/// near 4 GiB overflows on a 32-bit target, and that aborts the process. A
/// table it cannot add is left out, and the long names of sections with it.
fn symbol_table_fits(pointer: u32, count: u32, limit: u64) -> bool {
    // A long name is `/` and at most seven digits.
    let end = u64::from(pointer) + 18 * u64::from(count);
    end + 10_000_000 <= limit
}

/// Why a table of a PE could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unread {
    /// It does not parse: something it points to maps to no section or runs
    /// off the object.
    Malformed,
    /// Parsing it would take more memory than the caller allows.
    TooLarge,
}

/// The headers of a PE with its import and export tables, each parsed on its
/// own: the checks that read a PE's tables (imports, exports) need no more.
///
/// A full parse of the PE also walks the debug, resource, TLS, exception,
/// relocation, load configuration and CLR directories, and refuses the whole
/// file over one malformed entry in any of them, imports included (a debug
/// directory that points outside every section, which Windows ignores, is
/// enough). Here only a fault in a table is reported, and only for that table.
/// goblin's permissive mode is not used: it reads on through a fault in a
/// table, and would give the import hash of part of it.
///
/// The exports are read only when asked for ([`Tables::exports`]), by
/// [`exports::read_exports`]. The imports are read by [`read_imports`],
/// which goblin's reader cannot be made to do: it stops at a descriptor with no
/// address table, needs the address table to map when the lookup table does,
/// and refuses a name that is not UTF-8, where the references read the file on.
///
/// clamscan and yara-x do not map an RVA to the file the same way, so the
/// import table is read as clamscan reads it (`imports`, what `.imp` signatures
/// hash) and as libyara and yara-x read it ([`Tables::listed`], what the `pe`
/// module and `pe.imphash()` list). It is one reading, with each RVA looked up
/// both ways, as long as the two agree on every RVA the reading looks up, which
/// they do for an ordinary PE. If they differ, the table is read again with
/// yara-x's mapping, within what the first reading left of `room`.
pub(crate) struct Tables<'a> {
    pub header: goblin::pe::header::Header<'a>,
    pub sections: Vec<goblin::pe::section_table::SectionTable>,
    pub is_64: bool,
    /// Empty when the PE has no import table.
    pub imports: Result<Imports<'a>, Unread>,
    /// The reading with yara-x's mapping, when it is not `imports`.
    listed_apart: Option<Result<Imports<'a>, Unread>>,
    /// What [`Tables::exports`] needs: the export data directory, and the
    /// sections and file alignment that map its RVAs.
    export_dir: Option<goblin::pe::data_directories::DataDirectory>,
    map: Vec<goblin::pe::section_table::SectionTable>,
    file_alignment: u32,
}

impl<'a> Tables<'a> {
    /// The functions the export table lists, empty when the PE has none.
    /// `data` is the bytes the tables were read from. The table may take
    /// `room` bytes of memory to read; one that would take more is
    /// [`Unread::TooLarge`].
    pub(crate) fn exports(&self, data: &'a [u8], room: usize) -> Result<Vec<Export<'a>>, Unread> {
        match self.export_dir {
            Some(dir) => exports::read_exports(data, dir, &self.map, self.file_alignment, room),
            None => Ok(Vec::new()),
        }
    }

    /// The import table as libyara and yara-x read it.
    pub(crate) fn listed(&self) -> &Result<Imports<'a>, Unread> {
        self.listed_apart.as_ref().unwrap_or(&self.imports)
    }

    /// The memory the readings of the import table hold, as they count it.
    fn held(&self) -> usize {
        let spent = |read: &Result<Imports<'_>, Unread>| read.as_ref().map_or(0, |read| read.spent);
        spent(&self.imports).saturating_add(self.listed_apart.as_ref().map_or(0, spent))
    }
}

/// The import table of a PE as the file holds it. What a check makes of it is
/// the check's own: clamscan and yara-x read the same table and list
/// different things from it (see [`Imports::clamscan_hash`] and
/// [`Imports::listed`]).
#[derive(Default)]
pub(crate) struct Imports<'a> {
    /// The size the import data directory says the descriptors take.
    pub dir_size: u32,
    /// The file offset where the directory, so sized, ends.
    pub dir_end: u64,
    /// Every descriptor before the null one that could be read, including
    /// those that import nothing.
    pub libraries: Vec<Library<'a>>,
    /// Whether a descriptor that the size of the directory leaves room for
    /// could not be read, and is not in `libraries`. What is in them is read;
    /// the table as a whole is not.
    pub fault: bool,
    /// Whether the directory starts at or past the end of the bytes read, so
    /// that no descriptor could be.
    pub past_end: bool,
    /// The memory the libraries and their functions take, as [`LIBRARY_COST`]
    /// and [`FUNCTION_COST`] count it.
    pub spent: usize,
}

/// A descriptor of the import table and what its thunks name.
pub(crate) struct Library<'a> {
    /// Where its descriptor is in the directory, from 0.
    pub index: usize,
    /// Its name, up to [`MAX_LIBRARY_NAME`] bytes: one that long is not
    /// finished.
    pub name: &'a [u8],
    /// Whether the descriptor has neither a lookup table nor an address table.
    /// clamscan hashes such a library as one function it cannot read; yara-x
    /// ends the table there.
    pub tableless: bool,
    pub functions: Vec<Function<'a>>,
}

/// An entry of a thunk table.
pub(crate) enum Function<'a> {
    /// A hint/name entry: the name, up to [`MAX_FUNCTION_NAME`] bytes, and
    /// the offset in the object of the entry.
    Named { name: &'a [u8], at: usize },
    /// An import by ordinal: the low 16 bits of the thunk, and whether other
    /// bits of it below the flag are set.
    Ordinal { number: u16, high_bits: bool },
    /// A thunk that names nothing that can be read: an entry which maps to no
    /// section or to a place the object does not reach, or a descriptor with
    /// no table.
    Unread,
}

/// The most bytes read of a library's name, and of a function's: yara-x's
/// limits. The checks that cut shorter do so themselves.
const MAX_LIBRARY_NAME: usize = 512;
const MAX_FUNCTION_NAME: usize = 1024;

/// Estimates of the memory a parse of the tables makes, in bytes, to charge
/// against what the caller allows: a library of the import table, a function
/// it lists, an export (and its entries in the three tables that list it).
const LIBRARY_COST: usize = size_of::<Library<'static>>();
const FUNCTION_COST: usize = size_of::<Function<'static>>();
const EXPORT_COST: usize = 128;

/// How far the headers map: an RVA below the value returned that no section
/// holds is the file offset of the same value. Packers keep import names and
/// entries there (WinUpack, in the DOS header); goblin does not map them.
///
/// Windows maps `SizeOfHeaders` bytes, clamscan that rounded up to the section
/// alignment, libyara and yara-x everything below the lowest section. The
/// smaller of the last two is used for the clamscan reading of the imports;
/// the yara-x reading maps all of it ([`yarax_offset`]).
fn header_end(
    opt: &goblin::pe::optional_header::OptionalHeader,
    sections: &[goblin::pe::section_table::SectionTable],
) -> u32 {
    let of_headers = u64::from(opt.windows_fields.size_of_headers);
    let alignment = u64::from(opt.windows_fields.section_alignment);
    let rounded = if alignment.is_power_of_two() {
        of_headers.next_multiple_of(alignment)
    } else {
        of_headers
    };
    let lowest = sections.iter().map(|s| u64::from(s.virtual_address)).min();
    u32::try_from(lowest.map_or(rounded, |lowest| rounded.min(lowest))).unwrap_or(u32::MAX)
}

/// The sections the readers of the tables resolve an RVA through: those of
/// the PE, then one for its headers (see [`header_end`]). It is not the list
/// of the PE's sections, which [`Tables`] keeps. It places the data as clamscan
/// does (see [`data_start`]); [`yarax_offset`] is yara-x's own. A section that
/// goblin cannot use without overflowing is left out (see [`goblin_can_map`]).
/// `goblin_alignment` is the file alignment as goblin takes it.
///
/// The section for the headers starts at RVA 1, as RVA 0 is the absent table
/// (a lookup table at 0 is read from the address table). goblin sizes a
/// section in whole file alignments, so it can hold a few RVAs past
/// `header_end`.
fn rva_map(
    opt: &goblin::pe::optional_header::OptionalHeader,
    sections: &[goblin::pe::section_table::SectionTable],
    goblin_alignment: u32,
) -> Vec<goblin::pe::section_table::SectionTable> {
    let mut map: Vec<_> = sections
        .iter()
        .map(|s| goblin::pe::section_table::SectionTable {
            pointer_to_raw_data: data_start(s.pointer_to_raw_data, opt.windows_fields.file_alignment),
            ..s.clone()
        })
        .filter(|s| goblin_can_map(s, goblin_alignment, usize::MAX as u64))
        .collect();
    let end = header_end(opt, sections);
    if end > 1 {
        map.push(goblin::pe::section_table::SectionTable {
            virtual_address: 1,
            pointer_to_raw_data: 1,
            size_of_raw_data: end - 1,
            ..Default::default()
        });
    }
    map
}

/// Whether goblin can use `section` to map an RVA without a sum of its
/// overflowing `usize`, which is `limit` at most: goblin adds the pointer, the
/// sizes, the alignment and the RVA in `usize`, which a section laid out near
/// 4 GiB overflows on a 32-bit target, and that aborts the process. A section
/// that goblin cannot map is not mapped: the file does not reach it.
fn goblin_can_map(
    section: &goblin::pe::section_table::SectionTable,
    file_alignment: u32,
    limit: u64,
) -> bool {
    // The most goblin takes of a section: its sizes rounded up to a page.
    let size = u64::from(section.virtual_size.max(section.size_of_raw_data)) + 0xfff;
    let sums = [
        u64::from(section.pointer_to_raw_data) + u64::from(section.size_of_raw_data) + u64::from(file_alignment),
        u64::from(section.virtual_address) + size,
        u64::from(section.pointer_to_raw_data) + size,
    ];
    sums.iter().all(|&sum| sum <= limit)
}

/// [`Tables`] of the PE in `data`, `None` if its headers do not parse. Each
/// table may take `room` bytes of memory to parse (the two readings of the
/// imports, `room` between them); one that would take more is
/// [`Unread::TooLarge`].
pub(crate) fn tables(data: &[u8], room: usize) -> Option<Tables<'_>> {
    use goblin::pe::optional_header::MAGIC_64;
    let Headers { header, sections } = headers(data)?;
    let mut tables = Tables {
        header,
        sections,
        is_64: false,
        imports: Ok(Imports::default()),
        listed_apart: None,
        export_dir: None,
        map: Vec::new(),
        file_alignment: 0,
    };
    let Some(opt) = tables.header.optional_header.as_ref() else {
        return Some(tables);
    };
    // goblin maps no RVA at all if the file alignment is 0 or not a power of
    // two, which no loader accepts; clamscan maps as for 0x200 (where the data
    // of a section starts is [`data_start`]'s).
    let file_alignment = Some(opt.windows_fields.file_alignment)
        .filter(|alignment| alignment.is_power_of_two())
        .unwrap_or(0x200);
    let is_64 = opt.standard_fields.magic == MAGIC_64;
    let map = rva_map(opt, &tables.sections, file_alignment);
    if let Some(&dir) = opt.data_directories.get_import_table() {
        let opts = goblin::pe::options::ParseOptions::default();
        let by_clamscan =
            |rva: u32| goblin::pe::utils::find_offset(rva as usize, &map, file_alignment, &opts);
        let (file_alignment, section_alignment) =
            (opt.windows_fields.file_alignment, opt.windows_fields.section_alignment);
        let by_yarax = |rva: u32| {
            yarax_offset(rva, &tables.sections, file_alignment, section_alignment)
                .and_then(|at| usize::try_from(at).ok())
        };
        // Both mappings answer each lookup of the first reading, and say if
        // they ever differ.
        let apart = std::cell::Cell::new(false);
        let both = |rva: u32| {
            let at = by_clamscan(rva);
            apart.set(apart.get() || at != by_yarax(rva));
            at
        };
        tables.imports = read_imports(data, dir, &both, is_64, room);
        // yara-x has no imports for a directory at RVA 0.
        if apart.get() || dir.virtual_address == 0 {
            let room = match &tables.imports {
                Ok(read) => room.saturating_sub(read.spent),
                Err(_) => room,
            };
            tables.listed_apart = Some(if dir.virtual_address == 0 {
                Ok(Imports::default())
            } else {
                read_imports(data, dir, &by_yarax, is_64, room)
            });
        }
    }
    tables.export_dir = opt.data_directories.get_export_table().copied();
    tables.map = map;
    tables.file_alignment = file_alignment;
    tables.is_64 = is_64;
    Some(tables)
}

/// The import table of the PE: its descriptors up to the first that names no
/// library, and what the thunks of each name.
///
/// Read as clamscan, libyara and yara-x all read it:
/// - the end is a descriptor with no name; one with no address table does not
///   end it, and neither does one with no lookup table or whose lookup table
///   maps nowhere (the address table is read then);
/// - the address table need not map when the lookup table does;
/// - a table of thunks ends at a null thunk or at the end of the object;
/// - a thunk that names an entry which maps nowhere, or to the end of the
///   object or past it, is kept as [`Function::Unread`]: clamscan hashes it,
///   libyara and yara-x do not list it;
/// - a name is read as the bytes the file holds, whatever they are.
///
/// A directory that maps nowhere is [`Unread::Malformed`], as before. In a
/// descriptor that the size of the directory leaves room for (the null one
/// apart), a library name or tables that map nowhere leave the descriptor out
/// and set [`Imports::fault`]: what the other descriptors list is read, and
/// the table as a whole is not. The same fault in a descriptor past that size
/// is skipped without a trace, as libyara skips it and clamscan does not read
/// it (a packer that sizes the directory for its one descriptor leaves other
/// bytes after it).
///
/// `offset` maps an RVA to a file offset, which the references do not all do
/// the same way: see [`Tables`].
///
/// Every descriptor lists a thunk table, and any number of descriptors can
/// point at the same long one, so a table of a few kilobytes comes to
/// gigabytes. The table is walked twice. The first walk counts the memory the
/// second would keep, and stops with [`Unread::TooLarge`] when it passes `room`,
/// before anything is allocated; the second keeps it, in vectors of the sizes
/// counted.
fn read_imports<'a>(
    data: &'a [u8],
    dir: goblin::pe::data_directories::DataDirectory,
    offset: &dyn Fn(u32) -> Option<usize>,
    is_64: bool,
    room: usize,
) -> Result<Imports<'a>, Unread> {
    let at = offset(dir.virtual_address).ok_or(Unread::Malformed)?;
    let walk = Walk { data, at, dir_size: dir.size, offset, is_64, room };
    let counted = walk.over(None)?;
    let mut imports = Imports {
        dir_size: dir.size,
        dir_end: u64::try_from(at).unwrap_or(u64::MAX).saturating_add(u64::from(dir.size)),
        libraries: Vec::with_capacity(counted.libraries),
        fault: false,
        past_end: at >= data.len(),
        spent: counted.spent,
    };
    walk.over(Some(&mut imports))?;
    Ok(imports)
}

/// What a pass over the descriptors counted.
struct Counted {
    libraries: usize,
    spent: usize,
}

/// The import descriptors of a table, for [`read_imports`] to pass over.
struct Walk<'d, 'f> {
    data: &'d [u8],
    /// Where the first descriptor is in `data`.
    at: usize,
    /// The size the directory says the descriptors take.
    dir_size: u32,
    offset: &'f dyn Fn(u32) -> Option<usize>,
    is_64: bool,
    room: usize,
}

impl<'d> Walk<'d, '_> {
    /// One pass over the descriptors, counting the memory they take and
    /// stopping when it passes `room`. With `keep`, it also reads the
    /// libraries into it (and whether one was left out), by the same steps: a
    /// table that fits the count is kept whole.
    fn over(&self, mut keep: Option<&mut Imports<'d>>) -> Result<Counted, Unread> {
        const DESCRIPTOR: usize = 20;
        let (mut at, mut spent, mut libraries) = (self.at, 0usize, 0usize);
        let width = if self.is_64 { 8 } else { 4 };
        let mut fault = false;
        for index in 0.. {
            // Whether the descriptor is one of those the size in the header
            // leaves room for, besides the null one that ends them.
            let covered = (index as u64) < u64::from(self.dir_size.saturating_sub(1) / DESCRIPTOR as u32);
            let Some(d) = self.data.get(at..).and_then(|rest| rest.first_chunk::<DESCRIPTOR>()) else {
                fault |= covered;
                break;
            };
            let word = |i: usize| u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
            let (lookup, name, address) = (word(0), word(12), word(16));
            if name == 0 {
                break;
            }
            spent = spent.saturating_add(LIBRARY_COST);
            if spent > self.room {
                return Err(Unread::TooLarge);
            }
            match locate_library(self.data, self.offset, width, (lookup, name, address)) {
                Some(found) => {
                    spent = spent.saturating_add(found.functions(width).saturating_mul(FUNCTION_COST));
                    if spent > self.room {
                        return Err(Unread::TooLarge);
                    }
                    libraries += 1;
                    if let Some(imports) = keep.as_deref_mut() {
                        imports.libraries.push(Library {
                            index,
                            name: found.name,
                            tableless: found.tableless,
                            functions: read_functions(self.data, self.offset, width, &found),
                        });
                    }
                }
                None => fault |= covered,
            }
            at = at.saturating_add(DESCRIPTOR);
        }
        if let Some(imports) = keep {
            imports.fault = fault;
        }
        Ok(Counted { libraries, spent })
    }
}

/// A descriptor's library and where its thunks are.
struct Located<'a> {
    name: &'a [u8],
    /// Whether it has neither a lookup table nor an address table.
    tableless: bool,
    /// The thunks, up to the null one that ends them or the end of the object;
    /// `None` for a library that has one function that cannot be read.
    thunks: Option<&'a [u8]>,
}

impl Located<'_> {
    /// How many functions it lists.
    fn functions(&self, width: usize) -> usize {
        self.thunks.map_or(1, |thunks| thunks.len() / width)
    }
}

/// The library a descriptor names and where its thunks are: the lookup table is
/// read, or the address table when there is no lookup table or it maps
/// nowhere. `None` if the name or both tables map nowhere. A lookup table that
/// maps nowhere with no address table to fall back to is a function that
/// cannot be read, as a descriptor with no table at all is: clamscan hashes
/// both as an empty name.
fn locate_library<'a>(
    data: &'a [u8],
    offset: &dyn Fn(u32) -> Option<usize>,
    width: usize,
    (lookup, name, address): (u32, u32, u32),
) -> Option<Located<'a>> {
    let name = offset(name).and_then(|at| data.get(at..)).filter(|rest| !rest.is_empty())?;
    let name = until_nul(name, MAX_LIBRARY_NAME);
    if lookup == 0 && address == 0 {
        return Some(Located { name, tableless: true, thunks: None });
    }
    let rest = [lookup, address]
        .into_iter()
        .filter(|&rva| rva != 0)
        .find_map(|rva| offset(rva).and_then(|at| data.get(at..)));
    let Some(rest) = rest else {
        return (address == 0).then_some(Located { name, tableless: false, thunks: None });
    };
    let count = rest
        .chunks_exact(width)
        .position(|thunk| thunk.iter().all(|&b| b == 0))
        .unwrap_or(rest.len() / width);
    Some(Located { name, tableless: false, thunks: Some(&rest[..count * width]) })
}

/// The functions a located library's thunks name.
fn read_functions<'a>(
    data: &'a [u8],
    offset: &dyn Fn(u32) -> Option<usize>,
    width: usize,
    found: &Located<'a>,
) -> Vec<Function<'a>> {
    let Some(thunks) = found.thunks else {
        // clamscan hashes the library with a function it cannot read.
        return vec![Function::Unread];
    };
    let flag = 1u64 << (8 * width - 1);
    thunks
        .chunks_exact(width)
        .map(|chunk| {
            let thunk = chunk.iter().rev().fold(0u64, |all, &b| all << 8 | u64::from(b));
            if thunk & flag != 0 {
                return Function::Ordinal {
                    number: thunk as u16,
                    high_bits: thunk & !0xffff != flag,
                };
            }
            match u32::try_from(thunk).ok().and_then(offset).and_then(|at| data.get(at..)) {
                Some(entry) if !entry.is_empty() => Function::Named {
                    name: entry.get(2..).map_or(&[][..], |name| until_nul(name, MAX_FUNCTION_NAME)),
                    at: data.len() - entry.len(),
                },
                _ => Function::Unread,
            }
        })
        .collect()
}

/// Where the data of a section starts in the file, for a pointer in its header
/// and the file alignment of the PE, as clamscan places it (measured on 1.4.3):
/// the pointer as it is if the alignment is 0; rounded down to the alignment if
/// that is a power of two up to 0x400; else rounded down to 0x200. libyara and
/// yara-x round to the smaller of the alignment and 0x200, then to 0x200 when
/// the section alignment is 0x1000 or more (see [`yarax_offset`]).
fn data_start(pointer: u32, file_alignment: u32) -> u32 {
    match file_alignment {
        0 => pointer,
        alignment if alignment.is_power_of_two() && alignment <= 0x400 => pointer & !(alignment - 1),
        _ => pointer & !0x1ff,
    }
}

/// Convert an RVA to a file offset as yara-x does. Ported from yara-x's
/// `pe/rva2off.rs` (libyara 4.5.2 does the same in the cases measured).
pub(crate) fn yarax_offset(
    rva: u32,
    sections: &[goblin::pe::section_table::SectionTable],
    file_alignment: u32,
    section_alignment: u32,
) -> Option<u32> {
    let lowest_section_rva = sections.iter().map(|s| s.virtual_address).min();
    if matches!(lowest_section_rva, Some(x) if rva < x) {
        return Some(rva);
    }

    let mut section_rva = 0;
    let mut section_offset = 0;
    let mut section_raw_size = 0;

    for s in sections {
        let size = s.virtual_size.max(s.size_of_raw_data);
        let start = s.virtual_address;
        let end = start.saturating_add(size);

        if section_rva <= s.virtual_address && (start..end).contains(&rva) {
            section_rva = s.virtual_address;
            section_offset = s.pointer_to_raw_data;
            section_raw_size = s.size_of_raw_data;

            let file_alignment = file_alignment.min(0x200);
            if let Some(rem) = section_offset.checked_rem(file_alignment) {
                section_offset -= rem;
            }
            if section_alignment >= 0x1000 {
                section_offset = section_offset.saturating_sub(section_offset % 0x200);
            }
        }
    }

    if rva.saturating_sub(section_rva) >= section_raw_size {
        return None;
    }
    Some(section_offset.saturating_add(rva - section_rva))
}

/// The bytes of `rest` up to the first NUL, at most `cap` of them.
fn until_nul(rest: &[u8], cap: usize) -> &[u8] {
    let rest = &rest[..rest.len().min(cap)];
    rest.iter().position(|&b| b == 0).map_or(rest, |end| &rest[..end])
}

impl<'a> Library<'a> {
    /// The name yara-x lists the library under, if it lists it: a name that is
    /// UTF-8, has no control character and none of ` "*<>?|` (characters
    /// Windows does not allow in a file name, and the space). It may be empty.
    /// libyara also refuses a name of 256 bytes or more, or with a byte that is
    /// not printable ASCII, and accepts the space.
    pub(crate) fn listed_name(&self) -> Option<&'a str> {
        let name = std::str::from_utf8(self.name).ok()?;
        let refused = |c: char| c.is_ascii_control() || " \"*<>?|".contains(c);
        (!name.chars().any(refused)).then_some(name)
    }
}

impl<'a> Function<'a> {
    /// The name yara-x lists for the function, if it lists one. `library` is
    /// the name the library is listed under.
    ///
    /// An import by ordinal is named from the table of its library, and `ord`
    /// and the ordinal if the library has no table or the ordinal is not in
    /// it. A name is listed if it is not empty and has only the printable ASCII
    /// characters that are not a space. An entry that maps nowhere is not
    /// listed. libyara lists only letters, digits and `._?@$()<>`, and cuts a
    /// name at 512 bytes.
    pub(crate) fn listed_name(&self, library: &str) -> Option<Cow<'a, str>> {
        match *self {
            // yara-x skips a thunk with other bits set below the flag.
            Function::Ordinal { high_bits: true, .. } => None,
            Function::Ordinal { number, .. } => Some(match ordinals::name_exact(library, number) {
                Some(name) => Cow::Borrowed(name),
                None => Cow::Owned(format!("ord{number}")),
            }),
            Function::Named { name, .. } => {
                let valid = !name.is_empty() && name.iter().all(u8::is_ascii_graphic);
                valid.then(|| std::str::from_utf8(name).ok()).flatten().map(Cow::Borrowed)
            }
            Function::Unread => None,
        }
    }
}

/// The most thunks and descriptors yara-x reads, and the number of listed
/// functions it stops after.
const YARAX_MAX_IMPORTS: usize = 16384;

/// An import yara-x lists.
pub(crate) struct Listed<'s, 'a> {
    /// The library it is in.
    pub library: &'s Library<'a>,
    /// The name the library is listed under.
    pub library_name: &'a str,
    pub name: Cow<'a, str>,
    /// Set for an import by ordinal.
    pub ordinal: Option<u16>,
}

/// The imports yara-x lists, in the order of the table: see [`Imports::listed`].
pub(crate) struct Listing<'s, 'a> {
    libraries: std::slice::Iter<'s, Library<'a>>,
    /// The library being read: its listed name, and the thunks left in it.
    current: Option<(&'s Library<'a>, &'a str, std::iter::Take<std::slice::Iter<'s, Function<'a>>>)>,
    /// How many it has listed.
    total: usize,
    /// Whether it ends where yara-x ends the table.
    capped: bool,
}

impl<'s, 'a> Iterator for Listing<'s, 'a> {
    type Item = Listed<'s, 'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((library, library_name, thunks)) = &mut self.current {
                let (library, library_name) = (*library, *library_name);
                for function in thunks.by_ref() {
                    if let Some(name) = function.listed_name(library_name) {
                        self.total += 1;
                        let ordinal = match *function {
                            Function::Ordinal { number, .. } => Some(number),
                            _ => None,
                        };
                        return Some(Listed { library, library_name, name, ordinal });
                    }
                }
                self.current = None;
                // The listing ends with the library that reaches the limit.
                if self.capped && self.total >= YARAX_MAX_IMPORTS {
                    return None;
                }
            }
            let library = self.libraries.next()?;
            // The table ends at a descriptor with neither table, and after
            // the limit of descriptors.
            if self.capped && (library.tableless || library.index >= YARAX_MAX_IMPORTS) {
                return None;
            }
            let Some(name) = library.listed_name() else {
                continue;
            };
            let thunks = if self.capped { YARAX_MAX_IMPORTS } else { usize::MAX };
            self.current = Some((library, name, library.functions.iter().take(thunks)));
        }
    }
}

impl<'a> Imports<'a> {
    /// The imports libyara and yara-x list, which is what the `pe` module
    /// shows and `pe.imphash()` is made of.
    ///
    /// Of the descriptors, those that name a library [`Library::listed_name`]
    /// lists, up to the first that has no table; of the first 16384 thunks of
    /// each, those that [`Function::listed_name`] lists. It stops after the
    /// library that brings the total to 16384, and at the 16384th descriptor
    /// (yara-x's limits; libyara stops at 16384 functions wherever they are).
    pub(crate) fn listed(&self) -> Listing<'_, 'a> {
        Listing { libraries: self.libraries.iter(), current: None, total: 0, capped: true }
    }

    /// [`Imports::listed`] without yara-x's limits and its end at a descriptor
    /// with no table: every function of every library that is listed. The
    /// checks of exav's own (the count of imports, the suspicious ones) look
    /// at all of the table the reader read.
    pub(crate) fn listed_in_full(&self) -> Listing<'_, 'a> {
        Listing { libraries: self.libraries.iter(), current: None, total: 0, capped: false }
    }
}

/// The bytes of the object that follow the start of a hint/name entry, and
/// that clamscan needs there to hash the entry: its hint and 256 of the name.
/// An entry nearer than that to the end of the object is left out of the
/// hash (measured: 257 bytes from the end leaves it out, 258 keeps it).
const CLAMSCAN_ENTRY_WINDOW: usize = 258;
/// The most bytes of a name that clamscan hashes.
const CLAMSCAN_NAME_MAX: usize = 256;

/// `library` without its extension as clamscan cuts it: at the first `.` if
/// what follows starts with `dll`, `sys` or `ocx`, whatever the case. Any
/// other extension, and a `.dll` after another `.`, stays (`ntoskrnl.exe`,
/// `lua5.1.dll`). libyara cuts at the last `.`.
fn clamscan_stem(library: &[u8]) -> &[u8] {
    let Some(dot) = library.iter().position(|&b| b == b'.') else {
        return library;
    };
    let ext = &library[dot + 1..];
    if [b"dll", b"sys", b"ocx"].iter().any(|known| ext.len() >= 3 && ext[..3].eq_ignore_ascii_case(*known)) {
        &library[..dot]
    } else {
        library
    }
}

impl Imports<'_> {
    /// The import hash as clamscan makes it, with the length of the string
    /// hashed: the MD5 of `library.function` for each function of the
    /// libraries it reads, lowercased and joined by commas. `None` if clamscan
    /// makes none. `object_len` is the length of the object that holds the PE.
    ///
    /// Measured on clamscan 1.4.3, where libyara differs:
    /// - it makes none for a directory of size 0 or one that ends past the
    ///   object, nor if a descriptor it reads has a library name or tables
    ///   that map nowhere, nor if a function name has a character other than
    ///   letters, digits, `_` and `.`;
    /// - it reads the descriptors while more than 20 bytes of the directory
    ///   remain, so a directory sized for the descriptors and a null one reads
    ///   them all, and one sized for them alone leaves out the last;
    /// - it hashes a thunk whose entry it cannot read, and a library with no
    ///   table at all, as the empty name, and leaves out an entry that is too
    ///   near the end of the object;
    /// - it hashes no more than 256 bytes of a name, a library's or a
    ///   function's;
    /// - the library's name is cut as [`clamscan_stem`] says, and not checked.
    ///
    /// A library that imports nothing adds nothing, and a table with nothing
    /// to hash is the hash of the empty string, of length 0.
    ///
    /// `room` is the memory the string may take: the bytes added are taken from
    /// it, and `Cut::Names` is the answer when it runs out.
    pub(crate) fn clamscan_hash(
        &self,
        object_len: usize,
        room: &mut usize,
    ) -> Result<Option<(String, usize)>, Cut> {
        if self.dir_size == 0 || self.dir_end > object_len as u64 || self.fault {
            return Ok(None);
        }
        let read = u64::from((self.dir_size - 1) / 20);
        let mut hashed: Vec<u8> = Vec::new();
        for library in self.libraries.iter().filter(|l| (l.index as u64) < read) {
            let library_name = &library.name[..library.name.len().min(CLAMSCAN_NAME_MAX)];
            let stem = clamscan_stem(library_name);
            for function in &library.functions {
                let name: Cow<[u8]> = match *function {
                    Function::Ordinal { number, .. } => match ordinals::name_by_prefix(library_name, number) {
                        Some(name) => Cow::Borrowed(name.as_bytes()),
                        None => Cow::Owned(format!("ord{number}").into_bytes()),
                    },
                    Function::Named { name, at } => {
                        if object_len.saturating_sub(at) < CLAMSCAN_ENTRY_WINDOW {
                            continue;
                        }
                        let name = &name[..name.len().min(CLAMSCAN_NAME_MAX)];
                        if !name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.') {
                            return Ok(None);
                        }
                        Cow::Borrowed(name)
                    }
                    Function::Unread => Cow::Borrowed(&[]),
                };
                let cost = stem.len() + name.len() + 2;
                *room = room.checked_sub(cost).ok_or(Cut::Names)?;
                if !hashed.is_empty() {
                    hashed.push(b',');
                }
                hashed.extend(stem.iter().map(u8::to_ascii_lowercase));
                hashed.push(b'.');
                hashed.extend(name.iter().map(u8::to_ascii_lowercase));
            }
        }
        Ok(Some((encode_hex(&Md5::digest(&hashed)), hashed.len())))
    }
}

/// Where the section table of the PE in `src` ends, going by its COFF header:
/// its headers are the bytes before. `None` if `src` is not a PE, or the table
/// runs past the end of it.
pub(crate) fn headers_end(src: &dyn ByteSource) -> Option<usize> {
    let dos = src.window(0, 0x40);
    if dos.len() < 0x40 || !dos.starts_with(b"MZ") {
        return None;
    }
    let lfanew = u32::from_le_bytes([dos[0x3c], dos[0x3d], dos[0x3e], dos[0x3f]]);
    let coff = src.window(usize::try_from(lfanew).ok()?, 24);
    if coff.len() < 24 || coff[..4] != *b"PE\0\0" {
        return None;
    }
    let sections = u64::from(u16::from_le_bytes([coff[6], coff[7]]));
    let optional = u64::from(u16::from_le_bytes([coff[20], coff[21]]));
    let end = u64::from(lfanew) + 24 + optional + 40 * sections;
    usize::try_from(end).ok().filter(|&end| end <= src.len())
}

/// How far into a PE its structure reaches, from its headers alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Extent {
    /// End of the section table.
    pub headers: usize,
    /// End of the image: the headers, `SizeOfHeaders`, and the raw data of
    /// every section with the padding after it that an address of the
    /// section maps to (a page at most), at most the object. The tables the
    /// checks read ([`tables`]) lie before it. The certificate table, the
    /// debug records and whatever else follows is the overlay.
    pub image: usize,
}

/// [`Extent`] of the PE in `src`, `None` if `src` is not a PE whose headers
/// parse. Headers longer than `limit` are not read, and `image` is then their
/// end, which is past `limit` as the image is.
pub(crate) fn extent(src: &dyn ByteSource, limit: usize) -> Option<Extent> {
    let headers = headers_end(src)?;
    if headers > limit {
        return Some(Extent { headers, image: headers });
    }
    let head = src.window(0, headers);
    if head.len() != headers {
        return None;
    }
    let pe = self::headers(&head)?;
    let of_headers = pe
        .header
        .optional_header
        .map_or(0, |o| u64::from(o.windows_fields.size_of_headers));
    let image = pe
        .sections
        .iter()
        .filter(|s| s.size_of_raw_data != 0)
        .map(|s| u64::from(s.pointer_to_raw_data) + page_up(u64::from(s.size_of_raw_data)))
        .fold(of_headers.max(headers as u64), u64::max);
    Some(Extent {
        headers,
        image: usize::try_from(image).map_or(src.len(), |image| image.min(src.len())),
    })
}

/// `n` rounded up to a whole page. An address of a section maps to the file
/// from the start of its data for as many bytes as the parse of a PE reads:
/// those of the data, and the padding that follows them up to the file
/// alignment, at most a page of it.
fn page_up(n: u64) -> u64 {
    n.div_ceil(0x1000) * 0x1000
}

/// The image of the PE in `src` held in memory, when it is at most `limit`
/// bytes: what a check that parses the PE's structure is given of an object
/// too large to hold. `None` if `src` is not a PE whose headers parse, or its
/// image is longer, or cannot be read.
pub(crate) fn image_in(src: &dyn ByteSource, limit: usize) -> Option<Cow<'_, [u8]>> {
    let image = extent(src, limit)?.image;
    if image > limit {
        return None;
    }
    let bytes = src.window(0, image);
    (bytes.len() == image).then_some(bytes)
}

/// Structural facts extracted from a PE file.
pub struct PeInfo {
    pub is_64: bool,
    pub section_count: usize,
    /// (name, entropy) per section, entropy in bits/byte 0..=8.
    pub sections: Vec<(String, f64)>,
    /// Max section entropy (packing indicator).
    pub max_entropy: f64,
    /// The import hash as clamscan makes it (md5 of the ordered `dll.func`
    /// of the imports, see `Imports::clamscan_hash`), or empty if clamscan
    /// makes none.
    pub imphash: String,
    /// The length of the string `imphash` is the MD5 of: the size field of a
    /// `.imp` signature.
    pub imphash_len: usize,
    /// The import hash `pe.imphash()` gives, which is the usual one (what
    /// pefile and VirusTotal give for most PEs): the MD5 of the imports as
    /// yara-x lists them, or empty if it lists none (pefile has no import hash
    /// for a PE without imports).
    pub pe_imphash: String,
    /// The functions imported, named as yara-x names them, all of the table
    /// the reader read (not yara-x's end of the table at a descriptor with no
    /// table, nor its limits).
    pub import_count: usize,
    /// Whether a descriptor of the import table that its directory leaves
    /// room for could not be read: `import_count` and `suspicious_imports` are
    /// those of the others, and there is no `imphash`.
    pub import_fault: bool,
    /// Whether `import_fault` is only because the import directory starts at
    /// or past the end of the bytes read: the table is not in them.
    pub import_absent: bool,
    /// Names of imports considered security-relevant.
    pub suspicious_imports: Vec<String>,
}

/// Imports frequently abused by malware (injection, download-exec, etc.).
const SUSPICIOUS: &[&str] = &[
    "virtualalloc",
    "virtualallocex",
    "virtualprotect",
    "writeprocessmemory",
    "readprocessmemory",
    "createremotethread",
    "createremotethreadex",
    "ntunmapviewofsection",
    "queueuserapc",
    "setthreadcontext",
    "getthreadcontext",
    "loadlibrarya",
    "loadlibraryw",
    "getprocaddress",
    "winexec",
    "shellexecutea",
    "shellexecutew",
    "createprocessa",
    "createprocessw",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "internetopenurla",
    "wininet",
    "cryptencrypt",
    "cryptdecrypt",
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
];

/// Parse a PE and extract structural features. Returns `None` if the bytes
/// are not a parseable PE, or its import table cannot be read. Without a bound
/// on the work: see [`analyze_within`].
pub fn analyze(data: &[u8]) -> Option<PeInfo> {
    analyze_within(data, data.len(), usize::MAX, Views::ALL, &mut |_| Ok(()))
        .ok()
        .flatten()
}

/// Which readings of the import table a check needs (see [`Tables`]). A
/// reading that is not asked for is not held to account: if it cannot be read,
/// nothing is said.
#[derive(Clone, Copy)]
pub(crate) struct Views {
    /// As clamscan reads it: the `.imp` hash.
    pub clamscan: bool,
    /// As yara-x reads it: `pe.imphash()`, the `imphash:` lines, and the count
    /// of imports and the suspicious ones.
    pub listed: bool,
}

impl Views {
    pub(crate) const ALL: Views = Views { clamscan: true, listed: true };
}

/// The import hash `pe.imphash()` gives, built an import at a time: the MD5
/// of `library.function` for each, lowercased and joined by commas, the
/// library without its `.dll`, `.sys` or `.ocx` (yara-x's rule, which cuts an
/// extension only if it ends the name). It is the one function that the `pe`
/// module and the `imphash:` lines of a `.fdb` file use.
pub(crate) struct ImpHash {
    md5: Md5,
    first: bool,
}

impl ImpHash {
    pub(crate) fn new() -> Self {
        ImpHash { md5: Md5::new(), first: true }
    }

    pub(crate) fn add(&mut self, library: &str, function: &str) {
        let library = [".dll", ".sys", ".ocx"]
            .iter()
            .find_map(|ext| {
                let at = library.len().checked_sub(ext.len())?;
                library.get(at..)?.eq_ignore_ascii_case(ext).then(|| &library[..at])
            })
            .unwrap_or(library);
        if !self.first {
            Digest::update(&mut self.md5, b",");
        }
        self.first = false;
        update_lowercase(&mut self.md5, library);
        Digest::update(&mut self.md5, b".");
        update_lowercase(&mut self.md5, function);
    }

    pub(crate) fn finish(self) -> String {
        encode_hex(&self.md5.finalize())
    }
}

/// Feed `s` lowercased: ASCII only if it is ASCII, else as Unicode, as yara-x
/// and pefile do.
fn update_lowercase(md5: &mut Md5, s: &str) {
    if !s.is_ascii() {
        Digest::update(md5, s.to_lowercase().as_bytes());
        return;
    }
    let mut buf = [0u8; 256];
    for chunk in s.as_bytes().chunks(buf.len()) {
        for (to, from) in buf.iter_mut().zip(chunk) {
            *to = from.to_ascii_lowercase();
        }
        Digest::update(md5, &buf[..chunk.len()]);
    }
}

/// What stopped [`analyze_within`] short of an answer.
pub(crate) enum Cut {
    /// The names it copies came to more than it was allowed.
    Names,
    /// The bytes of sections it read came to more than the scan allows.
    Scanned(crate::unpack::LimitHit),
    /// The import table could not be read, so neither the import hash nor the
    /// features that count imports can be made.
    Imports(Unread),
}

/// [`analyze`] with a bound on the three things a crafted file makes it do
/// many times over. Sections may overlap, so reading the entropy of each can
/// read the file once per section: `scanned` is told the bytes of each before
/// they are read, and an `Err` from it ends the analysis. An import name may
/// be referred to by any number of thunks, and the import hash copies it for
/// each: those copies and the import table parsed may total `names` bytes.
///
/// `object_len` is the length of the object that holds the PE, which `data`
/// is all of or the image of: the import hash depends on how far from the end
/// of the object an entry is. `views` says which readings of the import table
/// are made into facts; what they hold of the others is left empty.
pub(crate) fn analyze_within(
    data: &[u8],
    object_len: usize,
    names: usize,
    views: Views,
    scanned: &mut dyn FnMut(u64) -> Result<(), crate::unpack::LimitHit>,
) -> Result<Option<PeInfo>, Cut> {
    let Some(pe) = tables(data, names) else {
        return Ok(None);
    };
    let (imports, listed) = pe.readings(views)?;

    let mut sections = Vec::with_capacity(pe.sections.len());
    let mut max_entropy = 0.0f64;
    for s in &pe.sections {
        let name = s.name().map(|n| n.to_string()).unwrap_or_else(|_| {
            s.real_name
                .clone()
                .unwrap_or_else(|| "<unnamed>".to_string())
        });
        let start = s.pointer_to_raw_data as usize;
        let len = s.size_of_raw_data as usize;
        let entropy = match data.get(start..start.saturating_add(len)) {
            Some(slice) if !slice.is_empty() => {
                scanned(slice.len() as u64).map_err(Cut::Scanned)?;
                shannon_entropy(slice)
            }
            _ => 0.0,
        };
        if entropy > max_entropy {
            max_entropy = entropy;
        }
        sections.push((name, entropy));
    }

    let imported = imported_from(&pe, imports, listed, object_len, names)?;
    Ok(Some(PeInfo {
        is_64: pe.is_64,
        section_count: pe.sections.len(),
        max_entropy,
        sections,
        imphash: imported.imphash,
        imphash_len: imported.imphash_len,
        pe_imphash: imported.pe_imphash,
        import_count: imported.import_count,
        import_fault: imported.import_fault,
        import_absent: imported.import_absent,
        suspicious_imports: imported.suspicious_imports,
    }))
}

/// What the imports of a PE come to, for the checks that need no more than
/// them (`PeInfo` has these and the sections' entropy).
pub(crate) struct Imported {
    pub is_64: bool,
    pub imphash: String,
    pub imphash_len: usize,
    pub pe_imphash: String,
    pub import_count: usize,
    pub import_fault: bool,
    pub import_absent: bool,
    pub suspicious_imports: Vec<String>,
}

/// [`analyze_within`] without the sections: only the imports, read as `views`
/// say. The sections' entropy is a read of the object that these checks do not
/// need.
pub(crate) fn imports_within(
    data: &[u8],
    object_len: usize,
    names: usize,
    views: Views,
) -> Result<Option<Imported>, Cut> {
    let Some(pe) = tables(data, names) else {
        return Ok(None);
    };
    let (imports, listed) = pe.readings(views)?;
    imported_from(&pe, imports, listed, object_len, names).map(Some)
}

impl<'a> Tables<'a> {
    /// The readings of the import table that `views` ask for, or why one
    /// cannot be read.
    fn readings(&self, views: Views) -> Result<(Option<&Imports<'a>>, Option<&Imports<'a>>), Cut> {
        fn take<'s, 'a>(
            wanted: bool,
            reading: &'s Result<Imports<'a>, Unread>,
        ) -> Result<Option<&'s Imports<'a>>, Cut> {
            match reading {
                Ok(read) => Ok(wanted.then_some(read)),
                Err(why) if wanted => Err(Cut::Imports(*why)),
                Err(_) => Ok(None),
            }
        }
        Ok((take(views.clamscan, &self.imports)?, take(views.listed, self.listed())?))
    }
}

/// The facts of the imports. The hash is clamscan's, what `.imp` signatures
/// are made from, from the table as clamscan reads it; what the heuristics and
/// the usual import hash count and look for is the functions yara-x lists.
/// The copies they make come out of `names`, less the memory of the tables.
fn imported_from(
    pe: &Tables<'_>,
    imports: Option<&Imports<'_>>,
    listed: Option<&Imports<'_>>,
    object_len: usize,
    names: usize,
) -> Result<Imported, Cut> {
    let mut room = names.saturating_sub(pe.held());
    let mut imported = Imported {
        is_64: pe.is_64,
        imphash: String::new(),
        imphash_len: 0,
        pe_imphash: String::new(),
        import_count: 0,
        import_fault: false,
        import_absent: true,
        suspicious_imports: Vec::new(),
    };
    if let Some(imports) = imports {
        (imported.imphash, imported.imphash_len) =
            imports.clamscan_hash(object_len, &mut room)?.unwrap_or_default();
        imported.import_fault |= imports.fault;
        imported.import_absent &= imports.past_end || !imports.fault;
    }
    if let Some(listed) = listed {
        let mut hash = ImpHash::new();
        let mut listed_by_yarax = 0;
        for import in listed.listed() {
            listed_by_yarax += 1;
            hash.add(import.library_name, &import.name);
        }
        if listed_by_yarax > 0 {
            imported.pe_imphash = hash.finish();
        }
        for import in listed.listed_in_full() {
            imported.import_count += 1;
            if SUSPICIOUS.iter().any(|known| import.name.eq_ignore_ascii_case(known)) {
                room = room.checked_sub(import.name.len()).ok_or(Cut::Names)?;
                imported.suspicious_imports.push(import.name.into_owned());
            }
        }
        imported.import_fault |= listed.fault;
        imported.import_absent &= listed.past_end || !listed.fault;
    }
    imported.import_absent &= imported.import_fault;
    Ok(imported)
}

/// Shannon entropy (bits per byte) of a buffer.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    entropy_of_counts(&counts, data.len())
}

/// [`shannon_entropy`] of `len` bytes, from how many times each value occurs.
pub(crate) fn entropy_of_counts(counts: &[u64; 256], len: usize) -> f64 {
    if len == 0 {
        return 0.0;
    }
    let len = len as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

impl PeInfo {
    /// True if any section's entropy suggests packing/encryption.
    pub fn looks_packed(&self) -> bool {
        self.max_entropy >= 7.2
    }
}

/// PE layout needed to resolve `EP`/section-relative signature offsets.
#[derive(Debug, Clone, Default)]
pub struct PeLayout {
    /// File offset of the entry point (translated from its RVA), if known.
    pub entry: Option<u64>,
    /// File offset (PointerToRawData) of each section, in order.
    pub section_rawptrs: Vec<u64>,
    /// SizeOfRawData of each section, in the same order: the section's extent
    /// in *file* space, which is what an `SEn:` offset is measured against.
    pub section_rawsizes: Vec<u64>,
    /// File offsets of the `VS_VERSION_INFO` string keys, the anchor set a
    /// `VI:` offset matches against. Empty for a PE with no version resource.
    pub version_info: Vec<u64>,
}

/// Whether a file that *claims* to be an executable describes a layout no
/// loader could map: ClamAV's `Heuristics.Broken.Executable`, reported under
/// `--alert-broken`.
///
/// The signal is the contradiction: something typed as a PE, ELF or Mach-O by
/// its magic, whose headers then do not hold together. Only the headers a
/// loader reads to map the image are judged. What they point at (imports,
/// resources, debug data, signatures, section names) is malformed routinely in
/// software that runs, and a full parse that fails on any of it made this the
/// largest false-positive class exav had: DLLs with a non-UTF-8 export name,
/// resource directories pointing nowhere, Android libraries with junk section
/// headers.
///
/// Each condition was measured against clamscan 1.5.4 on headers mutated one
/// field at a time; see `tests/suites/broken_executable.rs`.
///
/// Deliberately narrow: it only answers for input that already carries an
/// executable magic, so an arbitrary file can never be "a broken executable".
pub fn looks_broken(data: &[u8]) -> bool {
    looks_broken_in(&data)
}

/// [`looks_broken`] over an object that need not be held in memory.
pub(crate) fn looks_broken_in(src: &dyn ByteSource) -> bool {
    let head = src.window(0, 4);
    if head.starts_with(b"MZ") {
        pe_broken(src)
    } else if head.starts_with(b"\x7fELF") {
        elf_broken(src)
    } else {
        macho_broken(src)
    }
}

/// Header fields read through one cached window, so a walk over many small
/// records does not cost a read of the object per field.
struct Fields<'a> {
    src: &'a dyn ByteSource,
    at: usize,
    buf: std::borrow::Cow<'a, [u8]>,
    be: bool,
}

impl<'a> Fields<'a> {
    fn new(src: &'a dyn ByteSource) -> Self {
        Fields {
            src,
            at: 0,
            buf: std::borrow::Cow::Borrowed(&[]),
            be: false,
        }
    }

    /// `len` bytes at `off`, or `None` when the object ends first.
    fn get(&mut self, off: u64, len: usize) -> Option<&[u8]> {
        let off = usize::try_from(off).ok()?;
        let end = off.checked_add(len)?;
        if end > self.src.len() {
            return None;
        }
        if off < self.at || end > self.at + self.buf.len() {
            self.at = off;
            self.buf = self.src.window(off, len.max(64 * 1024));
        }
        self.buf.get(off - self.at..end - self.at)
    }

    fn u16(&mut self, off: u64) -> Option<u16> {
        let be = self.be;
        self.get(off, 2).map(|b| read_uint(b, be) as u16)
    }

    fn u32(&mut self, off: u64) -> Option<u32> {
        let be = self.be;
        self.get(off, 4).map(|b| read_uint(b, be) as u32)
    }

    /// A 4- or 8-byte field, by the file's class.
    fn word(&mut self, off: u64, wide: bool) -> Option<u64> {
        let be = self.be;
        self.get(off, if wide { 8 } else { 4 }).map(|b| read_uint(b, be))
    }
}

/// An unsigned integer of up to 8 bytes in the given byte order.
fn read_uint(b: &[u8], be: bool) -> u64 {
    let fold = |v: u64, &x: &u8| (v << 8) | u64::from(x);
    if be {
        b.iter().fold(0, fold)
    } else {
        b.iter().rev().fold(0, fold)
    }
}

/// `x` rounded up to a multiple of `a`, or `x` itself when `a` is 0.
fn round_up(x: u64, a: u64) -> u64 {
    if a == 0 {
        x
    } else {
        x.div_ceil(a) * a
    }
}

fn pe_broken(src: &dyn ByteSource) -> bool {
    let mut f = Fields::new(src);
    let n = src.len() as u64;
    // No PE header is a DOS program, and a COFF header cut short is too little
    // to judge: neither describes a layout.
    let Some(e) = f.u32(0x3c).map(u64::from) else {
        return false;
    };
    let Some(coff) = f.get(e, 24) else {
        return false;
    };
    if coff[..4] != *b"PE\0\0" {
        return false;
    }
    let nsec = u64::from(u16::from_le_bytes([coff[6], coff[7]]));
    let optsz = u64::from(u16::from_le_bytes([coff[20], coff[21]]));
    let opt = e + 24;
    // Any magic but PE32+ is read as PE32.
    let fixed = if f.u16(opt) == Some(0x20b) { 112 } else { 96 };
    if optsz < fixed {
        return true;
    }
    let Some(h) = f.get(opt, fixed as usize) else {
        return true;
    };
    let le32 = |at: usize| u64::from(u32::from_le_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]));
    let (entry, salign, falign, headers) = (le32(16), le32(32), le32(36), le32(60));
    let native = u16::from_le_bytes([h[68], h[69]]) == 1;
    let dirs = le32(fixed as usize - 4).min(16) * 8;
    if optsz < fixed + dirs {
        return true;
    }
    // The data directories cut short: incomplete rather than wrong.
    if opt + fixed + dirs > n {
        return false;
    }
    if nsec == 0 {
        return true;
    }
    // Drivers (the native subsystem) may use any alignment.
    let aligned = falign != 0 && falign % 0x200 == 0 && salign != 0 && salign % 0x1000 == 0;
    if salign == 0 || !(native || aligned) {
        return true;
    }
    let Some(table) = f.get(opt + optsz, (nsec * 40) as usize) else {
        return true;
    };
    // (VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData). A
    // section whose raw data starts at or past the end of the file is left out
    // of the layout, as though the table did not list it.
    let sections = || {
        table
            .as_chunks::<40>()
            .0
            .iter()
            .map(|s| {
                let at = |i: usize| u64::from(u32::from_le_bytes([s[i], s[i + 1], s[i + 2], s[i + 3]]));
                (at(8), at(12), at(16), at(20))
            })
            .filter(|&(_, _, raw_size, raw_ptr)| raw_size == 0 || raw_ptr < n)
    };
    let Some((_, first, _, _)) = sections().next() else {
        return true;
    };
    // Laid out in memory right after the headers, each section where the one
    // before it ends.
    if first != round_up(headers, salign) {
        return true;
    }
    let mut end = first;
    for (vsize, va, raw_size, _) in sections() {
        if va != end {
            return true;
        }
        end = va + round_up(if vsize != 0 { vsize } else { raw_size }, salign);
    }
    // The entry point has to land on bytes the file holds.
    if entry < first {
        return entry >= n;
    }
    let Some((_, va, _, raw_ptr)) = sections().find(|&(_, va, raw_size, _)| {
        entry >= va && entry - va < round_up(raw_size, falign)
    }) else {
        return true;
    };
    let raw_start = raw_ptr.checked_div(falign).map_or(raw_ptr, |q| q * falign);
    raw_start + (entry - va) >= n
}

fn elf_broken(src: &dyn ByteSource) -> bool {
    let mut f = Fields::new(src);
    let Some(ident) = f.get(0, 16) else {
        return false;
    };
    let wide = match ident[4] {
        1 => false,
        2 => true,
        _ => return true,
    };
    // Anything but little-endian is read as big-endian.
    f.be = ident[5] != 1;
    let (header, ph_size, sh_size) = if wide { (64, 56, 64) } else { (52, 32, 40) };
    // A header cut short is too little to judge.
    if f.get(0, header).is_none() {
        return false;
    }
    let w = if wide { 8 } else { 4 };
    let (Some(entry), Some(phoff), Some(shoff)) =
        (f.word(24, wide), f.word(24 + w, wide), f.word(24 + 2 * w, wide))
    else {
        return false;
    };
    let fields = 28 + 3 * w; // e_ehsize, then the table geometry
    let geometry = [2, 4, 6, 8].map(|i| f.u16(fields + i).map(u64::from));
    let [Some(ph_entsize), Some(phnum), Some(sh_entsize), Some(shnum)] = geometry else {
        return false;
    };
    if phnum > 0 {
        if phnum > 128 || ph_entsize != ph_size {
            return true;
        }
        if f.get(phoff, (phnum * ph_size) as usize).is_none() {
            return true;
        }
        // Inside some segment's memory image, whatever its type. 0 is no entry.
        let (vaddr_at, memsz_at) = if wide { (16, 40) } else { (8, 20) };
        let mapped = (0..phnum).any(|i| {
            let p = phoff + i * ph_size;
            let (Some(vaddr), Some(memsz)) = (f.word(p + vaddr_at, wide), f.word(p + memsz_at, wide)) else {
                return false;
            };
            entry >= vaddr && entry - vaddr < memsz
        });
        if entry != 0 && !mapped {
            return true;
        }
    }
    // A zero entry size is a stripped section table, which is reported under
    // its own name (see `elf_section_headers_stripped`).
    if sh_entsize == 0 {
        return false;
    }
    sh_entsize != sh_size || (shnum > 0 && f.get(shoff, (shnum * sh_size) as usize).is_none())
}

fn macho_broken(src: &dyn ByteSource) -> bool {
    let mut f = Fields::new(src);
    let n = src.len() as u64;
    // Thin images only: the universal ("fat") magic is a container, and a Java
    // class shares its bytes.
    let Some(magic) = f.get(0, 4) else {
        return false;
    };
    let (wide, be) = match magic {
        [0xCE, 0xFA, 0xED, 0xFE] => (false, false),
        [0xCF, 0xFA, 0xED, 0xFE] => (true, false),
        [0xFE, 0xED, 0xFA, 0xCE] => (false, true),
        [0xFE, 0xED, 0xFA, 0xCF] => (true, true),
        _ => return false,
    };
    f.be = be;
    let header: u64 = if wide { 32 } else { 28 };
    if n < header {
        return false;
    }
    let (Some(cpu), Some(ncmds)) = (f.u32(4), f.u32(16).map(u64::from)) else {
        return false;
    };
    // Every command moves the walk at least 8 bytes on, so more than the file
    // can hold is a read past its end. This also bounds the walk.
    if ncmds == 0 || ncmds * 8 > n - header {
        return true;
    }
    let (segment, segment_size, section_size) = if wide { (0x19, 72, 80) } else { (0x1, 56, 68) };
    // Thread state is read in full on these CPUs (i386, PowerPC, PowerPC 64),
    // and skipped on the others.
    let thread_state = match cpu {
        7 => Some(64),
        18 => Some(160),
        0x0100_0012 => Some(312),
        _ => None,
    };
    let mut at = header;
    for _ in 0..ncmds {
        let (Some(cmd), Some(size)) = (f.u32(at), f.u32(at + 4)) else {
            return true;
        };
        if cmd == segment {
            // A segment is read by its structure, whatever its cmdsize says.
            let Some(nsects) = f.u32(at + segment_size - 8) else {
                return true;
            };
            at += segment_size + u64::from(nsects) * section_size;
            if at > n {
                return true;
            }
            continue;
        }
        if matches!(cmd, 0x4 | 0x5) {
            // LC_THREAD, LC_UNIXTHREAD: flavor, count, then the registers.
            if thread_state.is_some_and(|len| at + 16 + len > n) {
                return true;
            }
        }
        at += u64::from(size).max(8);
    }
    false
}

/// Extract [`PeLayout`] from a PE. `None` if `data` is not a parseable PE.
pub fn layout(data: &[u8]) -> Option<PeLayout> {
    let pe = headers(data)?;
    let mut section_rawptrs = Vec::with_capacity(pe.sections.len());
    let mut section_rawsizes = Vec::with_capacity(pe.sections.len());
    let entry_rva = pe
        .header
        .optional_header
        .map_or(0, |o| u64::from(o.standard_fields.address_of_entry_point));
    let mut entry = None;
    for s in &pe.sections {
        let va = s.virtual_address as u64;
        let vsize = (s.virtual_size as u64).max(s.size_of_raw_data as u64);
        let ptr = s.pointer_to_raw_data as u64;
        section_rawptrs.push(ptr);
        section_rawsizes.push(s.size_of_raw_data as u64);
        if entry.is_none() && entry_rva >= va && entry_rva < va.saturating_add(vsize) {
            entry = Some(ptr + (entry_rva - va));
        }
    }
    // An entry point in the headers is at the file offset of its RVA.
    if entry.is_none()
        && let Some(opt) = pe.header.optional_header.as_ref()
        && entry_rva < u64::from(header_end(opt, &pe.sections))
    {
        entry = Some(entry_rva);
    }
    Some(PeLayout {
        entry,
        section_rawptrs,
        section_rawsizes,
        version_info: crate::icon::version_info_anchors(data),
    })
}

/// Most sections an ELF or Mach-O layout lists: a section table is a `u16`
/// long in an ELF, and nothing a real file has comes near it.
const MAX_EXEC_SECTIONS: u64 = 1 << 16;

/// [`PeLayout`] of an ELF file, for the `EP`, `Sn`, `SL` and `SEn` offsets of a
/// `Target:6` signature, read from the headers alone (the object is not held).
///
/// As clamscan resolves them (measured, with one signature per offset and one
/// wrong by three bytes as the control): `EP` is the entry point's file
/// offset, found by the loadable segment whose memory image holds it (the
/// part past the file's bytes, the `.bss`, included), and `Sn` is the file
/// offset of section header `n`, counted from the null section at 0.
/// A section with no bytes in the file (`SHT_NOBITS`) is a point.
pub fn elf_layout(src: &dyn ByteSource) -> Option<PeLayout> {
    let mut f = Fields::new(src);
    let ident = f.get(0, 16)?;
    if &ident[..4] != b"\x7fELF" {
        return None;
    }
    let wide = match ident[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    // Anything but little-endian is read as big-endian, as `elf_broken` does.
    f.be = ident[5] != 1;
    let (header, ph_min, sh_min) = if wide { (64, 56, 64) } else { (52, 32, 40) };
    f.get(0, header)?;
    let w = if wide { 8 } else { 4 };
    let entry_va = f.word(24, wide)?;
    let (phoff, shoff) = (f.word(24 + w, wide)?, f.word(24 + 2 * w, wide)?);
    let fields = 28 + 3 * w;
    let [ph_entsize, phnum, sh_entsize, shnum] =
        [2, 4, 6, 8].map(|i| f.u16(fields + i).map(u64::from));
    let (ph_entsize, phnum, sh_entsize, shnum) =
        (ph_entsize?, phnum?, sh_entsize?, shnum?);

    let mut entry = None;
    if ph_entsize >= ph_min {
        let (offset_at, vaddr_at, memsz_at) = if wide { (8, 16, 40) } else { (4, 8, 20) };
        for i in 0..phnum {
            let p = phoff.checked_add(i * ph_entsize)?;
            let (Some(kind), Some(offset), Some(vaddr), Some(memsz)) = (
                f.u32(p),
                p.checked_add(offset_at).and_then(|a| f.word(a, wide)),
                p.checked_add(vaddr_at).and_then(|a| f.word(a, wide)),
                p.checked_add(memsz_at).and_then(|a| f.word(a, wide)),
            ) else {
                break;
            };
            // PT_LOAD
            if kind == 1 && entry_va >= vaddr && entry_va - vaddr < memsz {
                entry = offset.checked_add(entry_va - vaddr);
                break;
            }
        }
    }

    let mut section_rawptrs = Vec::new();
    let mut section_rawsizes = Vec::new();
    if sh_entsize >= sh_min {
        let (offset_at, size_at) = if wide { (24, 32) } else { (16, 20) };
        for i in 0..shnum.min(MAX_EXEC_SECTIONS) {
            let Some(s) = shoff.checked_add(i * sh_entsize) else {
                break;
            };
            let (Some(kind), Some(offset), Some(size)) = (
                s.checked_add(4).and_then(|a| f.u32(a)),
                s.checked_add(offset_at).and_then(|a| f.word(a, wide)),
                s.checked_add(size_at).and_then(|a| f.word(a, wide)),
            ) else {
                break;
            };
            section_rawptrs.push(offset);
            // SHT_NOBITS
            section_rawsizes.push(if kind == 8 { 0 } else { size });
        }
    }
    Some(PeLayout {
        entry,
        section_rawptrs,
        section_rawsizes,
        version_info: Vec::new(),
    })
}

/// The image of the ELF file in `src` held in memory, when it is at most
/// `limit` bytes: what the `elf` YARA module parses of an object too large to
/// hold. The image ends where the last of these does: the ELF header, the two
/// header tables, and the bytes in the file of every segment and section.
/// Section names, symbols, relocations, the dynamic section and notes are
/// contents of one or the other. What follows is appended data.
///
/// `None` if `src` is not an ELF whose headers parse, or its image is longer,
/// or cannot be read.
pub(crate) fn elf_image_in(src: &dyn ByteSource, limit: usize) -> Option<Cow<'_, [u8]>> {
    let image = elf_image_end(src, limit)?;
    if image > limit {
        return None;
    }
    let bytes = src.window(0, image);
    (bytes.len() == image).then_some(bytes)
}

/// The end of the ELF image of `src` (see [`elf_image_in`]). A table longer
/// than `limit` is not read, and its end, past `limit`, is the answer.
fn elf_image_end(src: &dyn ByteSource, limit: usize) -> Option<usize> {
    let mut f = Fields::new(src);
    let ident = f.get(0, 16)?;
    if &ident[..4] != b"\x7fELF" {
        return None;
    }
    let wide = match ident[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    f.be = match ident[5] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let (header, ph_min, sh_min) = if wide { (64, 56, 64) } else { (52, 32, 40) };
    f.get(0, header)?;
    let w = if wide { 8 } else { 4 };
    let (phoff, shoff) = (f.word(24 + w, wide)?, f.word(24 + 2 * w, wide)?);
    let fields = 28 + 3 * w;
    let [ph_entsize, phnum, sh_entsize, shnum] =
        [2, 4, 6, 8].map(|i| f.u16(fields + i).map(u64::from));
    let (ph_entsize, phnum, sh_entsize, shnum) = (ph_entsize?, phnum?, sh_entsize?, shnum?);
    let len = src.len() as u64;
    let mut end = header as u64;
    // Each table, then what each of its entries holds: (offset, size) fields
    // at these places of an entry, and the type that is no bytes of the file.
    let (ph_at, sh_at) = if wide { ((8, 32), (24, 32)) } else { ((4, 16), (16, 20)) };
    // No section table at offset 0, and with no count the null section's size
    // is the count (what a table of 0xff00 sections or more does).
    let shnum = match shnum {
        _ if shoff == 0 => 0,
        0 => f.word(shoff.checked_add(sh_at.1)?, wide)?,
        n => n,
    };
    for (off, num, entsize, min, (offset_at, size_at), nobits) in [
        (phoff, phnum, ph_entsize, ph_min, ph_at, None),
        (shoff, shnum, sh_entsize, sh_min, sh_at, Some(8)),
    ] {
        if num == 0 {
            continue;
        }
        if entsize < min {
            return None;
        }
        let table_end = off.checked_add(num.checked_mul(entsize)?)?;
        if table_end > len {
            return None;
        }
        end = end.max(table_end);
        if table_end > limit as u64 {
            return usize::try_from(table_end).ok();
        }
        for i in 0..num {
            let e = off + i * entsize;
            // A section's type is the word after its name: `SHT_NOBITS` has
            // no bytes in the file, whatever its size says.
            let kind = f.u32(e + 4);
            let (Some(offset), Some(size)) =
                (f.word(e + offset_at, wide), f.word(e + size_at, wide))
            else {
                return None;
            };
            if nobits.is_some_and(|t| kind == Some(t)) {
                continue;
            }
            end = end.max(offset.saturating_add(size).min(len));
        }
    }
    usize::try_from(end).ok()
}

/// [`PeLayout`] of a thin Mach-O file, for the `Sn`, `SL` and `SEn` offsets
/// of a `Target:9` signature. `n` counts the sections of every segment in the
/// order of the load commands, and an offset is the section's own.
///
/// `EP` is left unresolved: clamscan 1.4.3 does not resolve it on a Mach-O of
/// either width, from `LC_MAIN` or from `LC_UNIXTHREAD` (a signature
/// anchored there never fired in any of eight variants, where the section
/// offsets did, each with a control), so a signature using it matches
/// nowhere, as it does there.
pub fn macho_layout(src: &dyn ByteSource) -> Option<PeLayout> {
    let mut f = Fields::new(src);
    let (wide, be) = match f.get(0, 4)? {
        [0xCE, 0xFA, 0xED, 0xFE] => (false, false),
        [0xCF, 0xFA, 0xED, 0xFE] => (true, false),
        [0xFE, 0xED, 0xFA, 0xCE] => (false, true),
        [0xFE, 0xED, 0xFA, 0xCF] => (true, true),
        _ => return None,
    };
    f.be = be;
    let header: u64 = if wide { 32 } else { 28 };
    let (ncmds, sizeofcmds) = (u64::from(f.u32(16)?), u64::from(f.u32(20)?));
    let end = header.checked_add(sizeofcmds)?;
    if end > src.len() as u64 {
        return None;
    }
    // LC_SEGMENT and LC_SEGMENT_64, and what each one's sections are like.
    let (segment, nsects_at, first_section, section_len, size_at, offset_at) = if wide {
        (0x19u32, 64u64, 72u64, 80u64, 40u64, 48u64)
    } else {
        (0x1, 48, 56, 68, 36, 40)
    };
    let mut section_rawptrs = Vec::new();
    let mut section_rawsizes = Vec::new();
    let mut at = header;
    'commands: for _ in 0..ncmds.min(MAX_EXEC_SECTIONS) {
        let (Some(cmd), Some(size)) = (f.u32(at), f.u32(at + 4).map(u64::from)) else {
            break;
        };
        if size < 8 || at.checked_add(size)? > end {
            break;
        }
        if cmd == segment {
            let Some(nsects) = f.u32(at + nsects_at).map(u64::from) else {
                break;
            };
            for i in 0..nsects {
                let s = at + first_section + i * section_len;
                if s + section_len > at + size || section_rawptrs.len() as u64 >= MAX_EXEC_SECTIONS {
                    break 'commands;
                }
                let (Some(offset), Some(len)) =
                    (f.u32(s + offset_at).map(u64::from), f.word(s + size_at, wide))
                else {
                    break 'commands;
                };
                section_rawptrs.push(offset);
                // A zero-fill section has no bytes in the file.
                section_rawsizes.push(if offset == 0 { 0 } else { len });
            }
        }
        at += size;
    }
    Some(PeLayout {
        entry: None,
        section_rawptrs,
        section_rawsizes,
        version_info: Vec::new(),
    })
}

/// One PE section in the shape the bytecode PE APIs expect
/// (`cli_exe_section`).
///
/// The name and layout are the interface a `.cbc` program is compiled against,
/// so an interpreter has to match them exactly. Both are established the same
/// way as the rest of that ABI here: from the field accesses real programs
/// make, not from any engine source.
#[derive(Debug, Clone, Copy, Default)]
pub struct BcPeSection {
    pub rva: u32,
    pub vsz: u32,
    pub raw: u32,
    pub rsz: u32,
    pub chr: u32,
}

/// PE header/section info needed by the bytecode `get_pe_section` and
/// `pe_rawaddr` APIs.
#[derive(Debug, Clone, Default)]
pub struct BcPe {
    pub sections: Vec<BcPeSection>,
    /// `SizeOfHeaders`: RVAs below this map directly to file offsets.
    pub hdr_size: u32,
    /// Byte image of `cli_pe_hook_data` (the `__clambc_pedata` global).
    pub pedata: Vec<u8>,
}

/// Size of the `cli_pe_hook_data` struct image (the bytecode-compiler view,
/// with both opt32/opt64 headers and their data directories inlined).
///
/// Fixed by the ABI rather than chosen: a program reads its fields at compiled
/// offsets, so the image has to be exactly this long. Derived from the accesses
/// real programs make, as with the rest of the layout.
const PEDATA_SIZE: usize = 648;

impl BcPe {
    /// Translate an RVA to a raw file offset.
    /// `None` if the RVA falls outside the header and every section.
    pub fn rawaddr(&self, rva: u32, file_size: usize) -> Option<u32> {
        if rva < self.hdr_size {
            return if (rva as usize) >= file_size {
                None
            } else {
                Some(rva)
            };
        }
        for s in self.sections.iter().rev() {
            if s.rsz != 0 && s.rva <= rva && s.rsz > rva - s.rva {
                return (rva - s.rva).checked_add(s.raw);
            }
        }
        None
    }
}

/// Extract [`BcPe`] from a PE image. `None` if `data` is not a parseable PE.
pub fn bytecode_pe(data: &[u8]) -> Option<BcPe> {
    Some(bytecode_of(&headers(data)?, data.len()))
}

/// [`bytecode_pe`] of the PE in `src`, which may be too large to hold: only
/// the headers are read, and what the programs see is the same whether or not
/// the object is held. `Err` holds the length of the headers when they are
/// over `limit` bytes, and `Ok(None)` is a `src` that is not a parseable PE.
pub(crate) fn bytecode_pe_in(src: &dyn ByteSource, limit: usize) -> Result<Option<BcPe>, usize> {
    if let Some(all) = src.as_slice() {
        return Ok(bytecode_pe(all));
    }
    let Some(end) = headers_end(src) else {
        return Ok(None);
    };
    if end > limit {
        return Err(end);
    }
    let head = src.window(0, end);
    Ok(headers(&head).map(|pe| bytecode_of(&pe, src.len())))
}

/// [`BcPe`] of parsed headers, in a file of `file_size` bytes.
fn bytecode_of(pe: &Headers, file_size: usize) -> BcPe {
    let hdr_size = pe
        .header
        .optional_header
        .map(|o| o.windows_fields.size_of_headers)
        .unwrap_or(0);
    let sections: Vec<BcPeSection> = pe
        .sections
        .iter()
        .map(|s| BcPeSection {
            rva: s.virtual_address,
            vsz: s.virtual_size,
            raw: s.pointer_to_raw_data,
            rsz: s.size_of_raw_data,
            chr: s.characteristics,
        })
        .collect();
    let mut bc = BcPe {
        sections,
        hdr_size,
        pedata: Vec::new(),
    };
    bc.pedata = build_pedata(&pe.header, &bc, file_size);
    bc
}

/// Build the `cli_pe_hook_data` byte image the way the bytecode compiler lays
/// it out (offsets verified against the field accesses real programs make).
fn build_pedata(header: &goblin::pe::header::Header, bc: &BcPe, file_size: usize) -> Vec<u8> {
    let mut b = vec![0u8; PEDATA_SIZE];
    let put16 =
        |b: &mut [u8], off: usize, v: u16| b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    let put32 =
        |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    let put64 =
        |b: &mut [u8], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());

    let coff = &header.coff_header;
    let e_lfanew = header.dos_header.pe_pointer;
    put32(&mut b, 0, e_lfanew); // offset
    put16(&mut b, 8, coff.number_of_sections); // nsections

    // file_hdr @12: Magic "PE\0\0", then the COFF header fields.
    b[12..16].copy_from_slice(b"PE\0\0");
    put16(&mut b, 16, coff.machine);
    put16(&mut b, 18, coff.number_of_sections);
    put32(&mut b, 20, coff.time_date_stamp);
    put32(&mut b, 24, coff.pointer_to_symbol_table);
    put32(&mut b, 28, coff.number_of_symbol_table);
    put16(&mut b, 32, coff.size_of_optional_header);
    put16(&mut b, 34, coff.characteristics);

    if let Some(oh) = header.optional_header {
        let s = &oh.standard_fields;
        let w = &oh.windows_fields;
        let ep = s.address_of_entry_point;
        put32(&mut b, 4, bc.rawaddr(ep, file_size).unwrap_or(0)); // ep as file offset
                                                                  // The compiler's struct inlines DataDirectory[16] into each opt header,
                                                                  // so opt32 spans 36..260 and opt64 spans 264..504.
        if s.magic == 0x20b {
            let base = 264;
            put16(&mut b, base, s.magic);
            put32(&mut b, base + 16, ep);
            put64(&mut b, base + 24, w.image_base);
            put32(&mut b, base + 32, w.section_alignment);
            put32(&mut b, base + 36, w.file_alignment);
            put32(&mut b, base + 56, w.size_of_image);
            put32(&mut b, base + 60, w.size_of_headers);
            put16(&mut b, base + 68, w.subsystem);
            put32(&mut b, base + 108, w.number_of_rva_and_sizes);
            put_dirs(&mut b, 376, &oh); // opt64 data dirs
        } else {
            let base = 36;
            put16(&mut b, base, s.magic);
            put32(&mut b, base + 16, ep);
            put32(&mut b, base + 28, w.image_base as u32);
            put32(&mut b, base + 32, w.section_alignment);
            put32(&mut b, base + 36, w.file_alignment);
            put32(&mut b, base + 56, w.size_of_image);
            put32(&mut b, base + 60, w.size_of_headers);
            put16(&mut b, base + 68, w.subsystem);
            put32(&mut b, base + 92, w.number_of_rva_and_sizes);
            put_dirs(&mut b, 132, &oh); // opt32 data dirs
        }
        put_dirs(&mut b, 504, &oh); // merged dirs[16]
    }

    put32(&mut b, 632, e_lfanew); // e_lfanew
    put32(&mut b, 644, bc.hdr_size); // hdr_size
    b
}

/// The raw array, not `dirs()`: that skips absent entries, so enumerating it
/// shifts the slots, and it panics on the reserved 16th entry.
fn put_dirs(b: &mut [u8], base: usize, oh: &goblin::pe::optional_header::OptionalHeader) {
    for (i, dd) in oh.data_directories.data_directories.iter().enumerate().take(16) {
        let Some((_, dd)) = dd else { continue };
        let off = base + i * 8;
        b[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
        b[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());
    }
}

/// How many of each kind carving lists for one object: the executables
/// (PE, ELF and Mach-O images, each kind to this many) and the archives. They
/// bound the work on an input crafted with many markers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarveCaps {
    pub(crate) executables: usize,
    pub(crate) archives: usize,
}

impl CarveCaps {
    /// The caps `limits` sets (`max_carved_executables` and
    /// `max_carved_archives`).
    pub(crate) fn of(limits: &crate::unpack::Limits) -> Self {
        let count = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
        CarveCaps {
            executables: count(limits.max_carved_executables),
            archives: count(limits.max_carved_archives),
        }
    }
}

impl Default for CarveCaps {
    fn default() -> Self {
        Self::of(&crate::unpack::Limits::default())
    }
}

/// What carving finds embedded at a non-zero offset in an object: validated
/// PE, ELF and Mach-O images, and archive candidates whose header checks out,
/// each in ascending order and within its cap.
#[derive(Default)]
pub(crate) struct Embedded {
    pub(crate) pe: Vec<usize>,
    pub(crate) elf: Vec<usize>,
    pub(crate) macho: Vec<usize>,
    pub(crate) archives: Vec<usize>,
    /// A PE image that validated was left out at its cap, so the object is
    /// not fully scanned.
    pub(crate) pe_capped: bool,
    /// The same for an ELF or Mach-O image or an archive.
    pub(crate) others_capped: bool,
}

/// The magics carving looks for, and what each marks.
#[derive(Clone, Copy)]
enum Magic {
    Pe,
    Elf,
    /// A thin Mach-O, big-endian or not.
    MachoThin(bool),
    MachoFat,
    Archive,
}

const CARVE_MAGICS: [(&[u8], Magic); 15] = [
    (b"MZ", Magic::Pe),
    (b"\x7fELF", Magic::Elf),
    (&[0xCE, 0xFA, 0xED, 0xFE], Magic::MachoThin(false)), // MH_MAGIC    (32-bit), LE host
    (&[0xCF, 0xFA, 0xED, 0xFE], Magic::MachoThin(false)), // MH_MAGIC_64 (64-bit), LE host
    (&[0xFE, 0xED, 0xFA, 0xCE], Magic::MachoThin(true)),  // MH_CIGAM    (32-bit), BE host
    (&[0xFE, 0xED, 0xFA, 0xCF], Magic::MachoThin(true)),  // MH_CIGAM_64 (64-bit), BE host
    (b"\xCA\xFE\xBA\xBE", Magic::MachoFat),
    (b"PK\x03\x04", Magic::Archive),         // ZIP / OOXML / APK / JAR
    (b"\x1f\x8b\x08", Magic::Archive),       // GZIP
    (b"BZh", Magic::Archive),                // BZIP2
    (b"\xfd7zXZ\x00", Magic::Archive),       // XZ
    (b"7z\xbc\xaf\x27\x1c", Magic::Archive), // 7-Zip
    (b"Rar!\x1a\x07", Magic::Archive),       // RAR
    (b"MSCF", Magic::Archive),               // CAB
    (&[0x60, 0xEA], Magic::Archive),         // ARJ, if its main header's CRC-32 holds
];

/// Everything carving looks for in `data`, found in one read of it, a window
/// at a time: the image at offset 0 is the object's own, and each candidate
/// is validated as it is met. The search stops once every kind is at its cap
/// and one more candidate has been seen past a cap.
pub(crate) fn embedded_in(data: &dyn ByteSource, caps: CarveCaps) -> Embedded {
    let mut carving = Carving::new(usize::MAX, caps);
    let len = data.len();
    let mut at = 0;
    while at < len && !carving.full() {
        let w = data.window(at, (len - at).min(crate::byte_source::CHUNK));
        if w.is_empty() {
            break;
        }
        let last = at + w.len() >= len;
        let owned = if last { w.len() } else { w.len().saturating_sub(Carving::OVERLAP).max(1) };
        carving.feed(data, at, &w, owned);
        if last {
            break;
        }
        at += owned;
    }
    carving.settle(data);
    carving.found
}

/// The search [`embedded_in`] makes, fed a window at a time by a read of the
/// object that serves other searches too.
pub(crate) struct Carving {
    finders: Vec<memchr::memmem::Finder<'static>>,
    hits: Vec<(usize, Magic)>,
    /// Where the last ZIP local header seen says the next entry begins, when
    /// it can say (see [`zip_next_header`]).
    zip_next: Option<usize>,
    /// `(header, MZ)` of candidates whose `PE\0\0` header lies beyond the
    /// window they were found in, in an object not held in memory. Checked
    /// by [`Carving::settle`] in offset order, so a header costs one read of
    /// its block however many candidates point near it.
    far: Vec<(usize, usize)>,
    /// How many of those wait before they are settled.
    far_max: usize,
    caps: CarveCaps,
    pub(crate) found: Embedded,
}

/// Where the ZIP local header at `off` says the next entry begins: after its
/// name, extra field and compressed data. `None` when it cannot say: the entry
/// is encrypted, its sizes follow the data (a data descriptor), or its size is
/// ZIP64's.
fn zip_next_header(data: &dyn ByteSource, off: usize) -> Option<usize> {
    let h = data.window(off, 30);
    if h.len() != 30 || h[..4] != *b"PK\x03\x04" {
        return None;
    }
    let flags = u16::from_le_bytes([h[6], h[7]]);
    if flags & 0b1001 != 0 {
        return None;
    }
    let csize = u32::from_le_bytes([h[18], h[19], h[20], h[21]]);
    if csize == u32::MAX {
        return None;
    }
    let name = usize::from(u16::from_le_bytes([h[26], h[27]]));
    let extra = usize::from(u16::from_le_bytes([h[28], h[29]]));
    off.checked_add(30 + name + extra)?.checked_add(csize as usize)
}

impl Carving {
    /// Bytes each window must run into the next, so a magic across the seam
    /// is seen whole.
    pub(crate) const OVERLAP: usize = {
        let mut longest = 0;
        let mut i = 0;
        while i < CARVE_MAGICS.len() {
            if CARVE_MAGICS[i].0.len() > longest {
                longest = CARVE_MAGICS[i].0.len();
            }
            i += 1;
        }
        longest - 1
    };

    /// A search that settles its far candidates once `far_max` wait, and lists
    /// no more of a kind than `caps` says.
    pub(crate) fn new(far_max: usize, caps: CarveCaps) -> Self {
        Carving {
            finders: CARVE_MAGICS.iter().map(|(m, _)| memchr::memmem::Finder::new(m)).collect(),
            hits: Vec::new(),
            zip_next: None,
            far: Vec::new(),
            far_max: far_max.max(1),
            caps,
            found: Embedded::default(),
        }
    }

    /// Whether the rest of the object has nothing more to add: every kind is
    /// at its cap, and candidates past the caps were already seen.
    pub(crate) fn full(&self) -> bool {
        let (f, caps) = (&self.found, self.caps);
        self.far.is_empty()
            && f.pe_capped
            && f.others_capped
            && f.pe.len() >= caps.executables
            && f.elf.len() >= caps.executables
            && f.macho.len() >= caps.executables
            && f.archives.len() >= caps.archives
    }

    /// Search the window `w` at `at` in `data` for the magics that start in
    /// its first `owned` bytes; those after start in the next window, which
    /// sees them whole. Candidates are validated against `data`.
    pub(crate) fn feed(&mut self, data: &dyn ByteSource, at: usize, w: &[u8], owned: usize) {
        let found = &mut self.found;
        let hits = &mut self.hits;
        let zip_next = &mut self.zip_next;
        let far = &mut self.far;
        let caps = self.caps;
        // A header beyond the window is a read of its own, where the object
        // is not in memory.
        let held = at + w.len();
        let in_memory = data.as_slice().is_some();
        hits.clear();
        for (f, (_, kind)) in self.finders.iter().zip(CARVE_MAGICS) {
            hits.extend(f.find_iter(w).take_while(|&p| p < owned).map(|p| (at + p, kind)));
        }
        hits.sort_unstable_by_key(|&(off, _)| off);
        for &(off, kind) in hits.iter() {
            let zip = matches!(kind, Magic::Archive) && data.window(off, 4)[..] == *b"PK\x03\x04";
            if off == 0 {
                // The object's own image or archive; a ZIP's later entries
                // are its own, not archives stapled inside it.
                if zip {
                    *zip_next = zip_next_header(data, off);
                }
                continue;
            }
            // The next entry of a ZIP already taken is read when that ZIP is:
            // its walk reaches every local header after its own, wherever the
            // directory points. Counting each as an archive of its own would
            // fill the cap with one zip's members and rescan the rest of the
            // object once per member.
            if zip && *zip_next == Some(off) {
                *zip_next = zip_next_header(data, off);
                continue;
            }
            let (list, cap, ok) = match kind {
                Magic::Pe => {
                    match pe_target(data, off) {
                        Some(pe) if pe >= held && !in_memory => far.push((pe, off)),
                        Some(pe) if pe_header_at(data, pe) => {
                            accept_pe(found, off, caps.executables)
                        }
                        _ => {}
                    }
                    continue;
                }
                Magic::Elf => (&mut found.elf, caps.executables, elf_at(data, off)),
                Magic::MachoThin(be) => (&mut found.macho, caps.executables, macho_thin_at(data, off, be)),
                Magic::MachoFat => (&mut found.macho, caps.executables, macho_fat_at(data, off)),
                Magic::Archive => (&mut found.archives, caps.archives, archive_at(data, off)),
            };
            // The chain follows only a ZIP that will be scanned.
            if zip {
                *zip_next = None;
            }
            if ok {
                if list.len() < cap {
                    list.push(off);
                    if zip {
                        *zip_next = zip_next_header(data, off);
                    }
                } else {
                    found.others_capped = true;
                }
            }
        }
        if self.far.len() >= self.far_max {
            self.settle(data);
        }
    }

    /// Check the far candidates waiting, in the order of the headers they
    /// point at. Call it once the object is fed.
    pub(crate) fn settle(&mut self, data: &dyn ByteSource) {
        self.far.sort_unstable();
        for (pe, off) in std::mem::take(&mut self.far) {
            if pe_header_at(data, pe) {
                accept_pe(&mut self.found, off, self.caps.executables);
            }
        }
    }
}

/// Take the PE at `off`: the lowest `cap` offsets are listed whatever order
/// they are found in, and one more makes the object capped.
fn accept_pe(found: &mut Embedded, off: usize, cap: usize) {
    let at = found.pe.partition_point(|&o| o < off);
    found.pe.insert(at, off);
    if found.pe.len() > cap {
        found.pe.pop();
        found.pe_capped = true;
    }
}

/// An archive header at `off` that holds up, as [`crate::unpack::detect_archive_start`]
/// checks one, gzip's more strictly. A candidate past a cap makes the object
/// `LIMITS-EXCEEDED`, so chance matches must not fill the caps: gzip's 27 fixed
/// bits occur about 32 times in 4 GiB of random data, so its `XFL` (0, 2 or 4)
/// and `OS` (0 to 13, or 255, per RFC 1952) are checked too.
fn archive_at(data: &dyn ByteSource, off: usize) -> bool {
    let sub = crate::byte_source::Sub::new(data, off, data.len() - off);
    match crate::unpack::detect_archive_start(&sub) {
        Some(crate::unpack::Format::Gzip) => {
            let head = data.window(off, 10);
            head.len() == 10 && matches!(head[8], 0 | 2 | 4) && matches!(head[9], 0..=13 | 255)
        }
        Some(_) => true,
        None => false,
    }
}

/// An `MZ` at `off` whose `e_lfanew` points to a sane `PE\0\0` header: what
/// carving finds, one candidate at a time, for the tests to compare it to.
#[cfg(test)]
fn pe_at(data: &dyn ByteSource, off: usize) -> bool {
    pe_target(data, off).is_some_and(|pe| pe_header_at(data, pe))
}

/// Where the `MZ` at `off` says its PE header is, if that is in bounds.
fn pe_target(data: &dyn ByteSource, off: usize) -> Option<usize> {
    if off + 0x40 > data.len() {
        return None;
    }
    let e_lfanew = le_u32_at(data, off + 0x3c)? as usize;
    // e_lfanew is relative to the MZ; the PE header must be in-bounds.
    let pe = off.checked_add(e_lfanew)?;
    (e_lfanew >= 0x40 && pe + 4 <= data.len()).then_some(pe)
}

/// A sane `PE\0\0` header at `pe`.
fn pe_header_at(data: &dyn ByteSource, pe: usize) -> bool {
    data.window(pe, 4)[..] == *b"PE\0\0" && valid_pe_coff(data, pe)
}

/// A validated ELF identification header at `off`: class, data and version,
/// and a plausible `e_type`.
fn elf_at(data: &dyn ByteSource, off: usize) -> bool {
    let h = data.window(off, 18);
    if h.len() != 18 {
        return false;
    }
    let class = h[4]; // EI_CLASS: 1=32-bit, 2=64-bit
    let endian = h[5]; // EI_DATA: 1=LE, 2=BE
    let version = h[6]; // EI_VERSION: 1
    if !matches!(class, 1 | 2) || !matches!(endian, 1 | 2) || version != 1 {
        return false;
    }
    // e_type at offset 16 (2 bytes, endianness per EI_DATA): REL/EXEC/DYN/CORE.
    let etype = if endian == 1 {
        u16::from_le_bytes([h[16], h[17]])
    } else {
        u16::from_be_bytes([h[16], h[17]])
    };
    matches!(etype, 1..=4)
}

fn rd_u32(h: &[u8], o: usize, be: bool) -> u32 {
    let b = [h[o], h[o + 1], h[o + 2], h[o + 3]];
    if be {
        u32::from_be_bytes(b)
    } else {
        u32::from_le_bytes(b)
    }
}

/// A thin Mach-O header at `off` with a sane `filetype` and `ncmds`.
fn macho_thin_at(data: &dyn ByteSource, off: usize, be: bool) -> bool {
    let h = data.window(off, 28);
    if h.len() != 28 {
        return false;
    }
    let filetype = rd_u32(&h, 12, be); // MH_OBJECT..MH_KEXT_BUNDLE
    let ncmds = rd_u32(&h, 16, be);
    (1..=11).contains(&filetype) && (1..=10_000).contains(&ncmds)
}

/// A fat Mach-O header at `off`: a sane arch count and a real `cputype`
/// first, which a Java `.class` (the same magic) does not have.
fn macho_fat_at(data: &dyn ByteSource, off: usize) -> bool {
    let h = data.window(off, 28);
    if h.len() != 28 {
        return false;
    }
    let nfat = rd_u32(&h, 4, true);
    let cputype0 = rd_u32(&h, 8, true);
    (1..=64).contains(&nfat) && is_macho_cputype(cputype0)
}

/// Offsets of PE images embedded at a **non-zero** offset (an `MZ` whose
/// `e_lfanew` points to a `PE\0\0` header within bounds). File-infectors and
/// droppers append/embed executables this way; scanning them is needed to match
/// signatures (incl. section hashes) the same way ClamAV does.
/// The image at offset 0, if any, is handled by the normal scan and skipped.
pub fn embedded_pe_offsets(data: &[u8]) -> Vec<usize> {
    embedded_pe_offsets_in(&data)
}

/// [`embedded_pe_offsets`] over an object that need not be held in memory.
pub(crate) fn embedded_pe_offsets_in(data: &dyn ByteSource) -> Vec<usize> {
    embedded_in(data, CarveCaps::default()).pe
}

/// The little-endian `u32` at `at`, if the object holds it.
fn le_u32_at(data: &dyn ByteSource, at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.window(at, 4)[..].try_into().ok()?))
}

/// A carved `MZ…PE\0\0` region is treated as a scannable embedded PE only when
/// its COFF + optional header pass basic structural sanity. Without this, any
/// bytes in a compressed/encrypted stream that merely contain the `MZ` and
/// `PE\0\0` markers get carved and scanned as a bogus PE, where a short
/// entry-point-anchored signature can false-positive on the garbage, since
/// [`layout`] still computes an "entry" from the junk section table. ClamAV
/// gates embedded-PE extraction the same way. `pe` is the offset of `PE\0\0`.
fn valid_pe_coff(data: &dyn ByteSource, pe: usize) -> bool {
    // 20-byte COFF header after `PE\0\0`, then the optional-header magic.
    if pe + 26 > data.len() {
        return false;
    }
    let h = data.window(pe, 26);
    if h.len() != 26 {
        return false;
    }
    let rd16 = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]);
    let machine = rd16(4);
    let n_sections = rd16(6);
    let opt_size = rd16(20);
    let magic = rd16(24);
    // Machine must be set, section count within the PE-spec maximum (96), an
    // optional header must be present, and its magic must be PE32 (0x10b) or
    // PE32+ (0x20b). Random data clears all four only vanishingly rarely.
    machine != 0 && (1..=96).contains(&n_sections) && opt_size != 0 && matches!(magic, 0x10b | 0x20b)
}

/// Offsets of ELF images embedded at a **non-zero** offset (a validated
/// `\x7fELF` identification header). Linux file-infectors and droppers append or
/// embed ELF payloads the same way Windows ones embed PE; carving them lets the
/// engine re-type the payload as ELF so `Target:6` and ELF-specific signatures
/// match at the embedded offset. Validated (class/data/version + a plausible
/// `e_type`) so a coincidental `\x7fELF` byte run is not carved. The image at
/// offset 0, if any, is handled by the normal scan and skipped.
pub fn embedded_elf_offsets(data: &[u8]) -> Vec<usize> {
    embedded_elf_offsets_in(&data)
}

/// [`embedded_elf_offsets`] over an object that need not be held in memory.
pub(crate) fn embedded_elf_offsets_in(data: &dyn ByteSource) -> Vec<usize> {
    embedded_in(data, CarveCaps::default()).elf
}

/// A Mach-O `cputype` we accept when validating a fat/universal header (used to
/// tell a real fat Mach-O from a Java `.class`, which shares the `CA FE BA BE`
/// magic). x86/x86_64/arm/arm64/arm64_32/ppc/ppc64.
fn is_macho_cputype(ct: u32) -> bool {
    matches!(
        ct,
        7 | 0x0100_0007 | 12 | 0x0100_000C | 0x0200_000C | 18 | 0x0100_0012
    )
}

/// Offsets of Mach-O images embedded at a **non-zero** offset. macOS malware is
/// commonly carried inside cross-platform droppers/archives; carving lets the
/// engine re-type the payload so Mach-O signatures match at the embedded offset.
/// Handles thin images (32/64-bit, both byte orders) and fat/universal images,
/// each validated (thin: a sane `filetype` + `ncmds`; fat: `nfat_arch` range and
/// a real `cputype` for the first arch) so a coincidental magic byte run (in
/// particular a Java `.class`, which also begins `CA FE BA BE`) is not carved.
/// The image at offset 0, if any, is handled by the normal scan and skipped.
pub fn embedded_macho_offsets(data: &[u8]) -> Vec<usize> {
    embedded_macho_offsets_in(&data)
}

/// [`embedded_macho_offsets`] over an object that need not be held in memory.
pub(crate) fn embedded_macho_offsets_in(data: &dyn ByteSource) -> Vec<usize> {
    embedded_in(data, CarveCaps::default()).macho
}

/// Offsets (> 0) where a supported container's magic appears: an archive
/// appended to or embedded in another file: SFX stubs, PE overlays (data after
/// the last section), and droppers that staple a ZIP/CAB/7z/RAR/ARJ/GZIP/XZ onto
/// a carrier. The normal scan only types the buffer at offset 0, so these embedded
/// containers are invisible without carving. A candidate counts only if its
/// header checks out (see `archive_at`), so a coincidental magic byte-run isn't
/// treated as a real archive. Bounded to keep a buffer full of archive headers
/// from blowing up the work.
pub fn embedded_archive_offsets(data: &[u8]) -> Vec<usize> {
    embedded_archive_offsets_in(&data)
}

/// [`embedded_archive_offsets`] over an object that need not be held in memory.
pub(crate) fn embedded_archive_offsets_in(data: &dyn ByteSource) -> Vec<usize> {
    embedded_in(data, CarveCaps::default()).archives
}

/// Whether `src` holds a UPX pack header, as [`crate::unpack::is_upx`] finds
/// one: in its start, where UPX writes it. `false` where UPX is not compiled
/// in.
pub(crate) fn upx_header_in(src: &dyn ByteSource) -> bool {
    crate::unpack::is_upx_source(src)
}

/// Whether `is_upx` can say yes in this build.
#[cfg(test)]
pub(crate) fn upx_compiled_in() -> bool {
    static YES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *YES.get_or_init(|| {
        let mut sample = [0u8; 40];
        sample[4..8].copy_from_slice(b"UPX!");
        for at in [16, 24, 28] {
            sample[at] = 1;
        }
        crate::unpack::is_upx(&sample)
    })
}

/// `(raw_size, section_bytes)` for each PE section, for `.mdb`/`.msb`
/// section-hash matching. The caller computes whatever digests it needs (so
/// SHA can be skipped when no `.msb` signatures are loaded). Empty if `data`
/// is not a parseable PE.
pub fn section_slices(data: &[u8]) -> Vec<(u64, &[u8])> {
    let Some(pe) = headers(data) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(pe.sections.len());
    for s in &pe.sections {
        let start = s.pointer_to_raw_data as usize;
        let len = s.size_of_raw_data as usize;
        if len == 0 || start >= data.len() {
            continue;
        }
        // Clamp to the bytes actually present rather than dropping the section:
        // overlay-trimmed / truncated PEs declare a raw size that overruns EOF,
        // and dropping them would lose section-hash detections. The size key is
        // the declared raw size; the hash is over the available bytes.
        let end = start.saturating_add(len).min(data.len());
        out.push((len as u64, &data[start..end]));
    }
    out
}

/// Whether an ELF's section-header table has been stripped: `e_shentsize` is
/// zero, so the table cannot be walked at all.
///
/// This is NOT breakage. Section headers are optional for execution: the program
/// headers are what the loader reads, and these binaries run. It is, however,
/// deliberate: no toolchain emits a zero entry size, and it is a standard
/// anti-analysis step (86 of 87 such files in the corpus were UPX-packed with the
/// section table blanked afterwards). So it is worth reporting, under a name that
/// says what was actually found.
///
/// Deliberately narrow, and measured: over 1,120 corpus ELFs this separates
/// cleanly from the neighbouring conditions: 87 files have a zeroed entry size,
/// 173 have `e_shnum == 0` with a canonical entry size (an ordinary way to say
/// "no sections", not flagged), and 21 have a section table running past EOF
/// (genuine breakage, caught by [`looks_broken`], as is a nonzero entry size
/// of the wrong length).
pub fn elf_section_headers_stripped(data: &[u8]) -> bool {
    elf_section_headers_stripped_in(&data)
}

/// [`elf_section_headers_stripped`] over an object that need not be held in
/// memory.
pub(crate) fn elf_section_headers_stripped_in(src: &dyn ByteSource) -> bool {
    let h = src.window(0, 64);
    if !h.starts_with(b"\x7fELF") {
        return false;
    }
    // `e_shentsize`, placed by the class. Zero reads the same in either byte
    // order.
    let off = match h.get(4) {
        Some(1) => 46,
        Some(2) => 58,
        _ => return false,
    };
    crate::bytes::at(&h, off, 2) == Some(&[0, 0][..])
}

#[cfg(test)]
mod tests {
    use goblin::pe::PE;

    use super::*;

    /// A section's raw pointer is the file's: an address inside it whose raw
    /// offset does not fit in 32 bits has no raw address, rather than a panic.
    #[test]
    fn rawaddr_past_the_top_of_u32_is_absent_not_a_panic() {
        let pe = BcPe {
            sections: vec![BcPeSection { rva: 0x1000, vsz: 0x1000, raw: 0xFFFF_FF00, rsz: 0x1000, chr: 0 }],
            hdr_size: 0x200,
            pedata: Vec::new(),
        };
        assert_eq!(pe.rawaddr(0x1010, 0x10000), Some(0xFFFF_FF10));
        assert_eq!(pe.rawaddr(0x1200, 0x10000), None);
    }

    /// Header offsets near the top of u64 are the file's to claim: the table
    /// they name is past the file, not an overflow.
    #[test]
    fn elf_table_offsets_near_the_top_of_u64_are_absent_not_a_panic() {
        for off in [u64::MAX, u64::MAX - 1, u64::MAX - 8, u64::MAX - 40] {
            let mut elf = vec![0u8; 120];
            elf[..4].copy_from_slice(b"\x7fELF");
            elf[4] = 2;
            elf[5] = 1;
            elf[32..40].copy_from_slice(&off.to_le_bytes());
            elf[40..48].copy_from_slice(&off.to_le_bytes());
            // e_phentsize, e_phnum, e_shentsize, e_shnum
            for (at, v) in [(54, 56u16), (56, 2), (58, 64), (60, 2)] {
                elf[at..at + 2].copy_from_slice(&v.to_le_bytes());
            }
            assert!(elf_broken(&elf.as_slice()), "{off:#x}");
            let layout = elf_layout(&elf.as_slice()).unwrap();
            assert!(layout.section_rawptrs.is_empty(), "{off:#x}");
        }
    }

    /// One read finds what looking for each magic at every offset finds:
    /// every validated image and archive candidate, in order and within its
    /// cap, whatever window seam it straddles, in memory and read through a
    /// cache of small blocks.
    #[test]
    fn one_read_finds_every_embedded_candidate() {
        use crate::byte_source::{BlockCache, CHUNK};
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut data: Vec<u8> = (0..7 * CHUNK + 77)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b"abcdefgh"[(state % 8) as usize]
            })
            .collect();
        let mut put = |at: usize, bytes: &[u8]| data[at..at + bytes.len()].copy_from_slice(bytes);
        let mut elf = b"\x7fELF\x02\x01\x01".to_vec();
        elf.resize(16, 0);
        elf.extend_from_slice(&2u16.to_le_bytes());
        let mut pe = b"MZ".to_vec();
        pe.resize(0x3c, 0);
        pe.extend_from_slice(&0x40u32.to_le_bytes());
        pe.extend_from_slice(b"PE\0\0\x4c\x01\x03\0");
        pe.resize(0x40 + 20, 0);
        pe.extend_from_slice(&0xe0u16.to_le_bytes());
        pe.extend_from_slice(&[0, 0, 0x0b, 0x01]);
        let mut thin = vec![0xCF, 0xFA, 0xED, 0xFE];
        thin.resize(12, 0);
        thin.extend_from_slice(&2u32.to_le_bytes());
        thin.extend_from_slice(&5u32.to_le_bytes());
        thin.resize(28, 0);
        let mut fat = b"\xCA\xFE\xBA\xBE".to_vec();
        fat.extend_from_slice(&2u32.to_be_bytes());
        fat.extend_from_slice(&7u32.to_be_bytes());
        fat.resize(28, 0);
        put(0, &pe);
        for seam in 1..7 {
            let at = seam * CHUNK;
            put(at - 3, [&elf, &pe, &thin, &fat, &elf, &pe][seam - 1]);
            put(at - 700, b"Rar!\x1a\x07");
            put(at + 900, b"\xfd7zXZ\x00");
        }
        for k in 0..40 {
            put(100 + k * 90, b"PK\x03\x04");
        }
        // Every candidate, one offset at a time, and the cap of its kind.
        let caps = CarveCaps::default();
        let mut want = Embedded::default();
        for off in 1..data.len() {
            for (magic, kind) in CARVE_MAGICS {
                if !data[off..].starts_with(magic) {
                    continue;
                }
                let d: &dyn ByteSource = &&data[..];
                let (list, cap, ok) = match kind {
                    Magic::Pe => (&mut want.pe, caps.executables, pe_at(d, off)),
                    Magic::Elf => (&mut want.elf, caps.executables, elf_at(d, off)),
                    Magic::MachoThin(be) => (&mut want.macho, caps.executables, macho_thin_at(d, off, be)),
                    Magic::MachoFat => (&mut want.macho, caps.executables, macho_fat_at(d, off)),
                    Magic::Archive => (&mut want.archives, caps.archives, archive_at(d, off)),
                };
                if ok && list.len() < cap {
                    list.push(off);
                } else if ok && matches!(kind, Magic::Pe) {
                    want.pe_capped = true;
                } else if ok {
                    want.others_capped = true;
                }
            }
        }
        assert_eq!((want.pe.len(), want.elf.len(), want.macho.len()), (2, 2, 2));
        assert_eq!(want.archives.len(), caps.archives);
        assert!(want.others_capped && !want.pe_capped);
        let src = BlockCache::with_sizes(std::io::Cursor::new(data.clone()), 512, 4096).unwrap();
        let slice: &[u8] = &data;
        for hay in [&slice as &dyn ByteSource, &src] {
            let got = embedded_in(hay, caps);
            assert_eq!(got.pe, want.pe);
            assert_eq!(got.elf, want.elf);
            assert_eq!(got.macho, want.macho);
            assert_eq!(got.archives, want.archives);
            assert_eq!((got.pe_capped, got.others_capped), (want.pe_capped, want.others_capped));
        }
    }

    /// An `MZ` points its header anywhere in the object. Over a source that
    /// is not in memory, those headers are checked in order, so many
    /// candidates cost about one pass over the object and not a block read
    /// each, and a real header far from its `MZ` is still found.
    #[test]
    fn far_headers_are_read_in_order() {
        use crate::byte_source::BlockCache;
        use std::sync::atomic::{AtomicU64, Ordering};
        struct Tally(std::io::Cursor<Vec<u8>>, std::sync::Arc<AtomicU64>);
        impl std::io::Read for Tally {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.1.fetch_add(1, Ordering::Relaxed);
                self.0.read(buf)
            }
        }
        impl std::io::Seek for Tally {
            fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
                self.0.seek(p)
            }
        }
        const BLOCK: usize = 4096;
        let len = 1024 * BLOCK;
        let mut data = vec![b'a'; len];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        // Candidates whose headers are somewhere else in the object.
        for k in 0..8000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let off = 1000 + k * 500;
            let to = 0x40 + (state as usize % (len - off - 0x80));
            data[off..off + 2].copy_from_slice(b"MZ");
            data[off + 0x3c..off + 0x40].copy_from_slice(&(to as u32).to_le_bytes());
        }
        // A real one, whose header is 3 MiB on.
        let at = 100;
        let header = at + (3 << 20);
        data[at..at + 2].copy_from_slice(b"MZ");
        data[at + 0x3c..at + 0x40].copy_from_slice(&(3u32 << 20).to_le_bytes());
        let mut pe = b"PE\0\0\x4c\x01\x03\0".to_vec();
        pe.resize(20, 0);
        pe.extend_from_slice(&0xe0u16.to_le_bytes());
        pe.extend_from_slice(&[0, 0, 0x0b, 0x01]);
        data[header..header + pe.len()].copy_from_slice(&pe);

        let reads = std::sync::Arc::new(AtomicU64::new(0));
        let src = BlockCache::with_sizes(Tally(std::io::Cursor::new(data), reads.clone()), BLOCK, 8 * BLOCK).unwrap();
        let found = embedded_in(&src, CarveCaps::default());
        assert_eq!(found.pe, [at]);
        assert!(!found.pe_capped);
        let reads = reads.load(Ordering::Relaxed) as usize;
        let blocks = len / BLOCK;
        assert!(reads <= 3 * blocks, "{reads} reads for {blocks} blocks");
    }

    /// A chance `1f 8b 08` run is not a gzip candidate unless the header's
    /// `XFL` and `OS` hold up, so random data cannot fill the archive cap and
    /// make an object `LIMITS-EXCEEDED`.
    #[test]
    fn gzip_candidates_need_a_plausible_header() {
        let mut data = vec![b'x'; 64 * 40];
        for k in 1..40 {
            let at = k * 64;
            // Flags 0 and an MTIME, then XFL 0x77 and OS 0x80: no gzip writer's.
            data[at..at + 10].copy_from_slice(&[0x1f, 0x8b, 0x08, 0, 1, 2, 3, 4, 0x77, 0x80]);
        }
        let caps = CarveCaps::default();
        let found = embedded_in(&&data[..], caps);
        assert!(found.archives.is_empty() && !found.others_capped);
        // The same headers with XFL 2 and OS 3 (Unix) are candidates.
        for k in 1..40 {
            let at = k * 64;
            data[at + 8] = 2;
            data[at + 9] = 3;
        }
        let found = embedded_in(&&data[..], caps);
        assert_eq!(found.archives.len(), caps.archives);
        assert!(found.others_capped);
    }

    /// A ZIP local header for an entry named `name` holding `len` bytes, with
    /// the general-purpose `flags` and a declared compressed size of `csize`,
    /// followed by `len` bytes of data.
    fn zip_entry(name: &str, flags: u16, csize: u32, len: usize) -> Vec<u8> {
        let mut e = b"PK\x03\x04\x14\0".to_vec();
        e.extend_from_slice(&flags.to_le_bytes());
        e.extend_from_slice(&[0, 0, 0, 0, 0x21, 0, 0, 0, 0, 0]);
        e.extend_from_slice(&csize.to_le_bytes());
        e.extend_from_slice(&(len as u32).to_le_bytes());
        e.extend_from_slice(&(name.len() as u16).to_le_bytes());
        e.extend_from_slice(&[0, 0]);
        e.extend_from_slice(name.as_bytes());
        e.extend_from_slice(&vec![b'.'; len]);
        e
    }

    /// `entries` entries of a ZIP (each declaring its size truthfully) after a
    /// text prefix.
    fn zip_after_prefix(entries: usize, flags: u16) -> (Vec<u8>, usize) {
        let mut data = b"a carrier with a zip stapled inside it\n".to_vec();
        let first = data.len();
        for k in 0..entries {
            data.extend(zip_entry(&format!("m{k}"), flags, 20, 20));
        }
        (data, first)
    }

    /// The entries of one ZIP stapled into an object are read when the ZIP is,
    /// so only the first is a candidate: they neither fill the cap nor are the
    /// object rescanned once per entry.
    #[test]
    fn the_entries_of_a_zip_are_not_archives_of_their_own() {
        let caps = CarveCaps::default();
        let (data, first) = zip_after_prefix(caps.archives * 2, 0);
        let found = embedded_in(&&data[..], caps);
        assert_eq!(found.archives, [first]);
        assert!(!found.others_capped);
    }

    /// A ZIP that is the object itself: every header after its own is an entry.
    #[test]
    fn the_entries_of_a_zip_at_offset_zero_are_not_archives_of_their_own() {
        let (data, first) = zip_after_prefix(40, 0);
        let found = embedded_in(&&data[first..], CarveCaps::default());
        assert!(found.archives.is_empty() && !found.others_capped);
    }

    /// Where the header does not say where the next entry begins, each header
    /// stays a candidate: a data descriptor, encryption or ZIP64's size leaves
    /// the position unknown.
    #[test]
    fn a_header_that_cannot_place_the_next_one_keeps_every_candidate() {
        for flags in [0b1000, 0b0001] {
            let (data, _) = zip_after_prefix(5, flags);
            let found = embedded_in(&&data[..], CarveCaps::default());
            assert_eq!(found.archives.len(), 5, "flags {flags:#b}");
        }
        let mut data = b"carrier\n".to_vec();
        for k in 0..5 {
            data.extend(zip_entry(&format!("m{k}"), 0, u32::MAX, 20));
        }
        let found = embedded_in(&&data[..], CarveCaps::default());
        assert_eq!(found.archives.len(), 5, "ZIP64 size");
    }

    /// A header that names a size that does not lead to the next header does
    /// not hide it: a second archive placed anywhere else is still a
    /// candidate.
    #[test]
    fn a_size_that_misses_the_next_header_keeps_it_a_candidate() {
        let mut data = b"carrier\n".to_vec();
        let first = data.len();
        // Declares 10 bytes of data, holds 20: the chain lands inside them.
        data.extend(zip_entry("a", 0, 10, 20));
        let second = data.len();
        data.extend(zip_entry("b", 0, 20, 20));
        let found = embedded_in(&&data[..], CarveCaps::default());
        assert_eq!(found.archives, [first, second]);
    }

    #[test]
    fn embedded_macho_carved_and_java_rejected() {
        // A 64-bit LE Mach-O executable header (MH_MAGIC_64 = CF FA ED FE) at a
        // non-zero offset.
        let mut macho = vec![0u8; 0x40];
        macho[..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        macho[12..16].copy_from_slice(&2u32.to_le_bytes()); // filetype = MH_EXECUTE
        macho[16..20].copy_from_slice(&20u32.to_le_bytes()); // ncmds
        let mut blob = vec![0x90u8; 200];
        blob.extend_from_slice(&macho);
        assert_eq!(embedded_macho_offsets(&blob), vec![200]);

        // A Java class file shares the fat magic CA FE BA BE but has a large
        // pseudo-`nfat_arch` / non-Mach-O cputype, so it must NOT be carved.
        let mut java = vec![0x11u8; 64];
        java[..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        java[4..8].copy_from_slice(&0x0000_0034u32.to_be_bytes()); // minor/major = Java 8
        let mut jblob = vec![0u8; 100];
        jblob.extend_from_slice(&java);
        assert!(embedded_macho_offsets(&jblob).is_empty());
    }

    #[test]
    fn embedded_elf_carved_and_validated() {
        // A 64-bit LE ELF executable header embedded after some prefix bytes.
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // class 64
        elf[5] = 1; // little-endian
        elf[6] = 1; // version
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = EXEC
        let mut buf = vec![0xAA; 100];
        buf.extend_from_slice(&elf);
        assert_eq!(embedded_elf_offsets(&buf), vec![100]);
        // A bare `\x7fELF` with a junk identification header must NOT be carved.
        let mut junk = vec![0xAA; 50];
        junk.extend_from_slice(b"\x7fELF\xff\xff\xff and random text after");
        assert!(embedded_elf_offsets(&junk).is_empty());
        // An ELF at offset 0 is left to the normal scan (not re-carved).
        assert!(embedded_elf_offsets(&elf).is_empty());
    }

    /// An ARJ is carved where the CRC-32 of its main header holds, wherever it
    /// sits against the windows the object is read in. A stray `60 EA`, even
    /// with a size that could be a header's, is not one.
    #[cfg(feature = "arj")]
    #[test]
    fn an_embedded_arj_is_carved_by_its_header_crc() {
        use crate::byte_source::{BlockCache, CHUNK};
        let arj: &[u8] = include_bytes!("../../exav-unpack/tests/fixtures/sample.arj");
        let size = usize::from(u16::from_le_bytes([arj[2], arj[3]]));
        for at in [1, 100, CHUNK - 1, CHUNK - 20, CHUNK, CHUNK + 1] {
            let mut data = vec![b'a'; 2 * CHUNK + arj.len()];
            for stray in [50, CHUNK / 2, CHUNK + 700] {
                if stray.abs_diff(at) > 4 {
                    data[stray..stray + 4].copy_from_slice(&[0x60, 0xEA, 0x2A, 0x00]);
                }
            }
            data[at..at + arj.len()].copy_from_slice(arj);
            assert_eq!(embedded_archive_offsets(&data), [at], "at {at}");
            let cache = BlockCache::with_sizes(std::io::Cursor::new(data.clone()), 512, 4096).unwrap();
            assert_eq!(embedded_archive_offsets_in(&cache), [at], "at {at}, in a cache");
            // The CRC changed: not an ARJ.
            data[at + 4 + size] ^= 1;
            assert!(embedded_archive_offsets(&data).is_empty(), "at {at}, bad CRC");
        }
    }

    #[test]
    fn embedded_pe_offsets_no_panic_on_tiny_input() {
        // Regression: `&data[1..]` panicked on an empty/sub-header buffer.
        for n in 0..0x41 {
            assert!(embedded_pe_offsets(&vec![b'M'; n]).is_empty() || n >= 0x40);
        }
        assert!(embedded_pe_offsets(b"").is_empty());
    }

    #[test]
    fn embedded_pe_carve_requires_valid_coff() {
        // A real minimal PE embedded after a prefix IS carved.
        let pe = minimal_pe(b"abcdefgh");
        let mut buf = vec![0xAAu8; 128];
        buf.extend_from_slice(&pe);
        assert_eq!(embedded_pe_offsets(&buf), vec![128]);

        // Regression (the Zbot FP family): `MZ` … `PE\0\0` followed by a junk
        // COFF header (zero machine, no optional header, bogus magic) must NOT be
        // carved, otherwise compressed/encrypted bytes that merely contain those
        // markers get scanned as a bogus PE, where a short entry-point-anchored
        // signature false-positives on the garbage.
        let mut junk = vec![0u8; 0x80];
        junk[0] = b'M';
        junk[1] = b'Z';
        junk[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew -> 0x40
        junk[0x40..0x44].copy_from_slice(b"PE\0\0"); // COFF beyond is all zero
        let mut buf2 = vec![0xAAu8; 64];
        buf2.extend_from_slice(&junk);
        assert!(embedded_pe_offsets(&buf2).is_empty());
    }

    /// Build a minimal PE32+ with one `.text` section holding `section`.
    fn minimal_pe(section: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
        v[0x40..0x44].copy_from_slice(b"PE\0\0");
        let coff = 0x44;
        v[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x86-64
        v[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        v[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // opt hdr size
        v[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // characteristics
        let opt = 0x58;
        v[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        v[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        v[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // base of code
        v[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // image base
        v[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section align
        v[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
        v[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        v[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        v[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem
        v[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        let sh = 0x148;
        v[sh..sh + 5].copy_from_slice(b".text");
        v[sh + 8..sh + 12].copy_from_slice(&(section.len() as u32).to_le_bytes()); // virtual size
        v[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
        v[sh + 16..sh + 20].copy_from_slice(&(section.len() as u32).to_le_bytes()); // raw size
        v[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes()); // ptr to raw data
        v[sh + 36..sh + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // characteristics
        v.extend_from_slice(section); // raw section data at 0x200
        v
    }

    #[test]
    fn section_hashes_of_minimal_pe() {
        let body = b"some .text section bytes";
        let pe = minimal_pe(body);
        let slices = section_slices(&pe);
        assert_eq!(slices.len(), 1, "expected one section");
        assert_eq!(slices[0].0, body.len() as u64);
        assert_eq!(slices[0].1, body);
        assert_eq!(
            encode_hex(&Md5::digest(slices[0].1)),
            encode_hex(&Md5::digest(body))
        );
    }

    #[test]
    fn section_hashes_non_pe_is_empty() {
        assert!(section_slices(b"not a pe").is_empty());
    }

    #[test]
    fn layout_of_minimal_pe() {
        let pe = minimal_pe(b"abcdefgh");
        let l = layout(&pe).unwrap();
        assert_eq!(l.section_rawptrs, vec![0x200]);
        // entry RVA 0x1000 falls in the section at VA 0x1000 / file 0x200.
        assert_eq!(l.entry, Some(0x200));
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[0u8; 1000]), 0.0); // all same byte
        let mut all = Vec::new();
        for b in 0..=255u8 {
            all.extend(std::iter::repeat_n(b, 16));
        }
        let h = shannon_entropy(&all);
        assert!(h > 7.9 && h <= 8.0, "uniform bytes ~8 bits, got {h}");
    }

    #[test]
    fn non_pe_returns_none() {
        assert!(analyze(b"not a pe file at all").is_none());
    }

    #[test]
    fn bytecode_pe_sections_and_rawaddr() {
        let pe = minimal_pe(b"abcdefgh");
        let bc = bytecode_pe(&pe).unwrap();
        assert_eq!(bc.sections.len(), 1);
        let s = bc.sections[0];
        assert_eq!((s.rva, s.raw), (0x1000, 0x200));
        // RVA inside the section maps to its raw offset.
        assert_eq!(bc.rawaddr(0x1000, pe.len()), Some(0x200));
        assert_eq!(bc.rawaddr(0x1004, pe.len()), Some(0x204));
        // An RVA in no section and past the header is unmapped.
        assert_eq!(bc.rawaddr(0x9_0000, pe.len()), None);
    }

    #[test]
    fn pedata_image_key_fields() {
        let pe = minimal_pe(b"abcdefgh");
        let bc = bytecode_pe(&pe).unwrap();
        let pd = &bc.pedata;
        let rd16 = |o: usize| u16::from_le_bytes([pd[o], pd[o + 1]]);
        let rd32 = |o: usize| u32::from_le_bytes([pd[o], pd[o + 1], pd[o + 2], pd[o + 3]]);
        assert_eq!(rd16(8), 1); // nsections
        assert_eq!(rd32(632), 0x40); // e_lfanew
        assert_eq!(rd16(264), 0x20b); // opt64 Magic (PE32+)
        assert_eq!(rd32(280), 0x1000); // opt64 AddressOfEntryPoint
        assert_eq!(rd32(644), 0x200); // hdr_size (SizeOfHeaders)
    }

    /// Each data directory lands in its own slot, whichever are absent, and
    /// the reserved 16th one (which goblin's `dirs()` panics on) is copied too.
    #[test]
    fn pedata_data_directories_keep_their_index() {
        let set_dir = |pe: &mut Vec<u8>, i: usize, rva: u32, size: u32| {
            let at = 0x58 + 112 + i * 8;
            pe[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            pe[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
        };
        let mut pe = minimal_pe(b"abcdefgh");
        set_dir(&mut pe, 8, 0x1004, 4); // GlobalPtr, not parsed by goblin
        set_dir(&mut pe, 15, 0x1008, 8); // reserved
        let bc = bytecode_pe(&pe).expect("parses");
        let pd = &bc.pedata;
        let rd32 = |o: usize| u32::from_le_bytes([pd[o], pd[o + 1], pd[o + 2], pd[o + 3]]);
        for base in [376, 504] {
            assert_eq!(rd32(base), 0, "slot 0 stays empty");
            assert_eq!((rd32(base + 64), rd32(base + 68)), (0x1004, 4));
            assert_eq!((rd32(base + 120), rd32(base + 124)), (0x1008, 8));
        }
    }

    /// From a live DLL in an MSI: a certificate table sized past the end of the
    /// file fails goblin's full parse. Its bytecode PE data was missing, so
    /// every bytecode program reading it left the scan `LIMITS-EXCEEDED`, and
    /// its section hashes were never computed. None of them reads a directory.
    #[test]
    fn a_malformed_certificate_table_leaves_the_pe_readable() {
        let body = b"abcdefgh";
        let mut pe = minimal_pe(body);
        let at = 0x58 + 112 + 4 * 8; // the certificate table's directory entry
        pe[at..at + 4].copy_from_slice(&0x200u32.to_le_bytes());
        pe[at + 4..at + 8].copy_from_slice(&2_409_852_894u32.to_le_bytes());
        assert!(PE::parse(&pe).is_err(), "the full parse refuses it");
        assert_eq!(bytecode_pe(&pe).expect("parses").sections.len(), 1);
        assert_eq!(section_slices(&pe), vec![(body.len() as u64, &body[..])]);
        assert_eq!(layout(&pe).expect("parses").entry, Some(0x200));
        assert!(analyze(&pe).is_some(), "and its imports are read");
    }

    /// Noise with embedded images and archive magics planted at `spots`, some
    /// valid and some a byte off.
    fn carrier(len: usize, spots: &[usize]) -> Vec<u8> {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut d: Vec<u8> = (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b"MZPE\x7fELF\xca\xfe\xba\xbe\x00\x01\x02 x"[(state % 16) as usize]
            })
            .collect();
        for (k, &at) in spots.iter().enumerate() {
            let mut img = vec![0u8; 0x80];
            match k % 5 {
                0 => {
                    img[..2].copy_from_slice(b"MZ");
                    img[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
                    img[0x40..0x44].copy_from_slice(b"PE\0\0");
                    img[0x44..0x46].copy_from_slice(&0x14cu16.to_le_bytes());
                    img[0x46..0x48].copy_from_slice(&(1 + k as u16 % 3).to_le_bytes());
                    img[0x54..0x56].copy_from_slice(&0xe0u16.to_le_bytes());
                    img[0x58..0x5a].copy_from_slice(&0x10bu16.to_le_bytes());
                }
                1 => img[..18].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0"),
                2 => img[..20].copy_from_slice(b"\xcf\xfa\xed\xfe\x07\0\0\x01\x03\0\0\0\x02\0\0\0\x05\0\0\0"),
                3 => img[..12].copy_from_slice(b"\xca\xfe\xba\xbe\0\0\0\x02\0\0\0\x07"),
                _ => img[..4].copy_from_slice(if k % 2 == 0 { b"PK\x03\x04" } else { b"MSCF" }),
            }
            let at = at.min(len - img.len());
            d[at..at + img.len()].copy_from_slice(&img);
        }
        d
    }

    #[test]
    fn carving_offsets_are_the_same_read_in_blocks() {
        use crate::byte_source::{BlockCache, CHUNK};
        // Each kind straddling a chunk seam at several splits, and some
        // images whose headers run past the end.
        let mut spots = Vec::new();
        for k in 0..60 {
            spots.push((k + 1) * CHUNK - (k * 7) % 0x60);
        }
        let d = carrier(62 * CHUNK, &spots);
        let cache = BlockCache::with_sizes(std::io::Cursor::new(d.clone()), 509, 8 * 509).unwrap();
        for (name, f) in [
            ("pe", embedded_pe_offsets_in as fn(&dyn ByteSource) -> Vec<usize>),
            ("elf", embedded_elf_offsets_in),
            ("macho", embedded_macho_offsets_in),
            ("archive", embedded_archive_offsets_in),
        ] {
            let want = f(&d);
            assert!(!want.is_empty(), "{name}: nothing planted was found");
            assert_eq!(f(&cache), want, "{name}");
        }
        // The tail of the object cut through a header.
        for cut in [d.len() - 20, d.len() - 1] {
            let short = &d[..cut];
            let cache = BlockCache::with_sizes(std::io::Cursor::new(short.to_vec()), 509, 8 * 509).unwrap();
            assert_eq!(embedded_pe_offsets_in(&cache), embedded_pe_offsets(short));
            assert_eq!(embedded_elf_offsets_in(&cache), embedded_elf_offsets(short));
        }
    }

    /// A source of `data` read through a cache of small blocks.
    fn cached(data: &[u8]) -> crate::byte_source::BlockCache<std::io::Cursor<Vec<u8>>> {
        crate::byte_source::BlockCache::with_sizes(std::io::Cursor::new(data.to_vec()), 509, 8 * 509).unwrap()
    }

    fn set32(f: &mut [u8], at: usize, v: u32) {
        f[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// The image of a PE ends a page after the start of its last section's
    /// data (as far as an address of the section maps to), the overlay after
    /// it is not part of it, and it is held only if it fits.
    #[test]
    fn the_image_of_a_pe_ends_at_its_last_section() {
        let image = minimal_pe(b"some .text section bytes");
        let mut file = image.clone();
        file.extend(vec![b'z'; 100_000]);
        let cache = cached(&file);
        let slice: &[u8] = &file;
        // The data starts at 0x200 and is 24 bytes: a page from there.
        let end = 0x200 + 0x1000;
        for src in [&slice as &dyn ByteSource, &cache] {
            assert_eq!(
                extent(src, 1 << 20),
                Some(Extent { headers: 0x170, image: end })
            );
            assert_eq!(image_in(src, 1 << 20).as_deref(), Some(&file[..end]));
            assert_eq!(image_in(src, end - 1), None);
            // Headers over the limit are not read, and the image is past it.
            assert_eq!(extent(src, 0x100), Some(Extent { headers: 0x170, image: 0x170 }));
            assert_eq!(image_in(src, 0x100), None);
        }
    }

    /// What the tables hold is in the image, and what no check reads is not:
    /// the tables of the image are those of the whole object, whatever its
    /// debug directory lists.
    #[test]
    fn the_tables_of_the_image_are_those_of_the_whole_object() {
        let mut f = pe_with_imports(2, 3);
        // A debug directory after the tables, which lists a record in the
        // overlay.
        let at = 20 * 3 + 8 * 4 + 24;
        set_dir(&mut f, 6, 0x1000 + at as u32, 28);
        set32(&mut f, 0x200 + at + 12, 2); // CodeView
        set32(&mut f, 0x200 + at + 16, 40); // its size
        set32(&mut f, 0x200 + at + 24, 0x5800); // and where it is
        f.resize(0x6000, 0);
        let image = extent(&&f[..], 1 << 20).unwrap().image;
        assert_eq!(image, 0x200 + 0x1000, "the section's data and a page");
        let (cut, whole) = (&f[..image], &f[..]);
        let (cut, whole) = (tables(cut, usize::MAX).unwrap(), tables(whole, usize::MAX).unwrap());
        assert_eq!(imports_of(&cut).len(), 6);
        assert_eq!(imports_of(&cut), imports_of(&whole));
    }

    /// What else an image holds, and what is not a PE with an image.
    #[test]
    fn the_image_of_a_pe_is_what_its_headers_say_within_the_object() {
        let image = minimal_pe(b"abcdefgh");
        let (opt, sh) = (0x58, 0x148);
        let image_of = |f: &[u8]| extent(&f, 1 << 20).map(|e| e.image);
        assert_eq!(image_of(&image), Some(0x208));
        // `SizeOfHeaders` past the last section's data and the page after it.
        let mut f = image.clone();
        f.resize(0x4000, 0);
        set32(&mut f, opt + 60, 0x2000);
        assert_eq!(image_of(&f), Some(0x2000));
        // The page after the data of a section: as far as an address of it
        // maps, the object permitting.
        let mut f = image.clone();
        f.resize(0x4000, 0);
        assert_eq!(image_of(&f), Some(0x1200));
        f.truncate(0x800);
        assert_eq!(image_of(&f), Some(0x800));
        // A section's data the object does not hold: the image is the object,
        // whatever the top of a 32-bit pointer and size add up to.
        let mut f = image.clone();
        set32(&mut f, sh + 16, u32::MAX);
        set32(&mut f, sh + 20, u32::MAX);
        assert_eq!(image_of(&f), Some(image.len()));
        // A section with no data in the file has no end, whatever its pointer.
        let mut f = image.clone();
        f.resize(0x1000, 0);
        set32(&mut f, sh + 16, 0);
        set32(&mut f, sh + 20, 0xf00);
        assert_eq!(image_of(&f), Some(0x200));
        // The section table cut short by the end of the object, a start that
        // is not a PE's, and a header past the object.
        assert_eq!(image_of(&image[..0x16f]), None);
        assert_eq!(image_of(b"MZ"), None);
        assert_eq!(image_of(b"not a pe at all, but long enough to hold a DOS header, which it lacks"), None);
        let mut f = image.clone();
        set32(&mut f, 0x3c, 0x10000);
        assert_eq!(image_of(&f), None);
        // The headers are in the image however far from the start: here after
        // 64 KiB of DOS stub, where they are over a small limit.
        let mut f = image[..0x40].to_vec();
        f.resize(0x10000, 0);
        f.extend_from_slice(&image[0x40..]);
        set32(&mut f, 0x3c, 0x10000);
        let far = Extent { headers: 0x10000 + 0x130, image: 0x10000 + 0x130 };
        assert_eq!(extent(&f, 1 << 20), Some(far));
        assert_eq!(extent(&f, 0x8000), Some(far));
        assert!(image_in(&f, 0x8000).is_none());
        assert_eq!(image_in(&f, 1 << 20).map(|i| i.len()), Some(far.image));
    }

    /// The bytecode's PE data is made from the headers of the object, with its
    /// size, whether or not it is held: the same as of the bytes held.
    #[test]
    fn bytecode_header_data_of_a_source_is_that_of_the_bytes() {
        let mut image = minimal_pe(b"abcdefgh");
        // An entry point in the headers, past where they end (0x170): its file
        // offset is the object's to bound, not the headers'.
        set32(&mut image, 0x58 + 16, 0x1f0);
        let mut file = image.clone();
        file.extend(vec![b'q'; 50_000]);
        let want = bytecode_pe(&file).unwrap();
        let rd32 = |pe: &BcPe, o: usize| u32::from_le_bytes(pe.pedata[o..o + 4].try_into().unwrap());
        assert_eq!(rd32(&want, 4), 0x1f0, "the entry point's file offset");
        let got = bytecode_pe_in(&cached(&file), 4096).unwrap().unwrap();
        assert_eq!(got.pedata, want.pedata);
        assert_eq!((got.hdr_size, got.sections.len()), (want.hdr_size, want.sections.len()));
        // The headers, which are all it reads, are over the limit.
        assert_eq!(bytecode_pe_in(&cached(&file), 0x100).err(), Some(0x170));
        // And not a PE.
        assert!(bytecode_pe_in(&cached(b"MZ not a pe"), 4096).unwrap().is_none());
        assert!(bytecode_pe_in(&&file[..], 0).unwrap().is_some());
    }

    /// A certificate table past the image, which a parse of the image alone
    /// cannot read, does not make it unreadable.
    #[test]
    fn a_certificate_table_past_the_image_does_not_hide_the_pe() {
        let image = minimal_pe(b"abcdefgh");
        let mut file = image.clone();
        let at = 0x58 + 112 + 4 * 8; // the certificate table's directory entry
        set32(&mut file, at, 0x4000);
        set32(&mut file, at + 4, 0x100);
        assert!(PE::parse(&file).is_err(), "the full parse refuses it");
        assert!(tables(&file, usize::MAX).is_some());
        assert!(analyze(&file).is_some());
    }

    /// A PE32+ whose `.text` holds an import table: `libs` descriptors of
    /// `A.dll`, each with the same `thunks` entries for the function `F`. It
    /// ends with 28 free bytes, at `0x1000 + 20 * (libs + 1) + 8 * (thunks +
    /// 1) + 24`.
    fn pe_with_imports(libs: usize, thunks: usize) -> Vec<u8> {
        let rva = |at: usize| (0x1000 + at) as u32;
        let table = 20 * (libs + 1);
        let hint = table + 8 * (thunks + 1);
        let name = hint + 16;
        let mut body = vec![0u8; name + 8 + 28];
        for i in 0..libs {
            set32(&mut body, 20 * i, rva(table)); // lookup table
            set32(&mut body, 20 * i + 12, rva(name)); // library name
            set32(&mut body, 20 * i + 16, rva(table)); // address table
        }
        for j in 0..thunks {
            let at = table + 8 * j;
            body[at..at + 8].copy_from_slice(&u64::from(rva(hint)).to_le_bytes());
        }
        body[hint + 2..hint + 4].copy_from_slice(b"F\0");
        body[name..name + 6].copy_from_slice(b"A.dll\0");
        let mut pe = minimal_pe(&body);
        set_dir(&mut pe, 1, rva(0), (20 * (libs + 1)) as u32);
        pe
    }

    /// Data directory `i` of a PE32+ made by `minimal_pe`.
    fn set_dir(pe: &mut [u8], i: usize, rva: u32, size: u32) {
        set32(pe, 0x58 + 112 + 8 * i, rva);
        set32(pe, 0x58 + 112 + 8 * i + 4, size);
    }

    /// The library and the function of every import, as goblin writes them: an
    /// import by ordinal is `ORDINAL n`, and a thunk that names nothing is left
    /// out.
    fn imports_of(t: &Tables) -> Vec<(String, String)> {
        let imports = t.imports.as_ref().expect("the imports are read");
        let mut all = Vec::new();
        for library in &imports.libraries {
            for function in &library.functions {
                let name = match *function {
                    Function::Named { name, .. } => String::from_utf8_lossy(name).into_owned(),
                    Function::Ordinal { number, .. } => format!("ORDINAL {number}"),
                    Function::Unread => continue,
                };
                all.push((String::from_utf8_lossy(library.name).into_owned(), name));
            }
        }
        all
    }

    /// The tables of a PE are what goblin's parse of the whole file gives, for
    /// every PE the repository holds that it parses.
    #[test]
    fn the_tables_are_those_of_a_full_parse() {
        let files: [&[u8]; 4] = [
            include_bytes!("../tests/testdata/tiny_pe32.exe"),
            include_bytes!("../tests/fixtures/pe/icon32.exe"),
            include_bytes!("../tests/fixtures/dotnet/system_buffers.dll"),
            include_bytes!("../tests/fixtures/authenticode/signed_mismatch.exe"),
        ];
        let mut listed = 0;
        for (n, file) in files.into_iter().enumerate() {
            let full = PE::parse(file).unwrap_or_else(|e| panic!("file {n}: {e}"));
            let t = tables(file, usize::MAX).expect("headers parse");
            assert_eq!(t.is_64, full.is_64, "file {n}");
            assert_eq!(t.sections.len(), full.sections.len(), "file {n}");
            let want: Vec<_> = full
                .imports
                .iter()
                .map(|i| (i.dll.to_string(), i.name.to_string()))
                .collect();
            assert_eq!(imports_of(&t), want, "file {n}");
            // goblin lists the named exports only.
            let got: Vec<_> = t
                .exports(file, usize::MAX)
                .unwrap()
                .iter()
                .filter(|e| e.name.is_some())
                .map(|e| (e.name, e.rva as usize, e.offset))
                .collect();
            let want: Vec<_> = full.exports.iter().map(|e| (e.name, e.rva, e.offset)).collect();
            assert_eq!(got, want, "file {n}");
            listed += want.len() + imports_of(&t).len();
        }
        assert!(listed > 0, "some of them have imports or exports");
    }

    /// A directory that no check reads does not hide the tables they do: a
    /// debug directory outside every section, which Windows ignores, fails a
    /// full parse as a whole, the import table with it.
    #[test]
    fn a_directory_that_does_not_map_does_not_hide_the_tables() {
        let pe = pe_with_imports(2, 3);
        let want = imports_of(&tables(&pe, usize::MAX).unwrap());
        assert_eq!(want.len(), 6);
        assert_eq!(want[0].0, "A.dll");
        assert_eq!(want[0].1, "F");
        // Each directory goblin parses, pointing outside every section.
        for dir in [2, 3, 5, 6, 9, 10, 14] {
            let mut bad = pe.clone();
            set_dir(&mut bad, dir, 0x9000, 28);
            if dir == 6 {
                assert!(PE::parse(&bad).is_err(), "the full parse refuses a debug directory");
            }
            let t = tables(&bad, usize::MAX).expect("headers parse");
            assert_eq!(imports_of(&t), want, "directory {dir}");
            assert!(t.exports(&bad, usize::MAX).is_ok(), "directory {dir}");
            assert!(analyze(&bad).is_some(), "directory {dir}");
        }
    }

    /// A table that does not parse is reported for itself, and not for the
    /// other one.
    #[test]
    fn a_table_that_does_not_parse_is_unread_alone() {
        let pe = pe_with_imports(1, 2);
        let mut bad = pe.clone();
        set_dir(&mut bad, 1, 0x9000, 40);
        let t = tables(&bad, usize::MAX).unwrap();
        assert_eq!(t.imports.as_ref().err(), Some(&Unread::Malformed));
        assert!(t.exports(&bad, usize::MAX).is_ok_and(|e| e.is_empty()));
        assert!(analyze(&bad).is_none());
        assert!(matches!(
            analyze_within(&bad, bad.len(), usize::MAX, Views::ALL, &mut |_| Ok(())),
            Err(Cut::Imports(Unread::Malformed))
        ));

        let mut bad = pe;
        set_dir(&mut bad, 0, 0x9000, 40);
        let t = tables(&bad, usize::MAX).unwrap();
        assert_eq!(t.exports(&bad, usize::MAX).err(), Some(Unread::Malformed));
        assert_eq!(imports_of(&t).len(), 2);
        assert!(analyze(&bad).is_some(), "the exports are not read for the import hash");

        // No table at all is not an unread table.
        let none = minimal_pe(b"abcdefgh");
        let t = tables(&none, usize::MAX).unwrap();
        assert!(t.imports.as_ref().is_ok_and(|i| i.libraries.is_empty()));
        assert!(t.exports(&none, usize::MAX).is_ok_and(|e| e.is_empty()));
    }

    /// A PE whose header starts inside the DOS header (some packers lay it
    /// out so, and Windows loads it) is read, which goblin's strict parse
    /// refuses. The optional header's `ImageBase` then lies where `e_lfanew`
    /// does (at 0x3c, for a PE32+).
    #[test]
    fn a_header_inside_the_dos_header_is_read() {
        let pe = pe_with_imports(1, 2);
        let mut moved = pe.clone();
        moved[0x0c..0x1cc].copy_from_slice(&pe[0x40..0x200]);
        moved[0x1cc..0x200].fill(0);
        set32(&mut moved, 0x3c, 0x0c);
        assert!(goblin::pe::header::Header::parse(&moved).is_err(), "goblin refuses it");
        let (want, got) = (tables(&pe, usize::MAX).unwrap(), tables(&moved, usize::MAX).unwrap());
        assert_eq!(got.sections.len(), 1);
        assert_eq!(got.header.dos_header.pe_pointer, 0x0c);
        assert_eq!(imports_of(&got), imports_of(&want));
        assert_eq!(layout(&moved).map(|l| l.entry), layout(&pe).map(|l| l.entry));
        assert!(analyze(&moved).is_some());
        assert_eq!(headers_end(&&moved[..]), Some(0x0c + 24 + 0xf0 + 40));
        // Without a PE signature where `e_lfanew` points it is not one.
        set32(&mut moved, 0x0c, 0);
        assert!(headers(&moved).is_none());
    }

    /// Many descriptors that list one long table make a parse of a few
    /// kilobytes take gigabytes (measured: 1.7 GB for 61 KB). A table whose
    /// parse would take more than the memory the caller allows is not parsed.
    #[test]
    fn an_import_table_that_would_take_too_much_to_parse_is_too_large() {
        let pe = pe_with_imports(50, 100);
        let cost = 50 * (LIBRARY_COST + 100 * FUNCTION_COST);
        let t = tables(&pe, cost).unwrap();
        assert_eq!(imports_of(&t).len(), 5000);
        let t = tables(&pe, cost - 1).unwrap();
        assert_eq!(t.imports.as_ref().err(), Some(&Unread::TooLarge));
        assert!(t.exports(&pe, usize::MAX).is_ok(), "the other table does not share its fate");
        assert!(matches!(
            analyze_within(&pe, pe.len(), cost - 1, Views::ALL, &mut |_| Ok(())),
            Err(Cut::Imports(Unread::TooLarge))
        ));

        // The file that took gigabytes, at its default limit: 18 million
        // functions, over it on a 32-bit target too, where they are smaller.
        let pe = pe_with_imports(3000, 6000);
        assert!(pe.len() < 200_000);
        let t = tables(&pe, 256 << 20).unwrap();
        assert_eq!(t.imports.as_ref().err(), Some(&Unread::TooLarge));
    }

    #[test]
    fn an_export_table_that_would_take_too_much_to_parse_is_too_large() {
        let mut body = vec![0u8; 40 + 4 * 10];
        set32(&mut body, 20, 10); // addresses
        set32(&mut body, 28, 0x1000 + 40); // their table
        let mut pe = minimal_pe(&body);
        set_dir(&mut pe, 0, 0x1000, 40);
        let t = tables(&pe, usize::MAX).unwrap();
        assert!(t.exports(&pe, 10 * EXPORT_COST).is_ok());
        assert_eq!(t.exports(&pe, 10 * EXPORT_COST - 1).err(), Some(Unread::TooLarge));
        assert!(t.imports.is_ok());
    }

    /// The hash clamscan and libyara give for `KERNEL32.DLL` importing
    /// `LoadLibraryA` and `GetProcAddress`.
    const KERNEL32_HASH: &str = "87bed5a7cba00c7e1f4015f1bdae2183";

    /// A PE32+ that imports `LoadLibraryA` and `GetProcAddress` from
    /// `KERNEL32.DLL` through an address table, with no lookup table, as
    /// WinUpack lays it out. The library's name, and the hint/name entry of
    /// `GetProcAddress` (a hint, then the name), are in the section unless an
    /// RVA is given: they are then written there, in the headers.
    fn pe_naming(name: Option<u32>, entry: Option<u32>) -> Vec<u8> {
        pe_naming_at(0x1000, name, entry)
    }

    /// [`pe_naming`] with its section at the RVA `va`.
    fn pe_naming_at(va: u32, name: Option<u32>, entry: Option<u32>) -> Vec<u8> {
        let mut body = vec![0u8; 0x7a];
        let (name_rva, entry_rva) = (name.unwrap_or(va + 0x48), entry.unwrap_or(va + 0x68));
        body[0..8].copy_from_slice(&u64::from(va + 0x58).to_le_bytes());
        body[8..16].copy_from_slice(&u64::from(entry_rva).to_le_bytes());
        set32(&mut body, 0x20 + 12, name_rva);
        set32(&mut body, 0x20 + 16, va);
        body[0x48..0x55].copy_from_slice(b"KERNEL32.DLL\0");
        body[0x5a..0x67].copy_from_slice(b"LoadLibraryA\0");
        body[0x6a..0x79].copy_from_slice(b"GetProcAddress\0");
        let mut pe = minimal_pe(&body);
        set32(&mut pe, 0x148 + 12, va);
        set_dir(&mut pe, 1, va + 0x20, 40);
        let mut put = |at: u32, bytes: &[u8]| {
            let at = at as usize;
            pe.resize(pe.len().max(at + bytes.len()), 0);
            pe[at..at + bytes.len()].copy_from_slice(bytes);
        };
        if let Some(at) = name {
            put(at, b"KERNEL32.DLL\0");
        }
        if let Some(at) = entry {
            put(at + 2, b"GetProcAddress\0");
        }
        // The import hash leaves out an entry less than 258 bytes from the end
        // of the file, as clamscan does.
        pe.resize(pe.len() + CLAMSCAN_ENTRY_WINDOW, 0);
        pe
    }

    fn names_of(t: &Tables) -> Vec<(String, String)> {
        imports_of(t)
    }

    /// Names that a PE keeps in its headers are read: Windows maps the headers,
    /// and goblin does not. The library's name and an entry in the DOS header,
    /// as WinUpack does (clamscan and libyara read them), an entry in the
    /// part of the headers after the section table, and one between the
    /// headers and the first section, which both read as well.
    #[test]
    fn names_in_the_headers_are_read() {
        let want = vec![
            ("KERNEL32.DLL".to_string(), "LoadLibraryA".to_string()),
            ("KERNEL32.DLL".to_string(), "GetProcAddress".to_string()),
        ];
        for (what, name, entry) in [
            ("none", None, None),
            ("the DOS header", Some(2), Some(0x10)),
            ("an entry after the section table", None, Some(0x180)),
            ("a name after the section table", Some(0x190), None),
            ("an entry below the first section", None, Some(0x300)),
        ] {
            let pe = pe_naming(name, entry);
            let t = tables(&pe, usize::MAX).unwrap();
            assert_eq!(names_of(&t), want, "{what}");
            assert_eq!(analyze(&pe).map(|i| i.imphash).as_deref(), Some(KERNEL32_HASH), "{what}");
        }
        // A section that starts a page after the headers: what is between
        // them is read up to the page, and not past it.
        for (entry, listed) in [(0xfff, 2), (0x1100, 1), (0x1800, 1)] {
            let pe = pe_naming_at(0x3000, None, Some(entry));
            let t = tables(&pe, usize::MAX).unwrap();
            assert_eq!(names_of(&t).len(), listed, "an entry at {entry:#x}");
        }
    }

    /// How far the headers map: the span clamscan and libyara both read.
    #[test]
    fn the_headers_map_as_far_as_clamscan_and_libyara_both_read() {
        let pe = minimal_pe(b"abcdefgh");
        let Headers { header, mut sections } = headers(&pe).unwrap();
        let mut opt = header.optional_header.unwrap();
        for (of_headers, alignment, first, want) in [
            // Rounded up to the section alignment.
            (0x200, 0x1000, 0x1000, 0x1000),
            (0x1001, 0x1000, 0x3000, 0x2000),
            // But not to one that is not a power of two, or is 0.
            (0x201, 0x300, 0x1000, 0x201),
            (0x200, 0, 0x1000, 0x200),
            // Not past the lowest section.
            (0x2000, 0x1000, 0x1000, 0x1000),
            (0x400, 0x1000, 0x800, 0x800),
            // A low alignment, which a PE may have.
            (0x200, 0x200, 0x400, 0x200),
            (0x300, 0x200, 0x1000, 0x400),
            (0, 0x1000, 0x1000, 0),
        ] {
            opt.windows_fields.size_of_headers = of_headers;
            opt.windows_fields.section_alignment = alignment;
            sections[0].virtual_address = first;
            assert_eq!(header_end(&opt, &sections), want, "{of_headers:#x} {alignment:#x} {first:#x}");
        }
        // The lowest section is not the first in the table.
        let mut two = vec![sections[0].clone(), sections[0].clone()];
        two[0].virtual_address = 0x5000;
        two[1].virtual_address = 0x1000;
        opt.windows_fields.size_of_headers = 0x200;
        opt.windows_fields.section_alignment = 0x4000;
        assert_eq!(header_end(&opt, &two), 0x1000);
        // No section.
        assert_eq!(header_end(&opt, &[]), 0x4000);
    }

    /// An entry point in the headers is at the file offset of its RVA, as
    /// clamscan anchors an `EP+n` signature there.
    #[test]
    fn an_entry_point_in_the_headers_is_at_its_rva() {
        let entry_of = |rva: u32| {
            let mut pe = minimal_pe(b"abcdefgh");
            set32(&mut pe, 0x58 + 16, rva);
            layout(&pe).unwrap().entry
        };
        assert_eq!(entry_of(0x1004), Some(0x204), "in a section");
        for rva in [0, 0x3c, 0x180, 0x1ff, 0x200, 0xfff] {
            assert_eq!(entry_of(rva), Some(u64::from(rva)), "{rva:#x}");
        }
        assert_eq!(entry_of(0x1008), None, "past the section");
    }

    /// The tables of a PE kept in its headers are bounded as the others are:
    /// descriptors in the headers, which point at one long table, make a parse
    /// of a few kilobytes take as much memory as those in a section.
    #[test]
    fn descriptors_in_the_headers_are_counted_as_those_in_a_section_are() {
        let (libs, thunks) = (40, 200);
        let mut pe = pe_with_headers_of(0x2000, b"........");
        for i in 0..libs {
            let at = 0x200 + 20 * i;
            set32(&mut pe, at, 0x600); // lookup table
            set32(&mut pe, at + 12, 0xd10); // library name
            set32(&mut pe, at + 16, 0x600); // address table
        }
        for j in 0..thunks {
            pe[0x600 + 8 * j..0x608 + 8 * j].copy_from_slice(&0xd00u64.to_le_bytes());
        }
        pe[0xd02..0xd04].copy_from_slice(b"F\0");
        pe[0xd10..0xd16].copy_from_slice(b"A.dll\0");
        set_dir(&mut pe, 1, 0x200, 20 * (libs as u32 + 1));
        let cost = libs * (LIBRARY_COST + thunks * FUNCTION_COST);
        let t = tables(&pe, cost).unwrap();
        assert_eq!(imports_of(&t).len(), libs * thunks);
        let t = tables(&pe, cost - 1).unwrap();
        assert_eq!(t.imports.as_ref().err(), Some(&Unread::TooLarge));
    }

    /// [`minimal_pe`] with `size` bytes of headers: `SizeOfHeaders`, and the
    /// section after them, in the file and in the image.
    fn pe_with_headers_of(size: usize, section: &[u8]) -> Vec<u8> {
        let pe = minimal_pe(section);
        let mut f = pe[..0x200].to_vec();
        f.resize(size, 0);
        f.extend_from_slice(&pe[0x200..]);
        set32(&mut f, 0x58 + 60, size as u32);
        set32(&mut f, 0x148 + 12, size as u32);
        set32(&mut f, 0x148 + 20, size as u32);
        f
    }

    /// A PE32+ whose headers hold an export table of one function, `Func` of
    /// `x.dll`.
    fn pe_exporting() -> Vec<u8> {
        let mut pe = minimal_pe(&[0x90; 8]);
        let dir = 0x180;
        set32(&mut pe, dir + 12, 0x1c0); // the library's name
        set32(&mut pe, dir + 16, 1); // the ordinal base
        set32(&mut pe, dir + 20, 1); // functions
        set32(&mut pe, dir + 24, 1); // names
        set32(&mut pe, dir + 28, 0x1b0); // their addresses
        set32(&mut pe, dir + 32, 0x1b4); // the addresses of the names
        set32(&mut pe, dir + 36, 0x1b8); // and their ordinals
        set32(&mut pe, 0x1b0, 0x1000);
        set32(&mut pe, 0x1b4, 0x1d0);
        pe[0x1c0..0x1c6].copy_from_slice(b"x.dll\0");
        pe[0x1d0..0x1d5].copy_from_slice(b"Func\0");
        set_dir(&mut pe, 0, dir as u32, 40);
        pe
    }

    /// An export table kept in the headers is read.
    #[test]
    fn an_export_table_in_the_headers_is_read() {
        let pe = pe_exporting();
        let t = tables(&pe, usize::MAX).unwrap();
        let exports = t.exports(&pe, usize::MAX).expect("the exports are read");
        let names: Vec<_> = exports.iter().map(|e| e.name).collect();
        assert_eq!(names, [Some("Func")]);
    }

    /// An export name is read up to [`MAX_FUNCTION_NAME`] bytes, however far
    /// the file goes on without a NUL.
    #[test]
    fn an_export_name_is_read_up_to_the_name_limit() {
        let mut pe = pe_exporting();
        // The name starts right after the section data, at RVA 0x1008.
        set32(&mut pe, 0x1b4, 0x1008);
        pe.extend(vec![b'a'; 3 * MAX_FUNCTION_NAME]);
        let t = tables(&pe, usize::MAX).unwrap();
        let exports = t.exports(&pe, usize::MAX).unwrap();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name.map(str::len), Some(MAX_FUNCTION_NAME));
    }

    /// An export has the ordinal its place in the address table gives, from the
    /// base of the directory, and a function that no name points at is listed.
    #[test]
    fn an_export_has_its_ordinal() {
        let mut pe = pe_exporting();
        let dir = 0x180;
        set32(&mut pe, dir + 16, 5); // the ordinal base
        set32(&mut pe, dir + 20, 2); // functions
        set32(&mut pe, 0x1b0, 0x1000);
        set32(&mut pe, 0x1b4, 0x1004);
        set32(&mut pe, dir + 32, 0x1b8); // the addresses of the names
        set32(&mut pe, 0x1b8, 0x1d0);
        set32(&mut pe, dir + 36, 0x1bc); // and their ordinals
        set32(&mut pe, 0x1bc, 1); // the name is that of the second function
        let t = tables(&pe, usize::MAX).unwrap();
        let got: Vec<_> = t.exports(&pe, usize::MAX).unwrap().iter().map(|e| (e.ordinal, e.rva, e.name)).collect();
        assert_eq!(got, [(5, 0x1000, None), (6, 0x1004, Some("Func"))]);
    }

    /// Reading the imports, or the sections, does not read the export table.
    #[test]
    fn the_export_table_is_read_only_when_asked_for() {
        let pe = pe_exporting();
        let reads = || exports::READS.with(|reads| reads.get());
        let before = reads();
        assert!(analyze(&pe).is_some());
        assert!(matches!(imports_within(&pe, pe.len(), usize::MAX, Views::ALL), Ok(Some(_))));
        let t = tables(&pe, usize::MAX).unwrap();
        assert_eq!(reads(), before);
        assert_eq!(t.exports(&pe, usize::MAX).unwrap().len(), 1);
        assert_eq!(reads(), before + 1);
    }

    /// The export reader against goblin's, which read the export table before
    /// it: for each PE named in the file `EXAV_DEBUG_PE_LIST` (one path per line),
    /// every difference in (name, rva, offset, forwarder) is printed, with a
    /// count of the functions listed by ordinal alone, which goblin does not
    /// list. Run with `--ignored --nocapture`.
    #[test]
    #[ignore = "reads the files named in EXAV_DEBUG_PE_LIST"]
    fn the_exports_are_those_goblin_reads() {
        use goblin::pe::export::{Export as Goblin, ExportData, Reexport};
        let Ok(list) = std::env::var("EXAV_DEBUG_PE_LIST") else {
            return;
        };
        let list = std::fs::read_to_string(list).unwrap();
        let (mut files, mut tables_seen, mut by_ordinal) = (0, 0, 0);
        for path in list.lines().filter(|line| !line.is_empty()) {
            let Ok(data) = std::fs::read(path) else { continue };
            let Some(t) = tables(&data, usize::MAX) else { continue };
            files += 1;
            let Some(dir) = t.export_dir else { continue };
            tables_seen += 1;
            let opts = goblin::pe::options::ParseOptions::default();
            let old = ExportData::parse_with_opts(&data, dir, &t.map, t.file_alignment, &opts)
                .and_then(|table| Goblin::parse_with_opts(&data, &table, &t.map, t.file_alignment, &opts));
            let new = t.exports(&data, usize::MAX);
            let (old, new) = match (old, new) {
                (Ok(old), Ok(new)) => (old, new),
                (Err(_), Err(why)) => {
                    eprintln!("{path}: both fail ({why:?})");
                    continue;
                }
                (old, new) => {
                    eprintln!("{path}: goblin {:?}, exav {:?}", old.map(|e| e.len()), new.map(|e| e.len()));
                    continue;
                }
            };
            type Key = (Option<String>, usize, Option<usize>, Option<String>);
            let mut want: Vec<Key> = old
                .iter()
                .map(|e| {
                    let forwarder = e.reexport.as_ref().map(|r| match r {
                        Reexport::DLLName { export, lib } => format!("{lib}.{export}"),
                        Reexport::DLLOrdinal { ordinal, lib } => format!("{lib}.#{ordinal}"),
                    });
                    (e.name.map(str::to_owned), e.rva, e.offset, forwarder)
                })
                .collect();
            let mut got: Vec<Key> = Vec::new();
            for e in &new {
                if e.name.is_none() {
                    by_ordinal += 1;
                }
                got.push((e.name.map(str::to_owned), e.rva as usize, e.offset, e.forwarder.map(str::to_owned)));
            }
            want.sort();
            got.sort();
            for key in want.iter().filter(|key| !got.contains(key)) {
                eprintln!("{path}: goblin only {key:?}");
            }
            for key in got.iter().filter(|key| key.0.is_some() && !want.contains(key)) {
                eprintln!("{path}: exav only {key:?}");
            }
        }
        eprintln!("{files} PE files, {tables_seen} with an export directory, {by_ordinal} functions by ordinal alone");
    }

    /// The index of RVAs gives the offsets goblin's lookup does, sections that
    /// overlap included (the first holds the RVA).
    #[test]
    fn the_rva_index_maps_as_goblin_does() {
        let section = |va, size, pointer, raw| goblin::pe::section_table::SectionTable {
            virtual_address: va,
            virtual_size: size,
            pointer_to_raw_data: pointer,
            size_of_raw_data: raw,
            ..Default::default()
        };
        let sections = [
            section(0x1000, 0x300, 0x400, 0x200),
            section(0x1100, 0x2000, 0x800, 0x1000),
            section(0x1000, 0, 0xc00, 0x100),
            section(0x4000, 0x10, 0x1800, 0),
            section(0x5000, 0x1f00, 0x1801, 0x200),
        ];
        let opts = goblin::pe::options::ParseOptions::default();
        for alignment in [0x200, 0x1000] {
            let index = exports::RvaIndex::new(&sections, alignment);
            for rva in (0..0x7000u32).step_by(7).chain([0xfff, 0x1000, 0x10ff, 0x1100, 0x13ff, 0x1400, 0x5000]) {
                let want = goblin::pe::utils::find_offset(rva as usize, &sections, alignment, &opts);
                assert_eq!(index.offset(rva), want, "rva {rva:#x}, alignment {alignment:#x}");
            }
        }
    }

    /// The image of a PE holds its headers, and what the headers map below the
    /// first section: its tables are those of the whole object.
    #[test]
    fn the_tables_of_the_image_include_the_names_in_its_headers() {
        for (name, entry) in [(Some(2), Some(0x10)), (None, Some(0x180)), (None, Some(0x300))] {
            let mut f = pe_naming(name, entry);
            f.extend(vec![b'z'; 100_000]);
            let image = extent(&&f[..], 1 << 20).unwrap().image;
            assert!(image < f.len());
            let whole = names_of(&tables(&f, usize::MAX).unwrap());
            assert_eq!(whole.len(), 2, "{name:?} {entry:?}");
            assert_eq!(names_of(&tables(&f[..image], usize::MAX).unwrap()), whole, "{name:?} {entry:?}");
            let cache = cached(&f);
            let held = image_in(&cache, 1 << 20).expect("the image is held");
            assert_eq!(names_of(&tables(&held, usize::MAX).unwrap()), whole, "{name:?} {entry:?}");
        }
    }

    /// What a thunk of [`pe_importing`] holds.
    enum Thunk<'a> {
        /// A hint/name entry with this name.
        Name(&'a [u8]),
        Ordinal(u16),
        /// This value as it is.
        Raw(u64),
    }
    use Thunk::{Name, Ordinal, Raw};

    /// A PE32+ whose `.text` holds the import table of `libs`: their
    /// descriptors and the null one, the names of the libraries, a thunk table
    /// for each (the lookup table is the address table), and the hint/name
    /// entries. `pad` zero bytes follow the section: the import hash leaves out
    /// an entry less than 258 bytes from the end of the file.
    fn pe_importing(libs: &[(&[u8], &[Thunk])], pad: usize) -> Vec<u8> {
        let rva = |at: usize| (0x1000 + at) as u32;
        let mut body = vec![0u8; 20 * (libs.len() + 1)];
        let mut names = Vec::new();
        for (name, _) in libs {
            names.push(body.len());
            body.extend_from_slice(name);
            body.push(0);
        }
        body.resize(body.len().next_multiple_of(8), 0);
        let mut tables = Vec::new();
        for (_, thunks) in libs {
            tables.push(body.len());
            body.resize(body.len() + 8 * (thunks.len() + 1), 0);
        }
        for (i, (_, thunks)) in libs.iter().enumerate() {
            for (j, thunk) in thunks.iter().enumerate() {
                let value = match thunk {
                    Name(name) => {
                        body.resize(body.len().next_multiple_of(2), 0);
                        let at = body.len();
                        body.extend_from_slice(&[0, 0]);
                        body.extend_from_slice(name);
                        body.push(0);
                        u64::from(rva(at))
                    }
                    Ordinal(ordinal) => 1 << 63 | u64::from(*ordinal),
                    Raw(value) => *value,
                };
                let at = tables[i] + 8 * j;
                body[at..at + 8].copy_from_slice(&value.to_le_bytes());
            }
            set32(&mut body, 20 * i, rva(tables[i]));
            set32(&mut body, 20 * i + 12, rva(names[i]));
            set32(&mut body, 20 * i + 16, rva(tables[i]));
        }
        let mut pe = minimal_pe(&body);
        set_dir(&mut pe, 1, rva(0), (20 * (libs.len() + 1)) as u32);
        pe.resize(pe.len() + pad, 0);
        pe
    }

    fn md5_of(s: &str) -> String {
        encode_hex(&Md5::digest(s.as_bytes()))
    }

    /// The import hash of `pe` as clamscan makes it, and the length of what it
    /// hashes.
    fn clamscan_hash_of(pe: &[u8]) -> Option<(String, usize)> {
        let t = tables(pe, usize::MAX).unwrap();
        let mut room = usize::MAX;
        t.imports.unwrap().clamscan_hash(pe.len(), &mut room).ok().unwrap()
    }

    /// The names yara-x lists, as `library.function`.
    fn listed_in(pe: &[u8]) -> Vec<String> {
        let t = tables(pe, usize::MAX).unwrap();
        let listed = t.listed().as_ref().unwrap();
        listed.listed().map(|import| format!("{}.{}", import.library_name, import.name)).collect()
    }

    /// Four functions of two libraries, one by ordinal: clamscan 1.4.3 prints
    /// `IMP: 74d5ac01e60a489ceee1bff98faf59c3:78` for them. The size is the
    /// length of the string hashed, `kernel32.loadlibrarya,...,user32.ord100`,
    /// and not the 4 functions.
    #[test]
    fn the_size_of_an_import_hash_is_the_length_of_the_string_hashed() {
        let libs: [(&[u8], &[Thunk]); 2] = [
            (b"KERNEL32.DLL", &[Name(b"LoadLibraryA"), Name(b"GetProcAddress")]),
            (b"USER32.DLL", &[Name(b"MessageBoxA"), Ordinal(100)]),
        ];
        let pe = pe_importing(&libs, 300);
        let hashed = "kernel32.loadlibrarya,kernel32.getprocaddress,user32.messageboxa,user32.ord100";
        assert_eq!(hashed.len(), 78);
        assert_eq!(clamscan_hash_of(&pe), Some(("74d5ac01e60a489ceee1bff98faf59c3".to_string(), 78)));
        assert_eq!(md5_of(hashed), "74d5ac01e60a489ceee1bff98faf59c3");
        let info = analyze(&pe).unwrap();
        assert_eq!((info.imphash.as_str(), info.imphash_len, info.import_count), ("74d5ac01e60a489ceee1bff98faf59c3", 78, 4));
    }

    /// An import by ordinal from `ws2_32`, `wsock32` and `oleaut32` is hashed
    /// by the name of the function, and from other libraries as `ord<n>`:
    /// clamscan and libyara agree on this for every ordinal.
    #[test]
    fn an_import_by_ordinal_is_hashed_by_name_in_the_libraries_both_references_resolve() {
        for (library, ordinal, hashed, hash) in [
            (&b"WS2_32.dll"[..], 115, "ws2_32.wsastartup", "b37125ceef051f12e08e29efb577946e"),
            (b"OLEAUT32.dll", 2, "oleaut32.sysallocstring", "3dc76082b322e4bf41120e4657c7f5c6"),
            (b"wsock32.dll", 151, "wsock32.__wsafdisset", "7dbac81d5616ee0d85292420d1ae97ba"),
            (b"USER32.dll", 100, "user32.ord100", ""),
            (b"ws2_32.dll", 600, "ws2_32.ord600", "9332f9fe89dee23adc49be53db9b7b8e"),
        ] {
            let pe = pe_importing(&[(library, &[Ordinal(ordinal)])], 300);
            let (got, len) = clamscan_hash_of(&pe).unwrap();
            assert_eq!((got, len), (md5_of(hashed), hashed.len()), "{hashed}");
            if !hash.is_empty() {
                assert_eq!(md5_of(hashed), hash, "{hashed}: the hash clamscan prints");
            }
        }
        // The names libyara lists are the same.
        let pe = pe_importing(&[(b"WS2_32.dll", &[Ordinal(115), Ordinal(100)]), (b"user32.dll", &[Ordinal(100)])], 300);
        assert_eq!(listed_in(&pe), ["WS2_32.dll.WSAStartup", "WS2_32.dll.ord100", "user32.dll.ord100"]);
    }

    /// The descriptors clamscan reads are those that leave more than 20 bytes
    /// of the directory unread, whatever the null descriptor is. libyara reads
    /// them all.
    #[test]
    fn the_descriptors_hashed_are_those_the_size_of_the_directory_leaves_room_for() {
        let libs: [(&[u8], &[Thunk]); 3] = [
            (b"KERNEL32.DLL", &[Name(b"LoadLibraryA")]),
            (b"USER32.DLL", &[Name(b"MessageBoxA")]),
            (b"GDI32.DLL", &[Name(b"BitBlt")]),
        ];
        let all = ["kernel32.loadlibrarya", "user32.messageboxa", "gdi32.bitblt"];
        let mut pe = pe_importing(&libs, 300);
        for (size, read) in [
            (0x14, 0),
            (0x15, 1),
            (0x1e, 1),
            (0x28, 1),
            (0x29, 2),
            (0x3c, 2),
            (0x3d, 3),
            (0x50, 3),
            (0x100, 3),
        ] {
            set_dir(&mut pe, 1, 0x1000, size);
            let hashed = all[..read].join(",");
            assert_eq!(clamscan_hash_of(&pe), Some((md5_of(&hashed), hashed.len())), "size {size:#x}");
            assert_eq!(listed_in(&pe).len(), 3, "libyara reads them all at {size:#x}");
        }
        // No hash for an empty directory, or one that ends past the object.
        for size in [0, 0x10000] {
            set_dir(&mut pe, 1, 0x1000, size);
            assert_eq!(clamscan_hash_of(&pe), None, "size {size:#x}");
        }
        // The empty list is the hash of the empty string.
        set_dir(&mut pe, 1, 0x1000, 0x14);
        assert_eq!(clamscan_hash_of(&pe), Some(("d41d8cd98f00b204e9800998ecf8427e".to_string(), 0)));
    }

    /// clamscan hashes a name made of letters, digits, `_` and `.`, and makes
    /// no hash at all if a function has another character; yara-x lists any
    /// printable ASCII character but the space, and skips the function with
    /// any other (libyara lists only `?@$()<>` besides the first kind).
    #[test]
    fn a_function_name_clamscan_rejects_ends_its_hash_and_yarax_lists_what_it_accepts() {
        let alpha: &[u8] = b"Alpha";
        for (name, clamscan, yarax) in [
            (&b"a.b_C9"[..], true, true),
            (b"_a@4", false, true),
            (b"?x@@YAXXZ", false, true),
            (b"a$(b)<c>", false, true),
            (b"a-b", false, true),
            (b"a\"b", false, true),
            (b"~", false, true),
            (b"!", false, true),
            (b"a b", false, false),
            (b" ", false, false),
            (b"a\xffb", false, false),
            (b"a\x80b", false, false),
            (b"a\x7fb", false, false),
            (b"a\x01b", false, false),
        ] {
            let pe = pe_importing(&[(b"K.DLL", &[Name(alpha), Name(name), Name(alpha)])], 300);
            assert_eq!(clamscan_hash_of(&pe).is_some(), clamscan, "{name:?}");
            let listed = listed_in(&pe);
            assert_eq!(listed.len(), if yarax { 3 } else { 2 }, "{name:?}");
        }
        // The empty name is hashed, and not listed.
        let pe = pe_importing(&[(b"K.DLL", &[Name(b"A"), Name(b""), Name(b"B")])], 300);
        assert_eq!(clamscan_hash_of(&pe), Some((md5_of("k.a,k.,k.b"), 10)));
        assert_eq!(listed_in(&pe), ["K.DLL.A", "K.DLL.B"]);
    }

    /// An entry that maps nowhere is hashed as the empty name by clamscan and
    /// is not listed by libyara or yara-x; so is a descriptor with no table.
    #[test]
    fn a_thunk_that_names_nothing_is_hashed_as_an_empty_name_and_not_listed() {
        for value in [0x9000, 0x7fff_ffff, 0x3000_0000] {
            let pe = pe_importing(&[(b"K.DLL", &[Name(b"A"), Raw(value), Name(b"B")])], 300);
            assert_eq!(clamscan_hash_of(&pe), Some((md5_of("k.a,k.,k.b"), 10)), "{value:#x}");
            assert_eq!(listed_in(&pe), ["K.DLL.A", "K.DLL.B"], "{value:#x}");
        }
        // No lookup table and no address table: clamscan hashes the library as
        // an empty name and goes on; yara-x ends the table there (libyara goes
        // on, and lists the third library).
        let libs: [(&[u8], &[Thunk]); 3] = [
            (b"K.DLL", &[Name(b"A")]),
            (b"U.DLL", &[Name(b"B")]),
            (b"G.DLL", &[Name(b"C")]),
        ];
        let mut pe = pe_importing(&libs, 300);
        set32(&mut pe, 0x200 + 20, 0);
        set32(&mut pe, 0x200 + 20 + 16, 0);
        assert_eq!(clamscan_hash_of(&pe), Some((md5_of("k.a,u.,g.c"), 10)));
        assert_eq!(listed_in(&pe), ["K.DLL.A"]);
        // The count of imports and the suspicious ones go on past it.
        let t = tables(&pe, usize::MAX).unwrap();
        assert_eq!(t.listed().as_ref().unwrap().listed_in_full().count(), 2);
    }

    /// An entry is hashed only if 258 bytes of the object follow its start
    /// (its hint, and 256 of the name), as clamscan reads it.
    #[test]
    fn an_entry_near_the_end_of_the_object_is_left_out_of_the_hash() {
        let last = [b'c'; 8];
        let libs: [(&[u8], &[Thunk]); 1] = [(b"K.DLL", &[Name(b"a"), Name(&last)])];
        let bare = pe_importing(&libs, 0);
        // The last entry: a hint of 2 bytes, then its name.
        let to_end = bare.len() - (bare.windows(8).position(|w| w == last).unwrap() - 2);
        for (distance, hashed) in [(257, "k.a"), (258, "k.a,k.cccccccc"), (1000, "k.a,k.cccccccc")] {
            let pe = pe_importing(&libs, distance - to_end);
            assert_eq!(clamscan_hash_of(&pe), Some((md5_of(hashed), hashed.len())), "{distance} bytes");
            // libyara lists both.
            assert_eq!(listed_in(&pe).len(), 2, "{distance} bytes");
        }
    }

    /// clamscan cuts the library's name at its first `.` when `dll`, `sys` or
    /// `ocx` follows, and no other way; a name is not checked.
    #[test]
    fn the_library_is_cut_as_clamscan_cuts_it() {
        for (library, cut) in [
            (&b"KERNEL32.DLL"[..], &b"KERNEL32"[..]),
            (b"x.Sys", b"x"),
            (b"x.ocx", b"x"),
            (b"x.dllx", b"x"),
            (b"x.dll.mui", b"x"),
            (b"x.dll.dll", b"x"),
            (b"ntoskrnl.exe", b"ntoskrnl.exe"),
            (b"lua5.1.dll", b"lua5.1.dll"),
            (b"a.b.dll", b"a.b.dll"),
            (b"x.dl", b"x.dl"),
            (b"x", b"x"),
            (b"", b""),
        ] {
            assert_eq!(clamscan_stem(library), cut, "{:?}", String::from_utf8_lossy(library));
        }
        let pe = pe_importing(&[(b"lua5.1.dll", &[Name(b"A")]), (b"Odd Name\xe9.DLL", &[Name(b"B")])], 300);
        let hashed = b"lua5.1.dll.a,odd name\xe9.b";
        assert_eq!(clamscan_hash_of(&pe), Some((encode_hex(&Md5::digest(hashed)), hashed.len())));
        // yara-x lists the first library, and not the second: its name has a
        // space and is not UTF-8.
        assert_eq!(listed_in(&pe), ["lua5.1.dll.A"]);
    }

    /// The name of a function is read to its end, at most as far as yara-x
    /// reads it (1024 bytes; libyara reads 512); clamscan hashes 256 bytes of
    /// it. The same for a library: 512 bytes for yara-x, and 256 for clamscan
    /// and libyara, which also lists no name that long.
    #[test]
    fn a_long_name_is_cut_where_each_reference_cuts_it() {
        let long = vec![b'a'; 1100];
        let pe = pe_importing(&[(b"K.DLL", &[Name(&long)])], 1200);
        let listed = listed_in(&pe);
        assert_eq!(listed[0].len(), "K.DLL.".len() + 1024, "yara-x reads 1024 bytes of a name");
        let hashed = format!("k.{}", "a".repeat(256));
        assert_eq!(clamscan_hash_of(&pe), Some((md5_of(&hashed), hashed.len())));

        let long = [vec![b'd'; 600], b".dll".to_vec()].concat();
        let pe = pe_importing(&[(&long, &[Name(b"f")])], 700);
        let listed = listed_in(&pe);
        assert_eq!(listed[0].len(), 512 + ".f".len(), "yara-x reads 512 bytes of a library's name");
        let hashed = format!("{}.f", "d".repeat(256));
        assert_eq!(clamscan_hash_of(&pe), Some((md5_of(&hashed), hashed.len())));
    }

    /// A thunk with a bit below the ordinal flag set is the ordinal of its
    /// low 16 bits to clamscan, and no import to libyara.
    #[test]
    fn an_ordinal_thunk_with_high_bits_is_hashed_and_not_listed() {
        let flag = 1u64 << 63;
        let pe = pe_importing(
            &[(b"K.DLL", &[Name(b"A"), Raw(flag | 0x1_0001), Raw(flag | 0xffff)])],
            300,
        );
        assert_eq!(clamscan_hash_of(&pe), Some((md5_of("k.a,k.ord1,k.ord65535"), 21)));
        assert_eq!(listed_in(&pe), ["K.DLL.A", "K.DLL.ord65535"]);
    }

    /// Three libraries of one function each, in a PE whose file offsets of the
    /// descriptor fields are `0x200 + 20 * i + field`.
    fn three_libraries() -> Vec<u8> {
        let libs: [(&[u8], &[Thunk]); 3] = [
            (b"KERNEL32.DLL", &[Name(b"LoadLibraryA")]),
            (b"USER32.DLL", &[Name(b"MessageBoxA")]),
            (b"GDI32.DLL", &[Name(b"BitBlt")]),
        ];
        pe_importing(&libs, 300)
    }

    const ALL_THREE: [&str; 3] = ["KERNEL32.DLL.LoadLibraryA", "USER32.DLL.MessageBoxA", "GDI32.DLL.BitBlt"];

    /// The end of the table is a descriptor with no name. One with no address
    /// table, or no lookup table, or a lookup table that maps nowhere, or an
    /// address table that maps nowhere beside a lookup table that maps, is
    /// read: clamscan and libyara read them all.
    #[test]
    fn a_descriptor_with_one_table_missing_is_read() {
        let second = 0x200 + 20;
        for (what, patches) in [
            ("no address table", vec![(16, 0)]),
            ("no lookup table", vec![(0, 0)]),
            ("a lookup table that maps nowhere", vec![(0, 0x9000)]),
            ("an address table that maps nowhere", vec![(16, 0x9000)]),
            ("a timestamp and a forwarder", vec![(4, u32::MAX), (8, 1)]),
        ] {
            let mut pe = three_libraries();
            for (field, value) in patches {
                set32(&mut pe, second + field, value);
            }
            assert_eq!(listed_in(&pe), ALL_THREE, "{what}");
        }
        // The null descriptor ends the table, whatever else it holds.
        for (what, patches) in [("all zero", vec![0, 4, 8, 12, 16]), ("no name", vec![12])] {
            let mut pe = three_libraries();
            for field in patches {
                set32(&mut pe, second + field, 0);
            }
            assert_eq!(listed_in(&pe), &ALL_THREE[..1], "{what}");
        }
    }

    /// A descriptor that cannot be read is left out, as libyara leaves it out.
    /// If the size of the directory leaves room for it the table is marked as
    /// not read whole, and the descriptors that can be read are listed; one
    /// past that size is skipped without a mark, as clamscan does not read it.
    #[test]
    fn a_fault_past_the_size_of_the_directory_is_skipped() {
        let second = 0x200 + 20;
        for (what, patches) in [
            ("a name that maps nowhere", vec![(12, 0x9000)]),
            ("tables that map nowhere", vec![(0, 0x9000), (16, 0x9000)]),
        ] {
            let mut pe = three_libraries();
            for (field, value) in patches {
                set32(&mut pe, second + field, value);
            }
            for (size, covered) in [(0x14, false), (0x15, false), (0x28, false), (0x29, true), (0x3c, true), (0x50, true)] {
                set_dir(&mut pe, 1, 0x1000, size);
                let t = tables(&pe, usize::MAX).unwrap();
                assert_eq!(t.imports.as_ref().unwrap().fault, covered, "{what}, size {size:#x}");
                assert_eq!(listed_in(&pe), [ALL_THREE[0], ALL_THREE[2]], "{what}, size {size:#x}");
                // clamscan makes no hash when it reads the descriptor.
                assert_eq!(clamscan_hash_of(&pe).is_none(), covered, "{what}, size {size:#x}");
                assert_eq!(analyze(&pe).unwrap().import_fault, covered, "{what}, size {size:#x}");
            }
        }
    }

    /// A name is read as the bytes the file holds: one that is not UTF-8 does
    /// not make the table unreadable.
    #[test]
    fn a_name_that_is_not_utf8_is_read() {
        let pe = pe_importing(&[(b"K\xe9.DLL", &[Name(b"a\xffb"), Name(b"c")])], 300);
        let t = tables(&pe, usize::MAX).unwrap();
        let imports = t.imports.unwrap();
        assert_eq!(imports.libraries[0].name, b"K\xe9.DLL");
        assert!(matches!(imports.libraries[0].functions[0], Function::Named { name, .. } if name == b"a\xffb"));
    }

    /// A section's data is taken from its pointer rounded down to 0x200, as
    /// Windows, clamscan and libyara take it.
    #[test]
    fn the_data_of_a_section_starts_at_its_pointer_rounded_down() {
        let mut pe = three_libraries();
        for pointer in [0x201, 0x210, 0x3ff] {
            set32(&mut pe, 0x148 + 20, pointer);
            assert_eq!(listed_in(&pe), ALL_THREE, "pointer {pointer:#x}");
        }
        // The rounded pointer does not reach another section's data.
        set32(&mut pe, 0x148 + 20, 0x400);
        let imports = tables(&pe, usize::MAX).unwrap().imports.unwrap();
        assert!(imports.fault && imports.libraries.is_empty());
    }

    /// A file alignment of 0, or one that is not a power of two, does not stop
    /// the sections from being mapped: the table is read, each reference by its
    /// own rule for where the data starts.
    #[test]
    fn a_file_alignment_that_is_not_a_power_of_two_still_maps_the_sections() {
        let mut pe = three_libraries();
        // The data is at 0x200 and the pointer says so: a multiple of 0x200,
        // and of 0x80, but not of 0x180.
        for (alignment, clamscan, yarax) in [
            (0, true, true),
            (0x180, true, false),
            (0x300, true, true),
            (0x600, true, true),
            (0xc00, true, true),
            (0x1800, true, true),
            (0x200, true, true),
            (0x1000, true, true),
        ] {
            set32(&mut pe, 0x58 + 36, alignment);
            let t = tables(&pe, usize::MAX).unwrap();
            assert_eq!(t.imports.as_ref().unwrap().libraries.len() == 3, clamscan, "clamscan, alignment {alignment:#x}");
            assert_eq!(t.listed().as_ref().unwrap().libraries.len() == 3, yarax, "yara-x, alignment {alignment:#x}");
        }
    }

    /// Where the data of a section starts for a pointer that is not a
    /// multiple of 0x200, by file alignment and section alignment, as measured
    /// on clamscan 1.4.3, libyara 4.5.2 and yara-x 1.21.0.
    #[test]
    fn the_data_of_a_section_starts_where_each_reference_puts_it() {
        let section = |pointer: u32| goblin::pe::section_table::SectionTable {
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            size_of_raw_data: 0x1000,
            pointer_to_raw_data: pointer,
            ..Default::default()
        };
        for (file, sect, pointer, clamscan, yarax) in [
            (0x200, 0x200, 0x7f0, 0x600, 0x600),
            (0x200, 0x1000, 0x7f0, 0x600, 0x600),
            (0x100, 0x200, 0x7f0, 0x700, 0x700),
            (0x100, 0x1000, 0x7f0, 0x700, 0x600),
            (0x80, 0x200, 0xbff, 0xb80, 0xb80),
            (0x4, 0x200, 0xbff, 0xbfc, 0xbfc),
            (0x1, 0x200, 0xbff, 0xbff, 0xbff),
            (0, 0x200, 0xbff, 0xbff, 0xbff),
            (0, 0x1000, 0xbff, 0xbff, 0xa00),
            (0x180, 0x200, 0xbff, 0xa00, 0xa80),
            (0x300, 0x200, 0xbff, 0xa00, 0xa00),
            (0x400, 0x200, 0xfff, 0xc00, 0xe00),
            (0x800, 0x200, 0xfff, 0xe00, 0xe00),
            (0x1000, 0x1000, 0xfff, 0xe00, 0xe00),
            (0x10000, 0x1000, 0xbff, 0xa00, 0xa00),
        ] {
            let what = format!("file alignment {file:#x}, section alignment {sect:#x}, pointer {pointer:#x}");
            assert_eq!(data_start(pointer, file), clamscan, "clamscan: {what}");
            assert_eq!(yarax_offset(0x1000, &[section(pointer)], file, sect), Some(yarax), "yara-x: {what}");
        }
        // A PE whose data is where clamscan puts it, and not where yara-x
        // does: each reads its own.
        let pe = three_libraries();
        let mut moved = pe[..0x200].to_vec();
        moved.resize(0x700, 0);
        moved.extend_from_slice(&pe[0x200..]);
        set32(&mut moved, 0x148 + 20, 0x7f0);
        set32(&mut moved, 0x58 + 36, 0x100);
        for (sect, yarax) in [(0x200, 3), (0x1000, 0)] {
            set32(&mut moved, 0x58 + 32, sect);
            let t = tables(&moved, usize::MAX).unwrap();
            assert_eq!(t.imports.as_ref().unwrap().libraries.len(), 3, "clamscan, section alignment {sect:#x}");
            assert_eq!(t.listed().as_ref().unwrap().libraries.len(), yarax, "yara-x, section alignment {sect:#x}");
        }
    }

    /// An entry that maps to the end of the object or past it is a thunk that
    /// names nothing: clamscan hashes it as an empty name, yara-x does not list
    /// it, and the other entries are read.
    #[test]
    fn an_entry_that_maps_to_the_end_of_the_object_names_nothing() {
        let len = pe_importing(&[(b"K.DLL", &[Name(b"A"), Raw(0)])], 0).len();
        // The first RVA past the section's data maps to the end of the file.
        let pe = pe_importing(&[(b"K.DLL", &[Name(b"A"), Raw(0x1000 + (len - 0x200) as u64)])], 0);
        assert_eq!(pe.len(), len);
        let t = tables(&pe, usize::MAX).unwrap();
        for imports in [t.imports.as_ref().unwrap(), t.listed().as_ref().unwrap()] {
            assert!(!imports.fault);
            assert!(matches!(imports.libraries[0].functions[1], Function::Unread));
        }
        // A is within 258 bytes of the end and left out of the clamscan hash.
        assert_eq!(clamscan_hash_of(&pe), Some((md5_of("k."), 2)));
        assert_eq!(listed_in(&pe), ["K.DLL.A"]);
    }

    /// A table of thunks that runs to the end of the object has the thunks it
    /// holds, as clamscan, libyara and yara-x read it; a thunk cut in two is
    /// not one.
    #[test]
    fn a_table_of_thunks_that_ends_with_the_object_has_the_thunks_it_holds() {
        let rva = |at: usize| (0x1000 + at) as u32;
        let mut body = vec![0u8; 40];
        let name = body.len();
        body.extend_from_slice(b"K.DLL\0\0\0");
        let (a, b) = (body.len(), body.len() + 4);
        body.extend_from_slice(b"\0\0A\0\0\0B\0");
        let table = body.len();
        for entry in [a, b] {
            body.extend_from_slice(&u64::from(rva(entry)).to_le_bytes());
        }
        set32(&mut body, 0, rva(table));
        set32(&mut body, 12, rva(name));
        set32(&mut body, 16, rva(table));
        let mut pe = minimal_pe(&body);
        set_dir(&mut pe, 1, rva(0), 40);
        pe.truncate(0x200 + body.len());
        for (cut, listed) in [(0, ["K.DLL.A", "K.DLL.B"].as_slice()), (4, ["K.DLL.A"].as_slice())] {
            let pe = &pe[..pe.len() - cut];
            let t = tables(pe, usize::MAX).unwrap();
            for imports in [t.imports.as_ref().unwrap(), t.listed().as_ref().unwrap()] {
                assert!(!imports.fault, "cut by {cut}");
                assert_eq!(imports.libraries[0].functions.len(), listed.len(), "cut by {cut}");
            }
            assert_eq!(listed_in(pe), listed, "cut by {cut}");
        }
    }

    /// goblin adds a section's pointer, sizes, alignment and an RVA in `usize`,
    /// and one laid out near 4 GiB made that overflow on a 32-bit target, which
    /// aborted a wasm32 build (the run of this suite there is the check). Such a
    /// section is not used to map an RVA.
    #[test]
    fn a_section_laid_out_near_4_gib_is_not_mapped_through_goblin() {
        let mut pe = pe_with_imports(1, 1);
        set32(&mut pe, 0x148 + 20, 0xffff_fe00);
        set32(&mut pe, 0x148 + 16, 0x1000);
        let t = tables(&pe, usize::MAX).unwrap();
        // Nothing is read, either because the section is left out or because
        // the data it points at is past the end of the file.
        assert!(t.imports.as_ref().map_or(true, |imports| imports.libraries.is_empty()));
    }

    /// A PE cut anywhere, or with any byte of its headers and tables set to
    /// 0, 0x7f, 0x80 or 0xff, is read to an answer and not to a panic (on a
    /// 32-bit target too: the run of this suite on wasm32 is the check).
    #[test]
    fn a_pe_cut_or_changed_anywhere_is_read_without_a_panic() {
        let read = |f: &[u8]| {
            let _ = analyze_within(f, f.len(), 1 << 20, Views::ALL, &mut |_| Ok(()));
        };
        // One with imports, and one with exports.
        for pe in [three_libraries(), pe_exporting()] {
            for cut in 0..pe.len() {
                read(&pe[..cut]);
            }
            for at in 0..pe.len().min(0x500) {
                for byte in [0x00, 0x7f, 0x80, 0xff] {
                    let mut bad = pe.clone();
                    bad[at] = byte;
                    read(&bad);
                }
            }
        }
    }

    /// The section headers are read as goblin reads them, long names (`/N`,
    /// `//` in base 64) included, and a name that says it is long and is not
    /// leaves the PE without headers, as goblin leaves it. What is read of the
    /// long names stops at the size of the file.
    #[test]
    fn section_headers_are_read_as_goblin_reads_them_within_the_file_size() {
        use goblin::pe::section_table::SectionTable;
        let header = |name: &[u8]| {
            let mut h = [0u8; 40];
            h[..name.len()].copy_from_slice(name);
            h[8..12].copy_from_slice(&0x1234u32.to_le_bytes());
            h[36..40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
            h
        };
        let same = |data: &[u8], count: usize, strings: usize| {
            let ours = section_table(data, &mut 0, count, strings).unwrap();
            let mut at = 0;
            for s in &ours {
                let theirs = SectionTable::parse(data, &mut at, strings).unwrap();
                assert_eq!(s, &theirs);
            }
            ours
        };
        let names: [&[u8]; 6] = [b".text", b"/4", b"//AAAAAE", b"/0", b"/999999", b"/4"];
        let mut data: Vec<u8> = names.iter().flat_map(|n| header(n)).collect();
        let strings = data.len();
        data.extend_from_slice(b"\0\0\0\0.debug_info\0");
        let read = same(&data, names.len(), strings);
        assert_eq!(read[1].real_name.as_deref(), Some(".debug_info"));
        assert_eq!(read[2].real_name.as_deref(), Some(".debug_info"));
        assert_eq!(read[3].real_name.as_deref(), Some(""));
        assert_eq!(read[4].real_name, None);
        assert!(section_table(&header(b"/x1"), &mut 0, 1, 40).is_none());
        assert!(SectionTable::parse(&header(b"/x1"), &mut 0, 40).is_err());

        // Long names that start along one long string: those read while the
        // file's size allows are goblin's, the rest are left unread.
        let count = 64;
        let mut data: Vec<u8> = (0..count).flat_map(|i| header(format!("/{i}").as_bytes())).collect();
        let strings = data.len();
        data.extend(std::iter::repeat_n(b'a', 4096));
        data.push(0);
        let ours = section_table(&data, &mut 0, count, strings).unwrap();
        let read: usize = ours.iter().filter_map(|s| s.real_name.as_ref()).map(String::len).sum();
        assert!(read <= data.len(), "{read} of {}", data.len());
        assert!(ours[0].real_name.is_some() && ours[count - 1].real_name.is_none());
        let mut at = 0;
        for s in ours.iter().filter(|s| s.real_name.is_some()) {
            assert_eq!(s, &SectionTable::parse(&data, &mut at, strings).unwrap());
        }
    }

    /// The end of the symbol table goblin adds to find the long names of
    /// sections, against the largest `usize`; a header whose table ends near
    /// 4 GiB aborted a wasm32 build (the run of the test above there is the
    /// check of the header itself).
    #[test]
    fn goblin_finds_the_string_table_when_its_sum_fits_in_usize() {
        let limit = u64::from(u32::MAX);
        for (pointer, count, fits) in [
            (0, 0, true),
            (0x1000, 100, true),
            (0x1_0000, 1_000_000, true),
            (0, 238_000_000, true),
            (0, 239_000_000, false),
            (0, 0xffff_ffff, false),
            (0xffff_0000, 10, false),
            (0xffff_ffff, 0, false),
        ] {
            assert_eq!(symbol_table_fits(pointer, count, limit), fits, "{pointer:#x} {count}");
            assert!(symbol_table_fits(pointer, count, u64::MAX));
        }
    }

    /// The sums goblin makes of a section, against the largest `usize`.
    #[test]
    fn goblin_maps_a_section_whose_sums_fit_in_usize() {
        let section = |pointer: u32, raw: u32, virtual_size: u32, virtual_address: u32| {
            goblin::pe::section_table::SectionTable {
                pointer_to_raw_data: pointer,
                size_of_raw_data: raw,
                virtual_size,
                virtual_address,
                ..Default::default()
            }
        };
        let limit = u64::from(u32::MAX);
        for (what, s, fits) in [
            ("a usual section", section(0x400, 0x200, 0x1a0, 0x1000), true),
            ("a large one", section(0x400, 0x4000_0000, 0x4000_0000, 0x1000), true),
            ("pointer near 4 GiB", section(0xffff_fe00, 0x1000, 0x1000, 0x1000), false),
            ("raw size near 4 GiB", section(0x400, 0xffff_f000, 0x1000, 0x1000), false),
            ("virtual size near 4 GiB", section(0x400, 0x200, 0xffff_ffff, 0x1000), false),
            ("address near 4 GiB", section(0x400, 0x200, 0x1000, 0xffff_f000), false),
        ] {
            assert_eq!(goblin_can_map(&s, 0x200, limit), fits, "{what}");
            // Every sum fits a 64-bit `usize`.
            assert!(goblin_can_map(&s, 0x200, u64::MAX), "{what}");
        }
        // The file alignment is one of the sums.
        let s = section(0xffff_0000, 0x200, 0x200, 0x1000);
        assert!(goblin_can_map(&s, 0x200, limit));
        assert!(!goblin_can_map(&s, 0x8000_0000, limit));
    }

    /// A table that fits is held in the memory counted for it, to the byte:
    /// the vectors are the size of what they hold. Two readings that agree on
    /// every RVA are one.
    #[test]
    fn a_table_that_fits_is_held_in_the_memory_counted() {
        let pe = pe_with_imports(5, 7);
        let t = tables(&pe, usize::MAX).unwrap();
        let imports = t.imports.as_ref().unwrap();
        assert_eq!(imports.libraries.len(), 5);
        assert_eq!(imports.libraries.capacity(), 5);
        for library in &imports.libraries {
            assert_eq!((library.functions.len(), library.functions.capacity()), (7, 7));
        }
        assert_eq!(imports.spent, 5 * (LIBRARY_COST + 7 * FUNCTION_COST));
        assert!(t.listed_apart.is_none(), "the yara-x reading is the one made");
        assert_eq!(t.held(), imports.spent);
    }

    /// The memory of a table is counted before any entry is looked at: a table
    /// over `room` allocates nothing for its functions (measured: 280 MB for
    /// one of 61 KB that was built as it was read, before it was refused).
    #[test]
    fn a_table_over_the_room_is_refused_before_any_entry_is_looked_at() {
        let (libs, thunks) = (50, 100);
        let pe = pe_with_imports(libs, thunks);
        // The hint/name entry every thunk points at.
        let entry = (0x1000 + 20 * (libs + 1) + 8 * (thunks + 1)) as u32;
        let looked = std::cell::Cell::new(0usize);
        let offset = |rva: u32| {
            if rva == entry {
                looked.set(looked.get() + 1);
            }
            rva.checked_sub(0x1000).map(|at| at as usize + 0x200)
        };
        let dir = goblin::pe::data_directories::DataDirectory {
            virtual_address: 0x1000,
            size: 20 * (libs as u32 + 1),
        };
        let cost = libs * (LIBRARY_COST + thunks * FUNCTION_COST);
        assert!(matches!(read_imports(&pe, dir, &offset, true, cost - 1), Err(Unread::TooLarge)));
        assert_eq!(looked.get(), 0, "an entry was looked at");
        let read = read_imports(&pe, dir, &offset, true, cost).unwrap();
        assert_eq!(read.libraries.len(), libs);
        assert_eq!(looked.get(), libs * thunks, "each entry is looked at once, by the second pass");
    }

    /// Offsets near the top of `usize`, which a PE read on a 32-bit target can
    /// map to, are not a panic: an overflow aborts a wasm32 build.
    #[test]
    fn offsets_near_the_top_of_usize_are_not_a_panic() {
        let (libs, thunks) = (2, 3);
        let pe = pe_with_imports(libs, thunks);
        let entry = (0x1000 + 20 * (libs + 1) + 8 * (thunks + 1)) as u32;
        let dir = goblin::pe::data_directories::DataDirectory { virtual_address: 0x1000, size: 60 };
        for top in [usize::MAX, usize::MAX - 1, usize::MAX - 2, usize::MAX - 19] {
            // The directory is there.
            let read = read_imports(&pe, dir, &|_| Some(top), true, usize::MAX).unwrap();
            assert!(read.libraries.is_empty() && read.fault);
            assert!(read.dir_end >= u64::try_from(top).unwrap_or(u64::MAX));
            // Only the entries are.
            let offset = |rva: u32| {
                if rva == entry {
                    Some(top)
                } else {
                    rva.checked_sub(0x1000).map(|at| at as usize + 0x200)
                }
            };
            let read = read_imports(&pe, dir, &offset, true, usize::MAX).unwrap();
            assert!(!read.fault);
            assert_eq!(read.libraries.len(), libs);
            for library in &read.libraries {
                assert!(library.functions.iter().all(|f| matches!(f, Function::Unread)));
            }
        }
    }

    /// A lookup table that maps nowhere, with no address table to read instead,
    /// is a function that cannot be read, which clamscan hashes as an empty
    /// name; with an address table that maps nowhere too, the descriptor
    /// cannot be read.
    #[test]
    fn a_lookup_table_that_maps_nowhere_and_no_address_table_is_a_function_that_cannot_be_read() {
        let second = 0x200 + 20;
        let mut pe = three_libraries();
        set32(&mut pe, second, 0x9000);
        set32(&mut pe, second + 16, 0);
        let t = tables(&pe, usize::MAX).unwrap();
        assert!(!t.imports.as_ref().unwrap().fault);
        let hashed = "kernel32.loadlibrarya,user32.,gdi32.bitblt";
        assert_eq!(clamscan_hash_of(&pe), Some((md5_of(hashed), hashed.len())));
        // yara-x lists the other two, and does not stop at it.
        assert_eq!(listed_in(&pe), [ALL_THREE[0], ALL_THREE[2]]);
        set32(&mut pe, second + 16, 0x9000);
        let t = tables(&pe, usize::MAX).unwrap();
        assert!(t.imports.as_ref().unwrap().fault);
        assert_eq!(clamscan_hash_of(&pe), None);
    }

    /// The names yara-x lists a library under, and not.
    #[test]
    fn a_library_is_listed_as_yarax_lists_it() {
        let long = [b"d".repeat(508), b".dll".to_vec()].concat();
        for (name, listed) in [
            (&b"KERNEL32.DLL"[..], true),
            (b"", true),
            (b"a.b", true),
            ("k\u{e9}rnel.dll".as_bytes(), true),
            (&long, true),
            (b"my lib.dll", false),
            (b"a?b", false),
            (b"a*b", false),
            (b"a\"b", false),
            (b"a<b", false),
            (b"a>b", false),
            (b"a|b", false),
            (b"a\x01b", false),
            (b"a\tb", false),
            (b"a\x7fb", false),
            (b"k\xe9rnel.dll", false),
        ] {
            let library = Library { index: 0, name, tableless: false, functions: Vec::new() };
            assert_eq!(library.listed_name().is_some(), listed, "{:?}", String::from_utf8_lossy(name));
        }
    }

    /// An import by ordinal is named from the table of its library when the
    /// whole name of the library is `ws2_32.dll`, `wsock32.dll` or
    /// `oleaut32.dll`, as yara-x has it; clamscan and libyara take the start
    /// of the name, so `.imp` hashes the name of the function.
    #[test]
    fn an_ordinal_is_named_for_the_whole_name_of_its_library_in_the_listing_and_its_start_in_the_hash() {
        for (library, listed, hashed) in [
            (&b"ws2_32.dll"[..], "WSAStartup", "wsastartup"),
            (b"WS2_32.DLL", "WSAStartup", "wsastartup"),
            (b"ws2_32.dllx", "ord115", "wsastartup"),
            (b"ws2_32.dll.mui", "ord115", "wsastartup"),
            (b"ws2_32", "ord115", "ord115"),
            (b"user32.dll", "ord115", "ord115"),
        ] {
            let pe = pe_importing(&[(library, &[Ordinal(115)])], 300);
            let name = String::from_utf8_lossy(library);
            assert_eq!(listed_in(&pe), [format!("{name}.{listed}")], "{name}");
            let stem = String::from_utf8_lossy(clamscan_stem(library)).to_ascii_lowercase();
            let string = format!("{stem}.{hashed}");
            assert_eq!(clamscan_hash_of(&pe), Some((md5_of(&string), string.len())), "{name}");
        }
    }

    /// yara-x stops listing at a descriptor with no table at all, and after
    /// 16384 thunks of a library, or the library that brings the total to 16384.
    /// The checks of exav's own count every function of the table.
    #[test]
    fn the_listing_stops_where_yarax_stops() {
        let many = |n: usize| -> Vec<Thunk> { (0..n).map(|_| Name(b"f")).collect() };
        for (counts, want) in [
            (&[16383][..], 16383),
            (&[16384], 16384),
            (&[16385], 16384),
            (&[20000], 16384),
            (&[10000, 10000], 20000),
            (&[6000, 6000, 6000], 18000),
            (&[16384, 5], 16384),
        ] {
            let thunks: Vec<Vec<Thunk>> = counts.iter().map(|&n| many(n)).collect();
            let libs: Vec<(&[u8], &[Thunk])> = thunks.iter().map(|t| (&b"K.DLL"[..], t.as_slice())).collect();
            let pe = pe_importing(&libs, 300);
            assert_eq!(listed_in(&pe).len(), want, "{counts:?}");
            let all: usize = counts.iter().sum();
            let t = tables(&pe, usize::MAX).unwrap();
            assert_eq!(t.listed().as_ref().unwrap().listed_in_full().count(), all, "{counts:?}");
            assert_eq!(analyze(&pe).unwrap().import_count, all, "{counts:?}");
        }
    }

    /// The import hash of `pe.imphash()`: the MD5 of `library.function`,
    /// lowercased and joined by commas, the library cut of a `.dll`, `.sys` or
    /// `.ocx` that ends its name; pefile gives these values for these imports.
    #[test]
    fn the_import_hash_of_the_pe_module_is_made_as_yarax_and_pefile_make_it() {
        let hash = |imports: &[(&str, &str)]| {
            let mut hash = ImpHash::new();
            for (library, function) in imports {
                hash.add(library, function);
            }
            hash.finish()
        };
        assert_eq!(hash(&[("KERNEL32.DLL", "LoadLibraryA"), ("kernel32.dll", "GetProcAddress")]), KERNEL32_HASH);
        assert_eq!(hash(&[]), md5_of(""));
        for (imports, string) in [
            (&[("lua5.1.dll", "f")][..], "lua5.1.f"),
            (&[("x.dllx", "f")], "x.dllx.f"),
            (&[("x.dll.dll", "f")], "x.dll.f"),
            (&[("x.SYS", "F"), ("y.Ocx", "G")], "x.f,y.g"),
            (&[("ntoskrnl.exe", "f")], "ntoskrnl.exe.f"),
            (&[(".dll", "f")], ".f"),
            (&[("\u{c9}.dll", "f")], "\u{e9}.f"),
            (&[("k", "\u{c9}")], "k.\u{e9}"),
            (&[("K", "f"), ("K", "g")], "k.f,k.g"),
        ] {
            assert_eq!(hash(imports), md5_of(string), "{imports:?}");
        }
        // 300 characters, which are lowercased in pieces.
        let (library, function) = ("D".repeat(300), "F".repeat(300));
        assert_eq!(hash(&[(&library, &function)]), md5_of(&format!("{}.{}", "d".repeat(300), "f".repeat(300))));
    }

    /// The image of an ELF file ends at the last of its header tables and the
    /// bytes its segments and sections hold in the file.
    #[test]
    fn the_image_of_an_elf_ends_at_its_last_table_or_contents() {
        let elf = include_bytes!("../tests/testdata/tiny_elf64").to_vec();
        // Header tables at 64 (one segment) and 168 (three sections): the
        // file ends with the section table.
        let mut file = elf.clone();
        file.extend(vec![b'z'; 100_000]);
        let cache = cached(&file);
        let slice: &[u8] = &file;
        for src in [&slice as &dyn ByteSource, &cache] {
            assert_eq!(elf_image_in(src, 1 << 20).as_deref(), Some(&elf[..]));
            assert_eq!(elf_image_in(src, elf.len() - 1), None);
        }
        // `.text`, the section at index 1 (header at 168 + 64), claims 90000
        // bytes at 128: they are the image's. As `SHT_NOBITS` they are not.
        let text_size = 168 + 64 + 32;
        let mut big = file.clone();
        big[text_size..text_size + 8].copy_from_slice(&90_000u64.to_le_bytes());
        assert_eq!(elf_image_in(&big, 1 << 20).map(|i| i.len()), Some(128 + 90_000));
        assert_eq!(elf_image_in(&big, 90_000), None);
        big[168 + 64 + 4..168 + 64 + 8].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(elf_image_in(&big, 1 << 20).map(|i| i.len()), Some(elf.len()));
        // A segment's bytes in the file.
        let mut seg = file.clone();
        seg[64 + 32..64 + 40].copy_from_slice(&60_000u64.to_le_bytes());
        assert_eq!(elf_image_in(&seg, 1 << 20).map(|i| i.len()), Some(60_000));
        // A section table past the object, over the limit, or with no entry
        // size to walk it by: no image.
        let mut bad = file.clone();
        bad[40..48].copy_from_slice(&(file.len() as u64).to_le_bytes());
        assert_eq!(elf_image_in(&bad, 1 << 20), None);
        let mut bad = file.clone();
        bad[58..60].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(elf_image_in(&bad, 1 << 20), None);
        // Not an ELF.
        assert_eq!(elf_image_in(&&b"MZ"[..], 1 << 20), None);
        // A count of 0 sections with a section table: the null section holds it.
        let mut counted = file.clone();
        counted[60..62].copy_from_slice(&0u16.to_le_bytes());
        counted[168 + 32..168 + 40].copy_from_slice(&3u64.to_le_bytes());
        assert_eq!(elf_image_in(&counted, 1 << 20).map(|i| i.len()), Some(elf.len()));
        // No section table at all: what the segment holds is the image.
        let mut none = file.clone();
        none[40..48].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(elf_image_in(&none, 1 << 20).map(|i| i.len()), Some(144));
    }

    /// A UPX header is found as `unpack::is_upx` finds one, in memory and
    /// through a cache, wherever the magic lies against the edges of the
    /// blocks of the cache; and only in the object's start.
    #[test]
    fn a_upx_header_is_found_as_is_upx_finds_it() {
        if !upx_compiled_in() {
            return;
        }
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let sizes = [0u32, 1, 2, 5, 8, 14, 36, 40, 1000, 256 << 20, (256 << 20) + 1, u32::MAX];
        let seam = crate::byte_source::CHUNK;
        let starts = [4, 5, 100, seam - 8, seam - 4, seam - 3, seam + 1, 2 * seam - 40, 2 * seam - 35];
        let (mut yes, mut no) = (0, 0);
        for k in 0..2000 {
            // `at` is the checksum before the magic: the header starts there.
            let at = starts[k % starts.len()];
            let mut buf = vec![b'.'; at + 36 + (next() % 70) as usize];
            buf[at + 4..at + 8].copy_from_slice(b"UPX!");
            buf[at + 10] = [2u8, 5, 8, 14, 0][k % 5];
            for field in [16, 20, 24, 28] {
                let v = sizes[(next() % sizes.len() as u64) as usize];
                set32(&mut buf, at + field, if next() % 3 == 0 { v % 90 } else { v });
            }
            let want = crate::unpack::is_upx(&buf);
            assert_eq!(upx_header_in(&&buf[..]), want, "{k}");
            assert_eq!(upx_header_in(&cached(&buf)), want, "{k} through a cache");
            if want {
                yes += 1;
            } else {
                no += 1;
            }
        }
        assert!(yes > 100 && no > 100, "{yes} headers found and {no} not");
        // A magic in the first 4 bytes has no checksum before it.
        assert!(!upx_header_in(&&b"UPX!"[..]));
        // A lone magic in a long object is not a header, and a header is
        // found past the first block, in the start; past the start it is not
        // looked for, as UPX writes it at the start.
        let start = 4 * 1024 * 1024 + 1024;
        let mut long = vec![b'.'; start + 5 * seam];
        long[3 * seam..3 * seam + 4].copy_from_slice(b"UPX!");
        assert!(!upx_header_in(&&long[..]));
        let header = |long: &mut Vec<u8>, at: usize| {
            long[at + 4..at + 8].copy_from_slice(b"UPX!");
            long[at + 10] = 2;
            set32(long, at + 20, 100);
            set32(long, at + 24, 100);
        };
        let mut far = long.clone();
        header(&mut long, 4 * seam - 20);
        assert!(upx_header_in(&&long[..]) && crate::unpack::is_upx(&long));
        assert!(upx_header_in(&cached(&long)));
        header(&mut far, start + seam);
        assert!(!upx_header_in(&&far[..]) && !crate::unpack::is_upx(&far));
        assert!(!upx_header_in(&cached(&far)));
    }
}
