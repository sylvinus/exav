//! The resource tree of a PE executable, read as far as it takes to find one
//! resource, and the one resource that names an Inno Setup installer.
//!
//! Kept apart from the Inno reader because typing an object as Inno Setup
//! asks the same question the reader does, and typing does not depend on the
//! reader being compiled in. It follows the headers and the tree wherever
//! they lead, so what it finds does not depend on how much of the file lies
//! before it.

use crate::pe::{Headers, Window, le16, le32};

/// The loader table's magic from Inno Setup 5.1.5 on, and the variant some
/// builds of that version write.
pub(crate) const LOADER_MAGICS: [&[u8; 12]; 2] =
    [b"rDlPtS\xcd\xe6\xd7{\x0b*", b"nS5W7dT\x83\xaa\x1b\x0fj"];
/// The loader table's magic before 5.1.5 (versions 1.2.10 to 5.1.4), as
/// innoextract lists them.
const OLD_LOADER_MAGICS: [&[u8; 12]; 5] = [
    b"rDlPtS02\x87eVx",
    b"rDlPtS04\x87eVx",
    b"rDlPtS05\x87eVx",
    b"rDlPtS06\x87eVx",
    b"rDlPtS07\x87eVx",
];
/// Where an installer before 5.1.5 says its loader table is: `Inno`, the
/// table's offset and its complement.
const OLD_LOADER_HEADER: usize = 0x30;
/// The loader table's resource: type RCDATA, name 11111.
pub(crate) const RT_RCDATA: u32 = 10;
pub(crate) const LOADER_RESOURCE: u32 = 11111;

/// The file offsets of the data of the resource `name` of type `kind` of the
/// PE executable that `window` reads, one for each language it is in.
pub(crate) fn resource_offsets(window: &Window, kind: u32, name: u32) -> Option<Vec<usize>> {
    const ENTRY: usize = 8;
    const SUBDIRECTORY: u32 = 1 << 31;
    let headers = Headers::read(window)?;
    // The resource table is the third data directory.
    let root = headers.rva_to_offset(headers.directories.get(2)?.address)?;
    // The entries of the directory at `at` as `(id, target)`, those named
    // first: a name is not an id, so they are told apart by their position.
    let entries = |at: usize| -> Option<(usize, Vec<(u32, u32)>)> {
        let d = window(at, 16);
        let named = usize::from(le16(&d, 12)?);
        let count = named + usize::from(le16(&d, 14)?);
        let e = window(at.checked_add(16)?, count * ENTRY);
        let all: Vec<(u32, u32)> = e
            .as_chunks::<ENTRY>()
            .0
            .iter()
            .filter_map(|c| Some((le32(c, 0)?, le32(c, 4)?)))
            .collect();
        (all.len() == count).then_some((named, all))
    };
    let subdirectory = |at: usize, id: u32| -> Option<usize> {
        let (named, all) = entries(at)?;
        let (_, target) = all[named..].iter().find(|e| e.0 == id)?;
        if target & SUBDIRECTORY == 0 {
            return None;
        }
        root.checked_add((target & !SUBDIRECTORY) as usize)
    };
    let by_name = subdirectory(subdirectory(root, kind)?, name)?;
    let (_, languages) = entries(by_name)?;
    let mut found = Vec::new();
    for (_, target) in languages {
        if target & SUBDIRECTORY != 0 {
            return None;
        }
        let leaf = window(root.checked_add(target as usize)?, 8);
        found.push(headers.rva_to_offset(le32(&leaf, 0)?)?);
    }
    Some(found)
}

/// Whether `src` is an Inno Setup installer: a PE executable whose resource
/// RCDATA 11111 starts, in some language, with the magic of a loader table.
/// Setup finds its data through that resource, so an installer has it
/// wherever the executable's code and padding put it.
pub(crate) fn has_inno_loader(window: &Window) -> bool {
    resource_offsets(window, RT_RCDATA, LOADER_RESOURCE).is_some_and(|tables| {
        tables.into_iter().any(|at| {
            let magic = window(at, LOADER_MAGICS[0].len());
            LOADER_MAGICS.iter().any(|m| magic.starts_with(&m[..]))
        })
    })
}

/// Whether `src` is an Inno Setup installer before 5.1.5, which has no loader
/// resource: the executable says where its loader table is at 0x30, and the
/// table starts with the magic of its version, as innoextract reads it.
pub(crate) fn has_old_inno_loader(window: &Window) -> bool {
    let h = window(OLD_LOADER_HEADER, 12);
    match (le32(&h, 0), le32(&h, 4), le32(&h, 8)) {
        (Some(0x6f6e_6e49), Some(at), Some(not)) if at == !not => {
            let magic = window(at as usize, OLD_LOADER_MAGICS[0].len());
            OLD_LOADER_MAGICS.iter().any(|m| magic.starts_with(&m[..]))
        }
        _ => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::source::ByteSource;

    /// The bytes of a loader table.
    const LOADER_TABLE: usize = 44;

    fn put(v: &mut [u8], at: usize, bytes: &[u8]) {
        v[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// A PE32 whose only resource is `data`, of type `kind` and name `name`,
    /// in one language. Its section, and so the resource, starts `raw` bytes
    /// into the file.
    pub(crate) fn pe_with_resource(raw: usize, kind: u32, name: u32, data: &[u8]) -> Vec<u8> {
        // The tree: the root, the type, the name, a data entry, then the data.
        let tree = 16 + 8 + 16 + 8 + 16 + 8 + 16;
        let size = tree + data.len();
        let mut f = vec![0u8; raw + size];
        put(&mut f, 0, b"MZ");
        put(&mut f, 0x3c, &0x40u32.to_le_bytes());
        put(&mut f, 0x40, b"PE\0\0");
        put(&mut f, 0x44, &0x14cu16.to_le_bytes());
        put(&mut f, 0x46, &1u16.to_le_bytes());
        put(&mut f, 0x54, &0xe0u16.to_le_bytes());
        let opt = 0x58;
        put(&mut f, opt, &0x10bu16.to_le_bytes());
        put(&mut f, opt + 92, &16u32.to_le_bytes());
        // The resource directory is the third.
        put(&mut f, opt + 96 + 16, &0x1000u32.to_le_bytes());
        put(&mut f, opt + 96 + 20, &(size as u32).to_le_bytes());
        let section = opt + 0xe0;
        put(&mut f, section, b".rsrc");
        put(&mut f, section + 8, &(size as u32).to_le_bytes());
        put(&mut f, section + 12, &0x1000u32.to_le_bytes());
        put(&mut f, section + 16, &(size as u32).to_le_bytes());
        put(&mut f, section + 20, &(raw as u32).to_le_bytes());
        let sub = 1u32 << 31;
        // Each directory has one entry, an id.
        let directory = |f: &mut Vec<u8>, at: usize, id: u32, target: u32| {
            put(f, raw + at + 14, &1u16.to_le_bytes());
            put(f, raw + at + 16, &id.to_le_bytes());
            put(f, raw + at + 20, &target.to_le_bytes());
        };
        directory(&mut f, 0, kind, sub | 24);
        directory(&mut f, 24, name, sub | 48);
        directory(&mut f, 48, 0x409, 72);
        // The data entry: where the data is in memory, and how long it is.
        put(&mut f, raw + 72, &(0x1000 + tree as u32).to_le_bytes());
        put(&mut f, raw + 76, &(data.len() as u32).to_le_bytes());
        put(&mut f, raw + tree, data);
        f
    }

    fn loader() -> Vec<u8> {
        let mut table = LOADER_MAGICS[0].to_vec();
        table.resize(LOADER_TABLE, 0);
        table
    }

    /// An executable that has an Inno Setup loader table in its resources,
    /// which start `raw` bytes into the file.
    pub(crate) fn inno_stub(raw: usize) -> Vec<u8> {
        pe_with_resource(raw, RT_RCDATA, LOADER_RESOURCE, &loader())
    }

    fn offsets(file: &[u8], kind: u32, name: u32) -> Option<Vec<usize>> {
        resource_offsets(&|off, len| ByteSource::window(file, off, len), kind, name)
    }

    fn inno(file: &[u8]) -> bool {
        has_inno_loader(&|off, len| ByteSource::window(file, off, len))
    }

    /// Where `pe_with_resource` puts the optional header and the section table.
    const OPT: usize = 0x58;
    const TABLE: usize = OPT + 0xe0;

    /// The image must start with the DOS signature, as the loader requires.
    #[test]
    fn an_image_without_the_dos_signature_has_no_resources() {
        let mut pe = pe_with_resource(0x400, RT_RCDATA, LOADER_RESOURCE, &loader());
        assert!(offsets(&pe, RT_RCDATA, LOADER_RESOURCE).is_some());
        pe[0] = b'Z';
        assert!(offsets(&pe, RT_RCDATA, LOADER_RESOURCE).is_none());
    }

    /// A data directory entry is only there if all of it lies inside the
    /// optional header.
    #[test]
    fn a_directory_entry_cut_by_the_optional_header_is_not_there() {
        // The third entry is at 96 + 16 to 96 + 24.
        let with_optional_size = |size: usize| {
            let mut pe = pe_with_resource(0x400, RT_RCDATA, LOADER_RESOURCE, &loader());
            pe[OPT - 4..OPT - 2].copy_from_slice(&(size as u16).to_le_bytes());
            pe.copy_within(TABLE..TABLE + 40, OPT + size);
            offsets(&pe, RT_RCDATA, LOADER_RESOURCE)
        };
        assert!(with_optional_size(120).is_some());
        // Its address is inside, its size is not.
        assert!(with_optional_size(116).is_none());
    }

    /// A table with more sections than the loader of Windows XP takes is
    /// read: later Windows takes up to 65535.
    #[test]
    fn a_long_section_table_is_read() {
        let mut pe = pe_with_resource(0x2000, RT_RCDATA, LOADER_RESOURCE, &loader());
        let header: Vec<u8> = pe[TABLE..TABLE + 40].to_vec();
        pe[TABLE..TABLE + 40].fill(0);
        pe[OPT - 18..OPT - 16].copy_from_slice(&100u16.to_le_bytes());
        pe[TABLE + 99 * 40..TABLE + 100 * 40].copy_from_slice(&header);
        assert!(offsets(&pe, RT_RCDATA, LOADER_RESOURCE).is_some());
    }

    /// A section with no virtual size is as long as its raw data; a
    /// resource past the virtual size is found while it is in the page of
    /// the virtual size and in the raw data.
    #[test]
    fn a_resource_is_found_to_the_end_of_the_page_of_the_virtual_size() {
        let mut pe = pe_with_resource(0x400, RT_RCDATA, LOADER_RESOURCE, &loader());
        let at = offsets(&pe, RT_RCDATA, LOADER_RESOURCE).unwrap();
        pe[TABLE + 8..TABLE + 12].fill(0);
        assert_eq!(offsets(&pe, RT_RCDATA, LOADER_RESOURCE).unwrap(), at);
        // The data is 88 bytes into the section, past a virtual size of 80.
        pe[TABLE + 8..TABLE + 12].copy_from_slice(&80u32.to_le_bytes());
        assert_eq!(offsets(&pe, RT_RCDATA, LOADER_RESOURCE).unwrap(), at);
    }

    /// The loader maps the headers: a resource tree below the size of
    /// headers is read.
    #[test]
    fn a_resource_tree_in_the_headers_is_found() {
        let mut pe = pe_with_resource(0x400, RT_RCDATA, LOADER_RESOURCE, &loader());
        let at = offsets(&pe, RT_RCDATA, LOADER_RESOURCE).unwrap();
        // The tree is at RVA 0x400, the same offset, and the section that
        // held it is moved away; the data entry follows the section.
        pe[OPT + 96 + 16..OPT + 96 + 20].copy_from_slice(&0x400u32.to_le_bytes());
        pe[TABLE + 12..TABLE + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[0x400 + 72..0x400 + 76].copy_from_slice(&(0x2000u32 + 88).to_le_bytes());
        assert!(offsets(&pe, RT_RCDATA, LOADER_RESOURCE).is_none());
        pe[OPT + 60..OPT + 64].copy_from_slice(&0x800u32.to_le_bytes());
        assert_eq!(offsets(&pe, RT_RCDATA, LOADER_RESOURCE).unwrap(), at);
    }

    #[test]
    fn a_resource_is_found_wherever_the_file_puts_it() {
        for raw in [0x400, 0x1_0000, 5 << 20] {
            let pe = pe_with_resource(raw, RT_RCDATA, LOADER_RESOURCE, &loader());
            let at = offsets(&pe, RT_RCDATA, LOADER_RESOURCE).unwrap();
            // The data follows the tree, which is 88 bytes.
            assert_eq!(at, vec![raw + 88], "section at {raw}");
            assert!(offsets(&pe, RT_RCDATA, 11112).is_none());
            assert!(offsets(&pe, 3, LOADER_RESOURCE).is_none());
        }
    }

    /// An Inno Setup installer has the loader table in its resource, however
    /// far into the executable that is; other data in the resource, or the
    /// table anywhere else, is none.
    #[test]
    fn an_inno_loader_is_told_by_its_resource_not_by_where_it_lies() {
        for raw in [0x400, 5 << 20] {
            let pe = pe_with_resource(raw, RT_RCDATA, LOADER_RESOURCE, &loader());
            assert!(inno(&pe), "section at {raw}");
        }
        let mut variant = LOADER_MAGICS[1].to_vec();
        variant.resize(LOADER_TABLE, 0);
        let pe = pe_with_resource(0x400, RT_RCDATA, LOADER_RESOURCE, &variant);
        assert!(inno(&pe));
        let pe = pe_with_resource(0x400, RT_RCDATA, LOADER_RESOURCE, &[0; LOADER_TABLE]);
        assert!(!inno(&pe));
        let pe = pe_with_resource(0x400, RT_RCDATA, 11112, &loader());
        assert!(!inno(&pe));
        let pe = pe_with_resource(0x400, 3, LOADER_RESOURCE, &loader());
        assert!(!inno(&pe));
        // The magic in the file, outside any resource.
        let mut bare = b"MZ".to_vec();
        bare.resize(64, 0);
        bare.extend(loader());
        assert!(!inno(&bare));
        assert!(!inno(&[]));
    }
}
