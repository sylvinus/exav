use std::io::{self, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::formats::cab_parse::consts;
use crate::formats::cab_parse::ctype::CompressionType;
use crate::formats::cab_parse::file::FileEntry;
use crate::formats::cab_parse::string::read_null_terminated_string;

pub(crate) struct Cabinet;

/// A CFFOLDER's location and codec, parsed without decompressing its data.
pub(crate) struct FolderMeta {
    pub first_data_offset: u32,
    pub num_data_blocks: u16,
    pub compression_type: CompressionType,
}

impl Cabinet {
    /// Parse the CFHEADER, CFFOLDER table, and CFFILE table **without**
    /// decompressing any folder data. The extractor walks the files and decodes
    /// each folder lazily (via [`super::folder::FolderReader`]).
    pub(crate) fn layout<R: Read + Seek>(
        reader: &mut R,
    ) -> io::Result<(Vec<FolderMeta>, Vec<FileEntry>)> {
        reader.seek(SeekFrom::Start(0))?;

        // === Fixed CFHEADER (36 bytes) ===
        let signature = reader.read_u32::<LittleEndian>()?;
        if signature != consts::FILE_SIGNATURE {
            invalid_data!("Cabinet has invalid signature");
        }
        let _reserved1 = reader.read_u32::<LittleEndian>()?;
        let _total_size = reader.read_u32::<LittleEndian>()?;
        let _reserved2 = reader.read_u32::<LittleEndian>()?;
        let first_file_offset = reader.read_u32::<LittleEndian>()?;
        let _reserved3 = reader.read_u32::<LittleEndian>()?;
        let _minor_version = reader.read_u8()?;
        let _major_version = reader.read_u8()?;
        let num_folders = reader.read_u16::<LittleEndian>()?;
        let num_files = reader.read_u16::<LittleEndian>()?;
        let flags = reader.read_u16::<LittleEndian>()?;
        let _set_id = reader.read_u16::<LittleEndian>()?;
        let _cabinet_index = reader.read_u16::<LittleEndian>()?;

        if flags & consts::FLAG_PREV_CABINET != 0 {
            invalid_input!("Multi-cabinet files are not supported");
        }

        // === Optional reserve area ===
        let mut header_reserve_size = 0u16;
        let mut folder_reserve_size: usize = 0;
        let mut _data_reserve_size: u8 = 0;
        if flags & consts::FLAG_RESERVE_PRESENT != 0 {
            header_reserve_size = reader.read_u16::<LittleEndian>()?;
            folder_reserve_size = reader.read_u8()? as usize;
            _data_reserve_size = reader.read_u8()?;
        }
        if header_reserve_size > 0 {
            let mut skip = vec![0u8; header_reserve_size as usize];
            reader.read_exact(&mut skip)?;
        }

        // === Continuation strings (not supported) ===
        if flags & consts::FLAG_NEXT_CABINET != 0 {
            let _ = read_null_terminated_string(reader, false)?;
            let _ = read_null_terminated_string(reader, false)?;
        }

        // === CFFOLDER entries (contiguous; data blocks are read later) ===
        let mut folder_metas = Vec::with_capacity(num_folders as usize);
        for _ in 0..num_folders {
            let first_data_offset = reader.read_u32::<LittleEndian>()?;
            let num_data_blocks = reader.read_u16::<LittleEndian>()?;
            let compression_bits = reader.read_u16::<LittleEndian>()?;
            let compression_type = CompressionType::from_bitfield(compression_bits)?;
            if folder_reserve_size > 0 {
                let mut skip = vec![0u8; folder_reserve_size];
                reader.read_exact(&mut skip)?;
            }
            folder_metas.push(FolderMeta {
                first_data_offset,
                num_data_blocks,
                compression_type,
            });
        }

        // === CFFILE entries (at first_file_offset) ===
        reader.seek(SeekFrom::Start(first_file_offset as u64))?;
        let mut file_entries = Vec::new();
        for _ in 0..num_files {
            let uncompressed_size = reader.read_u32::<LittleEndian>()?;
            let uncompressed_offset = reader.read_u32::<LittleEndian>()?;
            let folder_index = reader.read_u16::<LittleEndian>()?;
            let date = reader.read_u16::<LittleEndian>()?;
            let time = reader.read_u16::<LittleEndian>()?;
            let attributes = reader.read_u16::<LittleEndian>()?;
            let is_utf8 = (attributes & consts::ATTR_NAME_IS_UTF) != 0;
            let name = read_null_terminated_string(reader, is_utf8)?;
            file_entries.push(FileEntry::new(
                date,
                time,
                attributes,
                uncompressed_size,
                folder_index,
                uncompressed_offset,
                name,
            ));
        }
        Ok((folder_metas, file_entries))
    }
}
