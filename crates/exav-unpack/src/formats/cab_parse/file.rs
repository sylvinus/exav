#[derive(Clone, Debug)]
pub(crate) struct FileEntry {
    pub(crate) uncompressed_size: u32,
    pub(crate) folder_index: u16,
    pub(crate) data_offset: u32,
    pub(crate) name: String,
}

impl FileEntry {
    pub(crate) fn new(
        _date: u16,
        _time: u16,
        _attributes: u16,
        uncompressed_size: u32,
        folder_index: u16,
        data_offset: u32,
        name: String,
    ) -> FileEntry {
        FileEntry {
            uncompressed_size,
            folder_index,
            data_offset,
            name,
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}
