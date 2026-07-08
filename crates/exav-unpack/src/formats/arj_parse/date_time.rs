#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DosDateTime(u32);

impl DosDateTime {
    pub fn new(date_time_modified: u32) -> Self {
        Self(date_time_modified)
    }
}

impl From<DosDateTime> for u32 {
    fn from(dt: DosDateTime) -> u32 {
        dt.0
    }
}
