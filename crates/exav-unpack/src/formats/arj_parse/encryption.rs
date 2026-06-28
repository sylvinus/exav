#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArjEncryption {
    Garble,
    Gost40,
    Gost256,
    Unknown,
}

impl ArjEncryption {
    pub fn from_version(version: u8, is_garbled: bool) -> Option<Self> {
        if !is_garbled {
            return None;
        }
        Some(match version {
            0 | 1 => ArjEncryption::Garble,
            2 => ArjEncryption::Gost40,
            v if v >= 3 => ArjEncryption::Gost256,
            _ => ArjEncryption::Unknown,
        })
    }
}
