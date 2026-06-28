use std::collections::HashMap;

#[derive(Debug, Clone)]
pub(crate) enum Primitive {
    Null,
    Boolean(bool),
    Integer(i64),
    Real,
    Name(String),
    String(Vec<u8>),
    Array(Vec<Primitive>),
    Dictionary(HashMap<String, Primitive>),
    Stream {
        info: HashMap<String, Primitive>,
        data: Vec<u8>,
    },
}

impl Primitive {
    pub(crate) fn as_str(&self) -> Option<&[u8]> {
        match self {
            Primitive::String(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            Primitive::Integer(n) => Some(*n),
            _ => None,
        }
    }

    pub(crate) fn as_u32(&self) -> Option<u32> {
        self.as_i64().and_then(|n| u32::try_from(n).ok())
    }
}
