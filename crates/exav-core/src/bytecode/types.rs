//! Type table (`T` record) and constant globals (`G` record) decoding.
//!
//! Type ids `<= 64` are integers of that many bits; ids `>= 65` index a table
//! whose first [`NUM_STATIC`] entries are predefined pointer types and the rest
//! are declared in the `T` record. Globals are constant initializers laid out
//! as a flat list of 64-bit components (a pointer is two components), needed by
//! the VM to resolve pointer operands.

use super::decode::Reader;
use super::parse::ParseError;

/// First user type id; ids 65..69 are predefined pointer types.
const START_TID: u32 = 69;
/// Predefined pointer types occupying ids 65..69.
const NUM_STATIC: usize = (START_TID - 65) as usize;
const MAX_TYPES: usize = 1 << 20;
const MAX_GLOBAL_COMPONENTS: usize = 1 << 24;

#[derive(Debug, Clone)]
pub enum TypeDef {
    /// A predefined or declared pointer (to a contained type).
    Pointer(u32),
    Array {
        elements: u32,
        contained: u32,
    },
    Struct {
        packed: bool,
        fields: Vec<u32>,
    },
    Function {
        ret: u32,
        args: Vec<u32>,
    },
}

/// The decoded type table (indexed by `id - 65`).
#[derive(Debug, Clone, Default)]
pub struct TypeTable {
    defs: Vec<TypeDef>,
}

fn perr(msg: &'static str) -> ParseError {
    ParseError(msg.into())
}

impl TypeTable {
    /// Decode a `T` record (without its leading `T`). `num_types` comes from the
    /// file header.
    pub fn parse(rec: &[u8], num_types: u32) -> Result<Self, ParseError> {
        let mut r = Reader::new(rec);
        let m = |_| perr("truncated type record");
        let start_tid = r.fixed(2).map_err(m)? as u32;
        if start_tid != START_TID {
            return Err(perr("unexpected type start id"));
        }
        let num_types = num_types as usize;
        if num_types > MAX_TYPES {
            return Err(perr("too many types"));
        }
        // Predefined static pointer types (ids 65..69): pointers to i8, i16,
        // i32, i64 respectively (contained-type codes {8,16,32,64}). Their
        // pointee size is what GEP uses to scale an index, so this must be
        // exact — `Pointer(0)` would make every typed GEP stride by 1.
        let mut defs = vec![
            TypeDef::Pointer(8),
            TypeDef::Pointer(16),
            TypeDef::Pointer(32),
            TypeDef::Pointer(64),
        ];
        debug_assert_eq!(defs.len(), NUM_STATIC);
        // Declared types: ids START_TID..(num_types+65), i.e. indices NUM_STATIC..num_types-1.
        for _ in NUM_STATIC..num_types.saturating_sub(1) {
            let kind = r.fixed(1).map_err(m)?;
            let def = match kind {
                1 => {
                    // Function: numElements then that many contained type ids
                    // (ret + args).
                    let (ret, args) = read_contained(&mut r)?;
                    TypeDef::Function { ret, args }
                }
                2 | 3 => {
                    let (first, rest) = read_contained(&mut r)?;
                    let mut fields = vec![first];
                    fields.extend(rest);
                    TypeDef::Struct {
                        packed: kind == 2,
                        fields,
                    }
                }
                4 => {
                    let elements = r.number_u32().map_err(m)?;
                    let contained = read_type_id(&mut r)?;
                    TypeDef::Array {
                        elements,
                        contained,
                    }
                }
                5 => TypeDef::Pointer(read_type_id(&mut r)?),
                _ => return Err(perr("unknown type kind")),
            };
            defs.push(def);
        }
        Ok(TypeTable { defs })
    }

    fn get(&self, id: u32) -> Option<&TypeDef> {
        self.defs.get(id.checked_sub(65)? as usize)
    }

    /// Size in bytes of a value of this type, as laid out in the VM's value
    /// buffer. Integer ids `<= 64` round up to 1/2/4/8 bytes; pointers are 8;
    /// aggregates sum (no inter-field padding, as the format specifies). The
    /// high `0x8000` flag (a "this value is a buffer" marker) is ignored here.
    pub fn size(&self, id: u32) -> usize {
        self.size_depth(id & 0x7fff, 0)
    }

    fn size_depth(&self, t: u32, depth: u32) -> usize {
        if depth > 64 {
            return 0;
        }
        match t {
            0 => 0,
            1..=8 => 1,
            9..=16 => 2,
            17..=32 => 4,
            33..=64 => 8,
            _ => match self.get(t) {
                Some(TypeDef::Pointer(_)) => 8,
                Some(TypeDef::Array {
                    elements,
                    contained,
                }) => self
                    .size_depth(*contained, depth + 1)
                    .saturating_mul(*elements as usize),
                Some(TypeDef::Struct { fields, .. }) => fields
                    .iter()
                    .map(|&f| self.size_depth(f, depth + 1))
                    .fold(0usize, usize::saturating_add),
                _ => 0,
            },
        }
    }

    /// The pointed-at type of a pointer type. Declared pointer types yield
    /// their contained type; the `0x8000`-flagged integer "buffer" encoding
    /// (e.g. `0x8000 | 8` = `i8*`) yields the integer type it buffers.
    pub fn pointee(&self, id: u32) -> Option<u32> {
        let t = id & 0x7fff;
        if t > 64 {
            if let Some(TypeDef::Pointer(c)) = self.get(t) {
                return Some(*c);
            }
            return None;
        }
        if id & 0x8000 != 0 {
            return Some(t);
        }
        None
    }

    /// Byte offset of struct field `index` (sum of preceding field sizes), if
    /// `id` is a struct type.
    pub fn field_offset(&self, id: u32, index: usize) -> Option<usize> {
        match self.get(id & 0x7fff)? {
            TypeDef::Struct { fields, .. } => Some(
                fields
                    .iter()
                    .take(index)
                    .map(|&f| self.size(f))
                    .fold(0usize, usize::saturating_add),
            ),
            _ => None,
        }
    }

    /// True if `id` names a struct type.
    pub fn is_struct(&self, id: u32) -> bool {
        matches!(self.get(id & 0x7fff), Some(TypeDef::Struct { .. }))
    }

    /// Alignment in bytes for laying this type out (integers align to their
    /// size, pointers to 8, aggregates to their strictest field).
    pub fn align(&self, id: u32) -> usize {
        self.align_depth(id & 0x7fff, 0)
    }

    fn align_depth(&self, t: u32, depth: u32) -> usize {
        if depth > 64 {
            return 1;
        }
        if t <= 64 {
            return self.size_depth(t, depth).max(1);
        }
        match self.get(t) {
            Some(TypeDef::Pointer(_)) => 8,
            Some(TypeDef::Array { contained, .. }) => self.align_depth(*contained, depth + 1),
            Some(TypeDef::Struct { fields, .. }) => fields
                .iter()
                .map(|&f| self.align_depth(f, depth + 1))
                .max()
                .unwrap_or(1),
            _ => 1,
        }
    }

    /// Number of 64-bit components a value of this type occupies in a constant
    /// initializer. Integers = 1, pointer = 2, aggregates recurse.
    pub fn components(&self, id: u32) -> Result<usize, ParseError> {
        self.components_depth(id, 0)
    }

    fn components_depth(&self, id: u32, depth: u32) -> Result<usize, ParseError> {
        if depth > 64 {
            return Err(perr("recursive type"));
        }
        if id <= 64 {
            return Ok(1);
        }
        match self.get(id).ok_or(perr("bad type id"))? {
            TypeDef::Pointer(_) => Ok(2),
            TypeDef::Array {
                elements,
                contained,
            } => {
                let each = self.components_depth(*contained, depth + 1)?;
                Ok(each.saturating_mul(*elements as usize))
            }
            TypeDef::Struct { fields, .. } => {
                let mut sum = 0usize;
                for &f in fields {
                    sum = sum.saturating_add(self.components_depth(f, depth + 1)?);
                }
                Ok(sum)
            }
            TypeDef::Function { .. } => Err(perr("function type not a value")),
        }
    }
}

/// Read `numElements` then that many type ids; returns (first, rest).
fn read_contained(r: &mut Reader) -> Result<(u32, Vec<u32>), ParseError> {
    let m = |_| perr("truncated type");
    let n = r.number_u32().map_err(m)? as usize;
    if n == 0 || n > MAX_TYPES {
        return Err(perr("bad contained-type count"));
    }
    let first = read_type_id(r)?;
    let mut rest = Vec::with_capacity(n - 1);
    for _ in 1..n {
        rest.push(read_type_id(r)?);
    }
    Ok((first, rest))
}

fn read_type_id(r: &mut Reader) -> Result<u32, ParseError> {
    r.number_u32().map_err(|_| perr("truncated type id"))
}

/// Constant globals: a flat list, per global a list of 64-bit components.
#[derive(Debug, Clone, Default)]
pub struct Globals {
    pub values: Vec<Vec<u64>>,
}

impl Globals {
    /// Decode a `G` record (without its leading `G`) using `types` for
    /// component counts.
    pub fn parse(rec: &[u8], types: &TypeTable) -> Result<Self, ParseError> {
        let mut r = Reader::new(rec);
        let m = |_| perr("truncated globals");
        let _maxglobal = r.number().map_err(m)?;
        let num = r.number().map_err(m)? as usize;
        if num > MAX_TYPES {
            return Err(perr("too many globals"));
        }
        let mut values = Vec::with_capacity(num);
        for _ in 0..num {
            let tid = read_type_id(&mut r)?;
            let comp = types.components(tid)?;
            if comp > MAX_GLOBAL_COMPONENTS {
                return Err(perr("global too large"));
            }
            values.push(read_constant(&mut r, comp)?);
        }
        Ok(Globals { values })
    }
}

/// Read `comp` constant components, or a zero-initializer (`@\``), terminated
/// by a `` ` `` byte.
fn read_constant(r: &mut Reader, comp: usize) -> Result<Vec<u64>, ParseError> {
    let m = |_| perr("truncated constant");
    // Zero initializer: bytes 0x40 ('@') 0x60 ('`').
    if r.peek() == Some(0x40) && r.peek_at(1) == Some(0x60) {
        r.byte().map_err(m)?;
        r.byte().map_err(m)?;
        return Ok(vec![0u64; comp]);
    }
    let mut out = Vec::with_capacity(comp);
    while r.peek() != Some(0x60) {
        if out.len() >= comp {
            return Err(perr("constant has too many components"));
        }
        // Each component's lead byte is OR'd with 0x20, then read as a number.
        let lead = r.peek().ok_or(perr("constant truncated"))?;
        let count = ((lead | 0x20).wrapping_sub(0x60)) as usize;
        if count > 16 {
            return Err(perr("constant component too long"));
        }
        r.byte().map_err(m)?; // consume lead
        let mut v = 0u64;
        for i in 0..count {
            v |= u64::from(read_nibble(r)?) << (4 * i as u32);
        }
        out.push(v);
    }
    r.byte().map_err(m)?; // consume terminator
    if out.len() != comp {
        return Err(perr("constant has too few components"));
    }
    Ok(out)
}

fn read_nibble(r: &mut Reader) -> Result<u8, ParseError> {
    let b = r.byte().map_err(|_| perr("truncated nibble"))?;
    if b & 0xf0 != 0x60 {
        return Err(perr("bad nibble in constant"));
    }
    Ok(b & 0x0f)
}
