//! Parser for the `.cbc` bytecode signature format.
//!
//! Parses the header metadata, the triggering logical signature, the API
//! declarations, and the functions — including the full instruction stream
//! (see [`super::instr`]). Everything is fallible and bounded — a malformed
//! program yields an `Err`, never a panic. *Lowering* the decoded instructions
//! to the executable VM IR is staged separately; until that lands a program is
//! marked [`Bytecode::executable`] = false and is never run.

use super::decode::Reader;
use super::instr::{self, Function};
use super::types::{Globals, TypeTable};

/// The validation magic embedded in every header (a format constant).
const HEADER_MAGIC: u64 = 0x53e5_493e_9f3d_1c30;
/// Generous caps so a hostile file can't drive huge allocations.
const MAX_RECORDS: usize = 1 << 20;
const MAX_APIS: usize = 4096;
const MAX_STR: usize = 64 * 1024;

/// A parse failure (kept simple; the caller treats any error as "skip").
#[derive(Debug, Clone)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

type P<T> = Result<T, ParseError>;

fn err<T>(msg: impl Into<String>) -> P<T> {
    Err(ParseError(msg.into()))
}

/// Header metadata (the `ClamBC` line).
#[derive(Debug, Clone)]
pub struct Header {
    pub format_level: u32,
    pub kind: u32,
    pub min_flevel: u32,
    pub max_flevel: u32,
    pub num_types: u32,
    pub num_funcs: u32,
    pub compiler: String,
}

/// A parsed bytecode signature.
pub struct Bytecode {
    pub header: Header,
    /// The triggering logical signature (an `.ldb`-format line); the engine
    /// runs this program only when this signature matches.
    pub trigger: String,
    /// Detection name (the part of `trigger` before the first `;`).
    pub name: String,
    /// API functions the program declares it will call, as `(global_id, name)`.
    /// The `global_id` is what `CALL_API` instructions reference.
    pub apis: Vec<(u32, String)>,
    /// The type table (`T` record).
    pub types: TypeTable,
    /// Constant globals (`G` record).
    pub globals: Globals,
    /// Function headers (signatures + counts), in file order.
    pub functions: Vec<Function>,
    /// True only when the full body decoded into an executable form. False
    /// programs are loaded (and their trigger known) but never executed.
    pub executable: bool,
}

impl Bytecode {
    /// True if every API this program uses is one exav implements — a
    /// prerequisite (necessary, not sufficient) for ever executing it.
    pub fn apis_supported(&self) -> bool {
        self.apis.iter().all(|(_, a)| super::exec::api_supported(a))
    }
}

/// Parse one `.cbc` program's text.
pub fn parse(text: &str) -> P<Bytecode> {
    let mut lines = text.split('\n');
    let first = lines.next().unwrap_or("");
    let header = parse_header(first)?;

    // Line 2 is the triggering logical signature (plain ASCII).
    let trigger = lines
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(ParseError("missing trigger logical signature".into()))?
        .to_string();
    let name = trigger.split(';').next().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return err("empty bytecode signature name");
    }

    // Remaining records, by leading character. We only need the `E` (API)
    // records for now; the rest are validated for shape but not yet modeled.
    let mut apis = Vec::new();
    let mut types = TypeTable::default();
    let mut globals = Globals::default();
    let mut functions: Vec<Function> = Vec::new();
    let mut current: Option<Function> = None;
    let mut records = 0usize;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        records += 1;
        if records > MAX_RECORDS {
            return err("too many records");
        }
        let bytes = line.as_bytes();
        match bytes[0] {
            b'E' => parse_apis(&bytes[1..], &mut apis)?,
            // The type table precedes globals and functions in the file.
            b'T' => types = TypeTable::parse(&bytes[1..], header.num_types)?,
            b'G' => globals = Globals::parse(&bytes[1..], &types)?,
            b'A' => {
                if let Some(f) = current.take() {
                    functions.push(f);
                }
                current = Some(instr::parse_header(&bytes[1..])?);
            }
            // A basic block belongs to the function opened by the last `A`. The
            // last block of the function carries the `'E'` end marker.
            b'B' => {
                if let Some(f) = current.as_mut() {
                    let idx = f.blocks.len() as u32;
                    if idx < f.num_bb {
                        let is_last = idx + 1 == f.num_bb;
                        let block = instr::parse_block(&bytes[1..], is_last)?;
                        f.blocks.push(block);
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(f) = current.take() {
        functions.push(f);
    }

    Ok(Bytecode {
        header,
        trigger,
        name,
        apis,
        types,
        globals,
        functions,
        // The instruction stream isn't decoded into an executable IR yet, so no
        // real program is marked executable (keeps live scanning safe).
        executable: false,
    })
}

fn parse_header(line: &str) -> P<Header> {
    let line = line.trim_end_matches('\r');
    let body = line
        .strip_prefix("ClamBC")
        .ok_or(ParseError("missing ClamBC magic".into()))?;
    let mut r = Reader::new(body.as_bytes());
    let map = |_e: super::decode::DecodeError| ParseError("truncated header".into());

    let format_level = r.number_u32().map_err(map)?;
    let _timestamp = r.number().map_err(map)?;
    let _sigmaker = r.string(MAX_STR).map_err(map)?;
    let _target_exclude = r.number().map_err(map)?;
    let kind = r.number_u32().map_err(map)?;
    let min_flevel = r.number_u32().map_err(map)?;
    let max_flevel = r.number_u32().map_err(map)?;
    let _max_resource = r.number().map_err(map)?;
    let compiler = r.string(MAX_STR).map_err(map)?;
    let num_types = r.number_u32().map_err(map)?;
    let num_funcs = r.number_u32().map_err(map)?;
    let magic = r.number().map_err(map)?;
    if magic != HEADER_MAGIC {
        return err("bad header validation magic");
    }
    Ok(Header {
        format_level,
        kind,
        min_flevel,
        max_flevel,
        num_types,
        num_funcs,
        compiler,
    })
}

/// Parse an `E` record: `maxapi`, `count`, then `count` × (id, type, name).
fn parse_apis(rec: &[u8], out: &mut Vec<(u32, String)>) -> P<()> {
    let mut r = Reader::new(rec);
    let map = |_e: super::decode::DecodeError| ParseError("truncated API record".into());
    let _maxapi = r.number().map_err(map)?;
    let count = r.number().map_err(map)? as usize;
    if count > MAX_APIS {
        return err("too many API declarations");
    }
    for _ in 0..count {
        let id = r.number_u32().map_err(map)?;
        let _ty = r.number().map_err(map)?;
        let name = r.string(MAX_STR).map_err(map)?;
        out.push((id, name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny encoders (inverse of the decoder) to build a valid program.
    fn num(mut n: u64) -> String {
        let mut nibs = Vec::new();
        while n > 0 {
            nibs.push((n & 0xf) as u8);
            n >>= 4;
        }
        let mut s = String::new();
        s.push((0x60 + nibs.len() as u8) as char);
        for nb in nibs {
            s.push((0x60 + nb) as char);
        }
        s
    }
    fn data(bytes: &[u8]) -> String {
        let mut s = String::from("|");
        s.push_str(&num(bytes.len() as u64));
        for &b in bytes {
            s.push((0x60 + (b & 0xf)) as char);
            s.push((0x60 + (b >> 4)) as char);
        }
        s
    }

    fn sample_cbc() -> String {
        let mut h = String::from("ClamBC");
        h.push_str(&num(6)); // format level
        h.push_str(&num(0x5b4f9546)); // timestamp
        h.push_str(&data(b"")); // sigmaker
        h.push_str(&num(0)); // target exclude
        h.push_str(&num(256)); // kind
        h.push_str(&num(50)); // min flevel
        h.push_str(&num(255)); // max flevel
        h.push_str(&num(0)); // max resource
        h.push_str(&data(b"clambc-test")); // compiler
        h.push_str(&num(2)); // num types
        h.push_str(&num(1)); // num funcs
        h.push_str(&num(HEADER_MAGIC)); // validation magic
        let trigger = "Test.BC.Detect;Engine:50-255,Target:0;0;deadbeef";
        let mut e = String::from("E");
        e.push_str(&num(96)); // maxapi
        e.push_str(&num(1)); // one api
        e.push_str(&num(5)); // id
        e.push_str(&num(79)); // type
        e.push_str(&data(b"setvirusname"));
        // A record: 0 args, return type 32, 1 local (type 32, no flag),
        // 1 inst, 1 basic block.
        let mut a = String::from("A");
        a.push((0x60u8) as char); // numArgs = fixed(1) nibble 0
        a.push_str(&num(32)); // returnType
        a.push('L');
        a.push_str(&num(1)); // numLocals
        a.push_str(&num(32)); // local0 type
        a.push((0x60u8) as char); // flag fixed(1) = 0
        a.push('F');
        a.push_str(&num(1)); // numInsts
        a.push_str(&num(1)); // numBB
                             // B record: one terminator instruction RET_VOID (opcode 20 = fixed(2)
                             // nibbles 4,1), last block so end marker 'E'.
        let mut b = String::from("BT");
        b.push((0x60u8 + 4) as char); // opcode nibble lo (4)
        b.push((0x60u8 + 1) as char); // opcode nibble hi (1) -> 0x14 = 20
        b.push('E');
        format!("{h}\n{trigger}\n{e}\n{a}\n{b}\n")
    }

    #[test]
    fn parses_synthetic_program() {
        let bc = parse(&sample_cbc()).unwrap();
        assert_eq!(bc.header.format_level, 6);
        assert_eq!(bc.header.kind, 256);
        assert_eq!(bc.header.min_flevel, 50);
        assert_eq!(bc.header.num_funcs, 1);
        assert_eq!(bc.header.compiler, "clambc-test");
        assert_eq!(bc.name, "Test.BC.Detect");
        assert_eq!(bc.apis, vec![(5, "setvirusname".to_string())]);
        assert!(bc.apis_supported());
        assert!(!bc.executable); // not yet runnable
        assert_eq!(bc.functions.len(), 1);
        let f = &bc.functions[0];
        assert_eq!(f.num_args, 0);
        assert_eq!(f.return_type, 32);
        assert_eq!(f.types, vec![32]); // one local
        assert_eq!(f.num_insts, 1);
        assert_eq!(f.num_bb, 1);
        // The B block decoded into one terminator instruction (RET_VOID).
        assert_eq!(f.blocks.len(), 1);
        assert_eq!(f.blocks[0].len(), 1);
        assert_eq!(f.blocks[0][0].opcode, super::instr::OP_RET_VOID);
        assert!(matches!(f.blocks[0][0].body, super::instr::Body::Ret(None)));
    }

    #[test]
    fn rejects_non_bytecode() {
        assert!(parse("not a bytecode\n").is_err());
        assert!(parse("ClamBC\n").is_err()); // truncated header
    }

    #[test]
    fn rejects_bad_magic() {
        let cbc = sample_cbc().replace(&num(HEADER_MAGIC), &num(0x1234));
        assert!(parse(&cbc).is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(parse("").is_err());
    }
}
