//! Instruction decoding for the `.cbc` format: `A` function headers and `B`
//! basic-block instruction streams, into a structured form the VM can lower.
//!
//! Each instruction is `[ 'T' | type, dest ] opcode operands`, where `'T'`
//! marks the block's terminator and operand shapes are opcode-specific. The
//! function's last block ends with an `'E'` marker.

use super::decode::{Operand, Reader};
use super::parse::ParseError;

// Opcode values (the format's `bc_opcode` numbering).
pub const OP_TRUNC: u8 = 14;
pub const OP_SEXT: u8 = 15;
pub const OP_ZEXT: u8 = 16;
pub const OP_BRANCH: u8 = 17;
pub const OP_JMP: u8 = 18;
pub const OP_RET: u8 = 19;
pub const OP_RET_VOID: u8 = 20;
pub const OP_ICMP_FIRST: u8 = 21;
pub const OP_ICMP_LAST: u8 = 30;
pub const OP_CALL_DIRECT: u8 = 32;
pub const OP_CALL_API: u8 = 33;
pub const OP_GEP1: u8 = 35;
pub const OP_GEPZ: u8 = 36;
pub const OP_GEPN: u8 = 37;
pub const OP_INVALID: u8 = 51;

/// Number of generic operands per opcode (index = opcode). Opcodes with bespoke
/// shapes (calls, GEPs, branches, ret, icmp) are handled before this table.
const OPERAND_COUNTS: [u8; OP_INVALID as usize] = [
    0, // 0 (unused)
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 1-13 arith/bitwise
    1, 1, 1, // 14-16 casts
    3, 1, 1, 0, // 17-20 branch/jmp/ret/ret_void
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 21-30 icmp
    3, // 31 select
    0, 0, // 32-33 calls
    2, // 34 copy
    3, 3, 0, // 35-37 gep1/gepz/gepn
    2, 1, // 38-39 store/load
    3, 3, 3, 3, // 40-43 memset/memcpy/memmove/memcmp
    0, 0, // 44-45 isbigendian/abort
    1, 1, 1, // 46-48 bswap16/32/64
    2, 1, // 49-50 ptrdiff32/ptrtoint64
];

const MAX_INSTS_PER_BB: usize = 1 << 20;

/// The opcode-specific operand payload of an instruction.
#[derive(Debug, Clone)]
pub enum Body {
    /// Generic operands (arithmetic, comparisons, casts, loads/stores, …).
    Ops(Vec<Operand>),
    /// A call to another function (`api=false`) or a host API (`api=true`).
    Call {
        api: bool,
        func: u32,
        args: Vec<Operand>,
    },
    /// `getelementptr`: a leading index/struct-offset then pointer operands.
    Gep { first: u32, ops: Vec<Operand> },
    /// Unconditional jump to a basic-block id.
    Jmp(u32),
    /// Conditional branch.
    Branch { cond: Operand, t: u32, f: u32 },
    /// Return a value (`None` = void).
    Ret(Option<Operand>),
}

/// One decoded instruction.
#[derive(Debug, Clone)]
pub struct Inst {
    pub opcode: u8,
    pub dest: u32,
    pub ty: u32,
    pub body: Body,
}

/// A decoded function: signature, per-value types, and its basic blocks.
#[derive(Debug, Clone)]
pub struct Function {
    pub num_args: u32,
    pub return_type: u32,
    /// Type id per value (arguments then locals); high bit `0x8000` is the
    /// format's per-entry flag.
    pub types: Vec<u32>,
    pub num_insts: u32,
    pub num_bb: u32,
    pub blocks: Vec<Vec<Inst>>,
}

fn perr(msg: &'static str) -> ParseError {
    ParseError(msg.into())
}

/// Parse the `A` function-header record (without its leading `A`).
pub fn parse_header(rec: &[u8]) -> Result<Function, ParseError> {
    let mut r = Reader::new(rec);
    let m = |_| perr("truncated function header");
    let num_args = r.fixed(1).map_err(m)? as u32;
    let return_type = r.number_u32().map_err(m)?;
    if r.byte().map_err(m)? != b'L' {
        return Err(perr("missing 'L' locals marker"));
    }
    let num_locals = r.number().map_err(m)? as usize;
    let total = num_args as usize + num_locals;
    if total > MAX_INSTS_PER_BB {
        return Err(perr("too many locals"));
    }
    let mut types = Vec::with_capacity(total);
    for _ in 0..total {
        let ty = r.number_u32().map_err(m)?;
        let flag = r.fixed(1).map_err(m)?;
        types.push(if flag != 0 { ty | 0x8000 } else { ty });
    }
    if r.byte().map_err(m)? != b'F' {
        return Err(perr("missing 'F' body marker"));
    }
    let num_insts = r.number_u32().map_err(m)?;
    let num_bb = r.number_u32().map_err(m)?;
    Ok(Function {
        num_args,
        return_type,
        types,
        num_insts,
        num_bb,
        blocks: Vec::new(),
    })
}

/// Decode one `B` basic-block record (without its leading `B`). `is_last` makes
/// the trailing `'E'` end-of-function marker required.
pub fn parse_block(rec: &[u8], is_last: bool) -> Result<Vec<Inst>, ParseError> {
    let mut r = Reader::new(rec);
    let m = |_| perr("truncated instruction");
    let mut insts = Vec::new();
    let mut last = false;
    while !last {
        let (mut ty, dest) = if r.peek() == Some(b'T') {
            r.byte().map_err(m)?;
            last = true;
            (0u32, 0u32)
        } else {
            (r.number_u32().map_err(m)?, r.number_u32().map_err(m)?)
        };
        let opcode = r.fixed(2).map_err(m)? as u8;
        if opcode == 0 || opcode >= OP_INVALID {
            return Err(perr("invalid opcode"));
        }
        let body = match opcode {
            OP_JMP => Body::Jmp(r.number_u32().map_err(m)?),
            OP_RET => {
                ty = r.number_u32().map_err(m)?;
                Body::Ret(Some(r.operand().map_err(m)?))
            }
            OP_RET_VOID => Body::Ret(None),
            OP_BRANCH => Body::Branch {
                cond: r.operand().map_err(m)?,
                t: r.number_u32().map_err(m)?,
                f: r.number_u32().map_err(m)?,
            },
            OP_CALL_API | OP_CALL_DIRECT => {
                let n = r.fixed(1).map_err(m)? as usize;
                let func = r.number_u32().map_err(m)?.wrapping_sub(1);
                let mut args = Vec::with_capacity(n);
                for _ in 0..n {
                    args.push(r.operand().map_err(m)?);
                }
                Body::Call {
                    api: opcode == OP_CALL_API,
                    func,
                    args,
                }
            }
            OP_GEP1 | OP_GEPZ => {
                let first = r.number_u32().map_err(m)?;
                let ops = vec![r.operand().map_err(m)?, r.operand().map_err(m)?];
                Body::Gep { first, ops }
            }
            OP_GEPN => {
                let n = r.fixed(1).map_err(m)? as usize;
                let first = r.number_u32().map_err(m)?;
                let mut ops = Vec::with_capacity(n + 1);
                for _ in 0..(n + 1) {
                    ops.push(r.operand().map_err(m)?);
                }
                Body::Gep { first, ops }
            }
            OP_TRUNC | OP_SEXT | OP_ZEXT => Body::Ops(vec![r.operand().map_err(m)?]),
            OP_ICMP_FIRST..=OP_ICMP_LAST => {
                ty = r.number_u32().map_err(m)?;
                Body::Ops(vec![r.operand().map_err(m)?, r.operand().map_err(m)?])
            }
            _ => {
                let count = OPERAND_COUNTS[opcode as usize];
                let mut ops = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    ops.push(r.operand().map_err(m)?);
                }
                Body::Ops(ops)
            }
        };
        insts.push(Inst {
            opcode,
            dest,
            ty,
            body,
        });
        if insts.len() > MAX_INSTS_PER_BB {
            return Err(perr("runaway instruction stream"));
        }
    }
    if is_last && r.peek() != Some(b'E') {
        return Err(perr("missing 'E' end-of-function marker"));
    }
    Ok(insts)
}
