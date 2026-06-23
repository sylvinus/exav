//! Support for the `.cbc` bytecode signature format.
//!
//! A `.cbc` signature is a small verification program: a triggering logical
//! signature (handled by [`crate::engine`]) fires on a candidate file, then
//! this program inspects the file through a fixed, sandboxed API and may report
//! a detection. exav runs these in a memory-safe, strictly bounded interpreter
//! (no native codegen), so a malformed or hostile program can at worst be
//! rejected or time out — never corrupt memory.

pub mod decode;
pub mod disasm;
pub mod exec;
pub mod instr;
pub mod parse;
pub mod runtime;
pub mod types;

pub use instr::Function;
pub use parse::{parse, Bytecode};
