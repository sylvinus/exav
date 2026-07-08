#![cfg_attr(
    not(feature = "decrypt"),
    allow(dead_code, unused_mut, unused_imports, unreachable_code)
)]
#[cfg(feature = "decrypt")]
pub(crate) mod crypt;
pub(crate) mod filters;
pub(crate) mod lex;
pub(crate) mod parse;
pub(crate) mod types;
