//! BIFF, the record format of Excel files up to 2003: the one reader of its
//! records, workbook-wide tables and formula tokens, which the scanner (to
//! surface the Excel 4.0 macros of a macro sheet) and exav-render (to convert
//! a workbook) both read through.
//!
//! - [`records`] splits a stream into records, joining CONTINUE records;
//! - [`Book`] collects what formulas need from the workbook records: code
//!   page, sheet and defined names, external references;
//! - [`formula`] writes a token array as Excel's formula text.

mod book;
pub mod formula;
mod ftab;
mod record;

pub use book::{Book, BoundSheet, ExtSheet5, Name, Supbook};
pub use formula::{Ctx, Decoded, error_name};
pub use ftab::{function, function_name};
pub use record::{BOF_IDS, CONTINUE, Rec, Records, bof_type, bof_version, records};
