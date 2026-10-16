//! Office documents converted to the Open XML packages an Open XML renderer
//! draws: spreadsheets to XLSX ([`sheets`]), presentations to PPTX
//! ([`slides`]) and text documents to DOCX ([`docs`]).
//!
//! `common` is what the three share, and is not public. [`text`] is the text
//! each reads from a document, for a scanner or a search (see
//! [`crate::text`]).

#[cfg(feature = "_office")]
pub(crate) mod common;
#[cfg(feature = "office-docs")]
pub mod docs;
#[cfg(feature = "office-sheets")]
pub mod sheets;
// Presentations write their ODF charts with the spreadsheets' chart writer;
// without `office-sheets` the module is private and most of it unused.
#[cfg(all(feature = "office-slides", not(feature = "office-sheets")))]
#[allow(dead_code)]
mod sheets;
#[cfg(feature = "office-slides")]
pub mod slides;
#[cfg(any(
    feature = "office-sheets",
    feature = "office-slides",
    feature = "office-docs"
))]
pub mod text;
#[cfg(feature = "text-office")]
pub mod visible;

/// What the tests of the converters need from `common`, which they cannot
/// reach: writers of compound files, packages, protobuf messages and Snappy
/// blocks.
#[cfg(feature = "office-test-util")]
#[doc(hidden)]
pub mod test_util {
    pub use super::common::cfb::tests::build as build_cfb;
    pub use super::common::cfb::Compound;
    pub use super::common::iwa::proto::write::W;
    pub use super::common::iwa::snappy::literal_block;
    pub use super::common::package::{PackageWriter, Zip};
}
