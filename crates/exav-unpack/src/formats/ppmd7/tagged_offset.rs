//! Arena offset type, vendored from `ppmd-rust` 1.4.0 (CC0-1.0 OR MIT-0), the
//! non-`unstable-tagged-offsets` variant: an offset is a plain `u32` byte
//! offset into the PPMd allocation. Not derived from UnRAR.
//!
//! In this safe-Rust port the "tagged pointer" abstraction is just a checked
//! byte offset into the model's `Vec<u8>` arena. There is no raw-pointer
//! arithmetic; the model dereferences an offset through bounds-checked slice
//! accessors (see `model.rs`). An offset of `0` is the null sentinel (the byte
//! at offset 0 is part of the model's reserved alignment padding and is never a
//! real node, exactly as in the upstream pointer-based allocator where the base
//! pointer never holds a node).

const TAG_NULL: u32 = 0;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub(crate) struct TaggedOffset(u32);

impl TaggedOffset {
    pub(crate) const fn null() -> TaggedOffset {
        TaggedOffset(TAG_NULL)
    }

    #[inline(always)]
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    #[inline(always)]
    pub(crate) const fn from_bytes_offset(raw: u32) -> Self {
        TaggedOffset::from_raw(raw)
    }

    #[inline(always)]
    pub(crate) fn is_null(&self) -> bool {
        self.0 == TAG_NULL
    }

    #[inline(always)]
    pub(crate) fn is_not_null(&self) -> bool {
        self.0 != TAG_NULL
    }

    #[inline(always)]
    pub(crate) fn get_offset(&self) -> u32 {
        self.0
    }

    #[inline(always)]
    pub(crate) fn as_raw(&self) -> u32 {
        self.0
    }
}
