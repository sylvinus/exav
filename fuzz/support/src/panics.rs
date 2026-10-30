//! Panics of a dependency that exav contains.
//!
//! libFuzzer's panic hook aborts the process, so a panic that exav catches with
//! `catch_unwind` and reports as a file it cannot decode is a crash for the
//! fuzzer all the same. The ones listed here come from a dependency exav keeps
//! at the version ClamAV links, so that its hashes are ClamAV's, and are
//! contained where the dependency is called: the fuzzer should not stop on
//! them, nor report every file that reaches them again.
//!
//! Anything else still aborts. Each entry says what the panic is and what holds
//! it, so that an entry is removed when its dependency is replaced.

use std::sync::Once;

/// The source files whose panics are contained.
const CONTAINED: &[(&str, &str)] = &[
    // zune-jpeg 0.4.21, which decodes the JPEG strips of a TIFF (`tiff` 0.10
    // pins it, as ClamAV's does), multiplies in its scalar IDCT without room
    // for the largest coefficients a damaged stream gives. exav's release
    // profile checks overflow too, so the panic is caught, and the strip is
    // undecodable. 0.5.15 decodes the file.
    (
        "zune-jpeg-0.4.21/src/idct",
        "IDCT coefficients that overflow",
    ),
];

/// Whether a panic at `file` is one that is contained.
pub fn is_contained(file: &str) -> bool {
    CONTAINED.iter().any(|(path, _)| file.contains(path))
}

/// Silences the contained panics for the rest of the process: call it at the
/// start of a target. The hook libFuzzer installed still gets every other.
pub fn contained_panics() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !info.location().is_some_and(|l| is_contained(l.file())) {
                previous(info);
            }
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_listed_files_are_contained() {
        let idct = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/zune-jpeg-0.4.21/src/idct/scalar.rs";
        assert!(is_contained(idct));
        // Another file of the same crate, and another version, are not.
        assert!(!is_contained(&idct.replace("idct/scalar.rs", "decoder.rs")));
        assert!(!is_contained(&idct.replace("0.4.21", "0.4.22")));
        assert!(!is_contained("crates/exav-render/src/formats/image.rs"));
    }
}
