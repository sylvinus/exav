//! With the `dwg` feature, compiles the vendored FontoBene stroke font into
//! the byte table `formats::dwg::stroke_font` embeds. Done here rather than
//! committing the output, so that the human-readable `.bene` is the only
//! source of truth.

use std::path::Path;

// Only the encoding half of each module is used here; the readers are dead
// code in the build script and live code in the crate.
#[allow(dead_code)]
#[path = "src/formats/dwg/stroke_font/fontobene.rs"]
mod fontobene;

// `binary` names its input `super::fontobene::Font`, which here is the module
// above.
#[allow(dead_code)]
#[path = "src/formats/dwg/stroke_font/binary.rs"]
mod binary;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_DWG").is_none() {
        return;
    }
    let src = Path::new("fonts/newstroke.bene");
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed=src/formats/dwg/stroke_font/fontobene.rs");
    println!("cargo:rerun-if-changed=src/formats/dwg/stroke_font/binary.rs");

    let text =
        std::fs::read_to_string(src).unwrap_or_else(|e| panic!("reading {}: {e}", src.display()));
    let font = fontobene::parse(&text).unwrap_or_else(|e| panic!("parsing {}: {e}", src.display()));

    // The licence is declared inside the font file. Fail the build rather than
    // ship something whose terms changed under a vendor bump.
    assert_eq!(
        font.license, "CC0-1.0",
        "the vendored font is no longer CC0; check fonts/newstroke.bene before shipping it"
    );
    assert!(
        font.glyphs.len() > 2000,
        "the vendored font has only {} glyphs, which is not NewStroke",
        font.glyphs.len()
    );

    let out =
        Path::new(&std::env::var("OUT_DIR").expect("cargo sets OUT_DIR")).join("newstroke.bin");
    std::fs::write(&out, binary::encode(&font))
        .unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}
