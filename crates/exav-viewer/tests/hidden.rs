//! The characters the viewer's TypeScript hides in names and link targets are
//! exav-unpack's (`unsafe_to_show`): `ts/core/hidden.generated.ts` is written
//! from it, and this test fails when the two differ.
//!
//!     EXAV_DEBUG_WRITE_GENERATED=1 cargo test --manifest-path crates/exav-viewer/Cargo.toml --features text --test hidden
//!
//! writes the file again.
#![cfg(feature = "text")]

use std::path::Path;

/// `unsafe_to_show` over every character, as inclusive ranges.
fn ranges() -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for c in (0..=0x10ffff).filter_map(char::from_u32) {
        if !exav_unpack::tree::unsafe_to_show(c) {
            continue;
        }
        let n = c as u32;
        match out.last_mut() {
            Some((_, end)) if *end + 1 == n => *end = n,
            _ => out.push((n, n)),
        }
    }
    out
}

fn generated() -> String {
    let r = ranges();
    let pairs: Vec<String> = r
        .iter()
        .map(|(a, b)| format!("[0x{a:x}, 0x{b:x}]"))
        .collect();
    let class: String = r
        .iter()
        .map(|&(a, b)| {
            if a == b {
                format!("\\u{{{a:x}}}")
            } else {
                format!("\\u{{{a:x}}}-\\u{{{b:x}}}")
            }
        })
        .collect();
    format!(
        "// Generated from exav-unpack's `unsafe_to_show` (src/tree/name.rs) by the test\n\
         // tests/hidden.rs of the exav-viewer crate, which fails when this file differs.\n\
         // Written again by: EXAV_DEBUG_WRITE_GENERATED=1 cargo test --manifest-path\n\
         // crates/exav-viewer/Cargo.toml --features text --test hidden\n\
         \n\
         /** The characters a name or a link target cannot show: they end a line, move the cursor or reorder the text around them. */\n\
         export const HIDDEN_RANGES: readonly (readonly [number, number])[] = [{}];\n\
         \n\
         /** `HIDDEN_RANGES` as the inside of a regular expression's class, for a `u` regular expression. */\n\
         export const HIDDEN_CLASS = String.raw`{class}`;\n\
         \n\
         /** Whether the code point `c` is one of `HIDDEN_RANGES`. */\n\
         export function isHidden(c: number): boolean {{\n  \
           return HIDDEN_RANGES.some(([a, b]) => c >= a && c <= b);\n\
         }}\n",
        pairs.join(", ")
    )
}

#[test]
fn the_viewer_hides_the_characters_exav_unpack_hides() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("ts/core/hidden.generated.ts");
    let want = generated();
    // `EXAV_DEBUG_`: the scanner's docs test takes any other `EXAV_` variable
    // read in the tree for one of its flags.
    if std::env::var_os("EXAV_DEBUG_WRITE_GENERATED").is_some() {
        std::fs::write(&path, &want).expect("write the generated file");
    }
    let have = std::fs::read_to_string(&path).expect("ts/core/hidden.generated.ts");
    assert_eq!(
        have, want,
        "ts/core/hidden.generated.ts is not exav-unpack's set: write it again (see the top of tests/hidden.rs)"
    );
}
