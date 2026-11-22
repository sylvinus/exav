// Generated from exav-unpack's `unsafe_to_show` (src/tree/name.rs) by the test
// tests/hidden.rs of the exav-viewer crate, which fails when this file differs.
// Written again by: EXAV_DEBUG_WRITE_GENERATED=1 cargo test --manifest-path
// crates/exav-viewer/Cargo.toml --features text --test hidden

/** The characters a name or a link target cannot show: they end a line, move the cursor or reorder the text around them. */
export const HIDDEN_RANGES: readonly (readonly [number, number])[] = [[0x0, 0x1f], [0x7f, 0x9f], [0x61c, 0x61c], [0x200e, 0x200f], [0x2028, 0x202e], [0x2066, 0x2069]];

/** `HIDDEN_RANGES` as the inside of a regular expression's class, for a `u` regular expression. */
export const HIDDEN_CLASS = String.raw`\u{0}-\u{1f}\u{7f}-\u{9f}\u{61c}\u{200e}-\u{200f}\u{2028}-\u{202e}\u{2066}-\u{2069}`;

/** Whether the code point `c` is one of `HIDDEN_RANGES`. */
export function isHidden(c: number): boolean {
  return HIDDEN_RANGES.some(([a, b]) => c >= a && c <= b);
}
