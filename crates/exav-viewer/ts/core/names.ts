/**
 * What a name from the document may not show as itself: C0 and C1 controls,
 * DEL, the line and paragraph separators, and the bidirectional marks,
 * embeddings, overrides and isolates (CVE-2021-42574).
 */
const HIDDEN = /[\u{0}-\u{1f}\u{7f}-\u{9f}\u{61c}\u{200e}\u{200f}\u{2028}\u{2029}\u{202a}-\u{202e}\u{2066}-\u{2069}]/gu;

/**
 * `s` with each character of `HIDDEN` as U+FFFD: a name the viewer shows
 * (an archive member, a sheet, a layer, a section...) reads in the order it
 * is stored. The source stays ASCII: a literal U+2028 ends a regex literal.
 */
export function shownName(s: string): string {
  return s.replace(HIDDEN, "\u{fffd}");
}
