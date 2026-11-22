import { HIDDEN_CLASS } from "./hidden.generated.js";

/**
 * What a name from the document may not show as itself: C0 and C1 controls,
 * DEL, the line and paragraph separators, and the bidirectional marks,
 * embeddings, overrides and isolates (CVE-2021-42574), as exav-unpack's names.
 */
const HIDDEN = new RegExp(`[${HIDDEN_CLASS}]`, "gu");

/**
 * `s` with each character of `HIDDEN` as U+FFFD: a name the viewer shows
 * (an archive member, a sheet, a layer, a section...) reads in the order it
 * is stored.
 */
export function shownName(s: string): string {
  return s.replace(HIDDEN, "\u{fffd}");
}
