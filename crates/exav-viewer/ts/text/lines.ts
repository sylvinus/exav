/** A piece of a line, with the class that colours it. */
export type Seg = readonly [text: string, cls?: string];

/** A line: plain text, or pieces. */
export type Line = string | readonly Seg[];

export const lineLength = (line: Line): number => (typeof line === "string" ? line.length : line.reduce((n, s) => n + s[0].length, 0));

/** Lines made from a text by the text module (exav-render's `text_view`). */
export interface Formatted {
  lines: Line[];
  /** There were more lines than the cap. */
  more: boolean;
  /** XML: every construct ended and every tag was closed by its own. */
  wellFormed: boolean;
}
