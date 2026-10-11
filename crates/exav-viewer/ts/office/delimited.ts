/**
 * How to read a table saved as text.
 *
 * `@silurus/ooxml` draws a CSV on the same sheet surface as a workbook, but
 * it detects nothing: the separator and the encoding are arguments, and their
 * defaults are a comma and UTF-8. A table exported from a French Excel is
 * neither ("Save as CSV" writes semicolons in cp1252), so a file that opens
 * on the machine it came from would arrive as a single column, or as no
 * sheet at all, since the engine decodes with `fatal` and throws on the first
 * accented byte rather than painting a replacement character.
 *
 * So both are read off the bytes first.
 */

/** How much of the file to look at. Whole rows is all the sniff needs. */
const SNIFF_BYTES = 64 * 1024;

/** How many of them to weigh before deciding. */
const SNIFF_ROWS = 20;

/**
 * What a separator can be.
 *
 * Ordered, and the order settles a tie: a file that reads as a table under
 * both a comma and a semicolon is read as the comma.
 */
const DELIMITERS = [",", ";", "\t"];

/** What to hand the engine: the separator in the bytes, and their encoding. */
export interface Reading {
  delimiter: string;
  encoding: string;
}

export function readingOf(bytes: ArrayBuffer): Reading {
  const complete = bytes.byteLength <= SNIFF_BYTES;
  const head = new Uint8Array(bytes, 0, complete ? bytes.byteLength : SNIFF_BYTES);
  const encoding = encodingOf(head);
  return { delimiter: sniffDelimiter(decode(head, encoding) ?? "", complete), encoding };
}

/**
 * Which encoding to read the bytes as.
 *
 * A byte-order mark settles it outright where there is one: a UTF-16 export
 * read as single-byte text is a column of NULs, and nothing downstream would
 * say so.
 *
 * Otherwise UTF-8, and cp1252 when that fails, which is the one useful thing
 * a failed decode says. The `é` of a file saved by a French Excel is not
 * valid UTF-8 and throws; a UTF-8 file read as cp1252 throws nothing and
 * turns "libellé" into "libellÃ©", because every one of the 256 bytes is a
 * character in that encoding. So the order cannot be reversed, and cp1252 is
 * last because it cannot fail and would swallow everything.
 */
function encodingOf(head: Uint8Array): string {
  if (head[0] === 0xff && head[1] === 0xfe) return "utf-16le";
  if (head[0] === 0xfe && head[1] === 0xff) return "utf-16be";
  return decode(head, "utf-8") === null ? "windows-1252" : "utf-8";
}

/** The head as text, or `null` when these bytes are not that encoding. */
function decode(head: Uint8Array, encoding: string): string | null {
  try {
    // `stream`, so a character the head's edge cut in half is held back
    // rather than thrown over.
    return new TextDecoder(encoding, { fatal: true }).decode(head, { stream: true });
  } catch {
    return null;
  }
}

/**
 * Which character separates the fields.
 *
 * By shape, not by frequency: the separator is the one that cuts every row
 * into the same number of fields. Counting occurrences instead reads
 * `lot,observation` over `03,"reprise; enduit; joints"` as semicolon-
 * separated, and a free-text column with punctuation in it is the ordinary
 * case.
 *
 * Nothing fits (one column, or ragged rows) and it is a comma, which is
 * what the engine would have assumed and is right about a one-column file.
 */
function sniffDelimiter(head: string, complete: boolean): string {
  let best = DELIMITERS[0];
  let widest = 1;
  for (const delimiter of DELIMITERS) {
    const widths = rowWidths(head, delimiter, complete);
    if (widths.length === 0 || widths.some((width) => width !== widths[0])) continue;
    if (widths[0] > widest) {
      best = delimiter;
      widest = widths[0];
    }
  }
  return best;
}

/**
 * How many fields each row holds under this separator.
 *
 * Quoted text is stepped over, since a separator or a newline inside quotes
 * is part of the value; `""` is an escaped quote, which toggling twice
 * handles by itself. Blank lines are not rows: one in the middle of a file
 * would otherwise make every candidate look ragged and leave the comma to
 * win by default. The row a truncated head ends in is left out for the same
 * reason: it has no newline, and its width would be a lie.
 */
function rowWidths(head: string, delimiter: string, complete: boolean): number[] {
  const widths: number[] = [];
  let fields = 1;
  let quoted = false;
  let empty = true;
  for (const char of head) {
    if (char === "\n" && !quoted) {
      if (!empty) {
        widths.push(fields);
        if (widths.length === SNIFF_ROWS) return widths;
      }
      fields = 1;
      empty = true;
      continue;
    }
    if (char !== "\r") empty = false;
    if (char === '"') quoted = !quoted;
    else if (!quoted && char === delimiter) fields += 1;
  }
  // A file with no trailing newline (a header and one line, often enough)
  // still has that last row, and here it is whole.
  if (complete && !empty) widths.push(fields);
  return widths;
}
