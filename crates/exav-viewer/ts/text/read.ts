/** How the text module says a file is read (`fileReading`). */
export interface Reading {
  /** The WHATWG label of the encoding. */
  encoding: string;
  /** After the byte-order mark. */
  start: number;
  /** Before the character a partial read cut. */
  end: number;
}

/**
 * `bytes` as text, as `reading` says, by the platform's decoder of the WHATWG
 * Encoding Standard, the one exav-unpack's own decoder (encoding_rs) follows.
 * `start` skips the byte-order mark, so none is stripped again.
 */
export function readText(bytes: Uint8Array, reading: Reading): string {
  const body = bytes.subarray(reading.start, reading.end);
  // The encoding a page's charset of ISO-2022-KR and the like names, which
  // no `TextDecoder` takes: one replacement character for any bytes.
  if (reading.encoding === "replacement") return body.length ? "�" : "";
  return new TextDecoder(reading.encoding, { ignoreBOM: true }).decode(body);
}
