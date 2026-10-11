/**
 * What to tell the engine about a table saved as text.
 *
 * The library detects nothing and its defaults are a comma and UTF-8, which
 * is exactly what a table out of a French Excel is not. These are the files
 * that actually arrive.
 */
import { describe, expect, it } from "vitest";

import { readingOf } from "./delimited.js";

const utf8 = (text: string) => new TextEncoder().encode(text).buffer as ArrayBuffer;

/**
 * The same text as Windows-1252, which is what « Enregistrer sous → CSV »
 * writes. Every character used here is below U+0100, where cp1252 and
 * Latin-1 agree and the code point is the byte.
 */
const cp1252 = (text: string) =>
  Uint8Array.from([...text], (char) => char.charCodeAt(0)).buffer as ArrayBuffer;

/** And what a Windows tool that writes Unicode produces: UTF-16 with a mark. */
const utf16le = (text: string) => {
  const bytes = new Uint8Array((text.length + 1) * 2);
  // The mark, and then the text, low byte first.
  bytes[0] = 0xff;
  bytes[1] = 0xfe;
  for (let i = 0; i < text.length; i += 1) {
    bytes[(i + 1) * 2] = text.charCodeAt(i) & 0xff;
    bytes[(i + 1) * 2 + 1] = text.charCodeAt(i) >> 8;
  }
  return bytes.buffer;
};

describe("the separator in the file", () => {
  it("reads a comma", () => {
    expect(readingOf(utf8("lot,libelle,montant\n03,Enduit,1200\n")).delimiter).toBe(",");
  });

  it("reads the semicolon a French Excel writes", () => {
    expect(readingOf(utf8("lot;libelle;montant\n03;Enduit;1200\n")).delimiter).toBe(";");
  });

  it("reads a tab", () => {
    expect(readingOf(utf8("lot\tlibelle\n03\tEnduit\n")).delimiter).toBe("\t");
  });

  it("is not fooled by punctuation in a free-text column", () => {
    // The trap frequency-counting falls into: five semicolons against two
    // commas, and the file is comma-separated. Shape says so: every row is
    // two fields under a comma and ragged under a semicolon.
    const text = "lot,observation\n03,reprise; enduit; joints; seuil; appui\n04,rien\n";
    expect(readingOf(utf8(text)).delimiter).toBe(",");
  });

  it("ignores a separator inside a quoted field", () => {
    // Every row carries the same number of commas *inside* its quotes, so
    // counting through the quotes makes the comma look like a separator that
    // cuts the file into a clean two columns, and a wider one wins.
    const text = '"observation, détail";lot\n"reprise, enduit";03\n"pose, calfeutrement";04\n';
    expect(readingOf(utf8(text)).delimiter).toBe(";");
  });

  it("does not end a row on a newline inside a quoted field", () => {
    // An « observation » column holds two lines often enough. Cut there, the
    // row splits in two and every candidate looks ragged.
    const text = 'lot;observation\n03;"reprise enduit\net joints"\n04;rien\n';
    expect(readingOf(utf8(text)).delimiter).toBe(";");
  });

  it("reads an escaped quote as part of the value", () => {
    // `""` closes and reopens, so the semicolon after it is still inside the
    // field and the row stays two wide.
    const text = 'lot;observation\n03;"le ""joint"" haut; à revoir"\n04;rien\n';
    expect(readingOf(utf8(text)).delimiter).toBe(";");
  });

  it("is not thrown by a blank line in the middle", () => {
    // Counted as a row it would make every candidate look ragged, and the
    // comma would win a file that has none.
    expect(readingOf(utf8("a;b;c\n\nd;e;f\n")).delimiter).toBe(";");
  });

  it("reads a file that is one row and ends without a newline", () => {
    // The row the file ends in is a row: with nothing else to go on, leaving
    // it out would leave nothing at all.
    expect(readingOf(utf8("lot;libelle;montant")).delimiter).toBe(";");
  });

  it("ignores the row a long file is cut off in", () => {
    // Rows wide enough that the 64 KB the sniff reads ends inside the third
    // one, before its separators. Counted, that row is one field against the
    // others' three and the file looks ragged; it has no newline, and its
    // width is a lie.
    const row = `${"x".repeat(30_000)};Enduit;1200\n`;
    const rows = row.repeat(3);
    expect(rows.length).toBeGreaterThan(64 * 1024);
    expect(readingOf(utf8(rows)).delimiter).toBe(";");
  });

  it("settles on the comma when nothing looks like a table", () => {
    // One column: no separator fits, and a comma is what the engine would
    // have assumed anyway.
    expect(readingOf(utf8("Chopin\nDupont\n")).delimiter).toBe(",");
    expect(readingOf(utf8("")).delimiter).toBe(",");
  });
});

describe("the encoding the file is in", () => {
  it("reads UTF-8", () => {
    expect(readingOf(utf8("lot;libellé\n03;Enduit à la chaux\n")).encoding).toBe("utf-8");
  });

  it("reads what a French Excel wrote, which is not UTF-8", () => {
    // The byte that gives it away: 0xE9 alone is not valid UTF-8, and the
    // engine decodes with `fatal`, so the sheet would not be drawn at all.
    expect(readingOf(cp1252("lot;libellé\n03;Enduit à la chaux\n")).encoding).toBe("windows-1252");
  });

  it("tries UTF-8 first, so an accented UTF-8 file is not read as mojibake", () => {
    // Both decode these bytes; only one of them is right. Reversing the
    // order would turn « libellé » into « libellÃ© » on every such file.
    expect(readingOf(utf8("a;é\n")).encoding).toBe("utf-8");
  });

  it("still finds the separator in a file that is not UTF-8", () => {
    expect(readingOf(cp1252("lot;libellé;montant\n03;Enduit;1200\n")).delimiter).toBe(";");
  });

  it("believes a byte-order mark over either of them", () => {
    // Every one of the 256 bytes is a character in cp1252, so nothing about
    // a UTF-16 file makes the decode fail: read as single-byte text it comes
    // out as a column of NULs and says nothing. Only the mark tells it apart.
    expect(readingOf(utf16le("lot;libellé\n03;Enduit\n"))).toEqual({
      delimiter: ";",
      encoding: "utf-16le",
    });
  });
});
