import zlib from "node:zlib";

import { describe, expect, it } from "vitest";

import { parseTable, storedZip, xlsxOfRows, xlsxOfTable } from "./table.js";

describe("a delimited text read as rows", () => {
  it("splits on the separator and on every kind of line end", () => {
    expect(parseTable("a;b\r\nc;d\ne;f\rg;h", ";")).toEqual([
      ["a", "b"],
      ["c", "d"],
      ["e", "f"],
      ["g", "h"],
    ]);
  });

  it("keeps quoted separators, line ends and doubled quotes inside the field", () => {
    expect(parseTable('"a,b",c\n"line\nbreak","say ""hi"""\n', ",")).toEqual([
      ["a,b", "c"],
      ["line\nbreak", 'say "hi"'],
    ]);
  });

  it("keeps empty fields and leaves out blank lines", () => {
    expect(parseTable("a,,c\n\n,,\n,b\n", ",")).toEqual([
      ["a", "", "c"],
      ["", "", ""],
      ["", "b"],
    ]);
    expect(parseTable("", ",")).toEqual([]);
    expect(parseTable('""\n', ",")).toEqual([[""]]);
  });

  it("refuses more fields than the engine draws a sheet of, counting blanks, as too large", () => {
    expect(parseTable("a,b\nc,d\n", ",", 4)).toHaveLength(2);
    expect(() => parseTable("a,b\nc,d,\n", ",", 4)).toThrowError(expect.objectContaining({ code: "too-large" }));
    expect(() => parseTable(",".repeat(10), ",", 5)).toThrowError(expect.objectContaining({ code: "too-large" }));
  });

  it("takes a quote in the middle of a field as a character", () => {
    expect(parseTable('5" pipe,x', ",")).toEqual([['5" pipe', "x"]]);
  });
});

/** The members of a stored ZIP, read from its central directory. */
function members(zip: Uint8Array): Record<string, Uint8Array> {
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  const end = zip.length - 22;
  expect(view.getUint32(end, true)).toBe(0x06054b50);
  const count = view.getUint16(end + 10, true);
  let at = view.getUint32(end + 16, true);
  const out: Record<string, Uint8Array> = {};
  for (let i = 0; i < count; i++) {
    expect(view.getUint32(at, true)).toBe(0x02014b50);
    const crc = view.getUint32(at + 16, true);
    const size = view.getUint32(at + 24, true);
    const nameLength = view.getUint16(at + 28, true);
    const local = view.getUint32(at + 42, true);
    const name = new TextDecoder().decode(zip.subarray(at + 46, at + 46 + nameLength));
    expect(view.getUint32(local, true)).toBe(0x04034b50);
    const start = local + 30 + view.getUint16(local + 26, true);
    const data = zip.subarray(start, start + size);
    expect(zlib.crc32(data)).toBe(crc);
    out[name] = data;
    at += 46 + nameLength;
  }
  return out;
}

describe("a stored ZIP", () => {
  it("holds its members as given, with their checksums", () => {
    const text = (s: string) => new TextEncoder().encode(s);
    const zip = storedZip([
      ["a.txt", text("hello")],
      ["dir/b.bin", new Uint8Array([0, 1, 2, 255])],
      ["empty", new Uint8Array(0)],
    ]);
    const m = members(zip);
    expect(Object.keys(m)).toEqual(["a.txt", "dir/b.bin", "empty"]);
    expect(new TextDecoder().decode(m["a.txt"])).toBe("hello");
    expect([...m["dir/b.bin"]!]).toEqual([0, 1, 2, 255]);
    expect(m["empty"]!.length).toBe(0);
  });
});

describe("rows as a workbook", () => {
  const sheet = (rows: string[][]) => new TextDecoder().decode(members(xlsxOfRows(rows))["xl/worksheets/sheet1.xml"]);

  it("has the parts of a one-sheet workbook", () => {
    const m = members(xlsxOfRows([["a"]]));
    expect(Object.keys(m).sort()).toEqual(["[Content_Types].xml", "_rels/.rels", "xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/workbook.xml", "xl/worksheets/sheet1.xml"]);
    expect(new TextDecoder().decode(m["xl/workbook.xml"])).toContain('<sheet name="Sheet1"');
  });

  it("writes each field as text in its cell, empty ones not at all", () => {
    const xml = sheet([
      ["Item", "", "3,5"],
      ["", "x"],
    ]);
    expect(xml).toContain('<row r="1"><c r="A1" t="inlineStr"><is><t xml:space="preserve">Item</t></is></c><c r="C1" t="inlineStr"><is><t xml:space="preserve">3,5</t></is></c></row>');
    expect(xml).toContain('<row r="2"><c r="B2"');
    expect(xml).not.toContain('r="B1"');
  });

  it("escapes markup and drops what XML cannot carry", () => {
    const xml = sheet([["a<b>&c\u0001d\ttab"]]);
    expect(xml).toContain("a&lt;b&gt;&amp;cd\ttab");
  });

  it("names columns past Z", () => {
    expect(sheet([Array.from({ length: 28 }, (_, i) => String(i))])).toContain('r="AB1"');
  });

  it("reads the bytes as the encoding says, without a byte order mark", () => {
    const bytes = new TextEncoder().encode("﻿libellé;qté\n1;2\n");
    const xml = new TextDecoder().decode(members(xlsxOfTable(bytes.buffer, { delimiter: ";", encoding: "utf-8" }))["xl/worksheets/sheet1.xml"]);
    expect(xml).toContain(">libellé<");
    expect(xml).toContain('<c r="B2"');
    const latin1 = Uint8Array.from([0x6c, 0x69, 0x62, 0x65, 0x6c, 0x6c, 0xe9]);
    expect(new TextDecoder().decode(members(xlsxOfTable(latin1.buffer, { delimiter: ",", encoding: "windows-1252" }))["xl/worksheets/sheet1.xml"])).toContain(">libellé<");
  });
});
