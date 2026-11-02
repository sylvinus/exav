/**
 * A delimited text as a one-sheet XLSX, for the second copy of a CSV that
 * its pictures are drawn from: the engines read delimited text only through
 * the sheet viewer, which has no workbook to draw pictures with. Every field
 * is text, as the viewer reads them.
 */
import { RasterError } from "../core/pictures.js";
import type { Reading } from "./delimited.js";
import { columnName } from "./raster.js";

/**
 * The most fields a table is read with: the engine's own limit on the cells
 * of a sheet, counting blanks, which the viewer refuses a larger table for.
 */
export const MAX_FIELDS = 250_000;

/**
 * The rows of a delimited text, quoted fields unquoted (RFC 4180); blank
 * lines are no rows. More than `maxFields` fields is refused ("too-large"),
 * before they are all held.
 */
export function parseTable(text: string, delimiter: string, maxFields = MAX_FIELDS): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  let started = false;
  let fields = 0;
  const endField = () => {
    if (++fields > maxFields) throw new RasterError("too-large", `the table has more than ${maxFields} cells`);
    row.push(field);
    field = "";
  };
  const endRow = () => {
    if (started || row.length > 0) {
      endField();
      rows.push(row);
    }
    row = [];
    started = false;
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += c;
    } else if (c === '"' && field === "") {
      quoted = true;
      started = true;
    } else if (c === delimiter) {
      endField();
      started = true;
    } else if (c === "\n") endRow();
    else if (c === "\r") {
      if (text[i + 1] === "\n") i++;
      endRow();
    } else {
      field += c;
      started = true;
    }
  }
  endRow();
  return rows;
}

const CRC = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of data) c = CRC[(c ^ b) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** A ZIP of stored (uncompressed) members. */
export function storedZip(files: [string, Uint8Array][]): Uint8Array {
  const names = files.map(([name]) => new TextEncoder().encode(name));
  const size = files.reduce((n, [, data], i) => n + 30 + names[i]!.length + data.length + 46 + names[i]!.length, 22);
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  let at = 0;
  const offsets: number[] = [];
  files.forEach(([, data], i) => {
    offsets.push(at);
    view.setUint32(at, 0x04034b50, true);
    view.setUint16(at + 4, 20, true);
    view.setUint32(at + 14, crc32(data), true);
    view.setUint32(at + 18, data.length, true);
    view.setUint32(at + 22, data.length, true);
    view.setUint16(at + 26, names[i]!.length, true);
    out.set(names[i]!, at + 30);
    out.set(data, at + 30 + names[i]!.length);
    at += 30 + names[i]!.length + data.length;
  });
  const directory = at;
  files.forEach(([, data], i) => {
    view.setUint32(at, 0x02014b50, true);
    view.setUint16(at + 4, 20, true);
    view.setUint16(at + 6, 20, true);
    view.setUint32(at + 16, crc32(data), true);
    view.setUint32(at + 20, data.length, true);
    view.setUint32(at + 24, data.length, true);
    view.setUint16(at + 28, names[i]!.length, true);
    view.setUint32(at + 42, offsets[i]!, true);
    out.set(names[i]!, at + 46);
    at += 46 + names[i]!.length;
  });
  view.setUint32(at, 0x06054b50, true);
  view.setUint16(at + 8, files.length, true);
  view.setUint16(at + 10, files.length, true);
  view.setUint32(at + 12, at - directory, true);
  view.setUint32(at + 16, directory, true);
  return out;
}

/** Characters XML 1.0 cannot carry are dropped; the rest is escaped. */
const xml = (text: string) =>
  text
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]/g, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

const HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
const NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

/** The rows as a workbook of one sheet, "Sheet1". */
export function xlsxOfRows(rows: string[][]): Uint8Array {
  const body = rows
    .map((fields, r) => {
      const cells = fields
        .map((text, c) => (text === "" ? "" : `<c r="${columnName(c + 1)}${r + 1}" t="inlineStr"><is><t xml:space="preserve">${xml(text)}</t></is></c>`))
        .join("");
      return `<row r="${r + 1}">${cells}</row>`;
    })
    .join("");
  const enc = (text: string) => new TextEncoder().encode(HEAD + text);
  return storedZip([
    [
      "[Content_Types].xml",
      enc(
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>',
      ),
    ],
    ["_rels/.rels", enc(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>`)],
    ["xl/workbook.xml", enc(`<workbook xmlns="${NS}" xmlns:r="${REL}"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`)],
    [
      "xl/_rels/workbook.xml.rels",
      enc(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${REL}/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="${REL}/styles" Target="styles.xml"/></Relationships>`),
    ],
    [
      "xl/styles.xml",
      enc(
        `<styleSheet xmlns="${NS}"><fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs></styleSheet>`,
      ),
    ],
    ["xl/worksheets/sheet1.xml", enc(`<worksheet xmlns="${NS}"><sheetFormatPr defaultColWidth="8.43" defaultRowHeight="15"/><sheetData>${body}</sheetData></worksheet>`)],
  ]);
}

/** The delimited text `bytes`, read as `reading` says, as a workbook. */
export function xlsxOfTable(bytes: ArrayBuffer, reading: Reading): Uint8Array {
  const text = new TextDecoder(reading.encoding).decode(bytes);
  return xlsxOfRows(parseTable(text, reading.delimiter));
}
