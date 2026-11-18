import { describe, expect, it, vi } from "vitest";

import { SheetConversionError } from "./sheets.js";
import { xlsxOfTable } from "./table.js";

// exav-render's CSV reader runs in a worker on the page: the same module, in this process.
vi.mock("./table-engine.js", () => import("../test/table.js"));

const enc = (s: string) => new TextEncoder().encode(s);

describe("a CSV or TSV as a workbook", () => {
  it("is an XLSX, whatever the separator and the encoding", async () => {
    for (const bytes of [enc("a;b\n1;2\n"), enc("a\tb\n1\t2\n"), Uint8Array.from([0x6c, 0x69, 0x62, 0x65, 0x6c, 0xe9, 0x3b, 0x78, 0x0a])]) {
      const xlsx = new Uint8Array(await xlsxOfTable(bytes));
      expect([...xlsx.slice(0, 4)]).toEqual([0x50, 0x4b, 0x03, 0x04]);
    }
  });

  it("fails with a conversion error that says why: not text, or more fields than a sheet is drawn with", async () => {
    const fails = async (bytes: Uint8Array) => xlsxOfTable(bytes).then(() => null, (error: unknown) => error);
    const binary = await fails(Uint8Array.from([0, 1, 2, 0, 0, 0xff]));
    expect(binary).toBeInstanceOf(SheetConversionError);
    expect(binary).toMatchObject({ format: "csv", kind: "not-format" });
    // 250 000 fields in all, empty ones included, is the most: 500 rows of 500.
    const rows = `${",".repeat(499)}\n`.repeat(500);
    expect(await xlsxOfTable(enc(rows))).toBeInstanceOf(ArrayBuffer);
    expect(await fails(enc(`${rows}a\n`))).toMatchObject({ format: "csv", kind: "too-large" });
  });
});
