import { describe, expect, it } from "vitest";

import { decompressedName, folderOf, memberPath, safeFileName } from "./names.js";

describe("a member's name as a download name", () => {
  it("has no control or bidirectional character, so it reads as it is stored", () => {
    for (const c of ["\u{202e}", "\u{202d}", "\u{2067}", "\u{2069}", "\u{200e}", "\u{61c}", "\u{2029}", "\u{0}", "\u{9b}"]) {
      expect(safeFileName(`docs/invoice${c}fdp.exe`), JSON.stringify(c)).toBe("invoice_fdp.exe");
    }
    expect(safeFileName("../../ميزانية.xlsx")).toBe("ميزانية.xlsx");
  });
});

describe("what a compressed stream's file is called", () => {
  // The names gunzip, bunzip2, unxz and unzstd give what they decompress.
  it("is the stream's name without its compression", () => {
    expect(decompressedName("models.tar.gz", "gzip-content")).toBe("models.tar");
    expect(decompressedName("report.pdf.bz2", "bzip2-content")).toBe("report.pdf");
    expect(decompressedName("logs/app.log.xz", "xz-content")).toBe("app.log");
    expect(decompressedName("data.csv.zst", "zstd-content")).toBe("data.csv");
    expect(decompressedName("OLD.TAR.Z", "lzw-content")).toBe("OLD.TAR");
  });

  it("is a tar for the short tarball suffixes", () => {
    expect(decompressedName("site.tgz", "gzip-content")).toBe("site.tar");
    expect(decompressedName("site.tbz2", "bzip2-content")).toBe("site.tar");
    expect(decompressedName("site.txz", "xz-content")).toBe("site.tar");
    expect(decompressedName("site.tzst", "zstd-content")).toBe("site.tar");
    expect(decompressedName("site.tlz", "lzip-content")).toBe("site.tar");
    expect(decompressedName("site.tar.lzma", "lzma-content")).toBe("site.tar");
    expect(decompressedName("notes.txt.lzma", "lzma-content")).toBe("notes.txt");
    expect(decompressedName("site.taz", "lzw-content")).toBe("site.tar");
    expect(decompressedName("site.tbz", "bzip2-content")).toBe("site.tar");
  });

  it("drops the suffix of the other compressions too", () => {
    expect(decompressedName("dump.sql.lz4", "lz4-content")).toBe("dump.sql");
    expect(decompressedName("dump.sql.lz", "lzip-content")).toBe("dump.sql");
    expect(decompressedName("DUMP.SQL.Z", "lzw-content")).toBe("DUMP.SQL");
  });

  it("lists the members of a disk image or a help file as relative paths", () => {
    expect(memberPath("/docs/index.html")).toBe("docs/index.html");
    expect(memberPath("/test.txt")).toBe("test.txt");
    expect(memberPath("docs/a.txt")).toBe("docs/a.txt");
    expect(memberPath("\\a.txt")).toBe("a.txt");
    expect(folderOf(memberPath("/docs/index.html"))).toBe("docs");
  });

  it("falls back when the name says nothing", () => {
    expect(decompressedName("download", "gzip-content")).toBe("gzip-content");
    expect(decompressedName(".gz", "gzip-content")).toBe("gzip-content");
  });
});
