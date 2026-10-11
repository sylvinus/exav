import { describe, expect, it } from "vitest";

import { decompressedName, STREAM_MEMBER } from "./names.js";

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
  });

  it("falls back when the name says nothing", () => {
    expect(decompressedName("download", "gzip-content")).toBe("gzip-content");
    expect(decompressedName(".gz", "gzip-content")).toBe("gzip-content");
  });

  it("is told by the library's name for it, and only that", () => {
    for (const n of ["gzip-content", "bzip2-content", "xz-content", "zstd-content", "lzip-content", "lz4-content", "lzw-content"]) {
      expect(STREAM_MEMBER.test(n), n).toBe(true);
    }
    for (const n of ["content", "gzip-content.txt", "docs/gzip-content", "zip-content"]) {
      expect(STREAM_MEMBER.test(n), n).toBe(false);
    }
  });
});
