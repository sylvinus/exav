import { describe, expect, it, vi } from "vitest";

import { compoundFile } from "../test/compound.js";
import { zipOf } from "../test/zip-members.js";
import { openTailReader, type TailReader } from "./zip-engine.js";
import { officeKinds, trimZipTail, zipDirectory } from "./zip.js";

// The ZIP reader in this process: the page has it in a worker.
vi.mock("./zip-engine.js", async () => ({ openTailReader: vi.fn((await import("../test/sniff.js")).openTailReader) }));

/** A ZIP of one stored member, with `comment` after its end record. */
function zip(comment = ""): Uint8Array {
  const name = new TextEncoder().encode("a.txt");
  const data = new TextEncoder().encode("hello");
  const local = new Uint8Array(30 + name.length + data.length);
  const lv = new DataView(local.buffer);
  lv.setUint32(0, 0x04034b50, true);
  lv.setUint32(14, 0x3610a686, true);
  lv.setUint32(18, data.length, true);
  lv.setUint32(22, data.length, true);
  lv.setUint16(26, name.length, true);
  local.set(name, 30);
  local.set(data, 30 + name.length);
  const central = new Uint8Array(46 + name.length);
  const cv = new DataView(central.buffer);
  cv.setUint32(0, 0x02014b50, true);
  cv.setUint32(16, 0x3610a686, true);
  cv.setUint32(20, data.length, true);
  cv.setUint32(24, data.length, true);
  cv.setUint16(28, name.length, true);
  central.set(name, 46);
  const text = new TextEncoder().encode(comment);
  const end = new Uint8Array(22 + text.length);
  const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, 1, true);
  ev.setUint16(10, 1, true);
  ev.setUint32(12, central.length, true);
  ev.setUint32(16, local.length, true);
  ev.setUint16(20, text.length, true);
  end.set(text, 22);
  return Uint8Array.from([...local, ...central, ...end]);
}

const with_ = (a: Uint8Array, ...tail: number[]) => Uint8Array.from([...a, ...tail]);
const trim = async (b: Uint8Array) => trimZipTail(b, await zipDirectory(b));

describe("zipDirectory", () => {
  it("lists the members and their uncompressed sizes", async () => {
    const d = await zipDirectory(zipOf([["a/b.xml", 7], ["c", 0xfffff]]));
    expect(d?.members).toEqual(new Map([["a/b.xml", 7], ["c", 0xfffff]]));
  });

  it("gives nothing for what is not a ZIP, or whose directory does not add up", async () => {
    expect(await zipDirectory(new Uint8Array(100))).toBeNull();
    const bad = zipOf([["a", 1]]);
    // The directory's first header is not one.
    new DataView(bad.buffer, bad.byteOffset).setUint32(0, 0, true);
    expect(await zipDirectory(bad)).toBeNull();
  });

  it("reads a directory larger than the first tail it is given", async () => {
    const many = Array.from({ length: 30000 }, (_, i): [string, number] => [`ppt/slides/slide${i + 1}.xml`, i]);
    const z = zipOf(many);
    expect(z.length).toBeGreaterThan(1 << 20);
    const d = await zipDirectory(z);
    expect(d?.members.size).toBe(30000);
    expect(d?.members.get("ppt/slides/slide30000.xml")).toBe(29999);
  });
});

describe("zipDirectory's reader", () => {
  const trapped = (): TailReader & { closed: boolean } => ({
    closed: false,
    read: () => Promise.reject(new WebAssembly.RuntimeError("unreachable")),
    kinds: () => Promise.reject(new WebAssembly.RuntimeError("unreachable")),
    close() {
      this.closed = true;
    },
  });

  it("is closed when the file is done, whatever came of it", async () => {
    const real = (await import("../test/sniff.js")).openTailReader;
    let closes = 0;
    const counted = (): TailReader => {
      const inner = real();
      return {
        read: (tail, size) => inner.read(tail, size),
        kinds: (bytes, names) => inner.kinds(bytes, names),
        close() {
          closes += 1;
          inner.close();
        },
      };
    };
    vi.mocked(openTailReader).mockImplementationOnce(counted).mockImplementationOnce(counted);
    await zipDirectory(zipOf([["a", 1]]));
    await zipDirectory(new Uint8Array(10));
    expect(closes).toBe(2);
  });

  it("is not kept after it trapped: the next file has one of its own", async () => {
    const dead = trapped();
    vi.mocked(openTailReader).mockImplementationOnce(() => dead);
    await expect(zipDirectory(zipOf([["a", 1]]))).rejects.toThrow("unreachable");
    expect(dead.closed).toBe(true);
    const next = vi.mocked(openTailReader).mock.calls.length;
    const d = await zipDirectory(zipOf([["b", 2]]));
    expect(d?.members).toEqual(new Map([["b", 2]]));
    expect(vi.mocked(openTailReader).mock.calls.length).toBe(next + 1);
  });

  it("is closed at once when the session ends", async () => {
    const slow: TailReader & { closed: boolean } = {
      closed: false,
      read: () => new Promise(() => {}),
      kinds: () => new Promise(() => {}),
      close() {
        this.closed = true;
      },
    };
    vi.mocked(openTailReader).mockImplementationOnce(() => slow);
    const stop = new AbortController();
    void zipDirectory(zipOf([["a", 1]]), stop.signal).catch(() => {});
    stop.abort();
    expect(slow.closed).toBe(true);
  });
});

describe("officeKinds", () => {
  it("tells a ZIP by its directory and a compound file by its streams", async () => {
    expect(await officeKinds(zipOf([["[Content_Types].xml", 1], ["word/document.xml", 1]]))).toEqual(["docx"]);
    expect(await officeKinds(compoundFile(["Workbook", "WordDocument"]))).toEqual(["doc", "xls"]);
    expect(await officeKinds(new TextEncoder().encode("a,b\n1,2\n"))).toEqual([]);
  });

  it("gives a compound file whole, its directory being anywhere in it", async () => {
    const given: number[] = [];
    const real = (await import("../test/sniff.js")).openTailReader;
    vi.mocked(openTailReader).mockImplementationOnce(() => {
      const inner = real();
      return { ...inner, kinds: (bytes, names) => (given.push(bytes.length), inner.kinds(bytes, names)) };
    });
    const file = compoundFile(["WordDocument"]);
    await officeKinds(file);
    expect(given).toEqual([file.length]);
  });

  it("says it does not know a compound file the reader fails on, gives no kinds for anything else, and fails when the session ended", async () => {
    const dead: TailReader = { read: () => Promise.reject(new Error("dead")), kinds: () => Promise.reject(new Error("dead")), close() {} };
    vi.mocked(openTailReader).mockImplementationOnce(() => dead);
    expect(await officeKinds(compoundFile(["WordDocument"]))).toBeNull();
    vi.mocked(openTailReader).mockImplementationOnce(() => dead);
    expect(await officeKinds(new TextEncoder().encode("{\\rtf1"))).toEqual([]);
    vi.mocked(openTailReader).mockImplementationOnce(() => dead);
    const stop = new AbortController();
    stop.abort();
    await expect(officeKinds(compoundFile(["WordDocument"]), stop.signal)).rejects.toThrow("dead");
  });
});

describe("trimZipTail", () => {
  it("drops bytes after the end record, which the engines refuse", async () => {
    const z = zip();
    expect(await trim(with_(z, 0x0a))).toEqual(z);
    expect(await trim(with_(z, 0, 0, 0, 0))).toEqual(z);
  });

  it("keeps a comment, and drops what follows it", async () => {
    const z = zip("made by a tool");
    expect(await trim(z)).toEqual(z);
    expect(await trim(with_(z, 0x0a))).toEqual(z);
  });

  it("returns the same bytes when there is no tail", async () => {
    const z = zip();
    expect(await trim(z)).toBe(z);
  });

  it("is not fooled by an end record's signature inside the comment", async () => {
    const z = zip("PK\x05\x06" + "x".repeat(18));
    expect(await trim(with_(z, 0x0a))).toEqual(z);
  });

  it("keeps a prefix the reader opens past, and drops the tail", async () => {
    const z = zip();
    const prefixed = Uint8Array.from([...new Uint8Array(10), ...z]);
    expect(await trim(with_(prefixed, 0x0a))).toEqual(prefixed);
  });

  it("leaves what the reader does not open as it came", async () => {
    expect(await trim(new Uint8Array([1, 2, 3]))).toEqual(new Uint8Array([1, 2, 3]));
    const broken = with_(zip(), 0x0a);
    // The central header's signature, damaged.
    broken[40] = 0;
    expect(await trim(broken)).toBe(broken);
  });
});
