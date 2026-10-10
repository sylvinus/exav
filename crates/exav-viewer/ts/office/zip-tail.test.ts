import { describe, expect, it } from "vitest";

import { trimZipTail } from "./zip-tail.js";

/** A ZIP of one stored member, with `comment` after its end record. */
function zip(comment = ""): Uint8Array {
  const name = new TextEncoder().encode("a.txt");
  const data = new TextEncoder().encode("hello");
  const local = new Uint8Array(30 + name.length + data.length);
  const lv = new DataView(local.buffer);
  lv.setUint32(0, 0x04034b50, true);
  lv.setUint32(18, data.length, true);
  lv.setUint32(22, data.length, true);
  lv.setUint16(26, name.length, true);
  local.set(name, 30);
  local.set(data, 30 + name.length);
  const central = new Uint8Array(46 + name.length);
  const cv = new DataView(central.buffer);
  cv.setUint32(0, 0x02014b50, true);
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

describe("trimZipTail", () => {
  it("drops bytes after the end record, which the engines refuse", () => {
    const z = zip();
    expect(trimZipTail(with_(z, 0x0a))).toEqual(z);
    expect(trimZipTail(with_(z, 0, 0, 0, 0))).toEqual(z);
  });

  it("keeps a comment, and drops what follows it", () => {
    const z = zip("made by a tool");
    expect(trimZipTail(z)).toEqual(z);
    expect(trimZipTail(with_(z, 0x0a))).toEqual(z);
  });

  it("returns the same bytes when there is no tail", () => {
    const z = zip();
    expect(trimZipTail(z)).toBe(z);
  });

  it("is not fooled by an end record's signature inside the comment", () => {
    const fake = "PK\x05\x06" + "x".repeat(18);
    const z = zip(fake);
    expect(trimZipTail(with_(z, 0x0a))).toEqual(z);
  });

  it("leaves what it cannot be sure of as it came", () => {
    expect(trimZipTail(new Uint8Array([1, 2, 3]))).toEqual(new Uint8Array([1, 2, 3]));
    // A prefix before the archive (a self-extractor): the offsets do not add up.
    const prefixed = Uint8Array.from([...new Uint8Array(10), ...zip(), 0x0a]);
    expect(trimZipTail(prefixed)).toEqual(prefixed);
  });
});
