import zlib from "node:zlib";

/** A ZIP of stored (uncompressed) members, for tests that need an archive to read. */
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
    view.setUint32(at + 14, zlib.crc32(data), true);
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
    view.setUint32(at + 16, zlib.crc32(data), true);
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
