/**
 * A stream of a compound file: its name and its content, or just a name for
 * one of zeros. A type other than 2 (stream) makes it another kind of entry
 * (1 storage, 0 unused).
 */
export type CompoundStream = string | [name: string, data: Uint8Array, type?: number];

const SECTOR = 512;
const END = 0xfffffffe;
const FAT_SECTOR = 0xfffffffd;
const NONE = 0xffffffff;
/** Streams this long are kept in the FAT, not the mini stream. */
const LONG = 4096;

/**
 * A version 3 compound file whose root holds `streams`, each padded to 4096
 * bytes, for tests that need a directory to read. At most 12 streams.
 */
export function compoundFile(streams: readonly CompoundStream[]): Uint8Array {
  const entries = streams.map((s): [string, Uint8Array, number?] => (typeof s === "string" ? [s, new Uint8Array()] : s));
  if (entries.length > 12) throw new Error("compoundFile: at most 12 streams");
  const dirSectors = Math.ceil((entries.length + 1) / 4);
  const perStream = LONG / SECTOR;
  const sectors = 1 + dirSectors + entries.length * perStream;
  const out = new Uint8Array(SECTOR * (1 + sectors));
  const view = new DataView(out.buffer);

  out.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  view.setUint16(24, 0x3e, true);
  view.setUint16(26, 3, true);
  view.setUint16(28, 0xfffe, true);
  view.setUint16(30, 9, true);
  view.setUint16(32, 6, true);
  view.setUint32(44, 1, true);
  view.setUint32(48, 1, true);
  view.setUint32(56, LONG, true);
  view.setUint32(60, END, true);
  view.setUint32(68, END, true);
  view.setUint32(76, 0, true);
  for (let i = 1; i < 109; i++) view.setUint32(76 + 4 * i, NONE, true);

  // Sector n is at (n + 1) * 512. Sector 0 is the FAT, then the directory, then each stream.
  const sectorAt = (n: number) => (n + 1) * SECTOR;
  const fat = new Array<number>(SECTOR / 4).fill(NONE);
  fat[0] = FAT_SECTOR;
  const chain = (first: number, count: number) => {
    for (let k = 0; k < count; k++) fat[first + k] = k + 1 === count ? END : first + k + 1;
  };
  chain(1, dirSectors);
  entries.forEach((_, i) => chain(1 + dirSectors + i * perStream, perStream));
  fat.forEach((v, i) => view.setUint32(sectorAt(0) + 4 * i, v, true));

  const entry = (index: number, name: string, type: number, right: number, child: number, start: number, size: number) => {
    const at = sectorAt(1) + 128 * index;
    for (let i = 0; i < name.length; i++) view.setUint16(at + 2 * i, name.charCodeAt(i), true);
    view.setUint16(at + 64, (name.length + 1) * 2, true);
    out[at + 66] = type;
    out[at + 67] = 1;
    view.setUint32(at + 68, NONE, true);
    view.setUint32(at + 72, right, true);
    view.setUint32(at + 76, child, true);
    view.setUint32(at + 116, start, true);
    view.setUint32(at + 120, size, true);
  };
  entry(0, "Root Entry", 5, NONE, entries.length ? 1 : NONE, END, 0);
  // Unused slots of the last directory sector are entries of type 0.
  for (let i = entries.length + 1; i < dirSectors * 4; i++) entry(i, "", 0, NONE, NONE, 0, 0);
  entries.forEach(([name, data, type = 2], i) => {
    const start = 1 + dirSectors + i * perStream;
    entry(i + 1, name, type, i + 1 < entries.length ? i + 2 : NONE, NONE, start, LONG);
    out.set(data.subarray(0, LONG), sectorAt(start));
  });
  return out;
}
