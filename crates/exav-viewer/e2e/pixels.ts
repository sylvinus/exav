// Reads the PNG screenshots Playwright takes (8-bit RGB or RGBA, not
// interlaced), so a test can look at what was drawn: the WebGL and canvas
// engines leave nothing in the DOM to assert on.
import zlib from "node:zlib";

export interface Pixels {
  width: number;
  height: number;
  /** RGBA, row-major. */
  data: Uint8Array;
}

export function decodePng(png: Buffer): Pixels {
  let at = 8;
  let width = 0;
  let height = 0;
  let channels = 0;
  const idat: Buffer[] = [];
  while (at < png.length) {
    const len = png.readUInt32BE(at);
    const type = png.toString("latin1", at + 4, at + 8);
    const body = png.subarray(at + 8, at + 8 + len);
    if (type === "IHDR") {
      width = body.readUInt32BE(0);
      height = body.readUInt32BE(4);
      const [depth, color, , , interlace] = [body[8], body[9], body[10], body[11], body[12]];
      if (depth !== 8 || interlace !== 0 || (color !== 2 && color !== 6)) throw new Error(`unexpected PNG: depth ${depth}, colour ${color}`);
      channels = color === 6 ? 4 : 3;
    } else if (type === "IDAT") idat.push(body);
    at += 12 + len;
  }
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const stride = width * channels;
  const rows = new Uint8Array(stride * height);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)];
    const line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let x = 0; x < stride; x++) {
      const a = x >= channels ? rows[y * stride + x - channels]! : 0;
      const b = y > 0 ? rows[(y - 1) * stride + x]! : 0;
      const c = x >= channels && y > 0 ? rows[(y - 1) * stride + x - channels]! : 0;
      let v = line[x]!;
      if (filter === 1) v += a;
      else if (filter === 2) v += b;
      else if (filter === 3) v += (a + b) >> 1;
      else if (filter === 4) {
        const p = a + b - c;
        const [pa, pb, pc] = [Math.abs(p - a), Math.abs(p - b), Math.abs(p - c)];
        v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      }
      rows[y * stride + x] = v & 0xff;
    }
  }
  const data = new Uint8Array(width * height * 4);
  for (let i = 0; i < width * height; i++) {
    data[i * 4] = rows[i * channels]!;
    data[i * 4 + 1] = rows[i * channels + 1]!;
    data[i * 4 + 2] = rows[i * channels + 2]!;
    data[i * 4 + 3] = channels === 4 ? rows[i * channels + 3]! : 255;
  }
  return { width, height, data };
}

/** The pixels `test` accepts, counted, and the box around them (null if none). */
export function find(p: Pixels, test: (r: number, g: number, b: number) => boolean) {
  let count = 0;
  let [minX, minY, maxX, maxY] = [Infinity, Infinity, -1, -1];
  for (let y = 0; y < p.height; y++)
    for (let x = 0; x < p.width; x++) {
      const i = (y * p.width + x) * 4;
      if (!test(p.data[i]!, p.data[i + 1]!, p.data[i + 2]!)) continue;
      count++;
      minX = Math.min(minX, x);
      maxX = Math.max(maxX, x);
      minY = Math.min(minY, y);
      maxY = Math.max(maxY, y);
    }
  return { count, box: count ? { minX, minY, maxX, maxY, width: maxX - minX + 1, height: maxY - minY + 1 } : null };
}

/** Mean absolute difference per channel, 0..255, of two same-size images. */
export function difference(a: Pixels, b: Pixels): number {
  if (a.width !== b.width || a.height !== b.height) throw new Error(`sizes differ: ${a.width}x${a.height} and ${b.width}x${b.height}`);
  let sum = 0;
  for (let i = 0; i < a.data.length; i += 4) sum += Math.abs(a.data[i]! - b.data[i]!) + Math.abs(a.data[i + 1]! - b.data[i + 1]!) + Math.abs(a.data[i + 2]! - b.data[i + 2]!);
  return sum / ((a.data.length / 4) * 3);
}

/** Rows that have at least `min` pixels `test` accepts, grouped into bands of consecutive rows. */
export function bands(p: Pixels, test: (r: number, g: number, b: number) => boolean, min = 1): { from: number; to: number }[] {
  const out: { from: number; to: number }[] = [];
  for (let y = 0; y < p.height; y++) {
    let n = 0;
    for (let x = 0; x < p.width; x++) {
      const i = (y * p.width + x) * 4;
      if (test(p.data[i]!, p.data[i + 1]!, p.data[i + 2]!)) n++;
    }
    if (n < min) continue;
    const last = out[out.length - 1];
    if (last && last.to === y - 1) last.to = y;
    else out.push({ from: y, to: y });
  }
  return out;
}
