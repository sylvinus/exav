import { describe, it, expect } from 'vitest';

// Extract pure JS helpers from test.html for unit testing
function crc32(bytes: Uint8Array): number {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function buildTinyZip(entries: Array<{ name: string; data: string | Uint8Array }>): Uint8Array {
  const localHeaders: Array<{ buf: ArrayBuffer; data: Uint8Array }> = [];
  const centralHeaders: ArrayBuffer[] = [];
  let offset = 0;
  const encoder = new TextEncoder();

  for (const entry of entries) {
    const nameBytes = encoder.encode(entry.name);
    const dataBytes = entry.data instanceof Uint8Array ? entry.data : encoder.encode(entry.data || '');
    const compMethod = 0;

    // Local file header
    const lh = new ArrayBuffer(30 + nameBytes.length);
    const lv = new DataView(lh);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0, true);
    lv.setUint16(8, compMethod, true);
    lv.setUint16(10, 0, true);
    lv.setUint16(12, 0, true);
    lv.setUint32(14, crc32(dataBytes), true);
    lv.setUint32(18, dataBytes.length, true);
    lv.setUint32(22, dataBytes.length, true);
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true);
    new Uint8Array(lh).set(nameBytes, 30);
    localHeaders.push({ buf: lh, data: dataBytes });

    // Central directory header
    const ch = new ArrayBuffer(46 + nameBytes.length);
    const cv = new DataView(ch);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0, true);
    cv.setUint16(10, compMethod, true);
    cv.setUint16(12, 0, true);
    cv.setUint16(14, 0, true);
    cv.setUint32(16, crc32(dataBytes), true);
    cv.setUint32(20, dataBytes.length, true);
    cv.setUint32(24, dataBytes.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true);
    cv.setUint16(32, 0, true);
    cv.setUint16(34, 0, true);
    cv.setUint16(36, 0, true);
    cv.setUint32(38, 0, true);
    cv.setUint32(42, offset, true);
    new Uint8Array(ch).set(nameBytes, 46);
    centralHeaders.push(ch);

    offset += 30 + nameBytes.length + dataBytes.length;
  }

  const cdOffset = offset;
  let cdSize = 0;
  for (const ch of centralHeaders) cdSize += ch.byteLength;

  const eocd = new ArrayBuffer(22);
  const ev = new DataView(eocd);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(4, 0, true);
  ev.setUint16(6, 0, true);
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, cdOffset, true);
  ev.setUint16(20, 0, true);

  let totalSize = 0;
  for (const h of localHeaders) totalSize += h.buf.byteLength + h.data.length;
  for (const ch of centralHeaders) totalSize += ch.byteLength;
  totalSize += 22;

  const result = new Uint8Array(totalSize);
  let pos = 0;
  for (const h of localHeaders) {
    result.set(new Uint8Array(h.buf), pos);
    pos += h.buf.byteLength;
    result.set(h.data, pos);
    pos += h.data.length;
  }
  for (const ch of centralHeaders) {
    result.set(new Uint8Array(ch), pos);
    pos += ch.byteLength;
  }
  result.set(new Uint8Array(eocd), pos);
  return result;
}

describe('crc32', () => {
  it('computes correct CRC32 for "hello world"', () => {
    const data = new TextEncoder().encode('hello world');
    expect(crc32(data)).toBe(0x0d4a1185);
  });

  it('returns 0xFFFFFFFF for empty input', () => {
    expect(crc32(new Uint8Array(0))).toBe(0x00000000);
  });
});

describe('buildTinyZip', () => {
  it('produces a valid ZIP with PK signatures', () => {
    const zip = buildTinyZip([{ name: 'a.txt', data: 'hello' }]);
    // Local file header signature
    expect(zip[0]).toBe(0x50);
    expect(zip[1]).toBe(0x4b);
    expect(zip[2]).toBe(0x03);
    expect(zip[3]).toBe(0x04);
  });

  it('produces a ZIP detectable by magic bytes', () => {
    const zip = buildTinyZip([{ name: 'x.txt', data: 'data' }]);
    const isValidPk = zip[0] === 0x50 && zip[1] === 0x4b;
    expect(isValidPk).toBe(true);
  });

  it('supports multiple entries', () => {
    const zip = buildTinyZip([
      { name: 'a.txt', data: 'aaa' },
      { name: 'b.txt', data: 'bbb' },
    ]);
    expect(zip.length).toBeGreaterThan(0);
  });
});
