import { test, expect } from '@playwright/test';

// Shared helpers injected into the browser
const HELPERS = `
  function crc32(bytes) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) {
      crc ^= bytes[i];
      for (let j = 0; j < 8; j++) {
        crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
      }
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  function buildTinyZip(entries) {
    const localHeaders = [];
    const centralHeaders = [];
    let offset = 0;
    const encoder = new TextEncoder();

    for (const entry of entries) {
      const nameBytes = encoder.encode(entry.name);
      const dataBytes = entry.data instanceof Uint8Array ? entry.data : encoder.encode(entry.data || "");
      const compMethod = 0;

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

  async function readStream(stream) {
    const reader = stream.getReader();
    const chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const combined = new Uint8Array(totalLen);
    let off = 0;
    for (const c of chunks) { combined.set(c, off); off += c.length; }
    return combined;
  }
`;

async function setupPage(page) {
  await page.goto('/e2e/test.html');
  await page.waitForFunction('window.__test?.ready');
}

test.describe('WASM E2E', () => {
  test('detect_format identifies zip', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { detect_format } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([{ name: "a.txt", data: "hello" }]);
        return detect_format(zipBytes);
      })()
    `);
    expect(result).toBe('Zip');
  });

  test('unpack returns entries', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { unpack } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([
          { name: "hello.txt", data: "hello world" },
          { name: "sub/dir.txt", data: "nested content" },
        ]);
        const entries = await unpack(zipBytes);
        return entries.map(e => ({ name: e.name, len: e.data.byteLength || e.data.length }));
      })()
    `);
    expect(result).toHaveLength(2);
    expect(result[0].name).toBe('hello.txt');
    expect(result[1].name).toBe('sub/dir.txt');
  });

  test('Archive.open from Uint8Array', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([
          { name: "hello.txt", data: "hello world" },
          { name: "sub/dir.txt", data: "nested" },
        ]);
        const archive = await Archive.open(zipBytes);
        const fmt = archive.format();
        const members = await archive.list();
        return {
          fmt,
          count: members.length,
          names: members.map(m => m.name),
          sizes: members.map(m => m.uncompressedSize),
        };
      })()
    `);
    expect(result.fmt).toBe('Zip');
    expect(result.count).toBe(2);
    expect(result.names).toEqual(['hello.txt', 'sub/dir.txt']);
    expect(result.sizes).toEqual([11, 6]);
  });

  test('Archive.extract returns ReadableStream', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([{ name: "hello.txt", data: "hello world" }]);
        const archive = await Archive.open(zipBytes);
        const entry = await archive.extract(0);
        const text = new TextDecoder().decode(await readStream(entry.data));
        return { name: entry.name, encrypted: entry.encrypted, text };
      })()
    `);
    expect(result.name).toBe('hello.txt');
    expect(result.encrypted).toBe(false);
    expect(result.text).toBe('hello world');
  });

  test('Archive.extractAll returns all entries', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([
          { name: "a.txt", data: "alpha" },
          { name: "b.txt", data: "beta" },
        ]);
        const archive = await Archive.open(zipBytes);
        const all = await archive.extract_all();
        const results = [];
        for (const e of all) {
          const text = new TextDecoder().decode(await readStream(e.data));
          results.push({ name: e.name, text });
        }
        return results;
      })()
    `);
    expect(result).toHaveLength(2);
    expect(result[0]).toEqual({ name: 'a.txt', text: 'alpha' });
    expect(result[1]).toEqual({ name: 'b.txt', text: 'beta' });
  });

  test('custom reader object works', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([
          { name: "r.txt", data: "reader content" },
        ]);
        const readCalls = [];
        const customReader = {
          size: zipBytes.length,
          data: zipBytes,
          read(offset, length) {
            readCalls.push({ offset, length });
            const end = Math.min(offset + length, this.data.length);
            return Promise.resolve(this.data.slice(offset, end));
          },
        };
        const archive = await Archive.open(customReader);
        const fmt = archive.format();
        const members = await archive.list();
        const entry = await archive.extract(0);
        const text = new TextDecoder().decode(await readStream(entry.data));
        return { fmt, members: members.length, text, reads: readCalls.length };
      })()
    `);
    expect(result.fmt).toBe('Zip');
    expect(result.members).toBe(1);
    expect(result.text).toBe('reader content');
    expect(result.reads).toBeGreaterThan(0);
  });

  test('error on unsupported type', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        try {
          await Archive.open(42);
          return { ok: true };
        } catch (e) {
          return { ok: false, msg: String(e) };
        }
      })()
    `);
    expect(result.ok).toBe(false);
  });

  test('error on bad reader', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        try {
          await Archive.open({ notAReader: true });
          return { ok: true };
        } catch (e) {
          return { ok: false, msg: String(e) };
        }
      })()
    `);
    expect(result.ok).toBe(false);
    expect(result.msg).toContain('size');
  });

  test('error on unrecognized format', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        try {
          const garbage = new Uint8Array([1, 2, 3, 4, 5]);
          await Archive.open(garbage);
          return { ok: true };
        } catch (e) {
          return { ok: false, msg: String(e) };
        }
      })()
    `);
    expect(result.ok).toBe(false);
    expect(result.msg).toContain('unrecognised');
  });

  test('extract triggers additional reads on custom reader', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([
          { name: "file1.txt", data: "data1" },
          { name: "file2.txt", data: "data2" },
        ]);
        const readCalls = [];
        const customReader = {
          size: zipBytes.length,
          data: zipBytes,
          read(offset, length) {
            readCalls.push({ offset, length });
            const end = Math.min(offset + length, this.data.length);
            return Promise.resolve(this.data.slice(offset, end));
          },
        };
        const archive = await Archive.open(customReader);
        const callsBefore = readCalls.length;
        await archive.extract(0);
        return { callsBeforeExtract: callsBefore, totalAfterExtract: readCalls.length };
      })()
    `);
    expect(result.totalAfterExtract).toBeGreaterThan(result.callsBeforeExtract);
  });

  test('gzip file via File object', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        ${HELPERS}
        const { Archive, detect_format } = window.__test;
        // Build a gzip file in JS using CompressionStream
        const encoder = new TextEncoder();
        const plain = encoder.encode("hello gzip");
        const cs = new CompressionStream("gzip");
        const writer = cs.writable.getWriter();
        writer.write(plain);
        writer.close();
        const reader = cs.readable.getReader();
        const chunks = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
        const totalLen = chunks.reduce((s, c) => s + c.length, 0);
        const gzBytes = new Uint8Array(totalLen);
        let off = 0;
        for (const c of chunks) { gzBytes.set(c, off); off += c.length; }

        // Detect from Uint8Array
        const fmt = detect_format(gzBytes);
        if (fmt !== "Gzip") return { step: "detect", fmt };

        // Open as Uint8Array
        const archive = await Archive.open(gzBytes);
        const members = await archive.list();
        const entry = await archive.extract(0);
        const text = new TextDecoder().decode(await readStream(entry.data));
        return { fmt, members: members.length, text };
      })()
    `);
    expect(result.fmt).toBe('Gzip');
    expect(result.members).toBe(1);
    expect(result.text).toBe('hello gzip');
  });

  test('gzip file via File object (drag-and-drop path)', async ({ page }) => {
    await setupPage(page);
    // Create a real File object in the browser (simulates drag-and-drop)
    const result = await page.evaluate(`
      (async () => {
        ${HELPERS}
        const { Archive } = window.__test;
        // Build gzip bytes
        const encoder = new TextEncoder();
        const plain = encoder.encode("file gzip content");
        const cs = new CompressionStream("gzip");
        const writer = cs.writable.getWriter();
        writer.write(plain);
        writer.close();
        const reader = cs.readable.getReader();
        const chunks = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
        const totalLen = chunks.reduce((s, c) => s + c.length, 0);
        const gzBytes = new Uint8Array(totalLen);
        let off = 0;
        for (const c of chunks) { gzBytes.set(c, off); off += c.length; }

        // Create a File object (exactly what drag-and-drop produces)
        const file = new File([gzBytes], "test.gz", { type: "application/gzip" });
        const archive = await Archive.open(file);
        const fmt = archive.format();
        const members = await archive.list();
        const entry = await archive.extract(0);
        const text = new TextDecoder().decode(await readStream(entry.data));
        return { fmt, members: members.length, text };
      })()
    `);
    expect(result.fmt).toBe('Gzip');
    expect(result.members).toBe(1);
    expect(result.text).toBe('file gzip content');
  });
});
