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
  test('detectFormat identifies zip', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { detectFormat } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([{ name: "a.txt", data: "hello" }]);
        return detectFormat(zipBytes);
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

  // A budget that cannot be set is a budget the page cannot honour. The
  // browser is the tightest memory environment exav runs in, and running out of
  // it aborts the module rather than returning an error, so the caller gets no
  // verdict at all — which is why this is settable and why it has to work.
  test('Archive.open honours a caller-supplied limit', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([
          { name: "hello.txt", data: "hello world" },
        ]);
        // Well below the 11-byte member, so extraction cannot complete.
        const archive = await Archive.open(zipBytes, { maxBufferBytes: 4 });
        try {
          const entries = await archive.extractAll();
          const bytes = await Promise.all(entries.map(e => readStream(e.data)));
          return {
            threw: false,
            error: null,
            // Whole-member bytes coming back means the limit was ignored.
            sizes: bytes.map(b => b.length),
            unsupported: entries.map(e => e.unsupported || ""),
          };
        } catch (e) {
          return { threw: true, error: String(e), sizes: [], unsupported: [] };
        }
      })()
    `);
    // Refusing outright is acceptable. Completing is acceptable only if the
    // member is reported rather than handed back as though it were whole.
    // What is not acceptable is the third outcome this test previously could
    // not tell apart: the limit ignored and the full member returned.
    if (result.threw) {
      expect(result.error).not.toContain('is not a function');
    } else {
      const full = result.sizes.some((n: number, i: number) =>
        n > 4 && !result.unsupported[i]);
      expect(full, `a member larger than maxBufferBytes came back whole and \
unflagged; sizes=${JSON.stringify(result.sizes)} \
unsupported=${JSON.stringify(result.unsupported)}`).toBe(false);
    }
  });

  // The counterweight. Without it the assertion above is satisfied by a build
  // that refuses everything, and a limit that always refuses is not a limit.
  test('a generous limit returns the whole member', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([
          { name: "hello.txt", data: "hello world" },
        ]);
        const archive = await Archive.open(zipBytes, { maxBufferBytes: 1 << 20 });
        const entries = await archive.extractAll();
        const bytes = await Promise.all(entries.map(e => readStream(e.data)));
        return {
          text: new TextDecoder().decode(bytes[0]),
          unsupported: entries[0].unsupported || "",
        };
      })()
    `);
    expect(result.text).toBe('hello world');
    expect(result.unsupported).toBe('');
  });

  test('Archive.open with no limits still works', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([{ name: "a.txt", data: "hello world" }]);
        const archive = await Archive.open(zipBytes);
        const members = await archive.list();
        return members.length;
      })()
    `);
    expect(result).toBe(1);
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
        const all = await archive.extractAll();
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
          // Synchronous, returning bytes rather than a promise of them: the
          // archive readers are Read + Seek, and a read that returns bytes has
          // nowhere to await anything.
          read(offset, length) {
            readCalls.push({ offset, length });
            const end = Math.min(offset + length, this.data.length);
            return this.data.slice(offset, end);
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
    expect(result.msg).toContain('read');
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

  test('opening a large archive does not read all of it', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        // Two stored members of a megabyte each, so the archive is far larger
        // than any read window. Listing needs the central directory at the end
        // and nothing else; a reader that pulls the whole file to open it would
        // read every byte of this.
        const big = (fill) => { const b = new Uint8Array(1 << 20); b.fill(fill); return b; };
        const zipBytes = buildTinyZip([
          { name: "one.bin", data: big(1) },
          { name: "two.bin", data: big(2) },
        ]);
        let bytesRead = 0;
        const customReader = {
          size: zipBytes.length,
          data: zipBytes,
          read(offset, length) {
            const end = Math.min(offset + length, this.data.length);
            bytesRead += end - offset;
            return this.data.slice(offset, end);
          },
        };
        const archive = await Archive.open(customReader);
        const members = await archive.list();
        const afterOpen = bytesRead;
        const entry = await archive.extract(1);
        return {
          total: zipBytes.length,
          afterOpen,
          afterExtract: bytesRead,
          members: members.length,
          // The second member, so extracting it proves the reader seeks rather
          // than streaming from the front.
          extracted: entry.bytes.length,
          correct: entry.bytes.every((b) => b === 2),
        };
      })()
    `);
    expect(result.members).toBe(2);
    expect(result.extracted).toBe(1 << 20);
    expect(result.correct).toBe(true);
    // Listing reads the directory, not the members.
    expect(result.afterOpen).toBeLessThan(result.total / 2);
    // Extracting one member reads that member, and still not the whole archive.
    expect(result.afterExtract).toBeGreaterThan(result.afterOpen);
    expect(result.afterExtract).toBeLessThan(result.total);
  });

  test('gzip file via File object', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        ${HELPERS}
        const { Archive, detectFormat } = window.__test;
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
        const fmt = detectFormat(gzBytes);
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

  // A set like `big.zip.001`, `.002`, `.003` is one archive cut into pieces at
  // arbitrary byte offsets. Opened one file at a time — which is what a
  // multi-file drop gives you — none of them is a recognisable archive at all.
  test('isVolumePart recognises a byte-split part by name alone', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { isVolumePart } = window.__test;
        return {
          part: isVolumePart("big.7z.001"),
          zip: isVolumePart("big.zip.002"),
          plain: isVolumePart("notes.txt"),
          archive: isVolumePart("archive.zip"),
          // A RAR volume carries its own headers, so it is NOT byte-split:
          // concatenating those yields garbage that still looks like an archive.
          rar: isVolumePart("a.part1.rar"),
        };
      })()
    `);
    expect(result).toEqual({ part: true, zip: true, plain: false, archive: false, rar: false });
  });

  test('joinVolumes rejoins a split archive into an openable file', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive, joinVolumes, detectFormat } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([{ name: "inside.txt", data: "hello from a split archive" }]);
        // Cut through the middle, so no single piece is a recognisable zip.
        const cut = Math.floor(zipBytes.length / 3);
        const parts = [
          { name: "big.zip.001", data: zipBytes.slice(0, cut) },
          { name: "big.zip.002", data: zipBytes.slice(cut, cut * 2) },
          { name: "big.zip.003", data: zipBytes.slice(cut * 2) },
        ];
        const aloneRecognised = parts.map(p => detectFormat(p.data));
        const sets = joinVolumes(parts);
        const archive = await Archive.open(sets[0].data);
        const members = await archive.list();
        return {
          aloneRecognised,
          count: sets.length,
          name: sets[0].name,
          parts: sets[0].parts,
          incomplete: sets[0].incomplete,
          members: members.map(m => m.name),
        };
      })()
    `);
    // The fixture check: if a piece were openable on its own, this test would
    // pass without joinVolumes doing anything.
    expect(result.aloneRecognised.slice(1)).toEqual([undefined, undefined]);
    expect(result.count).toBe(1);
    expect(result.name).toBe('big.zip');
    expect(result.parts).toEqual(['big.zip.001', 'big.zip.002', 'big.zip.003']);
    expect(result.incomplete).toBeNull();
    expect(result.members).toEqual(['inside.txt']);
  });

  test('joinVolumes hands back a set it could not rejoin', async ({ page }) => {
    // Those bytes belong to an archive nothing can now read. Letting them vanish
    // is the failure this whole path exists to prevent.
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { joinVolumes } = window.__test;
        const enc = new TextEncoder();
        const sets = joinVolumes([
          { name: "gap.zip.001", data: enc.encode("AAA") },
          { name: "gap.zip.003", data: enc.encode("CCC") },
        ]);
        return sets.map(s => ({ name: s.name, incomplete: s.incomplete, len: s.data.length }));
      })()
    `);
    expect(result).toHaveLength(2);
    expect(result.every(s => typeof s.incomplete === 'string')).toBe(true);
    expect(result.every(s => s.len === 3)).toBe(true);
  });

  test('joinVolumes leaves ordinary files and lone parts alone', async ({ page }) => {
    // Plenty of ordinary files end in `.001`. One part is not a set, and the
    // caller already has the file.
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { joinVolumes } = window.__test;
        const enc = new TextEncoder();
        return joinVolumes([
          { name: "notes.txt", data: enc.encode("hello") },
          { name: "odd.dat.001", data: enc.encode("lone") },
          { name: "a.part1.rar", data: enc.encode("rar") },
        ]).length;
      })()
    `);
    expect(result).toBe(0);
  });

  // A decoder panic traps the module on this target — `panic = "abort"`, so
  // nothing in Rust catches it. The containment is in JS, and these are the
  // parts of it that can be exercised without a decoder that actually panics.

  test('an ordinary error is not treated as a decoder trap', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([{ name: "a.txt", data: "alpha" }]);
        const archive = await Archive.open(zipBytes);
        let message = "";
        try {
          await archive.extract(99);
        } catch (e) {
          message = String(e.message || e);
        }
        // The module must still be usable: an ordinary Err leaves the instance
        // healthy, and discarding it would throw away a working one on every
        // routine mistake.
        const entry = await archive.extract(0);
        const stillWorks = new TextDecoder().decode(entry.bytes);
        // And a freshly opened archive still works too.
        const second = await Archive.open(zipBytes);
        const secondWorks = (await second.list()).length;
        return { message, stillWorks, secondWorks };
      })()
    `);
    expect(result.message).not.toContain('trapped');
    expect(result.stillWorks).toBe('alpha');
    expect(result.secondWorks).toBe(1);
  });

  // Each of these fires a failure Rust cannot catch on this target, through a
  // member name the `testing-faults` build reserves. They need `npm run
  // build:e2e`; against a shipped build the member extracts normally and the
  // test reports that rather than passing vacuously.
  for (const [kind, member] of [
    ['a panic', '__exav_panic__'],
    ['an exhausted address space', '__exav_oom__'],
    ['an exhausted stack', '__exav_stack__'],
  ]) {
    test(`${kind} in a decoder costs the archive, not the page`, async ({ page }) => {
      await setupPage(page);
      const result = await page.evaluate(`
        (async () => {
          const { Archive } = window.__test;
          ${HELPERS}
          const bad = buildTinyZip([{ name: ${JSON.stringify(member)}, data: "boom" }]);
          const good = buildTinyZip([{ name: "fine.txt", data: "fine" }]);

          const archive = await Archive.open(bad);
          let failed = null;
          try {
            await archive.extract(0);
          } catch (e) {
            failed = String(e.message || e);
          }
          if (failed === null) return { skipped: true };

          // The page must still work: a fresh archive opens on a rebuilt
          // instance and extracts normally.
          const next = await Archive.open(good);
          const entry = await next.extract(0);
          return {
            skipped: false,
            failed,
            recovered: new TextDecoder().decode(entry.bytes),
          };
        })()
      `);
      if (result.skipped) {
        throw new Error(
          'built without the testing-faults feature — run `npm run build:e2e`',
        );
      }
      // Reported as a failure of this archive, not returned as an empty result.
      expect(result.failed).toContain('trapped');
      // And the next archive is unaffected.
      expect(result.recovered).toBe('fine');
    });
  }

  test('a trapped worker is replaced, and the stale archive says so', async ({ page }) => {
    await setupPage(page);
    const result = await page.evaluate(`
      (async () => {
        const { Archive } = window.__test;
        ${HELPERS}
        const zipBytes = buildTinyZip([{ name: "w.txt", data: "worker" }]);
        const file = new File([zipBytes], "w.zip");

        // Supplied through the public option, so the test holds the reference
        // and needs no hook into the module's internals.
        const worker = new Worker("/js/worker.js", { type: "module" });
        const archive = await Archive.open(file, undefined, { worker });
        const before = (await archive.list()).length;

        // Drive the failure path the way a real trap does: the worker reports
        // an error, and everything that referred to it is now stale.
        worker.dispatchEvent(new ErrorEvent("error", { message: "simulated trap" }));

        // The stale archive must SAY it is stale rather than post into a worker
        // that can never answer — an unsettled promise is worse than an error,
        // because nothing ever reports that the scan did not happen.
        let stale = "";
        try {
          await archive.list();
        } catch (e) {
          stale = String(e.message || e);
        }

        // A new archive gets a fresh worker with no action from the caller.
        const next = await Archive.open(new File([zipBytes], "w2.zip"));
        const after = (await next.list()).length;
        return { before, stale, after };
      })()
    `);
    expect(result.before).toBe(1);
    expect(result.stale).toContain('replaced');
    expect(result.after).toBe(1);
  });
});
