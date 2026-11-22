// The holes of a sparse file in a disk image, bounded by `maxHoleBytes`, on
// the module as built (`wasm-pack build`). The image is exav-unpack's: an ext4
// volume whose `a-sparse.bin` is 48 MiB of holes between two lines of text,
// then `z-last.txt`.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

import { beforeAll, describe, expect, it } from 'vitest';

// @ts-expect-error the facade is plain JS beside its own declarations
import init, { Archive } from '../js/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const image = () =>
  new Uint8Array(
    zlib.gunzipSync(fs.readFileSync(path.join(here, '..', '..', 'exav-unpack', 'tests', 'fixtures', 'fs', 'ext4_sparse.img.gz'))),
  );

beforeAll(async () => {
  await init({ module_or_path: fs.readFileSync(path.join(here, '..', 'pkg', 'exav_unpack_wasm_bg.wasm')) });
});

type Entry = { name: string; bytes: Uint8Array; unsupported: string };

/** Every entry of the image. An entry is held whole, so the buffer limit
 * takes the 48 MiB. */
async function extracted(limits: object): Promise<Entry[]> {
  const archive = await Archive.open(image(), { maxBufferBytes: 64 * 1024 * 1024, ...limits });
  const all = await archive.extractAll();
  await archive.close();
  return all;
}

describe('maxHoleBytes', () => {
  it('takes the holes of a sparse file, which do not count in maxScannedBytes', async () => {
    const all = await extracted({ maxScannedBytes: 4 * 1024 * 1024 });
    const sparse = all.find((e) => e.name.endsWith('a-sparse.bin'));
    expect(sparse?.bytes.length).toBe(50_331_671);
    expect(sparse?.unsupported).toBe('');
    expect(all.some((e) => e.name.endsWith('z-last.txt'))).toBe(true);
  });

  it('stops the walk at the file whose holes pass it', async () => {
    const all = await extracted({ maxHoleBytes: 1024 * 1024 });
    expect(all.at(-1)?.unsupported).toContain('holes');
    expect(all.some((e) => e.name.endsWith('z-last.txt'))).toBe(false);
  });
});
