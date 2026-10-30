// The split archives `volumeSet` tells from names and `joinSet` joins, on the
// module as built (`wasm-pack build`): the RAR sets are the ones the official
// tool wrote, which exav-unpack's tests read too.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

// @ts-expect-error the facade is plain JS beside its own declarations
import init, { Archive, joinSet, volumeSet } from '../js/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const rar = path.join(here, '..', '..', 'exav-unpack', 'tests', 'fixtures', 'rar_volumes');
const read = (name: string) => new Uint8Array(fs.readFileSync(path.join(rar, name)));

beforeAll(async () => {
  await init({ module_or_path: fs.readFileSync(path.join(here, '..', 'pkg', 'exav_unpack_wasm_bg.wasm')) });
});

describe('the volumes of a set, from names', () => {
  it('are in volume order whichever the order of the names', () => {
    expect(volumeSet('big.7z.001', ['big.7z.003', 'big.7z.001', 'big.7z.002', 'note.txt'])).toEqual({
      parts: ['big.7z.001', 'big.7z.002', 'big.7z.003'],
      scheme: 'split',
      complete: true,
    });
    expect(volumeSet('a.part2.rar', ['a.part3.rar', 'a.part1.rar', 'a.part2.rar'])).toEqual({
      parts: ['a.part1.rar', 'a.part2.rar', 'a.part3.rar'],
      scheme: 'rar',
      complete: true,
    });
    // The bare .rar is the first, .r00 the second.
    expect(volumeSet('a.r01', ['a.r01', 'a.rar', 'a.r00'])?.parts).toEqual(['a.rar', 'a.r00', 'a.r01']);
  });

  it('end with the .zip for a ZIP spanned over files, from any of its parts', () => {
    for (const name of ['s.z01', 's.z02', 's.zip']) {
      expect(volumeSet(name, ['s.zip', 's.z02', 's.z01'])).toEqual({ parts: ['s.z01', 's.z02', 's.zip'], scheme: 'zip', complete: true });
    }
  });

  it('are incomplete with a volume missing, and a set only of those the names have', () => {
    expect(volumeSet('big.7z.001', ['big.7z.001', 'big.7z.003'])?.complete).toBe(false);
    expect(volumeSet('a.part1.rar', ['a.part1.rar', 'a.part2.rar'])?.complete).toBe(true);
    expect(volumeSet('a.part2.rar', ['a.part2.rar', 'a.part3.rar'])?.complete).toBe(false);
    // The central directory is in the last part.
    expect(volumeSet('s.z01', ['s.z01', 's.z02'])?.complete).toBe(false);
    expect(volumeSet('s.z01', ['s.z01', 's.z02', 's.zip'])?.complete).toBe(true);
    expect(volumeSet('s.z01', ['s.z01', 's.z03', 's.zip'])?.complete).toBe(false);
  });

  it('are not found for a file that is one on its own, or in another set of the same stem', () => {
    expect(volumeSet('a.rar', ['a.rar'])).toBeNull();
    expect(volumeSet('a.zip', ['a.zip'])).toBeNull();
    expect(volumeSet('notes.txt', ['notes.txt', 'notes.002'])).toBeNull();
    expect(volumeSet('a.part1.rar', ['a.part1.rar', 'a.7z.001', 'a.7z.002'])).toBeNull();
    expect(volumeSet('a.7z.001', ['a.7z.001', 'a.zip.002'])).toBeNull();
    // Case does not matter to the stem or the scheme.
    expect(volumeSet('A.PART1.RAR', ['A.PART1.RAR', 'a.part2.rar'])?.parts).toEqual(['A.PART1.RAR', 'a.part2.rar']);
  });

  it('are not found when two names claim a position', () => {
    expect(volumeSet('a.7z.001', ['a.7z.001', 'a.7z.01', 'a.7z.002'])?.complete ?? false).toBe(false);
  });
});

describe('a set joined', () => {
  it('is read whole by its decoder: a RAR member that continues in the next volume has its size and bytes', async () => {
    for (const names of [
      ['set5.part1.rar', 'set5.part2.rar', 'set5.part3.rar'],
      ['set4.rar', 'set4.r00', 'set4.r01'],
    ]) {
      const set = volumeSet(names[0]!, names)!;
      const parts = set.parts.map(read);
      const size = async (data: Uint8Array) => {
        const archive = await Archive.open(data);
        const noise = (await archive.list()).find((m: { name: string }) => m.name === 'noise.bin');
        return noise.uncompressedSize as number;
      };
      expect(await size(parts[0]!), 'the first volume on its own').toBe(-1);
      expect(await size(joinSet('rar', parts))).toBe(20000);
    }
  });

  it('is the parts end to end for a split, and a ZIP spanned over files read as one', async () => {
    const part = (n: number) => new Uint8Array([n]);
    expect([...joinSet('split', [part(1), part(2), part(3)])]).toEqual([1, 2, 3]);
    expect(() => joinSet('rar', [part(1), part(2)])).toThrow();
    expect(() => joinSet('lzh', [part(1)])).toThrow(/cannot be joined/);
    expect(() => joinSet('split', [1 as unknown as Uint8Array])).toThrow(/Uint8Array/);
  });
});
