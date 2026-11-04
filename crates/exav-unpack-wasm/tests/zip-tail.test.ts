// `zipTail` on the module as built (`wasm-pack build`): a ZIP's central
// directory from the last bytes of the file, as a reader by ranges gets it.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

// @ts-expect-error the facade is plain JS beside its own declarations
import init, { zipTail } from '../js/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));

beforeAll(async () => {
  await init({ module_or_path: fs.readFileSync(path.join(here, '..', 'pkg', 'exav_unpack_wasm_bg.wasm')) });
});

/** A ZIP of stored members whose data is `size` zero bytes each. */
function zip(members: [string, number][]): Uint8Array {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let at = 0;
  for (const [name, size] of members) {
    const n = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    // The CRC-32 of zero bytes is not checked here: the directory is all that is read.
    local.writeUInt32LE(size, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(n.length, 26);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt32LE(size, 20);
    cd.writeUInt32LE(size, 24);
    cd.writeUInt16LE(n.length, 28);
    cd.writeUInt32LE(at, 42);
    parts.push(local, n, Buffer.alloc(size));
    central.push(cd, n);
    at += 30 + n.length + size;
  }
  const dir = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(members.length, 8);
  end.writeUInt16LE(members.length, 10);
  end.writeUInt32LE(dir.length, 12);
  end.writeUInt32LE(at, 16);
  return new Uint8Array(Buffer.concat([...parts, dir, end]));
}

describe('zipTail', () => {
  it("gives the members' local headers from a tail that holds the directory", () => {
    const z = zip([['a', 10], ['b', 20]]);
    expect(zipTail(z, z.length)).toEqual({ headers: [0, 31 + 10] });
  });

  it('asks for the bytes before the tail when the directory starts there', () => {
    const z = zip([['a', 200_000], ['b', 1]]);
    const tail = z.subarray(z.length - 40);
    const first = zipTail(tail, z.length);
    expect(first).toHaveProperty('needs');
    const from = (first as { needs: number }).needs;
    expect(from).toBeLessThan(z.length - 40);
    expect(zipTail(z.subarray(from), z.length)).toEqual({ headers: [0, 31 + 200_000] });
  });

  it('is undefined for what is not a ZIP', () => {
    expect(zipTail(new Uint8Array(100), 100)).toBeUndefined();
  });
});
