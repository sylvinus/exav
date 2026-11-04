// Which listed members the library named itself (`synthetic`): the one member
// of a single-stream format, and nothing a container stored, whatever its name.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

import { beforeAll, describe, expect, it } from 'vitest';

// @ts-expect-error the facade is plain JS beside its own declarations
import init, { Archive } from '../js/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));

beforeAll(async () => {
  await init({ module_or_path: fs.readFileSync(path.join(here, '..', 'pkg', 'exav_unpack_wasm_bg.wasm')) });
});

/** A ustar archive of regular files. */
function tar(files: Record<string, string>): Uint8Array {
  const blocks: Buffer[] = [];
  for (const [name, text] of Object.entries(files)) {
    const body = Buffer.from(text);
    const header = Buffer.alloc(512);
    header.write(name, 0, 'latin1');
    header.write('0000644\0', 100, 'latin1');
    header.write('0000000\0', 108, 'latin1');
    header.write('0000000\0', 116, 'latin1');
    header.write(body.length.toString(8).padStart(11, '0') + '\0', 124, 'latin1');
    header.write('00000000000\0', 136, 'latin1');
    header.write('        ', 148, 'latin1');
    header.write('0', 156, 'latin1');
    header.write('ustar\0' + '00', 257, 'latin1');
    const sum = header.reduce((a, b) => a + b, 0);
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'latin1');
    blocks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return new Uint8Array(Buffer.concat(blocks));
}

const listed = async (bytes: Uint8Array) => {
  const archive = await Archive.open(bytes);
  try {
    return await archive.list();
  } finally {
    await archive.close();
  }
};

describe('a listed member the library named itself', () => {
  it('is the one member of a gzip stream', async () => {
    const members = await listed(new Uint8Array(zlib.gzipSync('hello gzip')));
    expect(members.map((m: { name: string; synthetic: boolean }) => [m.name, m.synthetic])).toEqual([['gzip-content', true]]);
  });

  it('is the one member of another single-stream format', async () => {
    const members = await listed(new Uint8Array(zlib.zstdCompressSync('hello zstd')));
    expect(members.map((m: { name: string; synthetic: boolean }) => [m.name, m.synthetic])).toEqual([['zstd-content', true]]);
  });

  it('is the stream, not the files of the tar inside it', async () => {
    const inner = tar({ 'docs/a.txt': 'a', 'b.txt': 'b' });
    const outer = await Archive.open(new Uint8Array(zlib.gzipSync(inner)));
    const only = (await outer.list())[0];
    expect([only.name, only.synthetic]).toEqual(['gzip-content', true]);
    const entry = await outer.extract(only.index);
    await outer.close();
    expect(Array.from(entry.bytes as Uint8Array)).toEqual(Array.from(inner));
    const members = await listed(entry.bytes);
    expect(members.map((m: { name: string; synthetic: boolean }) => [m.name, m.synthetic])).toEqual([
      ['docs/a.txt', false],
      ['b.txt', false],
    ]);
  });

  it('is not a member a container stored under the same name', async () => {
    const members = await listed(tar({ 'gzip-content': 'x' }));
    expect(members.map((m: { name: string; synthetic: boolean }) => [m.name, m.synthetic])).toEqual([['gzip-content', false]]);
  });
});
