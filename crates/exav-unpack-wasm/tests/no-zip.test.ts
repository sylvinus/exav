// The facade over a build without the `zip` feature, whose module has no
// `zipTail`: it loads, and `zipTail` says why it cannot answer. A named import
// of an export the module lacks fails the whole facade when it is loaded.
import { expect, it, vi } from 'vitest';

vi.mock('../pkg/exav_unpack_wasm.js', () => ({
  default: async () => ({}),
  Archive: class {},
  unpack: () => [],
  detectFormat: () => 'gzip',
  joinVolumes: () => [],
  isVolumePart: () => false,
  volumeSet: () => null,
  joinSet: () => [],
}));

it('loads, and zipTail refuses with the reason', async () => {
  const facade = await import('../js/index.js');
  expect(facade.detectFormat(new Uint8Array())).toBe('gzip');
  expect(() => facade.zipTail(new Uint8Array(), 0)).toThrow('zipTail needs a build with the zip feature');
});
