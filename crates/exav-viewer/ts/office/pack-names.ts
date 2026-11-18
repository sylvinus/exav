/**
 * ZIP member names as one byte array for `officeKinds` of exav_viewer_sniff.wasm:
 * each name's length as 4 bytes little endian, then its UTF-8 bytes. An array
 * of strings would take imports from the host that the module has no other
 * use for, and a separator is a byte a member name may hold.
 */
export function packNames(names: readonly string[]): Uint8Array<ArrayBuffer> {
  const encoder = new TextEncoder();
  const encoded = names.map((name) => encoder.encode(name));
  const out = new Uint8Array(encoded.reduce((n, e) => n + 4 + e.length, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const e of encoded) {
    view.setUint32(at, e.length, true);
    out.set(e, at + 4);
    at += 4 + e.length;
  }
  return out;
}
