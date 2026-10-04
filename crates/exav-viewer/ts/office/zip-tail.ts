/**
 * Office files are ZIPs, and some come with bytes after the end of the
 * central directory (a newline a tool appended, say). `unzip` and most
 * libraries read them; the Office engines' strict ZIP check refuses the file
 * ("ZIP central directory preflight failed"), and the deck or document never
 * draws. The tail is dropped here, and only when the end record is certain:
 * the last one whose central directory ends exactly where it begins. Any
 * other layout (ZIP64, a prefix, a damaged file) is returned as it came, for
 * the engine to judge.
 */
export function trimZipTail(bytes: Uint8Array): Uint8Array {
  const EOCD = 22;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // The record may be followed by a comment of up to 65535 bytes, and by junk.
  const lowest = Math.max(0, bytes.length - EOCD - 0xffff - 1024);
  for (let at = bytes.length - EOCD; at >= lowest; at--) {
    if (view.getUint32(at, true) !== 0x06054b50) continue;
    const centralSize = view.getUint32(at + 12, true);
    const centralOffset = view.getUint32(at + 16, true);
    const commentLength = view.getUint16(at + 20, true);
    if (centralOffset + centralSize !== at) continue;
    const end = at + EOCD + commentLength;
    if (end > bytes.length) continue;
    return end === bytes.length ? bytes : bytes.subarray(0, end);
  }
  return bytes;
}
