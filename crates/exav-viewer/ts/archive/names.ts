/**
 * A member's name, made safe to offer as a download name. The archive wrote
 * it: it can hold a path, `..`, control characters or characters a file
 * system refuses. Only its last component is kept.
 */
export function safeFileName(name: string, fallback = "file"): string {
  const base = name.split(/[/\\]/).pop() ?? "";
  const cleaned = base
    // Control characters and what Windows refuses in a name.
    .replace(/[\u0000-\u001f\u007f<>:"|?*]/g, "_")
    .replace(/^[.\s]+|[.\s]+$/g, "")
    .slice(0, 200);
  return cleaned || fallback;
}

/** The name @exav/unpack-wasm gives the one member of a compressed stream: "gzip-content". */
export const STREAM_MEMBER = /^(gzip|bzip2|xz|zstd|lzip|lz4|lzw)-content$/;

/** A compressed file's name, and what it is called once decompressed. */
const SUFFIXES: [RegExp, string][] = [
  [/\.(tgz|taz|tbz2?|txz|tzst|tlz)$/i, ".tar"],
  [/\.(gz|bz2|xz|zst|lz|lz4|z)$/i, ""],
];

/**
 * What the one file in a compressed stream is called: the stream's own name
 * without its compression (`models.tar.gz` is `models.tar`, `x.tgz` is
 * `x.tar`), or `fallback` when the name does not end in one.
 */
export function decompressedName(name: string, fallback: string): string {
  const base = name.split(/[/\\]/).pop() ?? "";
  for (const [suffix, replacement] of SUFFIXES) {
    if (suffix.test(base)) {
      const plain = base.replace(suffix, replacement);
      if (plain) return plain;
    }
  }
  return fallback;
}

/** The folder part of a member's name, or "". */
export function folderOf(name: string): string {
  const i = name.lastIndexOf("/");
  return i > 0 ? name.slice(0, i) : "";
}
