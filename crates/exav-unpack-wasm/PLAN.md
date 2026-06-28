# Plan: Fully Async Streaming API

## JS API — format-agnostic, no format-specific behavior anywhere

```typescript
class Archive {
  /**
   * Open from File or Uint8Array.
   * Internally selects the best strategy for the detected format.
   */
  static open(source: File | Uint8Array): Promise<Archive>;

  /** Detected format name. Sync. */
  format(): string;

  /** List members (async — may need I/O). */
  list(passwords?: string[]): Promise<MemberInfo[]>;

  /** Extract one member by index (async). */
  extract(index: number, passwords?: string[]): Promise<Entry>;

  /** Extract all members (async). */
  extractAll(passwords?: string[]): Promise<Entry[]>;
}

type MemberInfo = {
  name: string;
  index: number;
  compressedSize: number;
  uncompressedSize: number;  // -1 if unknown
  encrypted: boolean;
};

type Entry = {
  name: string;
  data: Uint8Array;
  encrypted: boolean;
  unsupported: string;  // empty on success
};
```

`unpack()` standalone export stays for backward compat, calls `Archive.open()` + `extractAll()` internally.

---

## Rust Implementation

### `exav-unpack` crate changes

Make 3 helper functions `pub(crate)` in `formats/zip.rs` so the WASM binding can reuse them:
- `read_encrypted_member()`
- `decrypt_zip_member()`  
- `compression_to_u16()`

### `exav-unpack-wasm/src/lib.rs`

The `Archive` struct holds either a File ref or a buffer. Each method detects format and dispatches:

- **ZIP from File**: `list()` fetches central directory, `extract()` fetches one member via `file.slice()`
- **ZIP from buffer**: uses existing `exav-unpack::extract()`
- **TAR**: `list()` scans 512-byte headers, `extractAll()` streams via `extract_each()`
- **gz/bz2/xz**: single synthetic member, `extract()` decompresses the stream
- **7z/RAR/CAB/ISO/CPIO/AR/XAR/OLE/PDF/Email/ARJ/LHA/DMG/UPX**: `list()` and `extractAll()` use existing `exav-unpack::extract()`, `extract()` indexes into results

All logic stays in the WASM binding crate. The `exav-unpack` crate gets no new public API — only visibility changes on 3 helpers.

---

## Demo

Uses only the public API. No format-specific code.

```js
const archive = await Archive.open(file);
const members = await archive.list();
// render table...
const entry = await archive.extract(idx, passwords);
```

---

## Files Changed

| File | Change |
|------|--------|
| `crates/exav-unpack/src/formats/zip.rs` | 3 functions → `pub(crate)` |
| `crates/exav-unpack-wasm/Cargo.toml` | Add `web-sys` dep |
| `crates/exav-unpack-wasm/src/lib.rs` | Full rewrite |
| `crates/exav-unpack-wasm/index.html` | Use async API |

## Implementation Order

1. Visibility changes in `exav-unpack`
2. Add `web-sys` to WASM crate Cargo.toml
3. Implement `Archive` struct
4. Implement format dispatch for `open()`, `list()`, `extract()`, `extractAll()`
5. Keep standalone `unpack()` export
6. Rebuild WASM
7. Update demo
8. Test with zip, encrypted.dmg, tar.gz
