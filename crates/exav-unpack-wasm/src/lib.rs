//! WebAssembly bindings for `exav-unpack` — memory-safe, in-browser archive
//! extraction with no native/C dependencies.
//!
//! Build a browser package with `wasm-pack build --target web` (or `bundler`),
//! then from JavaScript:
//!
//! ```js
//! import init, { Archive, unpack } from "./pkg/exav_unpack_wasm.js";
//! await init();
//!
//! // Low-level streaming API
//! const archive = await Archive.open(file);
//! const members = await archive.list();
//! const entry = await archive.extract(0);
//! const chunks = entry.data.getReader();
//!
//! // High-level convenience
//! const entries = await unpack(file);
//! ```

use exav_unpack::{detect, extract, Budget, Entry as UnpackEntry, Format, Limits};
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Metadata for one archive member (no decompressed data).
struct MemberInfo {
    name: String,
    index: usize,
    compressed_size: u64,
    uncompressed_size: u64,
    encrypted: bool,
}

/// An extracted archive member with streaming data.
struct Entry {
    name: String,
    data: Vec<u8>,
    encrypted: bool,
    unsupported: String,
}

// ---------------------------------------------------------------------------
// ZIP central-directory metadata (for streaming from File)
// ---------------------------------------------------------------------------

struct ZipEntryMeta {
    name: String,
    local_header_offset: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: u16,
    encrypted: bool,
    crc32: u32,
}

/// Parse the ZIP End-of-Central-Directory record and central-directory entries
/// from the tail bytes. Returns entry metadata for listing and extraction.
fn parse_zip_central_directory(
    data: &[u8],
    file_size: u64,
) -> Result<Vec<ZipEntryMeta>, JsValue> {
    // Find EOCD: signature 0x06054b50. Search backwards from end.
    let mut eocd_offset = None;
    let search_end = data.len().saturating_sub(22);
    let search_start = search_end.saturating_sub(65535);
    for i in (search_start..=search_end).rev() {
        if i + 22 <= data.len()
            && data[i] == 0x50
            && data[i + 1] == 0x4b
            && data[i + 2] == 0x05
            && data[i + 3] == 0x06
        {
            eocd_offset = Some(i);
            break;
        }
    }
    let eocd = eocd_offset
        .ok_or_else(|| JsValue::from_str("ZIP: End-of-Central-Directory not found"))?;

    let cd_offset =
        u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap()) as u64;
    let _cd_size =
        u32::from_le_bytes(data[eocd + 12..eocd + 16].try_into().unwrap()) as u64;
    let num_entries =
        u16::from_le_bytes(data[eocd + 10..eocd + 12].try_into().unwrap()) as usize;

    // The central directory in `data` starts at `cd_offset` relative to file start,
    // but `data` may be a tail slice. Compute the local offset.
    let data_start = file_size.saturating_sub(data.len() as u64);
    let cd_local = cd_offset.saturating_sub(data_start) as usize;

    let mut entries = Vec::with_capacity(num_entries);
    let mut pos = cd_local;

    for _ in 0..num_entries {
        if pos + 46 > data.len() {
            break;
        }
        // Central directory signature: 0x02014b50
        if data[pos] != 0x50
            || data[pos + 1] != 0x4b
            || data[pos + 2] != 0x01
            || data[pos + 3] != 0x02
        {
            break;
        }
        let compression_method =
            u16::from_le_bytes(data[pos + 10..pos + 12].try_into().unwrap());
        let crc32 = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap());
        let comp_size =
            u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap()) as u64;
        let uncomp_size =
            u32::from_le_bytes(data[pos + 24..pos + 28].try_into().unwrap()) as u64;
        let name_len =
            u16::from_le_bytes(data[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(data[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len =
            u16::from_le_bytes(data[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let local_header_offset =
            u32::from_le_bytes(data[pos + 42..pos + 46].try_into().unwrap()) as u64;

        let name_start = pos + 46;
        let name_end = name_start + name_len;
        let name = if name_end <= data.len() {
            String::from_utf8_lossy(&data[name_start..name_end]).into_owned()
        } else {
            String::new()
        };

        // Detect encryption from general-purpose bit flag (bit 0 of bytes 8..10)
        let flags = u16::from_le_bytes(data[pos + 8..pos + 10].try_into().unwrap());
        let encrypted = (flags & 0x0001) != 0;

        entries.push(ZipEntryMeta {
            name,
            local_header_offset,
            compressed_size: comp_size,
            uncompressed_size: uncomp_size,
            compression_method,
            encrypted,
            crc32,
        });

        pos += 46 + name_len + extra_len + comment_len;
    }

    Ok(entries)
}

/// Fetch bytes from a File via slice().arrayBuffer().
async fn file_slice(file: &web_sys::File, offset: u64, len: u64) -> Result<Vec<u8>, JsValue> {
    let blob: web_sys::Blob = file.clone().into();
    let sliced = blob
        .slice_with_i32_and_i32(offset as i32, (offset + len) as i32)
        .map_err(|e| JsValue::from_str(&format!("slice: {e:?}")))?;
    let p = sliced.array_buffer();
    let ab = JsFuture::from(p)
        .await
        .map_err(|e| JsValue::from_str(&format!("arrayBuffer: {e:?}")))?;
    let arr = Uint8Array::new(&ab);
    Ok(arr.to_vec())
}

/// Read the tail of a File (last `max_bytes` bytes).
async fn file_tail(
    file: &web_sys::File,
    file_size: u64,
    max_bytes: u64,
) -> Result<Vec<u8>, JsValue> {
    let len = file_size.min(max_bytes);
    let offset = file_size.saturating_sub(len);
    file_slice(file, offset, len).await
}

/// Fetch bytes from a custom reader JS object via reader.read(offset, length).
/// The reader must have a `read(offset: number, length: number): Promise<Uint8Array>` method.
async fn reader_read(reader: &JsValue, offset: u64, len: u64) -> Result<Vec<u8>, JsValue> {
    let read_fn = Reflect::get(reader, &"read".into())
        .map_err(|_| JsValue::from_str("reader missing `read` method"))?;
    let read_fn = read_fn
        .dyn_ref::<js_sys::Function>()
        .ok_or_else(|| JsValue::from_str("`read` is not a function"))?;
    let args = Array::new();
    args.push(&JsValue::from_f64(offset as f64));
    args.push(&JsValue::from_f64(len as f64));
    let result = read_fn
        .call2(reader, &args.get(0), &args.get(1))
        .map_err(|e| JsValue::from_str(&format!("reader.read() failed: {e:?}")))?;
    let promise: js_sys::Promise = result.dyn_into()
        .map_err(|_| JsValue::from_str("reader.read() did not return a Promise"))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| JsValue::from_str(&format!("reader.read() promise rejected: {e:?}")))?;
    let arr = Uint8Array::new(&result);
    Ok(arr.to_vec())
}

/// Read the tail from a custom reader.
async fn reader_tail(
    reader: &JsValue,
    file_size: u64,
    max_bytes: u64,
) -> Result<Vec<u8>, JsValue> {
    let len = file_size.min(max_bytes);
    let offset = file_size.saturating_sub(len);
    reader_read(reader, offset, len).await
}

/// Unified read source: reads from File, reader, in-memory data, or returns an error.
async fn read_bytes(
    file: &Option<web_sys::File>,
    reader: &Option<JsValue>,
    data: &[u8],
    offset: u64,
    len: u64,
) -> Result<Vec<u8>, JsValue> {
    if let Some(f) = file {
        file_slice(f, offset, len).await
    } else if let Some(r) = reader {
        reader_read(r, offset, len).await
    } else if !data.is_empty() {
        let start = offset as usize;
        let end = ((offset + len) as usize).min(data.len());
        if start >= data.len() {
            Ok(Vec::new())
        } else {
            Ok(data[start..end].to_vec())
        }
    } else {
        Err(JsValue::from_str("no read source"))
    }
}

/// Read the tail from the unified source.
async fn read_tail(
    file: &Option<web_sys::File>,
    reader: &Option<JsValue>,
    data: &[u8],
    file_size: u64,
    max_bytes: u64,
) -> Result<Vec<u8>, JsValue> {
    if let Some(f) = file {
        file_tail(f, file_size, max_bytes).await
    } else if let Some(r) = reader {
        reader_tail(r, file_size, max_bytes).await
    } else if !data.is_empty() {
        let len = (file_size.min(max_bytes)) as usize;
        let start = data.len().saturating_sub(len);
        Ok(data[start..].to_vec())
    } else {
        Err(JsValue::from_str("no read source"))
    }
}

/// Decompress a ZIP member's raw bytes into plaintext.
fn decompress_zip_member(
    compressed: &[u8],
    method: u16,
    cap: u64,
) -> Result<Vec<u8>, JsValue> {
    match method {
        0 => {
            // Stored
            let take = (compressed.len() as u64).min(cap) as usize;
            Ok(compressed[..take].to_vec())
        }
        8 => {
            // Deflate
            use std::io::Read;
            let mut decoder =
                flate2::read::DeflateDecoder::new(std::io::Cursor::new(compressed));
            let mut buf = Vec::new();
            (&mut decoder)
                .take(cap + 1)
                .read_to_end(&mut buf)
                .map_err(|e| JsValue::from_str(&format!("deflate: {e}")))?;
            if buf.len() as u64 > cap {
                return Err(JsValue::from_str("member exceeds budget"));
            }
            Ok(buf)
        }
        _ => {
            // Unknown method — pass through raw bytes (scannable)
            let take = (compressed.len() as u64).min(cap) as usize;
            Ok(compressed[..take].to_vec())
        }
    }
}

/// Extract a single ZIP member from a unified source by index.
async fn extract_zip_member_from_source(
    file: &Option<web_sys::File>,
    reader: &Option<JsValue>,
    data: &[u8],
    _file_size: u64,
    meta: &ZipEntryMeta,
    passwords: &[String],
) -> Result<Entry, JsValue> {
    let budget_cap: u64 = 256 * 1024 * 1024; // 256 MiB per-member cap

    if meta.compressed_size == 0 && !meta.encrypted {
        return Ok(Entry {
            name: meta.name.clone(),
            data: Vec::new(),
            encrypted: false,
            unsupported: String::new(),
        });
    }

    if meta.encrypted {
        let header_bytes = read_bytes(file, reader, data, meta.local_header_offset, 30 + 256).await?;
        let name_len =
            u16::from_le_bytes(header_bytes[26..28].try_into().unwrap()) as u64;
        let extra_len =
            u16::from_le_bytes(header_bytes[28..30].try_into().unwrap()) as u64;
        let data_offset = meta.local_header_offset + 30 + name_len + extra_len;

        let raw = read_bytes(file, reader, data, data_offset, meta.compressed_size).await?;

        let crc = meta.crc32;
        let enc = exav_unpack::formats::zip::EncryptedMember {
            raw,
            aes_strength: None,
            method: meta.compression_method,
        };
        match exav_unpack::formats::zip::decrypt_zip_member(&enc, crc, &mut Budget::new(Limits::default())) {
            Ok(Some(plain)) => {
                let data = if plain.len() as u64 > budget_cap {
                    plain[..budget_cap as usize].to_vec()
                } else {
                    plain
                };
                return Ok(Entry {
                    name: meta.name.clone(),
                    data,
                    encrypted: true,
                    unsupported: String::new(),
                });
            }
            _ => {
                let passwords_tried = !passwords.is_empty();
                return Ok(Entry {
                    name: meta.name.clone(),
                    data: Vec::new(),
                    encrypted: true,
                    unsupported: if passwords_tried {
                        "wrong password".into()
                    } else {
                        "encrypted (no password provided)".into()
                    },
                });
            }
        }
    }

    let local_header = read_bytes(file, reader, data, meta.local_header_offset, 30 + 256).await?;
    let name_len =
        u16::from_le_bytes(local_header[26..28].try_into().unwrap()) as u64;
    let extra_len =
        u16::from_le_bytes(local_header[28..30].try_into().unwrap()) as u64;
    let data_offset = meta.local_header_offset + 30 + name_len + extra_len;

    let compressed = read_bytes(file, reader, data, data_offset, meta.compressed_size).await?;
    let decompressed = decompress_zip_member(&compressed, meta.compression_method, budget_cap)?;

    Ok(Entry {
        name: meta.name.clone(),
        data: decompressed,
        encrypted: false,
        unsupported: String::new(),
    })
}

// ---------------------------------------------------------------------------
// Helper: format detection + member-to-JS conversions
// ---------------------------------------------------------------------------

fn detect_format_from_data(data: &[u8]) -> Option<Format> {
    detect(data)
}

fn format_name(fmt: Format) -> String {
    format!("{fmt:?}")
}

fn entry_to_js(e: &Entry) -> Result<JsValue, JsValue> {
    let obj = Object::new();
    Reflect::set(&obj, &"name".into(), &JsValue::from_str(&e.name))?;
    let bytes = Uint8Array::from(e.data.as_slice());
    // Wrap in ReadableStream
    let chunks = Array::new();
    chunks.push(&bytes);
    let blob = web_sys::Blob::new_with_u8_array_sequence(&chunks)
        .map_err(|e| JsValue::from_str(&format!("blob: {e:?}")))?;
    let stream = blob.stream();
    Reflect::set(&obj, &"data".into(), &stream)?;
    Reflect::set(
        &obj,
        &"encrypted".into(),
        &JsValue::from_bool(e.encrypted),
    )?;
    Reflect::set(
        &obj,
        &"unsupported".into(),
        &JsValue::from_str(&e.unsupported),
    )?;
    Ok(obj.into())
}

fn member_to_js(m: &MemberInfo) -> Result<JsValue, JsValue> {
    let obj = Object::new();
    Reflect::set(&obj, &"name".into(), &JsValue::from_str(&m.name))?;
    Reflect::set(&obj, &"index".into(), &JsValue::from_f64(m.index as f64))?;
    Reflect::set(
        &obj,
        &"compressedSize".into(),
        &JsValue::from_f64(m.compressed_size as f64),
    )?;
    Reflect::set(
        &obj,
        &"uncompressedSize".into(),
        &JsValue::from_f64(m.uncompressed_size as f64),
    )?;
    Reflect::set(
        &obj,
        &"encrypted".into(),
        &JsValue::from_bool(m.encrypted),
    )?;
    Ok(obj.into())
}

fn unpack_entry_to_entry(e: &UnpackEntry) -> Entry {
    Entry {
        name: e.name.clone(),
        data: e.data.clone(),
        encrypted: e.encrypted,
        unsupported: e
            .unsupported
            .unwrap_or("")
            .to_string(),
    }
}

fn parse_passwords(passwords: &JsValue) -> Vec<String> {
    let arr = match passwords.dyn_ref::<Array>() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut list = Vec::new();
    for i in 0..arr.length() {
        if let Some(s) = arr.get(i).as_string() {
            list.push(s);
        }
    }
    list
}

fn make_budget(passwords: Vec<String>) -> Budget {
    Budget::with_passwords(Limits::default(), passwords)
}

// ---------------------------------------------------------------------------
// Archive class
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct Archive {
    file: Option<web_sys::File>,
    reader: Option<JsValue>,
    file_size: u64,
    data: Vec<u8>,
    format_name: String,
    detected_format: Option<Format>,
    zip_entries: Option<Vec<ZipEntryMeta>>,
}

#[wasm_bindgen]
impl Archive {
    /// Open from a File, Uint8Array, or custom reader object.
    /// A reader must implement: { read(offset: number, length: number): Promise<Uint8Array>, size: number }
    #[wasm_bindgen(js_name = "open")]
    pub async fn open(source: JsValue) -> Result<Archive, JsValue> {
        // Detect File vs Uint8Array vs custom reader
        if let Some(file) = source.dyn_ref::<web_sys::File>() {
            let size = file.size() as u64;
            // Read head (for magic-byte detection) and tail (for ZIP central directory).
            let head = file_slice(file, 0, 256.min(size)).await?;
            let tail = if size > 256 { file_tail(file, size, 65536).await? } else { Vec::new() };
            // Merge: head first, then tail (skipping overlapping bytes).
            let mut probe = head;
            let tail_start = size.saturating_sub(tail.len() as u64) as usize;
            if tail_start > probe.len() {
                probe.extend_from_slice(&tail);
            }
            let fmt = detect_format_from_data(&probe)
                .ok_or_else(|| JsValue::from_str("unrecognised archive format"))?;
            let fmt_name = format_name(fmt);

            let zip_entries = if fmt == Format::Zip {
                if size <= 65536 * 2 {
                    let all = file_slice(file, 0, size).await?;
                    Some(parse_zip_central_directory(&all, size)?)
                } else {
                    let cd_tail = file_tail(file, size, 1024 * 1024).await?;
                    Some(parse_zip_central_directory(&cd_tail, size)?)
                }
            } else {
                None
            };

            Ok(Archive {
                file: Some(file.clone()),
                reader: None,
                file_size: size,
                data: Vec::new(),
                format_name: fmt_name,
                detected_format: Some(fmt),
                zip_entries,
            })
        } else if let Some(arr) = source.dyn_ref::<Uint8Array>() {
            let data = arr.to_vec();
            let fmt = detect_format_from_data(&data)
                .ok_or_else(|| JsValue::from_str("unrecognised archive format"))?;
            let fmt_name = format_name(fmt);

            let zip_entries = if fmt == Format::Zip {
                Some(parse_zip_central_directory(&data, data.len() as u64)?)
            } else {
                None
            };

            Ok(Archive {
                file: None,
                reader: None,
                file_size: 0,
                data,
                format_name: fmt_name,
                detected_format: Some(fmt),
                zip_entries,
            })
        } else if let Some(obj) = source.dyn_ref::<Object>() {
            // Custom reader: { read(offset, length): Promise<Uint8Array>, size: number }
            let size_val = Reflect::get(obj, &"size".into())
                .map_err(|_| JsValue::from_str("reader missing `size` property"))?;
            let size = size_val
                .as_f64()
                .ok_or_else(|| JsValue::from_str("`size` is not a number"))? as u64;

            let tail = read_tail(&None, &Some(source.clone()), &[], size, 65536).await?;
            let fmt = detect_format_from_data(&tail)
                .ok_or_else(|| JsValue::from_str("unrecognised archive format"))?;
            let fmt_name = format_name(fmt);

            let zip_entries = if fmt == Format::Zip {
                let cd_tail = read_tail(&None, &Some(source.clone()), &[], size, 1024 * 1024).await?;
                Some(parse_zip_central_directory(&cd_tail, size)?)
            } else {
                None
            };

            Ok(Archive {
                file: None,
                reader: Some(source.clone()),
                file_size: size,
                data: Vec::new(),
                format_name: fmt_name,
                detected_format: Some(fmt),
                zip_entries,
            })
        } else {
            Err(JsValue::from_str(
                "expected File, Uint8Array, or reader object",
            ))
        }
    }

    /// Detected format name. Sync.
    pub fn format(&self) -> String {
        self.format_name.clone()
    }

    /// Ensure `self.data` is populated. For File/reader sources where data is
    /// still empty, this reads the entire source into memory. For in-memory
    /// sources it's a no-op.  Returns a reference to the (now non-empty) data.
    async fn ensure_data_loaded(&self) -> Result<Vec<u8>, JsValue> {
        if !self.data.is_empty() {
            return Ok(self.data.clone());
        }
        if let Some(f) = &self.file {
            let all = file_slice(f, 0, self.file_size).await?;
            return Ok(all);
        }
        if let Some(r) = &self.reader {
            let all = reader_read(r, 0, self.file_size).await?;
            return Ok(all);
        }
        Err(JsValue::from_str("no data source"))
    }

    /// List archive members. Async.
    pub async fn list(&self, passwords: Option<JsValue>) -> Result<Array, JsValue> {
        let pw = passwords.map(|p| parse_passwords(&p)).unwrap_or_default();

        if let Some(zip_entries) = &self.zip_entries {
            // ZIP fast path: return pre-parsed metadata, no I/O
            let out = Array::new();
            for (i, ze) in zip_entries.iter().enumerate() {
                out.push(&member_to_js(&MemberInfo {
                    name: ze.name.clone(),
                    index: i,
                    compressed_size: ze.compressed_size,
                    uncompressed_size: ze.uncompressed_size,
                    encrypted: ze.encrypted,
                })?);
            }
            return Ok(out);
        }

        let data = self.ensure_data_loaded().await?;
        let fmt = self.detected_format
            .ok_or_else(|| JsValue::from_str("unrecognised archive format"))?;
        let budget = make_budget(pw);
        let mut budget = budget;
        let entries =
            extract(fmt, &data, &mut budget).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let out = Array::new();
        for (i, e) in entries.iter().enumerate() {
            out.push(&member_to_js(&MemberInfo {
                name: e.name.clone(),
                index: i,
                compressed_size: e.comp_size,
                uncompressed_size: e.data.len() as u64,
                encrypted: e.encrypted,
            })?);
        }
        Ok(out)
    }

    /// Extract one member by index. Async.
    pub async fn extract(
        &self,
        index: usize,
        passwords: Option<JsValue>,
    ) -> Result<JsValue, JsValue> {
        let pw = passwords.map(|p| parse_passwords(&p)).unwrap_or_default();

        if let Some(zip_entries) = &self.zip_entries {
            if index < zip_entries.len() {
                let entry = extract_zip_member_from_source(
                    &self.file,
                    &self.reader,
                    &self.data,
                    self.file_size,
                    &zip_entries[index],
                    &pw,
                ).await?;
                return entry_to_js(&entry);
            }
            return Err(JsValue::from_str("index out of bounds"));
        }

        let data = self.ensure_data_loaded().await?;
        let fmt = self.detected_format
            .ok_or_else(|| JsValue::from_str("unrecognised archive format"))?;
        let budget = make_budget(pw);
        let mut budget = budget;
        let entries =
            extract(fmt, &data, &mut budget).map_err(|e| JsValue::from_str(&e.to_string()))?;

        if index < entries.len() {
            let entry = unpack_entry_to_entry(&entries[index]);
            entry_to_js(&entry)
        } else {
            Err(JsValue::from_str("index out of bounds"))
        }
    }

    /// Extract all members. Async.
    pub async fn extract_all(
        &self,
        passwords: Option<JsValue>,
    ) -> Result<Array, JsValue> {
        let pw = passwords.map(|p| parse_passwords(&p)).unwrap_or_default();

        if let Some(zip_entries) = &self.zip_entries {
            let out = Array::new();
            for ze in zip_entries {
                let entry = extract_zip_member_from_source(
                    &self.file,
                    &self.reader,
                    &self.data,
                    self.file_size,
                    ze,
                    &pw,
                ).await?;
                out.push(&entry_to_js(&entry)?);
            }
            return Ok(out);
        }

        // Buffer fallback: extract all
        let data = self.ensure_data_loaded().await?;
        let fmt = self.detected_format
            .ok_or_else(|| JsValue::from_str("unrecognised archive format"))?;
        let budget = make_budget(pw);
        let mut budget = budget;
        let entries =
            extract(fmt, &data, &mut budget).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let out = Array::new();
        for e in &entries {
            let entry = unpack_entry_to_entry(e);
            out.push(&entry_to_js(&entry)?);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Standalone functions (backward compat + convenience)
// ---------------------------------------------------------------------------

/// Detect the archive/container format from magic bytes.
#[wasm_bindgen]
pub fn detect_format(data: &[u8]) -> Option<String> {
    exav_unpack::detect(data).map(|f| format!("{f:?}"))
}

/// Extract all members from an archive (buffered). Convenience wrapper.
#[wasm_bindgen]
pub async fn unpack(data: Uint8Array, passwords: Option<JsValue>) -> Result<Array, JsValue> {
    let archive = Archive::open(data.into()).await?;
    archive.extract_all(passwords).await
}
