//! VBA macro extraction for OLE2 Office documents.
//!
//! Office stores VBA project metadata and module source code compressed with
//! the run-length "compressed container" scheme described in the open
//! [MS-OVBA] specification (§2.4.1). Plain-text macro signatures cannot match
//! that compressed form, so this module decompresses the `dir` stream, walks
//! its records to find each module's stream and source offset, decompresses the
//! per-module source, and emits a single text artifact that mirrors the layout
//! widely used by macro signatures (`REM`-prefixed project/module headers
//! followed by the decompressed source). Everything here works from documented
//! record layouts; the source text is emitted verbatim.

/// Decompress an MS-OVBA "CompressedContainer" ([MS-OVBA] §2.4.1.1).
///
/// Returns `None` if the signature byte or a chunk header is invalid. On
/// truncated/corrupt input it returns whatever was decoded so far (malware
/// often ships deliberately damaged containers).
pub(crate) fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.first() != Some(&0x01) {
        return None;
    }
    let mut out = Vec::new();
    let mut pos = 1usize;
    while pos + 2 <= data.len() {
        let header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let size = (header & 0x0FFF) as usize; // CompressedChunkSize
        let signature = (header >> 12) & 0x07;
        let compressed = (header >> 15) & 0x01;
        if signature != 0b011 {
            // Not a valid chunk header; stop rather than misinterpret.
            return if out.is_empty() { None } else { Some(out) };
        }
        let chunk_data_len = size + 1; // bytes of chunk data following the header
        let chunk_end = (pos + chunk_data_len).min(data.len());
        let chunk_start = out.len();
        if compressed == 0 {
            // Raw chunk: copy up to 4096 verbatim bytes.
            let n = (chunk_end - pos).min(4096);
            out.extend_from_slice(&data[pos..pos + n]);
        } else {
            while pos < chunk_end {
                let flags = data[pos];
                pos += 1;
                for bit in 0..8 {
                    if pos >= chunk_end {
                        break;
                    }
                    if (flags >> bit) & 1 == 0 {
                        // Literal token.
                        out.push(data[pos]);
                        pos += 1;
                    } else {
                        // Copy token.
                        if pos + 2 > chunk_end {
                            return Some(out);
                        }
                        let token = u16::from_le_bytes([data[pos], data[pos + 1]]);
                        pos += 2;
                        let diff = out.len() - chunk_start;
                        let bits = copy_token_bits(diff);
                        let len_mask = 0xFFFFu16 >> bits;
                        let length = (token & len_mask) as usize + 3;
                        let offset = ((token & !len_mask) >> (16 - bits)) as usize + 1;
                        if offset > out.len() {
                            return Some(out);
                        }
                        let src = out.len() - offset;
                        // Copy byte-by-byte: ranges may overlap (RLE runs).
                        for j in 0..length {
                            let b = out[src + j];
                            out.push(b);
                        }
                    }
                }
            }
        }
        pos = chunk_end;
    }
    Some(out)
}

/// `BitCount = max(ceil(log2(difference)), 4)` ([MS-OVBA] §2.4.1.3.19.3).
fn copy_token_bits(difference: usize) -> u32 {
    let mut w = 0u32;
    while (1usize << w) < difference {
        w += 1;
    }
    w.max(4)
}

/// A module discovered in the `dir` stream.
struct Module {
    name: String,
    stream_name: String,
    text_offset: u32,
    is_class: bool,
    private: bool,
    cookie: u16,
    help_context: u32,
}

/// Parsed `dir`-stream contents needed to render the dump.
struct DirInfo {
    headers: Vec<String>, // project-level "REM ..." lines, in emission order
    modules: Vec<Module>,
}

fn read_u16(d: &[u8], p: usize) -> Option<u16> {
    d.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn read_u32(d: &[u8], p: usize) -> Option<u32> {
    d.get(p..p + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn read_str(d: &[u8], p: usize, n: usize) -> String {
    String::from_utf8_lossy(d.get(p..p + n).unwrap_or(&[])).into_owned()
}

/// Parse the decompressed `dir` stream ([MS-OVBA] §2.3.4.2). Best-effort: an
/// unrecognised record is skipped using its declared size so one malformed
/// field doesn't abort the whole walk.
fn parse_dir(d: &[u8]) -> DirInfo {
    let mut headers = Vec::new();
    let mut modules: Vec<Module> = Vec::new();
    let mut cur: Option<Module> = None;
    let mut p = 0usize;
    while p + 6 <= d.len() {
        let id = read_u16(d, p).unwrap();
        let size = read_u32(d, p + 2).unwrap() as usize;
        let body = p + 6;
        // Records whose 32-bit field after the id is NOT a plain size need
        // special handling; everything else advances by `size`.
        match id {
            0x0001 => {
                // PROJECTSYSKIND
                let k = read_u32(d, body).unwrap_or(0);
                let s = match k {
                    0 => "Windows 16 bit",
                    1 => "Windows 32 bit",
                    2 => "Macintosh",
                    3 => "Windows 64 bit",
                    _ => "Unknown",
                };
                headers.push(format!("REM PROJECTSYSKIND: {s}"));
                p = body + size;
            }
            0x0002 => {
                headers.push(format!(
                    "REM PROJECTLCID: 0x{:08x}",
                    read_u32(d, body).unwrap_or(0)
                ));
                p = body + size;
            }
            0x0014 => {
                headers.push(format!(
                    "REM PROJECTLCIDINVOKE: 0x{:08x}",
                    read_u32(d, body).unwrap_or(0)
                ));
                p = body + size;
            }
            0x0003 => {
                headers.push(format!(
                    "REM PROJECTCODEPAGE: 0x{:04x}",
                    read_u16(d, body).unwrap_or(0)
                ));
                p = body + size;
            }
            0x0004 => {
                // PROJECTNAME: size is the name length
                headers.push(format!("REM PROJECTNAME: {}", read_str(d, body, size)));
                p = body + size;
            }
            0x0005 => {
                // PROJECTDOCSTRING: DocString[size], Reserved(0x0040) u16,
                // SizeOfDocStringUnicode u32, DocStringUnicode[..]
                headers.push(format!("REM PROJECTDOCSTRING: {}", read_str(d, body, size)));
                let u_off = body + size + 2;
                let u_sz = read_u32(d, u_off).unwrap_or(0) as usize;
                headers.push(format!(
                    "REM PROJECTDOCSTRINGUNICODE: {}",
                    decode_utf16(d, u_off + 4, u_sz)
                ));
                p = u_off + 4 + u_sz;
            }
            0x0006 => {
                // PROJECTHELPFILEPATH: HelpFile1[size], Reserved(0x003D) u16,
                // SizeOfHelpFile2 u32, HelpFile2[..]
                headers.push(format!("REM PROJECTHELPFILEPATH: {}", read_str(d, body, size)));
                let h2_off = body + size + 2;
                let h2_sz = read_u32(d, h2_off).unwrap_or(0) as usize;
                headers.push(format!(
                    "REM PROJECTHELPFILEPATH2: {}",
                    read_str(d, h2_off + 4, h2_sz)
                ));
                p = h2_off + 4 + h2_sz;
            }
            0x0007 => {
                headers.push(format!(
                    "REM PROJECTHELPCONTEXT: 0x{:04x}",
                    read_u32(d, body).unwrap_or(0)
                ));
                p = body + size;
            }
            0x0008 => {
                headers.push(format!(
                    "REM PROJECTLIBFLAGS: 0x{:04x}",
                    read_u32(d, body).unwrap_or(0)
                ));
                p = body + size;
            }
            0x0009 => {
                // PROJECTVERSION: Reserved u32 (==4), VersionMajor u32,
                // VersionMinor u16 — the 32-bit field here is Reserved, not size.
                let major = read_u32(d, body).unwrap_or(0);
                let minor = read_u16(d, body + 4).unwrap_or(0);
                headers.push(format!("REM PROJECTVERSION: {major}.{minor}"));
                p = body + 6;
            }
            0x000F => {
                // PROJECTMODULES: Count u16
                headers.push(format!(
                    "REM PROJECTMODULES: {}",
                    read_u16(d, body).unwrap_or(0)
                ));
                p = body + size;
            }
            0x0013 => {
                // ProjectCookie
                headers.push(format!(
                    "REM PROJECTCOOKIE: 0x{:04x}",
                    read_u16(d, body).unwrap_or(0)
                ));
                p = body + size;
            }
            0x0019 => {
                // MODULENAME — begins a new module record group.
                if let Some(m) = cur.take() {
                    modules.push(m);
                }
                cur = Some(Module {
                    name: read_str(d, body, size),
                    stream_name: String::new(),
                    text_offset: 0,
                    is_class: false,
                    private: false,
                    cookie: 0,
                    help_context: 0,
                });
                p = body + size;
            }
            0x001A => {
                // MODULESTREAMNAME: StreamName[size], Reserved(0x0032) u16,
                // SizeOfStreamNameUnicode u32, StreamNameUnicode[..]
                if let Some(m) = cur.as_mut() {
                    m.stream_name = read_str(d, body, size);
                }
                let u_off = body + size + 2;
                let u_sz = read_u32(d, u_off).unwrap_or(0) as usize;
                p = u_off + 4 + u_sz;
            }
            0x001C => {
                // MODULEDOCSTRING: DocString[size], Reserved(0x0048) u16,
                // SizeOfDocStringUnicode u32, DocStringUnicode[..]
                let u_off = body + size + 2;
                let u_sz = read_u32(d, u_off).unwrap_or(0) as usize;
                p = u_off + 4 + u_sz;
            }
            0x0031 => {
                // MODULEOFFSET: TextOffset u32
                if let Some(m) = cur.as_mut() {
                    m.text_offset = read_u32(d, body).unwrap_or(0);
                }
                p = body + size;
            }
            0x001E => {
                if let Some(m) = cur.as_mut() {
                    m.help_context = read_u32(d, body).unwrap_or(0);
                }
                p = body + size;
            }
            0x002C => {
                if let Some(m) = cur.as_mut() {
                    m.cookie = read_u16(d, body).unwrap_or(0);
                }
                p = body + size;
            }
            0x0021 | 0x0022 => {
                // MODULETYPE: 0x0021 Procedural, 0x0022 Document/Class.
                // The 32-bit field is Reserved (0), not a size.
                if let Some(m) = cur.as_mut() {
                    m.is_class = id == 0x0022;
                }
                p = body;
            }
            0x0025 => {
                // MODULEREADONLY — Reserved u32 (0), no payload.
                p = body;
            }
            0x0028 => {
                // MODULEPRIVATE — Reserved u32 (0), no payload.
                if let Some(m) = cur.as_mut() {
                    m.private = true;
                }
                p = body;
            }
            0x002B => {
                // Module terminator — Reserved u32 (0).
                if let Some(m) = cur.take() {
                    modules.push(m);
                }
                p = body;
            }
            0x0010 => break, // PROJECTTERMINATOR
            _ => {
                // Unknown/uninteresting record: skip its declared size.
                p = body + size;
            }
        }
    }
    if let Some(m) = cur.take() {
        modules.push(m);
    }
    DirInfo { headers, modules }
}

fn decode_utf16(d: &[u8], p: usize, n: usize) -> String {
    let bytes = d.get(p..p + n).unwrap_or(&[]);
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// ASCII-lowercase VBA source EXCEPT inside double-quoted string literals.
/// ClamAV's macro dump lowercases code tokens (keywords/identifiers) but leaves
/// string-literal contents intact, so a signature can match a lowercased
/// identifier next to a case-sensitive string (e.g. `environ("WINDIR")`). A bare
/// `"` toggles in/out of a string; `""` (an escaped quote) toggles twice, which
/// keeps the state correct.
fn lowercase_vba_code(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len());
    let mut in_str = false;
    for &b in src {
        if b == b'"' {
            in_str = !in_str;
            out.push(b);
        } else if in_str {
            out.push(b);
        } else {
            out.push(b.to_ascii_lowercase());
        }
    }
    out
}

/// Build the macro-source artifacts from the OLE project's streams. Returns
/// `(dump, raw)`: `dump` is the `REM`-headed layout with code-lowercased source
/// (string literals preserved) that ClamAV `Doc.*` macro signatures match; `raw`
/// is the concatenated decompressed module source in ORIGINAL case, which
/// `Target:2` (OLE) signatures match (e.g. `Attribute VB_Name =`/`CreateObject`).
/// `None` if there is no VBA project.
pub(crate) fn build_artifacts(streams: &[(String, &[u8])]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Find the compressed `dir` stream (under a `VBA` storage).
    let (dir_parent, dir_raw) = streams.iter().find_map(|(path, data)| {
        let comps: Vec<&str> = path.split(['/', '\\']).filter(|s| !s.is_empty()).collect();
        if comps.last().map(|s| s.eq_ignore_ascii_case("dir")) == Some(true)
            && comps.len() >= 2
            && comps[comps.len() - 2].eq_ignore_ascii_case("vba")
        {
            let parent = comps[..comps.len() - 1].join("/");
            Some((parent, *data))
        } else {
            None
        }
    })?;

    let dir = decompress(dir_raw)?;
    let info = parse_dir(&dir);
    if info.modules.is_empty() {
        return None;
    }

    // Index streams by lowercased final component for module lookup.
    let find_stream = |stream_name: &str| -> Option<&[u8]> {
        let want = format!("{dir_parent}/{stream_name}");
        streams.iter().find_map(|(path, data)| {
            if path.eq_ignore_ascii_case(&want) {
                Some(*data)
            } else {
                // Fall back to matching on the final path component.
                let last = path.rsplit(['/', '\\']).next().unwrap_or("");
                if last.eq_ignore_ascii_case(stream_name) {
                    Some(*data)
                } else {
                    None
                }
            }
        })
    };

    let mut out = String::new();
    let mut raw = Vec::new();
    out.push_str("REM VBA project extracted from Microsoft Office document\n\n");
    for h in &info.headers {
        out.push_str(h);
        out.push('\n');
    }
    out.push_str("\n\n");

    for m in &info.modules {
        out.push_str(&format!("REM MODULENAME: {}\n", m.name));
        out.push_str(&format!("REM MODULENAMEUNICODE: {}\n", m.name));
        out.push_str(&format!("REM MODULESTREAMNAME: {}\n", m.stream_name));
        out.push_str(&format!("REM MODULESTREAMNAMEUNICODE: {}\n", m.stream_name));
        out.push_str("REM MODULEDOCSTRING: \n");
        out.push_str("REM MODULEDOCSTRINGUNICODE: \n");
        out.push_str(&format!("REM MODULEOFFSET: 0x{:08x}\n", m.text_offset));
        out.push_str(&format!("REM MODULEHELPCONTEXT: 0x{:08x}\n", m.help_context));
        out.push_str(&format!("REM MODULECOOKIE: 0x{:04x}\n", m.cookie));
        out.push_str(if m.is_class {
            "REM MODULETYPE: Class\n"
        } else {
            "REM MODULETYPE: Procedural\n"
        });
        if m.private {
            out.push_str("REM MODULEPRIVATE\n");
        }
        out.push_str("REM ##################################################\n");
        if let Some(stream) = find_stream(&m.stream_name) {
            let off = m.text_offset as usize;
            if let Some(src) = stream.get(off..).and_then(decompress) {
                // Dump: code-lowercased (string literals preserved) after the
                // uppercase REM headers, so a header+source logical sig matches in
                // one buffer. Raw: original case, for Target:2 OLE sigs.
                out.push_str(&String::from_utf8_lossy(&lowercase_vba_code(&src)));
                raw.extend_from_slice(&src);
                raw.push(b'\n');
            }
        }
        out.push('\n');
    }

    Some((out.into_bytes(), raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_token_bit_allocation() {
        assert_eq!(copy_token_bits(1), 4);
        assert_eq!(copy_token_bits(16), 4);
        assert_eq!(copy_token_bits(17), 5);
        assert_eq!(copy_token_bits(4096), 12);
    }

    #[test]
    fn decompress_rejects_bad_signature() {
        assert!(decompress(&[0x00, 0x01, 0x02]).is_none());
        assert!(decompress(&[]).is_none());
    }

    #[test]
    fn decompress_literal_only_chunk() {
        // SignatureByte 0x01, header for a compressed chunk holding the
        // literal bytes "abcd" (FlagByte 0x00 => 8 literals, but only 4 here).
        // ChunkData = FlagByte(0x00) + 'a','b','c','d' = 5 bytes.
        // CompressedChunkSize = data_len - 1 = 4; signature 0b011, flag 1.
        let header: u16 = 0b1011_0000_0000_0000 | 4;
        let mut buf = vec![0x01u8];
        buf.extend_from_slice(&header.to_le_bytes());
        buf.push(0x00); // flag byte: all literals
        buf.extend_from_slice(b"abcd");
        assert_eq!(decompress(&buf).unwrap(), b"abcd");
    }

    #[test]
    fn decompress_copy_token_run() {
        // Encode "aaaaaaaa" (8 a's): literal 'a', then a copy token of
        // length 7 offset 1. FlagByte bit0=0 (literal), bit1=1 (copy).
        // After the literal, difference=1 => BitCount=4, LengthMask=0x0FFF.
        // Length=7 => token length field = 4; Offset=1 => offset field = 0.
        // OffsetMask high bits, shift (16-4)=12. token = (0<<12)|4 = 4.
        let token: u16 = 4;
        let mut chunk = vec![0b0000_0010u8]; // flags: bit0 literal, bit1 copy
        chunk.push(b'a');
        chunk.extend_from_slice(&token.to_le_bytes());
        let header: u16 = 0b1011_0000_0000_0000 | (chunk.len() as u16 - 1);
        let mut buf = vec![0x01u8];
        buf.extend_from_slice(&header.to_le_bytes());
        buf.extend_from_slice(&chunk);
        assert_eq!(decompress(&buf).unwrap(), b"aaaaaaaa");
    }
}
