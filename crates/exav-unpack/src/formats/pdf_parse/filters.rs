//! Pure PDF stream filter decoders (PDF 32000-1:2008 §7.4).
//!
//! Every decoder here is a total function over `&[u8]` — bounds-checked,
//! panic-free, and self-terminating. Each takes a `cap` (the per-member output
//! budget from `Budget::reserve`) and returns `(bytes, truncated)`: once more
//! than `cap` bytes would be produced it stops and flags `truncated`, so a
//! malformed or deliberately bombing stream can neither exhaust memory nor loop
//! forever. On malformed input a decoder returns whatever it managed to decode
//! rather than erroring — signatures can still match a partial result.
//!
//! These are the standard non-Flate PDF stream filters: ASCIIHexDecode,
//! ASCII85Decode, RunLengthDecode and LZWDecode. FlateDecode stays on the
//! bounded `flate2` reader in `pdf.rs`.

/// Append `bytes`, then enforce the output cap. Returns `true` if the cap was
/// exceeded (buffer left truncated to exactly `cap`), signalling the caller to
/// stop.
#[inline]
fn push_capped(out: &mut Vec<u8>, cap: u64) -> bool {
    if out.len() as u64 > cap {
        out.truncate(cap as usize);
        return true;
    }
    false
}

/// ASCIIHexDecode (§7.4.2): pairs of hexadecimal digits, whitespace ignored,
/// terminated by `>`. A trailing odd nibble is treated as the high nibble of a
/// final byte whose low nibble is 0. Non-hex, non-whitespace bytes are skipped
/// defensively.
pub(crate) fn ascii_hex_decode(data: &[u8], cap: u64) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut hi: Option<u8> = None;
    for &b in data {
        if b == b'>' {
            break;
        }
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            // whitespace and any other junk: ignore
            _ => continue,
        };
        match hi.take() {
            None => hi = Some(nibble),
            Some(h) => {
                out.push((h << 4) | nibble);
                if push_capped(&mut out, cap) {
                    return (out, true);
                }
            }
        }
    }
    if let Some(h) = hi {
        // odd trailing nibble -> low nibble assumed 0
        out.push(h << 4);
        if push_capped(&mut out, cap) {
            return (out, true);
        }
    }
    (out, false)
}

/// ASCII85Decode (§7.4.3): base-85 digits `!`..`u`, `z` shorthand for four zero
/// bytes, whitespace ignored, terminated by `~>`. A final partial group is
/// padded with `u` and truncated per spec. A leading `<~` (Adobe framing) is
/// tolerated. Group values that overflow 32 bits wrap rather than panic.
pub(crate) fn ascii85_decode(data: &[u8], cap: u64) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut group = [0u8; 5];
    let mut count = 0usize;
    let mut i = 0usize;
    // Skip an optional leading "<~" frame (Adobe), past any leading whitespace.
    // '<' itself falls inside the '!'..='u' digit range, so it must be stripped
    // here rather than relying on the digit match below.
    {
        let mut j = 0usize;
        while j < data.len() && matches!(data[j], b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0) {
            j += 1;
        }
        if j + 1 < data.len() && data[j] == b'<' && data[j + 1] == b'~' {
            i = j + 2;
        }
    }
    while i < data.len() {
        let b = data[i];
        i += 1;
        match b {
            // EOD is the two-byte marker "~>".
            b'~' if i < data.len() && data[i] == b'>' => break,
            b'~' => continue,
            b'z' if count == 0 => {
                out.extend_from_slice(&[0, 0, 0, 0]);
                if push_capped(&mut out, cap) {
                    return (out, true);
                }
            }
            b'!'..=b'u' => {
                group[count] = b - b'!';
                count += 1;
                if count == 5 {
                    let mut val = 0u32;
                    for &g in &group {
                        val = val.wrapping_mul(85).wrapping_add(g as u32);
                    }
                    out.extend_from_slice(&val.to_be_bytes());
                    count = 0;
                    if push_capped(&mut out, cap) {
                        return (out, true);
                    }
                }
            }
            // whitespace, the leading '<' of "<~", and any other byte: ignore
            _ => {}
        }
    }
    // Flush a final partial group (1 char is invalid and dropped per spec).
    if count >= 2 {
        for slot in group.iter_mut().skip(count) {
            *slot = 84; // 'u' - '!' — pad with the max digit
        }
        let mut val = 0u32;
        for &g in &group {
            val = val.wrapping_mul(85).wrapping_add(g as u32);
        }
        let bytes = val.to_be_bytes();
        out.extend_from_slice(&bytes[..count - 1]);
        if push_capped(&mut out, cap) {
            return (out, true);
        }
    }
    (out, false)
}

/// RunLengthDecode (§7.4.5): a length byte L drives each run —
/// `0..=127` copies the next `L + 1` literal bytes, `129..=255` repeats the
/// next byte `257 - L` times, and `128` is the end-of-data marker.
pub(crate) fn run_length_decode(data: &[u8], cap: u64) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let length = data[i];
        i += 1;
        if length == 128 {
            break; // EOD
        }
        if length < 128 {
            let n = length as usize + 1;
            for _ in 0..n {
                if i >= data.len() {
                    return (out, false);
                }
                out.push(data[i]);
                i += 1;
                if push_capped(&mut out, cap) {
                    return (out, true);
                }
            }
        } else {
            if i >= data.len() {
                break;
            }
            let b = data[i];
            i += 1;
            let n = 257 - length as usize; // 129 -> 128 … 255 -> 2
            for _ in 0..n {
                out.push(b);
                if push_capped(&mut out, cap) {
                    return (out, true);
                }
            }
        }
    }
    (out, false)
}

/// LZWDecode (§7.4.4): variable-width 9→12-bit LZW as used by PDF and TIFF,
/// MSB-first, with clear code 256 and EOD 257. `early_change` selects the
/// one-code-early width bump (PDF/TIFF default = true, i.e. `/EarlyChange 1`);
/// pass `false` for `/EarlyChange 0`. The dictionary is bounded to 4096 entries
/// and output to `cap`, so growth and length are both finite.
pub(crate) fn lzw_decode(data: &[u8], early_change: bool, cap: u64) -> (Vec<u8>, bool) {
    const CLEAR: u32 = 256;
    const EOD: u32 = 257;
    const MAX_ENTRIES: usize = 4096;
    let early: u32 = if early_change { 1 } else { 0 };

    let mut dict: Vec<Vec<u8>> = Vec::with_capacity(MAX_ENTRIES);
    fn reset(dict: &mut Vec<Vec<u8>>) {
        dict.clear();
        for i in 0..256u32 {
            dict.push(vec![i as u8]);
        }
        dict.push(Vec::new()); // 256 CLEAR (placeholder)
        dict.push(Vec::new()); // 257 EOD  (placeholder)
    }
    reset(&mut dict);

    let mut out = Vec::new();
    let mut code_width = 9u32;
    let mut prev: Option<u32> = None;

    let total_bits = data.len() * 8;
    let mut bitpos = 0usize;

    while bitpos + code_width as usize <= total_bits {
        // Read code_width bits, most-significant bit first.
        let mut code = 0u32;
        for _ in 0..code_width {
            let byte = data[bitpos >> 3];
            let bit = (byte >> (7 - (bitpos & 7))) & 1;
            code = (code << 1) | bit as u32;
            bitpos += 1;
        }

        if code == EOD {
            break;
        }
        if code == CLEAR {
            reset(&mut dict);
            code_width = 9;
            prev = None;
            continue;
        }

        let entry: Vec<u8> = if (code as usize) < dict.len() {
            dict[code as usize].clone()
        } else if code as usize == dict.len() {
            // KwKwK: code not yet in the table — reconstruct from prev.
            match prev {
                Some(p) if (p as usize) < dict.len() => {
                    let mut e = dict[p as usize].clone();
                    if let Some(&first) = e.first() {
                        e.push(first);
                    }
                    e
                }
                _ => break, // malformed
            }
        } else {
            break; // code out of range — malformed
        };

        out.extend_from_slice(&entry);
        if push_capped(&mut out, cap) {
            return (out, true);
        }

        // Add prev + first-byte-of-entry as the next dictionary entry.
        if let Some(p) = prev {
            if (p as usize) < dict.len() && dict.len() < MAX_ENTRIES {
                let mut new_entry = dict[p as usize].clone();
                new_entry.push(entry[0]);
                dict.push(new_entry);
            }
        }
        prev = Some(code);

        // Bump the code width in lockstep with the encoder. The decoder builds
        // the table one code behind the encoder, so it must widen one code
        // earlier (hence the `+ 1`) to read the next code at the right width.
        if code_width < 12 && dict.len() as u32 + 1 + early >= (1u32 << code_width) {
            code_width += 1;
        }
    }

    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: u64 = 1 << 20;

    #[test]
    fn ascii_hex_hello() {
        let (out, trunc) = ascii_hex_decode(b"48656C6C6F>", CAP);
        assert!(!trunc);
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn ascii_hex_whitespace_and_odd_nibble() {
        // "48 65 6C 6C 6F 7" — trailing single nibble 7 -> 0x70.
        let (out, _) = ascii_hex_decode(b"48 65\n6C\t6C 6F 7>", CAP);
        assert_eq!(out, b"Hello\x70");
    }

    #[test]
    fn ascii85_man() {
        // "9jqo^" is the canonical ASCII85 encoding of the 4 bytes "Man ".
        let (out, trunc) = ascii85_decode(b"9jqo^~>", CAP);
        assert!(!trunc);
        assert_eq!(out, b"Man ");
    }

    #[test]
    fn ascii85_z_and_leading_frame() {
        // Leading "<~", a `z` (four zero bytes), then "9jqo^" = "Man ".
        let (out, _) = ascii85_decode(b"<~z9jqo^~>", CAP);
        assert_eq!(out, b"\x00\x00\x00\x00Man ");
    }

    #[test]
    fn run_length_roundtrip_vector() {
        // Hand-built: literal run of 3 bytes "ABC", then 5 copies of 'Z',
        // then EOD.
        //   0x02, 'A','B','C'   (length 2 -> 3 literals)
        //   0xFC, 'Z'           (257-252 = 5 copies)
        //   0x80                (EOD)
        let stream = [0x02, b'A', b'B', b'C', 0xFC, b'Z', 0x80, b'X'];
        let (out, trunc) = run_length_decode(&stream, CAP);
        assert!(!trunc);
        assert_eq!(out, b"ABCZZZZZ");
    }

    // A minimal LZW encoder mirroring the decoder's early-change semantics, so
    // the roundtrip validates the decoder against an independent implementation.
    fn lzw_encode(data: &[u8], early_change: bool) -> Vec<u8> {
        use std::collections::HashMap;
        const CLEAR: u32 = 256;
        const EOD: u32 = 257;
        let early: u32 = if early_change { 1 } else { 0 };

        let mut out_bits: Vec<u8> = Vec::new();
        let mut acc: u32 = 0;
        let mut nbits: u32 = 0;
        let emit = |code: u32, width: u32, out: &mut Vec<u8>, acc: &mut u32, nbits: &mut u32| {
            *acc = (*acc << width) | code;
            *nbits += width;
            while *nbits >= 8 {
                *nbits -= 8;
                out.push((*acc >> *nbits) as u8);
            }
        };

        let mut table: HashMap<Vec<u8>, u32> = HashMap::new();
        let reset_table = |t: &mut HashMap<Vec<u8>, u32>| {
            t.clear();
            for i in 0..256u32 {
                t.insert(vec![i as u8], i);
            }
        };
        reset_table(&mut table);
        let mut next_code = 258u32;
        let mut code_width = 9u32;

        emit(CLEAR, code_width, &mut out_bits, &mut acc, &mut nbits);

        let mut w: Vec<u8> = Vec::new();
        for &c in data {
            let mut wc = w.clone();
            wc.push(c);
            if table.contains_key(&wc) {
                w = wc;
            } else {
                emit(table[&w], code_width, &mut out_bits, &mut acc, &mut nbits);
                if next_code < 4096 {
                    table.insert(wc, next_code);
                    next_code += 1;
                    if code_width < 12 && next_code + early >= (1u32 << code_width) {
                        code_width += 1;
                    }
                }
                w = vec![c];
            }
        }
        if !w.is_empty() {
            emit(table[&w], code_width, &mut out_bits, &mut acc, &mut nbits);
        }
        emit(EOD, code_width, &mut out_bits, &mut acc, &mut nbits);
        if nbits > 0 {
            out_bits.push((acc << (8 - nbits)) as u8);
        }
        out_bits
    }

    #[test]
    fn lzw_pdf_spec_vector() {
        // PDF 32000-1:2008 §7.4.4.2 example: "-----A---B" (EarlyChange 1)
        // encodes to 80 0B 60 50 22 0C 0C 85 01.
        let plain = b"-----A---B";
        let encoded = lzw_encode(plain, true);
        assert_eq!(
            encoded,
            vec![0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01],
            "encoder must match the PDF spec vector"
        );
        let (out, trunc) = lzw_decode(&encoded, true, CAP);
        assert!(!trunc);
        assert_eq!(out, plain);
    }

    #[test]
    fn lzw_roundtrip_long() {
        // Long, repetitive input forces the 9->10->11-bit width transitions.
        let mut plain = Vec::new();
        for i in 0..4000u32 {
            plain.push((i % 7) as u8);
            plain.push(b'A' + (i % 3) as u8);
        }
        for &early in &[true, false] {
            let encoded = lzw_encode(&plain, early);
            let (out, trunc) = lzw_decode(&encoded, early, CAP);
            assert!(!trunc, "early_change={early}");
            assert_eq!(out, plain, "early_change={early}");
        }
    }

    #[test]
    fn caps_are_enforced() {
        // RunLength that would expand to 128 bytes, capped at 10.
        let stream = [0x81, b'Q']; // 257-129 = 128 copies
        let (out, trunc) = run_length_decode(&stream, 10);
        assert!(trunc);
        assert_eq!(out.len(), 10);
    }
}
