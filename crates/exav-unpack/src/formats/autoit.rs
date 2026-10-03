//! Compiled AutoIt3 script extractor.
//!
//! AutoIt3 compiles a `.au3` script into a Windows executable; the compiled
//! script is embedded (usually a PE resource, often appended past the image) and
//! tagged with an `AU3!EA05` or `AU3!EA06` marker. Malware ships as compiled
//! AutoIt, so carving the embedded script back out lets the engine scan it.
//!
//! Implemented from the MIT-licensed **AutoIt-Ripper** reference
//! (<https://github.com/nazywam/AutoIt-Ripper>, MIT) and the public format.
//! After the marker, 16 bytes, then a run of `FILE` records: a 4-byte tag that
//! decrypts to `"FILE"`, subtype and name strings, sizes, a checksum, two
//! timestamps and the content, each field under its own key. A compressed
//! member is an `EA05`/`EA06` magic, a big-endian output size and an LZSS
//! bitstream. The two versions differ in:
//!
//! * **EA05** (older): a Mersenne-Twister keystream, byte strings, and a content
//!   key that adds the sum of the 16 bytes after the marker;
//! * **EA06** (newer): a floating-point PRNG keystream and UTF-16 strings.
//!
//! A compiled script (`>>>AUTOIT SCRIPT<<<`) is a token stream, turned back into
//! text in the form ClamAV writes it, so that the signatures written against
//! that form match (see [`decompile`]).
//!
//! Every read is bounds-checked, output grows dynamically (never pre-allocated
//! from an attacker size), and members are charged against the [`Budget`], so
//! hostile input can neither panic nor over-allocate.

use crate::*;

pub(crate) const MARKER_EA05: &[u8; 8] = b"AU3!EA05";
pub(crate) const MARKER_EA06: &[u8; 8] = b"AU3!EA06";

// AutoIt EA05 keystream seeds / XOR keys (format constants).
const KEY_FILE_TAG: u32 = 0x16FA; // decrypts the 4-byte record tag to "FILE"
const KEY_SUBTYPE_LEN: u32 = 0x29BC;
const KEY_SUBTYPE_DATA: u32 = 0xA25E;
const KEY_NAME_LEN: u32 = 0x29AC;
const KEY_NAME_DATA: u32 = 0xF25E;
const KEY_SIZE: u32 = 0x45AA;
#[cfg(test)]
const KEY_CRC: u32 = 0xC3D2;
const KEY_CONTENT: u32 = 0x22AF;

#[derive(Clone, Copy)]
enum Cipher {
    Mt,
    Lame,
}

/// What differs between the two versions of the record stream.
struct Version {
    cipher: Cipher,
    /// Strings are UTF-16, their length counted in characters.
    unicode: bool,
    /// The content key adds the sum of the 16 bytes after the marker.
    checksum: bool,
    file_tag: u32,
    subtype: (u32, u32),
    name: (u32, u32),
    size: u32,
    content: u32,
}

const EA05: Version = Version {
    cipher: Cipher::Mt,
    unicode: false,
    checksum: true,
    file_tag: KEY_FILE_TAG,
    subtype: (KEY_SUBTYPE_LEN, KEY_SUBTYPE_DATA),
    name: (KEY_NAME_LEN, KEY_NAME_DATA),
    size: KEY_SIZE,
    content: KEY_CONTENT,
};

const EA06: Version = Version {
    cipher: Cipher::Lame,
    unicode: true,
    checksum: false,
    file_tag: 0x18EE,
    subtype: (0xADBC, 0xB33F),
    name: (0xF820, 0xF479),
    size: 0x87BC,
    content: 0x2477,
};

pub(crate) fn is_autoit(p: &crate::Probe) -> bool {
    p.find(MARKER_EA05).is_some() || p.find(MARKER_EA06).is_some()
}

fn find_marker(data: &[u8], needle: &[u8; 8]) -> Option<usize> {
    memchr::memmem::find(data, needle)
}

#[inline]
fn le32(d: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?))
}
#[inline]
fn be32(d: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(p..p + 4)?.try_into().ok()?))
}

pub(crate) fn extract_autoit<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if let Some(off) = find_marker(data, MARKER_EA05) {
        return records(&data[off + 8..], &EA05, budget, visit);
    }
    if let Some(off) = find_marker(data, MARKER_EA06) {
        return records(&data[off + 8..], &EA06, budget, visit);
    }
    Ok(None)
}

/// Decode the record stream (`body` starts just past the marker).
fn records<R>(
    body: &[u8],
    v: &Version,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if body.len() < 16 {
        return Ok(None);
    }
    let checksum: u32 = if v.checksum {
        body[..16]
            .iter()
            .fold(0u32, |a, &b| a.wrapping_add(b as u32))
    } else {
        0
    };

    let mut pos = 16usize;
    let mut emitted = 0u32;
    while let Some(tag_enc) = body.get(pos..pos + 4) {
        let mut tag = tag_enc.to_vec();
        xor(&mut tag, v.file_tag, v.cipher);
        if tag != b"FILE" {
            break;
        }
        pos += 4;

        // The subtype says what the member is; the name is only skipped.
        let Some(subtype) = read_string(body, &mut pos, v, v.subtype) else {
            break;
        };
        if read_string(body, &mut pos, v, v.name).is_none() {
            break;
        }

        // Compressed flag (u8), compressed size, uncompressed size and checksum
        // (each XOR-keyed), then two 8-byte timestamps. The checksum is not
        // verified: a wrong one must not stop the content being scanned.
        let Some(&comp) = body.get(pos) else { break };
        pos += 1;
        let Some(csize_raw) = le32(body, pos) else {
            break;
        };
        let csize = (csize_raw ^ v.size) as usize;
        pos += 12 + 16;
        if (csize as i32) < 0 {
            break;
        }

        let Some(enc) = pos.checked_add(csize).and_then(|end| body.get(pos..end)) else {
            break;
        };
        pos += csize;
        let mut content = enc.to_vec();
        xor(&mut content, checksum.wrapping_add(v.content), v.cipher);

        let cap = budget.reserve()?;
        let (content, complete) = if comp == 1 {
            match decompress(&content, cap as usize) {
                Some(v) => v,
                None => continue,
            }
        } else {
            (content, true)
        };
        let (out, mut unsupported) = match subtype.as_str() {
            ">>>AUTOIT SCRIPT<<<" => match decompile(&content, cap as usize) {
                Ok(text) => (text, None),
                // Not a token stream at all: the plain script older compilers
                // stored under this subtype.
                Err(None) => (content, None),
                Err(Some(text)) => (
                    text,
                    Some(
                        "AutoIt script token stream is malformed; the lines before it were scanned",
                    ),
                ),
            },
            ">AUTOIT UNICODE SCRIPT<" => (utf16le(&content).into_bytes(), None),
            _ => (content, None),
        };
        if !complete {
            unsupported = Some("AutoIt member ends early; the part decoded was scanned");
        }
        if out.len() < 4 {
            continue;
        }
        if out.len() as u64 > cap {
            return Err(LimitHit::new("autoit member exceeds budget".to_string()));
        }

        budget.count_entry()?;
        budget.commit(out.len() as u64);
        let name = if subtype.contains("SCRIPT") || emitted == 0 {
            "autoit-script.au3".to_string()
        } else {
            format!("autoit-{:03}.au3", emitted + 1)
        };
        emitted += 1;
        let mut e = Entry::new(name, out);
        e.unsupported = unsupported;
        if let Some(r) = visit(e, budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// Read an XOR-keyed length, then that many encrypted characters (keyed by the
/// length plus `keys.1`), advancing `pos`.
fn read_string(body: &[u8], pos: &mut usize, v: &Version, keys: (u32, u32)) -> Option<String> {
    let chars = le32(body, *pos)? ^ keys.0;
    *pos += 4;
    if (chars as i32) < 0 {
        return None;
    }
    let len = if v.unicode {
        chars as usize * 2
    } else {
        chars as usize
    };
    let mut bytes = body.get(*pos..pos.checked_add(len)?)?.to_vec();
    *pos += len;
    xor(&mut bytes, chars.wrapping_add(keys.1), v.cipher);
    Some(if v.unicode {
        utf16le(&bytes)
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

fn utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// XOR `buf` in place with the version's keystream seeded by `seed`.
fn xor(buf: &mut [u8], seed: u32, cipher: Cipher) {
    match cipher {
        Cipher::Mt => mt_xor(buf, seed),
        Cipher::Lame => {
            let mut prng = Lame::new(seed);
            for b in buf.iter_mut() {
                *b ^= prng.next_byte();
            }
        }
    }
}

// --- AutoIt EA06 keystream (from AutoIt-Ripper lame.py, MIT) -----------------

/// A lagged-Fibonacci generator whose output is read through a double in
/// [0, 1), then scaled to a byte.
struct Lame {
    c0: usize,
    c1: usize,
    grp: [u32; 17],
}

impl Lame {
    fn new(mut seed: u32) -> Self {
        let mut grp = [0u32; 17];
        for g in grp.iter_mut() {
            seed = 1u32.wrapping_sub(seed.wrapping_mul(0x53A9_B4FB));
            *g = seed;
        }
        let mut l = Lame { c0: 0, c1: 10, grp };
        for _ in 0..9 {
            l.step();
        }
        l
    }

    fn step(&mut self) -> f64 {
        let r = self.grp[self.c0]
            .rotate_left(9)
            .wrapping_add(self.grp[self.c1].rotate_left(13));
        self.grp[self.c0] = r;
        self.c0 = if self.c0 == 0 { 16 } else { self.c0 - 1 };
        self.c1 = if self.c1 == 0 { 16 } else { self.c1 - 1 };
        let bits = (((r >> 12) | 0x3FF0_0000) as u64) << 32 | (r << 20) as u64;
        f64::from_bits(bits) - 1.0
    }

    fn next_byte(&mut self) -> u8 {
        self.step();
        (self.step() * 256.0) as u8
    }
}

// --- AutoIt Mersenne-Twister keystream (from AutoIt-Ripper mt.py, MIT) --------

/// XOR `buf` in place with AutoIt's MT keystream seeded by `seed` (symmetric).
fn mt_xor(buf: &mut [u8], seed: u32) {
    let mut mt = Mt::new(seed);
    for b in buf.iter_mut() {
        *b ^= mt.next_byte();
    }
}

struct Mt {
    state: [u32; 624],
    i: usize,
}

impl Mt {
    fn new(seed: u32) -> Self {
        let mut state = [0u32; 624];
        state[0] = seed;
        for i in 1..624 {
            let last = state[i - 1];
            state[i] = (i as u32).wrapping_add(0x6C07_8965u32.wrapping_mul(last ^ (last >> 30)));
        }
        Mt { state, i: 0 }
    }

    fn twist(&mut self) {
        let s = &mut self.state;
        for i in 0..227 {
            let mut v = s[i + 397];
            v ^= (s[i] ^ ((s[i + 1] ^ s[i]) & 0x7FFF_FFFE)) >> 1;
            if s[i + 1] & 1 != 0 {
                v ^= 0x9908_B0DF;
            }
            s[i] = v;
        }
        for i in 0..396 {
            let mut v = s[i];
            v ^= (s[i + 227] ^ ((s[i + 228] ^ s[i + 227]) & 0x7FFF_FFFE)) >> 1;
            if s[i + 228] & 1 != 0 {
                v ^= 0x9908_B0DF;
            }
            s[227 + i] = v;
        }
        let mut v = s[396];
        v ^= (s[623] ^ ((s[0] ^ s[623]) & 0x7FFF_FFFE)) >> 1;
        if s[0] & 1 != 0 {
            v ^= 0x9908_B0DF;
        }
        s[623] = v;
    }

    fn next_byte(&mut self) -> u8 {
        if self.i.is_multiple_of(624) {
            self.twist();
        }
        let mut r = self.state[self.i % 624];
        self.i += 1;
        r = ((((r >> 11) ^ r) & 0xFF3A_58AD) << 7) ^ (r >> 11) ^ r;
        r = (((r & 0xFFFF_DF8C) << 15) ^ r ^ ((((r & 0xFFFF_DF8C) << 15) ^ r) >> 18)) >> 1;
        (r & 0xFF) as u8
    }
}

// --- LZSS decompressor (from AutoIt-Ripper decompress.py, MIT) ----------------

/// MSB-first bit reader over a byte slice.
struct Bits<'a> {
    data: &'a [u8],
    bit: usize,
    err: bool,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Bits {
            data,
            bit: 0,
            err: false,
        }
    }
    fn get(&mut self, n: u32) -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = self.bit / 8;
            if byte >= self.data.len() {
                self.err = true;
                return 0;
            }
            let b = (self.data[byte] >> (7 - (self.bit % 8))) & 1;
            v = (v << 1) | b as u32;
            self.bit += 1;
        }
        v
    }
}

/// Read a match length via the variable-length ladder (min 3).
fn read_match_len(bits: &mut Bits) -> usize {
    // (base, bits, sentinel)
    const LADDER: &[(usize, u32, u32)] = &[
        (3, 2, 0b11),
        (6, 3, 0b111),
        (13, 5, 0b11111),
        (44, 8, 255),
        (299, 8, 255),
    ];
    let mut base = 3usize;
    let mut nbits = 2u32;
    let mut sentinel = 0b11u32;
    for &(b, nb, s) in LADDER {
        base = b;
        nbits = nb;
        sentinel = s;
        let add = bits.get(nb);
        if add != s {
            return base + add as usize;
        }
    }
    // Past the ladder: keep adding the last sentinel.
    let mut total = base;
    loop {
        total += sentinel as usize;
        let add = bits.get(nbits);
        if add != sentinel {
            return total + add as usize;
        }
    }
}

/// Decompress an `EA05`/`EA06` magic + big-endian size + LZSS bitstream,
/// bounded by `cap`. The magic sets the flag bit that marks a literal. The
/// flag is false when the stream ended before the size it declares.
fn decompress(content: &[u8], cap: usize) -> Option<(Vec<u8>, bool)> {
    let literal = match content.get(0..4)? {
        b"EA05" => 0,
        b"EA06" => 1,
        _ => return None,
    };
    let mut want = be32(content, 4)? as usize;
    if want == 0 {
        want = content.len();
    }
    let want = want.min(cap.saturating_add(1));

    let mut bits = Bits::new(&content[8..]);
    let mut out: Vec<u8> = Vec::new();
    while !bits.err && out.len() < want {
        if bits.get(1) == literal {
            let b = bits.get(8) as u8;
            if bits.err {
                break;
            }
            out.push(b);
        } else {
            let offset = bits.get(15) as usize;
            let len = read_match_len(&mut bits);
            if bits.err || offset == 0 || offset > out.len() || out.len() + len > want {
                break;
            }
            for _ in 0..len {
                let b = out[out.len() - offset];
                out.push(b);
            }
        }
    }
    let complete = out.len() >= want;
    Some((out, complete))
}

// --- Token stream to script text (token layout from AutoIt-Ripper, MIT) ------

/// Rebuild the text of a compiled script from its token stream, one line per
/// `0x7F` token, in the form ClamAV writes it, which is the form signatures
/// are written against. Observed on ClamAV's own output, byte for byte over
/// 38,000 lines of corpus scripts plus a crafted one for the rarer tokens:
///
/// * each token is followed by a space, except a user function's name, which
///   runs into the `(` after it; lines end with LF, and nothing is indented;
/// * keywords and built-in functions named by index are upper-cased; names
///   stored as text are written as stored;
/// * a 32-bit integer is `0x%08x`; a 64-bit one is its high word shifted up
///   plus its low word sign-extended, as `0x%016x`; a float is C's `%g`;
/// * a string is quoted without escaping, and each UTF-16 unit is written as
///   its low byte.
///
/// `Err(None)` when not even one line decodes, which is content that is not a
/// token stream; `Err(Some(text))` holds the lines before a malformed token.
/// Stops once past `cap` bytes; the caller reports that as a limit.
fn decompile(tokens: &[u8], cap: usize) -> Result<Vec<u8>, Option<Vec<u8>>> {
    use super::autoit_data::{FUNCTIONS, KEYWORDS};
    let fail = |out: Vec<u8>| Err(Some(out).filter(|o| !o.is_empty()));
    let mut t = Tokens { d: tokens, pos: 0 };
    let mut out = Vec::new();
    let Some(lines) = t.u32() else {
        return fail(out);
    };
    let mut line = 0u32;
    while line < lines && out.len() <= cap {
        let Some(op) = t.u8() else {
            return fail(out);
        };
        let ok = match op {
            0x7F => {
                line += 1;
                out.push(b'\n');
                continue;
            }
            0x00 | 0x01 => {
                let table: &[&str] = if op == 0 { &KEYWORDS } else { &FUNCTIONS };
                t.i32()
                    .and_then(|i| table.get(usize::try_from(i).ok()?))
                    .map(|name| out.extend(name.bytes().map(|b| b.to_ascii_uppercase())))
            }
            0x05 => t
                .u32()
                .map(|n| out.extend_from_slice(format!("0x{n:08x}").as_bytes())),
            0x10 => t.u64().map(|n| {
                let v = (n & !0xFFFF_FFFF).wrapping_add(n as u32 as i32 as i64 as u64);
                out.extend_from_slice(format!("0x{v:016x}").as_bytes());
            }),
            0x20 => t
                .f64()
                .map(|f| out.extend_from_slice(c_float_g(f).as_bytes())),
            0x30..=0x37 => {
                let prefix: &[u8] = match op {
                    0x32 => b"@",
                    0x33 => b"$",
                    0x35 => b".",
                    0x36 => b"\"",
                    _ => b"",
                };
                out.extend_from_slice(prefix);
                let ok = t.string(&mut out);
                if op == 0x36 {
                    out.push(b'"');
                }
                // A user function's name runs into its `(`.
                if op == 0x34 {
                    if ok.is_none() {
                        return fail(out);
                    }
                    continue;
                }
                ok
            }
            0x40..=0x58 => {
                out.extend_from_slice(OPERATORS[(op - 0x40) as usize].as_bytes());
                Some(())
            }
            _ => None,
        };
        if ok.is_none() {
            return fail(out);
        }
        out.push(b' ');
    }
    Ok(out)
}

const OPERATORS: [&str; 25] = [
    ",", "=", ">", "<", "<>", ">=", "<=", "(", ")", "+", "-", "/", "*", "&", "[", "]", "==", "^",
    "+=", "-=", "/=", "*=", "&=", "?", ":",
];

/// `f` as C's `printf("%g")` writes it: six significant digits, trailing zeros
/// dropped, exponent form below 1e-4 and from 1e6 with a signed exponent of at
/// least two digits.
fn c_float_g(f: f64) -> String {
    if !f.is_finite() {
        return match (f.is_nan(), f.is_sign_negative()) {
            (true, _) => "nan",
            (false, true) => "-inf",
            (false, false) => "inf",
        }
        .to_string();
    }
    let trim = |s: String| {
        if s.contains('.') {
            s.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            s
        }
    };
    // The exponent after rounding to six digits decides the form.
    let sci = format!("{f:.5e}");
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    if (-4..6).contains(&exp) {
        trim(format!("{f:.*}", (5 - exp) as usize))
    } else {
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{}e{sign}{:02}", trim(mantissa.to_string()), exp.abs())
    }
}

struct Tokens<'a> {
    d: &'a [u8],
    pos: usize,
}

impl Tokens<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let b = self.d.get(self.pos..self.pos.checked_add(N)?)?;
        self.pos += N;
        b.try_into().ok()
    }
    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|b| b[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_le_bytes)
    }
    fn i32(&mut self) -> Option<i32> {
        self.take().map(i32::from_le_bytes)
    }
    fn u64(&mut self) -> Option<u64> {
        self.take().map(u64::from_le_bytes)
    }
    fn f64(&mut self) -> Option<f64> {
        self.take().map(f64::from_le_bytes)
    }

    /// A length in characters, then that many UTF-16 units XOR-keyed by it;
    /// the low byte of each is appended to `out`.
    fn string(&mut self, out: &mut Vec<u8>) -> Option<()> {
        let key = self.u32()?;
        let len = (key as usize).checked_mul(2)?;
        let raw = self.d.get(self.pos..self.pos.checked_add(len)?)?;
        self.pos += len;
        out.extend(raw.as_chunks::<2>().0.iter().map(|c| c[0] ^ key as u8));
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_autoit(data: &[u8]) -> bool {
        super::is_autoit(&crate::Probe::whole(data))
    }

    /// MT is symmetric, so encrypting == decrypting.
    fn mt_apply(plain: &[u8], seed: u32) -> Vec<u8> {
        let mut v = plain.to_vec();
        mt_xor(&mut v, seed);
        v
    }

    /// Build an EA05 blob with one stored (uncompressed) FILE record, per the
    /// AutoIt-Ripper layout (16-byte checksum region of zeros → checksum 0).
    fn build_ea05_stored(subtype: &[u8], script: &[u8]) -> Vec<u8> {
        let checksum = 0u32; // 16 zero bytes
        let mut d = Vec::new();
        d.extend_from_slice(MARKER_EA05);
        d.extend_from_slice(&[0u8; 16]); // checksum region
        d.extend_from_slice(&mt_apply(b"FILE", KEY_FILE_TAG)); // tag
                                                               // subtype string
        d.extend_from_slice(&((subtype.len() as u32) ^ KEY_SUBTYPE_LEN).to_le_bytes());
        d.extend_from_slice(&mt_apply(
            subtype,
            (subtype.len() as u32).wrapping_add(KEY_SUBTYPE_DATA),
        ));
        // name string ("x")
        let name = b"x";
        d.extend_from_slice(&((name.len() as u32) ^ KEY_NAME_LEN).to_le_bytes());
        d.extend_from_slice(&mt_apply(
            name,
            (name.len() as u32).wrapping_add(KEY_NAME_DATA),
        ));
        // data header
        d.push(0); // comp = 0 (stored)
        d.extend_from_slice(&((script.len() as u32) ^ KEY_SIZE).to_le_bytes()); // csize
        d.extend_from_slice(&((script.len() as u32) ^ KEY_SIZE).to_le_bytes()); // usize
        d.extend_from_slice(&KEY_CRC.to_le_bytes()); // crc
        d.extend_from_slice(&[0u8; 16]); // two u64 timestamps
        d.extend_from_slice(&mt_apply(script, checksum.wrapping_add(KEY_CONTENT))); // content
        d
    }

    /// Encode `plain` as an all-literal EA05 LZSS stream ("EA05" + BE size + bits).
    fn ea05_all_literal(plain: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut cur = 0u8;
        let mut nbits = 0u8;
        let push_bit = |bit: u8, bytes: &mut Vec<u8>, cur: &mut u8, nbits: &mut u8| {
            *cur = (*cur << 1) | (bit & 1);
            *nbits += 1;
            if *nbits == 8 {
                bytes.push(*cur);
                *cur = 0;
                *nbits = 0;
            }
        };
        for &b in plain {
            push_bit(0, &mut bytes, &mut cur, &mut nbits); // literal flag
            for k in (0..8).rev() {
                push_bit((b >> k) & 1, &mut bytes, &mut cur, &mut nbits);
            }
        }
        if nbits != 0 {
            cur <<= 8 - nbits;
            bytes.push(cur);
        }
        bytes.push(0); // trailing slack
        let mut out = Vec::new();
        out.extend_from_slice(b"EA05");
        out.extend_from_slice(&(plain.len() as u32).to_be_bytes());
        out.extend_from_slice(&bytes);
        out
    }

    #[test]
    fn mt_keystream_is_symmetric() {
        let plain = b"MALWARETEST keystream roundtrip";
        assert_eq!(mt_apply(&mt_apply(plain, 0x1234), 0x1234), plain);
    }

    #[test]
    fn stored_script_extracted() {
        let script = b"; AutoIt\nMsgBox(0, \"x\", \"MALWARETEST\")\n";
        let blob = build_ea05_stored(b">>>AUTOIT SCRIPT<<<", script);
        assert!(is_autoit(&blob));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Autoit, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "autoit-script.au3");
        assert_eq!(entries[0].data, script);
    }

    #[test]
    fn lzss_literal_roundtrip() {
        let plain = b"MALWARETEST-lzss-literal-stream";
        let stream = ea05_all_literal(plain);
        let (out, complete) = decompress(&stream, 1 << 20).unwrap();
        assert_eq!(out, plain);
        assert!(complete);
        let (_, complete) = decompress(&stream[..stream.len() - 6], 1 << 20).unwrap();
        assert!(!complete, "a cut stream says so");
    }

    #[test]
    fn compressed_script_extracted() {
        let script = b"Run(\"calc.exe\") ; MALWARETEST inside compressed EA05";
        let comp = ea05_all_literal(script);
        // Build a compressed FILE record.
        let mut d = Vec::new();
        d.extend_from_slice(MARKER_EA05);
        d.extend_from_slice(&[0u8; 16]);
        d.extend_from_slice(&mt_apply(b"FILE", KEY_FILE_TAG));
        d.extend_from_slice(&KEY_SUBTYPE_LEN.to_le_bytes()); // empty subtype
        d.extend_from_slice(&KEY_NAME_LEN.to_le_bytes()); // empty name
        d.push(1); // compressed
        d.extend_from_slice(&((comp.len() as u32) ^ KEY_SIZE).to_le_bytes());
        d.extend_from_slice(&((script.len() as u32) ^ KEY_SIZE).to_le_bytes());
        d.extend_from_slice(&KEY_CRC.to_le_bytes());
        d.extend_from_slice(&[0u8; 16]);
        d.extend_from_slice(&mt_apply(&comp, KEY_CONTENT)); // checksum 0
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Autoit, &d, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, script);
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The EA06 keystream, against AutoIt-Ripper's `LAME` seeded with the tag key.
    #[test]
    fn ea06_keystream_matches_the_reference() {
        let mut ks = [0u8; 16];
        xor(&mut ks, EA06.file_tag, Cipher::Lame);
        assert_eq!(ks.to_vec(), unhex("2d0a8617b6b371a0071084f7e5bae729"));
    }

    /// A token stream and its text in ClamAV's form: keywords and a function
    /// by index, a function by name, quotes inside a string, integers and
    /// floats.
    const TOKENS: &str = "04000000001c0000003301000000590041013a00000047360c000000670069007e006200690060003f003e0022006800600060004036030000006a006d0077004036040000004600610061007400487f00040000003301000000590000050000007f31060000004b0055004100440049005e00470500000000403611000000620070006800310033005c0050005d004600500043005400450054004200450033004020000000000000f83f4020408cb5781daf1544487f00080000007f";
    const SOURCE: &str = "LOCAL $X = DLLCALL ( \"kernel32.dll\" , \"int\" , \"Beep\" ) \nIF $X THEN \nMSGBOX ( 0x00000000 , \"say \"MALWARETEST\"\" , 1.5 , 1e+20 ) \nENDIF \n";

    #[test]
    fn tokens_decompile_as_clamav_writes_them() {
        assert_eq!(
            decompile(&unhex(TOKENS), 1 << 20).unwrap(),
            SOURCE.as_bytes()
        );
        let cut = unhex(TOKENS);
        match decompile(&cut[..cut.len() - 3], 1 << 20) {
            Err(Some(text)) => assert!(text.starts_with(b"LOCAL $X")),
            other => panic!("the lines before the cut are kept: {other:?}"),
        }
        assert!(matches!(
            decompile(b"; plain script text", 1 << 20),
            Err(None)
        ));
    }

    /// The rarer tokens, against what ClamAV wrote for a crafted script: 64-bit
    /// integers (whose low word it sign-extends), floats as `%g`, a user
    /// function's name running into its `(`, and a non-ASCII character as the
    /// low byte of its UTF-16 unit.
    #[test]
    fn rare_tokens_render_as_clamav_writes_them() {
        let mut t = 1u32.to_le_bytes().to_vec();
        for v in [
            0xffff_ffffu64,
            0x1_0000_0002,
            0x1234_5678_9abc_def0,
            0x8000_0000,
            5,
        ] {
            t.push(0x10);
            t.extend_from_slice(&v.to_le_bytes());
        }
        for f in [6.0f64, 0.5, 1e20, 123456.789, -2.5, 1e-7, 1.2345678] {
            t.push(0x20);
            t.extend_from_slice(&f.to_le_bytes());
        }
        let key = 3u32;
        t.push(0x34);
        t.extend_from_slice(&key.to_le_bytes());
        for c in "F\u{2014}N".encode_utf16() {
            t.extend_from_slice(&(c ^ key as u16).to_le_bytes());
        }
        t.extend_from_slice(&[0x47, 0x48, 0x7F]);
        let want = b"0xffffffffffffffff 0x0000000100000002 0x123456779abcdef0 \
            0xffffffff80000000 0x0000000000000005 6 0.5 1e+20 123457 -2.5 1e-07 \
            1.23457 F\x14N( ) \n";
        assert_eq!(decompile(&t, 1 << 20).unwrap(), want);
    }

    /// A whole EA06 record: the tag, UTF-16 subtype and name, and a compressed
    /// token stream, all under the EA06 keystream, come out as source text.
    #[test]
    fn ea06_script_is_extracted_as_source() {
        let lame = |b: &[u8], seed: u32| {
            let mut v = b.to_vec();
            xor(&mut v, seed, Cipher::Lame);
            v
        };
        let utf16 = |s: &str| {
            s.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>()
        };
        let comp = ea06_all_literal(&unhex(TOKENS));
        let mut d = MARKER_EA06.to_vec();
        d.extend_from_slice(&[0x5a; 16]); // not summed into any key for EA06
        d.extend_from_slice(&lame(b"FILE", EA06.file_tag));
        for (s, keys) in [(">>>AUTOIT SCRIPT<<<", EA06.subtype), ("s.au3", EA06.name)] {
            let n = s.encode_utf16().count() as u32;
            d.extend_from_slice(&(n ^ keys.0).to_le_bytes());
            d.extend_from_slice(&lame(&utf16(s), n.wrapping_add(keys.1)));
        }
        d.push(1);
        d.extend_from_slice(&(comp.len() as u32 ^ EA06.size).to_le_bytes());
        d.extend_from_slice(&[0; 8 + 16]);
        d.extend_from_slice(&lame(&comp, EA06.content));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Autoit, &d, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].unsupported, None);
        assert_eq!(entries[0].data, SOURCE.as_bytes());
    }

    /// An EA06 file of `(subtype, compressed content)` records, as
    /// [`ea06_script_is_extracted_as_source`] lays one out.
    fn ea06_blob(records: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let lame = |b: &[u8], seed: u32| {
            let mut v = b.to_vec();
            xor(&mut v, seed, Cipher::Lame);
            v
        };
        let mut d = MARKER_EA06.to_vec();
        d.extend_from_slice(&[0x5a; 16]);
        for (subtype, comp) in records {
            d.extend_from_slice(&lame(b"FILE", EA06.file_tag));
            for (s, keys) in [(*subtype, EA06.subtype), ("src.bin", EA06.name)] {
                let utf16: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
                let n = s.encode_utf16().count() as u32;
                d.extend_from_slice(&(n ^ keys.0).to_le_bytes());
                d.extend_from_slice(&lame(&utf16, n.wrapping_add(keys.1)));
            }
            d.push(1);
            d.extend_from_slice(&(comp.len() as u32 ^ EA06.size).to_le_bytes());
            d.extend_from_slice(&[0; 8 + 16]);
            d.extend_from_slice(&lame(comp, EA06.content));
        }
        d
    }

    /// A file the script installs (`FileInstall`) is a member of its own, the
    /// bytes exactly as stored.
    #[test]
    fn an_ea06_installed_file_is_extracted_whole() {
        let payload: Vec<u8> = b"MZ installed payload "
            .iter()
            .copied()
            .cycle()
            .take(3000)
            .collect();
        let blob = ea06_blob(&[
            (">>>AUTOIT SCRIPT<<<", ea06_all_literal(&unhex(TOKENS))),
            ("C:\\Users\\Public\\payload.exe", ea06_all_literal(&payload)),
        ]);
        let entries = extract(Format::Autoit, &blob, &mut Budget::new(Limits::default())).unwrap();
        assert_eq!(entries.len(), 2, "{:?}", entries.iter().map(|e| &e.name).collect::<Vec<_>>());
        assert_eq!(entries[0].data, SOURCE.as_bytes());
        assert_eq!(entries[1].unsupported, None);
        assert!(entries[1].data == payload, "the installed file differs");
    }

    /// A member whose compressed stream stops half way is scanned as far as it
    /// decoded, and reported: what comes out is a prefix of what went in.
    #[test]
    fn an_ea06_member_cut_short_is_kept_and_reported() {
        let payload: Vec<u8> = (0..4000u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut comp = ea06_all_literal(&payload);
        comp.truncate(comp.len() / 2);
        let blob = ea06_blob(&[("C:\\x.bin", comp)]);
        let entries = extract(Format::Autoit, &blob, &mut Budget::new(Limits::default())).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert!(e.unsupported.is_some(), "the cut was not reported");
        assert!(e.data.len() > 1000, "{} bytes kept", e.data.len());
        assert!(payload.starts_with(&e.data), "what was kept is not the start of the member");
    }

    /// [`ea05_all_literal`] with EA06's literal flag (1) and magic.
    fn ea06_all_literal(plain: &[u8]) -> Vec<u8> {
        let mut bits: Vec<u8> = Vec::new();
        for &b in plain {
            bits.push(1);
            bits.extend((0..8).rev().map(|k| (b >> k) & 1));
        }
        bits.resize(bits.len().div_ceil(8) * 8 + 8, 0);
        let mut out = b"EA06".to_vec();
        out.extend_from_slice(&(plain.len() as u32).to_be_bytes());
        let packed = bits.as_slice().chunks(8);
        out.extend(packed.map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b)));
        out
    }

    #[test]
    fn truncated_and_garbage_no_panic() {
        for cut in 0..40usize {
            let full = build_ea05_stored(b"x", b"MALWARETEST short");
            let mut budget = Budget::new(Limits::default());
            let _ = extract(Format::Autoit, &&full[..cut.min(full.len())], &mut budget).unwrap();
        }
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Autoit, b"not autoit", &mut budget)
            .unwrap()
            .is_empty());
    }
}
