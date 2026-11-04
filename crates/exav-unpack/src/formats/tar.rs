//! tar: POSIX ustar and pax, GNU's extensions (long names and links, sparse
//! members) and the V7 format before them. Each member is read off the source
//! where it lies, and one the visitor does not read is passed over.
//!
//! An archive is a run of 512-byte headers, each followed by its member's
//! bytes padded to a block. A pax extended header (`x`), a global one (`g`)
//! and GNU's long name and long link (`L`, `K`) describe the header after
//! them and are not members.
//!
//! Formats: POSIX.1-2017 `pax` (ustar and pax interchange formats) and the
//! "Standard" and "Sparse Formats" chapters of the GNU tar manual.

use std::io::{self, Read};

use crate::source::{ByteSource, Reader};
use crate::stream::{MemberMeta, Mtime, Visit, emit_range, emit_stream};
use crate::{Budget, LimitHit};

const BLOCK: u64 = 512;

pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    // What a header held in memory (a pax header, a long name, a sparse map)
    // may take.
    let held = budget.limits().max_buffer_bytes;
    let mut global = Pax::default();
    let mut local = Pax::default();
    let mut long_name: Option<Vec<u8>> = None;
    let mut long_link: Option<Vec<u8>> = None;
    let mut off = 0u64;
    loop {
        // A header cut short, or none where one should be: the archive is
        // truncated, and what is missing is absent rather than hidden.
        let Some(h) = block(src, off) else {
            return Ok(None);
        };
        if h.iter().all(|&b| b == 0) {
            // The end of the archive. A header after the zero blocks is a
            // second archive appended to the first (`cat a.tar b.tar`).
            match after_zeros(src, off) {
                Some(next) => {
                    off = next;
                    continue;
                }
                None => return Ok(None),
            }
        }
        if !checksum_ok(&h) {
            return Err(LimitHit::corrupt(format!(
                "tar: header checksum mismatch at offset {off}"
            )));
        }
        let data = off + BLOCK;
        let typeflag = h[156];
        if matches!(typeflag, b'x' | b'g' | b'L' | b'K') {
            let size = numeric(&h[124..136])
                .ok_or_else(|| LimitHit::corrupt(format!("tar: bad size at offset {off}")))?;
            let n = usize::try_from(size).ok().filter(|_| size <= held);
            let Some(n) = n else {
                return Err(LimitHit::new(format!(
                    "tar: a {size}-byte extended header at offset {off}, over the \
                     {held}-byte buffer limit (--max-object-bytes): the members \
                     after it were not scanned"
                )));
            };
            let Ok(at) = usize::try_from(data) else {
                return Ok(None);
            };
            let body = src.window(at, n);
            if body.len() < n {
                return Ok(None);
            }
            match typeflag {
                b'x' => local.read(&body, true),
                b'g' => global.read(&body, false),
                b'L' => long_name = Some(cstr(&body).to_vec()),
                _ => long_link = Some(cstr(&body).to_vec()),
            }
            let Some(next) = data.checked_add(padded(size)) else {
                return Ok(None);
            };
            off = next;
            continue;
        }

        budget.count_entry()?;
        let pax = |f: fn(&Pax) -> &Option<Vec<u8>>| -> Option<Vec<u8>> {
            f(&local)
                .as_ref()
                .or(f(&global).as_ref())
                .filter(|v| !v.is_empty())
                .cloned()
        };
        let name = pax(|p| &p.sparse_name)
            .or_else(|| pax(|p| &p.path))
            .or(long_name.take())
            .unwrap_or_else(|| header_name(&h));
        let link = pax(|p| &p.linkpath)
            .or(long_link.take())
            .unwrap_or_else(|| cstr(&h[157..257]).to_vec());
        let size = match pax(|p| &p.size) {
            Some(v) => decimal(&v),
            None => numeric(&h[124..136]),
        }
        .ok_or_else(|| LimitHit::corrupt(format!("tar: bad size at offset {off}")))?;
        let mtime = pax(|p| &p.mtime)
            .and_then(|v| pax_time(&v))
            .or_else(|| set(&h[136..148]).and_then(|t| i64::try_from(t).ok()));

        // The type bits `st_mode` has and a tar header keeps apart. A hard
        // link has neither a type of its own nor content here: no mode. An
        // archive from before typeflag `5` marks a directory by its name.
        let kind = match typeflag {
            b'0' | b'\0' if name.ends_with(b"/") => Some(0o040000),
            b'0' | b'\0' | b'7' | b'S' => Some(0o100000),
            b'5' => Some(0o040000),
            b'2' => Some(0o120000),
            _ => None,
        };
        let mut meta = MemberMeta {
            name: String::from_utf8_lossy(&name).into_owned(),
            comp_size: size,
            size: Some(size),
            mtime: mtime.map(Mtime::Unix),
            mode: kind.and_then(|k| Some(k | (set(&h[100..108])? as u32 & 0o7777))),
            link: (typeflag == b'2').then(|| String::from_utf8_lossy(&link).into_owned()),
            ..MemberMeta::default()
        };

        // Where the stored bytes start and how many there are, and the map
        // and size of a sparse member. An old GNU sparse member keeps its map
        // in the header and in blocks after it, which its size leaves out; a
        // GNU 1.0 one at the start of its data, which its size counts.
        let (mut start, mut stored, mut next_from) = (data, size, data);
        let mut sparse = None;
        if typeflag == b'S' {
            let (map, at) = match gnu_sparse_map(src, &h, data, held) {
                Ok(m) => m,
                Err(Cut::Truncated) => return Ok(None),
                Err(Cut::Held(n)) => return Err(over_held(n, off, held)),
            };
            (start, next_from) = (at, at);
            sparse = map.zip(set(&h[483..495]));
        } else if let Some(real) = pax(|p| &p.sparse_realsize).and_then(|v| decimal(&v)) {
            let map = if pax(|p| &p.sparse_major).as_deref() == Some(b"1") {
                match pax1_map(src, data, size, held) {
                    Ok(Some((map, skip))) if skip <= size => {
                        (start, stored) = (data + skip, size - skip);
                        Some(map)
                    }
                    Ok(_) => None,
                    Err(Cut::Truncated) => return Ok(None),
                    Err(Cut::Held(n)) => return Err(over_held(n, off, held)),
                }
            } else if let Some(v) = pax(|p| &p.sparse_map) {
                pairs(v.split(|&b| b == b',').map(decimal))
            } else {
                Some(std::mem::take(&mut local.sparse_pairs))
            };
            sparse = map.map(|m| (m, real));
        }
        local = Pax::default();
        // `None` when the member runs past the largest offset: it takes the
        // rest of the source, and nothing follows it.
        let next = next_from.checked_add(padded(size));

        let out = match sparse {
            Some((map, real)) if valid_map(&map, real, stored) => {
                meta.comp_size = stored;
                meta.size = Some(real);
                let mut r = Sparse {
                    data: range(src, start, stored),
                    map,
                    i: 0,
                    pos: 0,
                    real,
                };
                emit_stream(&meta, &mut r, budget, visit)?
            }
            // Not sparse, or a sparse member whose map does not hold
            // together: its bytes as they are stored, so none goes unread.
            _ => {
                let mut r = range(src, next_from, size);
                emit_range(&mut meta, (next_from, size), &mut r, budget, visit)?
            }
        };
        match (out, next) {
            (Some(t), _) => return Ok(Some(t)),
            (None, Some(n)) => off = n,
            (None, None) => return Ok(None),
        }
    }
}

/// The 512 bytes at `off`, or `None` when the source has fewer.
fn block(src: &dyn ByteSource, off: u64) -> Option<Vec<u8>> {
    let off = usize::try_from(off).ok()?;
    let w = src.window(off, BLOCK as usize);
    (w.len() == BLOCK as usize).then(|| w.into_owned())
}

/// Where the next header is after the zero block at `off`: the first block
/// that is not zeros, when it is a header.
fn after_zeros(src: &dyn ByteSource, off: u64) -> Option<u64> {
    let mut found = None;
    src.chunks(
        off as usize,
        src.len(),
        &mut |at, chunk| match chunk.iter().position(|&b| b != 0) {
            Some(i) => {
                found = Some((at + i) as u64);
                false
            }
            None => true,
        },
    );
    let next = found? / BLOCK * BLOCK;
    block(src, next).filter(|h| checksum_ok(h)).map(|_| next)
}

/// The header's checksum, computed over the block with its own field read as
/// spaces. POSIX sums the bytes unsigned; some old writers summed them signed.
fn checksum_ok(h: &[u8]) -> bool {
    let field = &h[148..156];
    let digits = field.split(|&b| b == 0).next().unwrap_or(&[]).trim_ascii();
    let Some(want) = (!digits.is_empty()).then(|| octal(digits)).flatten() else {
        return false;
    };
    let (mut unsigned, mut signed) = (0u64, 0i64);
    for (i, &b) in h.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += u64::from(b);
        signed += i64::from(b as i8);
    }
    want == unsigned || i64::try_from(want).is_ok_and(|w| w == signed)
}

/// A numeric field: octal digits ended by a NUL or a space (both ends may be
/// padded with spaces), or a base-256 number when the first byte has its high
/// bit set, which GNU writes for a value octal cannot hold. A blank field is
/// 0; a negative base-256 value is `None`.
fn numeric(f: &[u8]) -> Option<u64> {
    if f[0] & 0x80 != 0 {
        if f[0] & 0x40 != 0 {
            return None;
        }
        return f[1..].iter().try_fold(u64::from(f[0] & 0x3f), |v, &b| {
            v.checked_mul(256)?.checked_add(u64::from(b))
        });
    }
    let t = f.split(|&b| b == 0).next().unwrap_or(&[]).trim_ascii();
    if t.is_empty() {
        return Some(0);
    }
    octal(t)
}

/// A numeric field that is filled in: `None` when it is blank.
fn set(f: &[u8]) -> Option<u64> {
    let blank = f.iter().all(|&b| b == 0 || b == b' ');
    if blank { None } else { numeric(f) }
}

fn octal(t: &[u8]) -> Option<u64> {
    t.iter().try_fold(0u64, |v, &b| {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        v.checked_mul(8)?.checked_add(u64::from(b - b'0'))
    })
}

/// A decimal number, as pax records and GNU's sparse maps write them.
fn decimal(t: &[u8]) -> Option<u64> {
    let t = t.trim_ascii();
    if t.is_empty() || t.len() > 20 {
        return None;
    }
    t.iter().try_fold(0u64, |v, &b| {
        if !b.is_ascii_digit() {
            return None;
        }
        v.checked_mul(10)?.checked_add(u64::from(b - b'0'))
    })
}

/// A pax time, seconds with an optional sign and fraction: the seconds.
fn pax_time(t: &[u8]) -> Option<i64> {
    let whole = t.split(|&b| b == b'.').next()?;
    match whole.strip_prefix(b"-") {
        Some(n) => i64::try_from(decimal(n)?).ok().map(|v| -v),
        None => i64::try_from(decimal(whole)?).ok(),
    }
}

/// `f` up to its first NUL.
fn cstr(f: &[u8]) -> &[u8] {
    f.split(|&b| b == 0).next().unwrap_or(&[])
}

fn padded(size: u64) -> u64 {
    size.div_ceil(BLOCK).saturating_mul(BLOCK)
}

/// The name a header gives: ustar joins its prefix and name with a slash.
/// GNU's magic (`ustar  `) has no prefix there, and star's (`tar\0` at the
/// end) a shorter one.
fn header_name(h: &[u8]) -> Vec<u8> {
    let name = cstr(&h[..100]);
    if &h[257..263] == b"ustar\0" {
        let prefix = if &h[508..512] == b"tar\0" {
            cstr(&h[345..476])
        } else {
            cstr(&h[345..500])
        };
        if !prefix.is_empty() {
            return [prefix, b"/", name].concat();
        }
    }
    name.to_vec()
}

/// The records of pax extended headers that the reader acts on. A value of
/// zero length removes the field, so the header's own (or the global one)
/// applies again.
#[derive(Default)]
struct Pax {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<Vec<u8>>,
    mtime: Option<Vec<u8>>,
    sparse_name: Option<Vec<u8>>,
    sparse_realsize: Option<Vec<u8>>,
    sparse_major: Option<Vec<u8>>,
    sparse_map: Option<Vec<u8>>,
    /// GNU sparse 0.0: `GNU.sparse.offset` and `GNU.sparse.numbytes`
    /// records, repeated in order.
    sparse_pairs: Vec<(u64, u64)>,
    sparse_offset: Option<u64>,
}

impl Pax {
    /// Read the records `len value=...\n` of `body`, up to the first that is
    /// malformed. The sparse records are for one member, not global ones.
    fn read(&mut self, body: &[u8], member: bool) {
        let mut at = 0;
        while at < body.len() {
            let rest = &body[at..];
            let Some(sp) = rest.iter().position(|&b| b == b' ') else {
                return;
            };
            let Some(n) = decimal(&rest[..sp]).and_then(|n| usize::try_from(n).ok()) else {
                return;
            };
            if n <= sp + 1 || n > rest.len() || rest[n - 1] != b'\n' {
                return;
            }
            let rec = &rest[sp + 1..n - 1];
            let Some(eq) = rec.iter().position(|&b| b == b'=') else {
                return;
            };
            let (key, value) = (&rec[..eq], &rec[eq + 1..]);
            let slot = match key {
                b"path" => &mut self.path,
                b"linkpath" => &mut self.linkpath,
                b"size" => &mut self.size,
                b"mtime" => &mut self.mtime,
                b"GNU.sparse.name" if member => &mut self.sparse_name,
                b"GNU.sparse.realsize" | b"GNU.sparse.size" if member => &mut self.sparse_realsize,
                b"GNU.sparse.major" if member => &mut self.sparse_major,
                b"GNU.sparse.map" if member => &mut self.sparse_map,
                b"GNU.sparse.offset" if member => {
                    self.sparse_offset = decimal(value);
                    at += n;
                    continue;
                }
                b"GNU.sparse.numbytes" if member => {
                    if let (Some(o), Some(len)) = (self.sparse_offset.take(), decimal(value)) {
                        self.sparse_pairs.push((o, len));
                    }
                    at += n;
                    continue;
                }
                _ => {
                    at += n;
                    continue;
                }
            };
            *slot = Some(value.to_vec());
            at += n;
        }
    }
}

/// Why a sparse map was not read: the archive ends inside it, or holding it
/// would take this many bytes, over the buffer limit.
enum Cut {
    Truncated,
    Held(u64),
}

fn over_held(n: u64, off: u64, held: u64) -> LimitHit {
    LimitHit::new(format!(
        "tar: the sparse map of the member at offset {off} takes {n} bytes, over \
         the {held}-byte buffer limit (--max-object-bytes): it was not scanned"
    ))
}

/// A sparse member's `(offset, size)` pieces, in order.
type Map = Vec<(u64, u64)>;

/// Bytes a map entry takes in memory, for the bound on a map.
const ENTRY_BYTES: u64 = 16;

/// An old GNU sparse member's map: four entries in the header, then 21 in each
/// extension block while the one before says another follows. `None` for a
/// map that does not parse; with it, where the member's data starts.
fn gnu_sparse_map(
    src: &dyn ByteSource,
    h: &[u8],
    data: u64,
    held: u64,
) -> Result<(Option<Map>, u64), Cut> {
    let mut map = Vec::new();
    let mut ok = read_entries(&h[386..482], &mut map);
    let mut extended = h[482] != 0;
    let mut at = data;
    while extended {
        let b = block(src, at).ok_or(Cut::Truncated)?;
        at += BLOCK;
        let n = (map.len() as u64 + 21).saturating_mul(ENTRY_BYTES);
        if n > held {
            return Err(Cut::Held(n));
        }
        ok &= read_entries(&b[..504], &mut map);
        extended = b[504] != 0;
    }
    Ok((ok.then_some(map), at))
}

/// The `(offset, numbytes)` entries of 24 bytes in `f`, up to the first blank
/// one. False when one does not parse.
fn read_entries(f: &[u8], map: &mut Map) -> bool {
    for e in f.as_chunks::<24>().0 {
        if e[0] == 0 {
            break;
        }
        match (numeric(&e[..12]), numeric(&e[12..])) {
            (Some(o), Some(n)) => map.push((o, n)),
            _ => return false,
        }
    }
    true
}

/// A GNU sparse 1.0 map, at the start of the member's data: decimal numbers
/// each ended by a newline, the count of entries then each offset and size,
/// padded to a block. With it, how many bytes of the data it takes. `None`
/// for a map that does not parse or runs past the data, whose bytes are then
/// read as they are stored.
fn pax1_map(
    src: &dyn ByteSource,
    data: u64,
    size: u64,
    held: u64,
) -> Result<Option<(Map, u64)>, Cut> {
    let mut r = io::BufReader::with_capacity(64 * 1024, range(src, data, size)).bytes();
    let mut used = 0u64;
    let mut next = || -> Option<u64> {
        let mut digits = Vec::new();
        loop {
            let b = r.next()?.ok()?;
            used += 1;
            if b == b'\n' {
                return decimal(&digits);
            }
            if digits.len() > 20 {
                return None;
            }
            digits.push(b);
        }
    };
    let Some(count) = next() else {
        return Ok(None);
    };
    let n = count.saturating_mul(ENTRY_BYTES);
    if n > held {
        return Err(Cut::Held(n));
    }
    let mut v = Vec::new();
    for _ in 0..count {
        let (Some(o), Some(len)) = (next(), next()) else {
            return Ok(None);
        };
        v.push((o, len));
    }
    Ok(Some((v, padded(used))))
}

/// The pairs of a `GNU.sparse.map` list, `None` when one does not parse or
/// one is missing its size.
fn pairs(mut it: impl Iterator<Item = Option<u64>>) -> Option<Vec<(u64, u64)>> {
    let mut v = Vec::new();
    while let Some(o) = it.next() {
        v.push((o?, it.next()??));
    }
    Some(v)
}

/// A map whose entries are in order, do not overlap, lie inside the file and
/// take the stored bytes exactly: a stored byte no entry places would not be
/// read.
fn valid_map(map: &[(u64, u64)], real: u64, stored: u64) -> bool {
    let mut end = 0u64;
    let mut total = 0u64;
    for &(o, n) in map {
        let Some(e) = o.checked_add(n) else {
            return false;
        };
        if o < end || e > real {
            return false;
        }
        end = e;
        total += n;
    }
    total == stored
}

fn range(src: &dyn ByteSource, from: u64, len: u64) -> Reader<'_> {
    let n = src.len() as u64;
    let from = from.min(n);
    Reader::range(src, from as usize, from.saturating_add(len).min(n) as usize)
}

/// A sparse member's content: the stored pieces where the map puts them, and
/// zeros in the holes between them and up to the file's size.
struct Sparse<'a> {
    data: Reader<'a>,
    map: Vec<(u64, u64)>,
    i: usize,
    pos: u64,
    real: u64,
}

impl Read for Sparse<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let room = buf.len() as u64;
        while let Some(&(o, n)) = self.map.get(self.i) {
            if self.pos < o {
                let k = (o - self.pos).min(room) as usize;
                buf[..k].fill(0);
                self.pos += k as u64;
                return Ok(k);
            }
            if self.pos < o + n {
                let k = (o + n - self.pos).min(room) as usize;
                let got = self.data.read(&mut buf[..k])?;
                if got == 0 {
                    // The archive ends inside the stored data: the rest is
                    // absent, holes included.
                    self.i = self.map.len();
                    self.real = self.pos;
                }
                self.pos += got as u64;
                return Ok(got);
            }
            self.i += 1;
        }
        let k = (self.real.saturating_sub(self.pos)).min(room) as usize;
        buf[..k].fill(0);
        self.pos += k as u64;
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Budget, Format, LimitHit, Limits, Member, MemberMeta};

    #[derive(Clone, Copy)]
    enum Magic {
        V7,
        Ustar,
        Gnu,
    }

    /// A header block with its checksum.
    fn header(name: &[u8], typeflag: u8, size: u64, magic: Magic) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name);
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        h[136..148].copy_from_slice(b"14000000000\0");
        h[156] = typeflag;
        match magic {
            Magic::V7 => {}
            Magic::Ustar => h[257..265].copy_from_slice(b"ustar\x0000"),
            Magic::Gnu => h[257..265].copy_from_slice(b"ustar  \0"),
        }
        sum(&mut h);
        h
    }

    fn sum(h: &mut [u8]) {
        h[148..156].copy_from_slice(b"        ");
        let s: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{s:06o}\0 ").as_bytes());
    }

    /// `h` followed by `body` padded to a block.
    fn entry(mut h: Vec<u8>, body: &[u8]) -> Vec<u8> {
        h.extend_from_slice(body);
        h.resize(h.len().div_ceil(512) * 512, 0);
        h
    }

    fn pax(typeflag: u8, records: &[(&str, &str)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (k, v) in records {
            // The length counts its own digits.
            let rec = format!(" {k}={v}\n");
            let mut n = rec.len() + 1;
            while n != rec.len() + n.to_string().len() {
                n = rec.len() + n.to_string().len();
            }
            body.extend_from_slice(format!("{n}{rec}").as_bytes());
        }
        entry(
            header(b"././@PaxHeader", typeflag, body.len() as u64, Magic::Ustar),
            &body,
        )
    }

    fn archive(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut out = parts.concat();
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    struct Seen {
        name: String,
        data: Vec<u8>,
        meta: MemberMeta,
    }

    fn walk_with(blob: &[u8], limits: Limits) -> (Vec<Seen>, Result<(), LimitHit>) {
        let mut out = Vec::new();
        let mut budget = Budget::new(limits);
        let r = crate::walk(Format::Tar, &blob, &mut budget, &mut |m, c, _| {
            let mut data = Vec::new();
            if let Some(Member::Stream(r)) = c {
                r.read_to_end(&mut data).unwrap();
            }
            out.push(Seen {
                name: m.name.clone(),
                data,
                meta: m.clone(),
            });
            None::<()>
        });
        (out, r.map(|_| ()))
    }

    fn walk(blob: &[u8]) -> Vec<Seen> {
        let (seen, r) = walk_with(blob, Limits::default());
        r.unwrap();
        seen
    }

    fn names(seen: &[Seen]) -> Vec<&str> {
        seen.iter().map(|s| s.name.as_str()).collect()
    }

    #[test]
    fn ustar_joins_the_prefix_and_the_name() {
        let mut h = header(b"file.txt", b'0', 2, Magic::Ustar);
        h[345..349].copy_from_slice(b"a/bc");
        sum(&mut h);
        let seen = walk(&archive(&[entry(h, b"hi")]));
        assert_eq!(names(&seen), ["a/bc/file.txt"]);
        assert_eq!(seen[0].data, b"hi");
        assert_eq!(seen[0].meta.mode, Some(0o100644));
        assert_eq!(seen[0].meta.mtime, Some(crate::Mtime::Unix(0o14000000000)));
        // GNU's magic has no prefix there.
        let mut h = header(b"file.txt", b'0', 2, Magic::Gnu);
        h[345..349].copy_from_slice(b"a/bc");
        sum(&mut h);
        assert_eq!(names(&walk(&archive(&[entry(h, b"hi")]))), ["file.txt"]);
    }

    #[test]
    fn gnu_long_names_and_links_apply_to_the_next_header() {
        let long = "d/".repeat(80) + "f";
        let target = "t/".repeat(70) + "x";
        let blob = archive(&[
            entry(
                header(b"././@LongLink", b'L', long.len() as u64 + 1, Magic::Gnu),
                format!("{long}\0").as_bytes(),
            ),
            entry(header(b"short", b'0', 3, Magic::Gnu), b"abc"),
            entry(
                header(b"././@LongLink", b'K', target.len() as u64, Magic::Gnu),
                target.as_bytes(),
            ),
            header(b"lnk", b'2', 0, Magic::Gnu),
            entry(header(b"after", b'0', 1, Magic::Gnu), b"z"),
        ]);
        let seen = walk(&blob);
        assert_eq!(names(&seen), [long.as_str(), "lnk", "after"]);
        assert_eq!(seen[0].data, b"abc");
        assert_eq!(seen[1].meta.link.as_deref(), Some(target.as_str()));
        assert_eq!(seen[1].meta.mode, Some(0o120644));
        assert_eq!(seen[2].meta.link, None);
    }

    #[test]
    fn pax_records_override_the_header() {
        let blob = archive(&[
            pax(
                b'x',
                &[
                    ("path", "long/pax/name.bin"),
                    ("size", "5"),
                    ("mtime", "1700000000.25"),
                ],
            ),
            // The header's own size is wrong: pax's is the one to follow.
            entry(header(b"trunc", b'0', 0, Magic::Ustar), b"12345"),
            pax(b'x', &[("linkpath", "the/target")]),
            header(b"l", b'2', 0, Magic::Ustar),
            entry(header(b"plain", b'0', 1, Magic::Ustar), b"p"),
        ]);
        let seen = walk(&blob);
        assert_eq!(names(&seen), ["long/pax/name.bin", "l", "plain"]);
        assert_eq!(seen[0].data, b"12345");
        assert_eq!(seen[0].meta.mtime, Some(crate::Mtime::Unix(1_700_000_000)));
        assert_eq!(seen[1].meta.link.as_deref(), Some("the/target"));
        assert_eq!(seen[2].data, b"p");
    }

    #[test]
    fn a_pax_global_header_applies_to_every_member_after_it() {
        let blob = archive(&[
            pax(b'g', &[("mtime", "42")]),
            entry(header(b"a", b'0', 1, Magic::Ustar), b"a"),
            // A record of zero length takes the global one away again.
            pax(b'x', &[("mtime", "")]),
            entry(header(b"b", b'0', 1, Magic::Ustar), b"b"),
            entry(header(b"c", b'0', 1, Magic::Ustar), b"c"),
        ]);
        let seen = walk(&blob);
        assert_eq!(
            names(&seen),
            ["a", "b", "c"],
            "a global header is no member"
        );
        let t: Vec<_> = seen.iter().map(|s| s.meta.mtime).collect();
        assert_eq!(
            t,
            [
                Some(crate::Mtime::Unix(42)),
                Some(crate::Mtime::Unix(0o14000000000)),
                Some(crate::Mtime::Unix(42)),
            ]
        );
    }

    #[test]
    fn a_v7_archive_marks_directories_by_name() {
        let blob = archive(&[
            header(b"dir/", b'\0', 0, Magic::V7),
            entry(header(b"dir/f", b'\0', 4, Magic::V7), b"v7v7"),
        ]);
        let seen = walk(&blob);
        assert_eq!(names(&seen), ["dir/", "dir/f"]);
        assert_eq!(seen[0].meta.mode, Some(0o040644));
        assert_eq!(seen[1].meta.mode, Some(0o100644));
        assert_eq!(seen[1].data, b"v7v7");
    }

    #[test]
    fn a_damaged_checksum_is_corrupt_after_the_members_before_it() {
        let mut bad = header(b"b", b'0', 1, Magic::Ustar);
        bad[0] = b'c';
        let blob = archive(&[
            entry(header(b"a", b'0', 1, Magic::Ustar), b"a"),
            entry(bad, b"b"),
        ]);
        let (seen, r) = walk_with(&blob, Limits::default());
        assert_eq!(names(&seen), ["a"]);
        assert!(r.unwrap_err().is_corrupt());
    }

    #[test]
    fn a_checksum_summed_signed_is_accepted() {
        let mut h = header("é".as_bytes(), b'0', 1, Magic::Ustar);
        h[148..156].copy_from_slice(b"        ");
        let s: i64 = h.iter().map(|&b| i64::from(b as i8)).sum();
        h[148..156].copy_from_slice(format!("{s:06o}\0 ").as_bytes());
        assert_eq!(names(&walk(&archive(&[entry(h, b"x")]))), ["é"]);
    }

    #[test]
    fn a_base_256_size_is_read() {
        let mut h = header(b"big", b'0', 0, Magic::Gnu);
        h[124..136].copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        sum(&mut h);
        let seen = walk(&archive(&[entry(h, b"xyz")]));
        assert_eq!(seen[0].data, b"xyz");
    }

    #[test]
    fn a_truncated_archive_ends_the_walk_without_an_error() {
        let full = archive(&[
            entry(header(b"a", b'0', 600, Magic::Ustar), &[b'a'; 600]),
            entry(header(b"b", b'0', 1, Magic::Ustar), b"b"),
        ]);
        // Inside the first member's data, then inside the second header.
        for (cut, want) in [(700, 188), (1024 + 100, 600)] {
            let (seen, r) = walk_with(&full[..cut], Limits::default());
            r.unwrap();
            assert_eq!(names(&seen), ["a"], "cut at {cut}");
            assert_eq!(seen[0].data.len(), want, "cut at {cut}");
        }
        // Inside a long name.
        let blob = entry(
            header(b"././@LongLink", b'L', 2000, Magic::Gnu),
            &[b'n'; 1000],
        );
        let (seen, r) = walk_with(&blob, Limits::default());
        r.unwrap();
        assert!(seen.is_empty());
    }

    #[test]
    fn an_extended_header_over_the_buffer_limit_is_a_limit() {
        let blob = archive(&[
            pax(b'x', &[("path", &"p".repeat(3000))]),
            entry(header(b"a", b'0', 1, Magic::Ustar), b"a"),
        ]);
        let (seen, r) = walk_with(
            &blob,
            Limits {
                max_buffer_bytes: 1000,
                ..Limits::default()
            },
        );
        assert!(seen.is_empty());
        let hit = r.unwrap_err();
        assert!(!hit.is_corrupt(), "{}", hit.reason);
        assert!(hit.reason.contains("--max-object-bytes"), "{}", hit.reason);
    }

    #[test]
    fn an_archive_appended_after_the_end_marker_is_read() {
        let mut blob = archive(&[entry(header(b"a", b'0', 1, Magic::Ustar), b"a")]);
        blob.extend_from_slice(&[0u8; 8192]);
        blob.extend(archive(&[entry(header(b"b", b'0', 1, Magic::Ustar), b"b")]));
        assert_eq!(names(&walk(&blob)), ["a", "b"]);
        // What follows the zeros and is no header ends the archive.
        let mut blob = archive(&[entry(header(b"a", b'0', 1, Magic::Ustar), b"a")]);
        blob.extend_from_slice(&[0x55; 512]);
        assert_eq!(names(&walk(&blob)), ["a"]);
    }

    #[test]
    fn a_member_names_its_range_in_the_archive() {
        let blob = archive(&[
            entry(header(b"a", b'0', 1, Magic::Ustar), b"a"),
            entry(header(b"b", b'0', 700, Magic::Ustar), &[b'b'; 700]),
        ]);
        let seen = walk(&blob);
        assert_eq!(seen[0].meta.range, Some((512, 1)));
        assert_eq!(seen[1].meta.range, Some((1536, 700)));
    }

    /// `pieces` at their offsets in a file of `real` bytes, zeros elsewhere.
    fn expanded(real: usize, pieces: &[(usize, &[u8])]) -> Vec<u8> {
        let mut v = vec![0u8; real];
        for (o, p) in pieces {
            v[*o..o + p.len()].copy_from_slice(p);
        }
        v
    }

    #[test]
    fn an_old_gnu_sparse_member_is_expanded() {
        // Six pieces: four in the header, two in an extension block.
        let pieces: Vec<(usize, Vec<u8>)> = (0..6)
            .map(|i| (i * 2000 + 100, vec![b'A' + i as u8; 10 + i]))
            .collect();
        let stored: Vec<u8> = pieces.iter().flat_map(|(_, p)| p.clone()).collect();
        let real = 20_000;
        let mut h = header(b"sparse", b'S', stored.len() as u64, Magic::Gnu);
        let entry24 = |o: usize, n: usize| format!("{o:011o}\0{n:011o}\0").into_bytes();
        for (i, (o, p)) in pieces.iter().take(4).enumerate() {
            h[386 + i * 24..386 + (i + 1) * 24].copy_from_slice(&entry24(*o, p.len()));
        }
        h[482] = 1;
        h[483..495].copy_from_slice(format!("{real:011o}\0").as_bytes());
        sum(&mut h);
        let mut ext = vec![0u8; 512];
        for (i, (o, p)) in pieces.iter().skip(4).enumerate() {
            ext[i * 24..(i + 1) * 24].copy_from_slice(&entry24(*o, p.len()));
        }
        h.extend_from_slice(&ext);
        let blob = archive(&[
            entry(h, &stored),
            entry(header(b"next", b'0', 1, Magic::Gnu), b"n"),
        ]);
        let seen = walk(&blob);
        assert_eq!(names(&seen), ["sparse", "next"]);
        let want: Vec<(usize, &[u8])> = pieces.iter().map(|(o, p)| (*o, p.as_slice())).collect();
        assert_eq!(seen[0].data, expanded(real, &want));
        assert_eq!(seen[0].meta.size, Some(real as u64));
        assert_eq!(seen[0].meta.comp_size, stored.len() as u64);
        assert_eq!(seen[1].data, b"n");
    }

    #[test]
    fn pax_sparse_members_are_expanded() {
        let real = 5000;
        let want = expanded(real, &[(1000, b"HELLO"), (4000, b"WORLD!")]);
        let stored = b"HELLOWORLD!";
        // 1.0: the map at the start of the data, padded to a block.
        let mut data = b"2\n1000\n5\n4000\n6\n".to_vec();
        data.resize(512, 0);
        data.extend_from_slice(stored);
        let v10 = archive(&[
            pax(
                b'x',
                &[
                    ("GNU.sparse.major", "1"),
                    ("GNU.sparse.minor", "0"),
                    ("GNU.sparse.name", "real/name"),
                    ("GNU.sparse.realsize", "5000"),
                ],
            ),
            entry(
                header(
                    b"GNUSparseFile.1/name",
                    b'0',
                    data.len() as u64,
                    Magic::Ustar,
                ),
                &data,
            ),
            entry(header(b"next", b'0', 1, Magic::Ustar), b"n"),
        ]);
        // 0.1: the map as one record.
        let v01 = archive(&[
            pax(
                b'x',
                &[
                    ("GNU.sparse.size", "5000"),
                    ("GNU.sparse.numblocks", "2"),
                    ("GNU.sparse.map", "1000,5,4000,6"),
                    ("path", "real/name"),
                ],
            ),
            entry(header(b"x", b'0', 11, Magic::Ustar), stored),
            entry(header(b"next", b'0', 1, Magic::Ustar), b"n"),
        ]);
        // 0.0: one record for each offset and size.
        let v00 = archive(&[
            pax(
                b'x',
                &[
                    ("GNU.sparse.size", "5000"),
                    ("GNU.sparse.numblocks", "2"),
                    ("GNU.sparse.offset", "1000"),
                    ("GNU.sparse.numbytes", "5"),
                    ("GNU.sparse.offset", "4000"),
                    ("GNU.sparse.numbytes", "6"),
                    ("path", "real/name"),
                ],
            ),
            entry(header(b"x", b'0', 11, Magic::Ustar), stored),
            entry(header(b"next", b'0', 1, Magic::Ustar), b"n"),
        ]);
        for (label, blob) in [("1.0", v10), ("0.1", v01), ("0.0", v00)] {
            let seen = walk(&blob);
            assert_eq!(names(&seen), ["real/name", "next"], "{label}");
            assert_eq!(seen[0].data, want, "{label}");
            assert_eq!(seen[1].data, b"n", "{label}");
        }
    }

    #[test]
    fn a_sparse_map_that_runs_past_its_data_gives_the_bytes_as_stored() {
        // The count says three entries; the data holds one and a half.
        let data = b"3\n1000\n5\n4000\nHELLO";
        let blob = archive(&[
            pax(
                b'x',
                &[("GNU.sparse.major", "1"), ("GNU.sparse.realsize", "5000")],
            ),
            entry(header(b"x", b'0', data.len() as u64, Magic::Ustar), data),
            entry(header(b"next", b'0', 1, Magic::Ustar), b"n"),
        ]);
        let seen = walk(&blob);
        assert_eq!(names(&seen), ["x", "next"]);
        assert_eq!(seen[0].data, data);
    }

    #[test]
    fn a_member_sized_past_the_largest_offset_is_read_to_the_end() {
        let blob = archive(&[
            pax(b'x', &[("size", &u64::MAX.to_string())]),
            entry(header(b"huge", b'0', 0, Magic::Ustar), b"PAYLOAD"),
        ]);
        let seen = walk(&blob);
        assert_eq!(names(&seen), ["huge"]);
        assert!(seen[0].data.starts_with(b"PAYLOAD"));
    }

    #[test]
    fn a_sparse_map_that_leaves_stored_bytes_out_gives_them_as_stored() {
        // The map places five of the eleven stored bytes.
        let blob = archive(&[
            pax(
                b'x',
                &[("GNU.sparse.size", "5000"), ("GNU.sparse.map", "1000,5")],
            ),
            entry(header(b"x", b'0', 11, Magic::Ustar), b"HELLOWORLD!"),
        ]);
        let seen = walk(&blob);
        assert_eq!(seen[0].data, b"HELLOWORLD!");
        assert_eq!(seen[0].meta.range, Some((1536, 11)));
    }
}
