//! ZOO: Rahul Dhesi's 1986 archive format.
//!
//! Old, and that is exactly why it is worth opening. A format no modern scanner
//! bothers with is a place to hide something: the container is still trivially
//! unpackable by anyone who wants the payload, while a scanner that does not
//! know it sees compressed noise and reports `OK`.
//!
//! Two codecs: **LZD**, a 13-bit LZW variant, and **LZH**, Dhesi's own, which
//! is `lh5` on the wire, so `delharc` decodes it, despite ZOO sharing nothing
//! else with LHA. Structures are in [`super::zoo_parse`].
//!
//! **Deleted members are extracted too.** ZOO marks a member deleted by setting
//! a flag in its directory entry and leaves the bytes in place, exactly like the
//! NTFS MFT records `formats/ntfs.rs` walks. A scanner wants those bytes: they
//! are still in the file the victim has.
//!
//! **A CRC mismatch does not stop a scan.** ZOO records a CRC-16 per member.
//! Bytes that fail it are still emitted, as a ZIP member's are: a tampered
//! member is the interesting case, and dropping it would be a silent skip.
//! With checksums verified (`Budget::set_verify_checksums`) the entry also
//! carries the mismatch.

use super::zoo_parse::{DIRENT_HEADER_SIZE, DirEntry, Header, Method, ZOO_HEADER_SIZE, crc16_arc};
use crate::{Budget, Entry, Sink};

/// Bound on the directory walk; hitting it is reported, never a quiet stop.
const MAX_ENTRIES: usize = 20_000;

pub(crate) fn is_zoo(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::Zoo)
}

/// A writer that takes at most `left` bytes and fails past them.
struct Bounded {
    out: Vec<u8>,
    left: usize,
    over: bool,
}

impl std::io::Write for Bounded {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() > self.left {
            self.over = true;
            return Err(std::io::Error::other("past the declared size"));
        }
        self.left -= b.len();
        self.out.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// LZD: LZW over codes of 9 to 13 bits read low bit first, 256 clearing the
/// table and 257 ending the data. Codes widen by a bit once the table fills
/// their range. From the constants and decoder of zoo 2.10 (`lzconst.h`,
/// `lzd.c`, public domain).
fn lzd(raw: &[u8], out: &mut impl std::io::Write) -> Result<(), ()> {
    const CLEAR: u16 = 256;
    const END: u16 = 257;
    const FIRST_FREE: u16 = 258;
    const MAX_BITS: u32 = 13;
    const TABLE: usize = 1 << MAX_BITS;
    let mut prefix = vec![0u16; TABLE];
    let mut suffix = vec![0u8; TABLE];
    for (i, s) in suffix.iter_mut().enumerate().take(256) {
        *s = i as u8;
    }
    let (mut bits, mut free, mut old) = (9u32, FIRST_FREE, None::<u16>);
    // The bit the next code starts at, in a u64: on 32-bit targets a count of
    // bits overflows `usize` past 512 MiB.
    let mut at = 0u64;
    let mut word = Vec::new();
    loop {
        // The next code, or the end of the data without its end code.
        if at + u64::from(bits) > raw.len() as u64 * 8 {
            return Err(());
        }
        let i = (at / 8) as usize;
        let b = |i: usize| u32::from(raw.get(i).copied().unwrap_or(0));
        let w = b(i) | b(i + 1) << 8 | b(i + 2) << 16;
        let code = ((w >> (at % 8)) & ((1 << bits) - 1)) as u16;
        at += u64::from(bits);
        match (code, old) {
            (CLEAR, _) => {
                (bits, free, old) = (9, FIRST_FREE, None);
                continue;
            }
            (END, _) => return Ok(()),
            (c, None) if c < 256 => {
                out.write_all(&[c as u8]).map_err(|_| ())?;
                old = Some(c);
                continue;
            }
            (_, None) => return Err(()),
            _ => {}
        }
        let prev = old.ok_or(())?;
        // The word the code names, last byte first. A code one past the
        // table is the previous word and its own first byte.
        word.clear();
        let mut c = match code.cmp(&free) {
            std::cmp::Ordering::Less => code,
            std::cmp::Ordering::Equal => {
                word.push(0);
                prev
            }
            std::cmp::Ordering::Greater => return Err(()),
        };
        while c >= FIRST_FREE {
            word.push(suffix[c as usize]);
            c = prefix[c as usize];
        }
        word.push(c as u8);
        if code == free {
            word[0] = c as u8;
        }
        word.reverse();
        out.write_all(&word).map_err(|_| ())?;
        // zoo clears a full table before another code; one that comes anyway
        // is read with the table as it stands.
        if usize::from(free) < TABLE {
            prefix[free as usize] = prev;
            suffix[free as usize] = word[0];
            free += 1;
            if u32::from(free) >= 1 << bits && bits < MAX_BITS {
                bits += 1;
            }
        }
        old = Some(code);
    }
}

/// Decode one member's bytes, or why they could not be.
fn decode(method: Method, raw: &[u8], org_size: u32, cap: u64) -> Result<Vec<u8>, &'static str> {
    match method {
        Method::Stored => Ok(raw.to_vec()),
        Method::Lzw => {
            // `org_size` is what the budget was checked against, and LZW
            // expands a few thousand times, so the output stops there.
            let mut out = Bounded {
                out: Vec::new(),
                left: org_size as usize,
                over: false,
            };
            match lzd(raw, &mut out) {
                Ok(()) => Ok(out.out),
                Err(_) if out.over => Err("ZOO member decodes past its declared size"),
                Err(_) => Err("ZOO member could not be LZW-decoded"),
            }
        }
        Method::Lh5 => {
            use delharc::decode::Decoder;
            // `org_size` decides the output length, so it is capped first: a
            // crafted entry declaring 4 GB must not allocate it.
            let want = (org_size as u64).min(cap) as usize;
            let mut dec = delharc::decode::DecoderAny::new_from_compression(
                delharc::CompressionMethod::Lh5,
                raw,
            );
            let mut out = vec![0u8; want];
            dec.fill_buffer(&mut out)
                .map_err(|_| "ZOO member could not be LZH-decoded")?;
            Ok(out)
        }
        Method::Unknown(_) => Err("ZOO member uses a compression method exav does not decode"),
    }
}

pub(crate) fn extract_zoo(data: &[u8], budget: &mut Budget, visit: Sink) -> crate::Extracted {
    if !is_zoo(data) {
        return Ok(None);
    }
    let Some(header) = data.get(..ZOO_HEADER_SIZE).and_then(Header::parse) else {
        // The magic said ZOO; failing to read the header leaves every member
        // unexamined, which must not pass quietly.
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "<zoo-archive>".to_string(),
                data.len() as u64,
                false,
                "ZOO archive header could not be read",
            ),
            budget,
        ));
    };

    let mut at = header.start as usize;
    let mut seen = 0usize;
    // The directory is a chain of offsets, and a crafted archive can point one
    // entry back at another. Visiting an offset twice is the cycle.
    let mut visited = std::collections::HashSet::new();
    loop {
        if !visited.insert(at) {
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    "<zoo-directory>".to_string(),
                    0,
                    false,
                    "ZOO directory chain loops back on itself; the rest is unreachable",
                ),
                budget,
            ));
        }
        // The chain ends at an entry whose next offset is zero, which can be
        // short of the fixed header: its tag, type and method, then that
        // offset.
        let rest = data.get(at..).unwrap_or(&[]);
        let le32 = |o: usize| {
            crate::bytes::at(rest, o, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        if rest.len() < DIRENT_HEADER_SIZE
            && le32(0) == Some(super::zoo_parse::ZOO_TAG)
            && le32(6) == Some(0)
        {
            break;
        }
        let Some(fixed) = data.get(at..).and_then(|b| b.get(..DIRENT_HEADER_SIZE)) else {
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    "<zoo-directory>".to_string(),
                    0,
                    false,
                    "ZOO directory entry runs past the end of the archive; the \
                     members after that point are unreachable",
                ),
                budget,
            ));
        };
        let Some(entry) = DirEntry::parse(fixed) else {
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    "<zoo-directory>".to_string(),
                    0,
                    false,
                    "ZOO directory chain broke; the members after that point are \
                     unreachable",
                ),
                budget,
            ));
        };
        // A zero data offset marks the end-of-directory sentinel entry: it names
        // nothing and holds nothing.
        if entry.offset == 0 && entry.org_size == 0 {
            break;
        }
        seen += 1;
        if seen > MAX_ENTRIES {
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    format!("<zoo-entries-beyond-{MAX_ENTRIES}>"),
                    0,
                    false,
                    "too many ZOO members to walk them all",
                ),
                budget,
            ));
        }

        let var = data
            .get(at + DIRENT_HEADER_SIZE..)
            .map(|b| &b[..b.len().min(entry.var_dir_len as usize)])
            .unwrap_or(&[]);
        let name = entry.path(var);

        budget.count_entry()?;
        let cap = budget.reserve()?;
        if entry.org_size as u64 > cap {
            if let Some(r) = visit(
                Entry::over_limit(
                    name,
                    entry.size_now as u64,
                    "ZOO member exceeds the per-member size budget",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
        } else {
            let raw = data
                .get(entry.offset as usize..)
                .map(|b| &b[..b.len().min(entry.size_now as usize)]);
            let decoded = match raw {
                None => Err("ZOO member data lies past the end of the archive"),
                Some(raw) if (raw.len() as u32) < entry.size_now => {
                    Err("ZOO member data is truncated")
                }
                Some(raw) => decode(entry.method, raw, entry.org_size, cap),
            };
            match decoded {
                Ok(bytes) => {
                    // A CRC-16 mismatch after a full decode hides nothing: the
                    // bytes are scanned, as a ZIP member's are, and the entry
                    // says so only when checksums are verified.
                    let ok = !budget.should_verify_checksums() || crc16_arc(&bytes) == entry.crc16;
                    budget.commit(bytes.len() as u64);
                    let mut e = Entry::new(name, bytes);
                    e.comp_size = entry.size_now as u64;
                    if !ok {
                        e.unsupported = Some(
                            "ZOO member failed its recorded CRC-16; the bytes were \
                                  scanned but may be wrong",
                        );
                    }
                    if let Some(r) = visit(e, budget) {
                        return Ok(Some(r));
                    }
                }
                Err(reason) => {
                    // One member exav cannot decode must not stop the rest: the
                    // directory chain is still intact, so keep walking.
                    let mut e = Entry::unsupported(name, entry.size_now as u64, false, reason);
                    if matches!(entry.method, Method::Unknown(_)) {
                        e = e.of_kind(crate::tree::ReasonKind::Unsupported);
                    }
                    if let Some(r) = visit(e, budget) {
                        return Ok(Some(r));
                    }
                }
            }
        }

        if entry.next == 0 {
            break;
        }
        at = entry.next as usize;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::lzd;

    /// Codes written low bit first, at the width the decoder reads them.
    struct Enc {
        out: Vec<u8>,
        acc: u32,
        n: u32,
        bits: u32,
        /// The decoder's next free code, one behind the encoder's.
        dec_free: u32,
        emitted: u32,
    }

    impl Enc {
        fn emit(&mut self, code: u16) {
            self.acc |= u32::from(code) << self.n;
            self.n += self.bits;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
            if self.emitted > 0 {
                self.dec_free += 1;
                if self.dec_free >= 1 << self.bits && self.bits < 13 {
                    self.bits += 1;
                }
            }
            self.emitted += 1;
        }
    }

    /// `data` as LZD codes, the table cleared after every `clear_after` input
    /// bytes, and the widest code used. The widths follow the decoder's rule;
    /// the fixtures of the zoo suite are what tie that rule to zoo's output.
    fn encode(data: &[u8], clear_after: usize) -> (Vec<u8>, u32) {
        let mut e = Enc {
            out: Vec::new(),
            acc: 0,
            n: 0,
            bits: 9,
            dec_free: 258,
            emitted: 0,
        };
        let mut widest = 9;
        for (i, part) in data.chunks(clear_after).enumerate() {
            if i > 0 {
                e.emit(256);
                (e.bits, e.dec_free, e.emitted) = (9, 258, 0);
            }
            let mut table = std::collections::HashMap::new();
            let mut next = 258u16;
            let mut w = u16::from(part[0]);
            for &c in &part[1..] {
                match table.get(&(w, c)) {
                    Some(&code) => w = code,
                    None => {
                        e.emit(w);
                        assert!(next < 8191, "the test input fills the table");
                        table.insert((w, c), next);
                        next += 1;
                        w = u16::from(c);
                    }
                }
                widest = widest.max(e.bits);
            }
            e.emit(w);
        }
        e.emit(257);
        let pad = e.bits;
        e.bits = 7;
        e.emit(0);
        e.bits = pad;
        (e.out, widest)
    }

    fn text(len: usize) -> Vec<u8> {
        let mut x = 0x2545_f491u32;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                b"etaoin shrdlu"[(x % 13) as usize]
            })
            .collect()
    }

    #[test]
    fn lzd_reads_codes_of_13_bits() {
        let data = text(20_000);
        let (lzd_data, widest) = encode(&data, usize::MAX);
        assert_eq!(widest, 13);
        let mut out = Vec::new();
        lzd(&lzd_data, &mut out).unwrap();
        assert_eq!(out, data);
    }

    /// The last entry of the chain can stop right after its next offset (10
    /// bytes): the members before it are the whole archive.
    #[test]
    fn a_chain_ending_in_a_ten_byte_entry_is_complete() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/zoo/store.zoo");
        let full = crate::read_fixture(path).unwrap();
        let read = |data: &[u8]| {
            let mut budget = crate::Budget::new(crate::Limits::default());
            crate::extract(crate::Format::Zoo, &data, &mut budget)
                .unwrap()
                .into_iter()
                .map(|e| {
                    (
                        e.name,
                        e.data.len(),
                        super::crc16_arc(&e.data),
                        e.unsupported,
                    )
                })
                .collect::<Vec<_>>()
        };
        let want = read(&full);
        assert!(
            !want.is_empty() && want.iter().all(|m| m.3.is_none()),
            "{want:?}"
        );
        // Follow the chain from the header's start offset to the terminator,
        // and keep its first 10 bytes.
        let le32 = |o: usize| u32::from_le_bytes(full[o..o + 4].try_into().unwrap()) as usize;
        let mut at = le32(24);
        while le32(at + 6) != 0 {
            at = le32(at + 6);
        }
        assert_eq!(le32(at), super::super::zoo_parse::ZOO_TAG as usize);
        assert_eq!(read(&full[..at + 10]), want);
    }

    #[test]
    fn lzd_starts_over_at_a_clear_code() {
        let data = text(40_000);
        let mut out = Vec::new();
        lzd(&encode(&data, 20_000).0, &mut out).unwrap();
        assert_eq!(out, data);
    }
}
