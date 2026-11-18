//! IWA ("iWork archive") streams: chunks of Snappy blocks, each a 1-byte
//! type (0) and a 24-bit length; uncompressed, a run of archives, each a
//! varint length, a TSP.ArchiveInfo and the payloads its MessageInfos
//! count. Objects are indexed by their identifier.

pub mod proto;
pub mod snappy;

use proto::{Msg, varint};
use std::collections::HashMap;

/// The objects of a document's IWA streams.
#[derive(Default)]
pub struct Store {
    files: Vec<Vec<u8>>,
    /// identifier: (message type, file, start, length).
    objects: HashMap<u64, (u32, usize, usize, usize)>,
}

/// A stream that decompresses past the bytes it was allowed.
#[derive(Debug, PartialEq, Eq)]
pub struct OverBudget;

/// What an object of the index holds, its key and its value.
const OBJECT_COST: usize = size_of::<(u64, (u32, usize, usize, usize))>();

impl Store {
    /// Adds a stream; `budget` is the bytes it may still decompress to.
    /// Returns the bytes used, its index included; past `budget`, an error
    /// rather than a part of the stream.
    pub fn add(&mut self, data: &[u8], budget: usize) -> Result<usize, OverBudget> {
        let mut out = Vec::new();
        let mut p = 0usize;
        while p + 4 <= data.len() {
            let kind = data[p];
            let len = usize::from(data[p + 1])
                | usize::from(data[p + 2]) << 8
                | usize::from(data[p + 3]) << 16;
            p += 4;
            let Some(chunk) = data.get(p..p + len) else {
                break;
            };
            p += len;
            if kind != 0 {
                continue;
            }
            let before = out.len();
            if snappy::declared_len(chunk).is_some_and(|(n, _)| before.saturating_add(n) > budget) {
                return Err(OverBudget);
            }
            if snappy::decompress(chunk, &mut out, budget).is_none() {
                // Some writers store a chunk uncompressed.
                out.truncate(before);
                if out.len() + chunk.len() > budget {
                    return Err(OverBudget);
                }
                out.extend_from_slice(chunk);
            }
        }
        let mut used = out.len();
        let fi = self.files.len();
        let d = &out;
        let mut p = 0usize;
        while p < d.len() {
            let Some(n) = varint(d, &mut p).and_then(|n| usize::try_from(n).ok()) else {
                break;
            };
            let Some(info) = d.get(p..p.saturating_add(n)) else {
                break;
            };
            p += n;
            let info = Msg(info);
            let id = info.uint(1).unwrap_or(0);
            let mut first = true;
            for mi in info.msgs(2).take(64) {
                let kind = mi.uint(1).unwrap_or(0) as u32;
                let len = mi.uint(3).unwrap_or(0) as usize;
                if p.saturating_add(len) > d.len() {
                    p = d.len();
                    break;
                }
                if first
                    && id != 0
                    && let std::collections::hash_map::Entry::Vacant(v) = self.objects.entry(id)
                {
                    v.insert((kind, fi, p, len));
                    used = used.saturating_add(OBJECT_COST);
                }
                first = false;
                p += len;
            }
        }
        self.files.push(out);
        Ok(used)
    }

    /// An object: its message type and its first message.
    pub fn get(&self, id: u64) -> Option<(u32, Msg<'_>)> {
        let &(kind, f, start, len) = self.objects.get(&id)?;
        Some((kind, Msg(self.files.get(f)?.get(start..start + len)?)))
    }

    /// An object's message, when it is of type `kind`.
    pub fn typed(&self, id: u64, kind: u32) -> Option<Msg<'_>> {
        self.get(id).filter(|o| o.0 == kind).map(|o| o.1)
    }

    /// A store of one stream holding `objects` (identifier, message type,
    /// payload), for tests.
    #[cfg(test)]
    pub fn of(objects: &[(u64, u32, proto::write::W)]) -> Store {
        let mut s = Store::default();
        s.add(&Self::stream(objects).0, usize::MAX)
            .expect("no budget");
        s
    }

    /// One stream holding `objects`, and what it decompresses to, for tests.
    #[cfg(test)]
    pub fn stream(objects: &[(u64, u32, proto::write::W)]) -> (Vec<u8>, usize) {
        use proto::write::W;
        let mut raw = vec![];
        for (id, kind, m) in objects {
            let info = W::default().uint(1, *id).msg(
                2,
                W::default()
                    .uint(1, u64::from(*kind))
                    .uint(3, m.0.len() as u64),
            );
            raw.extend(W::varint_len(info.0.len() as u64));
            raw.extend(&info.0);
            raw.extend(&m.0);
        }
        let block = snappy::literal_block(&raw);
        let mut stream = vec![
            0u8,
            block.len() as u8,
            (block.len() >> 8) as u8,
            (block.len() >> 16) as u8,
        ];
        stream.extend(block);
        (stream, raw.len())
    }

    pub fn ids_of(&self, kind: u32) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .objects
            .iter()
            .filter(|o| o.1.0 == kind)
            .map(|o| *o.0)
            .collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::{OBJECT_COST, OverBudget, Store, proto::write::W};

    /// One chunk of type 0 holding `block`.
    fn chunk(block: &[u8]) -> Vec<u8> {
        let n = block.len();
        let mut c = vec![0, n as u8, (n >> 8) as u8, (n >> 16) as u8];
        c.extend_from_slice(block);
        c
    }

    /// A stream that decompresses past what is left is refused whole, not
    /// kept in part or as its compressed bytes.
    #[test]
    fn a_stream_over_its_budget_is_refused() {
        let objects = [(1, 10000, W::default().bytes(3, &[b'x'; 300]))];
        let (stream, raw) = Store::stream(&objects);
        assert_eq!(Store::default().add(&stream, raw - 1), Err(OverBudget));
        assert_eq!(
            Store::default().add(&stream, raw + OBJECT_COST),
            Ok(raw + OBJECT_COST)
        );
        // 300 bytes in 18: one literal, then copies 64 long at distance 1.
        let mut packed = vec![0xAC, 0x02, 0x00, b'x'];
        for _ in 0..4 {
            packed.extend([63 << 2 | 2, 1, 0]);
        }
        packed.extend([42 << 2 | 2, 1, 0]);
        assert_eq!(Store::default().add(&chunk(&packed), 100), Err(OverBudget));
        // Not a Snappy block (its length does not read): kept as it is
        // stored, within the budget only.
        let stored = [0xFFu8; 200];
        assert_eq!(Store::default().add(&chunk(&stored), 100), Err(OverBudget));
        assert_eq!(Store::default().add(&chunk(&stored), 200), Ok(200));
    }

    /// The index of the objects is charged with the bytes.
    #[test]
    fn each_object_indexed_is_charged() {
        let objects = [
            (1, 10000, W::default().uint(1, 5)),
            (2, 2001, W::default().uint(1, 6)),
        ];
        let (stream, raw) = Store::stream(&objects);
        assert_eq!(
            Store::default().add(&stream, usize::MAX),
            Ok(raw + 2 * OBJECT_COST)
        );
    }
}
