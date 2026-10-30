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

impl Store {
    /// Adds a stream; `budget` is the bytes it may still decompress to.
    /// Returns the bytes used.
    pub fn add(&mut self, data: &[u8], budget: usize) -> usize {
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
            if snappy::decompress(chunk, &mut out, budget).is_none() {
                // Some writers store a chunk uncompressed.
                out.truncate(before);
                if out.len() + chunk.len() > budget {
                    break;
                }
                out.extend_from_slice(chunk);
            }
        }
        let used = out.len();
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
                if first && id != 0 {
                    self.objects.entry(id).or_insert((kind, fi, p, len));
                }
                first = false;
                p += len;
            }
        }
        self.files.push(out);
        used
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
