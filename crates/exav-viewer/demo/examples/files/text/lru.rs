//! A small least-recently-used cache. CC0-1.0, exav project.
use std::collections::HashMap;
use std::hash::Hash;

/// A cache that keeps at most `capacity` entries and drops the one used longest ago.
pub struct Lru<K, V> {
    capacity: usize,
    tick: u64,
    entries: HashMap<K, (V, u64)>,
}

impl<K: Hash + Eq + Clone, V> Lru<K, V> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "a cache holds at least one entry");
        Lru { capacity, tick: 0, entries: HashMap::with_capacity(capacity) }
    }

    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.tick += 1;
        let tick = self.tick;
        self.entries.get_mut(key).map(|(v, used)| {
            *used = tick;
            &*v
        })
    }

    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        self.tick += 1;
        if !self.entries.contains_key(&key) && self.entries.len() == self.capacity {
            let oldest = self.entries.iter().min_by_key(|(_, (_, used))| *used).map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(key, (value, self.tick)).map(|(v, _)| v)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_the_least_recently_used() {
        let mut c = Lru::new(2);
        c.put("a", 1);
        c.put("b", 2);
        assert_eq!(c.get(&"a"), Some(&1));
        c.put("c", 3);
        assert_eq!(c.get(&"b"), None);
        assert_eq!(c.len(), 2);
    }
}
