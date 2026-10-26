//! What a scan spends on password key derivations, and the keys it made.
//!
//! Every derivation costs time the file chooses: 7z's runs 2^`numCyclesPower`
//! SHA-256 rounds (up to 2^24) for every password tried over every folder, and
//! a disk image's PBKDF2 asks for any count a `u32` holds. None of that is
//! members, bytes or entries, which the [`Budget`](crate::Budget) counts, so it
//! is counted here, over the whole scan however many archives it opens, as
//! RAR5's was (`rar5_crypt`). A derivation past the bound is not made, and the
//! member is reported encrypted like one no password opens.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// SHA-256 rounds all the 7z derivations of one scan may add up to: about
/// 1.3 s (a round is about 20 ns), 128 derivations at 7-Zip's default of 2^19.
pub(crate) const SEVENZ_MAX_ROUNDS: u64 = 1 << 26;

/// PBKDF2 iterations all the derivations of one scan may add up to, for RAR5
/// and for disk images alike: about 0.7 s of HMACs. See `rar5_crypt`.
pub(crate) const PBKDF2_MAX_ROUNDS: u64 = 1 << 22;

/// The least a derivation is charged, so that many with a tiny count still
/// add up.
const MIN_CHARGE: u64 = 256;

/// The most keys kept, of one scan.
const MAX_KEYS: usize = 4096;

/// Adds `rounds` to `spent` unless that passes `max`; a refused derivation is
/// not charged, so one member asking for too much leaves the rest of the scan
/// its share.
pub(crate) fn charge(spent: &AtomicU64, rounds: u64, max: u64) -> bool {
    let rounds = rounds.max(MIN_CHARGE);
    let mut now = spent.load(Ordering::Relaxed);
    loop {
        let Some(next) = now.checked_add(rounds).filter(|&t| t <= max) else {
            return false;
        };
        match spent.compare_exchange_weak(now, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(seen) => now = seen,
        }
    }
}

/// A 7z key: the password as UTF-16LE, the salt, `numCyclesPower`.
type SevenZKey = (Vec<u8>, Vec<u8>, u32);

/// The derivations of one scan.
#[derive(Default)]
pub(crate) struct Kdf {
    sevenz_rounds: AtomicU64,
    sevenz_keys: Mutex<HashMap<SevenZKey, [u8; 32]>>,
}

impl Kdf {
    /// The 7z key for a password, a salt and a count, made by `derive` (which is
    /// charged `rounds`) unless this scan made it before. `None` when the scan has
    /// spent its share, or `derive` refuses.
    pub(crate) fn sevenz_key(
        &self,
        password: &[u8],
        salt: &[u8],
        cycles: u32,
        rounds: u64,
        derive: impl FnOnce() -> Option<[u8; 32]>,
    ) -> Option<[u8; 32]> {
        let id = (password.to_vec(), salt.to_vec(), cycles);
        if let Some(k) = self.sevenz_keys.lock().ok()?.get(&id) {
            return Some(*k);
        }
        if !charge(&self.sevenz_rounds, rounds, SEVENZ_MAX_ROUNDS) {
            return None;
        }
        let key = derive()?;
        if let Ok(mut keys) = self.sevenz_keys.lock() {
            if keys.len() < MAX_KEYS {
                keys.insert(id, key);
            }
        }
        Some(key)
    }

    #[cfg(test)]
    pub(crate) fn sevenz_spent(&self) -> u64 {
        self.sevenz_rounds.load(Ordering::Relaxed)
    }
}

/// A password to try, with what its derivations are counted against.
#[derive(Clone, Copy)]
pub(crate) struct Pass<'a> {
    pub word: &'a str,
    pub kdf: &'a Kdf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_made_once_and_the_scan_has_a_share() {
        let kdf = Kdf::default();
        let mut made = 0;
        for _ in 0..5 {
            let k = kdf.sevenz_key(b"pw", b"", 19, 1 << 19, || {
                made += 1;
                Some([1; 32])
            });
            assert_eq!(k, Some([1; 32]));
        }
        assert_eq!(made, 1);
        assert_eq!(kdf.sevenz_spent(), 1 << 19);
        // Other salts are other keys, until the scan has spent its share:
        // 2^26 rounds is 128 keys of 2^19.
        let mut keys = 1;
        for salt in 0u32..1000 {
            if kdf
                .sevenz_key(b"pw", &salt.to_le_bytes(), 19, 1 << 19, || Some([2; 32]))
                .is_some()
            {
                keys += 1;
            }
        }
        assert_eq!(keys, 128);
    }

    #[test]
    fn a_tiny_count_is_charged_something() {
        let spent = AtomicU64::new(0);
        let mut n = 0;
        while charge(&spent, 1, 10_000) {
            n += 1;
        }
        assert_eq!(n, 10_000 / MIN_CHARGE);
    }
}
