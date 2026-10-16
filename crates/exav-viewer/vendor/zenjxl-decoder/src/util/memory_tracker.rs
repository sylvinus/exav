// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Memory tracking for decoder resource limits.
//!
//! Provides a thread-safe memory tracker that can be used to enforce
//! `max_memory_bytes` limits during decoding.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Error, Result};

/// A thread-safe memory tracker for enforcing memory limits.
///
/// Clone is cheap (Arc-based) and all clones share the same counter.
#[derive(Debug, Clone, Default)]
pub struct MemoryTracker {
    inner: Option<Arc<MemoryTrackerInner>>,
}

#[derive(Debug)]
struct MemoryTrackerInner {
    allocated: AtomicU64,
    limit: u64,
}

impl MemoryTracker {
    /// Creates a new memory tracker with no limit (unlimited).
    pub fn unlimited() -> Self {
        Self { inner: None }
    }

    /// Creates a new memory tracker with the specified byte limit.
    pub fn with_limit(limit: u64) -> Self {
        Self {
            inner: Some(Arc::new(MemoryTrackerInner {
                allocated: AtomicU64::new(0),
                limit,
            })),
        }
    }

    /// Creates a memory tracker from an optional limit.
    pub fn from_limit(limit: Option<u64>) -> Self {
        match limit {
            Some(limit) => Self::with_limit(limit),
            None => Self::unlimited(),
        }
    }

    /// Returns true if this tracker has a limit configured.
    pub fn has_limit(&self) -> bool {
        self.inner.is_some()
    }

    /// Returns the current allocated bytes.
    pub fn allocated(&self) -> u64 {
        self.inner
            .as_ref()
            .map(|i| i.allocated.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Returns the limit, or None if unlimited.
    pub fn limit(&self) -> Option<u64> {
        self.inner.as_ref().map(|i| i.limit)
    }

    /// Attempts to allocate `bytes` from the budget.
    /// Returns Ok(()) if successful, or Error::LimitExceeded if over budget.
    pub fn try_allocate(&self, bytes: u64) -> Result<()> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };

        // Use fetch_add and check after - this is slightly optimistic but avoids
        // the complexity of a CAS loop. In the worst case we slightly exceed the
        // limit temporarily.
        let prev = inner.allocated.fetch_add(bytes, Ordering::Relaxed);
        let new_total = prev.saturating_add(bytes);

        if new_total > inner.limit {
            // Rollback the allocation
            inner.allocated.fetch_sub(bytes, Ordering::Relaxed);
            return Err(Error::LimitExceeded {
                resource: "memory_bytes",
                actual: new_total,
                limit: inner.limit,
            });
        }

        Ok(())
    }

    /// Releases `bytes` back to the budget.
    /// Call this when deallocating tracked memory.
    pub fn release(&self, bytes: u64) {
        if let Some(inner) = &self.inner {
            inner.allocated.fetch_sub(bytes, Ordering::Relaxed);
        }
    }

    /// Checks if allocating `bytes` would exceed the limit without actually allocating.
    pub fn would_exceed(&self, bytes: u64) -> bool {
        let Some(inner) = &self.inner else {
            return false;
        };
        let current = inner.allocated.load(Ordering::Relaxed);
        current.saturating_add(bytes) > inner.limit
    }

    /// Checks if allocating `bytes` would exceed the budget.
    /// Unlike `try_allocate`, this does NOT reserve the bytes.
    /// Use for Vec/temporary allocations where RAII release tracking is impractical.
    pub fn check_alloc(&self, bytes: u64) -> Result<()> {
        if self.would_exceed(bytes) {
            let Some(inner) = &self.inner else {
                return Ok(());
            };
            return Err(Error::LimitExceeded {
                resource: "memory_bytes",
                actual: inner
                    .allocated
                    .load(Ordering::Relaxed)
                    .saturating_add(bytes),
                limit: inner.limit,
            });
        }
        Ok(())
    }
}

/// A guard that automatically releases memory when dropped.
/// Use this to ensure memory is released even if an error occurs.
#[derive(Debug)]
pub struct MemoryGuard {
    tracker: MemoryTracker,
    bytes: u64,
}

impl MemoryGuard {
    /// Creates a new memory guard that will release `bytes` on drop.
    pub fn new(tracker: MemoryTracker, bytes: u64) -> Self {
        Self { tracker, bytes }
    }

    /// Disarms the guard so it will NOT release memory on drop.
    /// Use when transferring ownership of the allocation to another structure
    /// (e.g., `OwnedRawImage`'s `Drop`).
    ///
    /// Unlike `std::mem::forget`, this properly drops the internal `MemoryTracker`
    /// clone, avoiding a 32-byte `Arc` leak per call.
    pub fn disarm(mut self) {
        self.bytes = 0;
        // self drops normally here — tracker Arc refcount decrements,
        // but release(0) is a no-op on the budget.
    }

    /// Consumes the guard without releasing memory.
    ///
    /// **Deprecated**: use [`disarm`](Self::disarm) instead. `forget` leaks the
    /// internal `Arc` allocation (32 bytes per call) because `std::mem::forget`
    /// prevents the destructor from running.
    #[deprecated(note = "use disarm() instead — forget() leaks the internal Arc")]
    #[allow(dead_code)]
    pub fn forget(self) {
        std::mem::forget(self);
    }
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        self.tracker.release(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlimited() {
        let tracker = MemoryTracker::unlimited();
        assert!(!tracker.has_limit());
        assert!(tracker.try_allocate(u64::MAX).is_ok());
    }

    #[test]
    fn test_with_limit() {
        let tracker = MemoryTracker::with_limit(1000);
        assert!(tracker.has_limit());
        assert_eq!(tracker.limit(), Some(1000));

        // Should succeed
        assert!(tracker.try_allocate(500).is_ok());
        assert_eq!(tracker.allocated(), 500);

        // Should succeed (exactly at limit)
        assert!(tracker.try_allocate(500).is_ok());
        assert_eq!(tracker.allocated(), 1000);

        // Should fail (over limit)
        assert!(tracker.try_allocate(1).is_err());
        assert_eq!(tracker.allocated(), 1000); // Unchanged after failed alloc

        // Release some memory
        tracker.release(500);
        assert_eq!(tracker.allocated(), 500);

        // Should succeed now
        assert!(tracker.try_allocate(100).is_ok());
        assert_eq!(tracker.allocated(), 600);
    }

    #[test]
    fn test_clone_shares_state() {
        let tracker1 = MemoryTracker::with_limit(1000);
        let tracker2 = tracker1.clone();

        tracker1.try_allocate(500).unwrap();
        assert_eq!(tracker2.allocated(), 500);

        tracker2.try_allocate(300).unwrap();
        assert_eq!(tracker1.allocated(), 800);
    }

    #[test]
    fn test_memory_guard() {
        let tracker = MemoryTracker::with_limit(1000);
        tracker.try_allocate(500).unwrap();

        {
            let _guard = MemoryGuard::new(tracker.clone(), 500);
            // Memory is tracked
        }
        // Guard dropped, memory released
        assert_eq!(tracker.allocated(), 0);
    }

    #[test]
    fn test_memory_guard_disarm() {
        let tracker = MemoryTracker::with_limit(1000);
        tracker.try_allocate(500).unwrap();

        let guard = MemoryGuard::new(tracker.clone(), 500);
        guard.disarm();
        // Memory NOT released (disarm zeroed the guard's bytes)
        assert_eq!(tracker.allocated(), 500);
    }
}
