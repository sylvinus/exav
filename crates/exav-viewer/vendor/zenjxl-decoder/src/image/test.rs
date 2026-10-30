// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use arbtest::arbitrary::Arbitrary;

use crate::error::Result;
use crate::util::MemoryTracker;

use super::{Image, ImageDataType, Rect};

impl<T: ImageDataType> Image<T> {
    #[cfg(test)]
    pub fn new_random<R: rand::Rng>(size: (usize, usize), rng: &mut R) -> Result<Image<T>> {
        let mut img = Self::new(size)?;
        for y in 0..size.1 {
            img.row_mut(y).iter_mut().for_each(|x| *x = T::random(rng));
        }
        Ok(img)
    }

    #[cfg(test)]
    pub fn new_range(size: (usize, usize), start: f32, step: f32) -> Result<Image<T>> {
        let mut img = Self::new(size)?;
        for y in 0..size.1 {
            img.row_mut(y).iter_mut().enumerate().for_each(|(x, val)| {
                *val = T::from_f64((start + step * (y * size.0 + x) as f32) as f64)
            });
        }
        Ok(img)
    }
}

#[test]
fn huge_image() {
    assert!(Image::<u8>::new((1 << 28, 1 << 28)).is_err());
}

#[test]
fn rect_basic() -> Result<()> {
    let mut image = Image::<u8>::new((32, 42))?;
    assert_eq!(
        image
            .get_rect_mut(Rect {
                origin: (31, 40),
                size: (1, 1)
            })
            .size(),
        (1, 1)
    );
    assert_eq!(
        image
            .get_rect_mut(Rect {
                origin: (0, 0),
                size: (1, 1)
            })
            .size(),
        (1, 1)
    );
    image
        .get_rect_mut(Rect {
            origin: (30, 30),
            size: (1, 1),
        })
        .row(0)[0] = 1;
    assert_eq!(image.row(30)[30], 1);
    Ok(())
}

#[test]
#[should_panic(expected = "image byte offset must be aligned to element size")]
fn image_from_raw_rejects_misaligned_offset() {
    use super::OwnedRawImage;
    // Regression test (libjxl/jxl-rs#757): Image<T>::from_raw used to check the base
    // RawImageBuffer alignment but not OwnedRawImage's byte offset. This safe construction
    // leaves the allocation itself 4-byte aligned while making row(0) start one byte later;
    // accepting it would let Image::<u32>::row create a misaligned &[u32], which is UB on the
    // `allow-unsafe` cast path.
    let raw = OwnedRawImage::new_zeroed_with_padding((4, 1), (1, 0), (1, 0)).unwrap();
    let _ = Image::<u32>::from_raw(raw);
}

fn f64_conversions<T: ImageDataType + Eq + for<'a> Arbitrary<'a>>() {
    arbtest::arbtest(|u| {
        let t = T::arbitrary(u)?;
        assert_eq!(t, T::from_f64(t.to_f64()));
        Ok(())
    });
}

#[test]
fn u8_f64_conv() {
    f64_conversions::<u8>();
}

#[test]
fn u16_f64_conv() {
    f64_conversions::<u16>();
}

#[test]
fn u32_f64_conv() {
    f64_conversions::<u32>();
}

#[test]
fn i8_f64_conv() {
    f64_conversions::<i8>();
}

#[test]
fn i16_f64_conv() {
    f64_conversions::<i16>();
}

#[test]
fn i32_f64_conv() {
    f64_conversions::<i32>();
}

#[test]
fn f32_f64_conv() {
    arbtest::arbtest(|u| {
        let t = f32::arbitrary(u)?;
        if !t.is_nan() {
            assert_eq!(t, f32::from_f64(t.to_f64()));
        }
        Ok(())
    });
}

#[test]
fn tracked_image_releases_on_drop() {
    let tracker = MemoryTracker::with_limit(1_000_000);
    {
        let _img = Image::<f32>::new_tracked((100, 100), &tracker).unwrap();
        assert!(tracker.allocated() > 0, "budget should be reserved");
    }
    assert_eq!(tracker.allocated(), 0, "budget should be released on drop");
}

#[test]
fn tracked_image_budget_is_accurate() {
    let tracker = MemoryTracker::with_limit(1_000_000);
    let expected = Image::<f32>::allocation_size((64, 64));
    let _img = Image::<f32>::new_tracked((64, 64), &tracker).unwrap();
    assert_eq!(tracker.allocated(), expected);
}

#[test]
fn tracked_image_try_clone_reserves_and_releases() {
    let tracker = MemoryTracker::with_limit(1_000_000);
    let alloc_size = Image::<f32>::allocation_size((50, 50));
    let img = Image::<f32>::new_tracked((50, 50), &tracker).unwrap();
    assert_eq!(tracker.allocated(), alloc_size);

    let clone = img.try_clone().unwrap();
    assert_eq!(tracker.allocated(), alloc_size * 2);

    drop(clone);
    assert_eq!(tracker.allocated(), alloc_size);

    drop(img);
    assert_eq!(tracker.allocated(), 0);
}

#[test]
fn tracked_image_exceeds_budget() {
    let tracker = MemoryTracker::with_limit(1000);
    // A 100x100 f32 image needs ~40000 bytes, well over the 1000 byte limit
    assert!(Image::<f32>::new_tracked((100, 100), &tracker).is_err());
    assert_eq!(
        tracker.allocated(),
        0,
        "budget should be rolled back on failure"
    );
}

#[test]
fn tracked_try_clone_exceeds_budget() {
    let alloc_size = Image::<f32>::allocation_size((50, 50));
    // Budget for exactly one image
    let tracker = MemoryTracker::with_limit(alloc_size);
    let img = Image::<f32>::new_tracked((50, 50), &tracker).unwrap();
    assert_eq!(tracker.allocated(), alloc_size);

    // Clone should fail — no budget left
    assert!(img.try_clone().is_err());
    assert_eq!(tracker.allocated(), alloc_size, "original still tracked");

    drop(img);
    assert_eq!(tracker.allocated(), 0);
}

#[test]
fn untracked_image_ignores_tracker() {
    let tracker = MemoryTracker::with_limit(1_000_000);
    {
        let _img = Image::<f32>::new((100, 100)).unwrap();
        assert_eq!(
            tracker.allocated(),
            0,
            "untracked image should not affect tracker"
        );
    }
    assert_eq!(tracker.allocated(), 0);
}
