// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use crate::error::Result;
use crate::image::Image;
use num_traits::abs;

#[allow(clippy::excessive_precision)]
const W_SIDE: f32 = 0.20345139757231578;
#[allow(clippy::excessive_precision)]
const W_CORNER: f32 = 0.0334829185968739;
const W_CENTER: f32 = 1.0 - 4.0 * (W_SIDE + W_CORNER);

fn compute_pixel_channel(
    dc_factor: f32,
    gap: f32,
    x: usize,
    row_top: &[f32],
    row: &[f32],
    row_bottom: &[f32],
) -> (f32, f32, f32) {
    let tl = row_top[x - 1];
    let tc = row_top[x];
    let tr = row_top[x + 1];
    let ml = row[x - 1];
    let mc = row[x];
    let mr = row[x + 1];
    let bl = row_bottom[x - 1];
    let bc = row_bottom[x];
    let br = row_bottom[x + 1];
    let corner = tl + tr + bl + br;
    let side = ml + mr + tc + bc;
    let sm = corner * W_CORNER + side * W_SIDE + mc * W_CENTER;
    (mc, sm, gap.max(abs((mc - sm) / dc_factor)))
}

pub fn adaptive_lf_smoothing(
    lf_factors: [f32; 3],
    lf_image: &mut [Image<f32>; 3],
    #[cfg(feature = "threads")] parallel: bool,
) -> Result<()> {
    let xsize = lf_image[0].size().0;
    let ysize = lf_image[0].size().1;
    if ysize <= 2 || xsize <= 2 {
        return Ok(());
    }
    // Use new_uninit: every pixel is written (borders copied, interior computed).
    let mut smoothed: [Image<f32>; 3] = [
        Image::<f32>::new_uninit((xsize, ysize))?,
        Image::<f32>::new_uninit((xsize, ysize))?,
        Image::<f32>::new_uninit((xsize, ysize))?,
    ];
    // Copy border rows (row 0 and ysize-1) and border columns (x=0, x=xsize-1).
    for c in 0..3 {
        for y in [0, ysize - 1] {
            smoothed[c].row_mut(y).copy_from_slice(lf_image[c].row(y));
        }
    }

    #[cfg(feature = "threads")]
    if parallel && ysize > 4 {
        use rayon::prelude::*;

        // Zero-allocation parallel smoothing: write directly into pre-allocated
        // smoothed images via all_rows_mut(). Each parallel task writes to its
        // own disjoint output row — no per-row Vec allocation or copy-back.
        let [s0, s1, s2] = &mut smoothed;
        let mut rows0 = s0.all_rows_mut();
        let mut rows1 = s1.all_rows_mut();
        let mut rows2 = s2.all_rows_mut();

        // Split into (border_top, interior, border_bottom) so the interior
        // rows can be processed in parallel without borrowing the border rows.
        // Border rows were already copied above, so we just need the interior.
        let (_, interior0) = rows0.split_at_mut(1);
        let (interior0, _) = interior0.split_at_mut(ysize - 2);
        let (_, interior1) = rows1.split_at_mut(1);
        let (interior1, _) = interior1.split_at_mut(ysize - 2);
        let (_, interior2) = rows2.split_at_mut(1);
        let (interior2, _) = interior2.split_at_mut(ysize - 2);

        // Zip the three channels' interior rows together for parallel iteration.
        // Each tuple element is &mut &mut [f32], which we iterate over.
        interior0
            .par_iter_mut()
            .zip(interior1.par_iter_mut())
            .zip(interior2.par_iter_mut())
            .enumerate()
            .for_each(|(i, ((out0, out1), out2))| {
                let y = i + 1; // rows 1..ysize-1
                let rows_in: [(&[f32], &[f32], &[f32]); 3] = core::array::from_fn(|c| {
                    (
                        lf_image[c].row(y - 1),
                        lf_image[c].row(y),
                        lf_image[c].row(y + 1),
                    )
                });

                // Copy border columns.
                out0[0] = rows_in[0].1[0];
                out0[xsize - 1] = rows_in[0].1[xsize - 1];
                out1[0] = rows_in[1].1[0];
                out1[xsize - 1] = rows_in[1].1[xsize - 1];
                out2[0] = rows_in[2].1[0];
                out2[xsize - 1] = rows_in[2].1[xsize - 1];

                #[allow(clippy::needless_range_loop)] // x indexes 6+ parallel arrays
                for x in 1..xsize - 1 {
                    let gap = 0.5;
                    let (mc_x, sm_x, gap) = compute_pixel_channel(
                        lf_factors[0],
                        gap,
                        x,
                        rows_in[0].0,
                        rows_in[0].1,
                        rows_in[0].2,
                    );
                    let (mc_y, sm_y, gap) = compute_pixel_channel(
                        lf_factors[1],
                        gap,
                        x,
                        rows_in[1].0,
                        rows_in[1].1,
                        rows_in[1].2,
                    );
                    let (mc_b, sm_b, gap) = compute_pixel_channel(
                        lf_factors[2],
                        gap,
                        x,
                        rows_in[2].0,
                        rows_in[2].1,
                        rows_in[2].2,
                    );
                    let factor = (3.0 - 4.0 * gap).max(0.0);
                    out0[x] = (sm_x - mc_x) * factor + mc_x;
                    out1[x] = (sm_y - mc_y) * factor + mc_y;
                    out2[x] = (sm_b - mc_b) * factor + mc_b;
                }
            });
    } else {
        smooth_serial(lf_factors, lf_image, &mut smoothed, xsize, ysize);
    }

    #[cfg(not(feature = "threads"))]
    smooth_serial(lf_factors, lf_image, &mut smoothed, xsize, ysize);

    *lf_image = smoothed;
    Ok(())
}

fn smooth_serial(
    lf_factors: [f32; 3],
    lf_image: &[Image<f32>; 3],
    smoothed: &mut [Image<f32>; 3],
    xsize: usize,
    ysize: usize,
) {
    for y in 1..ysize - 1 {
        for x in [0, xsize - 1] {
            for c in 0..3 {
                smoothed[c].row_mut(y)[x] = lf_image[c].row(y)[x];
            }
        }
        for x in 1..xsize - 1 {
            let gap = 0.5;
            let (mc_x, sm_x, gap) = compute_pixel_channel(
                lf_factors[0],
                gap,
                x,
                lf_image[0].row(y - 1),
                lf_image[0].row(y),
                lf_image[0].row(y + 1),
            );
            let (mc_y, sm_y, gap) = compute_pixel_channel(
                lf_factors[1],
                gap,
                x,
                lf_image[1].row(y - 1),
                lf_image[1].row(y),
                lf_image[1].row(y + 1),
            );
            let (mc_b, sm_b, gap) = compute_pixel_channel(
                lf_factors[2],
                gap,
                x,
                lf_image[2].row(y - 1),
                lf_image[2].row(y),
                lf_image[2].row(y + 1),
            );
            let factor = (3.0 - 4.0 * gap).max(0.0);
            smoothed[0].row_mut(y)[x] = (sm_x - mc_x) * factor + mc_x;
            smoothed[1].row_mut(y)[x] = (sm_y - mc_y) * factor + mc_y;
            smoothed[2].row_mut(y)[x] = (sm_b - mc_b) * factor + mc_b;
        }
    }
}
