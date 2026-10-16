// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use crate::{
    error::Result,
    frame::modular::{
        ModularChannel, Predictor,
        predict::{PredictionData, WeightedPredictorState},
    },
    headers::modular::WeightedHeader,
    image::Image,
};

const RGB_CHANNELS: usize = 3;

// 5x5x5 color cube for the larger cube.
const LARGE_CUBE: usize = 5;

// Smaller interleaved color cube to fill the holes of the larger cube.
const SMALL_CUBE: usize = 4;
const SMALL_CUBE_BITS: usize = 2;
// SMALL_CUBE ** 3
const LARGE_CUBE_OFFSET: usize = SMALL_CUBE * SMALL_CUBE * SMALL_CUBE;

fn scale<const DENOM: usize>(value: usize, bit_depth: usize) -> i32 {
    // return (value * ((1 << bit_depth) - 1)) / DENOM;
    // We only call this function with SMALL_CUBE or LARGE_CUBE - 1 as DENOM,
    // allowing us to avoid a division here.
    const {
        assert!(DENOM == 4, "denom must be 4");
    }
    ((value * ((1 << bit_depth) - 1)) >> 2) as i32
}

// The purpose of this function is solely to extend the interpretation of
// palette indices to implicit values. If index < nb_deltas, indicating that the
// result is a delta palette entry, it is the responsibility of the caller to
// treat it as such.
fn get_palette_value(
    palette: &Image<i32>,
    index: isize,
    c: usize,
    palette_size: usize,
    bit_depth: usize,
) -> i32 {
    if index < 0 {
        const DELTA_PALETTE: [[i32; 3]; 72] = [
            [0, 0, 0],
            [4, 4, 4],
            [11, 0, 0],
            [0, 0, -13],
            [0, -12, 0],
            [-10, -10, -10],
            [-18, -18, -18],
            [-27, -27, -27],
            [-18, -18, 0],
            [0, 0, -32],
            [-32, 0, 0],
            [-37, -37, -37],
            [0, -32, -32],
            [24, 24, 45],
            [50, 50, 50],
            [-45, -24, -24],
            [-24, -45, -45],
            [0, -24, -24],
            [-34, -34, 0],
            [-24, 0, -24],
            [-45, -45, -24],
            [64, 64, 64],
            [-32, 0, -32],
            [0, -32, 0],
            [-32, 0, 32],
            [-24, -45, -24],
            [45, 24, 45],
            [24, -24, -45],
            [-45, -24, 24],
            [80, 80, 80],
            [64, 0, 0],
            [0, 0, -64],
            [0, -64, -64],
            [-24, -24, 45],
            [96, 96, 96],
            [64, 64, 0],
            [45, -24, -24],
            [34, -34, 0],
            [112, 112, 112],
            [24, -45, -45],
            [45, 45, -24],
            [0, -32, 32],
            [24, -24, 45],
            [0, 96, 96],
            [45, -24, 24],
            [24, -45, -24],
            [-24, -45, 24],
            [0, -64, 0],
            [96, 0, 0],
            [128, 128, 128],
            [64, 0, 64],
            [144, 144, 144],
            [96, 96, 0],
            [-36, -36, 36],
            [45, -24, -45],
            [45, -45, -24],
            [0, 0, -96],
            [0, 128, 128],
            [0, 96, 0],
            [45, 24, -45],
            [-128, 0, 0],
            [24, -45, 24],
            [-45, 24, -45],
            [64, 0, -64],
            [64, -64, -64],
            [96, 0, 96],
            [45, -45, 24],
            [24, 45, -45],
            [64, 64, -64],
            [128, 128, 0],
            [0, 0, -128],
            [-24, 45, -45],
        ];
        if c >= RGB_CHANNELS {
            return 0;
        }
        // Do not open the brackets, otherwise INT32_MIN negation could overflow.
        let mut index = -(index + 1) as usize;
        index %= 1 + 2 * (DELTA_PALETTE.len() - 1);
        const MULTIPLIER: [i32; 2] = [-1, 1];
        let mut result = DELTA_PALETTE[(index + 1) >> 1][c] * MULTIPLIER[index & 1];
        if bit_depth > 8 {
            result *= 1 << (bit_depth - 8);
        }
        result
    } else {
        let mut index = index as usize;
        if palette_size <= index && index < palette_size + LARGE_CUBE_OFFSET {
            if c >= RGB_CHANNELS {
                return 0;
            }
            index -= palette_size;
            index >>= c * SMALL_CUBE_BITS;
            scale::<SMALL_CUBE>(index % SMALL_CUBE, bit_depth)
                + (1 << (0.max(bit_depth as isize - 3)))
        } else if palette_size + LARGE_CUBE_OFFSET <= index {
            if c >= RGB_CHANNELS {
                return 0;
            }
            index -= palette_size + LARGE_CUBE_OFFSET;
            // TODO(eustas): should we take care of ambiguity created by
            //               index >= LARGE_CUBE ** 3 ?
            match c {
                0 => (),
                1 => {
                    index /= LARGE_CUBE;
                }
                2 => {
                    index /= LARGE_CUBE * LARGE_CUBE;
                }
                _ => (),
            }
            scale::<{ LARGE_CUBE - 1 }>(index % LARGE_CUBE, bit_depth)
        } else {
            palette.row(c)[index]
        }
    }
}

pub fn do_palette_step_general(
    buf_in: &ModularChannel,
    buf_pal: &ModularChannel,
    buf_out: &mut [&mut ModularChannel],
    num_colors: usize,
    num_deltas: usize,
    predictor: Predictor,
    wp_header: &WeightedHeader,
) -> Result<()> {
    let (w, h) = buf_in.data.size();
    let palette = &buf_pal.data;
    let bit_depth = buf_in.bit_depth.bits_per_sample().min(24) as usize;

    if w == 0 {
        // Nothing to do.
        // Avoid touching "empty" channels with non-zero height.
    } else if num_deltas == 0 && predictor == Predictor::Zero {
        for (chan_index, out) in buf_out.iter_mut().enumerate() {
            for y in 0..h {
                let row_index = buf_in.data.row(y);
                let row_out = out.data.row_mut(y);
                for x in 0..w {
                    let index = row_index[x];
                    let palette_value = get_palette_value(
                        palette,
                        index as isize,
                        /*c=*/ chan_index,
                        /*palette_size=*/ num_colors,
                        /*bit_depth=*/ bit_depth,
                    );
                    row_out[x] = palette_value;
                }
            }
        }
    } else if predictor == Predictor::Weighted {
        let w = buf_in.data.size().0;
        let mut row_prev_buf: Vec<i32> = Vec::new();
        let mut row_prev2_buf: Vec<i32> = Vec::new();
        for (chan_index, out) in buf_out.iter_mut().enumerate() {
            let mut wp_state = WeightedPredictorState::new(wp_header, w)?;
            for y in 0..h {
                let idx = buf_in.data.row(y);

                // Pre-fetch completed top rows (avoids per-pixel .row() calls)
                std::mem::swap(&mut row_prev2_buf, &mut row_prev_buf);
                if y > 0 {
                    row_prev_buf.clear();
                    row_prev_buf.extend_from_slice(out.data.row(y - 1));
                }
                let row_prev = if y > 0 {
                    Some(row_prev_buf.as_slice())
                } else {
                    None
                };
                let row_prev2 = if y > 1 {
                    Some(row_prev2_buf.as_slice())
                } else {
                    None
                };

                let mut last = if y > 0 { row_prev.unwrap()[0] } else { 0 };
                let mut last_last = last;

                for (x, &index) in idx.iter().enumerate() {
                    let palette_entry = get_palette_value(
                        palette,
                        index as isize,
                        /*c=*/ chan_index,
                        /*palette_size=*/ num_colors + num_deltas,
                        /*bit_depth=*/ bit_depth,
                    );
                    let left = last;
                    let leftleft = if x > 1 { last_last } else { left };
                    let val = if index < num_deltas as i32 {
                        let prediction_data = PredictionData::from_hoisted_neighbors(
                            left, leftleft, row_prev, row_prev2, w, None, None, None, None, None,
                            x, y, w, h,
                        );
                        let (wp_pred, _) =
                            wp_state.predict_and_property((x, y), w, &prediction_data);
                        let pred = predictor.predict_one(prediction_data, wp_pred);
                        (pred + palette_entry as i64) as i32
                    } else {
                        palette_entry
                    };
                    out.data.row_mut(y)[x] = val;
                    wp_state.update_errors(val, (x, y), w);
                    last_last = last;
                    last = val;
                }
            }
        }
    } else {
        let mut row_prev_buf: Vec<i32> = Vec::new();
        let mut row_prev2_buf: Vec<i32> = Vec::new();
        for (chan_index, out) in buf_out.iter_mut().enumerate() {
            for y in 0..h {
                let idx = buf_in.data.row(y);

                // Pre-fetch completed top rows (avoids per-pixel .row() calls)
                std::mem::swap(&mut row_prev2_buf, &mut row_prev_buf);
                if y > 0 {
                    row_prev_buf.clear();
                    row_prev_buf.extend_from_slice(out.data.row(y - 1));
                }
                let row_prev = if y > 0 {
                    Some(row_prev_buf.as_slice())
                } else {
                    None
                };
                let row_prev2 = if y > 1 {
                    Some(row_prev2_buf.as_slice())
                } else {
                    None
                };

                let mut last = if y > 0 { row_prev.unwrap()[0] } else { 0 };
                let mut last_last = last;

                for (x, &index) in idx.iter().enumerate() {
                    let palette_entry = get_palette_value(
                        palette,
                        index as isize,
                        /*c=*/ chan_index,
                        /*palette_size=*/ num_colors + num_deltas,
                        /*bit_depth=*/ bit_depth,
                    );
                    let left = last;
                    let leftleft = if x > 1 { last_last } else { left };
                    let val = if index < num_deltas as i32 {
                        let prediction_data = PredictionData::from_hoisted_neighbors(
                            left, leftleft, row_prev, row_prev2, w, None, None, None, None, None,
                            x, y, w, h,
                        );
                        let pred = predictor.predict_one(prediction_data, /*wp_pred=*/ 0);
                        (pred + palette_entry as i64) as i32
                    } else {
                        palette_entry
                    };
                    out.data.row_mut(y)[x] = val;
                    last_last = last;
                    last = val;
                }
            }
        }
    }
    Ok(())
}

/// Like `get_prediction_data` but takes pre-fetched/tracked values for the
/// main rect, avoiding per-pixel `Image::row()` overhead.
///
/// - `left`, `leftleft`: tracked as running variables by the caller
/// - `row_prev`, `row_prev2`: pre-fetched (copied) once per y-iteration
/// - Neighbor images: only accessed at grid boundaries
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn get_prediction_data_hoisted(
    left: i32,
    leftleft: i32,
    row_prev: Option<&[i32]>,
    row_prev2: Option<&[i32]>,
    rect_width: usize,
    buf: &[&mut ModularChannel],
    idx: usize,
    grid_x: usize,
    grid_y: usize,
    grid_xsize: usize,
    x: usize,
    y: usize,
    xsize: usize,
    ysize: usize,
) -> PredictionData {
    PredictionData::from_hoisted_neighbors(
        left,
        leftleft,
        row_prev,
        row_prev2,
        rect_width,
        if grid_x > 0 {
            Some(&buf[idx - 1].data)
        } else {
            None
        },
        if grid_y > 0 {
            Some(&buf[idx - grid_xsize].data)
        } else {
            None
        },
        if grid_x > 0 && grid_y > 0 {
            Some(&buf[idx - grid_xsize - 1].data)
        } else {
            None
        },
        if grid_x + 1 < grid_xsize {
            Some(&buf[idx + 1].data)
        } else {
            None
        },
        if grid_x + 1 < grid_xsize && grid_y > 0 {
            Some(&buf[idx - grid_xsize + 1].data)
        } else {
            None
        },
        x,
        y,
        xsize,
        ysize,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn do_palette_step_one_group(
    buf_in: &ModularChannel,
    buf_pal: &ModularChannel,
    buf_out: &mut [&mut ModularChannel],
    grid_x: usize,
    grid_y: usize,
    grid_xsize: usize,
    grid_ysize: usize,
    num_colors: usize,
    num_deltas: usize,
    predictor: Predictor,
) {
    let h = buf_in.data.size().1;
    let palette = &buf_pal.data;
    let bit_depth = buf_in.bit_depth.bits_per_sample().min(24) as usize;
    let num_c = buf_out.len() / (grid_xsize * grid_ysize);
    let (xsize, ysize) = buf_out[0].data.size();

    for c in 0..num_c {
        let out_idx = c * grid_ysize * grid_xsize + grid_y * grid_xsize + grid_x;
        let rect_width = buf_out[out_idx].data.size().0;
        // Reusable buffers for pre-fetched completed rows (avoids per-pixel .row() calls)
        let mut row_prev_buf: Vec<i32> = Vec::new();
        let mut row_prev2_buf: Vec<i32> = Vec::new();

        for y in 0..h {
            let index_img = buf_in.data.row(y);

            // Copy completed top rows — these don't change during the x-loop.
            // row_prev2 = previous row_prev (rotate), row_prev = row just completed.
            std::mem::swap(&mut row_prev2_buf, &mut row_prev_buf);
            if y > 0 {
                row_prev_buf.clear();
                row_prev_buf.extend_from_slice(buf_out[out_idx].data.row(y - 1));
            }
            let row_prev = if y > 0 {
                Some(row_prev_buf.as_slice())
            } else {
                None
            };
            let row_prev2 = if y > 1 {
                Some(row_prev2_buf.as_slice())
            } else {
                None
            };

            // Track left/leftleft as running variables
            let initial_left = if y > 0 {
                row_prev.unwrap()[0]
            } else if grid_y > 0 {
                buf_out[out_idx - grid_xsize].data.row(ysize - 1)[0]
            } else {
                0
            };
            let mut last = initial_left;
            let mut last_last = initial_left;

            for (x, &index) in index_img.iter().enumerate() {
                let palette_entry = get_palette_value(
                    palette,
                    index as isize,
                    c,
                    /*palette_size=*/ num_colors + num_deltas,
                    /*bit_depth=*/ bit_depth,
                );
                // Compute left/leftleft for this pixel
                let left = if x > 0 {
                    last
                } else if grid_x > 0 {
                    buf_out[out_idx - 1].data.row(y)[xsize - 1]
                } else {
                    initial_left
                };
                let leftleft = if x > 1 {
                    last_last
                } else if let Some(l_img) = if grid_x > 0 {
                    Some(&buf_out[out_idx - 1].data)
                } else {
                    None
                } {
                    l_img.row(y)[xsize + x - 2]
                } else {
                    left
                };

                let val = if index < num_deltas as i32 {
                    let pred = predictor.predict_one(
                        get_prediction_data_hoisted(
                            left, leftleft, row_prev, row_prev2, rect_width, buf_out, out_idx,
                            grid_x, grid_y, grid_xsize, x, y, xsize, ysize,
                        ),
                        /*wp_pred=*/ 0,
                    );
                    (pred + palette_entry as i64) as i32
                } else {
                    palette_entry
                };
                buf_out[out_idx].data.row_mut(y)[x] = val;
                last_last = last;
                last = val;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn do_palette_step_group_row(
    buf_in: &[&ModularChannel],
    buf_pal: &ModularChannel,
    buf_out: &mut [&mut ModularChannel],
    grid_y: usize,
    grid_xsize: usize,
    num_colors: usize,
    num_deltas: usize,
    predictor: Predictor,
    wp_header: &WeightedHeader,
) -> Result<()> {
    let palette = &buf_pal.data;
    let h = buf_in[0].data.size().1;
    let bit_depth = buf_in[0].bit_depth.bits_per_sample().min(24) as usize;
    let grid_ysize = grid_y + 1;
    let num_c = buf_out.len() / (grid_xsize * grid_ysize);
    let total_w = buf_out[0..grid_xsize]
        .iter()
        .map(|buf| buf.data.size().0)
        .sum();
    let (xsize, ysize) = buf_out[0].data.size();

    // Helper closure: compute initial "left" value for x=0 of a grid block
    let initial_left_for = |buf_out: &[&mut ModularChannel],
                            out_idx: usize,
                            grid_y: usize,
                            grid_xsize: usize,
                            row_prev: Option<&[i32]>,
                            ysize: usize|
     -> i32 {
        if let Some(rp) = row_prev {
            rp[0]
        } else if grid_y > 0 {
            buf_out[out_idx - grid_xsize].data.row(ysize - 1)[0]
        } else {
            0
        }
    };

    // Per-grid-x row buffers: each grid block needs its own prev/prev2 tracking
    // because blocks may have different widths and the swap pattern must rotate
    // per-block across y iterations, not across grid_x iterations.
    let mut row_prev_bufs: Vec<Vec<i32>> = (0..grid_xsize).map(|_| Vec::new()).collect();
    let mut row_prev2_bufs: Vec<Vec<i32>> = (0..grid_xsize).map(|_| Vec::new()).collect();

    if predictor == Predictor::Weighted {
        for c in 0..num_c {
            let mut wp_state = WeightedPredictorState::new(wp_header, total_w)?;
            let out_row_idx = c * grid_ysize * grid_xsize + grid_y * grid_xsize;
            if grid_y > 0 {
                let prev_row_idx = out_row_idx - grid_y * grid_xsize;
                wp_state.restore_state(
                    buf_out[prev_row_idx].auxiliary_data.as_ref().unwrap(),
                    total_w,
                );
            }
            for y in 0..h {
                for (grid_x, index_buf) in buf_in.iter().enumerate().take(grid_xsize) {
                    let index_img = index_buf.data.row(y);
                    let out_idx = out_row_idx + grid_x;
                    let rect_width = buf_out[out_idx].data.size().0;

                    // Pre-fetch completed top rows for THIS grid block
                    std::mem::swap(&mut row_prev2_bufs[grid_x], &mut row_prev_bufs[grid_x]);
                    if y > 0 {
                        row_prev_bufs[grid_x].clear();
                        row_prev_bufs[grid_x].extend_from_slice(buf_out[out_idx].data.row(y - 1));
                    }
                    let row_prev = if y > 0 {
                        Some(row_prev_bufs[grid_x].as_slice())
                    } else {
                        None
                    };
                    let row_prev2 = if y > 1 {
                        Some(row_prev2_bufs[grid_x].as_slice())
                    } else {
                        None
                    };

                    let initial_left =
                        initial_left_for(buf_out, out_idx, grid_y, grid_xsize, row_prev, ysize);
                    let mut last = initial_left;
                    let mut last_last = initial_left;

                    for (x, &index) in index_img.iter().enumerate() {
                        let palette_entry = get_palette_value(
                            palette,
                            index as isize,
                            c,
                            /*palette_size=*/ num_colors + num_deltas,
                            /*bit_depth=*/ bit_depth,
                        );
                        let left = if x > 0 {
                            last
                        } else if grid_x > 0 {
                            buf_out[out_idx - 1].data.row(y)[xsize - 1]
                        } else {
                            initial_left
                        };
                        let leftleft = if x > 1 {
                            last_last
                        } else if let Some(l_img) = if grid_x > 0 {
                            Some(&buf_out[out_idx - 1].data)
                        } else {
                            None
                        } {
                            l_img.row(y)[xsize + x - 2]
                        } else {
                            left
                        };

                        let val = if index < num_deltas as i32 {
                            let prediction_data = get_prediction_data_hoisted(
                                left, leftleft, row_prev, row_prev2, rect_width, buf_out, out_idx,
                                grid_x, grid_y, grid_xsize, x, y, xsize, ysize,
                            );
                            let (pred, _) = wp_state.predict_and_property(
                                (grid_x * xsize + x, y & 1),
                                total_w,
                                &prediction_data,
                            );
                            (pred + palette_entry as i64) as i32
                        } else {
                            palette_entry
                        };
                        buf_out[out_idx].data.row_mut(y)[x] = val;
                        wp_state.update_errors(val, (grid_x * xsize + x, y & 1), total_w);
                        last_last = last;
                        last = val;
                    }
                }
            }
            let mut wp_image = Image::<i32>::new((total_w + 2, 1))?;
            wp_state.save_state(&mut wp_image, total_w);
            buf_out[out_row_idx].auxiliary_data = Some(wp_image);
        }
    } else {
        for c in 0..num_c {
            for y in 0..h {
                for (grid_x, index_buf) in buf_in.iter().enumerate().take(grid_xsize) {
                    let index_img = index_buf.data.row(y);
                    let out_idx = c * grid_ysize * grid_xsize + grid_y * grid_xsize + grid_x;
                    let rect_width = buf_out[out_idx].data.size().0;

                    // Pre-fetch completed top rows for THIS grid block
                    std::mem::swap(&mut row_prev2_bufs[grid_x], &mut row_prev_bufs[grid_x]);
                    if y > 0 {
                        row_prev_bufs[grid_x].clear();
                        row_prev_bufs[grid_x].extend_from_slice(buf_out[out_idx].data.row(y - 1));
                    }
                    let row_prev = if y > 0 {
                        Some(row_prev_bufs[grid_x].as_slice())
                    } else {
                        None
                    };
                    let row_prev2 = if y > 1 {
                        Some(row_prev2_bufs[grid_x].as_slice())
                    } else {
                        None
                    };

                    let initial_left =
                        initial_left_for(buf_out, out_idx, grid_y, grid_xsize, row_prev, ysize);
                    let mut last = initial_left;
                    let mut last_last = initial_left;

                    for (x, &index) in index_img.iter().enumerate() {
                        let palette_entry = get_palette_value(
                            palette,
                            index as isize,
                            c,
                            /*palette_size=*/ num_colors + num_deltas,
                            /*bit_depth=*/ bit_depth,
                        );
                        let left = if x > 0 {
                            last
                        } else if grid_x > 0 {
                            buf_out[out_idx - 1].data.row(y)[xsize - 1]
                        } else {
                            initial_left
                        };
                        let leftleft = if x > 1 {
                            last_last
                        } else if let Some(l_img) = if grid_x > 0 {
                            Some(&buf_out[out_idx - 1].data)
                        } else {
                            None
                        } {
                            l_img.row(y)[xsize + x - 2]
                        } else {
                            left
                        };

                        let val = if index < num_deltas as i32 {
                            let pred = predictor.predict_one(
                                get_prediction_data_hoisted(
                                    left, leftleft, row_prev, row_prev2, rect_width, buf_out,
                                    out_idx, grid_x, grid_y, grid_xsize, x, y, xsize, ysize,
                                ),
                                /*wp_pred=*/ 0,
                            );
                            (pred + palette_entry as i64) as i32
                        } else {
                            palette_entry
                        };
                        buf_out[out_idx].data.row_mut(y)[x] = val;
                        last_last = last;
                        last = val;
                    }
                }
            }
        }
    }
    Ok(())
}
