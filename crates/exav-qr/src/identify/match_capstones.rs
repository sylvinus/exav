// Vendored from rqrr 0.11.0 (https://github.com/WanzenBug/rqrr), src/identify/match_capstones.rs,
// a port of quirc. License: (MIT OR Apache-2.0) AND ISC, see LICENSE-*.
// Copyright 2019 Moritz Wanzenböck; quirc: copyright 2010-2012 Daniel Beer.
// Changed: the ranking of neighbors counts its steps and its memory in the
// image's meter and returns `None` when that stops the search.

use std::mem;

use crate::CapStone;
use crate::limits::Meter;

#[derive(Debug, Clone)]
pub struct CapStoneGroup(pub CapStone, pub CapStone, pub CapStone);

#[derive(Clone, Copy, Debug, PartialEq)]
struct Neighbor {
    index: usize,
    distance: f64,
}

/// Return each pair Capstone indexes that are likely to be from a QR code
/// Ordered from most symmetric to least symmetric
///
/// `None` when the meter stopped the search. The memory of the pairs returned
/// stays counted in the meter: the caller releases it.
pub fn find_and_rank_possible_neighbors(
    capstones: &[CapStone],
    idx: usize,
    meter: &Meter,
) -> Option<Vec<(usize, usize)>> {
    const VIABILITY_THRESHOLD: f64 = 0.25;

    let (hlist, vlist) = find_possible_neighbors(capstones, idx, meter)?;
    let list_bytes = ((hlist.len() + vlist.len()) * mem::size_of::<Neighbor>()) as u64;
    if !meter.reserve(list_bytes)
        || !meter.charge((hlist.len() as u64).saturating_mul(vlist.len() as u64))
    {
        return None;
    }
    let mut res = Vec::new();
    struct NeighborSet {
        score: f64,
        h_index: usize,
        v_index: usize,
    }
    let set_bytes = mem::size_of::<NeighborSet>() as u64;
    let pair_bytes = mem::size_of::<(usize, usize)>() as u64;
    /* Test each possible grouping */
    for hn in hlist {
        for vn in vlist.iter() {
            let score = {
                if hn.distance < vn.distance {
                    (1.0f64 - hn.distance / vn.distance).abs()
                } else {
                    (1.0f64 - vn.distance / hn.distance).abs()
                }
            };
            if score < VIABILITY_THRESHOLD {
                // A set, and its pair in the result.
                if !meter.reserve(set_bytes + pair_bytes) {
                    return None;
                }
                res.push(NeighborSet {
                    score,
                    h_index: hn.index,
                    v_index: vn.index,
                });
            }
        }
    }

    res.sort_unstable_by(|a, b| {
        (a.score)
            .partial_cmp(&(b.score))
            .expect("Neighbor distance should never cause a div by 0")
    });
    meter.release(res.len() as u64 * set_bytes + list_bytes);
    Some(res.iter().map(|n| (n.h_index, n.v_index)).collect())
}

fn find_possible_neighbors(
    capstones: &[CapStone],
    idx: usize,
    meter: &Meter,
) -> Option<(Vec<Neighbor>, Vec<Neighbor>)> {
    if !meter.charge(capstones.len() as u64) {
        return None;
    }
    let cap = &capstones[idx];
    let mut hlist = Vec::new();
    let mut vlist = Vec::new();

    /* Look for potential neighbours by examining the relative gradients
     * from this capstone to others.
     */
    #[allow(clippy::needless_range_loop)]
    for others_idx in 0..capstones.len() {
        if others_idx == idx {
            continue;
        }

        let cmp_cap = &capstones[others_idx];

        let (mut u, mut v) = cap.c.unmap(&cmp_cap.center);
        u = (u - 3.5f64).abs();
        v = (v - 3.5f64).abs();

        if u < 0.2f64 * v {
            hlist.push(Neighbor {
                index: others_idx,
                distance: v,
            });
        }

        if v < 0.2f64 * u {
            vlist.push(Neighbor {
                index: others_idx,
                distance: u,
            });
        }
    }

    Some((hlist, vlist))
}
