// Vendored from rqrr 0.11.0 (https://github.com/WanzenBug/rqrr), src/identify/mod.rs,
// a port of quirc. License: (MIT OR Apache-2.0) AND ISC, see LICENSE-*.
// Copyright 2019 Moritz Wanzenböck; quirc: copyright 2010-2012 Daniel Beer.

pub use self::grid::SkewedGridLocation;
pub use self::match_capstones::find_and_rank_possible_neighbors;

pub mod grid;
pub mod match_capstones;

/// A simple point in (some) space
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}
