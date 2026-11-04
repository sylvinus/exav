# exav-qr

QR code detection and decoding for exav's `qr` feature: [rqrr] 0.11.0, a port
of [quirc], vendored. The crate is `#![forbid(unsafe_code)]` and has no
dependency (the `image` crate is a dev-dependency, for the PNG files of its
tests).

Changes from rqrr 0.11.0, each file saying its own in its header:

- the `lru` crate's cache of recolored regions is a safe cache of the same
  eviction order (`src/prepare.rs`);
- the `g2p` crate's GF(16) and GF(256) are tables of this crate (`src/gf.rs`);
- a search stops at a deadline, at a memory budget and at caps on finder
  patterns and candidate grids, by counting its steps and its bytes in its own
  loops (`src/limits.rs`; `PreparedImage::detect` returns the grids found and
  why it stopped): it never unwinds for a limit, so it builds with
  `panic = "abort"` too;
- the `img` feature (`ImageBuffer` for the `image` crate's grey images) is
  removed: pixels come from a function (`PreparedImage::prepare_from_greyscale`
  and its siblings);
- the helpers that write images to a path (`write_grid_to`, `write_state_to`)
  are removed, and the usage example of the crate docs does not read a file;
- clippy and rustfmt fixes.

The API is rqrr's, with the crate named `exav_qr`.

## License

Under rqrr's license, `(MIT OR Apache-2.0) AND ISC` (see `LICENSE-MIT`,
`LICENSE-APACHE` and `LICENSE-ISC`): the ISC part is quirc's, copyright
2010-2012 Daniel Beer. The files written for exav (`src/gf.rs`,
`src/limits.rs`) are under the same terms.

[rqrr]: https://github.com/WanzenBug/rqrr
[quirc]: https://github.com/dlbeer/quirc
