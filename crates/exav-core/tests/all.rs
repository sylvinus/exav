//! Entry point for the consolidated integration-test binary. See `suites/mod.rs`.
mod suites;

// The library's temp-file support, included by path: it is `#[cfg(test)]` inside
// the crate, so an integration test cannot import it, and pulling a temp-file
// crate in just for these two call sites would put thousands of `unsafe` blocks
// back into `cargo test`.
#[path = "../src/tmpfile.rs"]
mod tmpfile;
