//! Seekable input backends.
//!
//! The engine scans two ways: a sequential `Read` (stdin, a pipe, an S3
//! streaming GET) drives the constant-memory pattern+hash core, while a
//! `Read + Seek` source additionally lets [`crate::scan_seekable`] read a
//! ZIP's central directory and only the entries it extracts.
//!
//! [`HttpRangeReader`] (enabled with the `http` feature) is a `Read + Seek`
//! backend over HTTP(S) range requests, so an object on S3 (via a public or
//! presigned URL) can be scanned without downloading it whole — only the
//! ranges the scanner touches are fetched.

#[cfg(feature = "http")]
mod http {
    use std::io::{self, Read, Seek, SeekFrom};

    /// Bytes fetched per range request (read-ahead block size).
    const BLOCK: u64 = 64 * 1024;

    /// A `Read + Seek` view over an HTTP(S) resource, served by range
    /// requests with a one-block read-ahead cache.
    pub struct HttpRangeReader {
        agent: ureq::Agent,
        url: String,
        len: u64,
        pos: u64,
        block: Vec<u8>,
        block_start: u64,
        /// Total bytes fetched over the wire (observability / tests).
        pub bytes_fetched: u64,
        /// Number of range requests issued.
        pub requests: u64,
    }

    impl HttpRangeReader {
        /// Open a URL, probing its length and range support with a single
        /// `bytes=0-0` request.
        pub fn open(url: &str) -> io::Result<Self> {
            let agent = ureq::AgentBuilder::new()
                .user_agent(concat!("exav/", env!("CARGO_PKG_VERSION")))
                .build();
            let resp = agent
                .get(url)
                .set("Range", "bytes=0-0")
                .call()
                .map_err(|e| io::Error::other(e.to_string()))?;
            let total = resp
                .header("Content-Range")
                .and_then(|cr| cr.rsplit('/').next())
                .and_then(|n| n.trim().parse::<u64>().ok())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "server did not return a Content-Range total (no range support?)",
                    )
                })?;
            Ok(Self {
                agent,
                url: url.to_string(),
                len: total,
                pos: 0,
                block: Vec::new(),
                block_start: 0,
                bytes_fetched: 0,
                requests: 0,
            })
        }

        pub fn len(&self) -> u64 {
            self.len
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        fn cached(&self, pos: u64) -> bool {
            pos >= self.block_start && pos < self.block_start + self.block.len() as u64
        }

        fn fetch_block(&mut self, start: u64) -> io::Result<()> {
            self.block.clear();
            self.block_start = start;
            if start >= self.len {
                return Ok(());
            }
            let last = (start + BLOCK).min(self.len) - 1;
            let resp = self
                .agent
                .get(&self.url)
                .set("Range", &format!("bytes={start}-{last}"))
                .call()
                .map_err(|e| io::Error::other(e.to_string()))?;
            let mut buf = Vec::new();
            resp.into_reader().take(BLOCK).read_to_end(&mut buf)?;
            self.bytes_fetched += buf.len() as u64;
            self.requests += 1;
            self.block = buf;
            Ok(())
        }
    }

    impl Read for HttpRangeReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if out.is_empty() || self.pos >= self.len {
                return Ok(0);
            }
            if !self.cached(self.pos) {
                let aligned = (self.pos / BLOCK) * BLOCK;
                self.fetch_block(aligned)?;
            }
            let off = (self.pos - self.block_start) as usize;
            if off >= self.block.len() {
                return Ok(0);
            }
            let n = out.len().min(self.block.len() - off);
            out[..n].copy_from_slice(&self.block[off..off + n]);
            self.pos += n as u64;
            Ok(n)
        }
    }

    impl Seek for HttpRangeReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            let target: i128 = match pos {
                SeekFrom::Start(o) => o as i128,
                SeekFrom::End(o) => self.len as i128 + o as i128,
                SeekFrom::Current(o) => self.pos as i128 + o as i128,
            };
            if target < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "seek before start",
                ));
            }
            self.pos = target as u64;
            Ok(self.pos)
        }
    }
}

#[cfg(feature = "http")]
pub use http::HttpRangeReader;
