//! Seekable input backends.
//!
//! [`crate::scan_seekable`] reads a `Read + Seek` source by offset, so a
//! ZIP's central directory and its members are read where they are. A
//! sequential `Read` (stdin, a pipe) is buffered by the caller first.
//!
//! `HttpRangeReader` (enabled with the `http` feature) is a `Read + Seek`
//! backend over HTTP(S) range requests, so an object on S3 (via a public or
//! presigned URL) can be scanned without downloading it whole: only the
//! ranges the scanner touches are fetched.

#[cfg(feature = "http")]
mod http {
    use std::io::{self, Read, Seek, SeekFrom};

    /// Bytes fetched by a range request that does not continue the previous
    /// one.
    const BLOCK: u64 = 64 * 1024;

    /// Most bytes one range request fetches.
    const MAX_BLOCK: u64 = 8 * 1024 * 1024;

    /// A `Read + Seek` view over an HTTP(S) resource, served by range
    /// requests, the last one's bytes kept.
    ///
    /// A request that continues the previous one fetches twice as much, up to
    /// [`MAX_BLOCK`]: a pass through the object costs a request per 8 MiB
    /// rather than per 64 KiB, while reads scattered through it (a ZIP's
    /// directory, then its members) stay small.
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
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .user_agent(concat!("exav/", env!("CARGO_PKG_VERSION")))
                .build()
                .into();
            let resp = agent
                .get(url)
                .header("Range", "bytes=0-0")
                .call()
                .map_err(|e| io::Error::other(e.to_string()))?;
            let total = resp
                .headers()
                .get("Content-Range")
                .and_then(|cr| cr.to_str().ok())
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
            let continues =
                !self.block.is_empty() && start == self.block_start + self.block.len() as u64;
            let size = match continues {
                true => (self.block.len() as u64 * 2).min(MAX_BLOCK),
                false => BLOCK,
            };
            self.block.clear();
            self.block_start = start;
            if start >= self.len {
                return Ok(());
            }
            let last = start.saturating_add(size).min(self.len) - 1;
            let resp = self
                .agent
                .get(&self.url)
                .header("Range", format!("bytes={start}-{last}"))
                .call()
                .map_err(|e| io::Error::other(e.to_string()))?;
            // Anything but a partial response is not the range asked for: a
            // `200` is the object from its first byte.
            if resp.status() != 206 {
                return Err(io::Error::other(format!(
                    "range request answered with status {}",
                    resp.status()
                )));
            }
            let mut buf = Vec::new();
            resp.into_body()
                .into_reader()
                .take(size)
                .read_to_end(&mut buf)?;
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
                let next = self.block_start + self.block.len() as u64;
                // Read on from the previous request, or from the aligned block
                // holding a position elsewhere.
                let start = match self.pos == next {
                    true => next,
                    false => (self.pos / BLOCK) * BLOCK,
                };
                self.fetch_block(start)?;
            }
            let off = (self.pos - self.block_start) as usize;
            if off >= self.block.len() {
                // `self.pos < self.len` was established above, so the object is
                // NOT finished; the server just did not give us the bytes it
                // said existed (a short 206, a range it declined to honour, a
                // truncated body). Returning `Ok(0)` here would report EOF, and
                // every reader upstream would treat the object as merely
                // truncated: a partial scan that comes back clean. Fail loudly
                // instead so it surfaces as an error, never a quiet OK.
                return Err(io::Error::other(format!(
                    "range request for {} returned no data at offset {} \
                     (object declares {} bytes)",
                    self.url, self.pos, self.len
                )));
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
            self.pos = u64::try_from(target).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "seek past the largest offset")
            })?;
            Ok(self.pos)
        }
    }
}

#[cfg(feature = "http")]
pub use http::HttpRangeReader;

#[cfg(all(test, feature = "http"))]
mod tests {
    use super::HttpRangeReader;
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
    use std::net::TcpListener;

    /// Serve `body` on a local port, one request per connection, answering a
    /// range request with `206` and that range, except that past the first
    /// request a `full` server answers `200` and the whole body.
    fn serve(body: Vec<u8>, full: bool) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/obj", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for (n, conn) in listener.incoming().enumerate() {
                let Ok(mut conn) = conn else { return };
                let mut range = None;
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(r) = line.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        let (a, b) = r.trim().split_once('-').unwrap();
                        range = Some((a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()));
                    }
                }
                let head = match range {
                    Some((a, b)) if !(full && n > 0) => {
                        let part = &body[a..=b];
                        let h = format!(
                            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {a}-{b}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len(),
                            part.len()
                        );
                        [h.as_bytes(), part].concat()
                    }
                    _ => {
                        let h = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        [h.as_bytes(), &body].concat()
                    }
                };
                let _ = conn.write_all(&head);
            }
        });
        url
    }

    #[test]
    fn ranges_are_read_where_they_are() {
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut r = HttpRangeReader::open(&serve(body.clone(), false)).unwrap();
        assert_eq!(r.len(), body.len() as u64);
        let mut buf = vec![0; 1000];
        r.seek(SeekFrom::Start(150_000)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, body[150_000..151_000]);
        let mut all = Vec::new();
        r.seek(SeekFrom::Start(0)).unwrap();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, body);
    }

    /// A seek past the largest offset is refused, not wrapped to a small one.
    #[test]
    fn a_seek_past_u64_is_an_error_not_a_wrap() {
        let body: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut r = HttpRangeReader::open(&serve(body, false)).unwrap();
        assert_eq!(r.seek(SeekFrom::Start(u64::MAX)).unwrap(), u64::MAX);
        assert!(r.seek(SeekFrom::Current(2)).is_err());
        assert_eq!(r.seek(SeekFrom::Start(5)).unwrap(), 5);
    }

    /// A server that answers a range with the whole object is not read as
    /// though the object started at the range.
    #[test]
    fn a_range_answered_whole_is_an_error() {
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut r = HttpRangeReader::open(&serve(body, true)).unwrap();
        r.seek(SeekFrom::Start(150_000)).unwrap();
        let mut buf = vec![0; 1000];
        assert!(r.read_exact(&mut buf).is_err());
    }
}
