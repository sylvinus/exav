//! Seekable input backends.
//!
//! [`crate::scan_seekable`] reads a `Read + Seek` source too large to hold by
//! offset, so a ZIP's central directory and its members are read where they
//! are. A sequential `Read` (stdin, a pipe) is buffered by the caller first.
//!
//! `HttpRangeReader` (enabled with the `http` feature) is a `Read + Seek`
//! backend over HTTP(S) range requests, so an object on S3 (via a public or
//! presigned URL) can be scanned without downloading it whole: only the
//! ranges the scanner touches are fetched.

#[cfg(feature = "http")]
mod http {
    use std::io::{self, Read, Seek, SeekFrom};

    /// Bytes fetched by a range request that does not continue the previous
    /// one, unless the caller says otherwise: the block of the cache that
    /// reads through the reader, so that a block is one request.
    pub const BLOCK: u64 = 1024 * 1024;

    /// Most bytes one range request fetches, unless the caller says otherwise.
    pub const MAX_BLOCK: u64 = 8 * 1024 * 1024;

    /// How a source is fetched, past the sizes of its requests.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct HttpConfig {
        /// The most one request may take, from connecting to the last byte of
        /// its body. `None`: no limit.
        pub timeout: Option<std::time::Duration>,
        /// Redirects followed to reach the object. `None`: no limit.
        pub max_redirects: Option<u32>,
        /// Whether a redirect may lead to a host with a loopback, private,
        /// link-local, shared-address or unspecified address (an IPv6 address
        /// that carries one included). The host asked for is the caller's
        /// choice; where a redirect leads is the server's. The addresses are
        /// filtered where each connection is made.
        pub redirect_to_private: bool,
    }

    impl Default for HttpConfig {
        fn default() -> Self {
            HttpConfig {
                timeout: Some(std::time::Duration::from_secs(120)),
                max_redirects: Some(10),
                redirect_to_private: false,
            }
        }
    }

    /// The URL a `Location` header names, from the URL that answered with it.
    fn resolve(base: &ureq::http::Uri, location: &str) -> io::Result<String> {
        let bad = || io::Error::other(format!("a redirect to {location:?} is not a URL"));
        if location.starts_with("http://") || location.starts_with("https://") {
            return Ok(location.to_string());
        }
        let scheme = base.scheme_str().ok_or_else(bad)?;
        if let Some(rest) = location.strip_prefix("//") {
            return Ok(format!("{scheme}://{rest}"));
        }
        let authority = base.authority().ok_or_else(bad)?;
        if location.starts_with('/') {
            return Ok(format!("{scheme}://{authority}{location}"));
        }
        let dir = base.path().rsplit_once('/').map_or("", |(d, _)| d);
        Ok(format!("{scheme}://{authority}{dir}/{location}"))
    }

    /// Whether an address is one only the host or its network reaches.
    pub(super) fn is_private(ip: std::net::IpAddr) -> bool {
        use std::net::IpAddr;
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    // "This network" (RFC 791).
                    || v4.octets()[0] == 0
                    // Shared address space (RFC 6598).
                    || (v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64)
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                // An IPv4 address carried in the low bits: mapped, compatible
                // (::a.b.c.d) or NAT64 (64:ff9b::/96).
                let carried = v6.to_ipv4_mapped().or_else(|| {
                    let low = std::net::Ipv4Addr::from(u128::from(v6) as u32);
                    let compatible = s[..6] == [0; 6] && !v6.is_loopback() && !v6.is_unspecified();
                    let nat64 = s[..6] == [0x64, 0xff9b, 0, 0, 0, 0];
                    (compatible || nat64).then_some(low)
                });
                match carried {
                    Some(v4) => is_private(IpAddr::V4(v4)),
                    None => {
                        v6.is_loopback()
                            || v6.is_unspecified()
                            || v6.is_unique_local()
                            || v6.is_unicast_link_local()
                            // Site-local (fec0::/10), deprecated and still routed
                            // inside some networks.
                            || s[0] & 0xffc0 == 0xfec0
                    }
                }
            }
        }
    }

    /// Host and port of a URL, as the connection sees them.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Origin(String, u16);

    impl Origin {
        fn of(uri: &ureq::http::Uri) -> Self {
            let host = uri.host().unwrap_or("");
            let bare = host.trim_start_matches('[').trim_end_matches(']');
            let port = uri
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                });
            Origin(bare.to_ascii_lowercase(), port)
        }
    }

    /// Whether an address is refused to a host the server sent the scan to.
    pub(super) type Refuse = std::sync::Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>;

    /// The resolver of a source's agent, which every connection it makes goes
    /// through, the first and the ones that follow (a range request on a new
    /// connection looks the name up again).
    ///
    /// The address of the URL the caller named is the caller's choice. Any
    /// other host, one a redirect led to, is refused the addresses `refuse`
    /// names, at the moment it is connected to: a name whose answer changes
    /// between a check and a connection cannot lead the scan to an address that
    /// was refused. Only the addresses it kept are connected to.
    struct Guard {
        inner: Box<dyn ureq::unversioned::resolver::Resolver>,
        named: Origin,
        refuse: Option<Refuse>,
    }

    impl std::fmt::Debug for Guard {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Guard").field("named", &self.named).finish()
        }
    }

    impl ureq::unversioned::resolver::Resolver for Guard {
        fn resolve(
            &self,
            uri: &ureq::http::Uri,
            config: &ureq::config::Config,
            timeout: ureq::unversioned::transport::NextTimeout,
        ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
            let found = self.inner.resolve(uri, config, timeout)?;
            let Some(refuse) = &self.refuse else {
                return Ok(found);
            };
            if Origin::of(uri) == self.named {
                return Ok(found);
            }
            let mut kept = self.empty();
            let mut refused = None;
            for addr in found.iter() {
                match refuse(addr.ip()) {
                    true => refused = refused.or(Some(addr.ip())),
                    false => kept.push(*addr),
                }
            }
            match (kept.is_empty(), refused) {
                (true, Some(ip)) => Err(ureq::Error::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{uri} leads to the private address {ip}, which a redirect may not \
                         reach (--http-redirect-private allows it)"
                    ),
                ))),
                _ => Ok(kept),
            }
        }
    }

    /// Refuse a redirect from `from` to `to` that changes the scheme, or that
    /// is written as a private address unless `private` allows it. A name is
    /// checked where it is connected to, by [`Guard`]; an address written out is
    /// checked here too, for a connection through a proxy, which looks names up
    /// itself.
    fn check_redirect(
        from: &ureq::http::Uri,
        to: &str,
        private: bool,
        named: &Origin,
    ) -> io::Result<()> {
        let uri: ureq::http::Uri = to
            .parse()
            .map_err(|e| io::Error::other(format!("a redirect to {to:?}: {e}")))?;
        if uri.scheme_str() != from.scheme_str() {
            return Err(io::Error::other(format!(
                "a redirect from {from} to {to} changes the scheme: not followed"
            )));
        }
        let origin = Origin::of(&uri);
        if private || origin == *named {
            return Ok(());
        }
        if let Ok(ip) = origin.0.parse::<std::net::IpAddr>()
            && is_private(ip)
        {
            return Err(io::Error::other(format!(
                "a redirect to {to} leads to the private address {ip}: not followed \
                 (--http-redirect-private allows it)"
            )));
        }
        Ok(())
    }

    /// A `Read + Seek` view over an HTTP(S) resource, served by range
    /// requests, the last one's bytes kept.
    ///
    /// A request that continues the previous one fetches twice as much, up to
    /// the largest request (8 MiB unless set): a pass through the object costs a
    /// request per 8 MiB rather than per block, while reads scattered through it
    /// (a ZIP's directory, then its members) stay one block.
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
        /// What a request that does not continue the previous one fetches.
        first: u64,
        /// The most one request fetches.
        most: u64,
        /// The object's `ETag` when it is a strong one, else its
        /// `Last-Modified`: sent as `If-Range`, so a server whose object has
        /// changed since the first request answers with all of the new one,
        /// which is refused.
        pin: Option<String>,
        /// The strong `ETag` the first answer had, which every later one must
        /// have too.
        etag: Option<String>,
    }

    /// A header's value, as text.
    fn header(resp: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
    }

    impl HttpRangeReader {
        /// Open a URL, probing its length and range support with a single
        /// `bytes=0-0` request.
        pub fn open(url: &str) -> io::Result<Self> {
            Self::open_with(url, BLOCK, MAX_BLOCK)
        }

        /// [`Self::open`] with the size of a request that does not continue
        /// the previous one (`first`, at least 1) and the most any request
        /// fetches (`most`, never below `first`).
        pub fn open_with(url: &str, first: u64, most: u64) -> io::Result<Self> {
            Self::open_config(url, first, most, &HttpConfig::default())
        }

        /// [`Self::open_with`] under `config`. Redirects are followed here, to
        /// the URL every later request goes to. A server that does not answer
        /// a range request with one is an error of kind `Unsupported`.
        pub fn open_config(
            url: &str,
            first: u64,
            most: u64,
            config: &HttpConfig,
        ) -> io::Result<Self> {
            let (agent, url, resp) = probe(url, config)?;
            Self::from_probe(agent, url, resp, first, most)
        }

        pub(super) fn from_probe(
            agent: ureq::Agent,
            url: String,
            resp: ureq::http::Response<ureq::Body>,
            first: u64,
            most: u64,
        ) -> io::Result<Self> {
            let first = first.max(1);
            let most = most.max(first);
            match resp.status().as_u16() {
                206 => {}
                200 => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("{url} does not answer range requests"),
                    ));
                }
                s => return Err(io::Error::other(format!("{url} answered with status {s}"))),
            }
            let etag = header(&resp, "ETag").filter(|t| !t.starts_with("W/"));
            let pin = etag.clone().or_else(|| header(&resp, "Last-Modified"));
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
                url,
                len: total,
                pos: 0,
                block: Vec::new(),
                block_start: 0,
                bytes_fetched: 0,
                requests: 0,
                first,
                most,
                pin,
                etag,
            })
        }

        /// The URL the requests go to, redirects followed.
        pub fn url(&self) -> &str {
            &self.url
        }

        pub fn len(&self) -> u64 {
            self.len
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
    }

    /// The first answer for `url`, asked for its first byte, redirects
    /// followed under `config`; the agent that asked, and the URL that
    /// answered.
    fn probe(
        url: &str,
        config: &HttpConfig,
    ) -> io::Result<(ureq::Agent, String, ureq::http::Response<ureq::Body>)> {
        let refuse: Option<Refuse> = (!config.redirect_to_private).then(|| {
            let refuse: Refuse = std::sync::Arc::new(is_private);
            refuse
        });
        probe_with(
            url,
            config,
            Box::<ureq::unversioned::resolver::DefaultResolver>::default(),
            refuse,
        )
    }

    /// [`probe`] with the resolver that looks names up, and the addresses a
    /// redirect is refused.
    pub(super) fn probe_with(
        url: &str,
        config: &HttpConfig,
        inner: Box<dyn ureq::unversioned::resolver::Resolver>,
        refuse: Option<Refuse>,
    ) -> io::Result<(ureq::Agent, String, ureq::http::Response<ureq::Body>)> {
        let first: ureq::http::Uri = url
            .parse()
            .map_err(|e| io::Error::other(format!("{url}: {e}")))?;
        let named = Origin::of(&first);
        let guard = Guard {
            inner,
            named: named.clone(),
            refuse,
        };
        let agent = ureq::Agent::with_parts(
            ureq::Agent::config_builder()
                .user_agent(concat!("exav/", env!("CARGO_PKG_VERSION")))
                .max_redirects(0)
                .http_status_as_error(false)
                .timeout_per_call(config.timeout)
                .build(),
            ureq::unversioned::transport::DefaultConnector::new(),
            guard,
        );
        let mut url = url.to_string();
        let mut followed = 0u32;
        loop {
            let resp = agent
                .get(&url)
                .header("Range", "bytes=0-0")
                .call()
                .map_err(|e| io::Error::other(e.to_string()))?;
            let status = resp.status().as_u16();
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                return Ok((agent, url, resp));
            }
            if config.max_redirects.is_some_and(|m| followed >= m) {
                return Err(io::Error::other(format!(
                    "{url} redirects more than {followed} times (--http-max-redirects)"
                )));
            }
            let base: ureq::http::Uri = url
                .parse()
                .map_err(|e| io::Error::other(format!("{url}: {e}")))?;
            let location = header(&resp, "Location").ok_or_else(|| {
                io::Error::other(format!("{url} answered {status} with no Location"))
            })?;
            let next = resolve(&base, &location)?;
            check_redirect(&base, &next, config.redirect_to_private, &named)?;
            url = next;
            followed += 1;
        }
    }

    /// An http(s) object to scan, and its size. It is read by range requests,
    /// or, with `opts.http_spill` and a spill to go to, downloaded once into a
    /// spill file by the same requests, so the passes of the scan read the
    /// disk instead of the network. A server that does not answer range
    /// requests has the object downloaded whole: into memory up to
    /// `opts.limits.max_buffer_bytes`, past it into a spill file, and refused past
    /// that. An object past `opts.max_scan_size` is not downloaded past it:
    /// only its head is scanned.
    pub fn open_http(
        url: &str,
        opts: &crate::ScanOptions,
    ) -> io::Result<(Box<dyn crate::spill::SpillReader>, u64)> {
        let (agent, url, resp) = probe(url, &opts.http_config())?;
        if resp.status() == 200 {
            return download(&url, resp, opts);
        }
        let mut r = HttpRangeReader::from_probe(
            agent,
            url,
            resp,
            opts.object_cache_block_bytes,
            opts.http_request_bytes,
        )?;
        let len = r.len();
        // Past `--max-input-bytes` only its head is scanned, so it is not
        // downloaded.
        if let Some(spill) = opts.spill.as_ref().filter(|_| opts.http_spill)
            && len > opts.limits.max_buffer_bytes
            && opts.max_scan_size.is_none_or(|m| len <= m)
        {
            match copy_to(&mut r, spill.as_ref(), None, len) {
                Ok((back, n)) if n == len => return Ok((back, len)),
                Ok((_, n)) => {
                    return Err(io::Error::other(format!(
                        "{}: {n} of its {len} bytes came",
                        r.url
                    )));
                }
                // A spill file it does not fit: read by ranges, as without one.
                Err(Stop::Spill(_)) => r.seek(SeekFrom::Start(0)).map(|_| ())?,
                Err(Stop::Read(e)) => return Err(e),
            }
        }
        Ok((Box::new(r), len))
    }

    /// Why a copy into a spill file stopped.
    enum Stop {
        Read(io::Error),
        Spill(String),
    }

    /// What `r` gives after `head`, in a new spill file, read back, and how
    /// many bytes the file holds: `limit` and one more at most, so that a
    /// source with more than `limit` shows it and is not read to its end.
    fn copy_to(
        r: &mut dyn Read,
        spill: &dyn crate::spill::Spill,
        head: Option<&[u8]>,
        limit: u64,
    ) -> Result<(Box<dyn crate::spill::SpillReader>, u64), Stop> {
        let mut file = spill.create().map_err(Stop::Spill)?;
        let mut n = 0u64;
        if let Some(head) = head {
            file.write(head).map_err(Stop::Spill)?;
            n += head.len() as u64;
        }
        let mut buf = vec![0u8; crate::byte_source::CHUNK];
        while n <= limit {
            let room = (limit - n + 1).min(buf.len() as u64) as usize;
            match r.read(&mut buf[..room]) {
                Ok(0) => break,
                Ok(k) => {
                    file.write(&buf[..k]).map_err(Stop::Spill)?;
                    n += k as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Stop::Read(e)),
            }
        }
        Ok((file.finish().map_err(Stop::Spill)?, n))
    }

    /// Up to `want` bytes of `body`, fewer if it ends first. The memory is
    /// asked for as the body arrives, not on the word of a length the server
    /// declares.
    pub(super) fn read_held(body: &mut impl Read, want: usize) -> io::Result<Vec<u8>> {
        let mut held = Vec::new();
        crate::unpack::source::read_capped(body, &mut held, want as u64)?;
        Ok(held)
    }

    /// The object a server sent whole, for one that does not answer range
    /// requests.
    ///
    /// Past `--max-input-bytes` only the bytes up to it are scanned, so those
    /// are all that is kept and the transfer stops there; the size is the one
    /// the server declared, or one over the limit when it did not say.
    fn download(
        url: &str,
        resp: ureq::http::Response<ureq::Body>,
        opts: &crate::ScanOptions,
    ) -> io::Result<(Box<dyn crate::spill::SpillReader>, u64)> {
        let declared = resp.body().content_length();
        let keep = opts.max_scan_size.unwrap_or(u64::MAX);
        let mut body = resp.into_body().into_reader();
        // Held in memory up to the smaller of the two limits.
        let hold = opts.limits.max_buffer_bytes.min(keep);
        let want = usize::try_from(hold.saturating_add(1)).unwrap_or(usize::MAX);
        let mut held = read_held(&mut body, want)?;
        if held.len() as u64 <= hold {
            let len = held.len() as u64;
            return Ok((Box::new(io::Cursor::new(held)), len));
        }
        if keep <= opts.limits.max_buffer_bytes {
            held.truncate(held.len() - 1);
            let size = declared.unwrap_or(0).max(keep.saturating_add(1));
            return Ok((Box::new(io::Cursor::new(held)), size));
        }
        let refused = |why: &str| {
            io::Error::other(format!(
                "{url} does not answer range requests, and is larger than \
                 --max-object-bytes {} with {why}",
                opts.limits.max_buffer_bytes
            ))
        };
        let Some(spill) = &opts.spill else {
            return Err(refused("no spill file to download it to"));
        };
        match copy_to(&mut body, spill.as_ref(), Some(&held), keep) {
            Ok((back, n)) if n <= keep => Ok((back, n)),
            Ok((back, n)) => Ok((back, declared.unwrap_or(0).max(n))),
            Err(Stop::Read(e)) => Err(e),
            Err(Stop::Spill(e)) => Err(refused(&format!(
                "a spill file that would not take it: {e}"
            ))),
        }
    }

    impl HttpRangeReader {
        fn cached(&self, pos: u64) -> bool {
            pos >= self.block_start && pos < self.block_start + self.block.len() as u64
        }

        fn fetch_block(&mut self, start: u64) -> io::Result<()> {
            let continues =
                !self.block.is_empty() && start == self.block_start + self.block.len() as u64;
            let size = match continues {
                true => (self.block.len() as u64 * 2).min(self.most),
                false => self.first,
            };
            self.block.clear();
            self.block_start = start;
            if start >= self.len {
                return Ok(());
            }
            let last = start.saturating_add(size).min(self.len) - 1;
            let mut req = self
                .agent
                .get(&self.url)
                .header("Range", format!("bytes={start}-{last}"));
            if let Some(pin) = &self.pin {
                req = req.header("If-Range", pin);
            }
            let resp = req.call().map_err(|e| io::Error::other(e.to_string()))?;
            // Anything but a partial response is not the range asked for: a
            // `200` is the object from its first byte, and under `If-Range`
            // the object as it is now, changed since the scan began.
            if resp.status() != 206 {
                let why = match (resp.status().as_u16(), &self.pin) {
                    (200, Some(_)) => ": the object changed since the scan began",
                    _ => "",
                };
                return Err(io::Error::other(format!(
                    "range request answered with status {}{why}",
                    resp.status()
                )));
            }
            if let Some(etag) = &self.etag
                && header(&resp, "ETag").is_some_and(|t| t != *etag)
            {
                return Err(io::Error::other(format!(
                    "{} changed since the scan began: its ETag was {etag}",
                    self.url
                )));
            }
            // The range it says it sent, of the object it said it was: a server
            // that answers another range hands over bytes of another place, and
            // one whose object has changed since a scan began hands over a
            // mixture. Neither is the object that was asked to be scanned.
            let range = resp
                .headers()
                .get("Content-Range")
                .and_then(|cr| cr.to_str().ok())
                .and_then(|cr| cr.trim().strip_prefix("bytes "))
                .and_then(|cr| {
                    let (span, total) = cr.split_once('/')?;
                    let (from, _) = span.split_once('-')?;
                    Some((
                        from.trim().parse::<u64>().ok()?,
                        total.trim().parse::<u64>().ok(),
                    ))
                });
            match range {
                Some((from, total)) if from == start && total.is_none_or(|t| t == self.len) => {}
                other => {
                    return Err(io::Error::other(format!(
                        "range request for bytes {start}-{last} of {} answered with {other:?} \
                         (the object is {} bytes)",
                        self.url, self.len
                    )));
                }
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
                    false => (self.pos / self.first) * self.first,
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
pub use http::{HttpConfig, HttpRangeReader, open_http};

#[cfg(all(test, feature = "http"))]
mod tests {
    use super::http::{Refuse, probe_with};
    use super::{HttpConfig, HttpRangeReader, open_http};
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
    use std::net::{IpAddr, SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};

    /// A request as the test servers see it.
    struct Req {
        path: String,
        host: String,
        range: Option<(usize, usize)>,
        if_range: Option<String>,
    }

    /// Serve on a local port, one request per connection, answering the
    /// `n`th request with what `answer` makes of it. The base URL, and the
    /// count of requests answered.
    fn serve_fn(
        answer: impl Fn(usize, &Req) -> Vec<u8> + Send + 'static,
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&count);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { return };
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut req = Req {
                    path: String::new(),
                    host: String::new(),
                    range: None,
                    if_range: None,
                };
                let mut first = true;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if first {
                        req.path = line.split(' ').nth(1).unwrap_or("").to_string();
                        first = false;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(r) = lower.strip_prefix("range: bytes=") {
                        let (a, b) = r.trim().split_once('-').unwrap();
                        req.range = Some((a.parse().unwrap(), b.parse().unwrap()));
                    }
                    if lower.starts_with("if-range:") {
                        req.if_range = Some(line[9..].trim().to_string());
                    }
                    if lower.starts_with("host:") {
                        req.host = line[5..].trim().to_string();
                    }
                }
                let n = counted.fetch_add(1, Ordering::SeqCst);
                let _ = conn.write_all(&answer(n, &req));
            }
        });
        (base, count)
    }

    /// `206` with the range asked for of `body`, and `headers`.
    fn partial(body: &[u8], (a, b): (usize, usize), headers: &str) -> Vec<u8> {
        let b = b.min(body.len() - 1);
        let part = &body[a..=b];
        let h = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {a}-{b}/{}\r\n\
             Content-Length: {}\r\n{headers}Connection: close\r\n\r\n",
            body.len(),
            part.len()
        );
        [h.as_bytes(), part].concat()
    }

    /// `200` with all of `body`, and `headers`.
    fn whole(body: &[u8], headers: &str) -> Vec<u8> {
        let h = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
            body.len()
        );
        [h.as_bytes(), body].concat()
    }

    fn redirect(to: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    }

    fn body(n: u32) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn config(private: bool) -> HttpConfig {
        HttpConfig {
            redirect_to_private: private,
            ..HttpConfig::default()
        }
    }

    /// An object that changes between requests is an error, not a scan of a
    /// mixture: a server that honours `If-Range` sends all of the new one,
    /// and one that does not sends another `ETag`.
    #[test]
    fn an_object_that_changes_is_an_error() {
        let old = body(300_000);
        let new: Vec<u8> = old.iter().map(|b| b ^ 1).collect();
        for honours in [true, false] {
            let (old, new) = (old.clone(), new.clone());
            let (base, _) = serve_fn(move |n, req| {
                let (b, tag) = match n {
                    0 => (&old, "\"v1\""),
                    _ => (&new, "\"v2\""),
                };
                let etag = format!("ETag: {tag}\r\n");
                match (req.range, &req.if_range) {
                    (Some(_), Some(t)) if honours && t != tag => whole(b, &etag),
                    (Some(r), _) => partial(b, r, &etag),
                    (None, _) => whole(b, &etag),
                }
            });
            let mut r = HttpRangeReader::open_with(&format!("{base}/obj"), 1000, 1000).unwrap();
            let mut all = Vec::new();
            let e = r.read_to_end(&mut all).expect_err("the object changed");
            assert!(
                e.to_string().contains("changed since the scan began"),
                "{e}"
            );
        }
    }

    /// The pin is the strong `ETag`, else `Last-Modified`, sent as `If-Range`.
    #[test]
    fn requests_carry_the_pin() {
        for (headers, want) in [
            ("ETag: \"abc\"\r\n", "\"abc\""),
            (
                "ETag: W/\"weak\"\r\nLast-Modified: Mon, 02 Nov 2026 10:00:00 GMT\r\n",
                "Mon, 02 Nov 2026 10:00:00 GMT",
            ),
        ] {
            let b = body(5000);
            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
            let log = Arc::clone(&seen);
            let (base, _) = serve_fn(move |_, req| {
                log.lock().unwrap().push(req.if_range.clone());
                partial(&b, req.range.unwrap(), headers)
            });
            let mut r = HttpRangeReader::open_with(&format!("{base}/obj"), 1000, 1000).unwrap();
            r.read_to_end(&mut Vec::new()).unwrap();
            let seen = seen.lock().unwrap();
            assert_eq!(seen[0], None);
            assert!(
                seen[1..].iter().all(|p| p.as_deref() == Some(want)),
                "{seen:?}"
            );
        }
    }

    /// Redirects are followed to the object, within their count, and never to
    /// another scheme.
    #[test]
    fn redirects_are_bounded() {
        let b = body(5000);
        let (base, _) = serve_fn(move |_, req| match req.path.as_str() {
            "/a" => redirect("/b"),
            "/b" => redirect("obj"),
            "/http" => redirect("https://127.0.0.1:1/obj"),
            _ => partial(&b, req.range.unwrap(), ""),
        });
        let url = format!("{base}/a");
        let mut r = HttpRangeReader::open_config(&url, 1000, 1000, &config(true)).unwrap();
        assert_eq!(r.url(), format!("{base}/obj"));
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, body(5000));
        // The host the caller named is the caller's choice, a loopback one
        // here, however the server moves the request about on it.
        HttpRangeReader::open_config(&url, 1000, 1000, &config(false)).unwrap();
        let mut c = config(true);
        c.max_redirects = Some(1);
        let e = HttpRangeReader::open_config(&url, 1000, 1000, &c).err();
        assert!(e.unwrap().to_string().contains("redirects more than 1"));
        let e = HttpRangeReader::open_config(&format!("{base}/http"), 1000, 1000, &config(true));
        assert!(e.err().unwrap().to_string().contains("changes the scheme"));
    }

    /// The names a server redirects to, looked up by the test and not by the
    /// system: every one resolves to the server's loopback address on the
    /// port asked for, the first time to `first` and after it to `later`.
    #[derive(Debug)]
    struct Names {
        calls: AtomicUsize,
        first: std::net::IpAddr,
        later: std::net::IpAddr,
    }

    impl Names {
        fn new(first: &str, later: &str) -> Box<Self> {
            Box::new(Names {
                calls: AtomicUsize::new(0),
                first: first.parse().unwrap(),
                later: later.parse().unwrap(),
            })
        }
    }

    impl Resolver for Names {
        fn resolve(
            &self,
            uri: &ureq::http::Uri,
            config: &ureq::config::Config,
            timeout: ureq::unversioned::transport::NextTimeout,
        ) -> Result<ResolvedSocketAddrs, ureq::Error> {
            // An address written out is not a name.
            if uri.host().is_some_and(|h| h.parse::<IpAddr>().is_ok()) {
                return DefaultResolver::default().resolve(uri, config, timeout);
            }
            let ip = match self.calls.fetch_add(1, Ordering::SeqCst) {
                0 => self.first,
                _ => self.later,
            };
            let mut found = self.empty();
            found.push(SocketAddr::new(ip, uri.port_u16().unwrap()));
            Ok(found)
        }
    }

    fn port_of(req: &Req) -> &str {
        req.host.rsplit(':').next().unwrap()
    }

    fn refuse_private() -> Option<Refuse> {
        Some(Arc::new(super::http::is_private))
    }

    /// A redirect to a host the caller did not name is refused when it is
    /// connected to if the name leads to a private address, however the
    /// address is written, and followed when private addresses are allowed.
    #[test]
    fn a_redirect_to_a_private_address_is_refused() {
        let b = body(5000);
        let (base, _) = serve_fn(move |_, req| match req.path.as_str() {
            "/name" => redirect(&format!("http://elsewhere.test:{}/obj", port_of(req))),
            "/literal" => redirect(&format!("http://127.0.0.2:{}/obj", port_of(req))),
            _ => partial(&b, req.range.unwrap(), ""),
        });
        let open = |path: &str, refuse: Option<Refuse>| {
            probe_with(
                &format!("{base}/{path}"),
                &HttpConfig::default(),
                Names::new("127.0.0.1", "127.0.0.1"),
                refuse,
            )
        };
        for path in ["name", "literal"] {
            let e = open(path, refuse_private()).expect_err(path);
            assert!(e.to_string().contains("private address"), "{path}: {e}");
        }
        open("name", None).unwrap();
    }

    /// A name whose answer changes between the redirect and a later request is
    /// refused when the later one connects: the check is not a lookup made
    /// beforehand, which the connection would not repeat.
    #[test]
    fn a_name_that_changes_its_answer_is_refused_when_connected() {
        let b = body(5000);
        let (base, _) = serve_fn(move |_, req| match req.path.as_str() {
            "/start" => redirect(&format!("http://rebind.test:{}/obj", port_of(req))),
            _ => partial(&b, req.range.unwrap(), ""),
        });
        // The test serves on loopback, so what it refuses is the other family:
        // `rebind.test` is allowed the first time and refused after.
        let refuse: Option<Refuse> = Some(Arc::new(|ip: IpAddr| ip.is_ipv6()));
        let (agent, url, resp) = probe_with(
            &format!("{base}/start"),
            &HttpConfig::default(),
            Names::new("127.0.0.1", "::1"),
            refuse,
        )
        .unwrap();
        let mut r = HttpRangeReader::from_probe(agent, url, resp, 1000, 1000).unwrap();
        let e = r
            .read_to_end(&mut Vec::new())
            .expect_err("the name now leads to a refused address");
        assert!(e.to_string().contains("private address"), "{e}");
    }

    /// Serve `total` bytes to one client that does not honour ranges, in
    /// pieces, with or without a `Content-Length`; the number of them it got
    /// out before the client went away comes from the thread.
    fn serve_stream(total: usize, declared: bool) -> (String, std::thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let sender = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            let length = if declared {
                format!("Content-Length: {total}\r\n")
            } else {
                String::new()
            };
            let head = format!("HTTP/1.1 200 OK\r\n{length}Connection: close\r\n\r\n");
            let _ = conn.write_all(head.as_bytes());
            let mut sent = 0;
            while sent < total {
                let n = (total - sent).min(65_536);
                let piece: Vec<u8> = (sent..sent + n).map(|i| (i % 251) as u8).collect();
                if conn.write_all(&piece).is_err() {
                    break;
                }
                sent += n;
            }
            sent
        });
        (base, sender)
    }

    /// A download past `--max-input-bytes` stops there: the bytes up to it
    /// are kept, in memory or in a spill file by `--max-object-bytes`, the
    /// size is the declared one (or one over the limit, when the server said
    /// none) and the rest of the object is not transferred.
    #[test]
    fn a_download_stops_at_the_input_limit() {
        const TOTAL: usize = 48 << 20;
        const KEEP: usize = 300_000;
        // Held in memory, and in a spill file.
        for (deep, held_bytes) in [(1usize << 20, KEEP), (100_000, KEEP + 1)] {
            for declared in [true, false] {
                let (base, sender) = serve_stream(TOTAL, declared);
                let opts = crate::ScanOptions {
                    max_scan_size: Some(KEEP as u64),
                    spill: mem_spill(),
                    ..holding(deep as u64)
                };
                let (mut r, size) = open_http(&format!("{base}/obj"), &opts).unwrap();
                let want = if declared {
                    TOTAL as u64
                } else {
                    KEEP as u64 + 1
                };
                assert_eq!(size, want, "deep {deep}, declared {declared}");
                let mut got = Vec::new();
                r.read_to_end(&mut got).unwrap();
                assert_eq!(got.len(), held_bytes, "deep {deep}, declared {declared}");
                assert!(
                    got.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8),
                    "deep {deep}, declared {declared}"
                );
                drop(r);
                let sent = sender.join().unwrap();
                assert!(sent < TOTAL / 2, "{sent} of {TOTAL} bytes were sent");
            }
        }
    }

    /// A body read into memory, of a size the limit does not tell, is held at
    /// about its size, not at the capacity doubling leaves (here 8 MiB for
    /// 5 MB).
    #[test]
    fn a_body_is_held_once() {
        let n = 5_000_000usize;
        let src = body(n as u32);
        let held = super::http::read_held(&mut &src[..], 100_000_000).unwrap();
        assert_eq!(held, src);
        assert!(
            held.capacity() <= n + n / 4 + (1 << 20),
            "{}",
            held.capacity()
        );
    }

    /// An object past `--max-input-bytes` is not downloaded into a spill file:
    /// only its head is scanned.
    #[test]
    fn an_object_over_the_input_limit_is_not_spilled() {
        let b = body(300_000);
        let (base, count) = serve_fn(move |_, req| partial(&b, req.range.unwrap(), ""));
        let opts = crate::ScanOptions {
            max_scan_size: Some(50_000),
            http_spill: true,
            spill: mem_spill(),
            ..holding(10_000)
        };
        open_http(&format!("{base}/obj"), &opts).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// Addresses only the host or its network reaches, however written.
    #[test]
    fn private_addresses_are_private() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "169.254.169.254",
            "0.1.2.3",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "fec0::1",
        ] {
            assert!(super::http::is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["93.184.216.34", "2606:2800:220:1::1", "64:ff9b::5db8:d822"] {
            assert!(!super::http::is_private(ip.parse().unwrap()), "{ip}");
        }
    }

    /// A request that takes longer than the timeout fails.
    #[test]
    fn a_slow_request_times_out() {
        let b = body(5000);
        let (base, _) = serve_fn(move |n, req| {
            if n > 0 {
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            partial(&b, req.range.unwrap(), "")
        });
        let c = HttpConfig {
            timeout: Some(std::time::Duration::from_millis(500)),
            ..HttpConfig::default()
        };
        let mut r = HttpRangeReader::open_config(&format!("{base}/obj"), 1000, 1000, &c).unwrap();
        let started = std::time::Instant::now();
        assert!(r.read_to_end(&mut Vec::new()).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }

    fn mem_spill() -> Option<Arc<dyn crate::spill::Spill>> {
        Some(Arc::new(exav_unpack::spill::MemSpill::new()))
    }

    /// The default options with the object limit set to `max`.
    fn holding(max: u64) -> crate::ScanOptions {
        let mut opts = crate::ScanOptions::default();
        opts.limits.max_buffer_bytes = max;
        opts
    }

    /// A server that does not answer range requests has the object
    /// downloaded whole: into memory within the limit, into a spill past it,
    /// and refused past that.
    #[test]
    fn a_server_without_ranges_is_downloaded() {
        let b = body(100_000);
        let served = b.clone();
        let (base, _) = serve_fn(move |_, _| whole(&served, ""));
        let url = format!("{base}/obj");
        let read = |opts: &crate::ScanOptions| {
            open_http(&url, opts).map(|(mut r, len)| {
                let mut all = Vec::new();
                r.read_to_end(&mut all).unwrap();
                assert_eq!(all.len() as u64, len);
                all
            })
        };
        let mut opts = crate::ScanOptions::default();
        assert_eq!(read(&opts).unwrap(), b);
        opts.limits.max_buffer_bytes = 10_000;
        let e = read(&opts).unwrap_err();
        assert!(
            e.to_string().contains("does not answer range requests"),
            "{e}"
        );
        opts.spill = mem_spill();
        assert_eq!(read(&opts).unwrap(), b);
    }

    /// With `http_spill`, the object is fetched once, and every pass after
    /// reads the spill file.
    #[test]
    fn a_spilled_object_is_fetched_once() {
        let b = body(300_000);
        let served = b.clone();
        let (base, count) = serve_fn(move |_, req| partial(&served, req.range.unwrap(), ""));
        let opts = crate::ScanOptions {
            object_cache_block_bytes: 10_000,
            http_request_bytes: 100_000,
            http_spill: true,
            spill: mem_spill(),
            ..holding(10_000)
        };
        let (mut r, len) = open_http(&format!("{base}/obj"), &opts).unwrap();
        let fetched = count.load(Ordering::SeqCst);
        for _ in 0..3 {
            r.seek(SeekFrom::Start(0)).unwrap();
            let mut all = Vec::new();
            r.read_to_end(&mut all).unwrap();
            assert_eq!((all.len() as u64, &all), (len, &b));
        }
        assert_eq!(count.load(Ordering::SeqCst), fetched);
        // The probe, then 10,000 bytes doubling to 100,000: seven requests.
        assert_eq!(fetched, 7);
    }

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

    /// A server that answers the first request as it should and every later one
    /// with the range `shift` bytes on from the one asked for (`Offset`), or with
    /// the range asked for of an object of another size (`Total`).
    enum Wrong {
        Offset,
        Total,
    }

    fn serve_wrong(body: Vec<u8>, wrong: Wrong) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/obj", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for (n, conn) in listener.incoming().enumerate() {
                let Ok(mut conn) = conn else { return };
                let mut range = (0usize, 0usize);
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(r) = line.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        let (a, b) = r.trim().split_once('-').unwrap();
                        range = (a.parse().unwrap(), b.parse().unwrap());
                    }
                }
                let (a, b) = range;
                let (from, to, total) = match (&wrong, n) {
                    (_, 0) => (a, b, body.len()),
                    (Wrong::Offset, _) => (
                        (a + 1).min(body.len() - 1),
                        (b + 1).min(body.len() - 1),
                        body.len(),
                    ),
                    (Wrong::Total, _) => (a, b, body.len() + 7),
                };
                let part = &body[from..=to];
                let h = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {from}-{to}/{total}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    part.len()
                );
                let _ = conn.write_all(&[h.as_bytes(), part].concat());
            }
        });
        url
    }

    /// The bytes of a range are the bytes of the range that was asked for, of
    /// the object that was asked about.
    #[test]
    fn an_answer_for_another_range_or_another_object_is_refused() {
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        for wrong in [Wrong::Offset, Wrong::Total] {
            let mut r = HttpRangeReader::open(&serve_wrong(body.clone(), wrong)).unwrap();
            let mut all = Vec::new();
            let e = r
                .read_to_end(&mut all)
                .expect_err("the answer is not the range asked for");
            assert!(e.to_string().contains("answered with"), "{e}");
        }
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

    /// The size of a request that starts a read, and the most one may grow to,
    /// are the caller's.
    #[test]
    fn the_request_sizes_are_the_callers() {
        let body = vec![7u8; 3_000_000];
        let sequential = |first, most| {
            let mut r =
                HttpRangeReader::open_with(&serve(body.clone(), false), first, most).unwrap();
            let mut all = Vec::new();
            r.read_to_end(&mut all).unwrap();
            assert_eq!(all, body);
            r
        };
        // One request per 100,000 bytes.
        assert_eq!(sequential(100_000, 100_000).requests, 30);
        // 10 KB, doubling up to 1 MB: seven requests to 1,270,000 bytes, two
        // of 1 MB, the rest.
        let mut r = sequential(10_000, 1_000_000);
        assert_eq!(r.requests, 9);
        // A read elsewhere is one request of the first size, from its block.
        let (requests, fetched) = (r.requests, r.bytes_fetched);
        r.seek(SeekFrom::Start(123)).unwrap();
        r.read_exact(&mut [0u8; 10]).unwrap();
        assert_eq!(r.requests, requests + 1);
        assert_eq!(r.bytes_fetched, fetched + 10_000);
        // The defaults are the ones `open` has.
        assert_eq!(
            (super::http::BLOCK, super::http::MAX_BLOCK),
            (1 << 20, 8 << 20)
        );
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
