#![no_main]
//! The ICAP server (RFC 3507) as a proxy or a mail gateway sees it: the request
//! line and headers, the `Encapsulated` offsets that cut the rest of the
//! request into an HTTP head and a body, `Preview`, `Allow: 204`, and the
//! chunked body with its extensions, `ieof` and trailers, over memory in place
//! of a socket (`exav::fuzzing::icap`). The parsers read straight off the
//! network.
//!
//! The input is a list of requests (`arbitrary`) written out as a client writes
//! them, with the mistakes one makes: offsets that point past the head, chunk
//! sizes that lie, a body with no last chunk, a line ending that is not CRLF.
//!
//! One check beyond "does not panic": for a request that is plain and correct,
//! a `REQMOD` of some bytes is blocked (an `X-Infection-Found` header) when
//! `analyze` calls the bytes anything but clean, and is not when it calls them
//! clean (`crates/exav/src/icap/mod.rs`, the verdict table).
use arbitrary::Arbitrary;
use exav_core::{analyze, ScanOptions, VerdictCategory};
use libfuzzer_sys::fuzz_target;

#[path = "../db.rs"]
mod db;

#[derive(Arbitrary, Debug)]
enum Method {
    Options,
    Reqmod,
    Respmod,
    Other(String),
}

#[derive(Arbitrary, Debug)]
enum Service {
    Avscan,
    VirusScan,
    Other(String),
}

#[derive(Arbitrary, Debug)]
enum Offsets {
    /// What the pieces sent add up to.
    Honest,
    /// The header's value, whatever it says.
    Raw(String),
}

#[derive(Arbitrary, Debug)]
enum Eol {
    Crlf,
    Lf,
}

#[derive(Arbitrary, Debug)]
struct Chunk {
    data: Vec<u8>,
    /// Declares this many bytes more or fewer (wrapping).
    lie: i16,
    extension: Option<String>,
    upper_hex: bool,
}

#[derive(Arbitrary, Debug)]
struct Body {
    chunks: Vec<Chunk>,
    ieof: bool,
    trailer: Vec<String>,
    /// Ends without the last chunk.
    unterminated: bool,
    eol: Eol,
}

impl Body {
    fn write(&self, out: &mut Vec<u8>) {
        let eol: &[u8] = match self.eol {
            Eol::Crlf => b"\r\n",
            Eol::Lf => b"\n",
        };
        for c in &self.chunks {
            if c.data.is_empty() {
                continue;
            }
            let declared = (c.data.len() as i64 + i64::from(c.lie)).max(0);
            let size = if c.upper_hex {
                format!("{declared:X}")
            } else {
                format!("{declared:x}")
            };
            out.extend_from_slice(size.as_bytes());
            if let Some(e) = &c.extension {
                out.push(b';');
                out.extend_from_slice(e.as_bytes());
            }
            out.extend_from_slice(eol);
            out.extend_from_slice(&c.data);
            out.extend_from_slice(eol);
        }
        if !self.unterminated {
            out.push(b'0');
            if self.ieof {
                out.extend_from_slice(b"; ieof");
            }
            out.extend_from_slice(eol);
            for t in &self.trailer {
                out.extend_from_slice(t.as_bytes());
                out.extend_from_slice(eol);
            }
            out.extend_from_slice(eol);
        }
    }

    /// The bytes of a body that is correct, or `None`.
    fn honest(&self) -> Option<Vec<u8>> {
        let plain = !self.unterminated
            && !self.ieof
            && self.trailer.is_empty()
            && matches!(self.eol, Eol::Crlf)
            && self.chunks.iter().all(|c| c.lie == 0 && c.extension.is_none());
        plain.then(|| {
            self.chunks
                .iter()
                .flat_map(|c| c.data.iter().copied())
                .collect()
        })
    }
}

#[derive(Arbitrary, Debug)]
struct Request {
    method: Method,
    service: Service,
    allow_204: bool,
    preview: Option<u16>,
    headers: Vec<(String, String)>,
    req_hdr: Option<Vec<u8>>,
    res_hdr: Option<Vec<u8>>,
    offsets: Offsets,
    body: Option<Body>,
}

const REQ_HDR: &[u8] = b"POST /upload HTTP/1.1\r\nHost: example.com\r\n\r\n";

impl Request {
    fn write(&self, out: &mut Vec<u8>) {
        let method = match &self.method {
            Method::Options => "OPTIONS",
            Method::Reqmod => "REQMOD",
            Method::Respmod => "RESPMOD",
            Method::Other(m) => m.as_str(),
        };
        let service = match &self.service {
            Service::Avscan => "avscan",
            Service::VirusScan => "virus_scan",
            Service::Other(s) => s.as_str(),
        };
        let mut block = Vec::new();
        let mut parts: Vec<(&str, usize)> = Vec::new();
        if let Some(h) = &self.req_hdr {
            parts.push(("req-hdr", block.len()));
            block.extend_from_slice(h);
        }
        if let Some(h) = &self.res_hdr {
            parts.push(("res-hdr", block.len()));
            block.extend_from_slice(h);
        }
        let terminal = match (&self.body, &self.method) {
            (None, _) => "null-body",
            (Some(_), Method::Reqmod) => "req-body",
            (Some(_), _) => "res-body",
        };
        parts.push((terminal, block.len()));
        let encapsulated = match &self.offsets {
            Offsets::Honest => parts
                .iter()
                .map(|(n, o)| format!("{n}={o}"))
                .collect::<Vec<_>>()
                .join(", "),
            Offsets::Raw(s) => s.clone(),
        };

        out.extend_from_slice(format!("{method} icap://127.0.0.1/{service} ICAP/1.0\r\nHost: 127.0.0.1\r\n").as_bytes());
        if self.allow_204 {
            out.extend_from_slice(b"Allow: 204\r\n");
        }
        if let Some(p) = self.preview {
            out.extend_from_slice(format!("Preview: {p}\r\n").as_bytes());
        }
        for (k, v) in &self.headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Encapsulated: {encapsulated}\r\n\r\n").as_bytes());
        out.extend_from_slice(&block);
        if let Some(b) = &self.body {
            b.write(out);
        }
    }

    /// The body of a request this target can say the answer to: a plain,
    /// correct `REQMOD` of the one service, with nothing to change how it is
    /// read.
    fn plain_body(&self) -> Option<Vec<u8>> {
        let plain = matches!(self.method, Method::Reqmod)
            && matches!(self.service, Service::Avscan | Service::VirusScan)
            && matches!(self.offsets, Offsets::Honest)
            && self.preview.is_none()
            && self.headers.is_empty()
            && self.req_hdr.as_deref() == Some(REQ_HDR)
            && self.res_hdr.is_none();
        if !plain {
            return None;
        }
        self.body.as_ref()?.honest()
    }
}

fn options() -> ScanOptions {
    let mut o = ScanOptions::default();
    let l = &mut o.limits;
    l.max_recursion = 8;
    l.max_members = 1_000;
    l.max_extracted_bytes = 8 << 20;
    l.max_compression_ratio = 200;
    l.max_buffer_bytes = 4 << 20;
    l.max_scanned_bytes = 16 << 20;
    l.max_pe_emulation_steps = 2_000_000;
    o
}

fuzz_target!(|data: &[u8]| {
    let Ok(requests) = Vec::<Request>::arbitrary(&mut arbitrary::Unstructured::new(data)) else {
        return;
    };
    let mut input = Vec::new();
    for r in &requests {
        r.write(&mut input);
    }
    let opts = options();
    let out = exav_cli::fuzzing::icap(&input, db::shared(), &opts);

    if let [only] = requests.as_slice() {
        if let Some(body) = only.plain_body() {
            if body.is_empty() {
                return;
            }
            let blocked = analyze(db::scanner(), &body, &opts).verdict.category() != VerdictCategory::Clean;
            let said = String::from_utf8_lossy(&out).contains("X-Infection-Found:");
            assert_eq!(said, blocked, "ICAP said {:?} of bytes analyze judges {:?}", String::from_utf8_lossy(&out), blocked);
        }
    }
});
