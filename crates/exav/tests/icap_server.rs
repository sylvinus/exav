//! End to end over ICAP: a real `exav --listen icap://…` process on a real socket, driven
//! by a client written here that speaks the wire protocol byte for byte.
//!
//! Two things make this the shape these answers need. The bytes on the wire are
//! the only thing a c-icap client or Squid ever sees, so the client below parses
//! them with its own code rather than the server's — a framing bug both sides
//! share would otherwise cancel itself out. And the server is the shipped
//! binary, started from a command line, so the flag parsing, the database load
//! and the listener are the ones an operator gets.

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// The binary's own temp-directory type, so the test suite needs no temp-file
// dependency either.
#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

/// The EICAR test file: the industry-standard string every scanner detects.
const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// A minimal HTTP response header block for the encapsulated message.
const RES_HDR: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n";

/// A minimal HTTP request header block.
const REQ_HDR: &[u8] = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n";

/// A one-member ZIP with the encryption bit set, so exav reports it
/// `PASSWORD-PROTECTED`.
///
/// The tests that need a partial verdict *other than* a size limit use
/// this: since the ICAP listener took its size ceiling from `--max-input-bytes`
/// like every other surface, an over-limit object no longer has its whole body
/// in hand, and some of these properties are about what happens when it does.
fn encrypted_zip() -> Vec<u8> {
    const NAME: &str = "secret.bin";
    // Anything at all — the general-purpose bit flag is what marks the member
    // encrypted, and no reader gets past that without a password.
    const DATA: &[u8] = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0cciphertext";
    /// Bit 0 of the general-purpose bit flag: the member is encrypted.
    const ENCRYPTED: u16 = 1;

    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&ENCRYPTED.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // stored
    out.extend_from_slice(&0u16.to_le_bytes()); // time
    out.extend_from_slice(&0u16.to_le_bytes()); // date
    out.extend_from_slice(&0u32.to_le_bytes()); // crc — unchecked, nothing decodes this
    out.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
    out.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
    out.extend_from_slice(&(NAME.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra
    out.extend_from_slice(NAME.as_bytes());
    out.extend_from_slice(DATA);

    let cd_offset = out.len() as u32;
    let mut cd = Vec::new();
    cd.extend_from_slice(b"PK\x01\x02");
    cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
    cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
    cd.extend_from_slice(&ENCRYPTED.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes()); // stored
    cd.extend_from_slice(&0u16.to_le_bytes()); // time
    cd.extend_from_slice(&0u16.to_le_bytes()); // date
    cd.extend_from_slice(&0u32.to_le_bytes()); // crc
    cd.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(NAME.len() as u16).to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes()); // extra
    cd.extend_from_slice(&0u16.to_le_bytes()); // comment
    cd.extend_from_slice(&0u16.to_le_bytes()); // disk
    cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    cd.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    cd.extend_from_slice(NAME.as_bytes());
    let cd_len = cd.len() as u32;
    out.extend_from_slice(&cd);

    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with the directory
    out.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
    out.extend_from_slice(&1u16.to_le_bytes()); // entries total
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment
    out
}

// ───────────────────────────── harness ─────────────────────────────

fn exav_bin() -> &'static str {
    env!("CARGO_BIN_EXE_exav")
}

/// A running `exav --listen icap://…`, stopped when the test drops it.
struct Server {
    child: Child,
    /// The address the process reported binding.
    addr: String,
    _db: TempDir,
    _dir: TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// Start a server on a port of its own, scanning with the signatures in
    /// `db` (an empty directory means the built-in EICAR-only baseline).
    ///
    /// The port is `0`, so the kernel picks it and two tests running side by
    /// side cannot land on the same one. Which port that turned out to be is
    /// read back from the line the process prints when it starts serving, which
    /// is also how an operator finds out.
    fn start(db: TempDir, extra: &[&str]) -> Server {
        Server::start_at("icap://127.0.0.1:0", db, extra)
    }

    /// The same, with the listen address spelled out — for the settings that
    /// ride on it (`?mode=`, `?max-connections=`) rather than on a flag.
    fn start_at(listen: &str, db: TempDir, extra: &[&str]) -> Server {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("stderr.log");
        let child = Command::new(exav_bin())
            .arg("--listen")
            .arg(listen)
            .arg("-d")
            .arg(db.path())
            .args(extra)
            // Deliberately the built-in EICAR-only baseline where `-d` is empty;
            // exav otherwise refuses to run with no real database.
            .env("EXAV_ALLOW_NO_DB", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(&log).expect("create the log"),
            ))
            .spawn()
            .expect("start exav --listen icap://…");
        let addr = announced_addr(&log);
        Server {
            child,
            addr,
            _db: db,
            _dir: dir,
        }
    }

    fn connect(&self) -> Conn {
        let stream = TcpStream::connect(self.addr.as_str()).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        Conn {
            reader: BufReader::new(stream.try_clone().unwrap()),
            writer: stream,
        }
    }
}

/// Wait for the server to announce its listener, and return the address it
/// named.
fn announced_addr(log: &std::path::Path) -> String {
    const MARKER: &str = "serving ICAP on tcp:";
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if let Some(rest) = text.split_once(MARKER).map(|(_, r)| r) {
            let addr = rest
                .split_whitespace()
                .next()
                .expect("the announcement names an address");
            return addr.to_string();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "the server never announced its listener:\n{}",
        std::fs::read_to_string(log).unwrap_or_default()
    );
}

/// A server over the built-in baseline and the default configuration.
fn start_default() -> Server {
    Server::start(TempDir::new().unwrap(), &[])
}

/// A port nothing is listening on, for the tests that need the clamd listener
/// alongside the ICAP one. Racy in principle, free of coordination in practice —
/// and the ICAP side already asks the kernel for its own.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a localhost port")
        .local_addr()
        .expect("its address")
        .port()
}

/// Send one clamd `INSTREAM` and return the verdict line, so a test can ask the
/// two listeners the same question and compare their answers.
fn clamd_instream(port: u16, body: &[u8]) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut s = loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            break s;
        }
        assert!(
            Instant::now() < deadline,
            "nothing answered on clamd {port}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    s.write_all(b"zINSTREAM\0").unwrap();
    s.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    s.write_all(body).unwrap();
    s.write_all(&0u32.to_be_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    String::from_utf8_lossy(&out).trim_end_matches('\0').into()
}

struct Conn {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

/// A parsed ICAP response.
#[derive(Debug)]
struct Resp {
    code: u16,
    reason: String,
    headers: Vec<(String, String)>,
    /// The encapsulated HTTP header block, verbatim.
    encapsulated_hdr: Vec<u8>,
    /// The decoded encapsulated body.
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn has_header(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl Conn {
    fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).expect("send");
        self.writer.flush().expect("flush");
    }

    /// Read one line including its CRLF, as a client that trusts nothing about
    /// the framing has to.
    fn line(&mut self) -> String {
        let mut raw = Vec::new();
        loop {
            let mut b = [0u8; 1];
            match self.reader.read(&mut b) {
                Ok(0) => panic!("connection closed mid-line, so far: {raw:?}"),
                Ok(_) => {}
                Err(e) => panic!("read failed: {e}"),
            }
            if b[0] == b'\n' {
                break;
            }
            if b[0] != b'\r' {
                raw.push(b[0]);
            }
        }
        String::from_utf8(raw).expect("ICAP heads are ASCII")
    }

    fn recv(&mut self) -> Resp {
        // A stray blank line before the status line is legal framing; every
        // other empty line ends the head.
        let status = loop {
            let l = self.line();
            if !l.is_empty() {
                break l;
            }
        };
        let mut fields = status.splitn(3, ' ');
        assert_eq!(fields.next(), Some("ICAP/1.0"), "status line: {status:?}");
        let code: u16 = fields
            .next()
            .expect("status code")
            .parse()
            .expect("numeric");
        let reason = fields.next().unwrap_or("").to_string();

        let mut headers = Vec::new();
        loop {
            let l = self.line();
            if l.is_empty() {
                break;
            }
            let (k, v) = l.split_once(':').expect("header line");
            headers.push((k.to_string(), v.trim().to_string()));
        }

        let mut resp = Resp {
            code,
            reason,
            headers,
            encapsulated_hdr: Vec::new(),
            body: Vec::new(),
        };

        if let Some(raw) = resp.header("Encapsulated") {
            let (header_bytes, has_body) = encapsulated(raw);
            resp.encapsulated_hdr = vec![0u8; header_bytes];
            self.reader
                .read_exact(&mut resp.encapsulated_hdr)
                .expect("encapsulated headers");
            if has_body {
                resp.body = self.chunked_body();
            }
        }
        resp
    }

    /// Decode a chunk-encoded body, stopping at the blank line after the last
    /// chunk so the stream is left where the next response starts.
    fn chunked_body(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let line = self.line();
            let size_text = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_text, 16)
                .unwrap_or_else(|e| panic!("chunk size {size_text:?}: {e}"));
            if size == 0 {
                // The trailer section, which the server leaves empty.
                while !self.line().is_empty() {}
                return out;
            }
            let mut chunk = vec![0u8; size];
            self.reader.read_exact(&mut chunk).expect("chunk data");
            out.extend_from_slice(&chunk);
            assert!(self.line().is_empty(), "chunk must end with CRLF");
        }
    }
}

/// The length of the encapsulated header block and whether a body follows,
/// read out of an `Encapsulated` value the way a client does.
fn encapsulated(raw: &str) -> (usize, bool) {
    let last = raw.split(',').next_back().expect("at least one entry");
    let (name, offset) = last.trim().split_once('=').expect("entry=offset");
    let offset: usize = offset.trim().parse().expect("decimal offset");
    let has_body = matches!(name.trim(), "req-body" | "res-body" | "opt-body");
    assert!(
        has_body || name.trim() == "null-body",
        "the list must end with a body entity: {raw:?}"
    );
    (offset, has_body)
}

/// Build a REQMOD/RESPMOD request whose body bytes are supplied already
/// chunk-encoded, so a test can frame a preview (or malformed framing) exactly
/// as it means to. `None` produces a `null-body` message.
fn request_raw(
    method: &str,
    service: &str,
    req_hdr: Option<&[u8]>,
    res_hdr: Option<&[u8]>,
    body: Option<&[u8]>,
    extra: &[&str],
) -> Vec<u8> {
    let mut parts: Vec<(String, usize)> = Vec::new();
    let mut block = Vec::new();
    if let Some(h) = req_hdr {
        parts.push(("req-hdr".to_string(), block.len()));
        block.extend_from_slice(h);
    }
    if let Some(h) = res_hdr {
        parts.push(("res-hdr".to_string(), block.len()));
        block.extend_from_slice(h);
    }
    let terminal = match (body, method) {
        (None, _) => "null-body",
        (Some(_), "REQMOD") => "req-body",
        (Some(_), _) => "res-body",
    };
    parts.push((terminal.to_string(), block.len()));

    let encapsulated = parts
        .iter()
        .map(|(n, o)| format!("{n}={o}"))
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = Vec::new();
    out.extend_from_slice(
        format!("{method} icap://127.0.0.1/{service} ICAP/1.0\r\nHost: 127.0.0.1\r\n").as_bytes(),
    );
    for line in extra {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Encapsulated: {encapsulated}\r\n\r\n").as_bytes());
    out.extend_from_slice(&block);
    if let Some(b) = body {
        out.extend_from_slice(b);
    }
    out
}

/// The common case: a complete body in one chunk.
fn request(
    method: &str,
    service: &str,
    req_hdr: Option<&[u8]>,
    res_hdr: Option<&[u8]>,
    body: Option<&[u8]>,
    extra: &[&str],
) -> Vec<u8> {
    let encoded = body.map(chunk);
    request_raw(method, service, req_hdr, res_hdr, encoded.as_deref(), extra)
}

/// One chunk plus the last-chunk marker. Also how a partial preview ends: a
/// plain `0` says more of the object exists and the client is waiting.
fn chunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if !data.is_empty() {
        out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

/// One chunk terminated the way a preview that carries the whole object is.
fn chunk_ieof(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n0; ieof\r\n\r\n");
    out
}

// ───────────────────────────── OPTIONS ─────────────────────────────

#[test]
fn options_advertises_everything_a_client_needs() {
    let s = start_default();
    let mut c = s.connect();
    c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
    let r = c.recv();

    assert_eq!(r.code, 200, "{r:?}");
    assert_eq!(r.header("Methods"), Some("REQMOD, RESPMOD"));
    assert_eq!(r.header("Allow"), Some("204"));
    assert_eq!(r.header("Preview"), Some("4096"));
    assert_eq!(r.header("Max-Connections"), Some("100"));
    drop(c);
    drop(s);

    // And it comes from the address, so one option spells the connection cap
    // for either listener rather than each protocol needing a flag of its own.
    let s = Server::start_at(
        "icap://127.0.0.1:0?max-connections=7",
        TempDir::new().unwrap(),
        &[],
    );
    let mut c = s.connect();
    c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
    assert_eq!(c.recv().header("Max-Connections"), Some("7"));
    drop(c);
    drop(s);

    let s = start_default();
    let mut c = s.connect();
    c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
    let r = c.recv();
    assert_eq!(r.header("Options-TTL"), Some("3600"));
    assert_eq!(r.header("Encapsulated"), Some("null-body=0"));
    assert!(r.header("Service").unwrap().starts_with("exav/"));

    // RFC 3507 caps the quoted ISTag at 32 bytes, and clients cache against it.
    let istag = r.header("ISTag").expect("ISTag");
    assert!(istag.starts_with('"') && istag.ends_with('"'), "{istag}");
    assert!(istag.len() <= 32, "{istag}");
}

#[test]
fn the_istag_encodes_the_signature_set() {
    // Two servers with different databases must not share an ISTag, or a proxy
    // will keep serving verdicts from a database that no longer exists.
    let a = start_default();
    let extra = TempDir::new().unwrap();
    std::fs::write(extra.path().join("extra.ndb"), "Test.Marker:0:*:4d5a4d5a\n").unwrap();
    let b = Server::start(extra, &[]);

    let probe = |s: &Server| {
        let mut c = s.connect();
        c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\n\r\n");
        c.recv().header("ISTag").unwrap().to_string()
    };
    assert_ne!(probe(&a), probe(&b));
}

#[test]
fn every_configured_service_alias_answers() {
    let s = start_default();
    for service in ["avscan", "srv_clamav", "virus_scan"] {
        let mut c = s.connect();
        c.send(format!("OPTIONS icap://127.0.0.1/{service} ICAP/1.0\r\n\r\n").as_bytes());
        assert_eq!(c.recv().code, 200, "service {service}");
    }
    // Query-string service options, the form c-icap's `avscan` alias carries.
    let mut c = s.connect();
    c.send(
        b"OPTIONS icap://127.0.0.1/avscan?allow204=on&sizelimit=off&mode=simple ICAP/1.0\r\n\r\n",
    );
    assert_eq!(c.recv().code, 200);
}

/// The path of the listen address names the set exactly: a deployment that asks
/// for one name must not keep answering on three it never configured.
///
/// The address is the ICAP URL a proxy is pointed at, so this is the same string
/// on both sides — what a `squid.conf` contains is what exav is started with.
#[test]
fn the_path_of_the_address_replaces_the_default_services() {
    let s = Server::start_at(
        "icap://127.0.0.1:0/only_this_one",
        TempDir::new().unwrap(),
        &[],
    );
    let mut c = s.connect();
    c.send(b"OPTIONS icap://127.0.0.1/only_this_one ICAP/1.0\r\n\r\n");
    assert_eq!(c.recv().code, 200);

    let mut c = s.connect();
    c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\n\r\n");
    assert_eq!(c.recv().code, 404, "a default name is not served as well");
}

/// A repeated `?service=` is the escape hatch the path cannot express: two
/// proxies whose configurations disagree about the name, pointed at one exav.
#[test]
fn a_repeated_service_names_more_than_one() {
    let s = Server::start_at(
        "icap://127.0.0.1:0?service=one&service=two",
        TempDir::new().unwrap(),
        &[],
    );
    for name in ["one", "two"] {
        let mut c = s.connect();
        c.send(format!("OPTIONS icap://127.0.0.1/{name} ICAP/1.0\r\n\r\n").as_bytes());
        assert_eq!(c.recv().code, 200, "{name} was configured");
    }
    let mut c = s.connect();
    c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\n\r\n");
    assert_eq!(
        c.recv().code,
        404,
        "and the defaults are replaced, not added to"
    );
}

#[test]
fn an_unknown_service_is_a_404() {
    let s = start_default();
    let mut c = s.connect();
    c.send(b"OPTIONS icap://127.0.0.1/no_such_service ICAP/1.0\r\n\r\n");
    let r = c.recv();
    assert_eq!(r.code, 404);
    assert_eq!(r.reason, "ICAP Service not found");
}

// ───────────────────────────── RESPMOD ─────────────────────────────

#[test]
fn a_clean_respmod_with_allow_204_gets_204() {
    let s = start_default();
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(b"a perfectly ordinary file"),
        &["Allow: 204"],
    ));
    let r = c.recv();
    assert_eq!(r.code, 204, "{r:?}");
    assert!(r.body.is_empty());
    assert!(!r.has_header("X-Infection-Found"));
    assert!(!r.has_header("X-Exav-Category"));
}

#[test]
fn a_clean_respmod_without_allow_204_gets_its_message_back_unmodified() {
    let s = start_default();
    let mut c = s.connect();
    let payload = b"a perfectly ordinary file";
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(payload),
        &[],
    ));
    let r = c.recv();
    assert_eq!(r.code, 200, "{r:?}");
    // Byte for byte: exav has no opinion about a message it found nothing in.
    assert_eq!(r.encapsulated_hdr, RES_HDR);
    assert_eq!(r.body, payload);
    assert_eq!(
        r.header("Encapsulated"),
        Some(format!("res-hdr=0, res-body={}", RES_HDR.len()).as_str())
    );
}

#[test]
fn a_header_only_respmod_is_handled() {
    let s = start_default();
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        None,
        &["Allow: 204"],
    ));
    assert_eq!(c.recv().code, 204);
}

#[test]
fn eicar_over_respmod_is_blocked_with_the_c_icap_header() {
    let s = start_default();
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(EICAR),
        &["Allow: 204"],
    ));
    let r = c.recv();

    // A detection blocks even though the client offered 204.
    assert_eq!(r.code, 200, "{r:?}");
    let found = r
        .header("X-Infection-Found")
        .expect("a detection must carry X-Infection-Found");
    // The shape c-icap's virus_scan emits, which deployed clients parse by hand.
    assert!(
        found.starts_with("Type=0; Resolution=2; Threat=") && found.ends_with(';'),
        "{found}"
    );
    assert!(
        found.to_ascii_uppercase().contains("EICAR"),
        "the threat name is the signature that matched: {found}"
    );
    assert!(!r.has_header("X-Exav-Category"));

    // The original message is replaced, not passed through.
    let hdr = String::from_utf8_lossy(&r.encapsulated_hdr).into_owned();
    assert!(hdr.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{hdr}");
    assert!(
        r.body_text().contains("Malware detected"),
        "{}",
        r.body_text()
    );
}

// ───────────────────────────── REQMOD ─────────────────────────────

#[test]
fn a_clean_reqmod_with_allow_204_gets_204() {
    let s = start_default();
    let mut c = s.connect();
    c.send(&request(
        "REQMOD",
        "avscan",
        Some(REQ_HDR),
        None,
        Some(b"form data, nothing interesting"),
        &["Allow: 204"],
    ));
    assert_eq!(c.recv().code, 204);
}

#[test]
fn a_clean_reqmod_without_allow_204_gets_its_request_back() {
    let s = start_default();
    let mut c = s.connect();
    let payload = b"form data, nothing interesting";
    c.send(&request(
        "REQMOD",
        "avscan",
        Some(REQ_HDR),
        None,
        Some(payload),
        &[],
    ));
    let r = c.recv();
    assert_eq!(r.code, 200, "{r:?}");
    assert_eq!(r.encapsulated_hdr, REQ_HDR);
    assert_eq!(r.body, payload);
    assert!(r
        .header("Encapsulated")
        .unwrap()
        .starts_with("req-hdr=0, req-body="));
}

#[test]
fn eicar_over_reqmod_is_blocked_with_a_response() {
    let s = start_default();
    let mut c = s.connect();
    c.send(&request(
        "REQMOD",
        "avscan",
        Some(REQ_HDR),
        None,
        Some(EICAR),
        &["Allow: 204"],
    ));
    let r = c.recv();
    assert_eq!(r.code, 200, "{r:?}");
    assert!(r.has_header("X-Infection-Found"));
    // Blocking a REQMOD means handing back an HTTP *response* for the client to
    // serve instead of forwarding the request.
    assert!(r
        .header("Encapsulated")
        .unwrap()
        .starts_with("res-hdr=0, res-body="));
    assert!(String::from_utf8_lossy(&r.encapsulated_hdr).starts_with("HTTP/1.1 403 Forbidden"));
}

// ────────────────────── partial verdicts ──────────────────────

#[test]
fn an_object_past_the_size_limit_blocks_rather_than_passing() {
    // c-icap's MaxObjectSize lets an oversized object through unscanned. The
    // same situation here must not produce a clean pass.
    let s = Server::start(TempDir::new().unwrap(), &["--max-input-bytes", "1024"]);
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&vec![b'A'; 64 * 1024]),
        &["Allow: 204"],
    ));
    let r = c.recv();

    assert_eq!(r.code, 200, "an unscanned object must not get a 204: {r:?}");
    assert_eq!(r.header("X-Exav-Category"), Some("LIMITS-EXCEEDED"));
    // Word for word what the clamd listener says about a stream this size.
    // There is one size setting, and it does not answer differently depending
    // on which port the object arrived at.
    assert_eq!(r.header("X-Exav-Reason"), Some("size exceeds 1024"));
    // Blocked in the c-icap vocabulary too, under a name that says which
    // condition blocked it rather than borrowing a database signature's.
    assert_eq!(
        r.header("X-Infection-Found"),
        Some("Type=0; Resolution=2; Threat=Heuristics.Exav.LimitsExceeded;")
    );
    assert!(r.body_text().contains("Not scannable"));
}

#[test]
fn every_block_is_legible_to_a_client_that_reads_only_x_infection_found() {
    // A whole class of ICAP client decides clean-or-not from that header alone
    // — a script that hands a file to `c-icap-client` and greps the response,
    // for one. Such a client reads a 200 without the header as a pass, so
    // withholding it from a partial block would turn exav's fail-closed
    // answer into a fail-open one.
    let s = Server::start(TempDir::new().unwrap(), &["--max-input-bytes", "1024"]);

    // A detection, reported under its signature name.
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(EICAR),
        &["Allow: 204"],
    ));
    let hit = c.recv();
    let threat = hit
        .header("X-Infection-Found")
        .expect("a detection must carry X-Infection-Found");
    assert!(
        threat.to_ascii_uppercase().contains("EICAR"),
        "a database hit is reported under its signature name: {threat}"
    );

    // An object nobody examined, reported under a name that cannot be mistaken
    // for one — no database ships `Heuristics.Exav.*`.
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&vec![b'A'; 64 * 1024]),
        &["Allow: 204"],
    ));
    let unscanned = c.recv();
    let threat = unscanned
        .header("X-Infection-Found")
        .expect("a block a header-only client can see");
    assert!(threat.contains("Threat=Heuristics.Exav."), "{unscanned:?}");

    // And the clean object is the only one that gets no such header at all,
    // which is what makes the header's absence mean something.
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(b"harmless"),
        &["Allow: 204"],
    ));
    let clean = c.recv();
    assert_eq!(clean.code, 204, "{clean:?}");
    assert!(!clean.has_header("X-Infection-Found"), "{clean:?}");
}

#[test]
fn the_detections_policy_keeps_the_infection_header_for_database_hits_alone() {
    // The opt-out, for a deployment that wants `X-Infection-Found` to mean a
    // database hit and nothing else. The block itself does not change — only
    // how it is spelled for a client that reads that header.
    let s = Server::start(
        TempDir::new().unwrap(),
        &[
            "--max-input-bytes",
            "1024",
            "--icap-infection-header",
            "detections",
        ],
    );
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&vec![b'A'; 64 * 1024]),
        &["Allow: 204"],
    ));
    let r = c.recv();

    assert_eq!(r.code, 200, "the object is still blocked: {r:?}");
    assert_eq!(r.header("X-Exav-Category"), Some("LIMITS-EXCEEDED"));
    assert!(!r.has_header("X-Infection-Found"), "{r:?}");
    assert!(r.body_text().contains("Not scannable"));

    // A real detection still carries it, under either policy.
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(EICAR),
        &["Allow: 204"],
    ));
    let threat = c
        .recv()
        .header("X-Infection-Found")
        .expect("a detection must carry X-Infection-Found")
        .to_string();
    assert!(threat.to_ascii_uppercase().contains("EICAR"), "{threat}");
}

#[test]
fn an_over_limit_object_still_gets_its_verdict_delivered() {
    // The failure this guards against is not a wrong verdict but an undelivered
    // one: answer while the client is still sending and the close resets the
    // connection with the answer in flight.
    let s = Server::start(TempDir::new().unwrap(), &["--max-input-bytes", "1024"]);
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&vec![b'A'; 512 * 1024]),
        &["Allow: 204"],
    ));
    let r = c.recv();
    assert_eq!(r.header("X-Exav-Category"), Some("LIMITS-EXCEEDED"));
    assert_eq!(r.header("Connection"), Some("keep-alive"));

    // And the stream is back at a request boundary, so the connection is
    // reusable in fact rather than only in the header that says so.
    c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\n\r\n");
    assert_eq!(c.recv().code, 200);
}

#[test]
fn malware_in_the_head_of_an_over_limit_object_is_reported_as_the_detection() {
    // Past the limit the object is blocked either way, but *why* it was blocked
    // is what an operator acts on, and a real detection outranks a resource
    // limit.
    let s = Server::start(TempDir::new().unwrap(), &["--max-input-bytes", "4096"]);
    let mut c = s.connect();
    let mut payload = EICAR.to_vec();
    payload.extend(std::iter::repeat_n(b'A', 256 * 1024));
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&payload),
        &["Allow: 204"],
    ));
    let r = c.recv();
    assert_eq!(r.code, 200, "{r:?}");
    assert!(r.has_header("X-Infection-Found"), "{r:?}");
    assert!(!r.has_header("X-Exav-Category"), "{r:?}");
}

// ───────────────── passing what could not be examined ─────────────────

#[test]
fn a_deployment_can_take_delivery_of_what_exav_could_not_examine() {
    // The c-icap + ClamAV trade, made explicitly: an upload service that would
    // rather deliver an encrypted archive than reject a user's file asks for it
    // by name, and gets the ordinary clean answer.
    let s = Server::start(
        TempDir::new().unwrap(),
        &["--max-input-bytes", "1024", "--partial-as", "ok"],
    );
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&vec![b'A'; 64 * 1024]),
        &["Allow: 204"],
    ));
    let r = c.recv();

    assert_eq!(r.code, 204, "the object is delivered, not blocked: {r:?}");
    // Delivered, but not passed off as clean: the client is told what was
    // skipped, and never told it was an infection — that would be false, and it
    // would make the header-only client this setting exists for block anyway.
    assert_eq!(r.header("X-Exav-Category"), Some("LIMITS-EXCEEDED"));
    assert!(r.has_header("X-Exav-Reason"), "{r:?}");
    assert!(!r.has_header("X-Infection-Found"), "{r:?}");

    // A real detection is not covered by any of this. It still blocks.
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(EICAR),
        &["Allow: 204"],
    ));
    let hit = c.recv();
    assert_eq!(hit.code, 200, "{hit:?}");
    assert!(hit.has_header("X-Infection-Found"), "{hit:?}");
}

#[test]
fn a_pass_policy_covers_the_tags_it_names_and_no_others() {
    // Naming tags rather than taking `all` is what lets a deployment accept one
    // risk without accepting the rest.
    let s = Server::start(
        TempDir::new().unwrap(),
        &[
            "--max-input-bytes",
            "1024",
            "--partial-as",
            "unscannable=ok",
        ],
    );
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&vec![b'A'; 64 * 1024]),
        &["Allow: 204"],
    ));
    let r = c.recv();

    // LIMITS-EXCEEDED was not named, so it blocks exactly as it did before.
    assert_eq!(r.code, 200, "{r:?}");
    assert_eq!(r.header("X-Exav-Category"), Some("LIMITS-EXCEEDED"));
    assert!(r.has_header("X-Infection-Found"), "{r:?}");
}

#[test]
fn a_pass_still_hands_back_a_whole_message_when_the_client_wants_one() {
    // Without `Allow: 204` the client is owed its own message back, and a pass
    // has to produce it byte for byte rather than a block page.
    let s = Server::start(TempDir::new().unwrap(), &["--partial-as", "ok"]);
    let body = encrypted_zip();
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&body),
        &[],
    ));
    let r = c.recv();

    assert_eq!(r.code, 200, "{r:?}");
    assert_eq!(
        r.encapsulated_hdr, RES_HDR,
        "the original headers come back"
    );
    assert_eq!(r.body, body, "the original body comes back unmodified");
    assert_eq!(r.header("X-Exav-Category"), Some("PASSWORD-PROTECTED"));
    assert!(!r.has_header("X-Infection-Found"), "{r:?}");
}

#[test]
fn an_over_limit_object_cannot_be_passed_to_a_client_that_wants_it_back() {
    // The one object no policy can pass. Its tail was read and discarded to
    // reach the next request boundary, so the bytes needed to hand the message
    // back are gone — and handing back the head alone would deliver a truncated
    // object as though it were the whole one. The block stands.
    let s = Server::start(
        TempDir::new().unwrap(),
        &["--max-input-bytes", "1024", "--partial-as", "ok"],
    );
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&vec![b'A'; 64 * 1024]),
        &[],
    ));
    let r = c.recv();

    assert_eq!(r.code, 200, "{r:?}");
    assert_eq!(r.header("X-Exav-Category"), Some("LIMITS-EXCEEDED"));
    assert!(
        String::from_utf8_lossy(&r.encapsulated_hdr).starts_with("HTTP/1.1 403 Forbidden"),
        "a truncated object must not be delivered as the real one: {r:?}"
    );
}

#[test]
fn nothing_is_passed_unless_a_deployment_asks_for_it() {
    // The default, restated end to end: exav does not make the c-icap trade on
    // anyone's behalf.
    let s = Server::start(TempDir::new().unwrap(), &["--max-input-bytes", "1024"]);
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&vec![b'A'; 64 * 1024]),
        &["Allow: 204"],
    ));
    let r = c.recv();
    assert_eq!(
        r.code, 200,
        "an unexamined object must not get a 204: {r:?}"
    );
    assert!(r.body_text().contains("Not scannable"));
}

#[test]
fn a_misspelled_pass_policy_stops_the_server_rather_than_never_firing() {
    // A policy that parsed but matched nothing would leave an operator believing
    // they had opened a hole they had not — found out from traffic, months on.
    let dir = TempDir::new().unwrap();
    let out = Command::new(exav_bin())
        .arg("--listen")
        .arg("icap://127.0.0.1:0")
        .arg("-d")
        .arg(dir.path())
        .arg("--partial-as")
        .arg("unscannble=ok")
        .env("EXAV_ALLOW_NO_DB", "1")
        .output()
        .expect("run exav");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unscannble"), "{err}");
    assert!(err.contains("tags:"), "{err}");
}

#[test]
fn an_object_too_big_to_scan_is_the_same_object_on_either_listener() {
    // The ICAP listener has no size ceiling of its own, so an object's size is
    // one setting with one answer. Before, a 50 MB upload was scanned normally
    // over clamd and blocked over ICAP — the same file, two verdicts, decided by
    // which port it arrived at.
    //
    // Both listeners in one process, so the comparison is between two surfaces
    // over one database and one configuration and cannot drift.
    let sigs = TempDir::new().unwrap();
    let clamd = free_port();
    let s = Server::start(
        sigs,
        &[
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--max-input-bytes",
            "1024",
        ],
    );
    let body = vec![b'A'; 64 * 1024];

    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&body),
        &["Allow: 204"],
    ));
    let icap = c.recv();
    let clamd_reply = clamd_instream(clamd, &body);

    assert_eq!(icap.header("X-Exav-Category"), Some("LIMITS-EXCEEDED"));
    assert!(
        clamd_reply.contains("LIMITS-EXCEEDED"),
        "clamd: {clamd_reply:?}"
    );
    // Not merely both non-clean: the same reason, in the same words.
    let reason = icap.header("X-Exav-Reason").expect("a reason");
    assert!(
        clamd_reply.contains(reason),
        "icap said {reason:?}, clamd said {clamd_reply:?}"
    );

    // And an object the limit does not touch is scanned on both, rather than
    // one of them refusing it for its size.
    let small = b"harmless enough";
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(small),
        &["Allow: 204"],
    ));
    assert_eq!(c.recv().code, 204);
    assert!(clamd_instream(clamd, small).contains(": OK"));
}

#[test]
fn an_object_with_nowhere_to_spill_gets_a_verdict_rather_than_a_dropped_connection() {
    // Running out of temp space must not cost the client its answer. A client
    // that gets no answer decides for itself, which is the one outcome a full
    // filesystem must not be able to buy an attacker.
    let s = Server::start(
        TempDir::new().unwrap(),
        &[
            "--spill-threshold-bytes",
            "4096",
            "--max-spill-bytes",
            "8192",
            "--max-total-spill-bytes",
            "8192",
        ],
    );
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&vec![b'A'; 256 * 1024]),
        &["Allow: 204"],
    ));
    let r = c.recv();

    assert_eq!(r.code, 200, "an object nobody buffered is not a 204: {r:?}");
    assert_eq!(r.header("X-Exav-Category"), Some("UNSCANNABLE"));
    assert!(
        r.header("X-Exav-Reason")
            .unwrap_or_default()
            .contains("spill"),
        "the reason names the budget that refused it: {r:?}"
    );
    // Blocked, and legible to a header-only client like any other block.
    assert!(r.has_header("X-Infection-Found"), "{r:?}");

    // The rest of the body was read and discarded rather than the read being
    // abandoned, so the stream is back at a request boundary. That is what makes
    // the verdict deliverable at all: answering into a socket that still holds
    // unread bytes makes the kernel reset the connection, and the reset throws
    // away the response along with them.
    assert_eq!(r.header("Connection"), Some("keep-alive"), "{r:?}");
    c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\n\r\n");
    assert_eq!(c.recv().code, 200, "the connection is reusable in fact");
}

#[test]
fn no_spill_keeps_scanned_bytes_off_the_disk() {
    // For a read-only root filesystem, or a deployment that would rather refuse
    // a large object than let a scanned payload touch a disk. The threshold
    // becomes a hard per-object memory ceiling, and past it there is nowhere
    // left to put the object — which is a verdict, not a silent pass.
    let s = Server::start(
        TempDir::new().unwrap(),
        &["--spill-dir", "off", "--spill-threshold-bytes", "8192"],
    );

    // Under the threshold: scanned in memory as usual, detection and all.
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(EICAR),
        &["Allow: 204"],
    ));
    assert!(c.recv().has_header("X-Infection-Found"));

    // Over it: refused, with the reason naming the switch that refused it.
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&vec![b'A'; 256 * 1024]),
        &["Allow: 204"],
    ));
    let r = c.recv();
    assert_eq!(r.code, 200, "{r:?}");
    assert_eq!(r.header("X-Exav-Category"), Some("UNSCANNABLE"));
    assert!(
        r.header("X-Exav-Reason")
            .unwrap_or_default()
            .contains("--spill-dir"),
        "{r:?}"
    );
    // Still delivered on a connection that survives, like any other verdict.
    assert_eq!(r.header("Connection"), Some("keep-alive"), "{r:?}");

    // That verdict is itself the evidence no file was written: had one been,
    // the object would have been buffered, scanned, and answered `204`. There is
    // no third outcome where exav both spilled and reported UNSCANNABLE.
}

#[test]
fn the_spill_budget_is_returned_when_the_object_is_done_with() {
    // The process-wide budget is a *concurrent* bound, not a lifetime quota. If
    // a finished object kept its share, a listener would spill fine until it had
    // handled its budget's worth of traffic and then refuse everything for ever.
    let s = Server::start(
        TempDir::new().unwrap(),
        &[
            "--spill-threshold-bytes",
            "4096",
            "--max-spill-bytes",
            "1M",
            "--max-total-spill-bytes",
            "1M",
        ],
    );
    // Each of these spills, and each is several times the budget in total.
    for i in 0..8 {
        let mut c = s.connect();
        c.send(&request(
            "RESPMOD",
            "avscan",
            Some(REQ_HDR),
            Some(RES_HDR),
            Some(&vec![b'A'; 512 * 1024]),
            &["Allow: 204"],
        ));
        let r = c.recv();
        assert_eq!(r.code, 204, "request {i} was refused: {r:?}");
    }
}

// ─────────────────── what the listener says about itself ───────────────────

#[test]
fn icap_scans_are_counted_and_reported_through_stats() {
    // A listener is the one surface that cannot be timed from outside: it is a
    // long-lived process serving objects nobody kept, so "the box is at 100%
    // CPU" is all an operator gets unless the process counts for itself. Both
    // listeners in one process, so ICAP's work is visible on the channel a clamd
    // client already knows how to ask on.
    let clamd = free_port();
    let s = Server::start(
        TempDir::new().unwrap(),
        &[
            // The thread model, so both listeners share one process and one set
            // of counters. Under the worker pool ICAP is a forked child and its
            // scans are its own — which `STATS` says rather than hides.
            "--workers",
            "threads",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--profile",
        ],
    );

    let before = clamd_stats(clamd);
    assert!(before.contains("SCANSTATS: scans "), "{before}");

    for _ in 0..3 {
        let mut c = s.connect();
        c.send(&request(
            "RESPMOD",
            "avscan",
            Some(REQ_HDR),
            Some(RES_HDR),
            Some(EICAR),
            &["Allow: 204"],
        ));
        assert!(c.recv().has_header("X-Infection-Found"));
    }

    let after = clamd_stats(clamd);
    assert!(
        scans_in(&after) >= scans_in(&before) + 3,
        "ICAP scans must reach the counters:\nbefore {before}\nafter {after}"
    );
    assert!(after.contains("infected "), "{after}");
    // With --profile-scans the breakdown says which matcher owned the time,
    // which is the question after "how much time".
    assert!(!after.contains("MATCHERSTATS: off"), "{after}");
    assert!(after.contains("engine="), "{after}");
}

#[test]
fn without_profiling_the_totals_are_still_kept() {
    // Timing every scan costs one clock read; timing every matcher inside it
    // does not. The cheap half is always on, so a listener can always say how
    // busy it is.
    let clamd = free_port();
    let s = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "threads",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
        ],
    );
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(EICAR),
        &["Allow: 204"],
    ));
    assert!(c.recv().has_header("X-Infection-Found"));

    let stats = clamd_stats(clamd);
    assert!(scans_in(&stats) >= 1, "{stats}");
    assert!(stats.contains("throughput-MBps"), "{stats}");
    assert!(
        stats.contains("MATCHERSTATS: off (start with --profile-scans)"),
        "{stats}"
    );
}

/// Send `STATS` to the clamd listener and return the reply.
fn clamd_stats(port: u16) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut s = loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            break s;
        }
        assert!(
            Instant::now() < deadline,
            "nothing answered on clamd {port}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    s.write_all(b"zSTATS\0").unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    String::from_utf8_lossy(&out).trim_end_matches('\0').into()
}

/// The `scans N` field out of a `STATS` reply.
fn scans_in(stats: &str) -> u64 {
    stats
        .split_once("SCANSTATS: scans ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no scan count in {stats}"))
}

#[test]
fn an_object_far_past_the_spill_threshold_is_scanned_whole() {
    // The reason no per-listener ceiling is needed: the body goes to a temp file
    // past the shared threshold, so a large object is an ordinary scan rather
    // than a memory decision. The detection sits well beyond where a RAM-only
    // listener would have stopped keeping bytes.
    let s = start_default();
    let mut payload = vec![b'A'; 24 * 1024 * 1024];
    payload.extend_from_slice(EICAR);
    let mut c = s.connect();
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&payload),
        &["Allow: 204"],
    ));
    let r = c.recv();

    assert_eq!(r.code, 200, "{r:?}");
    assert!(
        r.has_header("X-Infection-Found"),
        "malware 24 MB into an object must still be found: {r:?}"
    );
    assert!(!r.has_header("X-Exav-Category"), "{r:?}");
}

// ───────────────────────────── Preview ─────────────────────────────

#[test]
fn a_partial_preview_gets_100_continue_and_then_the_verdict() {
    let s = start_default();
    let mut c = s.connect();
    let head = b"the first part of a larger object";
    let tail = b"and the rest of it, still clean";

    c.send(&request_raw(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&chunk(head)),
        &["Allow: 204", "Preview: 33"],
    ));

    let cont = c.recv();
    assert_eq!(cont.code, 100, "expected 100 Continue, got {cont:?}");

    c.send(&chunk(tail));
    let r = c.recv();
    assert_eq!(r.code, 204, "{r:?}");
}

#[test]
fn a_preview_that_carries_the_whole_object_is_answered_without_continue() {
    let s = start_default();
    let mut c = s.connect();
    c.send(&request_raw(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&chunk_ieof(b"a small, complete, clean object")),
        &["Allow: 204", "Preview: 100"],
    ));

    // `0; ieof` says there is nothing left to ask for, so the next thing on the
    // wire is the final answer and not an interim 100.
    let r = c.recv();
    assert_eq!(r.code, 204, "{r:?}");
}

#[test]
fn a_preview_that_already_contains_malware_is_blocked_without_continue() {
    let s = start_default();
    let mut c = s.connect();
    c.send(&request_raw(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&chunk(EICAR)),
        &["Allow: 204", "Preview: 68"],
    ));

    let r = c.recv();
    assert_eq!(r.code, 200, "expected an immediate block, got {r:?}");
    assert!(r.has_header("X-Infection-Found"));
}

#[test]
fn malware_that_only_appears_after_the_preview_is_still_caught() {
    // The head of the object is clean, so answering the preview would be a
    // bypass anyone could drive by prefixing their payload with filler.
    let s = start_default();
    let mut c = s.connect();
    c.send(&request_raw(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&chunk(b"harmless filler.")),
        &["Allow: 204", "Preview: 16"],
    ));

    assert_eq!(c.recv().code, 100);
    c.send(&chunk(EICAR));
    let r = c.recv();
    assert_eq!(r.code, 200, "{r:?}");
    assert!(r.has_header("X-Infection-Found"));
}

#[test]
fn a_zero_length_preview_works() {
    // Squid sends `Preview: 0` for messages it cannot buffer a head of.
    let s = start_default();
    let mut c = s.connect();
    c.send(&request_raw(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(b"0\r\n\r\n"),
        &["Allow: 204", "Preview: 0"],
    ));

    assert_eq!(c.recv().code, 100);
    c.send(&chunk(EICAR));
    let r = c.recv();
    assert_eq!(r.code, 200);
    assert!(r.has_header("X-Infection-Found"));
}

// ─────────────────────── connection handling ───────────────────────

#[test]
fn several_requests_share_one_connection() {
    let s = start_default();
    let mut c = s.connect();

    c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\n\r\n");
    assert_eq!(c.recv().code, 200);

    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(b"clean one"),
        &["Allow: 204"],
    ));
    assert_eq!(c.recv().code, 204);

    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(EICAR),
        &["Allow: 204"],
    ));
    let infected = c.recv();
    assert_eq!(infected.code, 200);
    assert!(infected.has_header("X-Infection-Found"));

    // And the connection survives a detection.
    c.send(&request(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(b"clean again"),
        &["Allow: 204"],
    ));
    assert_eq!(c.recv().code, 204);
}

#[test]
fn a_preview_and_a_following_request_share_one_connection() {
    let s = start_default();
    let mut c = s.connect();

    c.send(&request_raw(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(&chunk(b"12345678")),
        &["Allow: 204", "Preview: 8"],
    ));
    assert_eq!(c.recv().code, 100);
    c.send(&chunk(b"90 and the rest"));
    assert_eq!(c.recv().code, 204);

    c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\n\r\n");
    assert_eq!(c.recv().code, 200);
}

#[test]
fn connection_close_is_honoured() {
    let s = start_default();
    let mut c = s.connect();
    c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\nConnection: close\r\n\r\n");
    let r = c.recv();
    assert_eq!(r.code, 200);
    assert_eq!(r.header("Connection"), Some("close"));
    let mut rest = Vec::new();
    c.reader.read_to_end(&mut rest).expect("read to close");
    assert!(rest.is_empty(), "server kept the connection open");
}

#[test]
fn the_keepalive_request_count_is_honoured() {
    // c-icap's MaxKeepAliveRequests: a connection serves that many and then
    // closes, so no client can hold one open indefinitely.
    let s = Server::start(TempDir::new().unwrap(), &["--icap-max-requests", "2"]);
    let mut c = s.connect();
    for _ in 0..2 {
        c.send(b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\n\r\n");
        assert_eq!(c.recv().code, 200);
    }
    let mut rest = Vec::new();
    c.reader.read_to_end(&mut rest).expect("read to close");
    assert!(
        rest.is_empty(),
        "the connection must close after its last request"
    );
}

// ─────────────────────────── bad requests ───────────────────────────

#[test]
fn a_malformed_encapsulated_header_is_a_400() {
    let s = start_default();
    for bad in [
        "res-hdr=0, res-body=-5",
        "res-body=notanumber",
        "bogus=0",
        "res-hdr=0",
        "res-body=10, res-hdr=0",
    ] {
        let mut c = s.connect();
        c.send(
            format!("RESPMOD icap://127.0.0.1/avscan ICAP/1.0\r\nEncapsulated: {bad}\r\n\r\n")
                .as_bytes(),
        );
        let r = c.recv();
        assert_eq!(r.code, 400, "Encapsulated: {bad} -> {r:?}");
    }
}

#[test]
fn a_respmod_without_an_encapsulated_header_is_a_400() {
    let s = start_default();
    let mut c = s.connect();
    c.send(b"RESPMOD icap://127.0.0.1/avscan ICAP/1.0\r\nHost: h\r\n\r\n");
    assert_eq!(c.recv().code, 400);
}

#[test]
fn an_unsupported_method_is_a_405() {
    let s = start_default();
    let mut c = s.connect();
    c.send(b"GET icap://127.0.0.1/avscan ICAP/1.0\r\n\r\n");
    assert_eq!(c.recv().code, 405);
}

#[test]
fn a_malformed_chunked_body_is_a_400() {
    let s = start_default();
    let mut c = s.connect();
    c.send(&request_raw(
        "RESPMOD",
        "avscan",
        Some(REQ_HDR),
        Some(RES_HDR),
        Some(b"zzzz\r\nrubbish\r\n"),
        &["Allow: 204"],
    ));
    assert_eq!(c.recv().code, 400);
}

#[test]
fn a_hostile_head_is_refused_rather_than_guessed_at() {
    // Header smuggling: a folded continuation line and a name with a space in
    // it are the constructs two parsers disagree about, and a proxy in front of
    // exav is the other parser.
    let s = start_default();
    for bad in [
        &b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\nHost: a\r\n\tfolded: yes\r\n\r\n"[..],
        &b"OPTIONS icap://127.0.0.1/avscan ICAP/1.0\r\nBad Name: a\r\n\r\n"[..],
        &b"OPTIONS icap://127.0.0.1/avscan HTTP/1.1\r\n\r\n"[..],
    ] {
        let mut c = s.connect();
        c.send(bad);
        let r = c.recv();
        assert_eq!(r.code, 400, "{}: {r:?}", String::from_utf8_lossy(bad));
    }
}
