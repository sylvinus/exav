//! Parsing of the ICAP head: request line, headers, and the `Encapsulated`
//! offset list.
//!
//! Everything in this file reads bytes that arrived from the network, from a
//! client that may be hostile or merely broken. The rules are therefore
//! explicit and the failure mode is a `400`, never a best-effort guess: an
//! offset list that is accepted loosely decides which bytes get scanned, and a
//! guess there is a scan of the wrong bytes.

use std::io::{self, BufRead};

use super::chunked::read_line;

/// Why a request could not be understood. The text is what goes on the ICAP
/// status line of the `400`, so it is short and free of anything echoed back
/// from the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ParseError(&'static str);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ParseError {}

/// The ICAP methods, plus a catch-all for anything else a client sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum IcapMethod {
    /// Capability discovery.
    Options,
    /// Adapt an HTTP request.
    ReqMod,
    /// Adapt an HTTP response.
    RespMod,
    /// Something exav does not implement.
    Other(String),
}

impl IcapMethod {
    fn parse(s: &str) -> Self {
        // Method names are case-sensitive in RFC 3507, and every deployed
        // client sends them uppercase.
        match s {
            "OPTIONS" => Self::Options,
            "REQMOD" => Self::ReqMod,
            "RESPMOD" => Self::RespMod,
            other => Self::Other(other.to_string()),
        }
    }
}

/// A parsed ICAP request head: the request line plus the ICAP headers. The
/// encapsulated HTTP message is not part of this — it is read separately, using
/// the offsets in [`RequestHead::encapsulated`].
#[derive(Debug, Clone)]
pub(super) struct RequestHead {
    /// The method from the request line.
    pub(super) method: IcapMethod,
    /// The service name taken from the request-URI's path.
    pub(super) service: String,
    headers: Vec<(String, String)>,
}

/// Longest a single header line may be. Bounded separately from the whole head
/// so one absurd line is rejected before it is accumulated.
const MAX_LINE: usize = 16 * 1024;

/// Read one ICAP head — everything up to and including the blank line that ends
/// it — from `r`, refusing to buffer more than `max` bytes.
///
/// `Ok(None)` means the client closed the connection cleanly between requests,
/// which is how a keep-alive connection normally ends and is not an error.
pub(super) fn read_head<R: BufRead>(r: &mut R, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut head: Vec<u8> = Vec::new();
    loop {
        let remaining = max.saturating_sub(head.len());
        if remaining == 0 {
            return Err(io::Error::other("ICAP head exceeds the configured ceiling"));
        }
        let line = match read_line(r, remaining.min(MAX_LINE))? {
            Some(l) => l,
            None => {
                return if head.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed inside an ICAP head",
                    ))
                }
            }
        };
        let blank = line == b"\r\n" || line == b"\n";
        // A stray CRLF before the request line is tolerated the way HTTP
        // tolerates it: some clients leave one behind after a previous body.
        if blank && head.is_empty() {
            continue;
        }
        head.extend_from_slice(&line);
        if blank {
            return Ok(Some(head));
        }
    }
}

impl RequestHead {
    /// Parse a head as returned by [`read_head`].
    pub(super) fn parse(head: &[u8]) -> Result<Self, ParseError> {
        // ICAP heads are ASCII. Anything else is either a client sending binary
        // at a text protocol or an attempt to smuggle bytes past a proxy's
        // header parser, and neither is worth accommodating.
        let text = std::str::from_utf8(head).map_err(|_| ParseError("head is not valid UTF-8"))?;
        if !text.is_ascii() {
            return Err(ParseError("head contains non-ASCII bytes"));
        }
        let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));

        let request_line = lines.next().ok_or(ParseError("empty head"))?;
        let mut parts = request_line.split(' ').filter(|p| !p.is_empty());
        let method = parts.next().ok_or(ParseError("empty request line"))?;
        let uri = parts.next().ok_or(ParseError("request line has no URI"))?;
        let version = parts
            .next()
            .ok_or(ParseError("request line has no version"))?;
        if parts.next().is_some() {
            return Err(ParseError("request line has trailing garbage"));
        }
        if !version.starts_with("ICAP/") {
            return Err(ParseError("not an ICAP request"));
        }

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            // Obsolete line folding: a header value continued on a line
            // starting with whitespace. Rejected rather than reassembled,
            // because folding is exactly the construct front-end and back-end
            // parsers disagree about, and disagreement between two parsers over
            // where a header ends is how a request gets smuggled past one of
            // them.
            if line.starts_with(' ') || line.starts_with('\t') {
                return Err(ParseError("folded header line"));
            }
            let (name, value) = line
                .split_once(':')
                .ok_or(ParseError("header line without a colon"))?;
            if name.is_empty() || name.contains(char::is_whitespace) {
                return Err(ParseError("malformed header name"));
            }
            headers.push((name.to_string(), value.trim().to_string()));
        }

        Ok(Self {
            method: IcapMethod::parse(method),
            service: service_from_uri(uri),
            headers,
        })
    }

    /// The first value of `name`, matched case-insensitively.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every value of `name`, matched case-insensitively.
    fn header_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether the client said it accepts `204 No Content`.
    ///
    /// `Allow` is a comma-separated list and may appear more than once, so both
    /// forms are checked.
    pub(super) fn allow_204(&self) -> bool {
        self.header_all("Allow")
            .flat_map(|v| v.split(','))
            .any(|t| t.trim() == "204")
    }

    /// Whether the client asked for the connection to close after this request.
    pub(super) fn wants_close(&self) -> bool {
        self.header("Connection")
            .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
            .unwrap_or(false)
    }

    /// The `Preview` size, or `None` when the client sent no preview.
    ///
    /// The number itself is not what drives the read — the preview body is
    /// chunked and ends with its own terminator — but a value that is not a
    /// plain decimal number means the head was not produced by an ICAP client,
    /// so it is an error rather than a shrug.
    pub(super) fn preview(&self) -> Result<Option<usize>, ParseError> {
        match self.header("Preview") {
            None => Ok(None),
            Some(v) => v
                .parse::<usize>()
                .map(Some)
                .map_err(|_| ParseError("malformed Preview header")),
        }
    }

    /// Parse the `Encapsulated` header. `max_header_bytes` bounds the
    /// encapsulated HTTP header block the offsets describe.
    pub(super) fn encapsulated(&self, max_header_bytes: usize) -> Result<Encapsulated, ParseError> {
        let raw = self
            .header("Encapsulated")
            .ok_or(ParseError("missing Encapsulated header"))?;
        if self.header_all("Encapsulated").count() > 1 {
            // Two offset lists describe two different splits of the same bytes.
            // Picking one is a guess about which bytes to scan.
            return Err(ParseError("duplicate Encapsulated header"));
        }
        Encapsulated::parse(raw, max_header_bytes)
    }
}

/// Extract the service name from an ICAP request-URI.
///
/// Accepts the absolute form deployed clients send (`icap://host:1344/avscan`)
/// and the bare path some hand-rolled clients send (`/avscan`). A query string
/// is dropped: c-icap carries per-request service options there
/// (`avscan?allow204=on&mode=simple`) and the name in front of the `?` is what
/// selects the service.
fn service_from_uri(uri: &str) -> String {
    let rest = match uri.split_once("://") {
        // The authority runs to the first `/`; with no `/` there is no path,
        // and so no service name.
        Some((_scheme, after)) => match after.find('/') {
            Some(i) => &after[i + 1..],
            None => "",
        },
        None => uri.strip_prefix('/').unwrap_or(uri),
    };
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    rest[..end].trim_end_matches('/').to_string()
}

/// One entry of the `Encapsulated` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Entity {
    /// HTTP request headers.
    ReqHdr,
    /// HTTP request body.
    ReqBody,
    /// HTTP response headers.
    ResHdr,
    /// HTTP response body.
    ResBody,
    /// `OPTIONS` response body.
    OptBody,
    /// Marker: the message has headers but no body.
    NullBody,
}

impl Entity {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "req-hdr" => Self::ReqHdr,
            "req-body" => Self::ReqBody,
            "res-hdr" => Self::ResHdr,
            "res-body" => Self::ResBody,
            "opt-body" => Self::OptBody,
            "null-body" => Self::NullBody,
            _ => return None,
        })
    }

    /// The wire name of this entity.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::ReqHdr => "req-hdr",
            Self::ReqBody => "req-body",
            Self::ResHdr => "res-hdr",
            Self::ResBody => "res-body",
            Self::OptBody => "opt-body",
            Self::NullBody => "null-body",
        }
    }

    /// Whether this entity terminates the list. Exactly one of these appears,
    /// last, and its offset is where the encapsulated header block ends.
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ReqBody | Self::ResBody | Self::OptBody | Self::NullBody
        )
    }

    /// Whether an actual (chunk-encoded) body follows the headers.
    pub(super) fn has_body(self) -> bool {
        matches!(self, Self::ReqBody | Self::ResBody | Self::OptBody)
    }
}

/// A validated `Encapsulated` offset list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Encapsulated {
    parts: Vec<(Entity, usize)>,
}

impl Encapsulated {
    /// Parse and validate an `Encapsulated` header value.
    ///
    /// `max_header_bytes` caps the encapsulated header block, so a list whose
    /// terminal offset claims gigabytes is refused here rather than at the
    /// allocation it would otherwise cause.
    pub(super) fn parse(value: &str, max_header_bytes: usize) -> Result<Self, ParseError> {
        let mut parts: Vec<(Entity, usize)> = Vec::new();
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() {
                return Err(ParseError("empty Encapsulated entry"));
            }
            let (name, offset) = item
                .split_once('=')
                .ok_or(ParseError("Encapsulated entry without an offset"))?;
            let entity =
                Entity::parse(name.trim()).ok_or(ParseError("unknown Encapsulated entity"))?;
            let offset = offset.trim();
            // `str::parse::<usize>` accepts a leading `+`, and would accept a
            // leading `-` for a signed type. Requiring plain digits keeps the
            // accepted set to exactly what RFC 3507 defines and keeps two
            // parsers from disagreeing about `+0`.
            if offset.is_empty() || !offset.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError("Encapsulated offset is not a decimal number"));
            }
            let offset: usize = offset
                .parse()
                .map_err(|_| ParseError("Encapsulated offset out of range"))?;

            if parts.iter().any(|(e, _)| *e == entity) {
                return Err(ParseError("duplicate Encapsulated entity"));
            }
            if let Some((prev_entity, prev_offset)) = parts.last() {
                if prev_entity.is_terminal() {
                    return Err(ParseError("Encapsulated entity after the body entity"));
                }
                // RFC 3507 requires ascending offsets. Equal offsets are kept
                // legal because a zero-length header section is expressible;
                // a descending pair is not, and would make one section's
                // length negative.
                if offset < *prev_offset {
                    return Err(ParseError("Encapsulated offsets are not ascending"));
                }
            }
            if offset > max_header_bytes {
                return Err(ParseError("Encapsulated offset exceeds the header ceiling"));
            }
            parts.push((entity, offset));
        }

        match parts.last() {
            None => Err(ParseError("empty Encapsulated header")),
            // Without a terminal entity the final header section has no end:
            // its length is defined only by the offset that follows it. There
            // is nothing to fall back on, so this is a parse failure and not a
            // default.
            Some((e, _)) if !e.is_terminal() => {
                Err(ParseError("Encapsulated list has no body or null-body"))
            }
            Some(_) => Ok(Self { parts }),
        }
    }

    /// The terminal entity and its offset. Always present after parsing.
    pub(super) fn terminal(&self) -> (Entity, usize) {
        *self
            .parts
            .last()
            .expect("parse rejects an empty entity list")
    }

    /// Total length of the encapsulated HTTP header block, i.e. everything
    /// before the chunk-encoded body.
    pub(super) fn header_bytes(&self) -> usize {
        self.terminal().1
    }

    /// Byte range of `entity` within the encapsulated header block, or `None`
    /// when the list does not carry it.
    pub(super) fn span(&self, entity: Entity) -> Option<(usize, usize)> {
        let i = self.parts.iter().position(|(e, _)| *e == entity)?;
        let start = self.parts[i].1;
        let end = self.parts.get(i + 1).map_or(start, |(_, o)| *o);
        Some((start, end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: usize = 64 * 1024;

    fn err(v: &str) -> String {
        Encapsulated::parse(v, CAP).unwrap_err().to_string()
    }

    #[test]
    fn parses_a_respmod_offset_list() {
        let e = Encapsulated::parse("req-hdr=0, res-hdr=137, res-body=296", CAP).unwrap();
        assert_eq!(e.header_bytes(), 296);
        assert_eq!(e.span(Entity::ReqHdr), Some((0, 137)));
        assert_eq!(e.span(Entity::ResHdr), Some((137, 296)));
        assert_eq!(e.terminal(), (Entity::ResBody, 296));
        assert!(e.terminal().0.has_body());
    }

    #[test]
    fn parses_a_null_body_list() {
        let e = Encapsulated::parse("req-hdr=0, null-body=170", CAP).unwrap();
        assert_eq!(e.header_bytes(), 170);
        assert_eq!(e.span(Entity::ReqHdr), Some((0, 170)));
        assert!(!e.terminal().0.has_body());
    }

    #[test]
    fn parses_an_options_list() {
        let e = Encapsulated::parse("null-body=0", CAP).unwrap();
        assert_eq!(e.header_bytes(), 0);
        assert_eq!(e.terminal(), (Entity::NullBody, 0));
    }

    #[test]
    fn tolerates_whitespace_variants() {
        let tight = Encapsulated::parse("req-hdr=0,res-hdr=10,res-body=20", CAP).unwrap();
        let loose =
            Encapsulated::parse("  req-hdr = 0 ,\tres-hdr=10 ,  res-body=20 ", CAP).unwrap();
        assert_eq!(tight, loose);
    }

    #[test]
    fn rejects_malformed_lists() {
        assert_eq!(err(""), "empty Encapsulated entry");
        assert_eq!(err("   "), "empty Encapsulated entry");
        assert_eq!(err("res-body"), "Encapsulated entry without an offset");
        assert_eq!(
            err("res-body="),
            "Encapsulated offset is not a decimal number"
        );
        assert_eq!(err("bogus=0"), "unknown Encapsulated entity");
        assert_eq!(
            err("res-body=abc"),
            "Encapsulated offset is not a decimal number"
        );
        assert_eq!(
            err("res-body=0x10"),
            "Encapsulated offset is not a decimal number"
        );
        assert_eq!(err("req-hdr=0,,res-body=5"), "empty Encapsulated entry");
        assert_eq!(
            err("req-hdr=0"),
            "Encapsulated list has no body or null-body"
        );
    }

    #[test]
    fn rejects_hostile_offsets() {
        // Signed and explicitly-positive forms: two parsers can disagree about
        // these, and the header decides which bytes get scanned.
        assert_eq!(
            err("res-body=-1"),
            "Encapsulated offset is not a decimal number"
        );
        assert_eq!(
            err("res-body=+1"),
            "Encapsulated offset is not a decimal number"
        );
        assert_eq!(
            err("res-body= 1 2"),
            "Encapsulated offset is not a decimal number"
        );
        // Past usize on every platform.
        assert_eq!(
            err("res-body=999999999999999999999999999999"),
            "Encapsulated offset out of range"
        );
        // These two land on either "out of range" or "exceeds the header
        // ceiling" depending on the width of `usize`. Both are refusals; which
        // one fires is not the property under test.
        assert!(Encapsulated::parse("res-body=18446744073709551615", CAP).is_err());
        assert!(Encapsulated::parse("res-body=4294967295", CAP).is_err());
    }

    #[test]
    fn rejects_structurally_impossible_lists() {
        assert_eq!(
            err("res-hdr=100, req-hdr=0, res-body=200"),
            "Encapsulated offsets are not ascending"
        );
        assert_eq!(
            err("req-hdr=0, req-hdr=10, null-body=20"),
            "duplicate Encapsulated entity"
        );
        assert_eq!(
            err("req-hdr=0, res-body=10, res-hdr=20"),
            "Encapsulated entity after the body entity"
        );
        assert_eq!(
            err("req-hdr=0, null-body=10, res-body=20"),
            "Encapsulated entity after the body entity"
        );
    }

    #[test]
    fn equal_offsets_describe_an_empty_section() {
        let e = Encapsulated::parse("req-hdr=0, res-hdr=0, res-body=0", CAP).unwrap();
        assert_eq!(e.span(Entity::ReqHdr), Some((0, 0)));
        assert_eq!(e.header_bytes(), 0);
    }

    #[test]
    fn parses_a_request_line_and_headers() {
        let head = b"RESPMOD icap://av.example:1344/avscan?allow204=on ICAP/1.0\r\n\
                     Host: av.example\r\n\
                     Allow: 204\r\n\
                     Encapsulated: res-hdr=0, res-body=42\r\n\r\n";
        let r = RequestHead::parse(head).unwrap();
        assert_eq!(r.method, IcapMethod::RespMod);
        assert_eq!(r.service, "avscan");
        assert!(r.allow_204());
        assert!(!r.wants_close());
        assert_eq!(r.preview().unwrap(), None);
        assert_eq!(r.encapsulated(CAP).unwrap().header_bytes(), 42);
    }

    #[test]
    fn header_lookup_is_case_insensitive_and_allow_accepts_lists() {
        let head = b"OPTIONS /avscan ICAP/1.0\r\nallow: 206, 204\r\nALLOW: 100\r\n\r\n";
        let r = RequestHead::parse(head).unwrap();
        assert_eq!(r.header("Allow"), Some("206, 204"));
        assert!(r.allow_204());
    }

    #[test]
    fn extracts_the_service_from_every_uri_shape() {
        let cases = [
            ("icap://host:1344/avscan", "avscan"),
            ("icap://host/srv_clamav", "srv_clamav"),
            ("ICAP://host:1344/avscan?allow204=on&mode=simple", "avscan"),
            ("/avscan", "avscan"),
            ("avscan", "avscan"),
            ("icap://host:1344/avscan/", "avscan"),
            ("icap://host:1344/", ""),
            ("icap://host:1344", ""),
        ];
        for (uri, want) in cases {
            assert_eq!(service_from_uri(uri), want, "uri {uri}");
        }
    }

    #[test]
    fn rejects_hostile_heads() {
        let bad: [(&[u8], &str); 7] = [
            (b"RESPMOD\r\n\r\n", "request line has no URI"),
            (b"RESPMOD /avscan\r\n\r\n", "request line has no version"),
            (b"RESPMOD /avscan HTTP/1.1\r\n\r\n", "not an ICAP request"),
            (
                b"RESPMOD /avscan ICAP/1.0 extra\r\n\r\n",
                "request line has trailing garbage",
            ),
            (
                b"OPTIONS /avscan ICAP/1.0\r\nbroken\r\n\r\n",
                "header line without a colon",
            ),
            (
                b"OPTIONS /avscan ICAP/1.0\r\nHost: a\r\n\tfolded\r\n\r\n",
                "folded header line",
            ),
            (
                b"OPTIONS /avscan ICAP/1.0\r\nBad Name: a\r\n\r\n",
                "malformed header name",
            ),
        ];
        for (head, want) in bad {
            assert_eq!(RequestHead::parse(head).unwrap_err().to_string(), want);
        }
        // A high byte in the head is a client sending binary at a text
        // protocol; the UTF-8 check catches it first when it is not valid
        // UTF-8, the ASCII check when it is.
        assert!(RequestHead::parse(b"OPTIONS /a ICAP/1.0\r\nX: \xff\r\n\r\n").is_err());
        assert_eq!(
            RequestHead::parse("OPTIONS /a ICAP/1.0\r\nX: \u{e9}\r\n\r\n".as_bytes())
                .unwrap_err()
                .to_string(),
            "head contains non-ASCII bytes"
        );
    }

    #[test]
    fn rejects_a_duplicate_encapsulated_header() {
        let head =
            b"RESPMOD /avscan ICAP/1.0\r\nEncapsulated: res-hdr=0, res-body=10\r\nEncapsulated: res-hdr=0, res-body=20\r\n\r\n";
        let r = RequestHead::parse(head).unwrap();
        assert_eq!(
            r.encapsulated(CAP).unwrap_err().to_string(),
            "duplicate Encapsulated header"
        );
    }

    #[test]
    fn rejects_a_malformed_preview() {
        let head = b"RESPMOD /avscan ICAP/1.0\r\nPreview: -1\r\n\r\n";
        assert_eq!(
            RequestHead::parse(head)
                .unwrap()
                .preview()
                .unwrap_err()
                .to_string(),
            "malformed Preview header"
        );
        let head = b"RESPMOD /avscan ICAP/1.0\r\nPreview: 0\r\n\r\n";
        assert_eq!(
            RequestHead::parse(head).unwrap().preview().unwrap(),
            Some(0)
        );
    }

    #[test]
    fn reads_a_head_and_stops_at_the_blank_line() {
        let mut r =
            std::io::BufReader::new(&b"OPTIONS /avscan ICAP/1.0\r\nHost: a\r\n\r\nLEFTOVER"[..]);
        let head = read_head(&mut r, 4096).unwrap().unwrap();
        assert!(head.ends_with(b"\r\n\r\n"));
        let mut rest = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut rest).unwrap();
        assert_eq!(rest, b"LEFTOVER");
    }

    #[test]
    fn a_closed_connection_between_requests_is_not_an_error() {
        let mut r = std::io::BufReader::new(&b""[..]);
        assert!(read_head(&mut r, 4096).unwrap().is_none());
    }

    #[test]
    fn a_head_that_never_ends_is_cut_off() {
        let flood = b"OPTIONS /a ICAP/1.0\r\n".to_vec();
        let mut endless: Vec<u8> = flood;
        for _ in 0..500 {
            endless.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        let mut r = std::io::BufReader::new(&endless[..]);
        assert!(read_head(&mut r, 1024).is_err());
    }
}
