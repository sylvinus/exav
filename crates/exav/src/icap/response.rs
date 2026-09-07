//! Turning a scan verdict into an ICAP response.

use std::io::{self, Write};

use exav_core::{ScanReport, Scanner, VerdictCategory};

use super::chunked;
use super::config::{IcapConfig, InfectionHeader};
use super::wire::Entity;
use crate::daemon::StreamPayload;

/// What the ICAP server decided to do with an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Decision {
    /// Nothing found; the message passes through untouched.
    Clean,
    /// A signature matched. Carries the signature name.
    Infected(String),
    /// The object was not fully examined, so it is blocked. Carries the verdict
    /// tag (`LIMITS-EXCEEDED`, `UNSCANNABLE`, `PASSWORD-PROTECTED`) and the
    /// detail behind it.
    Partial(&'static str, String),
}

impl Decision {
    /// Map a [`ScanReport`] onto an ICAP decision.
    ///
    /// Keyed on [`VerdictCategory`] rather than on the individual verdicts, so
    /// a verdict added to the engine lands in the right column here without
    /// this file being touched — and lands on the blocking side, which is the
    /// side that fails safe.
    pub(super) fn from_report(report: &ScanReport) -> Self {
        let v = &report.verdict;
        match v.category() {
            VerdictCategory::Clean => Self::Clean,
            VerdictCategory::Infected => {
                Self::Infected(v.detail().unwrap_or("unnamed signature").to_string())
            }
            VerdictCategory::Partial => {
                Self::Partial(v.status_tag(), v.detail().unwrap_or_default().to_string())
            }
        }
    }

    /// Whether this decision blocks the object.
    pub(super) fn blocks(&self) -> bool {
        !matches!(self, Self::Clean)
    }

    /// The counter column this decision belongs in.
    pub(super) fn category(&self) -> crate::metrics::Category {
        match self {
            Self::Clean => crate::metrics::Category::Clean,
            Self::Infected(_) => crate::metrics::Category::Infected,
            Self::Partial(_, _) => crate::metrics::Category::Partial,
        }
    }

    /// The ICAP headers this decision adds to a `200` response.
    ///
    /// A detection always carries `X-Infection-Found` under its signature name.
    /// A partial verdict carries the `X-Exav-*` trio — `Status`, `Category`,
    /// `Reason` — which is the same three-word vocabulary the CLI prints and the
    /// JSON emits, and — under [`InfectionHeader::Blocks`] —
    /// `X-Infection-Found` as well, so that a client reading only the c-icap
    /// vocabulary still learns the object was blocked. The two are never
    /// confusable: a partial block is reported under `Heuristics.Exav.*`, a
    /// namespace no signature database occupies.
    fn headers(&self, policy: InfectionHeader) -> Vec<(&'static str, String)> {
        match self {
            Self::Clean => Vec::new(),
            Self::Infected(name) => vec![infection_found(name)],
            Self::Partial(tag, reason) => {
                let mut headers = Vec::with_capacity(4);
                if policy == InfectionHeader::Blocks {
                    headers.push(infection_found(&heuristic_name(tag)));
                }
                headers.extend(partial_headers(tag, reason));
                headers
            }
        }
    }

    /// The ICAP headers a decision adds when policy lets the object through
    /// rather than blocking it.
    ///
    /// The `X-Exav-*` pair and never `X-Infection-Found`, whichever
    /// [`InfectionHeader`] policy is in force. The object is being delivered, so
    /// reporting an infection would be false on its face — and it would make
    /// exactly the header-only client the policy exists for treat the pass as a
    /// block, which is the opposite of what the operator asked for.
    fn pass_headers(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::Clean | Self::Infected(_) => Vec::new(),
            Self::Partial(tag, reason) => partial_headers(tag, reason),
        }
    }

    /// One line for the log.
    pub(super) fn summary(&self) -> String {
        match self {
            Self::Clean => "clean".to_string(),
            Self::Infected(name) => format!("infected: {}", header_safe(name)),
            Self::Partial(tag, reason) => format!("{tag}: {}", header_safe(reason)),
        }
    }
}

/// The `X-Exav-*` trio describing a partial verdict.
///
/// The same three words the CLI line and the JSON use — status, category,
/// reason — so a client reading headers, a script reading stdout and a consumer
/// reading JSON all learn the object's fate in one vocabulary.
///
/// `Status` is `PARTIAL` even under `--partial-as error`: ICAP has no exit code,
/// which is the only thing those two statuses differ in, and reporting `ERROR`
/// here would tell a proxy the *scanner* failed. Squid answers that by counting
/// service failures and eventually bypassing the service — so relabelling an
/// encrypted archive could take the scanner out of rotation and start failing
/// open, which is the one outcome exav must never cause.
fn partial_headers(tag: &str, reason: &str) -> Vec<(&'static str, String)> {
    vec![
        ("X-Exav-Status", "PARTIAL".to_string()),
        ("X-Exav-Category", tag.to_string()),
        ("X-Exav-Reason", header_safe(reason)),
    ]
}

/// The `X-Infection-Found` header naming `threat`.
///
/// The exact shape c-icap's `virus_scan` module emits, down to the trailing
/// semicolon, because deployed clients parse this by hand.
fn infection_found(threat: &str) -> (&'static str, String) {
    (
        "X-Infection-Found",
        format!("Type=0; Resolution=2; Threat={};", header_safe(threat)),
    )
}

/// The threat name a partial block is reported under, derived from the
/// verdict's status tag: `LIMITS-EXCEEDED` becomes
/// `Heuristics.Exav.LimitsExceeded`.
///
/// Derived rather than tabulated, so a verdict added to the engine gets a name
/// here without this file being touched — the same reason
/// [`Decision::from_report`] keys on the category rather than the verdict.
///
/// `Heuristics.` is the prefix ClamAV puts on exactly this class of finding (an
/// object blocked by a policy rather than by a database entry), and `.Exav.`
/// says which scanner synthesised it. An analyst reading an incident log can
/// tell one of these from a real hit by its name, and no signature database
/// ships a name that collides.
fn heuristic_name(tag: &str) -> String {
    let mut out = String::from("Heuristics.Exav.");
    for word in tag.split('-') {
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars.map(|c| c.to_ascii_lowercase()));
        }
    }
    out
}

/// Make a string safe to put in a header value.
///
/// Signature names come from the database, but the *reason* on a partial
/// verdict can quote a container member's name, and that name came out of the
/// file being scanned. A newline in it would end the header and let the rest be
/// read as headers of its own — the attacker choosing what a proxy sees. So
/// control characters and non-ASCII bytes are replaced rather than escaped, and
/// the result is truncated.
fn header_safe(s: &str) -> String {
    const MAX: usize = 200;
    let mut out = String::with_capacity(s.len().min(MAX));
    for c in s.chars() {
        if out.len() >= MAX {
            out.push_str("...");
            break;
        }
        if c.is_ascii_graphic() || c == ' ' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    out
}

/// Escape the five characters that would otherwise be markup in the block page.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// An `ISTag` value that changes whenever the loaded signature set changes.
///
/// ICAP clients cache adaptation results against the `ISTag`, so a tag that
/// stayed put across a signature reload would keep serving verdicts from the
/// old database — a newly-published signature would not reach cached objects.
/// The tag folds the database version, its build time and the signature count
/// into one short opaque value; RFC 3507 caps the whole quoted string at 32
/// bytes, which rules out spelling those fields out.
pub(super) fn istag(db: &Scanner) -> String {
    // FNV-1a, 64-bit. A cryptographic hash is not wanted here: the tag is a
    // cache key, not a commitment, and it has to be cheap enough to recompute
    // per request so a reload is visible immediately.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    feed(super::VERSION.as_bytes());
    match db.db_version() {
        Some((ver, btime)) => {
            feed(&ver.to_le_bytes());
            feed(btime.as_bytes());
        }
        None => feed(b"no-container"),
    }
    feed(&(db.signature_count() as u64).to_le_bytes());
    format!("\"exav-{h:016x}\"")
}

/// An ICAP response under construction.
pub(super) struct Response {
    code: u16,
    text: &'static str,
    headers: Vec<(String, String)>,
    /// Value of the `Encapsulated` header.
    encapsulated: String,
    /// Encapsulated header block, followed by the chunk-encoded body when that
    /// body is small enough to have been built here.
    payload: Vec<u8>,
    /// A body handed back from where it was buffered, chunk-encoded straight
    /// out of it as the response is written.
    ///
    /// Echoing a message the client wants returned means writing back an object
    /// that may have spilled to disk, and collecting it into `payload` first
    /// would put the whole thing in memory — undoing on the way out the bound
    /// the spill buys on the way in.
    stream: Option<StreamPayload>,
    /// Whether the connection must close after this response.
    pub(super) close: bool,
}

impl Response {
    fn new(code: u16, text: &'static str) -> Self {
        Self {
            code,
            text,
            headers: Vec::new(),
            encapsulated: "null-body=0".to_string(),
            payload: Vec::new(),
            stream: None,
            close: false,
        }
    }

    fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    pub(super) fn closing(mut self) -> Self {
        self.close = true;
        self
    }

    /// Record, on a response that lets the object through, the verdict that
    /// would otherwise have blocked it. A configured pass is still not a silent
    /// one: the client is told what was skipped and why.
    pub(super) fn noting(mut self, decision: &Decision) -> Self {
        for (name, value) in decision.pass_headers() {
            self.headers.push((name.to_string(), value));
        }
        self
    }

    /// Serialise and write. `istag` is threaded in here rather than stored so
    /// that every response on a connection carries the tag of the database that
    /// answered it.
    pub(super) fn write_to<W: Write>(&self, w: &mut W, istag: &str) -> io::Result<()> {
        let mut out = Vec::with_capacity(256 + self.payload.len());
        out.extend_from_slice(format!("ICAP/1.0 {} {}\r\n", self.code, self.text).as_bytes());
        out.extend_from_slice(format!("Server: exav/{}\r\n", super::VERSION).as_bytes());
        out.extend_from_slice(format!("ISTag: {istag}\r\n").as_bytes());
        for (k, v) in &self.headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "Connection: {}\r\n",
                if self.close { "close" } else { "keep-alive" }
            )
            .as_bytes(),
        );
        out.extend_from_slice(format!("Encapsulated: {}\r\n\r\n", self.encapsulated).as_bytes());
        out.extend_from_slice(&self.payload);
        w.write_all(&out)?;
        if let Some(payload) = &self.stream {
            chunked::encode_into(w, payload)?;
        }
        w.flush()
    }
}

/// `100 Continue`: sent bare, with no headers at all, because it is an interim
/// answer inside a request rather than a response to it.
pub(super) fn write_continue<W: Write>(w: &mut W) -> io::Result<()> {
    w.write_all(b"ICAP/1.0 100 Continue\r\n\r\n")?;
    w.flush()
}

/// `204 No Content` — the object is unchanged, pass it on.
pub(super) fn no_content() -> Response {
    Response::new(204, "No Content")
}

/// An error response with no encapsulated message.
pub(super) fn error(code: u16, text: &'static str) -> Response {
    Response::new(code, text)
}

/// The answer to `OPTIONS`.
pub(super) fn options(cfg: &IcapConfig) -> Response {
    let mut r = Response::new(200, "OK")
        // Both methods, because the c-icap virus_scan service answers both and
        // their ACL permits both.
        .header("Methods", "REQMOD, RESPMOD")
        .header("Service", cfg.service_label.clone())
        .header("Allow", "204")
        .header("Preview", cfg.preview_size.to_string())
        .header("Max-Connections", cfg.max_connections.to_string())
        .header("Options-TTL", cfg.options_ttl.to_string());
    if !cfg.transfer_preview.is_empty() {
        r = r.header("Transfer-Preview", cfg.transfer_preview.clone());
    }
    r
}

/// A `200` that hands the original message back unmodified.
///
/// This is what a clean object gets from a client that did not offer
/// `Allow: 204`. The encapsulated headers go back byte for byte — rewriting
/// them would change a message exav has no opinion about.
pub(super) fn echo(hdr_entity: Entity, hdr: &[u8], body: Option<StreamPayload>) -> Response {
    let mut r = Response::new(200, "OK");
    let body_entity = match (hdr_entity, &body) {
        (Entity::ReqHdr, Some(_)) => Entity::ReqBody,
        (_, Some(_)) => Entity::ResBody,
        (_, None) => Entity::NullBody,
    };
    r.encapsulated = format!(
        "{}=0, {}={}",
        hdr_entity.as_str(),
        body_entity.as_str(),
        hdr.len()
    );
    r.payload.extend_from_slice(hdr);
    r.stream = body;
    r
}

/// A `200` that replaces the message with a block page.
///
/// Blocking a REQMOD is done the same way as blocking a RESPMOD — by returning
/// an HTTP *response* — which is RFC 3507's "request satisfaction": the client
/// serves this instead of forwarding the request upstream.
pub(super) fn block(decision: &Decision, policy: InfectionHeader) -> Response {
    let page = block_page(decision);
    let http = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Server: exav\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        page.len()
    );
    let mut r = Response::new(200, "OK");
    for (k, v) in decision.headers(policy) {
        r = r.header(k, v);
    }
    r.encapsulated = format!("res-hdr=0, res-body={}", http.len());
    r.payload.extend_from_slice(http.as_bytes());
    r.payload
        .extend_from_slice(&chunked::encode(page.as_bytes()));
    r
}

/// The HTML served in place of a blocked object.
fn block_page(decision: &Decision) -> String {
    let (heading, detail) = match decision {
        Decision::Clean => ("Blocked", String::new()),
        Decision::Infected(name) => (
            "Malware detected",
            format!(
                "The object matched the signature <code>{}</code>.",
                html_escape(name)
            ),
        ),
        Decision::Partial(tag, reason) => (
            "Not scannable",
            format!(
                "exav could not fully examine this object ({}): {}. \
                 An object that could not be examined is not known to be safe, so it is blocked.",
                html_escape(tag),
                html_escape(reason)
            ),
        ),
    };
    format!(
        "<!doctype html>\n\
         <html lang=\"en\">\n\
         <head><meta charset=\"utf-8\"><title>{heading}</title></head>\n\
         <body>\n\
         <h1>{heading}</h1>\n\
         <p>{detail}</p>\n\
         <p>Scanned by exav {}.</p>\n\
         </body>\n\
         </html>\n",
        super::VERSION
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use exav_core::{Method, Verdict};

    fn report(verdict: Verdict) -> ScanReport {
        ScanReport {
            verdict,
            findings: Vec::new(),
        }
    }

    /// The partial verdicts, with the status tag each one reports under.
    const NOT_SCANNED: [(&str, &str); 3] = [
        ("size exceeds 1024", "LIMITS-EXCEEDED"),
        ("rar: ppmd", "UNSCANNABLE"),
        ("zip member is encrypted", "PASSWORD-PROTECTED"),
    ];

    fn not_scanned(reason: &str, tag: &str) -> ScanReport {
        report(match tag {
            "LIMITS-EXCEEDED" => Verdict::LimitsExceeded {
                reason: reason.to_string(),
            },
            "UNSCANNABLE" => Verdict::Unscannable {
                reason: reason.to_string(),
            },
            _ => Verdict::PasswordProtected {
                reason: reason.to_string(),
            },
        })
    }

    /// Header names in the order they go on the wire.
    fn names(headers: &[(&'static str, String)]) -> Vec<&'static str> {
        headers.iter().map(|(k, _)| *k).collect()
    }

    #[test]
    fn clean_passes() {
        let d = Decision::from_report(&report(Verdict::Clean));
        assert_eq!(d, Decision::Clean);
        assert!(!d.blocks());
        assert!(d.headers(InfectionHeader::Blocks).is_empty());
        assert!(d.headers(InfectionHeader::Detections).is_empty());
    }

    #[test]
    fn an_infection_carries_the_c_icap_header_under_either_policy() {
        let d = Decision::from_report(&report(Verdict::Infected {
            signature: "Exav.Test.EICAR".to_string(),
            offset: 0,
            method: Method::Pattern,
        }));
        assert!(d.blocks());
        for policy in [InfectionHeader::Blocks, InfectionHeader::Detections] {
            assert_eq!(
                d.headers(policy),
                vec![(
                    "X-Infection-Found",
                    "Type=0; Resolution=2; Threat=Exav.Test.EICAR;".to_string()
                )],
                "{policy:?}"
            );
        }
    }

    #[test]
    fn a_not_scanned_verdict_is_legible_to_a_header_only_client() {
        // The default. A client that decides clean-or-not from
        // `X-Infection-Found` alone — a scan wrapper shelling out to an ICAP
        // client, a mail gateway — would otherwise read the block as a pass.
        for (reason, tag) in NOT_SCANNED {
            let d = Decision::from_report(&not_scanned(reason, tag));
            assert!(d.blocks());
            let headers = d.headers(InfectionHeader::Blocks);
            assert_eq!(
                names(&headers),
                vec![
                    "X-Infection-Found",
                    "X-Exav-Status",
                    "X-Exav-Category",
                    "X-Exav-Reason"
                ],
                "{tag}"
            );
            // `PARTIAL` whatever the category, because ICAP has no exit code —
            // the one thing `--partial-as error` changes.
            assert_eq!(headers[1].1, "PARTIAL");
            assert_eq!(headers[2].1, tag);
            assert_eq!(headers[3].1, reason);
            // Named so that no analyst reading a log, and no rule matching on
            // the threat name, can take it for a database detection.
            assert!(
                headers[0].1.contains("Threat=Heuristics.Exav."),
                "{tag}: {}",
                headers[0].1
            );
        }
    }

    #[test]
    fn the_detections_policy_keeps_the_header_for_database_hits_alone() {
        for (reason, tag) in NOT_SCANNED {
            let d = Decision::from_report(&not_scanned(reason, tag));
            let headers = d.headers(InfectionHeader::Detections);
            assert_eq!(
                names(&headers),
                vec!["X-Exav-Status", "X-Exav-Category", "X-Exav-Reason"],
                "{tag}"
            );
            assert_eq!(headers[0].1, "PARTIAL");
            assert_eq!(headers[1].1, tag);
        }
    }

    #[test]
    fn a_not_scanned_threat_name_reads_as_the_condition_that_blocked() {
        assert_eq!(
            heuristic_name("LIMITS-EXCEEDED"),
            "Heuristics.Exav.LimitsExceeded"
        );
        assert_eq!(heuristic_name("UNSCANNABLE"), "Heuristics.Exav.Unscannable");
        assert_eq!(
            heuristic_name("PASSWORD-PROTECTED"),
            "Heuristics.Exav.PasswordProtected"
        );
        // A tag the engine has not grown yet still produces a name rather than
        // an empty one, which is what makes the derivation safe to leave alone.
        assert_eq!(heuristic_name("NEW-TAG-HERE"), "Heuristics.Exav.NewTagHere");
        assert_eq!(heuristic_name(""), "Heuristics.Exav.");
    }

    #[test]
    fn header_values_cannot_carry_a_line_break() {
        let d = Decision::Partial(
            "UNSCANNABLE",
            "member\r\nX-Injected: yes\r\n\r\nevil".to_string(),
        );
        let headers = d.headers(InfectionHeader::Detections);
        // Status, Category, Reason — the reason is the one carrying attacker
        // bytes, since it can quote a container member's name.
        assert_eq!(headers[2].1, "member__X-Injected: yes____evil");
        assert!(!headers[2].1.contains('\r') && !headers[2].1.contains('\n'));
    }

    #[test]
    fn a_signature_name_cannot_carry_a_line_break() {
        let d = Decision::Infected("Evil\r\nX-Infection-Found: fake".to_string());
        let v = &d.headers(InfectionHeader::Blocks)[0].1;
        assert!(!v.contains('\r') && !v.contains('\n'));
    }

    #[test]
    fn long_header_values_are_truncated() {
        let d = Decision::Partial("UNSCANNABLE", "x".repeat(5000));
        assert!(d.headers(InfectionHeader::Detections)[1].1.len() <= 210);
    }

    #[test]
    fn the_block_page_escapes_the_detail() {
        let page = block_page(&Decision::Infected("<script>alert(1)</script>".to_string()));
        assert!(!page.contains("<script>"));
        assert!(page.contains("&lt;script&gt;"));
    }

    #[test]
    fn istag_tracks_the_signature_set() {
        let a = istag(&Scanner::builtin());
        let b = istag(&Scanner::builtin());
        assert_eq!(a, b, "the same database must produce the same tag");
        assert!(a.starts_with('"') && a.ends_with('"'));
        // RFC 3507 caps the quoted ISTag at 32 bytes.
        assert!(a.len() <= 32, "{a} is {} bytes", a.len());
    }

    #[test]
    fn a_response_serialises_with_crlf_framing() {
        let mut out = Vec::new();
        no_content().write_to(&mut out, "\"t\"").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("ICAP/1.0 204 No Content\r\n"));
        assert!(text.contains("\r\nISTag: \"t\"\r\n"));
        assert!(text.contains("\r\nEncapsulated: null-body=0\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn an_echo_reproduces_the_message() {
        let hdr = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n";
        let r = echo(
            Entity::ResHdr,
            hdr,
            Some(StreamPayload::Mem(b"hi".to_vec())),
        );
        assert_eq!(r.encapsulated, format!("res-hdr=0, res-body={}", hdr.len()));
        // The headers are built here; the body is written straight out of where
        // it was buffered, so it appears on the wire rather than in `payload`.
        assert_eq!(r.payload, hdr);
        let mut out = Vec::new();
        r.write_to(&mut out, "\"t\"").unwrap();
        assert!(out.ends_with(b"2\r\nhi\r\n0\r\n\r\n"), "{out:?}");
    }

    #[test]
    fn an_echo_of_a_header_only_message_uses_null_body() {
        let hdr = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let r = echo(Entity::ReqHdr, hdr, None);
        assert_eq!(
            r.encapsulated,
            format!("req-hdr=0, null-body={}", hdr.len())
        );
        assert_eq!(r.payload, hdr);
    }
}
