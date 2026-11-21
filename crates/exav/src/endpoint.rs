//! Where exav listens, and what speaks there.
//!
//! One address grammar for both directions and both protocols:
//!
//! ```text
//! clamd://0.0.0.0:3310        the clamd protocol over TCP
//! clamd:///var/run/exav.sock  the clamd protocol over a Unix socket
//! icap://0.0.0.0:1344         ICAP over TCP
//! 0.0.0.0:3310                no scheme: clamd, the older of the two
//! /var/run/exav.sock          no scheme, a path: clamd over a Unix socket
//! ```
//!
//! Two flags, and the protocol travels in the value. A flag per protocol would
//! need a second flag for the address, so a third protocol would cost two more
//! flags; and a flag naming only an address has to be told elsewhere whether it
//! means "listen here" or "connect there", which makes the same word mean
//! opposite directions depending on what else is on the line.
//!
//! Here `--listen` is always a place exav accepts connections, `--connect` is
//! always a place it makes one, and a protocol added later is a new scheme
//! rather than a new flag.

use std::path::PathBuf;

/// A protocol exav speaks on a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proto {
    /// The clamd wire protocol: `clamdscan`, milters, `clamdtop`.
    Clamd,
    /// ICAP (RFC 3507), for a proxy's or upload scanner's adaptation hook.
    Icap,
}

impl Proto {
    fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            // `clamd`, not `clamav`: ClamAV is the project, clamd is the daemon
            // and the protocol, and it reads as a peer of `icap`, which is also
            // a protocol rather than a product.
            "clamd" => Ok(Self::Clamd),
            "icap" => Ok(Self::Icap),
            other => Err(format!("unknown protocol `{other}` (known: clamd, icap)")),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Clamd => "clamd",
            Self::Icap => "icap",
        }
    }
}

/// Where a socket lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Addr {
    Tcp(String),
    Unix {
        path: PathBuf,
        /// Permission bits, from `?mode=660`. `None` leaves the default (0600,
        /// owner only).
        ///
        /// Carried by the address rather than by a flag of its own, because it
        /// is a property of *this* socket. A flag would need cross-checks that
        /// a clamd listener exists, that it is a Unix one, and that it is not
        /// TCP; here none of those states is representable.
        mode: Option<u32>,
    },
}

impl Addr {
    /// What two spellings of one socket have in common, `None` for an address
    /// that names no particular socket (port 0 asks for a free one each time).
    ///
    /// A socket address is compared as the address it parses to, a path by the
    /// directory it is in once that is resolved. A host name is compared as
    /// written: two names for one machine are left to the bind, which fails on
    /// a port that is taken.
    fn identity(&self) -> Option<String> {
        match self {
            Addr::Tcp(a) => {
                if a.rsplit_once(':')
                    .is_some_and(|(_, port)| port.parse::<u16>() == Ok(0))
                {
                    return None;
                }
                Some(match a.parse::<std::net::SocketAddr>() {
                    Ok(s) => format!("tcp:{s}"),
                    Err(_) => format!("tcp:{}", a.to_ascii_lowercase()),
                })
            }
            Addr::Unix { path, .. } => {
                // Drops `.`, repeated and trailing separators.
                let clean: PathBuf = path.components().collect();
                let resolved = match (clean.parent(), clean.file_name()) {
                    (Some(dir), Some(name)) => std::fs::canonicalize(dir)
                        .map(|d| d.join(name))
                        .unwrap_or_else(|_| clean.clone()),
                    _ => clean,
                };
                Some(format!("unix:{}", resolved.display()))
            }
        }
    }
}

/// A protocol and a place, parsed from one `--listen` / `--connect` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub proto: Proto,
    pub addr: Addr,
    /// Concurrent connections accepted here, from `?max-connections=200`.
    ///
    /// On the address rather than in a flag for the same reason `mode` is: it
    /// bounds *this* listener. A flag would have to name a protocol to apply to,
    /// so two listeners would need two flags, and the one without a flag would
    /// be stuck on a constant nobody could reach.
    pub max_connections: Option<usize>,
    /// The most seconds a connection waits for its client, from
    /// `?idle-secs=120`: each read of a clamd client (its first command, the
    /// next of a session, the next chunk of `INSTREAM`); an ICAP connection
    /// between requests or inside one. On the address, as `max-connections`
    /// is, because it bounds this listener's clients.
    pub idle_secs: Option<u64>,
    /// The most seconds a connection stays open, from `?session-secs=3600`,
    /// counted from accept. Once it has passed, no new clamd command and no new
    /// ICAP request is read; one that began before is answered. `None`: no limit.
    pub session_secs: Option<u64>,
    /// The most seconds the writes of one reply may wait for the client, summed
    /// over the writes of that reply, from `?reply-secs=60`: everything written
    /// for one clamd command, or for one ICAP request. `None`: no limit beyond
    /// the per-write timeout.
    pub reply_secs: Option<u64>,
    /// The most seconds one clamd command or ICAP request may take to arrive
    /// in full, from `?request-secs=600`: from its first byte to the end of its
    /// `INSTREAM` data or request body. `Some(0)` (`off`): no limit; `None`:
    /// the default.
    pub request_secs: Option<u64>,
    /// Requests served on one ICAP connection before it is closed, from
    /// `?max-requests=100`. `Some(0)` (`off`): no limit; `None`: the default.
    pub max_requests: Option<u64>,
    /// The largest ICAP head plus encapsulated HTTP headers of one request,
    /// from `?max-header-bytes=64K`.
    pub max_header_bytes: Option<usize>,
    /// The ICAP `Preview` size this listener offers, from `?preview-bytes=4096`;
    /// `off` leaves the header out.
    pub preview_bytes: Option<crate::OrOff<usize>>,
    /// Whether this ICAP listener sends `Transfer-Preview: *`, from
    /// `?transfer-preview=*`; `false` for `off`, which leaves the header out.
    pub transfer_preview: Option<bool>,
    /// Seconds an ICAP client may keep this listener's `OPTIONS` answer, from
    /// `?options-ttl-secs=3600`; `off` leaves the header out.
    pub options_ttl_secs: Option<crate::OrOff<u32>>,
    /// Which ICAP blocks carry `X-Infection-Found`, from
    /// `?infection-header=detections`.
    pub infection_header: Option<InfectionHeader>,
    /// ICAP service names to answer on, from the path (`icap://h:1344/avscan`)
    /// or from a repeated `?service=avscan&service=srv_clamav`. Empty keeps
    /// the default set.
    ///
    /// A service name *is* the path of the ICAP URL a proxy is configured with,
    /// so the address is where it already lives: `icap://scanner:1344/avscan`
    /// out of a `squid.conf` is pasted here unchanged. Naming it separately
    /// would split one URL across two flags, which is what putting the protocol
    /// in the value removed for the scheme.
    pub services: Vec<String>,
}

/// When an ICAP block carries the c-icap `X-Infection-Found` header.
///
/// c-icap's vocabulary has one header for "this object is not OK", and a whole
/// class of ICAP clients decides clean-or-not from that header alone rather than
/// from the response body: a health-check script, a mail gateway, the shell
/// wrapper a content scanner shells out to. Those clients read a `200` carrying
/// a block page and no `X-Infection-Found` as **clean**, which is the one answer
/// exav must never give for an object it did not fully examine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum InfectionHeader {
    /// Every block carries it. A signature match is reported under its own
    /// name; a partial verdict under a `Heuristics.Exav.*` name that says
    /// which condition blocked it, alongside the `X-Exav-Category` /
    /// `X-Exav-Reason` pair that spells it out for a client that reads them.
    #[default]
    Blocks,
    /// Only a signature match carries it, so the header means a database
    /// detection and nothing else. A client that keys on it alone then treats
    /// an unscannable object as clean, which is why this is not the default.
    Detections,
}

impl InfectionHeader {
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        match s {
            "blocks" => Ok(Self::Blocks),
            "detections" => Ok(Self::Detections),
            other => Err(format!("expected `blocks` or `detections`, got `{other}`")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Blocks => "blocks",
            Self::Detections => "detections",
        }
    }
}

impl Endpoint {
    /// Names of the server-side tunables this address carries: every `?…`
    /// option and the ICAP service (path or `?service=`). A `--connect` client
    /// dials `addr` and honours none of these, so an address carrying any of
    /// them is refused client-side rather than quietly dropped. Unknown keys
    /// never reach here: the parser refuses those for both flags.
    pub(crate) fn server_side_options(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.max_connections.is_some() {
            out.push("max-connections");
        }
        if self.idle_secs.is_some() {
            out.push("idle-secs");
        }
        if self.session_secs.is_some() {
            out.push("session-secs");
        }
        if self.reply_secs.is_some() {
            out.push("reply-secs");
        }
        if self.request_secs.is_some() {
            out.push("request-secs");
        }
        if self.max_requests.is_some() {
            out.push("max-requests");
        }
        if self.max_header_bytes.is_some() {
            out.push("max-header-bytes");
        }
        out.extend(self.icap_service_options());
        if !self.services.is_empty() {
            out.push("service");
        }
        if let Addr::Unix { mode: Some(_), .. } = &self.addr {
            out.push("mode");
        }
        out
    }

    /// The keys given of those that set what an ICAP service answers.
    fn icap_service_options(&self) -> Vec<&'static str> {
        [
            (self.preview_bytes.is_some(), "preview-bytes"),
            (self.transfer_preview.is_some(), "transfer-preview"),
            (self.options_ttl_secs.is_some(), "options-ttl-secs"),
            (self.infection_header.is_some(), "infection-header"),
        ]
        .into_iter()
        .filter_map(|(set, key)| set.then_some(key))
        .collect()
    }
}

/// The `?…` options of one address, before they are attached to a place.
#[derive(Default)]
struct Options {
    mode: Option<u32>,
    max_connections: Option<usize>,
    idle_secs: Option<u64>,
    session_secs: Option<u64>,
    reply_secs: Option<u64>,
    request_secs: Option<u64>,
    max_requests: Option<u64>,
    max_header_bytes: Option<usize>,
    preview_bytes: Option<crate::OrOff<usize>>,
    transfer_preview: Option<bool>,
    options_ttl_secs: Option<crate::OrOff<u32>>,
    infection_header: Option<InfectionHeader>,
    services: Option<Vec<String>>,
}

impl Endpoint {
    /// Parse one endpoint.
    ///
    /// A missing scheme means `clamd`, because that is the protocol exav
    /// answered before it answered any other and the one a bare `host:port` in
    /// an existing deployment means. A value beginning `/` is a Unix socket
    /// path; anything else is `host:port`, optionally followed by `/<service>`
    /// for ICAP. That rule needs no third spelling and cannot be ambiguous: a
    /// filesystem path and a host:port pair have disjoint first characters, so
    /// the leading `/` decides before any `/` inside can matter.
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty address".to_string());
        }
        let (proto, rest) = match s.split_once("://") {
            Some((scheme, rest)) => (Proto::parse(scheme)?, rest),
            None => (Proto::Clamd, s),
        };
        let (rest, query) = match rest.split_once('?') {
            Some((r, q)) => (r, Some(q)),
            None => (rest, None),
        };
        if rest.is_empty() {
            return Err(format!("`{s}` names a protocol but no address"));
        }
        let opts = parse_query(query, s)?;
        let (addr, path) = if rest.starts_with('/') {
            // Every `/` belongs to the socket path: a filesystem path is not a
            // URL, and splitting one would name a directory as a service.
            (
                Addr::Unix {
                    path: PathBuf::from(rest),
                    mode: opts.mode,
                },
                None,
            )
        } else {
            if opts.mode.is_some() {
                return Err(format!(
                    "`{s}`: `mode` sets the permissions of a socket file, and a host:port \
                     listener has none: restrict it with the bind address and a firewall"
                ));
            }
            let (hostport, path) = match rest.split_once('/') {
                Some((hostport, path)) => (hostport, Some(path)),
                None => (rest, None),
            };
            (Addr::Tcp(check_host_port(hostport, s)?), path)
        };
        // The ICAP server binds a TCP listener; RFC 3507 has no Unix-socket
        // form, and a proxy has no way to reach one. Refused rather than bound
        // somewhere the client cannot find it.
        if proto == Proto::Icap && matches!(addr, Addr::Unix { .. }) {
            return Err(format!(
                "`{s}`: ICAP is a TCP protocol; give it a host:port"
            ));
        }
        if proto == Proto::Clamd {
            for (set, key) in [
                (opts.max_requests.is_some(), "max-requests"),
                (opts.max_header_bytes.is_some(), "max-header-bytes"),
            ] {
                if set {
                    return Err(format!(
                        "`{s}`: {key} bounds an ICAP request, and the clamd protocol has none"
                    ));
                }
            }
        }
        let services = resolve_services(proto, path, opts.services, s)?;
        let e = Self {
            proto,
            addr,
            max_connections: opts.max_connections,
            idle_secs: opts.idle_secs,
            session_secs: opts.session_secs,
            reply_secs: opts.reply_secs,
            request_secs: opts.request_secs,
            max_requests: opts.max_requests,
            max_header_bytes: opts.max_header_bytes,
            preview_bytes: opts.preview_bytes,
            transfer_preview: opts.transfer_preview,
            options_ttl_secs: opts.options_ttl_secs,
            infection_header: opts.infection_header,
            services,
        };
        if proto == Proto::Clamd
            && let Some(key) = e.icap_service_options().first()
        {
            return Err(format!(
                "`{s}`: {key} sets what an ICAP service answers, and the clamd protocol has no \
                 such answer"
            ));
        }
        Ok(e)
    }
}

/// A listener needs a port, so `host` alone is refused rather than carried to a
/// bind that fails with `invalid socket address`.
///
/// This also catches the one mistake the comma grammar makes reachable.
/// `--listen` separates addresses with commas and the argument parser splits on
/// them before this ever runs, so `?service=one,two` arrives as two values:
/// `icap://h:1344?service=one` and a bare `two`. Both would otherwise look like
/// addresses, and exav would bind an ICAP listener answering on the wrong set
/// plus a clamd listener on a host called `two`. Requiring a port turns that
/// into an error that names the real problem.
fn check_host_port(hostport: &str, whole: &str) -> Result<String, String> {
    if hostport.contains(':') {
        return Ok(hostport.to_string());
    }
    Err(format!(
        "`{whole}`: `{hostport}` has no port, so nothing can be bound to it. If you \
         meant several ICAP services, a comma separates addresses rather than names: \
         repeat the key instead, `?service=…&service=…`"
    ))
}

/// Reconcile the two ways an ICAP service can be named: the URL path, and
/// `?service=`.
///
/// Giving both is refused rather than resolved. They are two spellings of one
/// setting, and picking a winner means the losing half sits on the command line
/// looking like it is in force, the failure this whole address grammar exists
/// to remove.
fn resolve_services(
    proto: Proto,
    path: Option<&str>,
    query: Option<Vec<String>>,
    whole: &str,
) -> Result<Vec<String>, String> {
    // A service on a clamd address is a mistake with a plausible cause: an ICAP
    // URL pasted under the wrong scheme. Say which protocol has services.
    // Refused in either spelling: accepting `?service=` here and dropping it
    // would leave the operator a listener answering on names they configured
    // and a command line that says otherwise.
    if proto == Proto::Clamd && (path.is_some() || query.is_some()) {
        let given = if path.is_some() {
            "a path"
        } else {
            "`service=`"
        };
        return Err(format!(
            "`{whole}`: the clamd protocol has no services, so {given} means nothing here \
             (an `icap://` address is the one that takes `/<service>`)"
        ));
    }
    match (path, query) {
        (Some(_), Some(_)) => Err(format!(
            "`{whole}`: the service is named twice, by the path and by `service=`; give one"
        )),
        (Some(p), None) => Ok(vec![service_name(p, whole)?]),
        (None, Some(list)) => Ok(list),
        (None, None) => Ok(Vec::new()),
    }
}

/// One service name out of a URL path.
///
/// A path names exactly one, because that is what a proxy's ICAP URL carries.
/// A comma in it is an operator reaching for a list, so it is answered with the
/// spelling that takes one rather than accepted as a service whose name has a
/// comma in it.
fn service_name(path: &str, whole: &str) -> Result<String, String> {
    if path.is_empty() {
        return Err(format!(
            "`{whole}`: a trailing `/` names no service; drop it to answer on the \
             default set, or give a name"
        ));
    }
    if path.contains(',') {
        let repeated = path
            .split(',')
            .map(|n| format!("service={}", n.trim()))
            .collect::<Vec<_>>()
            .join("&");
        return Err(format!(
            "`{whole}`: a path names one service; for several, use `?{repeated}`"
        ));
    }
    if path.contains('/') {
        return Err(format!(
            "`{whole}`: a service name is one path segment, and `{path}` has a `/` in it"
        ));
    }
    Ok(path.to_string())
}

/// Parse the `?…` options of an address. An unknown key is an error rather than
/// an ignored word, because a setting that parses and does nothing is one an
/// operator believes is in force.
fn parse_query(query: Option<&str>, whole: &str) -> Result<Options, String> {
    let mut opts = Options::default();
    let Some(q) = query else { return Ok(opts) };
    for item in q.split('&').filter(|i| !i.is_empty()) {
        let (k, v) = item
            .split_once('=')
            .ok_or_else(|| format!("`{whole}`: `{item}` is not a `key=value` option"))?;
        match k {
            "mode" => opts.mode = Some(parse_mode(v, whole)?),
            "max-connections" => opts.max_connections = Some(parse_max_connections(v, whole)?),
            "idle-secs" => opts.idle_secs = Some(parse_idle_secs(v, whole)?),
            "session-secs" => opts.session_secs = Some(parse_session_secs(v, whole)?),
            "reply-secs" => opts.reply_secs = Some(parse_reply_secs(v, whole)?),
            "request-secs" => opts.request_secs = Some(parse_or_off(v, whole, "request-secs=600")?),
            "max-requests" => opts.max_requests = Some(parse_or_off(v, whole, "max-requests=100")?),
            "max-header-bytes" => opts.max_header_bytes = Some(parse_header_bytes(v, whole)?),
            "preview-bytes" => {
                opts.preview_bytes = Some(
                    crate::parse_size_or_omit(v)
                        .map_err(|e| format!("`{whole}`: preview-bytes: {e}"))?,
                );
            }
            "transfer-preview" => {
                opts.transfer_preview = Some(parse_transfer_preview(v, whole)?);
            }
            "options-ttl-secs" => {
                opts.options_ttl_secs = Some(
                    crate::parse_secs_or_omit(v)
                        .map_err(|e| format!("`{whole}`: options-ttl-secs: {e}"))?,
                );
            }
            "infection-header" => {
                opts.infection_header = Some(
                    InfectionHeader::parse(v)
                        .map_err(|e| format!("`{whole}`: infection-header: {e}"))?,
                );
            }
            // Singular, and repeated rather than replaced: each occurrence adds
            // one name, so the key describes its own value. `services=a` reading
            // as one name would be a plural that never holds a list.
            "service" => opts
                .services
                .get_or_insert_with(Vec::new)
                .push(parse_service(v, whole)?),
            other => {
                return Err(format!(
                    "`{whole}`: unknown address option `{other}` (known: mode, \
                     max-connections, idle-secs, session-secs, reply-secs, request-secs, \
                     max-requests, max-header-bytes, preview-bytes, transfer-preview, \
                     options-ttl-secs, infection-header, service)"
                ));
            }
        }
    }
    Ok(opts)
}

/// One more ICAP service name to answer on, from a `service=` key.
///
/// The escape hatch from the path form, for the one deployment shape the path
/// cannot express: two proxies whose configurations disagree about which name to
/// use, pointed at one exav. Repeat the key for each:
/// `?service=avscan&service=srv_clamav`.
///
/// A comma-separated `service=a,b` cannot do it: `--listen` separates
/// *addresses* with a comma, so it would end this address before this parser
/// ever saw it. One separator per level (commas between addresses, `&` between
/// one address's options), which leaves each key naming exactly one value.
fn parse_service(v: &str, whole: &str) -> Result<String, String> {
    let name = v.trim();
    if name.is_empty() {
        return Err(format!(
            "`{whole}`: `service=` names none; drop it to answer on the default set"
        ));
    }
    if name.contains(',') {
        return Err(format!(
            "`{whole}`: a comma separates addresses, not service names; repeat the key \
             instead: `?service=…&service=…`"
        ));
    }
    if name.contains('/') {
        return Err(format!(
            "`{whole}`: a service name is one path segment, and `{name}` has a `/` in it"
        ));
    }
    Ok(name.to_string())
}

/// `*` or `off`. RFC 3507 asks that one `Transfer-*` header hold `*`, and
/// `Transfer-Preview` is the only one exav sends, so a list of extensions
/// would break that rule or repeat what `*` already says.
fn parse_transfer_preview(v: &str, whole: &str) -> Result<bool, String> {
    match v.trim() {
        "*" => Ok(true),
        v if v.eq_ignore_ascii_case("off") => Ok(false),
        _ => Err(format!(
            "`{whole}`: transfer-preview is `*` (preview every object) or `off`: exav \
             sends no other Transfer-* header, and RFC 3507 asks that one of them hold `*`"
        )),
    }
}

/// Concurrent connections a listener accepts. `0` is refused rather than read as
/// "no limit": a listener that accepts nothing is a scanner that answers nothing,
/// and every other `0` in exav's settings means the opposite.
fn parse_max_connections(v: &str, whole: &str) -> Result<usize, String> {
    match v.trim().parse::<usize>() {
        Ok(0) | Err(_) => Err(format!(
            "`{whole}`: max-connections must be a positive number of connections, \
             e.g. max-connections=200"
        )),
        Ok(n) => Ok(n),
    }
}

/// The most seconds a connection waits for its client. No `off`, and no `0`:
/// without it a client that sends nothing keeps its connection for good.
fn parse_idle_secs(v: &str, whole: &str) -> Result<u64, String> {
    positive_secs(v, whole, "idle-secs=120", "")
}

/// The most seconds a connection stays open. Absent means no limit; `0` and
/// `off` are refused, as a limit that is not one would be read as a short one.
fn parse_session_secs(v: &str, whole: &str) -> Result<u64, String> {
    positive_secs(v, whole, "session-secs=3600", "; leave it out for no limit")
}

/// The most seconds the writes of one reply may wait for the client. Absent
/// means no limit; `0` and `off` are refused, as for [`parse_session_secs`].
fn parse_reply_secs(v: &str, whole: &str) -> Result<u64, String> {
    positive_secs(v, whole, "reply-secs=60", "; leave it out for no limit")
}

/// A count or a number of seconds for the option `example` shows, with a
/// default: `off` or `0` is no limit, as for the flags.
fn parse_or_off(v: &str, whole: &str, example: &str) -> Result<u64, String> {
    let v = v.trim();
    if v.eq_ignore_ascii_case("off") {
        return Ok(0);
    }
    v.parse::<u64>().map_err(|_| {
        let key = example.split('=').next().unwrap_or(example);
        format!("`{whole}`: {key} must be a number or `off`, e.g. {example}")
    })
}

/// The largest ICAP request head: a size of at least 1K, no `off`, since it is
/// what stops a client that sends header bytes forever.
fn parse_header_bytes(v: &str, whole: &str) -> Result<usize, String> {
    let n =
        crate::parse_size_not_off(v).map_err(|e| format!("`{whole}`: max-header-bytes: {e}"))?;
    if n < 1024 {
        return Err(format!(
            "`{whole}`: max-header-bytes below 1K fits no ICAP request's headers"
        ));
    }
    usize::try_from(n).map_err(|_| format!("`{whole}`: max-header-bytes is too large"))
}

/// A positive number of seconds for the option `example` shows, `tail` added
/// to the error.
fn positive_secs(v: &str, whole: &str, example: &str, tail: &str) -> Result<u64, String> {
    let key = example.split('=').next().unwrap_or(example);
    match v.trim().parse::<u64>() {
        Ok(0) | Err(_) => Err(format!(
            "`{whole}`: {key} must be a positive number of seconds, e.g. {example}{tail}"
        )),
        Ok(n) => Ok(n),
    }
}

/// Permission bits in octal, the way an operator writes them (`660`, `666`).
fn parse_mode(v: &str, whole: &str) -> Result<u32, String> {
    let bad = || format!("`{whole}`: mode must be octal permission bits, e.g. mode=660");
    let mode = u32::from_str_radix(v.trim(), 8).map_err(|_| bad())?;
    if mode > 0o777 {
        return Err(format!(
            "`{whole}`: mode {v} is out of range; give the nine permission bits, 000 to 777"
        ));
    }
    // Connecting to a Unix socket takes write permission on it, so a mode that
    // grants write to nobody produces a daemon no client can reach. That is not
    // a tightening, it is an outage with a listening socket in front of it.
    if mode & 0o222 == 0 {
        return Err(format!(
            "`{whole}`: mode {v} grants write permission to nobody, so no client could \
             connect; a client needs write access to the socket"
        ));
    }
    Ok(mode)
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p = self.proto.as_str();
        let mut sep = '?';
        match &self.addr {
            Addr::Tcp(a) => {
                write!(f, "{p}://{a}")?;
                // One service goes back in the path it came from, so what `-v`
                // prints is the URL a proxy is pointed at. Several cannot, and
                // take the option that spells a list.
                if let [only] = self.services.as_slice() {
                    write!(f, "/{only}")?;
                } else {
                    for name in &self.services {
                        write!(f, "{sep}service={name}")?;
                        sep = '&';
                    }
                }
            }
            Addr::Unix { path, mode } => {
                write!(f, "{p}://{}", path.display())?;
                if let Some(m) = mode {
                    write!(f, "?mode={m:o}")?;
                    sep = '&';
                }
            }
        }
        if let Some(n) = self.max_connections {
            write!(f, "{sep}max-connections={n}")?;
            sep = '&';
        }
        if let Some(n) = self.idle_secs {
            write!(f, "{sep}idle-secs={n}")?;
            sep = '&';
        }
        if let Some(n) = self.session_secs {
            write!(f, "{sep}session-secs={n}")?;
            sep = '&';
        }
        if let Some(n) = self.reply_secs {
            write!(f, "{sep}reply-secs={n}")?;
            sep = '&';
        }
        let or_off = |n: u64| {
            if n == 0 {
                "off".to_string()
            } else {
                n.to_string()
            }
        };
        if let Some(n) = self.request_secs {
            write!(f, "{sep}request-secs={}", or_off(n))?;
            sep = '&';
        }
        if let Some(n) = self.max_requests {
            write!(f, "{sep}max-requests={}", or_off(n))?;
            sep = '&';
        }
        if let Some(n) = self.max_header_bytes {
            write!(f, "{sep}max-header-bytes={n}")?;
            sep = '&';
        }
        let shown = |v: Option<String>| v.unwrap_or_else(|| "off".to_string());
        if let Some(n) = self.preview_bytes {
            let n = shown(n.value().map(|n| n.to_string()));
            write!(f, "{sep}preview-bytes={n}")?;
            sep = '&';
        }
        if let Some(on) = self.transfer_preview {
            write!(f, "{sep}transfer-preview={}", if on { "*" } else { "off" })?;
            sep = '&';
        }
        if let Some(n) = self.options_ttl_secs {
            let n = shown(n.value().map(|n| n.to_string()));
            write!(f, "{sep}options-ttl-secs={n}")?;
            sep = '&';
        }
        if let Some(h) = self.infection_header {
            write!(f, "{sep}infection-header={}", h.as_str())?;
        }
        Ok(())
    }
}

/// Parse every `--listen` value, refusing a set that cannot all be bound.
///
/// Every address is served, each with the options on its own address, so a
/// protocol can be given any number of times. The same socket given twice is
/// refused (see [`Addr::identity`]).
///
/// An empty value names no listener rather than being an error, because
/// `EXAV_LISTEN=` is the only way to switch off a listener an image's `ENV` set:
/// a container runtime can override a variable and cannot unset one. Refusing it
/// would leave the published image's default address unremovable from the
/// environment, which is where a container is configured.
pub(crate) fn listeners(values: &[String]) -> Result<Vec<Endpoint>, String> {
    listeners_of("--listen", values)
}

/// [`listeners`] for the flag `flag`, which the errors name.
pub(crate) fn listeners_of(flag: &str, values: &[String]) -> Result<Vec<Endpoint>, String> {
    let mut out: Vec<Endpoint> = Vec::new();
    for v in values.iter().filter(|v| !v.trim().is_empty()) {
        let e = Endpoint::parse(v)?;
        // One socket given twice is a configuration with a silent loser: for a
        // Unix path the second bind replaces the first socket, so the options
        // of one address serve while both appear in the command line.
        if let Some(id) = e.addr.identity()
            && let Some(prev) = out.iter().find(|p| p.addr.identity().as_ref() == Some(&id))
        {
            return Err(format!(
                "{flag} {prev} and {flag} {e} are the same socket; give it once"
            ));
        }
        out.push(e);
    }
    Ok(out)
}

/// Refuses a socket named both in `--listen` and in `--listen-health`: for a
/// Unix path the second bind replaces the first one's socket, so one protocol
/// would serve under the other's address.
pub(crate) fn apart(listen: &[Endpoint], health: &[Endpoint]) -> Result<(), String> {
    for h in health {
        if let Some(id) = h.addr.identity()
            && let Some(l) = listen
                .iter()
                .find(|l| l.addr.identity().as_ref() == Some(&id))
        {
            return Err(format!(
                "--listen {l} and --listen-health {h} are the same socket; give each its own"
            ));
        }
    }
    Ok(())
}

/// [`listeners_of`] for `--listen-health`, which reads `?mode=`,
/// `?max-connections=` and `?idle-secs=` only: an option it would not read is
/// refused, as an unknown key is.
pub(crate) fn health_listeners_of(values: &[String]) -> Result<Vec<Endpoint>, String> {
    let out = listeners_of("--listen-health", values)?;
    for e in &out {
        let mut unread: Vec<&str> = [
            (!e.services.is_empty(), "service"),
            (e.session_secs.is_some(), "session-secs"),
            (e.reply_secs.is_some(), "reply-secs"),
            (e.request_secs.is_some(), "request-secs"),
            (e.max_requests.is_some(), "max-requests"),
            (e.max_header_bytes.is_some(), "max-header-bytes"),
        ]
        .into_iter()
        .filter_map(|(set, key)| set.then_some(key))
        .collect();
        // Its OPTIONS answer is fixed, and it blocks nothing.
        unread.extend(e.icap_service_options());
        if !unread.is_empty() {
            return Err(format!(
                "`{e}`: a health address answers PING and OPTIONS and nothing else, \
                 so {} means nothing there",
                unread.join(", ")
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> Endpoint {
        Endpoint::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn a_scheme_names_the_protocol() {
        assert_eq!(ep("clamd://0.0.0.0:3310").proto, Proto::Clamd);
        assert_eq!(ep("icap://0.0.0.0:1344").proto, Proto::Icap);
        assert_eq!(ep("ICAP://0.0.0.0:1344").proto, Proto::Icap);
    }

    #[test]
    fn no_scheme_means_clamd() {
        // The protocol exav answered first, and what a bare host:port in an
        // existing deployment already means.
        assert_eq!(ep("0.0.0.0:3310").proto, Proto::Clamd);
        assert_eq!(ep("/var/run/exav.sock").proto, Proto::Clamd);
    }

    #[test]
    fn a_leading_slash_is_a_socket_path() {
        let unix = |p: &str, mode| Addr::Unix {
            path: PathBuf::from(p),
            mode,
        };
        assert_eq!(
            ep("clamd:///var/run/exav.sock").addr,
            unix("/var/run/exav.sock", None)
        );
        assert_eq!(
            ep("/var/run/exav.sock").addr,
            unix("/var/run/exav.sock", None)
        );
        assert_eq!(
            ep("127.0.0.1:3310").addr,
            Addr::Tcp("127.0.0.1:3310".to_string())
        );
    }

    #[test]
    fn a_socket_carries_its_own_permissions() {
        // The mode belongs to this socket, so it travels with it. A flag of its
        // own would take three checks to establish that it is being applied to a
        // Unix clamd listener at all; here that is the only thing it can be
        // attached to.
        assert_eq!(
            ep("clamd:///run/x.sock?mode=660").addr,
            Addr::Unix {
                path: PathBuf::from("/run/x.sock"),
                mode: Some(0o660)
            }
        );
        assert_eq!(
            ep("/run/x.sock?mode=666").to_string(),
            "clamd:///run/x.sock?mode=666"
        );
    }

    #[test]
    fn a_listener_carries_its_own_connection_cap() {
        // It bounds *this* listener, so it travels with it, and it applies to
        // either protocol and either kind of socket, which is exactly what a
        // per-protocol flag could not express without one flag per protocol.
        assert_eq!(
            ep("icap://0.0.0.0:1344?max-connections=200").max_connections,
            Some(200)
        );
        assert_eq!(
            ep("/run/x.sock?mode=660&max-connections=8").max_connections,
            Some(8)
        );
        assert_eq!(ep("0.0.0.0:3310").max_connections, None);
        // Round-trips through Display with both options, in the order they are
        // written, so `-v` prints something that can be pasted back.
        assert_eq!(
            ep("/run/x.sock?mode=660&max-connections=8").to_string(),
            "clamd:///run/x.sock?mode=660&max-connections=8"
        );
        assert_eq!(
            ep("icap://h:1?max-connections=2").to_string(),
            "icap://h:1?max-connections=2"
        );
        // `0` accepts nothing, which is a listening socket that answers no
        // client. Every other `0` in exav's settings means "no limit", so this
        // one is refused rather than given the opposite meaning.
        for bad in [
            "0.0.0.0:3310?max-connections=0",
            "0.0.0.0:3310?max-connections=-1",
            "0.0.0.0:3310?max-connections=lots",
            "0.0.0.0:3310?max-connections=",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn a_listener_carries_its_idle_wait() {
        assert_eq!(ep("0.0.0.0:3310?idle-secs=30").idle_secs, Some(30));
        assert_eq!(ep("/run/x.sock?idle-secs=5").idle_secs, Some(5));
        assert_eq!(ep("icap://0.0.0.0:1344?idle-secs=30").idle_secs, Some(30));
        assert_eq!(ep("0.0.0.0:3310").idle_secs, None);
        assert_eq!(
            ep("/run/x.sock?mode=660&max-connections=8&idle-secs=30").to_string(),
            "clamd:///run/x.sock?mode=660&max-connections=8&idle-secs=30"
        );
        assert_eq!(ep("h:1?idle-secs=9").to_string(), "clamd://h:1?idle-secs=9");
        assert_eq!(ep("h:1?idle-secs=9").server_side_options(), ["idle-secs"]);
        // No `0` and no `off`: a client that sends nothing would keep its
        // connection for good.
        for bad in [
            "0.0.0.0:3310?idle-secs=0",
            "0.0.0.0:3310?idle-secs=off",
            "0.0.0.0:3310?idle-secs=-1",
            "0.0.0.0:3310?idle-secs=",
            "icap://0.0.0.0:1344?idle-secs=0",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn a_listener_carries_its_lifetime_and_reply_budget() {
        assert_eq!(ep("0.0.0.0:3310?session-secs=60").session_secs, Some(60));
        assert_eq!(ep("/run/x.sock?reply-secs=5").reply_secs, Some(5));
        assert_eq!(
            ep("icap://0.0.0.0:1344?session-secs=60&reply-secs=5").session_secs,
            Some(60)
        );
        assert_eq!(
            ep("icap://0.0.0.0:1344?session-secs=60&reply-secs=5").reply_secs,
            Some(5)
        );
        // Off when absent.
        let plain = ep("0.0.0.0:3310");
        assert_eq!((plain.session_secs, plain.reply_secs), (None, None));
        assert_eq!(
            ep("/run/x.sock?reply-secs=5&mode=660&session-secs=60&idle-secs=30").to_string(),
            "clamd:///run/x.sock?mode=660&idle-secs=30&session-secs=60&reply-secs=5"
        );
        assert_eq!(
            ep("h:1?session-secs=9").to_string(),
            "clamd://h:1?session-secs=9"
        );
        assert_eq!(
            ep("h:1?reply-secs=9").to_string(),
            "clamd://h:1?reply-secs=9"
        );
        // A `--connect` client has neither.
        assert_eq!(
            ep("h:1?session-secs=9&reply-secs=9").server_side_options(),
            ["session-secs", "reply-secs"]
        );
        // No `0`, no `off`: leaving the key out is how to have no limit.
        for key in ["session-secs", "reply-secs"] {
            for value in ["0", "off", "-1", "", "soon", "1.5"] {
                for scheme in ["", "icap://"] {
                    let bad = format!("{scheme}0.0.0.0:3310?{key}={value}");
                    let e = Endpoint::parse(&bad).unwrap_err();
                    assert!(e.contains(key) && e.contains("positive"), "{bad}: {e}");
                }
            }
        }
    }

    /// A health address reads its mode, connections and idle time; what it
    /// would not read is refused, not kept and ignored.
    #[test]
    fn a_health_address_refuses_what_it_does_not_read() {
        let health = |v: &str| health_listeners_of(&[v.to_string()]);
        for ok in [
            "clamd://127.0.0.1:3311?max-connections=8&idle-secs=5",
            "/run/h.sock?mode=660",
            "icap://127.0.0.1:1345",
        ] {
            assert!(health(ok).is_ok(), "{ok}");
        }
        for (bad, key) in [
            ("icap://127.0.0.1:1345/avscan", "service"),
            ("icap://127.0.0.1:1345?service=a", "service"),
            ("clamd://127.0.0.1:3311?session-secs=60", "session-secs"),
            ("clamd://127.0.0.1:3311?reply-secs=5", "reply-secs"),
            ("clamd://127.0.0.1:3311?request-secs=5", "request-secs"),
            ("icap://127.0.0.1:1345?max-requests=5", "max-requests"),
            (
                "icap://127.0.0.1:1345?max-header-bytes=8K",
                "max-header-bytes",
            ),
            ("icap://127.0.0.1:1345?preview-bytes=0", "preview-bytes"),
            (
                "icap://127.0.0.1:1345?transfer-preview=off",
                "transfer-preview",
            ),
            (
                "icap://127.0.0.1:1345?options-ttl-secs=9",
                "options-ttl-secs",
            ),
            (
                "icap://127.0.0.1:1345?infection-header=blocks",
                "infection-header",
            ),
        ] {
            let e = health(bad).unwrap_err();
            assert!(e.contains(key) && e.contains("health"), "{bad}: {e}");
        }
    }

    /// What an ICAP service answers: a default when absent, `0` and `off`
    /// apart where both mean something, and refused on a clamd address.
    #[test]
    fn a_listener_carries_what_its_icap_service_answers() {
        use crate::OrOff;
        let e = ep("icap://h:1?preview-bytes=1K&transfer-preview=off\
                    &options-ttl-secs=0&infection-header=detections");
        assert_eq!(e.preview_bytes, Some(OrOff::On(1024)));
        assert_eq!(e.transfer_preview, Some(false));
        assert_eq!(e.options_ttl_secs, Some(OrOff::On(0)));
        assert_eq!(e.infection_header, Some(InfectionHeader::Detections));
        assert_eq!(
            e.to_string(),
            "icap://h:1?preview-bytes=1024&transfer-preview=off&options-ttl-secs=0\
             &infection-header=detections"
        );
        assert_eq!(
            e.server_side_options(),
            [
                "preview-bytes",
                "transfer-preview",
                "options-ttl-secs",
                "infection-header"
            ]
        );
        let e = ep("icap://h:1?preview-bytes=off&transfer-preview=*&options-ttl-secs=off");
        assert_eq!(e.preview_bytes, Some(OrOff::Off));
        assert_eq!(e.transfer_preview, Some(true));
        assert_eq!(e.options_ttl_secs, Some(OrOff::Off));
        assert_eq!(
            e.to_string(),
            "icap://h:1?preview-bytes=off&transfer-preview=*&options-ttl-secs=off"
        );
        let e = ep("icap://h:1");
        assert!(e.preview_bytes.is_none() && e.transfer_preview.is_none());
        assert!(e.options_ttl_secs.is_none() && e.infection_header.is_none());
        for (bad, says) in [
            ("icap://h:1?preview-bytes=lots", "preview-bytes"),
            ("icap://h:1?transfer-preview=exe", "RFC 3507"),
            ("icap://h:1?transfer-preview=", "transfer-preview"),
            ("icap://h:1?options-ttl-secs=-1", "options-ttl-secs"),
            ("icap://h:1?infection-header=sometimes", "infection-header"),
            ("h:1?preview-bytes=0", "ICAP"),
            ("clamd://h:1?transfer-preview=off", "ICAP"),
            ("/run/x.sock?options-ttl-secs=9", "ICAP"),
            ("h:1?infection-header=blocks", "ICAP"),
        ] {
            let e = Endpoint::parse(bad).unwrap_err();
            assert!(e.contains(says), "{bad}: {e}");
        }
    }

    /// The time a request has to arrive, on either protocol, and the two
    /// bounds of an ICAP connection: a default when absent, `off` where no
    /// limit is safe.
    #[test]
    fn a_listener_carries_its_request_bounds() {
        assert_eq!(ep("h:1?request-secs=30").request_secs, Some(30));
        assert_eq!(ep("icap://h:1?request-secs=off").request_secs, Some(0));
        assert_eq!(ep("h:1?request-secs=0").request_secs, Some(0));
        assert_eq!(ep("h:1").request_secs, None);
        let e = ep("icap://h:1?max-requests=off&max-header-bytes=8K");
        assert_eq!((e.max_requests, e.max_header_bytes), (Some(0), Some(8192)));
        assert_eq!(
            e.to_string(),
            "icap://h:1?max-requests=off&max-header-bytes=8192"
        );
        assert_eq!(
            ep("h:1?request-secs=off").to_string(),
            "clamd://h:1?request-secs=off"
        );
        assert_eq!(
            ep("icap://h:1?request-secs=9&max-requests=2").server_side_options(),
            ["request-secs", "max-requests"]
        );
        for (bad, says) in [
            ("h:1?request-secs=soon", "request-secs"),
            ("icap://h:1?max-requests=-1", "max-requests"),
            ("icap://h:1?max-header-bytes=100", "1K"),
            ("icap://h:1?max-header-bytes=off", "max-header-bytes"),
            // ICAP's alone: clamd has no request head and no request count.
            ("h:1?max-requests=5", "ICAP"),
            ("/run/x.sock?max-header-bytes=8K", "ICAP"),
        ] {
            let e = Endpoint::parse(bad).unwrap_err();
            assert!(e.contains(says), "{bad}: {e}");
        }
    }

    #[test]
    fn an_unknown_address_option_lists_the_known_ones() {
        let e = Endpoint::parse("h:1?nope=1").unwrap_err();
        for key in [
            "session-secs",
            "reply-secs",
            "request-secs",
            "max-header-bytes",
            "preview-bytes",
            "transfer-preview",
            "options-ttl-secs",
            "infection-header",
        ] {
            assert!(e.contains(key), "{e}");
        }
    }

    #[test]
    fn a_mode_that_cannot_work_is_refused() {
        // Written the way an operator writes one, with or without the leading
        // zero.
        assert_eq!(parse_mode("660", "-").unwrap(), 0o660);
        assert_eq!(parse_mode("0660", "-").unwrap(), 0o660);
        // Octal, in range, and reachable: a socket nobody may write to is an
        // outage with a listening socket in front of it. Nothing here rounds a
        // bad value to a good one: an operator who wrote something else meant
        // something else, and a mode quietly repaired is one they believe is in
        // force.
        for bad in [
            "/run/x.sock?mode=999", // not octal digits
            "/run/x.sock?mode=8",   // ditto
            "/run/x.sock?mode=abc", // not a number
            "/run/x.sock?mode=0o660",
            "/run/x.sock?mode=7777",
            "/run/x.sock?mode=1660", // outside the nine bits (setgid)
            "/run/x.sock?mode=0",    // nothing could connect
            "/run/x.sock?mode=444",  // nor here: connecting takes write permission
            "/run/x.sock?mode=",
            "/run/x.sock?nope=1",
            "/run/x.sock?mode",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad:?} parsed");
        }
        // A TCP listener has no file to permission.
        let e = Endpoint::parse("0.0.0.0:3310?mode=660").unwrap_err();
        assert!(e.contains("host:port"), "{e}");
    }

    #[test]
    fn an_icap_service_is_the_path_of_the_url() {
        // The whole point: what a squid.conf contains is what exav is started
        // with, unchanged.
        let e = ep("icap://scanner:1344/avscan");
        assert_eq!(e.addr, Addr::Tcp("scanner:1344".to_string()));
        assert_eq!(e.services, ["avscan"]);
        // No path keeps the three names a c-icap `virus_scan` answers on, so
        // exav stands in for one without being told which the proxy asks for.
        assert!(ep("icap://scanner:1344").services.is_empty());
        // And it round-trips, so `-v` prints a URL that can be pasted back.
        assert_eq!(e.to_string(), "icap://scanner:1344/avscan");
    }

    #[test]
    fn several_services_take_the_option_that_spells_a_list() {
        let e = ep("icap://h:1344?service=one&service=two");
        assert_eq!(e.services, ["one", "two"]);
        assert_eq!(e.to_string(), "icap://h:1344?service=one&service=two");
        // A comma cannot spell the list: `--listen` separates addresses with
        // one, so it would end this address before this parser saw it. One
        // separator per level (commas between addresses, `&` within one),
        // which is also why the key is singular: each one names a single value.
        let err = Endpoint::parse("icap://h:1344?service=one,two").unwrap_err();
        assert!(err.contains("repeat the key"), "{err}");
        // And the same mistake as the argument parser actually delivers it: the
        // comma has already split the value, so what reaches here is a bare word
        // that would otherwise have been bound as a host.
        let err = listeners(&["icap://h:1344?service=one".into(), "two".into()]).unwrap_err();
        assert!(err.contains("no port") && err.contains("service="), "{err}");
        // A comma in the path is an operator reaching for a list. Answer with
        // the spelling that works, rather than accepting a service whose name
        // contains a comma, which would 404 every request and look right.
        let err = Endpoint::parse("icap://h:1344/one,two").unwrap_err();
        assert!(err.contains("?service=one&service=two"), "{err}");
    }

    #[test]
    fn a_service_named_twice_is_refused() {
        // Two spellings of one setting, disagreeing. Picking a winner leaves the
        // loser on the command line looking like it is in force.
        let err = Endpoint::parse("icap://h:1344/a?service=b").unwrap_err();
        assert!(err.contains("named twice"), "{err}");
    }

    #[test]
    fn a_service_belongs_to_icap_alone() {
        // The likely cause is an ICAP URL pasted under the wrong scheme, so the
        // message names the protocol that has services. Both spellings are
        // refused: accepting the query form and dropping it would leave a
        // listener answering on names the command line does not describe.
        for bad in ["clamd://h:3310/avscan", "clamd://h:3310?service=avscan"] {
            let err = Endpoint::parse(bad).unwrap_err();
            assert!(err.contains("icap://"), "{bad}: {err}");
        }
        // The default form has no scheme at all and must stay unaffected.
        assert!(ep("h:3310").services.is_empty());
        // A socket path is not a URL: every `/` in it belongs to the filesystem,
        // and splitting one would name a directory as a service.
        assert_eq!(
            ep("clamd:///var/run/exav.sock").addr,
            Addr::Unix {
                path: PathBuf::from("/var/run/exav.sock"),
                mode: None
            }
        );
    }

    #[test]
    fn a_service_that_cannot_be_one_is_refused() {
        for bad in [
            "icap://h:1344/",         // a trailing slash names nothing
            "icap://h:1344/a/b",      // a name is one path segment
            "icap://h:1344?service=", // ditto, spelled as an option
            "icap://h:1344?service=a/b",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn icap_over_a_unix_socket_is_refused() {
        // A proxy has no way to reach one, so binding it would be a listener
        // nothing can connect to, worse than an error.
        let e = Endpoint::parse("icap:///var/run/exav.sock").unwrap_err();
        assert!(e.contains("TCP"), "{e}");
    }

    #[test]
    fn a_bad_value_is_refused_rather_than_guessed_at() {
        for bad in ["", "   ", "http://x:80", "clamd://", "gopher://x"] {
            assert!(Endpoint::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn an_empty_value_switches_a_listener_off() {
        // `EXAV_LISTEN=` is how a container removes the address its image's ENV
        // set; a runtime can override a variable but cannot unset one, so an
        // error here would make the image's default permanent.
        assert_eq!(listeners(&["".into()]).unwrap(), vec![]);
        assert_eq!(listeners(&["   ".into()]).unwrap(), vec![]);
        assert_eq!(
            listeners(&["".into(), "icap://0.0.0.0:1344".into()])
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn every_address_of_a_protocol_is_kept_with_its_own_options() {
        let all = listeners(&[
            "/run/a.sock?mode=660".into(),
            "0.0.0.0:3310?max-connections=7".into(),
            "icap://0.0.0.0:1344?service=one".into(),
            "icap://0.0.0.0:1345?service=two".into(),
        ])
        .unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[1].max_connections, Some(7));
        assert_eq!(all[0].max_connections, None);
        assert_eq!(all[2].services, ["one"]);
        assert_eq!(all[3].services, ["two"]);
        // A health address is read the same way.
        let health = health_listeners_of(&["0.0.0.0:3311".into(), "/run/h.sock".into()]).unwrap();
        assert_eq!(health.len(), 2);
    }

    #[test]
    fn one_socket_given_twice_is_refused() {
        let twice = |a: &str, b: &str| listeners(&[a.into(), b.into()]).unwrap_err();
        // Options on either copy do not make them two sockets.
        let e = twice("0.0.0.0:3310", "clamd://0.0.0.0:3310?idle-secs=5");
        assert!(e.contains("same socket"), "{e}");
        // Nor does the protocol: the second bind would fail on the port.
        assert!(twice("0.0.0.0:3310", "icap://0.0.0.0:3310").contains("same socket"));
        // Spellings of one socket: an IPv6 address written long, a port with
        // leading zeros.
        assert!(twice("[::1]:3310", "[0:0:0:0:0:0:0:1]:3310").contains("same socket"));
        assert!(twice("127.0.0.1:3310", "127.0.0.1:03310").contains("same socket"));
        // Spellings of one path: repeated and trailing separators, a `.`, in a
        // directory that does not exist and in one that does.
        for dir in ["/exav-no-such-dir", "/"] {
            let first = format!("{dir}/a.sock");
            for second in [
                format!("{dir}//a.sock"),
                format!("{dir}/./a.sock"),
                format!("{dir}/a.sock//"),
                format!("clamd://{dir}/a.sock?mode=660"),
            ] {
                assert!(twice(&first, &second).contains("same socket"), "{second}");
            }
        }
        // The health flag reads the same rule.
        let e = health_listeners_of(&["/run/h.sock".into(), "/run//h.sock".into()]).unwrap_err();
        assert!(
            e.contains("--listen-health") && e.contains("same socket"),
            "{e}"
        );
        // And one socket in both flags is refused.
        let both = |l: &str, h: &str| {
            apart(
                &listeners(&[l.into()]).unwrap(),
                &health_listeners_of(&[h.into()]).unwrap(),
            )
        };
        let e = both("/run/a.sock", "/run//a.sock").unwrap_err();
        assert!(
            e.contains("--listen-health") && e.contains("same socket"),
            "{e}"
        );
        assert!(both("0.0.0.0:3310", "0.0.0.0:3310").is_err());
        assert!(both("0.0.0.0:3310", "0.0.0.0:3311").is_ok());
        // Other ports and paths, and port 0, which is a free port each time.
        assert!(listeners(&["0.0.0.0:3310".into(), "0.0.0.0:3311".into()]).is_ok());
        assert!(listeners(&["/run/a.sock".into(), "/run/b.sock".into()]).is_ok());
        assert!(listeners(&["127.0.0.1:0".into(), "127.0.0.1:0".into()]).is_ok());
    }

    #[test]
    fn an_endpoint_prints_the_way_it_was_asked_for() {
        assert_eq!(ep("0.0.0.0:3310").to_string(), "clamd://0.0.0.0:3310");
        assert_eq!(ep("icap://0.0.0.0:1344").to_string(), "icap://0.0.0.0:1344");
    }
}
