//! Where exav listens, and what speaks there.
//!
//! One address grammar for both directions and both protocols:
//!
//! ```text
//! clamd://0.0.0.0:3310        the clamd protocol over TCP
//! clamd:///var/run/exav.sock  the clamd protocol over a Unix socket
//! icap://0.0.0.0:1344         ICAP over TCP
//! 0.0.0.0:3310                no scheme — clamd, the older of the two
//! /var/run/exav.sock          no scheme, a path — clamd over a Unix socket
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
            // and the protocol — and it reads as a peer of `icap`, which is also
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

/// A protocol and a place, parsed from one `--listen` / `--connect` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub proto: Proto,
    pub addr: Addr,
    /// Concurrent connections accepted here, from `?max-connections=200`.
    ///
    /// On the address rather than in a flag for the same reason `mode` is: it
    /// bounds *this* listener. A flag would have to name a protocol to apply to,
    /// so two listeners would need two flags — and the one without a flag would
    /// be stuck on a constant nobody could reach.
    pub max_connections: Option<usize>,
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

/// The `?…` options of one address, before they are attached to a place.
#[derive(Default)]
struct Options {
    mode: Option<u32>,
    max_connections: Option<usize>,
    services: Option<Vec<String>>,
}

impl Endpoint {
    /// Parse one endpoint.
    ///
    /// A missing scheme means `clamd`, because that is the protocol exav
    /// answered before it answered any other and the one a bare `host:port` in
    /// an existing deployment means. A value beginning `/` is a Unix socket
    /// path; anything else is `host:port`, optionally followed by `/<service>`
    /// for ICAP. That rule needs no third spelling and cannot be ambiguous — a
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
            // Every `/` belongs to the socket path — a filesystem path is not a
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
                     listener has none — restrict it with the bind address and a firewall"
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
        let services = resolve_services(proto, path, opts.services, s)?;
        Ok(Self {
            proto,
            addr,
            max_connections: opts.max_connections,
            services,
        })
    }
}

/// A listener needs a port, so `host` alone is refused rather than carried to a
/// bind that fails with `invalid socket address`.
///
/// This also catches the one mistake the comma grammar makes reachable.
/// `--listen` separates addresses with commas and the argument parser splits on
/// them before this ever runs, so `?service=one,two` arrives as two values —
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
         meant several ICAP services, a comma separates addresses rather than names \
         — repeat the key instead: `?service=…&service=…`"
    ))
}

/// Reconcile the two ways an ICAP service can be named: the URL path, and
/// `?service=`.
///
/// Giving both is refused rather than resolved. They are two spellings of one
/// setting, and picking a winner means the losing half sits on the command line
/// looking like it is in force — the failure this whole address grammar exists
/// to remove.
fn resolve_services(
    proto: Proto,
    path: Option<&str>,
    query: Option<Vec<String>>,
    whole: &str,
) -> Result<Vec<String>, String> {
    // A path on a clamd address is a mistake with a plausible cause: an ICAP
    // URL pasted under the wrong scheme. Say which protocol has services.
    if proto == Proto::Clamd && path.is_some() {
        return Err(format!(
            "`{whole}`: the clamd protocol has no services, so a path means nothing here \
             — an `icap://` address is the one that takes `/<service>`"
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
            // Singular, and repeated rather than replaced: each occurrence adds
            // one name, so the key describes its own value. `services=a` reading
            // as one name would be a plural that never holds a list.
            "service" => opts
                .services
                .get_or_insert_with(Vec::new)
                .push(parse_service(v, whole)?),
            other => {
                return Err(format!(
                    "`{whole}`: unknown address option `{other}` \
                     (known: mode, max-connections, service)"
                ))
            }
        }
    }
    Ok(opts)
}

/// One more ICAP service name to answer on, from a `service=` key.
///
/// The escape hatch from the path form, for the one deployment shape the path
/// cannot express: two proxies whose configurations disagree about which name to
/// use, pointed at one exav. Repeat the key for each —
/// `?service=avscan&service=srv_clamav`.
///
/// A comma-separated `service=a,b` cannot do it: `--listen` separates
/// *addresses* with a comma, so it would end this address before this parser
/// ever saw it. One separator per level — commas between addresses, `&` between
/// one address's options — which leaves each key naming exactly one value.
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
             instead — `?service=…&service=…`"
        ));
    }
    if name.contains('/') {
        return Err(format!(
            "`{whole}`: a service name is one path segment, and `{name}` has a `/` in it"
        ));
    }
    Ok(name.to_string())
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
        }
        Ok(())
    }
}

/// Parse every `--listen` value, refusing a set that cannot all be bound.
///
/// An empty value names no listener rather than being an error, because
/// `EXAV_LISTEN=` is the only way to switch off a listener an image's `ENV` set:
/// a container runtime can override a variable and cannot unset one. Refusing it
/// would leave the published image's default address unremovable from the
/// environment, which is where a container is configured.
pub(crate) fn listeners(values: &[String]) -> Result<Vec<Endpoint>, String> {
    let mut out: Vec<Endpoint> = Vec::new();
    for v in values.iter().filter(|v| !v.trim().is_empty()) {
        let e = Endpoint::parse(v)?;
        // Two listeners on one protocol is a configuration with a silent loser:
        // whichever the code happens to pick first serves, and the other address
        // is simply never bound while appearing in the command line.
        if let Some(prev) = out.iter().find(|p| p.proto == e.proto) {
            return Err(format!(
                "--listen {e} and --listen {prev} both serve {}; give one",
                e.proto.as_str()
            ));
        }
        out.push(e);
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
        // It bounds *this* listener, so it travels with it — and it applies to
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
    fn a_mode_that_cannot_work_is_refused() {
        // Written the way an operator writes one, with or without the leading
        // zero.
        assert_eq!(parse_mode("660", "-").unwrap(), 0o660);
        assert_eq!(parse_mode("0660", "-").unwrap(), 0o660);
        // Octal, in range, and reachable: a socket nobody may write to is an
        // outage with a listening socket in front of it. Nothing here rounds a
        // bad value to a good one — an operator who wrote something else meant
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
        // separator per level — commas between addresses, `&` within one —
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
        // contains a comma — which would 404 every request and look right.
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
    fn a_path_belongs_to_icap_alone() {
        // The likely cause is an ICAP URL pasted under the wrong scheme, so the
        // message names the protocol that has services.
        let err = Endpoint::parse("clamd://h:3310/avscan").unwrap_err();
        assert!(err.contains("icap://"), "{err}");
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
        // nothing can connect to — worse than an error.
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
    fn one_listener_per_protocol() {
        assert!(listeners(&["clamd://0.0.0.0:3310".into(), "icap://0.0.0.0:1344".into()]).is_ok());
        // Both spellings of the same protocol, so the second would silently
        // never be bound.
        let e = listeners(&["0.0.0.0:3310".into(), "clamd://0.0.0.0:3311".into()]).unwrap_err();
        assert!(e.contains("both serve clamd"), "{e}");
    }

    #[test]
    fn an_endpoint_prints_the_way_it_was_asked_for() {
        assert_eq!(ep("0.0.0.0:3310").to_string(), "clamd://0.0.0.0:3310");
        assert_eq!(ep("icap://0.0.0.0:1344").to_string(), "icap://0.0.0.0:1344");
    }
}
