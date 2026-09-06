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
}

/// The `?…` options of one address, before they are attached to a place.
#[derive(Default)]
struct Options {
    mode: Option<u32>,
    max_connections: Option<usize>,
}

impl Endpoint {
    /// Parse one endpoint.
    ///
    /// A missing scheme means `clamd`, because that is the protocol exav
    /// answered before it answered any other and the one a bare `host:port` in
    /// an existing deployment means. A value beginning `/` is a Unix socket
    /// path; anything else is `host:port`. That rule needs no third spelling and
    /// cannot be ambiguous — a filesystem path and a host:port pair have
    /// disjoint first characters.
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
        let addr = if rest.starts_with('/') {
            Addr::Unix {
                path: PathBuf::from(rest),
                mode: opts.mode,
            }
        } else {
            if opts.mode.is_some() {
                return Err(format!(
                    "`{s}`: `mode` sets the permissions of a socket file, and a host:port \
                     listener has none — restrict it with the bind address and a firewall"
                ));
            }
            Addr::Tcp(rest.to_string())
        };
        // The ICAP server binds a TCP listener; RFC 3507 has no Unix-socket
        // form, and a proxy has no way to reach one. Refused rather than bound
        // somewhere the client cannot find it.
        if proto == Proto::Icap && matches!(addr, Addr::Unix { .. }) {
            return Err(format!(
                "`{s}`: ICAP is a TCP protocol; give it a host:port"
            ));
        }
        Ok(Self {
            proto,
            addr,
            max_connections: opts.max_connections,
        })
    }
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
            other => {
                return Err(format!(
                    "`{whole}`: unknown address option `{other}` \
                     (known: mode, max-connections)"
                ))
            }
        }
    }
    Ok(opts)
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
            Addr::Tcp(a) => write!(f, "{p}://{a}")?,
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
