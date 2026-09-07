//! Runtime configuration for the ICAP server.

use std::time::Duration;

/// The IANA-registered ICAP port, and the port exav binds when ICAP is enabled
/// without an explicit address. Matches `Port 1344` in `c-icap.conf`.
pub(super) const DEFAULT_PORT: u16 = 1344;

/// When a block carries the c-icap `X-Infection-Found` header.
///
/// c-icap's vocabulary has one header for "this object is not OK", and a whole
/// class of ICAP clients decides clean-or-not from that header alone rather than
/// from the response body — a health-check script, a mail gateway, the shell
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
    /// Parse the flag value.
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        match s {
            "blocks" => Ok(Self::Blocks),
            "detections" => Ok(Self::Detections),
            other => Err(format!("expected `blocks` or `detections`, got `{other}`")),
        }
    }
}

/// Everything an operator can tune about the ICAP listener.
///
/// The column on the right of each field names the `c-icap.conf` /
/// `virus_scan.conf` directive it corresponds to, so an existing configuration
/// can be translated across without guessing.
#[derive(Debug, Clone)]
pub(crate) struct IcapConfig {
    /// `host:port` to bind. c-icap `Port`.
    pub listen: String,
    /// Service names this server answers on, i.e. the path in
    /// `icap://host:1344/<service>`. c-icap `Service` + `ServiceAlias`.
    ///
    /// Multiple names are the norm: a c-icap deployment reaches the same
    /// module through its own name and through every alias, and the clients
    /// pointing at those aliases are not going to be reconfigured just because
    /// the server behind them changed.
    pub services: Vec<String>,
    /// Bytes advertised in the `Preview` header of an `OPTIONS` response — how
    /// much of a body a client should send before pausing for a verdict.
    pub preview_size: usize,
    /// Value of the `Transfer-Preview` header in an `OPTIONS` response. `*`
    /// asks the client to preview every object.
    pub transfer_preview: String,
    /// Concurrent connections accepted, and the value advertised as
    /// `Max-Connections`. c-icap `MaxServers` x `ThreadsPerChild`.
    pub max_connections: usize,
    /// Seconds a client may cache the `OPTIONS` answer (`Options-TTL`).
    pub options_ttl: u32,
    /// Requests served on one connection before it is closed. c-icap
    /// `MaxKeepAliveRequests`.
    pub keepalive_requests: u64,
    /// How long a connection may sit without sending anything. c-icap
    /// `KeepAliveTimeout`.
    pub idle_timeout: Duration,
    /// How much of an over-limit body is read and thrown away so that the
    /// stream reaches the next request boundary.
    ///
    /// A verdict is only useful once it is delivered, and answering while the
    /// client is still sending resets the connection with the answer still in
    /// flight. Reading the tail buys delivery, and this bounds what it may
    /// cost. Past it, exav answers and closes: the client sees the block, but
    /// the connection is not reused.
    pub max_drain_bytes: u64,
    /// Ceiling on the ICAP head plus the encapsulated HTTP headers of one
    /// request. Nothing legitimate approaches it; it exists so a client that
    /// opens a connection and streams header bytes forever is cut off.
    pub max_header_bytes: usize,
    /// Value of the `Service` header in an `OPTIONS` response.
    pub service_label: String,
    /// Which blocks carry `X-Infection-Found`.
    pub infection_header: InfectionHeader,
    /// What becomes of an object exav could not fully examine.
    ///
    /// Not an ICAP setting — `--partial-as` answers the same question for the
    /// CLI's exit code and the daemon's reply — but the listener needs it in
    /// hand to shape a response, and to say at startup that it is running that
    /// way.
    ///
    /// The nearest c-icap behaviour is unconditional: `virus_scan.MaxObjectSize`
    /// passes an oversized object, and ClamAV calls an encrypted archive clean
    /// unless asked not to. exav starts from the opposite end and makes each of
    /// those a named, logged choice.
    pub partial_as: crate::policy::PartialAs,
}

impl Default for IcapConfig {
    fn default() -> Self {
        Self {
            listen: format!("0.0.0.0:{DEFAULT_PORT}"),
            // The three names a c-icap deployment of the virus_scan module
            // answers on: the module's own name plus the two aliases in the
            // shipped configuration.
            services: vec![
                "avscan".to_string(),
                "srv_clamav".to_string(),
                "virus_scan".to_string(),
            ],
            preview_size: 4096,
            transfer_preview: "*".to_string(),
            max_connections: 100,
            options_ttl: 3600,
            keepalive_requests: 100,
            idle_timeout: Duration::from_secs(600),
            max_drain_bytes: crate::daemon::MAX_DRAIN_BYTES,
            max_header_bytes: 64 * 1024,
            service_label: format!("exav/{} ICAP service", super::VERSION),
            infection_header: InfectionHeader::default(),
            partial_as: crate::policy::PartialAs::default(),
        }
    }
}

impl IcapConfig {
    /// Whether `name` is one of the configured service names.
    ///
    /// Case-sensitive, like c-icap: a service name is a path, and treating
    /// `/AVSCAN` as `/avscan` would answer on a name no operator configured.
    pub(super) fn serves(&self, name: &str) -> bool {
        self.services.iter().any(|s| s == name)
    }
}

#[cfg(test)]
mod tests {
    use super::InfectionHeader;

    #[test]
    fn the_infection_header_policy_parses_and_defaults_to_blocks() {
        assert_eq!(InfectionHeader::default(), InfectionHeader::Blocks);
        assert_eq!(
            InfectionHeader::parse("blocks").unwrap(),
            InfectionHeader::Blocks
        );
        assert_eq!(
            InfectionHeader::parse("detections").unwrap(),
            InfectionHeader::Detections
        );
        // No case folding and no abbreviations: a misspelling that quietly
        // selected a policy would change what a client is told about an
        // unscannable object.
        for bad in ["Blocks", "detection", "", "all"] {
            assert!(InfectionHeader::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_drain_bound_is_the_one_the_daemon_uses() {
        // One number for "how much of an abandoned body is worth reading to keep
        // the connection usable", not one per listener.
        assert_eq!(
            super::IcapConfig::default().max_drain_bytes,
            crate::daemon::MAX_DRAIN_BYTES
        );
    }
}
