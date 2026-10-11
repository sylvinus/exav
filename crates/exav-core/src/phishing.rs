//! Phishing heuristics (opt-in): flag the classic link-spoofing tricks in
//! HTML/email bodies — the visible text names one domain while the `href` points
//! at another, the real host is hidden behind `user@host` userinfo, or the link
//! resolves to a bare IP under a brand-looking display. A general anchor-analysis
//! technique: parse each `<a>` element, compare the displayed registered domain
//! to the href's, and report the mismatch class. Deliberately conservative — the
//! *display* must itself look like a host/URL, so ordinary "click here" links
//! never trip — and off unless `ScanOptions::alert_phishing` is set.
//!
//! When present, the ClamAV-compatible `.wdb`/`.pdb` databases (on-disk data
//! formats) refine precision: `.wdb` allow-lists legitimate (real, displayed)
//! pairs to suppress false positives, and `.pdb` scopes the spoof check to a set
//! of monitored brands.

/// Longest span one anchor is read over.
const MAX_ANCHOR_SPAN: usize = 8192;

/// Cap on `.wdb` allow-list lookups per document. Each one runs every `X:`
/// regex, and a lookup is made only for a link that would otherwise be
/// reported, so an ordinary document never comes near it.
const MAX_ALLOW_CHECKS: usize = 4096;

/// Serialisable phishing-DB parts for the prebuilt database: `(protected domains,
/// `M:` allow-list host pairs, `X:` allow-list regex source pairs)`. Compiled
/// regexes aren't serialisable, so only the sources travel and are recompiled by
/// [`PhishingDb::from_cache_parts`].
pub type PhishingParts = (Vec<String>, Vec<(String, String)>, Vec<(String, String)>);

/// Phishing databases in the ClamAV `.wdb`/`.pdb` on-disk formats — an allow-list
/// of legitimate (real, displayed) URL pairs and a monitored-brand domain-list.
/// Precision-only: never adds a detection the raw heuristic wouldn't raise.
#[derive(Default, Debug)]
pub struct PhishingDb {
    /// `.pdb` `H:` protected hostnames, stored at registered-domain granularity.
    protected: std::collections::HashSet<String>,
    /// `.wdb` `M:realhost:disphost` literal allow-list pairs (lowercased).
    allow_hosts: Vec<(String, String)>,
    /// `.wdb` `X:realregex:dispregex` full-URL allow-list pattern sources.
    allow_regex_src: Vec<(String, String)>,
    /// Compiled forms of `allow_regex_src`, kept in sync.
    allow_regex: Vec<(regex::Regex, regex::Regex)>,
}

impl PhishingDb {
    /// Merge one `.wdb`/`.pdb`/`.gdb` database's text. `.pdb`/`.gdb` carry
    /// `H:hostname` monitored brands; `.wdb` carries `M:realhost:disphost` literal
    /// pairs and `X:realregex:dispregex` regex pairs. Unknown/unparseable lines
    /// are skipped; a malformed `X:` regex is dropped, not fatal.
    pub fn add_text(&mut self, ext: &str, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match ext {
                "pdb" | "gdb" => {
                    if let Some(host) = line.strip_prefix("H:") {
                        let host = host.trim().to_ascii_lowercase();
                        if !host.is_empty() {
                            self.protected.insert(registered(&host));
                        }
                    }
                }
                "wdb" => {
                    if let Some(rest) = line.strip_prefix("M:") {
                        if let Some((real, disp)) = rest.split_once(':') {
                            self.allow_hosts.push((
                                real.trim().to_ascii_lowercase(),
                                disp.trim().to_ascii_lowercase(),
                            ));
                        }
                    } else if let Some(rest) = line.strip_prefix("X:") {
                        if let Some((real, disp)) = rest.split_once(':') {
                            if let (Ok(re), Ok(rd)) = (compile_pattern(real), compile_pattern(disp))
                            {
                                self.allow_regex.push((re, rd));
                                self.allow_regex_src
                                    .push((real.to_string(), disp.to_string()));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// True if nothing was loaded.
    pub fn is_empty(&self) -> bool {
        self.protected.is_empty() && self.allow_hosts.is_empty() && self.allow_regex_src.is_empty()
    }

    fn has_allow_list(&self) -> bool {
        !self.allow_hosts.is_empty() || !self.allow_regex.is_empty()
    }

    /// Serialisable parts (compiled regexes omitted, rebuilt on load).
    pub fn to_cache_parts(&self) -> PhishingParts {
        (
            self.protected.iter().cloned().collect(),
            self.allow_hosts.clone(),
            self.allow_regex_src.clone(),
        )
    }

    /// Rebuild from the stored parts, recompiling the `X:` regexes.
    pub fn from_cache_parts((protected, allow_hosts, allow_regex_src): PhishingParts) -> Self {
        let mut allow_regex = Vec::new();
        let mut kept = Vec::new();
        for (real, disp) in allow_regex_src {
            if let (Ok(re), Ok(rd)) = (compile_pattern(&real), compile_pattern(&disp)) {
                allow_regex.push((re, rd));
                kept.push((real, disp));
            }
        }
        PhishingDb {
            protected: protected.into_iter().collect(),
            allow_hosts,
            allow_regex_src: kept,
            allow_regex,
        }
    }

    /// A `.pdb` domain-list is loaded → scope the spoof check to its brands.
    fn scoped(&self) -> bool {
        !self.protected.is_empty()
    }

    /// True if `host`'s registered domain is a monitored brand.
    fn is_protected(&self, host: &str) -> bool {
        self.protected.contains(&registered(host))
    }

    /// True if the (real href, displayed) pair is explicitly allow-listed.
    fn allowed(&self, real_url: &str, real_host: &str, display: &str, display_host: &str) -> bool {
        for (real, disp) in &self.allow_hosts {
            if host_suffix(real_host, real) && host_suffix(display_host, disp) {
                return true;
            }
        }
        for (re, rd) in &self.allow_regex {
            if re.is_match(real_url) && rd.is_match(display) {
                return true;
            }
        }
        false
    }
}

/// Compile a `.wdb` `X:` pattern as an anchored, case-insensitive regex over the
/// full string. The pattern is trusted DB content.
fn compile_pattern(pat: &str) -> Result<regex::Regex, regex::Error> {
    regex::RegexBuilder::new(&format!("^(?:{pat})$"))
        .case_insensitive(true)
        .size_limit(1 << 20)
        .build()
}

/// `host` equals `pat` or is a subdomain of it.
fn host_suffix(host: &str, pat: &str) -> bool {
    host == pat || host.strip_suffix(pat).is_some_and(|p| p.ends_with('.'))
}

/// A phishing verdict and its detection name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phish {
    SpoofedDomain,
    CloakedUsername,
    CloakedIp,
    /// The visible text advertises `https://`, the `href` is plain `http://`.
    /// The domains agree, so no other check fires — the lie is about transport,
    /// and transport is what the link is advertising.
    SslSpoof,
}

impl Phish {
    pub fn signature(self) -> &'static str {
        match self {
            Phish::SpoofedDomain => "Heuristics.Phishing.Email.SpoofedDomain",
            Phish::CloakedUsername => "Heuristics.Phishing.Email.Cloaked.Username",
            // ClamAV's name is `Cloaked.NumericIP`, not `Cloaked.IP`.
            Phish::CloakedIp => "Heuristics.Phishing.Email.Cloaked.NumericIP",
            Phish::SslSpoof => "Heuristics.Phishing.Email.SSL-Spoof",
        }
    }
}

/// Scan an HTML/text buffer for a phishing link; consult `db` for allow-listing
/// and brand scoping (`&PhishingDb::default()` = standalone heuristic).
pub fn scan(data: &[u8], db: &PhishingDb) -> Option<Phish> {
    scan_complete(data, db).0
}

/// [`scan`], also saying whether every link was examined: `false` when the
/// allow-list budget ran out before the end of `data`.
pub fn scan_complete(data: &[u8], db: &PhishingDb) -> (Option<Phish>, bool) {
    scan_complete_source(&data, db)
}

/// [`scan_complete`] over an object that need not be held in memory.
pub(crate) fn scan_complete_source(
    data: &dyn crate::byte_source::ByteSource,
    db: &PhishingDb,
) -> (Option<Phish>, bool) {
    let mut allow_checks = 0usize;
    let mut bytes = crate::byte_source::Stepper::new(data);
    let mut next = find_anchor(data, &mut bytes, 0);
    while let Some(start) = next {
        next = find_anchor(data, &mut bytes, start + 3);
        // An anchor is read up to the next one at most, so no byte is read for
        // two anchors and the whole scan stays linear in `data`.
        let end = next
            .unwrap_or(data.len())
            .min(start.saturating_add(MAX_ANCHOR_SPAN));
        let region = latin1(&data.window(start, end - start));
        let region_lc = region.to_ascii_lowercase();
        let Some(href) = extract_href(&region, &region_lc) else {
            continue;
        };
        let display = extract_display(&region, &region_lc);
        let Some(p) = classify(&href, &display, db) else {
            continue;
        };
        if db.has_allow_list() {
            if allow_checks == MAX_ALLOW_CHECKS {
                return (None, false);
            }
            allow_checks += 1;
            if allow_listed(&href, &display, db) {
                continue;
            }
        }
        return (Some(p), true);
    }
    (None, true)
}

/// Offset of the next `<a ` (case-insensitive) at or after `from`. `bytes`
/// reads `data` when it is not held in memory, and is kept across calls so
/// the object is read forward once.
fn find_anchor(
    data: &dyn crate::byte_source::ByteSource,
    bytes: &mut crate::byte_source::Stepper,
    from: usize,
) -> Option<usize> {
    use crate::byte_source::Bytes;
    if let Some(data) = data.as_slice() {
        let hay = data.get(from..)?;
        return memchr::memchr_iter(b'<', hay)
            .find(|&i| matches!(hay.get(i + 1..i + 3), Some([b'a' | b'A', b' '])))
            .map(|i| from + i);
    }
    let n = data.len();
    (from..n).find(|&i| {
        bytes.at(i) == b'<'
            && i + 2 < n
            && matches!(bytes.at(i + 1), b'a' | b'A')
            && bytes.at(i + 2) == b' '
    })
}

/// True if the `.wdb` allow-list covers this (href, display) pair.
fn allow_listed(href: &str, display: &str, db: &PhishingDb) -> bool {
    let Some((_, host)) = split_host(href) else {
        return false;
    };
    let disp_host = display_host(display).unwrap_or_default();
    db.allowed(href, host, display, &disp_host)
}

/// The spoof a link shows, before the `.wdb` allow-list is consulted.
fn classify(href: &str, display: &str, db: &PhishingDb) -> Option<Phish> {
    let (userinfo, host) = split_host(href)?;
    if host.is_empty() {
        return None;
    }
    let disp_host = display_host(display);
    // Userinfo cloak: `http://paypal.com@evil/` — flag only when the userinfo
    // itself looks like a hostname of a different registered domain.
    if let Some(ui) = userinfo {
        if ui.contains('.') && registered(ui) != registered(host) {
            return Some(Phish::CloakedUsername);
        }
    }
    // Raw-IP host under a domain-looking display.
    if is_ipv4(host) {
        if let Some(dh) = &disp_host {
            if !is_ipv4(dh) && dh.contains('.') {
                return Some(Phish::CloakedIp);
            }
        }
        return None;
    }
    // Display names a different registered domain than the href. Checked BEFORE
    // the transport lie below: a link that spoofs the domain *and* downgrades
    // the scheme is a domain spoof, the more specific finding. (Getting this
    // order wrong made a paypal.com-spoofing link report as a mere SSL
    // mismatch — the existing `spoofed_domain` test caught it.)
    if let Some(dh) = &disp_host {
        if !dh.is_empty() && registered(dh) != registered(host) {
            if db.scoped() && !db.is_protected(dh) {
                return None;
            }
            return Some(Phish::SpoofedDomain);
        }
    }
    // Transport lie: the display promises https, the href is plain http, and the
    // domains agree — the one phishing shape where everything except the scheme
    // matches, so no other check can catch it.
    if display
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("https://")
        && href
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("http://")
    {
        return Some(Phish::SslSpoof);
    }
    None
}

/// Value of the `href="…"` attribute in an anchor region.
fn extract_href(region: &str, region_lc: &str) -> Option<String> {
    let at = region_lc.find("href")?;
    let after = region[at + 4..]
        .trim_start()
        .strip_prefix('=')?
        .trim_start();
    let val = if let Some(rest) = after.strip_prefix('"') {
        rest.split('"').next()?
    } else if let Some(rest) = after.strip_prefix('\'') {
        rest.split('\'').next()?
    } else {
        after
            .split(|c: char| c.is_whitespace() || c == '>')
            .next()?
    };
    Some(val.trim().to_string())
}

/// Visible text of an anchor (between `>` and `</a>`), tags stripped.
fn extract_display(region: &str, region_lc: &str) -> String {
    let Some(gt) = region.find('>') else {
        return String::new();
    };
    let inner_start = gt + 1;
    let close = region_lc[inner_start..]
        .find("</a")
        .map(|p| inner_start + p)
        .unwrap_or(region.len());
    let mut out = String::new();
    let mut in_tag = false;
    for c in region[inner_start..close].chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

/// Split an `http(s)` URL into `(userinfo, host)` (port/path removed). Non-http
/// schemes return `None`.
fn split_host(url: &str) -> Option<(Option<&str>, &str)> {
    let rest = strip_http(url.trim())?;
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    let host = match hostport.rfind(':') {
        Some(c)
            if !hostport[c + 1..].is_empty()
                && hostport[c + 1..].bytes().all(|b| b.is_ascii_digit()) =>
        {
            &hostport[..c]
        }
        _ => hostport,
    };
    Some((userinfo, host.trim_end_matches('.')))
}

fn strip_http(url: &str) -> Option<&str> {
    let l = url.to_ascii_lowercase();
    if l.starts_with("http://") {
        Some(&url[7..])
    } else if l.starts_with("https://") {
        Some(&url[8..])
    } else {
        None
    }
}

/// The host named by anchor display text, if it is (or contains) a URL or bare host.
fn display_host(display: &str) -> Option<String> {
    let d = display.trim();
    if let Some((_, h)) = split_host(d) {
        if !h.is_empty() {
            return Some(h.to_ascii_lowercase());
        }
    }
    let token = d
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_start_matches("www.");
    if token.contains('.')
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && token.split('.').count() >= 2
        && token
            .rsplit('.')
            .next()
            .is_some_and(|t| t.len() >= 2 && t.chars().all(|c| c.is_ascii_alphabetic()))
    {
        return Some(token.to_ascii_lowercase());
    }
    None
}

/// Approximate registered domain: the last two DNS labels, lowercased.
fn registered(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = h.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() <= 2 {
        labels.join(".")
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

/// True for a dotted-quad IPv4 literal.
fn is_ipv4(host: &str) -> bool {
    let p: Vec<&str> = host.split('.').collect();
    p.len() == 4
        && p.iter().all(|s| {
            !s.is_empty()
                && s.len() <= 3
                && s.bytes().all(|b| b.is_ascii_digit())
                && s.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

/// Lossless latin-1 view (each byte → U+0000..=U+00FF) for byte-wise text search.
fn latin1(data: &[u8]) -> String {
    data.iter().map(|&b| b as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan0(data: &[u8]) -> Option<Phish> {
        scan(data, &PhishingDb::default())
    }

    #[test]
    fn a_page_read_in_blocks_is_judged_as_in_memory() {
        use crate::byte_source::{BlockCache, CHUNK};
        let benign: &[u8] = br#"<A href="http://example.com/page">example.com</A> "#;
        let spoof: &[u8] =
            br#"<a href="http://evil.example/login">https://www.paypal.com/signin</a>"#;
        for at in [0, CHUNK - 3, CHUNK - 40, 3 * CHUNK + 1] {
            let mut page = Vec::new();
            while page.len() < at {
                page.extend_from_slice(benign);
            }
            page.truncate(at);
            page.extend_from_slice(spoof);
            page.extend_from_slice(&benign.repeat(50));
            let cache =
                BlockCache::with_sizes(std::io::Cursor::new(page.clone()), 61, 4 * 61).unwrap();
            let want = scan_complete(&page, &PhishingDb::default());
            assert_eq!(want.0, Some(Phish::SpoofedDomain), "at {at}");
            assert_eq!(
                scan_complete_source(&cache, &PhishingDb::default()),
                want,
                "at {at}"
            );
        }
    }

    #[test]
    fn spoofed_domain() {
        assert_eq!(
            scan0(br#"<a href="http://evil.example/login">https://www.paypal.com/signin</a>"#),
            Some(Phish::SpoofedDomain)
        );
        assert_eq!(
            scan0(br#"<html><a href="http://secure-update.ru/x">www.bankofamerica.com</a></html>"#),
            Some(Phish::SpoofedDomain)
        );
    }

    #[test]
    fn userinfo_and_ip_cloak() {
        assert_eq!(
            scan0(br#"<a href="http://paypal.com@evil.example/login">Log in to PayPal</a>"#),
            Some(Phish::CloakedUsername)
        );
        assert_eq!(
            scan0(br#"<a href="http://192.0.2.55/paypal/">www.paypal.com</a>"#),
            Some(Phish::CloakedIp)
        );
    }

    #[test]
    fn benign_no_hits() {
        assert_eq!(
            scan0(br#"<a href="http://example.com/page">example.com</a>"#),
            None
        );
        assert_eq!(
            scan0(br#"<a href="http://login.example.com/">www.example.com</a>"#),
            None
        );
        assert_eq!(
            scan0(br#"<a href="http://bob@example.com/">example.com</a>"#),
            None
        );
        assert_eq!(
            scan0(br#"<a href="http://track.example.net/abc">Click here</a>"#),
            None
        );
    }

    #[test]
    fn hostile_no_panic() {
        assert_eq!(scan0(b""), None);
        assert_eq!(scan0(b"<a href=></a><a <a <a"), None);
        let mut d = b"<a ".to_vec();
        d.extend_from_slice(&[0xFFu8; 4100]);
        assert_eq!(scan0(&d), None);
    }

    #[test]
    fn wdb_m_pair_suppresses_spoof() {
        let mut db = PhishingDb::default();
        db.add_text("wdb", "M:info.searscard.com:sears.com\n");
        let html = br#"<a href="http://info.searscard.com/x">sears.com</a>"#;
        assert_eq!(
            scan(html, &PhishingDb::default()),
            Some(Phish::SpoofedDomain)
        );
        assert_eq!(scan(html, &db), None);
    }

    #[test]
    fn wdb_x_regex_suppresses_spoof() {
        let mut db = PhishingDb::default();
        db.add_text(
            "wdb",
            "X:.+\\.etradefinancial\\.com([/?].*)?:(.+\\.)?etrade\\.com([/?].*)?\n",
        );
        let html = br#"<a href="http://email.etradefinancial.com/login">www.etrade.com</a>"#;
        assert_eq!(
            scan(html, &PhishingDb::default()),
            Some(Phish::SpoofedDomain)
        );
        assert_eq!(scan(html, &db), None);
    }

    #[test]
    fn an_anchor_does_not_borrow_the_next_ones_href() {
        // The first anchor has no href. Reading it over a fixed span took the
        // second anchor's href and paired it with the first one's text.
        let html = br#"<a name="top">www.paypal.com</a> <a href="http://evil.example/">here</a>"#;
        assert_eq!(scan0(html), None);
    }

    #[test]
    fn running_out_of_allow_list_checks_is_reported() {
        let mut db = PhishingDb::default();
        db.add_text("wdb", "M:info.searscard.com:sears.com\n");
        let link = br#"<a href="http://info.searscard.com/x">sears.com</a>"#;
        assert_eq!(
            scan_complete(&link.repeat(MAX_ALLOW_CHECKS), &db),
            (None, true)
        );
        assert_eq!(
            scan_complete(&link.repeat(MAX_ALLOW_CHECKS + 1), &db),
            (None, false)
        );
    }

    #[test]
    fn pdb_scopes_to_protected_brands() {
        let mut db = PhishingDb::default();
        db.add_text("pdb", "H:paypal.com\n");
        let hit = br#"<a href="http://evil.example/login">www.paypal.com</a>"#;
        let miss = br#"<a href="http://evil.example/login">www.example.org</a>"#;
        assert_eq!(scan(hit, &db), Some(Phish::SpoofedDomain));
        assert_eq!(scan(miss, &db), None);
        assert_eq!(
            scan(miss, &PhishingDb::default()),
            Some(Phish::SpoofedDomain)
        );
    }

    #[test]
    fn db_parsing_skips_noise() {
        let mut db = PhishingDb::default();
        db.add_text("pdb", "# comment\n\n   \nH:bank.example\n");
        assert!(!db.is_empty());
        assert!(db.is_protected("login.bank.example"));
        assert!(!db.is_protected("bank.other"));
    }
}
