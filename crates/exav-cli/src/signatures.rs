//! The `--auto-update` signature lifecycle: where signatures come from, getting
//! them in place before the first load, and keeping them current afterwards.
//!
//! A scanner is only as good as the database it answers from, so this is a
//! capability a run asks for rather than something a mode switches on. It covers
//! four jobs, each of which is a way a deployment can otherwise end up serving
//! nothing:
//!
//!   * create the signature directory and fetch every configured source before
//!     the database is loaded, so the first request is answered from real
//!     signatures rather than the near-empty baseline;
//!   * where a sidecar owns the directory instead, block for
//!     `--startup-wait-secs` while it fills it;
//!   * re-check the sources every `--update-interval-secs`, floored at a minute,
//!     and reload the served database whenever anything changed;
//!   * pull a prebuilt `.exavdb` over HTTP (`--db-url`) as an alternative to
//!     fetching signature files, with the same change detection and reload.
//!
//! Unix only: the reload it drives belongs to the prefork supervisor, and the
//! fetching half needs a build with `--features http-update`.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::Cli;

/// The shortest interval honoured, however short a one is asked for. A
/// zero-second sleep is not a fast poll — it is a loop with no delay at all,
/// aimed at someone else's servers. A minute between checks is already far more
/// often than any signature feed changes.
const MIN_UPDATE_INTERVAL_SECS: u64 = 60;

/// Seconds between update checks unless `--update-interval-secs` says otherwise
/// — once a day, which is how often the signature feeds actually move.
const DEFAULT_UPDATE_INTERVAL_SECS: u64 = 24 * 3600;

/// Seconds `--auto-update` waits for a sidecar to populate an empty signature
/// directory when no source of its own is configured.
const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 1800;

/// Where a prebuilt database pulled from `--db-url` is written when `-d` names
/// no destination.
#[cfg(feature = "http-update")]
const PULLED_DB_NAME: &str = "remote.exavdb";

/// Seconds between `--db-url` re-checks unless `--update-interval-secs` says
/// otherwise. Five minutes, not the day a signature-file fetch gets: the check
/// is a conditional `HEAD` that transfers nothing when the database has not
/// moved, so the cost of asking often is close to zero.
#[cfg(feature = "http-update")]
const DEFAULT_DB_URL_POLL_SECS: u64 = 300;

/// Expand one `--sig-sources` value into the source URLs it names.
///
/// Three shapes, told apart by the value itself rather than by which flag it
/// arrived on. No privileged "official" source — every URL is fetched the same
/// way:
///
///   `https://host/main.cvd`  an exact source, fetched verbatim
///   `https://host/db/`       a mirror base -> `<base>/{main,daily,bytecode}.cvd`
///   `/etc/exav/sources`      a file of the above, or a `freshclam.conf`
///
/// The trailing slash is what separates a mirror from a file, and it is the
/// convention every other tool uses for "a directory, not a document". A value
/// that is not an `http(s)` URL is a path — the same rule `--listen` uses to
/// tell a socket path from a `host:port`.
fn expand_source(value: &str, out: &mut Vec<String>) {
    let v = value.trim();
    if v.is_empty() {
        return;
    }
    if !is_url(v) {
        match parse_sources_file(Path::new(v)) {
            Ok(mut file_urls) => out.append(&mut file_urls),
            Err(e) => eprintln!("exav: reading {v}: {e}"),
        }
    } else if v.ends_with('/') {
        push_mirror_cvds(v, out);
    } else {
        out.push(v.to_string());
    }
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Expand a mirror base (a bare host or a full URL) into the three ClamAV CVD
/// source URLs. A bare host gets an `https://` scheme, matching freshclam — a
/// `freshclam.conf` `DatabaseMirror` line is written that way.
fn push_mirror_cvds(base: &str, out: &mut Vec<String>) {
    let base = base.trim().trim_end_matches('/');
    if base.is_empty() {
        return;
    }
    let base = if base.contains("://") {
        base.to_string()
    } else {
        format!("https://{base}")
    };
    for name in ["main.cvd", "daily.cvd", "bytecode.cvd"] {
        out.push(format!("{base}/{name}"));
    }
}

/// Parse the sources file into a list of source URLs. In the simplest form it is a
/// flat list of URLs, one per line (`#` comments and blank lines OK). For drop-in
/// migration it also understands the `freshclam.conf` *source* directives
/// (case-insensitive):
///   `DatabaseMirror <host|url>` / `PrivateMirror <host|url>`  -> `<base>/{main,daily,bytecode}.cvd`
///   `DatabaseCustomURL <url>`                                 -> one source, verbatim (http/https)
/// A bare `http(s)` line (no directive) is a source. Every OTHER line is **warned
/// about and ignored** — including `DatabaseDirectory` (set the dir with
/// `--sigs-dir`/`EXAV_SIGS_DIR`, it is not a source) and non-source directives like
/// `Foreground` — so pointing at a real `freshclam.conf` reports exactly what was
/// and wasn't used.
fn parse_sources_file(path: &Path) -> std::io::Result<Vec<String>> {
    let text = std::fs::read_to_string(path)?;
    let mut urls = Vec::new();
    let warn = |line: &str, why: &str| {
        eprintln!(
            "exav: {}: ignoring unsupported line ({why}): {line}",
            path.display()
        );
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // A bare URL line is a source.
        if line.starts_with("http://") || line.starts_with("https://") {
            urls.push(line.to_string());
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let key = parts.next().unwrap_or("").to_ascii_lowercase();
        let val = parts.next().unwrap_or("").trim();
        match key.as_str() {
            "databasemirror" | "privatemirror" => {
                if val.is_empty() {
                    warn(line, "missing mirror URL");
                } else {
                    push_mirror_cvds(val, &mut urls);
                }
            }
            "databasecustomurl" => {
                if val.starts_with("http://") || val.starts_with("https://") {
                    urls.push(val.to_string());
                } else {
                    warn(line, "DatabaseCustomURL must be an http(s) URL");
                }
            }
            "databasedirectory" => warn(
                line,
                "set the signature dir with --sigs-dir / EXAV_SIGS_DIR",
            ),
            _ => warn(line, "not a source URL or a supported freshclam directive"),
        }
    }
    Ok(urls)
}

/// Every configured signature source, merged and de-duplicated: each
/// `--sig-sources` value expanded by its shape — an exact URL, a mirror base, or
/// a file of either. A read failure on a file is reported and the rest still run.
fn sources(cli: &Cli) -> Vec<String> {
    let mut urls = Vec::new();
    for value in &cli.sig_sources {
        expand_source(value, &mut urls);
    }
    urls.sort();
    urls.dedup();
    urls
}

/// True if the signature directory exists and holds at least one file (matching
/// how `load_db` decides whether to use the dir or the built-in baseline).
fn datadir_has_db(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
}

/// Block (up to `timeout`) for a sidecar to populate an empty signature dir
/// before the database loads. If signatures never appear the caller then refuses
/// to serve rather than come up blind, unless `--allow-no-db`. A zero timeout
/// skips the wait (fail fast / opted-in baseline).
fn wait_for_db(dir: &Path, timeout: Duration) {
    if timeout.is_zero() || datadir_has_db(dir) {
        return;
    }
    eprintln!(
        "exav: waiting up to {}s for signatures in {} ...",
        timeout.as_secs(),
        dir.display()
    );
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if datadir_has_db(dir) {
            eprintln!("exav: signatures found");
            return;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    eprintln!("exav: no signatures after {}s", timeout.as_secs());
}

/// Fetch each signature source into `sigdir` (change-checked, validated, atomic),
/// tracking per-URL validators across calls. Returns true if anything was
/// installed (so the caller can trigger a reload). Best-effort: a per-source
/// failure is logged and the rest still run.
#[cfg(feature = "http-update")]
fn update_signatures(
    urls: &[String],
    sigdir: &Path,
    validators: &mut std::collections::HashMap<String, Option<String>>,
) -> bool {
    let name_of = |url: &str| exav_update::url_basename(url).unwrap_or_else(|| "<source>".into());
    let mut updated = false;
    for url in urls {
        let prev = validators.get(url).cloned().flatten();
        match exav_update::fetch_signature_if_changed(url, sigdir, prev.as_deref()) {
            Ok(f) => {
                if f.is_updated() {
                    eprintln!("exav: updated signature {}", name_of(url));
                    updated = true;
                }
                validators.insert(url.clone(), f.validator().map(String::from));
            }
            Err(e) => eprintln!("exav: fetch {} failed: {e}", name_of(url)),
        }
    }
    // Garbage-collect exav's `env/` subtree: a source removed from the config
    // leaves stale files that would otherwise keep loading. exav owns only `env/`;
    // freshclam-/hand-managed files elsewhere in the dir are never touched. A
    // deletion counts as a change so the caller reloads.
    let url_refs: Vec<&str> = urls.iter().map(String::as_str).collect();
    validators.retain(|url, _| url_refs.contains(&url.as_str()));
    match exav_update::prune_env_sources(sigdir, &url_refs) {
        Ok(removed) => {
            for p in &removed {
                eprintln!("exav: removed stale signature {}", p.display());
                updated = true;
            }
        }
        Err(e) => eprintln!("exav: pruning stale signatures failed: {e}"),
    }
    updated
}

/// Hide any `user:pass@` userinfo when echoing a URL to logs, so Basic-auth
/// credentials in `--db-url` never land in the daemon's output.
#[cfg(feature = "http-update")]
fn redact_url(url: &str) -> String {
    if let Some(scheme) = url.find("://") {
        let after = scheme + 3;
        let auth_end = url[after..].find('/').map_or(url.len(), |i| after + i);
        if let Some(at) = url[after..auth_end].rfind('@') {
            return format!("{}***@{}", &url[..after], &url[after + at + 1..]);
        }
    }
    url.to_string()
}

/// Whether a reload has anything to act on: only the prefork supervisor re-forks
/// its pool on request. Elsewhere the change is picked up by the mtime watch on
/// the same path, and raising `SIGHUP` in a process with no handler for it would
/// kill the server instead of reloading it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reload {
    /// Signal the prefork supervisor as soon as an update lands.
    Signal,
    /// Leave it to the mtime watch on the signature path.
    Watch,
}

impl Reload {
    /// Only the updater reaches this, so a build without it has nothing to
    /// request a reload from.
    #[cfg_attr(not(feature = "http-update"), allow(dead_code))]
    fn request(self) {
        if self == Reload::Signal {
            crate::daemon::request_reload();
        }
    }
}

/// The `--auto-update` lifecycle for this run: the sources it fetches, the
/// signature path it maintains, and the schedule it keeps.
///
/// Built by [`start`], which does the up-front half (create the directory, fetch
/// or wait) before the database is loaded. The periodic half starts with
/// [`AutoUpdate::poll_in_background`], after the load, so the first tick is a
/// cheap conditional re-check rather than a re-download.
///
/// A build with no updater in it never constructs one: it has nothing to fetch
/// with, so `start` does the directory and waiting half and stops there.
#[cfg_attr(not(feature = "http-update"), allow(dead_code))]
pub(crate) struct AutoUpdate {
    /// Signature sources to fetch, already merged and de-duplicated.
    sources: Vec<String>,
    /// The directory the sources are fetched into. `None` in prebuilt-database
    /// mode, where [`start`] already owns the polling.
    dir: Option<PathBuf>,
    /// Time between source re-checks.
    interval: Duration,
    /// How an installed update reaches the running server.
    reload: Reload,
    /// Per-source HTTP validators learned by the initial fetch.
    #[cfg(feature = "http-update")]
    validators: std::collections::HashMap<String, Option<String>>,
}

/// How often the sources are re-checked, from `--update-interval-secs`.
fn interval(cli: &Cli) -> Duration {
    Duration::from_secs(
        cli.update_interval_secs
            .unwrap_or(DEFAULT_UPDATE_INTERVAL_SECS)
            .max(MIN_UPDATE_INTERVAL_SECS),
    )
}

/// Seconds to wait for a sidecar to fill an empty signature dir. `--auto-update`
/// brings a default with it, because a container whose volume is being populated
/// by another container has to be allowed to come up second; without the flag
/// only an explicit value waits at all.
fn startup_timeout(cli: &Cli) -> Duration {
    let secs = cli.startup_timeout.unwrap_or(if cli.auto_update {
        DEFAULT_STARTUP_TIMEOUT_SECS
    } else {
        0
    });
    Duration::from_secs(secs)
}

/// The signature path this run loads from and `--auto-update` maintains: the
/// database named by `-d` when there is one, else the `--sigs-dir` directory.
fn signature_path(cli: &Cli) -> PathBuf {
    cli.database.clone().unwrap_or_else(|| cli.sigs.clone())
}

/// Get signatures in place before the database is loaded.
///
/// Returns the lifecycle to hand to [`AutoUpdate::poll_in_background`] once the
/// load has succeeded, or `None` when there is nothing periodic left to do (the
/// prebuilt-database poller starts here and owns itself).
///
/// `cli.database` is set when a prebuilt database is pulled, so that the load,
/// the reload and the mtime watch all read one source of truth.
pub(crate) fn start(cli: &mut Cli, reload: Reload) -> Result<Option<AutoUpdate>, String> {
    let sources = sources(cli);

    // Prebuilt-database-over-HTTP (build once, serve many): one `.exavdb`
    // replaces the signature files entirely, so it is resolved first.
    if let Some(url) = cli.db_url.clone() {
        return start_prebuilt_db(cli, &url, &sources, reload).map(|()| None);
    }

    let dir = signature_path(cli);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!(
            "exav: warning: cannot create signature dir {}: {e}",
            dir.display()
        );
    }

    if sources.is_empty() {
        // Nobody to fetch from: a sidecar owns this directory, so give it time
        // to write one before the caller decides whether it can serve.
        wait_for_db(&dir, startup_timeout(cli));
        return Ok(None);
    }

    let interval = interval(cli);
    eprintln!(
        "exav: {} signature source(s), refreshed every {}s",
        sources.len(),
        interval.as_secs()
    );

    #[cfg(not(feature = "http-update"))]
    {
        eprintln!(
            "exav: signature source URLs are set but this build has no updater — rebuild \
             with `--features http-update`, or populate {} from a sidecar. Continuing.",
            dir.display()
        );
        Ok(None)
    }

    #[cfg(feature = "http-update")]
    {
        let mut validators = std::collections::HashMap::new();
        eprintln!("exav: fetching {} signature source(s) ...", sources.len());
        update_signatures(&sources, &dir, &mut validators);
        Ok(Some(AutoUpdate {
            sources,
            dir: Some(dir),
            interval,
            reload,
            validators,
        }))
    }
}

/// Pull a prebuilt `.exavdb` from `--db-url` and keep it current.
///
/// The destination is `-d` when given, else `<--sigs-dir>/remote.exavdb`;
/// whichever it is becomes the database this run loads. The initial fetch is
/// synchronous so the first load sees a file, and a background poll re-checks it
/// every `--update-interval-secs` — cheap when nothing changed, since a `HEAD`
/// compares the `ETag` / `Last-Modified` and skips the download. That cheapness
/// is why its default cadence is minutes where a full source fetch's is a day.
#[cfg(feature = "http-update")]
fn start_prebuilt_db(
    cli: &mut Cli,
    url: &str,
    sources: &[String],
    reload: Reload,
) -> Result<(), String> {
    if !sources.is_empty() {
        eprintln!(
            "exav: --db-url is set — ignoring --sig-sources \
             (serving a prebuilt database, not signature files)"
        );
    }
    let dest = cli
        .database
        .clone()
        .unwrap_or_else(|| cli.sigs.join(PULLED_DB_NAME));
    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "exav: warning: cannot create database dir {}: {e}",
                parent.display()
            );
        }
    }

    let shown = redact_url(url);
    // A prebuilt database is re-checked with a conditional `HEAD`, which costs
    // almost nothing, so the default cadence is minutes rather than the day a
    // full source fetch gets. One flag either way: how often exav re-checks is
    // one question, and the default answer follows from how expensive the check
    // is rather than from a second setting.
    let poll = Duration::from_secs(
        cli.update_interval_secs
            .unwrap_or(DEFAULT_DB_URL_POLL_SECS)
            .max(1),
    );

    // Synchronous initial fetch so the first load sees a file.
    eprintln!("exav: fetching database from {shown} -> {}", dest.display());
    let mut validator = match exav_update::fetch_db_if_changed(url, &dest, None) {
        Ok(f) => {
            if f.is_updated() {
                eprintln!("exav: database installed from {shown}");
            }
            f.validator().map(String::from)
        }
        Err(e) => {
            eprintln!("exav: initial database fetch failed: {e}");
            None
        }
    };

    eprintln!(
        "exav: polling {shown} for database changes every {}s",
        poll.as_secs()
    );
    let url = url.to_string();
    let watched = dest.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(poll);
        match exav_update::fetch_db_if_changed(&url, &watched, validator.as_deref()) {
            Ok(f) => {
                validator = f.validator().map(String::from);
                if f.is_updated() {
                    eprintln!("exav: database updated from {shown} — reloading");
                    reload.request();
                }
            }
            Err(e) => eprintln!("exav: database poll failed: {e}"),
        }
    });

    cli.database = Some(dest);
    Ok(())
}

#[cfg(not(feature = "http-update"))]
fn start_prebuilt_db(
    _cli: &mut Cli,
    _url: &str,
    _sources: &[String],
    _reload: Reload,
) -> Result<(), String> {
    Err("--db-url needs the updater — build with `--features http-update`".to_string())
}

impl AutoUpdate {
    /// Re-fetch the sources on the schedule and reload whenever any changed.
    /// Consumes the validators the initial fetch learned, so the first tick is a
    /// conditional check rather than a second download.
    pub(crate) fn poll_in_background(self) {
        #[cfg(feature = "http-update")]
        {
            let AutoUpdate {
                sources,
                dir,
                interval,
                reload,
                mut validators,
            } = self;
            let Some(dir) = dir else { return };
            std::thread::spawn(move || loop {
                std::thread::sleep(interval);
                if update_signatures(&sources, &dir, &mut validators) {
                    reload.request();
                }
            });
        }
        #[cfg(not(feature = "http-update"))]
        {
            let _ = self;
        }
    }

    /// Refresh forever and never serve: the updater half of a two-container
    /// deployment, where another process serves the directory this one writes.
    pub(crate) fn refresh_forever(self) -> ! {
        #[cfg(feature = "http-update")]
        {
            let AutoUpdate {
                sources,
                dir,
                interval,
                reload: _,
                mut validators,
            } = self;
            let dir = dir.expect("a prebuilt database poller is never an updater-only run");
            eprintln!(
                "exav: updater-only: refreshing {} every {}s",
                dir.display(),
                interval.as_secs()
            );
            loop {
                std::thread::sleep(interval);
                update_signatures(&sources, &dir, &mut validators);
            }
        }
        #[cfg(not(feature = "http-update"))]
        {
            let _ = self;
            unreachable!("without the updater there is nothing to refresh")
        }
    }
}

/// The message for a run that configured signature sources but did not ask for
/// them to be fetched, so the setting is never silently inert.
pub(crate) fn unused_sources_notice(cli: &Cli) -> Option<String> {
    if cli.auto_update {
        return None;
    }
    let named = !sources(cli).is_empty() || cli.db_url.is_some();
    if !named && cli.update_interval_secs.is_none() {
        return None;
    }
    Some(
        "signature sources are configured but this run does not fetch them; \
         add --auto-update to bootstrap and refresh them"
            .to_string(),
    )
}

/// An updater-only run needs somewhere to fetch from, and the message has to
/// name what is missing: a container told to update with no source configured
/// would otherwise sit in a loop doing nothing, looking healthy.
pub(crate) fn updater_only_error(cli: &Cli) -> Option<String> {
    if sources(cli).is_empty() && cli.db_url.is_none() {
        return Some(
            "--auto-update with no listener is an updater, and it has no signature \
             source to fetch from; give it --sig-sources"
                .to_string(),
        );
    }
    if cli.db_url.is_some() {
        return Some(
            "an updater fetches signature files; --db-url pulls a prebuilt \
             database, which is served rather than written for another process — \
             add --listen"
                .to_string(),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// The sources file collects bare URLs + freshclam *source* directives, and
    /// **ignores** (with a warning) `DatabaseDirectory` and non-source lines like
    /// `Foreground` — so it doubles as a plain URL list AND a freshclam.conf.
    #[test]
    fn parses_sources_file_urls_and_directives_warning_on_rest() {
        let dir = std::env::temp_dir().join(format!("exav-srcfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("sources");
        std::fs::write(
            &file,
            "# my sources\n\
             https://bare.example/plain.ndb\n\
             \n\
             DatabaseMirror db.example.net\n\
             PrivateMirror https://mirror.internal/clamav\n\
             DatabaseCustomURL https://feeds.example/extra.ndb\n\
             DatabaseCustomURL file:///skip/me.ndb\n\
             DatabaseDirectory /var/lib/clamav\n\
             Foreground yes\n",
        )
        .unwrap();

        let urls = parse_sources_file(&file).unwrap();
        // Bare URL + DatabaseCustomURL (http) + mirror expansion are sources.
        assert!(urls.contains(&"https://bare.example/plain.ndb".to_string()));
        assert!(urls.contains(&"https://feeds.example/extra.ndb".to_string()));
        assert!(urls.contains(&"https://db.example.net/daily.cvd".to_string()));
        assert!(urls.contains(&"https://mirror.internal/clamav/bytecode.cvd".to_string()));
        // Non-source lines are ignored (warned): no file://, no dir, no toggle.
        assert!(!urls.iter().any(|u| u.contains("file://")));
        assert!(!urls.iter().any(|u| u.contains("/var/lib/clamav")));
        assert!(!urls.iter().any(|u| u.contains("Foreground")));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// One flag takes all three shapes of source, told apart by the value.
    ///
    /// The alternative was a flag (or a variable) per shape, which asks an
    /// operator to classify their own URL before they can pass it — and gets
    /// them a silently-inert setting when they pick the wrong one.
    #[test]
    fn a_source_is_read_by_its_shape() {
        let mut out = Vec::new();
        // An exact source goes verbatim.
        expand_source("https://host/main.cvd", &mut out);
        assert_eq!(out, ["https://host/main.cvd"]);

        // A trailing slash makes it a mirror base — the convention every other
        // tool uses for "a directory, not a document".
        out.clear();
        expand_source("https://host/db/", &mut out);
        assert_eq!(
            out,
            [
                "https://host/db/main.cvd",
                "https://host/db/daily.cvd",
                "https://host/db/bytecode.cvd",
            ]
        );

        // Anything that is not an http(s) URL is a path, the same rule
        // `--listen` uses to tell a socket path from a host:port.
        let dir = std::env::temp_dir().join(format!("exav-shape-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("sources");
        std::fs::write(&file, "https://from.file/x.ndb\n").unwrap();
        out.clear();
        expand_source(file.to_str().unwrap(), &mut out);
        assert_eq!(out, ["https://from.file/x.ndb"]);
        std::fs::remove_dir_all(&dir).ok();

        // And they merge, because a deployment can have a mirror and a feed.
        let _env = crate::env_guard();
        let cli = Cli::parse_from([
            "exav",
            "--sig-sources",
            "https://host/db/",
            "--sig-sources",
            "https://feeds.example/extra.ndb",
        ]);
        let all = sources(&cli);
        assert!(
            all.contains(&"https://host/db/daily.cvd".to_string()),
            "{all:?}"
        );
        assert!(
            all.contains(&"https://feeds.example/extra.ndb".to_string()),
            "{all:?}"
        );
    }

    /// The interval comes from the outside, and a short enough one is a loop
    /// with no delay pointed at whoever hosts the mirror — so it is floored.
    #[test]
    fn the_update_interval_is_floored_however_short_a_one_is_asked_for() {
        let _env = crate::env_guard();
        let cli =
            |args: &[&str]| Cli::parse_from(std::iter::once("exav").chain(args.iter().copied()));

        assert_eq!(
            interval(&cli(&[])).as_secs(),
            24 * 3600,
            "once a day is the default"
        );
        assert_eq!(
            interval(&cli(&["--update-interval-secs", "3600"])).as_secs(),
            3600,
            "an interval in seconds is used as given"
        );
        for too_short in ["0", "1", "59"] {
            assert_eq!(
                interval(&cli(&["--update-interval-secs", too_short])).as_secs(),
                MIN_UPDATE_INTERVAL_SECS,
                "--update-interval-secs {too_short} must not become a delay-free loop"
            );
        }
    }

    /// Waiting for a sidecar is what `--auto-update` brings with it. Without the
    /// flag nothing blocks unless an explicit timeout asks it to, so a plain
    /// scan or daemon never stalls on an empty directory.
    #[test]
    fn only_an_asked_for_wait_happens() {
        let _env = crate::env_guard();
        let cli =
            |args: &[&str]| Cli::parse_from(std::iter::once("exav").chain(args.iter().copied()));

        assert_eq!(startup_timeout(&cli(&[])), Duration::ZERO);
        assert_eq!(
            startup_timeout(&cli(&["--listen", "clamd://127.0.0.1:3310"])),
            Duration::ZERO
        );
        assert_eq!(
            startup_timeout(&cli(&["--auto-update"])).as_secs(),
            DEFAULT_STARTUP_TIMEOUT_SECS
        );
        assert_eq!(
            startup_timeout(&cli(&["--auto-update", "--startup-wait-secs", "0"])),
            Duration::ZERO,
            "an explicit zero means do not wait, even under --auto-update"
        );
        assert_eq!(
            startup_timeout(&cli(&["--startup-wait-secs", "30"])).as_secs(),
            30,
            "and the flag works on its own, rather than needing the capability"
        );
    }

    /// A wait that has nothing to wait for returns at once: the directory
    /// already holds signatures, or the timeout is zero.
    #[test]
    fn a_populated_dir_is_not_waited_on() {
        let dir = std::env::temp_dir().join(format!("exav-waitdb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("some.ndb"), b"x").unwrap();
        assert!(datadir_has_db(&dir));

        let start = std::time::Instant::now();
        wait_for_db(&dir, Duration::from_secs(30));
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "signatures are already there; nothing to wait for"
        );

        std::fs::remove_file(dir.join("some.ndb")).unwrap();
        assert!(!datadir_has_db(&dir));
        let start = std::time::Instant::now();
        wait_for_db(&dir, Duration::ZERO);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "a zero timeout does not wait"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Credentials in `--db-url` must not reach the log the daemon writes to
    /// its container's stdout.
    #[cfg(feature = "http-update")]
    #[test]
    fn a_pulled_database_url_is_logged_without_its_credentials() {
        assert_eq!(
            redact_url("https://user:secret@db.example/x.exavdb"),
            "https://***@db.example/x.exavdb"
        );
        assert_eq!(
            redact_url("https://db.example/x.exavdb"),
            "https://db.example/x.exavdb"
        );
        // A `@` in the path is not userinfo and must not be mistaken for it.
        assert_eq!(
            redact_url("https://db.example/a@b/x.exavdb"),
            "https://db.example/a@b/x.exavdb"
        );
    }
}
