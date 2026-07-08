//! Standalone signature-database updater for exav.
//!
//! Fetches ClamAV-format CVD containers from a **user-supplied** mirror into a
//! data directory. exav bundles **no** mirror URL — the caller passes one
//! explicitly (the container reads it from `EXAV_DB_MIRROR`), so nothing here
//! points at Cisco's CDN by default. This is consistent with exav never shipping
//! the GPL database or its distribution endpoint.
//!
//! It lives in its own crate on purpose: this is the single place a TLS stack
//! (`ureq → rustls → ring`) enters the tree, kept out of `exav-core` so the
//! scanning engine stays 100% pure-Rust.
//!
//! This is a plain HTTPS fetch, deliberately *not* the full freshclam protocol:
//!   * no DNS `TXT` version probe,
//!   * no CDIFF incremental patching,
//!   * **no digital-signature verification** of the container.
//!
//! It only compares the CVD header version (cheaply, via a range request for the
//! 512-byte header) and downloads a whole container when the mirror is newer.
//! Point it only at a mirror you trust. For cryptographically verified,
//! bandwidth-efficient updates run `freshclam`/`cvdupdate` in a sidecar and let
//! exav hot-reload the shared volume instead.

use std::io::{self, Read};
use std::path::Path;

/// The standard ClamAV container set. `main`/`daily` carry the signatures;
/// `bytecode` is optional and treated as best-effort (some mirrors omit it).
const CVDS: [&str; 3] = ["main", "daily", "bytecode"];

/// Upper bound on a downloaded container, mirroring the DB-file cap in
/// `exav-core`. Rejects a mirror that streams an unbounded/oversized body.
const MAX_CVD: u64 = 2 * 1024 * 1024 * 1024;

/// Fetch any newer CVDs from `base_url` into `datadir`.
///
/// `base_url` is the directory the `<name>.cvd` files live under; each container
/// is resolved against it (`<base>/main.cvd`, …). Returns `Ok(true)` if at least
/// one container was replaced (so the caller can trigger a reload), `Ok(false)`
/// if everything was already current.
///
/// A per-container failure is non-fatal as long as something succeeds (a mirror
/// lacking `bytecode.cvd` is common); only a total failure returns `Err`.
pub fn update_from_mirror(base_url: &str, datadir: &Path) -> io::Result<bool> {
    let agent = ureq::AgentBuilder::new()
        .user_agent(concat!("exav-update/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(300))
        .build();
    std::fs::create_dir_all(datadir)?;

    let mut updated = false;
    let mut errors = Vec::new();
    for name in CVDS {
        match update_one(&agent, base_url, name, datadir) {
            Ok(true) => updated = true,
            Ok(false) => {}
            Err(e) => errors.push(format!("{name}.cvd: {e}")),
        }
    }
    // Every container failed and nothing is newer → surface it. Otherwise the
    // failures are per-file (e.g. an absent optional bytecode.cvd) and only
    // worth a warning to the caller.
    if !updated && errors.len() == CVDS.len() {
        return Err(io::Error::other(errors.join("; ")));
    }
    for e in &errors {
        eprintln!("exav: db update: {e}");
    }
    Ok(updated)
}

/// Resolve `<name>.cvd` against a base URL, tolerating a missing trailing slash.
fn join_url(base: &str, name: &str) -> String {
    let sep = if base.ends_with('/') { "" } else { "/" };
    format!("{base}{sep}{name}.cvd")
}

/// Download `<name>.cvd` iff the mirror's version is newer than the local copy.
fn update_one(agent: &ureq::Agent, base: &str, name: &str, datadir: &Path) -> io::Result<bool> {
    let url = join_url(base, name);
    let local_ver = local_version(datadir, name);

    // Cheap probe first: fetch just the 512-byte header via a range request and
    // compare versions, so an unchanged container costs one small request.
    if let (Some(remote), Some(local)) = (remote_version(agent, &url), local_ver) {
        if remote <= local {
            return Ok(false);
        }
    }

    // Either the mirror is newer, or the probe was inconclusive (no range
    // support / no local copy). Download the whole container.
    let resp = agent
        .get(&url)
        .call()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_CVD + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_CVD {
        return Err(io::Error::other("container exceeds size cap"));
    }
    // Validate it really is a CVD before committing — a mirror returning an HTML
    // error page must not overwrite a good database.
    let remote_ver =
        cvd_version(&body).ok_or_else(|| io::Error::other("response is not a CVD container"))?;
    // If the probe was inconclusive but the full download turns out not to be
    // newer, drop it rather than needlessly rewriting and triggering a reload.
    if let Some(local) = local_ver {
        if remote_ver <= local {
            return Ok(false);
        }
    }

    // Commit atomically: write a temp file in the same dir, then rename over the
    // target (rename bumps the directory mtime, which the daemon's watch uses).
    let final_path = datadir.join(format!("{name}.cvd"));
    let tmp = datadir.join(format!(".{name}.cvd.tmp"));
    std::fs::write(&tmp, &body)?;
    std::fs::rename(&tmp, &final_path)?;
    // A stale `.cld` sibling (e.g. left by a prior freshclam run) would be loaded
    // alongside our fresh `.cvd` as a duplicate — remove it.
    let _ = std::fs::remove_file(datadir.join(format!("{name}.cld")));
    Ok(true)
}

/// Version of the locally stored container for `name`, checking both `.cvd` and
/// `.cld` (freshclam stores the incrementally-patched daily set as `.cld`) and
/// taking the higher of the two.
fn local_version(datadir: &Path, name: &str) -> Option<u32> {
    let read_ver = |ext: &str| -> Option<u32> {
        let path = datadir.join(format!("{name}.{ext}"));
        let mut f = std::fs::File::open(path).ok()?;
        let mut head = [0u8; 512];
        f.read_exact(&mut head).ok()?;
        cvd_version(&head)
    };
    read_ver("cvd").max(read_ver("cld"))
}

/// Fetch just the 512-byte CVD header via a range request and read its version.
/// Returns `None` if the mirror doesn't support ranges or the head isn't a valid
/// CVD header, in which case the caller falls back to a full download.
fn remote_version(agent: &ureq::Agent, url: &str) -> Option<u32> {
    let resp = agent.get(url).set("Range", "bytes=0-511").call().ok()?;
    let mut head = Vec::new();
    resp.into_reader().take(512).read_to_end(&mut head).ok()?;
    cvd_version(&head)
}

/// Parse the version out of a 512-byte `ClamAV-VDB:` header.
///
/// Layout: `ClamAV-VDB:btime:version:sigs:flevel:md5:dsig:builder:stime`, so the
/// version is the third colon-separated field. Self-contained (no `exav-core`
/// dependency) — the header is a fixed ASCII line and only the version matters
/// here.
fn cvd_version(head: &[u8]) -> Option<u32> {
    if head.len() < 512 || !head.starts_with(b"ClamAV-VDB:") {
        return None;
    }
    let text = String::from_utf8_lossy(&head[..512]);
    text.split(':').nth(2)?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u32) -> Vec<u8> {
        let mut h = format!(
            "ClamAV-VDB:01 Jan 2026 00-00 +0000:{version}:1234:90:abcdef0123456789:dsig:exav-test:1700000000"
        )
        .into_bytes();
        h.resize(512, b' ');
        h
    }

    #[test]
    fn parses_version_field() {
        assert_eq!(cvd_version(&header(58)), Some(58));
        assert_eq!(cvd_version(&header(27000)), Some(27000));
    }

    #[test]
    fn rejects_non_cvd() {
        assert_eq!(cvd_version(b"<html>not a cvd</html>"), None);
        let mut short = b"ClamAV-VDB:x:5:".to_vec();
        short.resize(100, b' ');
        assert_eq!(cvd_version(&short), None); // under 512 bytes
    }

    #[test]
    fn join_url_handles_trailing_slash() {
        assert_eq!(join_url("https://m/db", "main"), "https://m/db/main.cvd");
        assert_eq!(join_url("https://m/db/", "daily"), "https://m/db/daily.cvd");
    }

    #[test]
    fn local_version_reads_higher_of_cvd_cld() {
        let dir = std::env::temp_dir().join(format!("exav-update-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("daily.cvd"), header(100)).unwrap();
        std::fs::write(dir.join("daily.cld"), header(105)).unwrap();
        assert_eq!(local_version(&dir, "daily"), Some(105));
        assert_eq!(local_version(&dir, "absent"), None);
        std::fs::remove_dir_all(&dir).ok();
    }
}
