//! Standalone HTTP fetcher for exav's signature sources and prebuilt database.
//!
//! exav bundles **no URLs**. The caller supplies them (`--sig-sources` and
//! `--db-url`, or the variables behind them), so nothing here points at any
//! vendor by default — exav treats Cisco's "official" CVDs as **just three more
//! URLs**, no different from any other feed.
//!
//! This crate is isolated on purpose: it is the single place a TLS stack
//! (`ureq → rustls → ring`) enters the tree, kept out of `exav-core` so the
//! scanning engine stays 100% pure-Rust. It contains **no `unsafe`** of its own
//! (`#![forbid(unsafe_code)]`); the only native code is the transitive `ring`.
//!
//! A fetch is a plain **conditional HTTPS GET**: an `ETag`/`Last-Modified`
//! validator (or, failing that, a byte-compare against the on-disk copy) decides
//! whether anything changed; the body is validated before it can overwrite a good
//! file; and it is installed atomically (temp + rename). There is **no**
//! digital-signature verification and **no** rsync — for GPG-signed or rsync-only
//! feeds (e.g. Sanesecurity), run `clamav-unofficial-sigs` into the signature
//! directory and let exav read it.
#![forbid(unsafe_code)]
// This crate's public surface is fully documented. The lint keeps it that way:
// an undocumented public item is a build warning rather than something noticed
// on docs.rs after publishing.
#![warn(missing_docs)]

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Upper bound on any single downloaded file (covers a large `.cvd` or a full
/// `.exavdb`). Rejects a server streaming an unbounded/oversized body.
const MAX_FETCH: u64 = 4 * 1024 * 1024 * 1024;

/// Framing of an exav prebuilt database: `MAGIC(8) | VERSION(4) | payload | SHA-256(32)`.
/// Mirrored from `exav-core::database` so this crate needs no `exav-core` dependency.
const EXAV_DB_MAGIC: &[u8; 8] = b"EXAVDB\x00\x01";
const EXAV_DB_HEADER_LEN: usize = 12; // 8-byte magic + 4-byte LE version
const EXAV_DB_DIGEST_LEN: usize = 32; // trailing SHA-256 of the payload

/// Outcome of a conditional fetch. Both variants carry the current validator so
/// the caller can persist it and short-circuit the next poll.
#[derive(Debug)]
pub enum Fetch {
    /// Nothing was written — the remote matched what we already have.
    Unchanged {
        /// The remote's current validator (`ETag`/`Last-Modified`), if it sent
        /// one. Persist it and pass it back to short-circuit the next poll.
        validator: Option<String>,
    },
    /// A new file was installed at the destination.
    Updated {
        /// The validator the new content was served with, if any. Persisting it
        /// is what makes the following poll cheap.
        validator: Option<String>,
    },
}

impl Fetch {
    /// The validator to remember for the next call (either variant).
    pub fn validator(&self) -> Option<&str> {
        match self {
            Fetch::Unchanged { validator } | Fetch::Updated { validator } => validator.as_deref(),
        }
    }
    /// Whether a new file was installed (i.e. the caller should reload).
    pub fn is_updated(&self) -> bool {
        matches!(self, Fetch::Updated { .. })
    }
}

/// Standard base64 (with padding) — just enough to encode Basic-auth credentials
/// without pulling a base64 crate into this thin updater.
fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((*c.get(1).unwrap_or(&0) as u32) << 8)
            | (*c.get(2).unwrap_or(&0) as u32);
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Split `user:pass@` credentials out of a URL's authority. Returns the URL with
/// the userinfo removed and, when present, a ready-to-send `Basic` Authorization
/// header value (kept out of the request line; RFC 7617).
fn split_basic_auth(url: &str) -> (String, Option<String>) {
    let Some(scheme) = url.find("://") else {
        return (url.to_string(), None);
    };
    let after = scheme + 3;
    let auth_end = url[after..].find('/').map_or(url.len(), |i| after + i);
    let authority = &url[after..auth_end];
    let Some(at) = authority.rfind('@') else {
        return (url.to_string(), None);
    };
    let creds = &authority[..at];
    let host = &authority[at + 1..];
    let clean = format!("{}{host}{}", &url[..after], &url[auth_end..]);
    (clean, Some(format!("Basic {}", base64(creds.as_bytes()))))
}

/// The change-detection validator advertised by a response: `ETag` if present,
/// else `Last-Modified`. Opaque strings, only ever compared for equality.
/// A cache validator and the request header that may send it back.
///
/// The two are not interchangeable. A `Last-Modified` date returned in
/// `If-None-Match` is not a well-formed entity-tag — unquoted, with spaces and
/// commas — so it can never match, and some CDNs answer a malformed
/// `If-None-Match` with `400`. The effect is a full re-download on every poll
/// against any origin that sends no `ETag`, or a hard failure.
fn validator_of(resp: &ureq::Response) -> Option<String> {
    resp.header("ETag")
        .or_else(|| resp.header("Last-Modified"))
        .map(|s| s.to_string())
}

/// The conditional-request header a stored validator belongs in.
///
/// An entity-tag is quoted — `"abc"` or `W/"abc"` — and an HTTP-date is not, so
/// the value says which it is and the stored form stays what the caller already
/// persists. Sending a date in `If-None-Match` is the failure this avoids: it is
/// not a well-formed entity-tag, so it can never match, and the poll re-downloads
/// the whole database every time against any origin that offers no `ETag`.
fn validator_header(v: &str) -> &'static str {
    let t = v.trim_start();
    if t.starts_with('"') || t.starts_with("W/") {
        "If-None-Match"
    } else {
        "If-Modified-Since"
    }
}

/// The trailing filename of a URL (path last segment, query/fragment stripped),
/// or `None` if there isn't a usable one. Never contains a path separator, and
/// `.`/`..` are rejected, so it is safe to join onto a directory.
pub fn url_basename(url: &str) -> Option<String> {
    let no_frag = url.split('#').next().unwrap_or(url);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    let seg = no_query.rsplit('/').next().unwrap_or("");
    if seg.is_empty() || seg == "." || seg == ".." {
        return None;
    }
    Some(seg.to_string())
}

/// Core conditional fetch: install `url` at `dest` only if it changed, running
/// `validate` on the body before it can replace a good file.
///
/// Cheap when unchanged: a `HEAD` reads the current `ETag`/`Last-Modified`, and if
/// it equals `prev` no body is transferred. Otherwise a conditional `GET`
/// (`If-None-Match`, honouring `304`) fetches the body, which is size-checked,
/// `validate`d, byte-compared against the on-disk copy (so an identical re-serve
/// with a fresh ETag doesn't needlessly reinstall), and finally swapped in
/// atomically. Basic-auth credentials in the URL are sent as a header.
fn fetch_into(
    url: &str,
    dest: &Path,
    prev: Option<&str>,
    validate: impl Fn(&[u8]) -> Result<(), String>,
) -> io::Result<Fetch> {
    // `https_only` also refuses an HTTPS→HTTP redirect, which is the point of
    // setting it here. A signature database fetched in cleartext can be
    // substituted by anyone on the path, and neither of the body checks would
    // notice: a `.cvd` is validated by its `ClamAV-VDB:` prefix, and an
    // `.exavdb` by a digest the same response supplied. The operator would see
    // "updated" and nothing else.
    //
    // A source configured as plain `http://` still works — `https_only` refuses
    // the DOWNGRADE, not the scheme — so an air-gapped mirror is unaffected.
    // `redirects` is pinned rather than inherited so a dependency's default
    // cannot quietly change how far this follows.
    let agent = ureq::AgentBuilder::new()
        .user_agent(concat!("exav-update/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(300))
        .https_only(url.starts_with("https://"))
        .redirects(5)
        .build();

    let (url, auth) = split_basic_auth(url);
    // Credentials over cleartext are refused rather than sent. `https_only`
    // above covers the downgrade an attacker causes; this covers the one the
    // operator wrote, which is the easier mistake to make and the one nothing
    // else here would catch — a `Basic` header is the password in base64, and a
    // fetch that succeeded looks identical either way. A plain `http://` source
    // with no userinfo still works, so an air-gapped mirror is unaffected.
    if auth.is_some() && url.starts_with("http://") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to send credentials over http:// — use https://, or drop \
             the `user:pass@` and authenticate another way",
        ));
    }
    let url = url.as_str();
    let with_auth = |mut r: ureq::Request| -> ureq::Request {
        if let Some(a) = &auth {
            r = r.set("Authorization", a);
        }
        r
    };

    // Only trust the "unchanged" fast-paths (the HEAD/ETag shortcut and the
    // conditional-GET `304`) while we still have the file they'd let us skip
    // re-downloading. If `dest` was deleted or truncated out from under us, a
    // matching validator must NOT report Unchanged — otherwise the on-disk copy
    // stays missing until the process restarts (which is what resets `prev`). So
    // gate both shortcuts on the destination actually existing.
    let have_dest = dest.exists();

    // HEAD shortcut: unchanged validator -> no body transfer.
    if have_dest {
        if let Some(p) = prev {
            if let Ok(head) = with_auth(agent.head(url)).call() {
                if validator_of(&head).as_deref() == Some(p) {
                    return Ok(Fetch::Unchanged {
                        validator: Some(p.to_string()),
                    });
                }
            }
        }
    }

    let mut req = with_auth(agent.get(url));
    if have_dest {
        if let Some(p) = prev {
            req = req.set(validator_header(p), p);
        }
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(304, _)) => {
            return Ok(Fetch::Unchanged {
                validator: prev.map(String::from),
            })
        }
        Err(e) => return Err(io::Error::other(e.to_string())),
    };
    // ureq surfaces a 304 as `Ok`; treat it as unchanged.
    if resp.status() == 304 {
        return Ok(Fetch::Unchanged {
            validator: prev.map(String::from),
        });
    }
    let validator = validator_of(&resp);
    let expected: Option<u64> = resp
        .header("Content-Length")
        .and_then(|v| v.trim().parse().ok());

    // Refuse before allocating, not after. `Content-Length` was already parsed
    // and was previously only consulted once the whole body was in memory, so a
    // server declaring 4 GiB got 4 GiB read before anything objected.
    if let Some(len) = expected {
        if len > MAX_FETCH {
            return Err(io::Error::other(format!(
                "response declares {len} bytes, over the {MAX_FETCH}-byte cap"
            )));
        }
    }
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_FETCH + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_FETCH {
        return Err(io::Error::other("response exceeds size cap"));
    }
    if let Some(len) = expected {
        if body.len() as u64 != len {
            return Err(io::Error::other(format!(
                "truncated download: got {} of {len} bytes",
                body.len()
            )));
        }
    }
    validate(&body).map_err(io::Error::other)?;

    // Identical on-disk copy (a server that re-serves the same bytes under a new
    // validator) -> remember the validator but don't reinstall / trigger a reload.
    if std::fs::read(dest).is_ok_and(|existing| existing == body) {
        return Ok(Fetch::Unchanged { validator });
    }

    // Commit atomically in `dest`'s directory (same-filesystem rename). The
    // directory may be new (the updater namespaces sources under `env/<host>/…`),
    // so create it first.
    let fname = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download");
    // The temp name carries this process's pid. A fixed name collides when two
    // updaters share a data directory — a daemon plus a cron `exav --update`, or
    // two daemons on one volume, both of which the README describes as supported
    // — and `fs::write` truncates, so the loser's `rename` publishes whatever
    // mixture of the two bodies was on disk at that moment. Each body passed
    // validation on its own; the blend did not.
    let tmp = match dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(d) => {
            std::fs::create_dir_all(d)?;
            d.join(format!(".{fname}.{}.tmp", std::process::id()))
        }
        None => PathBuf::from(format!(".exav-download.{}.tmp", std::process::id())),
    };
    // Written, flushed to the device, and only then renamed. `rename` is atomic
    // for the directory entry, but without the sync a crash can leave the entry
    // pointing at blocks that were never written — a zero-length or partly-zero
    // database where the README promises the previous one intact. Any failure
    // takes the temp file with it rather than leaving it for the next run to
    // trip over.
    let write_then_sync = || -> io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()
    };
    if let Err(e) = write_then_sync().and_then(|()| std::fs::rename(&tmp, dest)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(Fetch::Updated { validator })
}

/// Verify a body is a complete, uncorrupted exav database: correct magic and a
/// trailing SHA-256 matching its payload (the stamp `exav-core` writes and checks
/// at load). Catches an interrupted/corrupt download before it is installed.
fn verify_exav_db(body: &[u8]) -> Result<(), String> {
    if body.len() < EXAV_DB_HEADER_LEN + EXAV_DB_DIGEST_LEN {
        return Err("truncated download (shorter than an empty database header)".into());
    }
    if &body[..EXAV_DB_MAGIC.len()] != EXAV_DB_MAGIC {
        return Err("not an exav database (.exavdb) — wrong magic".into());
    }
    let (head_payload, trailer) = body.split_at(body.len() - EXAV_DB_DIGEST_LEN);
    let payload = &head_payload[EXAV_DB_HEADER_LEN..];
    if Sha256::digest(payload).as_slice() != trailer {
        return Err(
            "integrity check failed (SHA-256 mismatch) — download corrupt or interrupted".into(),
        );
    }
    Ok(())
}

/// Pull a prebuilt exav database (`.exavdb`) from `url` and install it at `dest`
/// only when it has changed. The body must carry the exav database magic and a
/// matching embedded SHA-256, so a corrupt/interrupted download is rejected and
/// the good on-disk database is kept. No signature verification — trust the
/// builder, over HTTPS.
pub fn fetch_db_if_changed(url: &str, dest: &Path, prev: Option<&str>) -> io::Result<Fetch> {
    fetch_into(url, dest, prev, verify_exav_db)
}

/// Sub-directory of the signature directory that exav's HTTP updater **fully
/// owns**. Every source fetched from `--sig-sources` lands under
/// here (namespaced by origin), and [`prune_env_sources`] deletes anything here
/// that no longer maps to a configured source. Deliberately kept OUT of the
/// signature-directory root, so files placed there by hand or by `freshclam` are
/// never touched. Not `.`-prefixed, so the recursive loader still reads it.
pub const ENV_SUBDIR: &str = "env";

/// Sanitize one path component: keep `[A-Za-z0-9._-]`, map anything else to `_`,
/// and reject empty / all-dot components (`.`/`..`). Guarantees the result is a
/// single, separator-free, non-traversing directory or file name.
fn sanitize_component(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    // An all-dots component (`.`, `..`, `...`) is either meaningless or traversal.
    if cleaned.chars().all(|c| c == '.') {
        return None;
    }
    Some(cleaned)
}

/// Map a source `url` to the on-disk path exav installs it at:
/// `<sigdir>/env/<host>/<url-path…>/<filename>`. Namespacing by origin means two
/// feeds that happen to share a filename (e.g. two CVD mirrors both ending in
/// `daily.cvd`) never clobber each other. Every component is sanitized, and `.`
/// /`..` are dropped, so a crafted URL can never escape `sigdir`. Errors only if
/// the URL has no usable trailing filename.
pub fn sig_dest(sigdir: &Path, url: &str) -> io::Result<PathBuf> {
    // A usable trailing filename is required (it becomes the last path component).
    if url_basename(url).is_none() {
        return Err(io::Error::other("URL has no filename to save"));
    }
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let (authority, path) = after_scheme.split_once('/').unwrap_or((after_scheme, ""));
    // Strip userinfo (`user:pass@`) and port (`:1234`) down to the bare host.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split_once(':').map_or(host, |(h, _)| h);
    // Drop query/fragment from the path.
    let path = path.split(['?', '#']).next().unwrap_or(path);

    let mut dest = sigdir.join(ENV_SUBDIR);
    let mut parts: Vec<String> = Vec::new();
    for raw in std::iter::once(host).chain(path.split('/')) {
        if let Some(part) = sanitize_component(raw) {
            parts.push(part);
        }
    }
    // Sanitising is lossy and the query is dropped entirely, so two different
    // sources on one host can land on one file: `get.php?db=daily` and
    // `get.php?db=main` both reduce to `get.php`, and `a+b/` and `a%20b/` both
    // to `a_b`. Sharing a destination is worse than a name collision — each poll
    // finds content that does not match its own stored validator, re-downloads,
    // and overwrites the other, so the two feeds flip-flop forever and the
    // loaded signature set depends on which finished last.
    //
    // A short digest of the WHOLE url, query included, separates them. It is
    // appended to the final component so the directory layout still reads as the
    // origin it came from.
    if let Some(last) = parts.last_mut() {
        let mut h = Sha256::new();
        h.update(url.as_bytes());
        let d = h.finalize();
        last.push_str(&format!("-{:02x}{:02x}{:02x}", d[0], d[1], d[2]));
    }
    for p in parts {
        dest.push(p);
    }
    Ok(dest)
}

/// Pull one **signature source** from `url` into the signature directory `sigdir`
/// (at [`sig_dest`], i.e. `<sigdir>/env/<host>/…`) only when it has changed. This
/// is how exav treats every source — a ClamAV `.cvd` and a third-party `.ndb` go
/// through the exact same path. Validation before install: a `.cvd`/`.cld` must
/// carry the `ClamAV-VDB:` header; any other file must be non-empty and not look
/// like an HTML error page. (No signature/GPG verification — trust the source,
/// over HTTPS.)
pub fn fetch_signature_if_changed(
    url: &str,
    sigdir: &Path,
    prev: Option<&str>,
) -> io::Result<Fetch> {
    let name = url_basename(url).ok_or_else(|| io::Error::other("URL has no filename to save"))?;
    let dest = sig_dest(sigdir, url)?;
    let is_cvd = name.ends_with(".cvd") || name.ends_with(".cld");
    fetch_into(url, &dest, prev, move |b: &[u8]| {
        if b.is_empty() {
            return Err("empty response".into());
        }
        if is_cvd {
            if !b.starts_with(b"ClamAV-VDB:") {
                return Err("not a CVD container (missing ClamAV-VDB header)".into());
            }
        } else {
            // Leading whitespace is ordinary in a templated error page, so the
            // check has to look past it — otherwise "\n<!DOCTYPE html>" installs
            // itself as a signature file and the loader gets to cope with the
            // markup. A JSON error body is the same class of answer.
            let head = b
                .iter()
                .position(|c| !c.is_ascii_whitespace())
                .map_or(&b[..0], |i| &b[i..]);
            if head.starts_with(b"<") || head.starts_with(b"{") {
                return Err("response looks like an error page, not a signature file".into());
            }
        }
        Ok(())
    })
}

/// Garbage-collect exav's `env/` subtree: delete every file under `<sigdir>/env/`
/// that no longer maps to one of `active_urls` (a source dropped from
/// `--sig-sources`), then remove the directories left empty.
/// exav owns only this subtree — files elsewhere in `sigdir` (freshclam- or
/// hand-managed) are never touched. Returns the paths removed. Best-effort: an
/// unreadable entry is skipped rather than fatal.
pub fn prune_env_sources(sigdir: &Path, active_urls: &[&str]) -> io::Result<Vec<PathBuf>> {
    let env_root = sigdir.join(ENV_SUBDIR);
    if !env_root.is_dir() {
        return Ok(Vec::new());
    }
    let keep: std::collections::HashSet<PathBuf> = active_urls
        .iter()
        .filter_map(|u| sig_dest(sigdir, u).ok())
        .collect();
    let mut removed = Vec::new();
    // A file that will not delete is still being LOADED, and the operator who
    // deconfigured its feed has no way to know unless it is said. Being
    // best-effort is right; being invisible is not — the recursive loader picks
    // up whatever is left here, so a stale or withdrawn feed keeps matching.
    let mut failed = Vec::new();
    for file in walk_files(&env_root, 0) {
        if keep.contains(&file) {
            continue;
        }
        // Another process's in-flight temp file is not ours to judge: it is
        // about to be renamed into place by an updater running right now.
        if file
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with('.') && n.ends_with(".tmp"))
        {
            continue;
        }
        match std::fs::remove_file(&file) {
            Ok(()) => removed.push(file),
            Err(e) => failed.push(format!("{}: {e}", file.display())),
        }
    }
    prune_empty_dirs(&env_root, true);
    if !failed.is_empty() {
        return Err(io::Error::other(format!(
            "removed {} deconfigured file(s); could not remove: {}",
            removed.len(),
            failed.join(", ")
        )));
    }
    Ok(removed)
}

/// Recursively collect regular files under `dir` (symlinks are not followed, so a
/// cycle can't loop and we never delete through a link). Depth-capped for safety.
fn walk_files(dir: &Path, depth: u32) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if depth > 64 {
        return out;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            out.extend(walk_files(&e.path(), depth + 1));
        } else if ft.is_file() {
            out.push(e.path());
        }
    }
    out
}

/// Remove now-empty directories bottom-up under `root`; `root` itself is kept.
fn prune_empty_dirs(dir: &Path, is_root: bool) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut empty = true;
    for e in entries.flatten() {
        let p = e.path();
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir && prune_empty_dirs(&p, false) {
            let _ = std::fs::remove_dir(&p);
        } else {
            empty = false;
        }
    }
    empty && !is_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(
            base64(b"Aladdin:open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn split_basic_auth_extracts_and_strips_credentials() {
        let (url, auth) = split_basic_auth("https://user:pass@host.tld/path/db.exavdb");
        assert_eq!(url, "https://host.tld/path/db.exavdb");
        assert_eq!(auth.as_deref(), Some("Basic dXNlcjpwYXNz"));

        let (url, auth) = split_basic_auth("https://host.tld/db.exavdb");
        assert_eq!(url, "https://host.tld/db.exavdb");
        assert_eq!(auth, None);

        let (url, auth) = split_basic_auth("http://bob:s3cr3t@host.tld:8080");
        assert_eq!(url, "http://host.tld:8080");
        assert_eq!(auth.as_deref(), Some("Basic Ym9iOnMzY3IzdA=="));
    }

    #[test]
    fn url_basename_strips_query_and_rejects_traversal() {
        assert_eq!(
            url_basename("https://m/db/main.cvd").as_deref(),
            Some("main.cvd")
        );
        assert_eq!(
            url_basename("https://si.example/get/sig/TOKEN/x.ndb?v=3").as_deref(),
            Some("x.ndb")
        );
        assert_eq!(
            url_basename("https://user:p@m/daily.cvd#frag").as_deref(),
            Some("daily.cvd")
        );
        assert_eq!(url_basename("https://m/dir/"), None); // no filename
        assert_eq!(url_basename("https://m/.."), None); // traversal rejected
    }

    #[test]
    fn verify_exav_db_accepts_valid_and_rejects_corrupt() {
        let framed = |payload: &[u8]| -> Vec<u8> {
            let mut v = EXAV_DB_MAGIC.to_vec();
            v.extend_from_slice(&1u32.to_le_bytes());
            v.extend_from_slice(payload);
            v.extend_from_slice(Sha256::digest(payload).as_slice());
            v
        };
        assert!(verify_exav_db(&framed(b"the database payload")).is_ok());
        assert!(verify_exav_db(&framed(b"")).is_ok());
        assert!(verify_exav_db(b"<html>404</html>").is_err());
        assert!(verify_exav_db(b"EXAVDB\x00\x01short").is_err());
        let mut cut = framed(b"the database payload");
        cut.pop();
        assert!(verify_exav_db(&cut).is_err());
        let mut bitflip = framed(b"the database payload");
        bitflip[EXAV_DB_HEADER_LEN] ^= 0x01;
        assert!(verify_exav_db(&bitflip).is_err());
    }
}
