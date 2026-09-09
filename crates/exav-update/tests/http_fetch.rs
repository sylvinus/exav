//! End-to-end coverage for the conditional HTTP fetcher: the HEAD/ETag
//! short-circuit, the 304 fallback, integrity/validation before install, and the
//! generalized `fetch_signature_if_changed` (a CVD and a loose `.ndb` go through
//! the same path).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use exav_update::{
    fetch_db_if_changed, fetch_signature_if_changed, prune_env_sources, sig_dest, Fetch,
};

struct State {
    etag: String,
    body: Vec<u8>,
    /// When false, HEAD responses omit `ETag` (forcing the conditional-GET path).
    head_etag: bool,
    /// When set, GET answers `302` to this location instead of serving a body.
    redirect_to: Option<String>,
    /// When set, the GET's `Content-Length` claims this instead of the real
    /// length. A declaration far past the cap must be refused before the body is
    /// read, not after it has been buffered.
    lie_content_length: Option<u64>,
}

impl Default for State {
    /// An ordinary server: serves its body, answers HEAD with an `ETag`, tells
    /// the truth about length, redirects nowhere. Tests name only what they bend.
    fn default() -> Self {
        State {
            etag: "\"v1\"".into(),
            body: Vec::new(),
            head_etag: true,
            redirect_to: None,
            lie_content_length: None,
        }
    }
}

/// Spawn a one-request-at-a-time HTTP/1.1 server that serves `state.body` for any
/// path; returns its base URL (`http://addr`). Tests append the filename.
fn spawn(state: Arc<Mutex<State>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
                continue;
            }
            let method = request_line.split(' ').next().unwrap_or("").to_string();
            let mut inm: Option<String> = None;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
                if let Some(v) = line.strip_prefix("If-None-Match:") {
                    inm = Some(v.trim().to_string());
                }
            }

            let st = state.lock().unwrap();
            let etag_hdr = format!("ETag: {}\r\n", st.etag);
            let resp = if method == "HEAD" {
                let e = if st.head_etag {
                    etag_hdr.clone()
                } else {
                    String::new()
                };
                format!(
                    "HTTP/1.1 200 OK\r\n{e}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    st.body.len()
                )
                .into_bytes()
            } else if let Some(loc) = &st.redirect_to {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\n\
                     Connection: close\r\n\r\n"
                )
                .into_bytes()
            } else if inm.as_deref() == Some(st.etag.as_str()) {
                format!("HTTP/1.1 304 Not Modified\r\n{etag_hdr}Connection: close\r\n\r\n")
                    .into_bytes()
            } else {
                let declared = st.lie_content_length.unwrap_or(st.body.len() as u64);
                let mut r = format!(
                    "HTTP/1.1 200 OK\r\n{etag_hdr}Content-Length: {declared}\r\n\
                     Connection: close\r\n\r\n"
                )
                .into_bytes();
                r.extend_from_slice(&st.body);
                r
            };
            drop(st);
            let _ = s.write_all(&resp);
            let _ = s.flush();
        }
    });
    format!("http://{addr}")
}

/// A valid `.exavdb`: magic + version + payload + trailing SHA-256.
fn exavdb_body() -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let payload = b"exav test database payload";
    let mut v = b"EXAVDB\x00\x01".to_vec();
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(payload);
    v.extend_from_slice(Sha256::digest(payload).as_slice());
    v
}

/// A minimal CVD body (just needs the header magic to validate).
fn cvd_body() -> Vec<u8> {
    let mut v = b"ClamAV-VDB:01 Jan 2026:100:1234:90:md5:dsig:builder:stime".to_vec();
    v.resize(600, b' ');
    v
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("exav-httpfetch-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A declared length past the cap is refused before the body is read.
///
/// `Content-Length` was already parsed but only consulted after `read_to_end`,
/// so a server declaring gigabytes got gigabytes buffered before anything
/// objected. The updater runs on the daemon's poll thread, so that allocation
/// kills the scanner rather than just the update.
#[test]
fn an_oversized_declaration_is_refused_before_the_body_is_read() {
    let state = Arc::new(Mutex::new(State {
        etag: "\"big\"".into(),
        body: exavdb_body(),
        // Far past MAX_FETCH. The body actually sent is small, so if the check
        // ran after the read this would succeed and the test would pass for the
        // wrong reason.
        lie_content_length: Some(64 * 1024 * 1024 * 1024),
        ..Default::default()
    }));
    let base = spawn(state.clone());
    let dir = tempdir("toobig");
    let dest = dir.join("big.exavdb");

    let err = fetch_db_if_changed(&format!("{base}/big.exavdb"), &dest, None)
        .expect_err("a response declaring 64 GiB must be refused");
    assert!(
        err.to_string().contains("cap"),
        "the error should name the cap, got {err}"
    );
    assert!(
        !dest.exists(),
        "nothing may be installed from a refused fetch"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A redirect is followed, and the temp file does not survive the round trip.
///
/// Redirects were untested entirely, which matters because the scheme they may
/// redirect TO is a security property: an HTTPS source must never be downgraded
/// to cleartext. That half needs a TLS server to exercise; this pins the part
/// that can be tested here — that following works at all, and that a completed
/// fetch leaves no `.tmp` behind for the next run to trip over.
#[test]
fn a_redirect_is_followed_and_leaves_no_temp_file() {
    let target = Arc::new(Mutex::new(State {
        etag: "\"final\"".into(),
        body: exavdb_body(),
        ..Default::default()
    }));
    let target_base = spawn(target.clone());

    let front = Arc::new(Mutex::new(State {
        etag: "\"front\"".into(),
        body: Vec::new(),
        redirect_to: Some(format!("{target_base}/real.exavdb")),
        ..Default::default()
    }));
    let front_base = spawn(front.clone());

    let dir = tempdir("redir");
    let dest = dir.join("via.exavdb");
    // HEAD short-circuits before the GET, so disable it to force the redirect.
    front.lock().unwrap().head_etag = false;

    match fetch_db_if_changed(&format!("{front_base}/via.exavdb"), &dest, None) {
        Ok(Fetch::Updated { .. }) => {
            assert!(
                std::fs::read(&dest).unwrap().starts_with(b"EXAVDB\x00\x01"),
                "the redirected-to body must be what landed"
            );
        }
        other => panic!("a 302 should have been followed, got {other:?}"),
    }
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn head_etag_short_circuits_and_downloads_on_change() {
    let state = Arc::new(Mutex::new(State {
        etag: "\"v1\"".into(),
        body: exavdb_body(),
        ..Default::default()
    }));
    let base = spawn(state.clone());
    let url = format!("{base}/live.exavdb");
    let dir = tempdir("db");
    let dest = dir.join("live.exavdb");

    let v1 = match fetch_db_if_changed(&url, &dest, None).unwrap() {
        Fetch::Updated { validator } => validator,
        Fetch::Unchanged { .. } => panic!("first fetch should download"),
    };
    assert_eq!(v1.as_deref(), Some("\"v1\""));
    assert!(std::fs::read(&dest).unwrap().starts_with(b"EXAVDB\x00\x01"));

    // Same ETag: HEAD short-circuits, no download.
    assert!(matches!(
        fetch_db_if_changed(&url, &dest, v1.as_deref()).unwrap(),
        Fetch::Unchanged { .. }
    ));

    // New ETag but IDENTICAL bytes -> the byte-compare avoids a needless reinstall.
    state.lock().unwrap().etag = "\"v2-same-bytes\"".into();
    assert!(matches!(
        fetch_db_if_changed(&url, &dest, v1.as_deref()).unwrap(),
        Fetch::Unchanged { .. }
    ));

    // New ETag AND different bytes -> installed.
    {
        use sha2::{Digest, Sha256};
        let payload = b"a different database payload";
        let mut b = b"EXAVDB\x00\x01".to_vec();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(payload);
        b.extend_from_slice(Sha256::digest(payload).as_slice());
        let mut st = state.lock().unwrap();
        st.etag = "\"v3\"".into();
        st.body = b;
    }
    assert!(matches!(
        fetch_db_if_changed(&url, &dest, Some("\"v2-same-bytes\"")).unwrap(),
        Fetch::Updated { .. }
    ));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn conditional_get_304_when_head_lacks_etag() {
    let state = Arc::new(Mutex::new(State {
        etag: "\"abc\"".into(),
        body: exavdb_body(),
        head_etag: false,
        ..Default::default()
    }));
    let base = spawn(state);
    let url = format!("{base}/live.exavdb");
    let dir = tempdir("db304");
    let dest = dir.join("live.exavdb");

    let v = match fetch_db_if_changed(&url, &dest, None).unwrap() {
        Fetch::Updated { validator } => validator,
        Fetch::Unchanged { .. } => panic!("first fetch should download"),
    };
    assert_eq!(v.as_deref(), Some("\"abc\""));
    assert!(matches!(
        fetch_db_if_changed(&url, &dest, v.as_deref()).unwrap(),
        Fetch::Unchanged { .. }
    ));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rejects_corrupt_db_and_keeps_existing_file() {
    let state = Arc::new(Mutex::new(State {
        etag: "\"good\"".into(),
        body: exavdb_body(),
        ..Default::default()
    }));
    let base = spawn(state.clone());
    let url = format!("{base}/live.exavdb");
    let dir = tempdir("dbbad");
    let dest = dir.join("live.exavdb");

    assert!(matches!(
        fetch_db_if_changed(&url, &dest, None).unwrap(),
        Fetch::Updated { .. }
    ));
    // Truncated (valid length, mismatched digest) under a new ETag.
    {
        let mut st = state.lock().unwrap();
        st.etag = "\"partial\"".into();
        let mut b = exavdb_body();
        b.truncate(b.len() - 16);
        st.body = b;
    }
    let err = fetch_db_if_changed(&url, &dest, Some("\"good\"")).unwrap_err();
    assert!(err.to_string().contains("integrity check failed"), "{err}");
    assert!(std::fs::read(&dest).unwrap().starts_with(b"EXAVDB\x00\x01"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn fetch_signature_installs_under_env_namespaced_by_origin() {
    // A CVD source.
    let cvd = Arc::new(Mutex::new(State {
        etag: "\"c1\"".into(),
        body: cvd_body(),
        ..Default::default()
    }));
    let base = spawn(cvd);
    let dir = tempdir("sig");
    let url = format!("{base}/main.cvd");
    // The source lands under `env/<host>/…`, NOT in the sigdir root.
    assert!(matches!(
        fetch_signature_if_changed(&url, &dir, None).unwrap(),
        Fetch::Updated { .. }
    ));
    let dest = sig_dest(&dir, &url).unwrap();
    assert!(dest.starts_with(dir.join("env")), "must live under env/");
    // Named for the source, plus a digest of the full URL so two sources that
    // sanitise to the same name stay apart — the digest sitting in front of the
    // extension, which the loader needs intact to classify the file at all.
    let name = dest.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with("main-") && name.ends_with(".cvd"),
        "destination should read as main.cvd and keep its extension: {dest:?}"
    );
    assert!(dest.exists());
    assert!(std::fs::read(&dest).unwrap().starts_with(b"ClamAV-VDB:"));
    assert!(
        !dir.join("main.cvd").exists(),
        "nothing is written to the sigdir root"
    );

    // A loose .ndb source (plain text) via a query-string URL.
    let ndb = Arc::new(Mutex::new(State {
        etag: "\"n1\"".into(),
        body: b"Sig.A:0:*:6d616c\n".to_vec(),
        ..Default::default()
    }));
    let base2 = spawn(ndb);
    let ndb_url = format!("{base2}/feed.ndb?token=xyz");
    assert!(matches!(
        fetch_signature_if_changed(&ndb_url, &dir, None).unwrap(),
        Fetch::Updated { .. }
    ));
    let ndb_dest = sig_dest(&dir, &ndb_url).unwrap();
    let ndb_name = ndb_dest.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        ndb_name.starts_with("feed-") && ndb_name.ends_with(".ndb"),
        "the filename should read as its source and stay a .ndb: {ndb_name}"
    );
    assert!(
        !ndb_name.contains("token") && !ndb_name.contains("xyz"),
        "a query-string token must not be written into a filename: {ndb_name}"
    );
    assert!(ndb_dest.exists());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn sig_dest_namespaces_by_origin_and_resists_traversal() {
    let dir = std::path::Path::new("/var/lib/exav");
    // Same filename, different hosts -> distinct on-disk paths (no clobber).
    let a = sig_dest(dir, "https://mirror-a.example.com/daily.cvd").unwrap();
    let b = sig_dest(dir, "https://mirror-b.example.com/feeds/daily.cvd").unwrap();
    assert_ne!(a, b);
    assert!(a.starts_with("/var/lib/exav/env/"));
    // The layout still reads as the origin it came from; the final component
    // carries a digest of the whole URL, so the exact filename is not pinned.
    assert!(a.to_string_lossy().contains("mirror-a.example.com/daily"));
    assert!(b
        .to_string_lossy()
        .contains("mirror-b.example.com/feeds/daily"));

    // The extension survives the digest, for every source and every suffix. The
    // loader routes a database file by extension and nothing else, so a name it
    // cannot classify is skipped without a word — a fetch that reports success
    // and a database that never loads. Whatever the digest does to the name, it
    // must not touch the part the loader reads.
    for (url, want) in [
        ("https://mirror-a.example.com/daily.cvd", "cvd"),
        ("https://mirror-b.example.com/feeds/daily.cvd", "cvd"),
        ("https://feeds.example/rules.ndb", "ndb"),
        ("https://feeds.example/x/hashes.hsb?v=2", "hsb"),
        ("https://feeds.example/set.yar", "yar"),
    ] {
        let dest = sig_dest(dir, url).unwrap();
        assert_eq!(
            dest.extension().and_then(|e| e.to_str()),
            Some(want),
            "{url} lands at {dest:?}, which the loader classifies by extension \
             and would skip"
        );
    }

    // Two sources on ONE host differing only in the query must not share a
    // destination. Sharing one is worse than a name collision: each poll finds
    // content that does not match its own validator, re-downloads, and
    // overwrites the other, so the pair flip-flops forever and which signatures
    // are loaded depends on whichever finished last.
    let q1 = sig_dest(dir, "https://feeds.example/get.php?db=daily").unwrap();
    let q2 = sig_dest(dir, "https://feeds.example/get.php?db=main").unwrap();
    assert_ne!(
        q1, q2,
        "query-differing sources must not collide on one file"
    );
    // And an unchanged URL still maps to an unchanged destination, or every
    // poll would reinstall.
    assert_eq!(
        q1,
        sig_dest(dir, "https://feeds.example/get.php?db=daily").unwrap()
    );

    // A traversal attempt cannot escape the sigdir: `..` segments are dropped and
    // path separators in a component are sanitized away.
    let evil = sig_dest(dir, "https://host/../../../etc/passwd").unwrap();
    assert!(
        evil.starts_with("/var/lib/exav/env/"),
        "must stay under env/: {evil:?}"
    );
    assert!(!evil.to_string_lossy().contains(".."));

    // Userinfo and port are stripped from the host component.
    let auth = sig_dest(dir, "https://user:pass@host.tld:8443/x/daily.cvd").unwrap();
    assert!(auth.starts_with("/var/lib/exav/env/host.tld/"));
    assert!(!auth.to_string_lossy().contains("pass"));
}

#[test]
fn fetch_signature_rejects_non_cvd_for_cvd_url() {
    // A `.cvd` URL serving an HTML error page must be rejected (wrong header).
    let state = Arc::new(Mutex::new(State {
        etag: "\"x\"".into(),
        body: b"<html><body>500 Internal Server Error</body></html>".to_vec(),
        ..Default::default()
    }));
    let base = spawn(state);
    let dir = tempdir("sigbad");
    let url = format!("{base}/daily.cvd");
    let err = fetch_signature_if_changed(&url, &dir, None).unwrap_err();
    assert!(err.to_string().contains("CVD"), "{err}");
    assert!(
        !sig_dest(&dir, &url).unwrap().exists(),
        "bad body must not be installed"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn prune_env_sources_drops_deconfigured_and_keeps_the_rest() {
    let keep = Arc::new(Mutex::new(State {
        etag: "\"k\"".into(),
        body: cvd_body(),
        ..Default::default()
    }));
    let base = spawn(keep);
    let dir = tempdir("prune");
    let kept_url = format!("{base}/daily.cvd");
    let gone_url = format!("{base}/old.cvd");

    // Install two sources, then a user-managed root file the GC must NOT touch.
    fetch_signature_if_changed(&kept_url, &dir, None).unwrap();
    fetch_signature_if_changed(&gone_url, &dir, None).unwrap();
    std::fs::write(dir.join("hand-managed.ndb"), b"Sig.X:0:*:00\n").unwrap();
    let kept_dest = sig_dest(&dir, &kept_url).unwrap();
    let gone_dest = sig_dest(&dir, &gone_url).unwrap();
    assert!(kept_dest.exists() && gone_dest.exists());

    // Reconfigure to only the first source: the second is pruned from env/.
    let removed = prune_env_sources(&dir, &[kept_url.as_str()]).unwrap();
    assert_eq!(removed, vec![gone_dest.clone()]);
    assert!(kept_dest.exists(), "still-configured source is kept");
    assert!(!gone_dest.exists(), "deconfigured source is removed");
    assert!(
        dir.join("hand-managed.ndb").exists(),
        "files outside env/ are never touched by GC"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn redownloads_when_dest_deleted_despite_matching_validator() {
    // The validator ("v1") is unchanged, but the on-disk file was deleted out from
    // under us. The HEAD/ETag shortcut must NOT report Unchanged — it must notice
    // the file is gone and re-download, so a deleted DB self-heals without a restart.
    let state = Arc::new(Mutex::new(State {
        etag: "\"v1\"".into(),
        body: exavdb_body(),
        ..Default::default()
    }));
    let base = spawn(state);
    let url = format!("{base}/live.exavdb");
    let dir = tempdir("selfheal");
    let dest = dir.join("live.exavdb");

    let v = match fetch_db_if_changed(&url, &dest, None).unwrap() {
        Fetch::Updated { validator } => validator,
        Fetch::Unchanged { .. } => panic!("first fetch should download"),
    };
    assert_eq!(v.as_deref(), Some("\"v1\""));
    assert!(dest.exists());

    // Simulate an operator/error deleting the file while the validator is retained.
    std::fs::remove_file(&dest).unwrap();
    assert!(matches!(
        fetch_db_if_changed(&url, &dest, v.as_deref()).unwrap(),
        Fetch::Updated { .. }
    ));
    assert!(
        dest.exists(),
        "deleted file must be re-downloaded, not skipped"
    );
    std::fs::remove_dir_all(&dir).ok();
}
