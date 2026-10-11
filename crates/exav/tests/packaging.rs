//! The files exav ships for deployment: the release workflow, the systemd unit
//! and the compose file. Each is read as the tool that consumes it would read
//! it, for the one property a regression there would break.

use std::path::PathBuf;

fn repo_file(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Every archive the release uploads carries the licence and the NOTICE of
/// what is linked into it.
#[test]
fn every_release_archive_carries_the_licenses() {
    let release = repo_file(".github/workflows/release.yml");
    let uploads: Vec<&str> = release
        .split("- uses: taiki-e/upload-rust-binary-action")
        .skip(1)
        .map(|step| step.split("\n      - ").next().unwrap_or(step))
        .collect();
    assert!(uploads.len() >= 5, "{} upload steps", uploads.len());
    for step in uploads {
        let include = step
            .lines()
            .find_map(|l| l.trim().strip_prefix("include:"))
            .unwrap_or_else(|| panic!("no include in:{step}"));
        let files: Vec<&str> = include.split(',').map(str::trim).collect();
        assert!(
            files.contains(&"LICENSE") && files.contains(&"NOTICE"),
            "{step}"
        );
    }
    for f in ["LICENSE", "NOTICE"] {
        assert!(!repo_file(f).trim().is_empty(), "{f}");
    }
}

/// The unit serves the signatures freshclam writes on the distributions whose
/// clamd socket it takes over, and may read them under `ProtectSystem=strict`.
#[test]
fn the_systemd_unit_reads_what_freshclam_writes() {
    let unit = repo_file("packaging/exav.service");
    let exec = unit
        .lines()
        .find_map(|l| l.strip_prefix("ExecStart="))
        .expect("an ExecStart line");
    let args: Vec<&str> = exec.split_whitespace().collect();
    let dir = args
        .iter()
        .position(|a| *a == "-d" || *a == "--sig-dir")
        .and_then(|i| args.get(i + 1))
        .unwrap_or_else(|| panic!("no signature directory in {exec}"));
    // freshclam's DatabaseDirectory on Debian, Ubuntu and Fedora packages.
    assert_eq!(*dir, "/var/lib/clamav", "{exec}");
    let readable = unit
        .lines()
        .find_map(|l| l.strip_prefix("ReadOnlyPaths="))
        .unwrap_or_default();
    assert!(readable.split_whitespace().any(|p| p == *dir), "{readable}");
}

/// The clamd protocol has no authentication, so the compose file publishes
/// its ports on the loopback interface only.
#[test]
fn the_compose_file_publishes_no_port_beyond_localhost() {
    let compose = repo_file("docker-compose.yml");
    let mut published = 0;
    let mut in_ports = false;
    for line in compose.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if t == "ports:" {
            in_ports = true;
            continue;
        }
        match t.strip_prefix("- ") {
            Some(entry) if in_ports => {
                let entry = entry.trim_matches('"').trim_matches('\'');
                published += 1;
                assert!(
                    entry.starts_with("127.0.0.1:") || entry.starts_with("[::1]:"),
                    "{entry} is published on every interface"
                );
            }
            _ => in_ports = false,
        }
    }
    assert!(published > 0, "no port found to check");
}

/// The image's HEALTHCHECK is not honoured everywhere (podman ignores it on an
/// image without Docker mediatypes; Kubernetes always). The compose file says
/// it again for the scanner, and must not drift from the image's command and
/// timings.
#[test]
fn the_compose_file_repeats_the_images_health_check() {
    let docker = repo_file("Dockerfile");
    let line = docker
        .lines()
        .position(|l| l.starts_with("HEALTHCHECK"))
        .expect("a HEALTHCHECK in the Dockerfile");
    let check: String = docker
        .lines()
        .skip(line)
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let option = |name: &str| -> String {
        let at = check
            .find(&format!("--{name}="))
            .unwrap_or_else(|| panic!("no --{name} in {check}"));
        check[at + name.len() + 3..]
            .split_whitespace()
            .next()
            .unwrap()
            .to_string()
    };
    assert!(check.contains(r#"CMD ["/exav", "--ping"]"#), "{check}");
    let compose = repo_file("docker-compose.yml");
    // The scanner's own service: from its name to the next one.
    let scanner = compose
        .split("\n  exav:")
        .nth(1)
        .and_then(|s| s.split("\n  updater:").next())
        .expect("the exav service");
    assert!(
        scanner.contains(r#"test: ["CMD", "/exav", "--ping"]"#),
        "{scanner}"
    );
    for (flag, key) in [
        ("interval", "interval"),
        ("timeout", "timeout"),
        ("start-period", "start_period"),
        ("retries", "retries"),
    ] {
        let want = format!("{key}: {}", option(flag));
        assert!(scanner.contains(&want), "compose lacks `{want}`");
    }
}

/// podman reads the image's HEALTHCHECK only from Docker mediatypes, and
/// buildx's default provenance attestation forces an OCI index back. Dropping
/// either setting from the publish step looks like tidying and silently
/// removes the health check for podman.
#[test]
fn the_publish_step_pushes_docker_mediatypes() {
    let workflow = repo_file(".github/workflows/docker.yml");
    let publish = workflow
        .split("\n  publish:")
        .nth(1)
        .expect("the publish job");
    let live: Vec<&str> = publish
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();
    assert!(live.contains(&"provenance: false"), "provenance is on");
    let outputs = live
        .iter()
        .find_map(|l| l.strip_prefix("outputs:"))
        .expect("an outputs: line on the build-push step")
        .trim();
    for want in ["type=image", "oci-mediatypes=false", "push=true"] {
        assert!(
            outputs.split(',').any(|o| o == want),
            "outputs lacks {want}: {outputs}"
        );
    }
    assert!(!live.contains(&"push: true"), "push: true beside outputs");
}
