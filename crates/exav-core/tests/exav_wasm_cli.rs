//! The `exav-wasm` command line, run on the host.

/// A file name that is not UTF-8 is a file to scan, not a crash at start.
#[cfg(unix)]
#[test]
fn a_file_name_that_is_not_utf8_is_scanned() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = std::env::temp_dir().join(format!("exav-wasm-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let db = dir.join("db");
    std::fs::create_dir_all(&db).unwrap();
    std::fs::write(db.join("t.ndb"), b"Other.Sig:0:*:4f54484552\n").unwrap();
    let file = dir.join(OsStr::from_bytes(b"caf\xe9.txt"));
    std::fs::write(&file, b"an OTHER file").unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_exav-wasm"))
        .arg(&db)
        .arg(&file)
        .output()
        .expect("run exav-wasm");
    let _ = std::fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // A detection is 1, where a panic at start is 101.
    assert_eq!(out.status.code(), Some(1), "{stdout} {stderr}");
    assert!(stdout.contains("Other.Sig"), "{stdout} {stderr}");
}
