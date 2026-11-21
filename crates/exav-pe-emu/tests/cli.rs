//! The `exav-pe-emu` command line.

/// A file name that is not UTF-8 is a file to read, not a crash at start.
#[cfg(unix)]
#[test]
fn a_file_name_that_is_not_utf8_is_read() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = std::env::temp_dir().join(format!("exav-pe-emu-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(OsStr::from_bytes(b"caf\xe9.exe"));
    std::fs::write(&file, b"not a PE").unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_exav-pe-emu"))
        .arg("--report-only")
        .arg(&file)
        .output()
        .expect("run exav-pe-emu");
    let _ = std::fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Nothing to recover from it: 1, where a panic at start is 101.
    assert_eq!(out.status.code(), Some(1), "{stdout} {stderr}");
    assert!(stdout.contains("nothing recovered"), "{stdout} {stderr}");
}
