//! The `exav-imagehash` command line.

/// A file name that is not UTF-8 is a file to hash, not a crash at start.
#[cfg(unix)]
#[test]
fn a_file_name_that_is_not_utf8_is_hashed() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = std::env::temp_dir().join(format!("exav-imagehash-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(OsStr::from_bytes(b"caf\xe9.png"));
    let pixels =
        image::RgbImage::from_fn(32, 32, |x, y| image::Rgb([(x * 8) as u8, (y * 8) as u8, 0]));
    pixels
        .save_with_format(&file, image::ImageFormat::Png)
        .unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_exav-imagehash"))
        .arg(&file)
        .output()
        .expect("run exav-imagehash");
    let _ = std::fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stdout} {stderr}");
    assert!(stdout.contains(".png: "), "{stdout} {stderr}");
}
