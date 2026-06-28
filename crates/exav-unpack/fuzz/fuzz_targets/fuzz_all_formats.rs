#![no_main]
use libfuzzer_sys::fuzz_target;
use exav_unpack::{Budget, Format, Limits, detect, extract};

fuzz_target!(|data: &[u8]| {
    let _fmt = detect(data);

    for fmt in [
        Format::Zip, Format::Gzip, Format::Tar, Format::Bzip2,
        Format::Xz, Format::Cab, Format::Ole, Format::Pdf,
        Format::Email, Format::SevenZip, Format::Iso, Format::Lha,
        Format::Arj, Format::Rar, Format::Upx, Format::Ar,
        Format::Cpio, Format::Xar, Format::Dmg, Format::Zstd,
        Format::Lzip,
    ] {
        let mut budget = Budget::new(Limits {
            max_total_bytes: 256 * 1024,
            max_files: 5,
            max_ratio: 50,
            max_entry_bytes: 128 * 1024,
            max_scan_bytes: 256 * 1024,
            max_recursion: 2,
        });
        let _ = extract(fmt, data, &mut budget);
    }
});
