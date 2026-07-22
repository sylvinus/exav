//! Without the `decrypt` feature, encrypted members are reported unsupported and
//! never decrypted (the cipher stack isn't compiled in) — the same as when no
//! password is supplied, and never a silent clean. Compiled/run only in a
//! no-decrypt build: `cargo test -p exav-unpack --no-default-features --features zip`.
use exav_unpack::{extract, Budget, Format, Limits};

#[test]
fn encrypted_zip_is_unsupported_without_decrypt() {
    // Both WinZip-AES and legacy ZipCrypto members, with a password supplied —
    // which must be ignored, because there is no cipher stack to use it.
    for data in [
        &include_bytes!("../fixtures/encrypted/zip_aes256_store.zip")[..],
        &include_bytes!("../fixtures/encrypted/zip_zipcrypto_store.zip")[..],
    ] {
        let mut budget = Budget::with_passwords(Limits::default(), vec!["exavtest".into()]);
        let entries = extract(Format::Zip, data, &mut budget).unwrap();
        assert!(
            entries.iter().any(|e| e.encrypted && e.unsupported.is_some()),
            "encrypted member must be reported unsupported (not decrypted) without the decrypt feature",
        );
        // And never handed back as decrypted plaintext.
        assert!(
            entries
                .iter()
                .all(|e| e.unsupported.is_some() || e.data.is_empty()),
            "no member should be decrypted without the decrypt feature",
        );
    }
}
