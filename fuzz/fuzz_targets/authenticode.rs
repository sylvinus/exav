#![no_main]
//! Authenticode: the PE's certificate table, the PKCS#7 `SignedData` in it, the
//! DER of each certificate, and the digest the signature carries against the
//! file's own (`authenticode::analyze_pe`). The scan runs it for any PE when
//! `alert_broken_authenticode` is set or a `.crb` list is loaded, on bytes an
//! attacker chose, and a hand-written DER reader is where an off-by-one in a
//! length lives.
//!
//! Seeds are the signed PEs of `exav-core`'s fixtures: a PE the parser takes
//! to the certificates is the only way to reach them, and the mutator then
//! moves inside the signature.
//!
//! Checked beyond "does not panic": a `.crb` list that names the signer's
//! subject, with or without its serial, blocks the signer, and one that names
//! another subject does not.
use exav_core::authenticode::{self, CrbDb};
use libfuzzer_sys::fuzz_target;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fuzz_target!(|data: &[u8]| {
    let Some(sig) = authenticode::analyze_pe(data) else {
        return;
    };
    for cert in &sig.certs {
        let subject = hex(&cert.subject_sha1);
        let mut by_subject = CrbDb::default();
        by_subject.parse_into(&format!("Fuzz.Cert;0;{subject};\n"));
        assert!(
            by_subject.blocked(cert).is_some(),
            "a list naming the subject does not block it"
        );

        let mut by_serial = CrbDb::default();
        by_serial.parse_into(&format!("Fuzz.Cert;0;{subject};{};\n", cert.serial_hex));
        assert!(
            by_serial.blocked(cert).is_some(),
            "a list naming the subject and serial does not block it"
        );

        let mut other = CrbDb::default();
        let mut elsewhere = cert.subject_sha1;
        elsewhere[0] ^= 1;
        other.parse_into(&format!("Fuzz.Cert;0;{};\n", hex(&elsewhere)));
        assert!(
            other.blocked(cert).is_none(),
            "a list naming another subject blocks it"
        );
    }
});
