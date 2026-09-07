//! Authenticode (PE code-signing) inspection — **triage without RSA**.
//!
//! A signed PE carries a PKCS#7 `SignedData` blob (in the certificate table)
//! whose `SpcIndirectDataContent` embeds a digest of the file. We extract that
//! digest and the signer certificate fields, and recompute the PE's Authenticode
//! hash, using only:
//!   * `goblin` (already a dependency) for the certificate table + the byte
//!     ranges to hash ([`goblin::pe::PE::authenticode_ranges`]);
//!   * `sha1`/`sha2` (already dependencies) for the hash + thumbprint;
//!   * a small **vendored** DER reader (the `der` module) — so no `rsa`/`der`/`x509`/`nom`
//!     crate enters the tree and everything stays `#![forbid(unsafe_code)]`.
//!
//! What this gives, with no signature-verification crypto:
//!   * **digest-covers-file**: recomputed hash vs the embedded digest. A mismatch
//!     means the file was modified/appended-to after signing — a strong signal.
//!   * signer identity (subject/issuer CN, serial, SHA-1 thumbprint) and whether
//!     the leaf is **self-signed** — for reporting and `.crb` cert matching.
//!
//! What it deliberately does NOT do: verify that the digest was actually signed
//! by the certificate's private key (that needs RSA/ECDSA and is out of scope by
//! design — see `docs/DEPENDENCIES.md`).

mod der;

use sha1::Sha1;
use sha2::{Digest, Sha256};

// ---- OID content encodings (the bytes inside an OID TLV) --------------------
const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// The PE-hash algorithm named in the signature's `DigestInfo`.
#[derive(Clone, Copy, PartialEq, Debug)]
enum DigestAlg {
    Sha1,
    Sha256,
}

/// Fields extracted from one X.509 certificate (no key material).
#[derive(Clone, Debug)]
pub struct CertInfo {
    pub serial_hex: String,
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub self_signed: bool,
    /// SHA-1 of the whole certificate DER (the "thumbprint").
    pub sha1_thumbprint: [u8; 20],
    /// SHA-1 of the subject `Name` DER (tag+length+value) — the key a ClamAV
    /// `.crb` entry matches its `Subject` field against.
    pub subject_sha1: [u8; 20],
}

/// The result of inspecting a PE's Authenticode signature.
#[derive(Clone, Debug)]
pub struct PeSignature {
    /// The recomputed Authenticode hash equals the digest embedded in the
    /// signature — i.e. the signature covers the current file bytes.
    pub digest_matches: bool,
    /// The signer (leaf) certificate.
    pub signer: CertInfo,
    /// Every certificate embedded in the signature (leaf + chain).
    pub certs: Vec<CertInfo>,
}

// ---- .crb certificate block-list -------------------------------------------

/// One parsed `.crb` line (ClamAV certificate database).
struct CrbEntry {
    name: String,
    /// SHA-1 of the subject `Name` DER, hex-decoded (the `Subject` field).
    subject_sha1: Option<[u8; 20]>,
    /// Optional serial number (lowercase hex), the `Serial` field.
    serial: Option<String>,
}

/// A ClamAV `.crb` certificate database. We honour **block** entries
/// (`Trusted == 0`) only: a signed PE carrying a matching certificate is
/// reported. Trust/whitelist entries (`Trusted == 1`) are ignored, since honoring
/// them safely would require verifying the RSA signature chain (out of scope —
/// see the module docs).
#[derive(Default)]
pub struct CrbDb {
    blocked: Vec<CrbEntry>,
    /// Raw `.crb` texts, retained so the on-disk database can round-trip the
    /// database by re-parsing (mirrors how bytecode sources are stored).
    sources: Vec<String>,
}

impl CrbDb {
    pub fn is_empty(&self) -> bool {
        self.blocked.is_empty()
    }

    /// The raw `.crb` source texts (for database serialization).
    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    /// Rebuild a database from stored raw `.crb` source texts.
    pub fn from_sources(sources: &[String]) -> Self {
        let mut db = Self::default();
        for s in sources {
            db.parse_into(s);
        }
        db
    }

    /// Parse `.crb` text into this database. Format (`;`-separated):
    /// `Name;Trusted;Subject;Serial;PublicKey;Exp;CodeSign;TimeSign;CertSign;NotBefore;Comment`.
    /// Malformed lines are skipped (best effort — a bad line never aborts a load).
    pub fn parse_into(&mut self, text: &str) {
        self.sources.push(text.to_string());
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split(';').collect();
            if f.len() < 3 {
                continue;
            }
            // Only block entries (Trusted == 0).
            if f[1].trim() != "0" {
                continue;
            }
            let subject_sha1 = hex20(f[2].trim());
            let serial = f
                .get(3)
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty());
            if subject_sha1.is_none() && serial.is_none() {
                continue; // nothing to match on
            }
            self.blocked.push(CrbEntry {
                name: f[0].trim().to_string(),
                subject_sha1,
                serial,
            });
        }
    }

    /// The block-list signature name if `cert` matches any block entry: its
    /// subject hash matches and, when the entry pins a serial, that matches too.
    pub fn blocked(&self, cert: &CertInfo) -> Option<&str> {
        let cser = cert.serial_hex.trim_start_matches('0');
        for e in &self.blocked {
            if let Some(s) = e.subject_sha1 {
                if s != cert.subject_sha1 {
                    continue;
                }
            } else {
                continue;
            }
            if let Some(ref ser) = e.serial {
                if ser.trim_start_matches('0') != cser {
                    continue;
                }
            }
            return Some(&e.name);
        }
        None
    }
}

/// Decode a 40-char (20-byte) hex string; `None` on any non-hex or wrong length.
fn hex20(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

// ---- X.509 -----------------------------------------------------------------

/// Extract the Common Name from a `Name` (RDNSequence) value.
fn extract_cn(name_content: &[u8]) -> Option<String> {
    for rdn in der::children(name_content) {
        if rdn.tag != der::SET {
            continue;
        }
        for atv in der::children(rdn.content) {
            if atv.tag != der::SEQUENCE {
                continue;
            }
            let mut it = der::children(atv.content);
            let oid = it.next()?;
            let val = it.next()?;
            if oid.tag == der::OID && oid.content == OID_COMMON_NAME {
                return Some(String::from_utf8_lossy(val.content).into_owned());
            }
        }
    }
    None
}

/// Parse a single X.509 certificate (its full DER) into a [`CertInfo`].
fn parse_certificate(cert_der: &[u8]) -> Option<CertInfo> {
    let cert = der::top(cert_der)?;
    if cert.tag != der::SEQUENCE {
        return None;
    }
    // tbsCertificate is the first element.
    let tbs = der::children(cert.content).next()?;
    if tbs.tag != der::SEQUENCE {
        return None;
    }
    // Positional walk: [0]version(optional), serial, sigAlg, issuer, validity,
    // subject, ...
    let fields: Vec<der::Tlv> = der::children(tbs.content).collect();
    let mut i = 0;
    if fields.first().map(|t| t.tag) == Some(der::context(0)) {
        i = 1; // skip explicit version
    }
    let serial = fields.get(i)?;
    let issuer = fields.get(i + 2)?;
    let subject = fields.get(i + 4)?;
    if serial.tag != der::INTEGER || issuer.tag != der::SEQUENCE || subject.tag != der::SEQUENCE {
        return None;
    }

    let mut thumb = [0u8; 20];
    thumb.copy_from_slice(&Sha1::digest(cert.full));
    let mut subj = [0u8; 20];
    subj.copy_from_slice(&Sha1::digest(subject.full));

    Some(CertInfo {
        serial_hex: hex(serial.content),
        subject_cn: extract_cn(subject.content),
        issuer_cn: extract_cn(issuer.content),
        // Self-signed ⇔ issuer DN and subject DN are byte-identical.
        self_signed: issuer.full == subject.full,
        sha1_thumbprint: thumb,
        subject_sha1: subj,
    })
}

// ---- PKCS#7 SignedData / Authenticode --------------------------------------

/// The digest algorithm + embedded PE digest + certificates from a PKCS#7
/// Authenticode `SignedData`.
struct AuthContent {
    digest_alg: DigestAlg,
    message_digest: Vec<u8>,
    certs: Vec<CertInfo>,
}

/// Parse a PKCS#7 `SignedData` (Authenticode) blob.
fn parse_authenticode(pkcs7: &[u8]) -> Option<AuthContent> {
    // ContentInfo ::= SEQUENCE { contentType OID(signedData), content [0] SignedData }
    let ci = der::top(pkcs7)?;
    if ci.tag != der::SEQUENCE {
        return None;
    }
    let mut ci_children = der::children(ci.content);
    let content_type = ci_children.next()?;
    if content_type.tag != der::OID || content_type.content != OID_SIGNED_DATA {
        return None;
    }
    let content = ci_children.next()?; // [0] EXPLICIT
    let signed_data = der::children(content.content).next()?;
    if signed_data.tag != der::SEQUENCE {
        return None;
    }

    // SignedData ::= SEQUENCE { version INTEGER, digestAlgorithms SET,
    //   encapContentInfo SEQUENCE, certificates [0] OPTIONAL,
    //   crls [1] OPTIONAL, signerInfos SET }
    //
    // The first three fields are read BY POSITION, and their tags are checked.
    // Taking `encapContentInfo` to be "the first SEQUENCE child" instead lets a
    // blob that tags `digestAlgorithms` as a SEQUENCE substitute its own
    // structure for the real one, and the digest read out of it then decides
    // whether the signature is reported as covering the file. Position plus tag
    // is what an ASN.1 template does, so a blob rejected here is a blob a real
    // verifier rejects too.
    let sd: Vec<der::Tlv> = der::children(signed_data.content).collect();
    let version = sd.first()?;
    let digest_algorithms = sd.get(1)?;
    let encap = sd.get(2)?;
    if version.tag != der::INTEGER
        || digest_algorithms.tag != der::SET
        || encap.tag != der::SEQUENCE
    {
        return None;
    }
    let (digest_alg, message_digest) = parse_spc_digest(encap.content)?;

    // certificates [0] IMPLICIT: a concatenation of Certificate SEQUENCEs.
    let certs = sd
        .iter()
        .find(|t| t.tag == der::context(0))
        .map(|c| {
            der::children(c.content)
                .filter(|t| t.tag == der::SEQUENCE)
                .filter_map(|t| parse_certificate(t.full))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(AuthContent {
        digest_alg,
        message_digest,
        certs,
    })
}

/// From an `EncapsulatedContentInfo`, reach the `SpcIndirectDataContent`'s
/// `DigestInfo` and return `(alg, digest)`.
fn parse_spc_digest(encap_content: &[u8]) -> Option<(DigestAlg, Vec<u8>)> {
    // encapContentInfo: eContentType OID, eContent [0] EXPLICIT.
    let econtent = der::find(encap_content, der::context(0))?;
    // eContent wraps the SpcIndirectDataContent SEQUENCE, sometimes inside an
    // OCTET STRING (RFC 5652) and sometimes directly (classic Authenticode).
    let inner = der::read(econtent.content)?.0;
    let spc = if inner.tag == der::OCTET_STRING {
        der::read(inner.content)?.0
    } else {
        inner
    };
    if spc.tag != der::SEQUENCE {
        return None;
    }
    // SpcIndirectDataContent ::= SEQUENCE { data SEQUENCE, messageDigest DigestInfo }
    let mut it = der::children(spc.content);
    let _data = it.next()?;
    let digest_info = it.next()?; // DigestInfo SEQUENCE
    if digest_info.tag != der::SEQUENCE {
        return None;
    }
    // DigestInfo ::= SEQUENCE { digestAlgorithm SEQUENCE{OID,...}, digest OCTET STRING }
    let mut di = der::children(digest_info.content);
    let alg_id = di.next()?;
    let digest = di.next()?;
    if digest.tag != der::OCTET_STRING {
        return None;
    }
    let alg_oid = der::find(alg_id.content, der::OID)?;
    let alg = match alg_oid.content {
        OID_SHA1 => DigestAlg::Sha1,
        OID_SHA256 => DigestAlg::Sha256,
        _ => return None,
    };
    Some((alg, digest.content.to_vec()))
}

// ---- PE integration (reuses goblin) ----------------------------------------

/// Inspect a PE's Authenticode signature. Returns `None` if `data` is not a PE,
/// carries no PKCS#7 signature, or the signature can't be parsed. On `Some`, the
/// caller can act on `digest_matches` / `signer`.
pub fn analyze_pe(data: &[u8]) -> Option<PeSignature> {
    // Cheap gate before the (heavier) full PE parse.
    if data.len() < 2 || &data[..2] != b"MZ" {
        return None;
    }
    let pe = goblin::pe::PE::parse(data).ok()?;

    // The first PKCS#7 SignedData attribute certificate.
    let pkcs7 = pe.certificates.iter().find_map(|c| {
        (c.certificate_type
            == goblin::pe::certificate_table::AttributeCertificateType::PkcsSignedData)
            .then_some(c.certificate)
    })?;
    let auth = parse_authenticode(pkcs7)?;

    // Recompute the Authenticode hash over goblin's excluded-section ranges.
    let computed = match auth.digest_alg {
        DigestAlg::Sha1 => {
            let mut h = Sha1::new();
            for r in pe.authenticode_ranges() {
                h.update(r);
            }
            h.finalize().to_vec()
        }
        DigestAlg::Sha256 => {
            let mut h = Sha256::new();
            for r in pe.authenticode_ranges() {
                h.update(r);
            }
            h.finalize().to_vec()
        }
    };

    let signer = auth.certs.first().cloned()?;
    Some(PeSignature {
        digest_matches: computed == auth.message_digest,
        signer,
        certs: auth.certs,
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let p = format!(
            "{}/tests/fixtures/authenticode/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        crate::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
    }

    /// The vendored X.509 parser extracts the exact fields of a real
    /// openssl-generated self-signed certificate.
    #[test]
    fn parses_self_signed_cert_fields() {
        let der = fixture("cert.der");
        let c = parse_certificate(&der).expect("parse cert");
        assert_eq!(c.subject_cn.as_deref(), Some("exav Test Signer"));
        assert_eq!(c.issuer_cn.as_deref(), Some("exav Test Signer"));
        assert!(c.self_signed, "issuer==subject ⇒ self-signed");
        // openssl: serial 1199228E75C4EE36E17FA8970EA883E130AABEAD
        assert!(
            c.serial_hex
                .ends_with("1199228e75c4ee36e17fa8970ea883e130aabead")
                || c.serial_hex
                    .contains("1199228e75c4ee36e17fa8970ea883e130aabead"),
            "serial was {}",
            c.serial_hex
        );
        // openssl sha1 fingerprint 470304B86A0CE5CD5ED8C1C330E5D31CCBFDAD08
        let tp = hex(&c.sha1_thumbprint);
        assert_eq!(tp, "470304b86a0ce5cd5ed8c1c330e5d31ccbfdad08");
    }

    /// The PKCS#7 SignedData / SpcIndirectData reader recovers the embedded PE
    /// digest, its algorithm, and the signer certificate.
    #[test]
    fn parses_pkcs7_signeddata() {
        let p7 = fixture("signeddata.p7b");
        let a = parse_authenticode(&p7).expect("parse SignedData");
        assert_eq!(a.digest_alg, DigestAlg::Sha256);
        // sha256("hello authenticode")
        assert_eq!(
            hex(&a.message_digest),
            "8fb039682185b94da84d23a74dd7e7c0ea9184a5480be68e04663ccd3f73bf8a"
        );
        assert_eq!(a.certs.len(), 1);
        assert_eq!(a.certs[0].subject_cn.as_deref(), Some("exav Test Signer"));
        assert!(a.certs[0].self_signed);
    }

    /// `encapContentInfo` is the THIRD field of `SignedData`, not "the first
    /// child that happens to be a SEQUENCE".
    ///
    /// Retagging `digestAlgorithms` from SET to SEQUENCE puts an attacker-chosen
    /// structure in front of the real `encapContentInfo`. A by-tag search reads
    /// its digest instead of the signature's, and that digest is what decides
    /// whether the signature is reported as covering the file. A real verifier
    /// walks the template positionally and rejects the blob, so exav does too.
    #[test]
    fn a_retagged_digest_algorithms_field_cannot_stand_in_for_encap() {
        let p7 = fixture("signeddata.p7b");
        assert!(parse_authenticode(&p7).is_some(), "the fixture must parse");

        // Locate the digestAlgorithms SET inside the buffer by walking the same
        // structure the parser walks.
        let ci = der::top(&p7).expect("ContentInfo");
        let mut ci_children = der::children(ci.content);
        let _content_type = ci_children.next().expect("contentType");
        let content = ci_children.next().expect("[0] content");
        let signed_data = der::children(content.content).next().expect("SignedData");
        let sd: Vec<der::Tlv> = der::children(signed_data.content).collect();
        let algs = sd.get(1).expect("digestAlgorithms");
        assert_eq!(algs.tag, der::SET, "field 2 of SignedData is a SET");
        let at = algs.full.as_ptr() as usize - p7.as_ptr() as usize;

        let mut tampered = p7.clone();
        tampered[at] = der::SEQUENCE;
        assert!(
            parse_authenticode(&tampered).is_none(),
            "a SignedData whose second field is not a SET is malformed; parsing \
             it anyway lets the wrong element supply the embedded digest"
        );
    }

    /// A `.crb` block entry matches the fixture signer certificate by subject
    /// hash (+ optional serial); trusted entries and non-matches don't fire.
    #[test]
    fn crb_blocklist_matches_signer_cert() {
        let cert = parse_certificate(&fixture("cert.der")).unwrap();
        let subj = hex(&cert.subject_sha1); // 2c190fb7…
        assert_eq!(subj, "2c190fb742c4be7399e7706dd24610807dc9860c");

        // Subject-only block entry matches.
        let mut db = CrbDb::default();
        db.parse_into(&format!("Blocked.Signer;0;{subj};;;;;;;;stolen cert"));
        assert_eq!(db.blocked(&cert), Some("Blocked.Signer"));

        // Subject + matching serial matches; a wrong serial does not.
        let mut db = CrbDb::default();
        db.parse_into(&format!("Blocked.Serial;0;{subj};{}", cert.serial_hex));
        assert_eq!(db.blocked(&cert), Some("Blocked.Serial"));
        let mut db = CrbDb::default();
        db.parse_into(&format!("No.Match;0;{subj};deadbeef"));
        assert_eq!(db.blocked(&cert), None);

        // A trusted (whitelist) entry is ignored; a different subject misses.
        let mut db = CrbDb::default();
        db.parse_into(&format!("Trusted.Signer;1;{subj};")); // trusted → not stored
        db.parse_into("Other;0;00112233445566778899aabbccddeeff00112233;");
        assert!(!db.is_empty(), "the 'Other' block entry is stored");
        assert!(
            db.blocked(&cert).is_none(),
            "no block entry matches this cert"
        );
    }

    /// Not-a-PE / unsigned input yields `None`, never a panic.
    #[test]
    fn analyze_pe_handles_non_pe() {
        assert!(analyze_pe(b"not a pe").is_none());
        assert!(analyze_pe(&[]).is_none());
        assert!(analyze_pe(b"MZ\x00\x00garbage").is_none());
    }

    /// End-to-end: a PE whose embedded Authenticode digest is of *other* bytes
    /// (not this file) is detected as a signature that does NOT cover the file —
    /// the append-after-signing / tampering signal — while the signer identity is
    /// still recovered. Exercises goblin cert discovery + the vendored parser +
    /// the hash recompute + mismatch detection.
    #[test]
    fn analyze_pe_detects_digest_mismatch() {
        let pe = fixture("signed_mismatch.exe");
        let sig = analyze_pe(&pe).expect("signed PE must parse");
        assert!(
            !sig.digest_matches,
            "embedded digest is of unrelated bytes ⇒ must NOT match the file"
        );
        assert_eq!(sig.signer.subject_cn.as_deref(), Some("exav Test Signer"));
        assert!(sig.signer.self_signed);
    }
}
