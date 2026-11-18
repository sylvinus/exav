//! Authenticode (PE code-signing) inspection: **triage without RSA**.
//!
//! A signed PE carries a PKCS#7 `SignedData` blob (in the certificate table)
//! whose `SpcIndirectDataContent` embeds a digest of the file. We extract that
//! digest and the signer certificate fields, and recompute the PE's Authenticode
//! hash, using only:
//!   * `goblin` (already a dependency) for the headers, from which the byte
//!     ranges to hash follow (as [`goblin::pe::PE::authenticode_ranges`] has
//!     them), the certificate table being read from the file where they say;
//!   * `sha1`/`sha2` (already dependencies) for the hash + thumbprint;
//!   * a small **vendored** DER reader (the `der` module), so no `rsa`/`der`/`x509`/`nom`
//!     crate enters the tree and everything stays `#![forbid(unsafe_code)]`.
//!
//! What this gives, with no signature-verification crypto:
//!   * **digest-covers-file**: recomputed hash vs the embedded digest. A mismatch
//!     means the file was modified/appended-to after signing, a strong signal.
//!   * signer identity (subject/issuer CN, serial, SHA-1 thumbprint) and whether
//!     the leaf is **self-signed**, for reporting and `.crb` cert matching.
//!
//! What it does not do yet: verify that the digest was actually signed by the
//! certificate's private key. That needs RSA/ECDSA (see `docs/DEPENDENCIES.md`),
//! and is on the roadmap.

mod der;

use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::byte_source::ByteSource;

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
    /// SHA-1 of the subject `Name` DER (tag+length+value): the key a ClamAV
    /// `.crb` entry matches its `Subject` field against.
    pub subject_sha1: [u8; 20],
}

/// The result of inspecting a PE's Authenticode signature.
#[derive(Clone, Debug)]
pub struct PeSignature {
    /// The recomputed Authenticode hash equals the digest embedded in the
    /// signature, i.e. the signature covers the current file bytes. `false`
    /// when the scan did not ask for the hash.
    pub digest_matches: bool,
    /// The signer (leaf) certificate.
    pub signer: CertInfo,
    /// Every certificate embedded in the signature (leaf + chain).
    pub certs: Vec<CertInfo>,
}

// ---- .crb certificate block-list -------------------------------------------

/// One parsed `.crb` line (ClamAV certificate database).
#[derive(Debug)]
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
/// them safely would require verifying the RSA signature chain (out of scope;
/// see the module docs).
#[derive(Default, Debug)]
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
    /// Malformed lines are skipped (best effort: a bad line never aborts a load).
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
            if let Some(ref ser) = e.serial
                && ser.trim_start_matches('0') != cser
            {
                continue;
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
    inspect(&data, true, usize::MAX).ok().flatten()
}

/// [`analyze_pe`] of the PE in `src`, which need not be held in memory: its
/// headers and certificate table are read, and the digest is made in one pass
/// over it, so a PE of any size costs no more memory than those two.
///
/// `digest` asks for that pass. Without it `digest_matches` is `false`, and
/// the signature's certificates are all that is read.
///
/// `Err` holds the size of the headers or the certificate table when it is
/// over `limit` bytes: it was not read, and there is no answer.
pub(crate) fn inspect(
    src: &dyn ByteSource,
    digest: bool,
    limit: usize,
) -> Result<Option<PeSignature>, usize> {
    let Some(end) = crate::pe::headers_end(src) else {
        return Ok(None);
    };
    if end > limit {
        return Err(end);
    }
    let head = src.window(0, end);
    let Some(pe) = crate::pe::headers(&head) else {
        return Ok(None);
    };
    let Some(&table) = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|o| o.data_directories.get_certificate_table())
    else {
        return Ok(None);
    };
    // The table's address is a file offset, not an RVA. One that does not fit
    // the file is not a signature.
    let (at, size) = (table.virtual_address as usize, table.size as usize);
    if at.checked_add(size).is_none_or(|end| end > src.len()) {
        return Ok(None);
    }
    if size > limit {
        return Err(size);
    }
    let table_bytes = src.window(at, size);
    let Some(auth) = first_signed_data(&table_bytes).and_then(parse_authenticode) else {
        return Ok(None);
    };
    let Some(signer) = auth.certs.first().cloned() else {
        return Ok(None);
    };
    // An image whose layout does not hold together has no hash to match: the
    // signature cannot cover it.
    let digest_matches = digest
        && hashed_ranges(&pe, src.len(), size).is_some_and(|(ranges, padding)| {
            let computed = match auth.digest_alg {
                DigestAlg::Sha1 => hash_ranges::<Sha1>(src, &ranges, padding),
                DigestAlg::Sha256 => hash_ranges::<Sha256>(src, &ranges, padding),
            };
            computed.is_some_and(|c| c == auth.message_digest)
        });
    Ok(Some(PeSignature {
        digest_matches,
        signer,
        certs: auth.certs,
    }))
}

/// The first PKCS#7 `SignedData` in an attribute certificate table: entries
/// of a `WIN_CERTIFICATE` header (length, revision, type) and their data, each
/// padded to 8 bytes. Entries are read in order up to the first that does not
/// fit or has no known revision and type, so a malformed entry cannot hide
/// those before it.
fn first_signed_data(table: &[u8]) -> Option<&[u8]> {
    const REVISIONS: [u16; 2] = [0x0100, 0x0200];
    const PKCS_SIGNED_DATA: u16 = 2;
    let mut at = 0usize;
    while let Some(header) = table.get(at..at.checked_add(8)?) {
        let length = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let revision = u16::from_le_bytes([header[4], header[5]]);
        let kind = u16::from_le_bytes([header[6], header[7]]);
        let size = length.saturating_sub(8);
        let data = table.get(at + 8..(at + 8).checked_add(size)?)?;
        if !REVISIONS.contains(&revision) || !(1..=4).contains(&kind) {
            return None;
        }
        if kind == PKCS_SIGNED_DATA {
            return Some(data);
        }
        at = (at + 8 + size).checked_add(7)? & !7;
    }
    None
}

/// The byte ranges the Authenticode hash covers ("Calculating the PE Image
/// Hash" in the PE/COFF specification) as file offsets `(start, end)`, in the
/// order goblin's `authenticode_ranges` yields them, then the zero bytes that
/// pad the whole to a multiple of 8. `None` for an image whose headers,
/// sections or certificate table (of `cert_size` bytes) do not fit a file of
/// `len` bytes, or whose ranges add up to more than that: each byte of an
/// image that holds together is hashed once, and sections that name one region
/// as many times over make the hash cost that much more.
fn hashed_ranges(
    pe: &crate::pe::Headers<'_>,
    len: usize,
    cert_size: usize,
) -> Option<(Vec<(usize, usize)>, usize)> {
    let opt = pe.header.optional_header.as_ref()?;
    // Past the PE signature and the COFF header. The checksum field sits at
    // the same offset in PE32 and PE32+; the certificate table entry does not.
    let opt_off = (pe.header.dos_header.pe_pointer as usize).checked_add(4 + 20)?;
    let checksum = opt_off.checked_add(64)?;
    let wide = opt.standard_fields.magic == 0x20b;
    let cert_entry = opt_off.checked_add(if wide { 144 } else { 128 })?;
    let headers = opt.windows_fields.size_of_headers as usize;
    let mut out = vec![
        (0, checksum),
        (checksum.checked_add(4)?, cert_entry),
        (cert_entry.checked_add(8)?, headers),
    ];
    let mut sections: Vec<_> = pe
        .sections
        .iter()
        .filter(|s| s.size_of_raw_data != 0)
        .collect();
    sections.sort_by_key(|s| s.pointer_to_raw_data);
    let mut hashed = headers;
    for s in sections {
        let start = s.pointer_to_raw_data as usize;
        let size = s.size_of_raw_data as usize;
        out.push((start, start.checked_add(size)?));
        hashed = hashed.checked_add(size)?;
    }
    // What follows the last section, less the certificate table.
    if len > hashed {
        out.push((hashed, len.checked_sub(cert_size)?));
    }
    let fits = out.iter().all(|&(start, end)| start <= end && end <= len);
    // Summed once they are known to be in order, so no length is negative.
    let total = |out: &[(usize, usize)]| out.iter().map(|&(a, b)| (b - a) as u64).sum::<u64>();
    (fits && total(&out) <= len as u64).then_some((out, (8 - len % 8) % 8))
}

/// The digest `D` of `ranges` of `src`, read a chunk at a time, then `padding`
/// zero bytes. `None` if the source gave less than they hold.
fn hash_ranges<D: Digest>(
    src: &dyn ByteSource,
    ranges: &[(usize, usize)],
    padding: usize,
) -> Option<Vec<u8>> {
    let mut h = D::new();
    for &(start, end) in ranges {
        let mut got = 0;
        src.chunks(start, end, &mut |_, chunk| {
            h.update(chunk);
            got += chunk.len();
            true
        });
        if got != end - start {
            return None;
        }
    }
    h.update(&[0u8; 7][..padding]);
    Some(h.finalize().to_vec())
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
    /// (not this file) is detected as a signature that does NOT cover the file
    /// (the append-after-signing / tampering signal), while the signer identity is
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

    /// The ranges hashed are goblin's for a well-formed image, and a signed
    /// image whose section runs past the end of the file, on which goblin
    /// panics, is a signature that does not cover it.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "a panic aborts under WASI, so goblin's cannot be caught"
    )]
    fn hashed_ranges_follow_goblin_and_refuse_what_does_not_fit() {
        let pe = fixture("signed_mismatch.exe");
        let parsed = goblin::pe::PE::parse(&pe).unwrap();
        let want: Vec<u8> = parsed.authenticode_ranges().flatten().copied().collect();
        let head = crate::pe::headers(&pe).unwrap();
        let cert_size = parsed
            .header
            .optional_header
            .unwrap()
            .data_directories
            .get_certificate_table()
            .unwrap()
            .size;
        let (ranges, padding) = hashed_ranges(&head, pe.len(), cert_size as usize).unwrap();
        let mut got: Vec<u8> = ranges
            .iter()
            .flat_map(|&(a, b)| pe[a..b].iter().copied())
            .collect();
        got.resize(got.len() + padding, 0);
        assert_eq!(got, want);

        let mut bad = pe.clone();
        let at = u32::from_le_bytes(bad[0x3c..0x40].try_into().unwrap()) as usize;
        let opt_len = u16::from_le_bytes(bad[at + 20..at + 22].try_into().unwrap()) as usize;
        let first = at + 24 + opt_len;
        bad[first + 20..first + 24].copy_from_slice(&0xE727_0000u32.to_le_bytes());
        let parsed = goblin::pe::PE::parse(&bad).expect("goblin still parses it");
        let goblin_ranges = std::panic::AssertUnwindSafe(|| parsed.authenticode_ranges().count());
        assert!(
            std::panic::catch_unwind(goblin_ranges).is_err(),
            "goblin no longer panics here, so this image tests nothing"
        );
        let sig = analyze_pe(&bad).expect("the signature is still there");
        assert!(!sig.digest_matches);
    }

    /// The fixture with the digest its signature carries replaced by the one
    /// of the file (the certificate table is not part of it).
    fn covering(pe: &[u8]) -> Vec<u8> {
        let parsed = goblin::pe::PE::parse(pe).unwrap();
        let mut h = Sha256::new();
        parsed.authenticode_ranges().for_each(|r| h.update(r));
        let digest = h.finalize();
        let mut out = pe.to_vec();
        let was = Sha256::digest(b"hello authenticode");
        let at = out
            .windows(32)
            .position(|w| w == was.as_slice())
            .expect("the fixture's digest");
        out[at..at + 32].copy_from_slice(&digest);
        out
    }

    fn cached(data: &[u8]) -> crate::byte_source::BlockCache<std::io::Cursor<Vec<u8>>> {
        crate::byte_source::BlockCache::with_sizes(
            std::io::Cursor::new(data.to_vec()),
            509,
            8 * 509,
        )
        .unwrap()
    }

    /// A source is inspected as the bytes it holds are: the same signer, and
    /// a digest that matches when it covers the file, hashed only when asked.
    #[test]
    fn a_source_is_inspected_as_the_bytes_it_holds() {
        let mismatch = fixture("signed_mismatch.exe");
        let covered = covering(&mismatch);
        for (pe, matches) in [(&mismatch, false), (&covered, true)] {
            let want = analyze_pe(pe).expect("signed");
            assert_eq!(want.digest_matches, matches);
            let got = inspect(&cached(pe), true, 1 << 20)
                .unwrap()
                .expect("signed");
            assert_eq!(got.digest_matches, matches);
            assert_eq!(got.signer.sha1_thumbprint, want.signer.sha1_thumbprint);
            assert_eq!(got.certs.len(), want.certs.len());
            // Not asked for, not made.
            let none = inspect(&cached(pe), false, 1 << 20)
                .unwrap()
                .expect("signed");
            assert!(!none.digest_matches);
            assert_eq!(none.signer.sha1_thumbprint, want.signer.sha1_thumbprint);
        }
    }

    /// The hash is of what the object holds: a byte changed anywhere, in the
    /// headers, a section or after the sections, and it no longer matches.
    #[test]
    fn the_digest_is_of_the_whole_file() {
        let covered = covering(&fixture("signed_mismatch.exe"));
        // The checksum is not hashed.
        for at in [0x58 + 64, 0x58 + 66] {
            let mut same = covered.clone();
            same[at] ^= 1;
            assert!(
                inspect(&cached(&same), true, 1 << 20)
                    .unwrap()
                    .unwrap()
                    .digest_matches,
                "{at:#x}"
            );
        }
        // The DOS header, the optional header, the section table, and the
        // first and the last byte of the section.
        for at in [0x20, 0x58 + 20, 0x58 + 0xe0 + 8, 0x200, 0x3ff] {
            let mut changed = covered.clone();
            changed[at] ^= 1;
            let sig = inspect(&cached(&changed), true, 1 << 20).unwrap().unwrap();
            assert!(!sig.digest_matches, "{at:#x}");
        }
    }

    /// Nothing is read of what is over the limit: the answer is its size.
    #[test]
    fn headers_and_a_table_over_the_limit_are_not_read() {
        let pe = fixture("signed_mismatch.exe");
        // Headers end at 0x160, the table is 952 bytes.
        assert_eq!(inspect(&cached(&pe), true, 100).err(), Some(0x160));
        assert_eq!(inspect(&cached(&pe), true, 400).err(), Some(952));
        assert!(inspect(&cached(&pe), true, 952).unwrap().is_some());
        // An object with no table, or that is not a PE, is not signed.
        assert!(
            inspect(&cached(b"MZ not a pe"), true, 100)
                .unwrap()
                .is_none()
        );
        assert!(
            inspect(&cached(&pe[..0x200]), true, 100_000)
                .unwrap()
                .is_none()
        );
    }

    /// A hash is of each byte of the image once, not of a region as many times
    /// as sections name it: that costs a crafted file as much as it likes.
    #[test]
    fn sections_that_name_more_than_the_file_have_no_hash() {
        let pe = fixture("signed_mismatch.exe");
        let cert_size = 952;
        // The section table has room before `SizeOfHeaders` for more entries:
        // `n` copies of `.text`, each with a raw size of `size` at 0x200.
        let with_sections = |n: u16, size: u32| {
            let mut f = pe.clone();
            let sh = 0x138;
            f[sh + 16..sh + 20].copy_from_slice(&size.to_le_bytes());
            for i in 1..usize::from(n) {
                f.copy_within(sh..sh + 40, sh + 40 * i);
            }
            f[0x46..0x48].copy_from_slice(&n.to_le_bytes());
            f
        };
        // One section of the file's, which the cert table follows; then two of
        // 0x400 bytes, which each fit the file, and are 2 KiB over it.
        for (n, size, hashed) in [(1, 0x200, true), (2, 0x400, false)] {
            let f = with_sections(n, size);
            let head = crate::pe::headers(&f).unwrap();
            assert_eq!(
                hashed_ranges(&head, f.len(), cert_size).is_some(),
                hashed,
                "{n} sections"
            );
        }
    }

    fn entry(kind: u16, revision: u16, body: &[u8]) -> Vec<u8> {
        let mut e = ((8 + body.len()) as u32).to_le_bytes().to_vec();
        e.extend(revision.to_le_bytes());
        e.extend(kind.to_le_bytes());
        e.extend(body);
        e.resize(e.len().next_multiple_of(8), 0);
        e
    }

    /// The signed data is the first PKCS entry of the table, and a malformed
    /// entry hides the ones before it from no one.
    #[test]
    fn the_signed_data_is_the_first_pkcs_entry_before_a_malformed_one() {
        let table = [
            entry(1, 0x200, b"x509"),
            entry(2, 0x200, b"first"),
            entry(2, 0x200, b"second"),
        ]
        .concat();
        assert_eq!(first_signed_data(&table), Some(&b"first"[..]));
        let bad = entry(2, 0x300, b"a revision there is not");
        assert_eq!(
            first_signed_data(&[entry(2, 0x100, b"first"), bad.clone()].concat()),
            Some(&b"first"[..])
        );
        assert_eq!(
            first_signed_data(&[entry(1, 0x200, b"x"), bad, entry(2, 0x200, b"later")].concat()),
            None
        );
        // A type there is not, a length past the table's end, and nothing at all.
        assert_eq!(first_signed_data(&entry(9, 0x200, b"first")), None);
        let mut cut = entry(2, 0x200, b"0123456789");
        cut.truncate(12);
        assert_eq!(first_signed_data(&cut), None);
        assert_eq!(first_signed_data(&[]), None);
        // An entry with no data is passed, and the walk goes on.
        assert_eq!(
            first_signed_data(&[entry(1, 0x200, b""), entry(2, 0x200, b"first")].concat()),
            Some(&b"first"[..])
        );
    }
}
