//! Archive extraction with decompression-bomb limits.
//!
//! Extraction is bounded by a [`Budget`] (total output bytes, file count,
//! recursion depth, compression ratio). Hitting a bound returns [`LimitHit`],
//! which the caller maps to `LimitsExceeded`.
//!
//! The budget is reserved *before* each member is read, and each read is
//! capped to the bytes still remaining, so peak memory across an archive
//! (and across nested archives sharing the budget) never exceeds
//! `max_total_bytes`. Input is a buffer already in memory, so ZIP's random
//! access is served by a `Cursor`. Nested archives are handled by the caller
//! recursing on each returned [`Entry`].

use std::io::Read;

mod formats;
use formats::*;
pub use formats::ZipMembers;


/// Limits governing recursive extraction.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_recursion: u32,
    pub max_files: u64,
    /// Cap on the total decompressed bytes across the whole (recursive)
    /// extraction. Bounds peak memory.
    pub max_total_bytes: u64,
    /// Max output/input size ratio for a single compressed stream.
    pub max_ratio: u64,
    /// Per-member output cap.
    pub max_entry_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_recursion: 16,
            max_files: 10_000,
            max_total_bytes: 1024 * 1024 * 1024, // 1 GiB extracted total
            max_ratio: 1000,
            max_entry_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Mutable extraction budget, shared across the recursion.
pub struct Budget {
    pub limits: Limits,
    pub files: u64,
    pub total_out: u64,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            files: 0,
            total_out: 0,
        }
    }

    /// Count one archive member toward the file-count budget. Called for
    /// every entry encountered — including directories and skipped entries —
    /// so a huge directory-only archive still trips the cap.
    pub fn count_entry(&mut self) -> Result<(), LimitHit> {
        self.files += 1;
        if self.files > self.limits.max_files {
            return Err(LimitHit::new(format!(
                "file count > {}",
                self.limits.max_files
            )));
        }
        Ok(())
    }

    /// Maximum bytes the next member may decompress to: the smaller of the
    /// per-member cap and the bytes still left in the total budget. Fails if
    /// the total budget is already exhausted.
    pub fn reserve(&mut self) -> Result<u64, LimitHit> {
        let remaining = self.limits.max_total_bytes.saturating_sub(self.total_out);
        if remaining == 0 {
            return Err(LimitHit::new(format!(
                "extracted bytes > {}",
                self.limits.max_total_bytes
            )));
        }
        Ok(remaining.min(self.limits.max_entry_bytes))
    }

    pub fn commit(&mut self, n: u64) {
        self.total_out = self.total_out.saturating_add(n);
    }
}

/// A decompression limit was hit (treated as a bomb / unscanned region).
#[derive(Debug, Clone)]
pub struct LimitHit {
    pub reason: String,
}

impl LimitHit {
    fn new(reason: String) -> Self {
        Self { reason }
    }
}

/// One extracted member.
#[derive(Debug)]
pub struct Entry {
    pub name: String,
    pub data: Vec<u8>,
    /// Compressed size within the container (for `.cdb` matching); defaults to
    /// the decompressed length when the extractor can't report it.
    pub comp_size: u64,
    /// Whether the member is stored encrypted (`.cdb` `IsEncrypted`).
    pub encrypted: bool,
}

impl Entry {
    /// An entry whose compressed size is unknown (use the decompressed length)
    /// and which is not encrypted — the common case.
    pub fn new(name: String, data: Vec<u8>) -> Self {
        Entry {
            comp_size: data.len() as u64,
            encrypted: false,
            name,
            data,
        }
    }
}

/// A container/archive format this crate can extract embedded files from
/// (archives plus structured documents: OLE2, PDF, MIME email).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    Gzip,
    Tar,
    Bzip2,
    Xz,
    Cab,
    Ole,
    Pdf,
    Email,
    SevenZip,
    Iso,
    Lha,
    /// UPX-packed PE/ELF/Mach-O (decompress the embedded original).
    Upx,
}

/// Best-effort detection of an extractable container by magic bytes. Returns
/// `None` for content this crate can't unpack. Callers with a richer file-type
/// classifier may map to [`Format`] themselves instead of using this.
pub fn detect(data: &[u8]) -> Option<Format> {
    if data.len() >= 4 && &data[..2] == b"PK" && matches!(data[2..4], [3, 4] | [5, 6] | [7, 8]) {
        return Some(Format::Zip);
    }
    if data.starts_with(&[0x1f, 0x8b]) {
        return Some(Format::Gzip);
    }
    if data.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return Some(Format::SevenZip);
    }
    if data.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some(Format::Xz);
    }
    if data.starts_with(b"BZh") {
        return Some(Format::Bzip2);
    }
    if data.starts_with(b"MSCF") {
        return Some(Format::Cab);
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return Some(Format::Ole);
    }
    if data.starts_with(b"%PDF-") {
        return Some(Format::Pdf);
    }
    if data.len() >= 263 && &data[257..262] == b"ustar" {
        return Some(Format::Tar);
    }
    if data.len() >= 7 && data[2] == b'-' && data[6] == b'-' && matches!(data[3], b'l' | b'p') {
        return Some(Format::Lha);
    }
    if data.len() >= 32774 && &data[32769..32774] == b"CD001" {
        return Some(Format::Iso);
    }
    None
}

/// Extract the immediate members of a container buffer (one level) under the
/// budget.
pub fn extract(fmt: Format, data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    match fmt {
        Format::Gzip => extract_gzip(data, budget),
        Format::Tar => extract_tar(data, budget),
        Format::Zip => extract_zip(data, budget),
        Format::Bzip2 => extract_bzip2(data, budget),
        Format::Xz => extract_xz(data, budget),
        Format::Cab => extract_cab(data, budget),
        Format::Ole => extract_ole(data, budget),
        Format::Pdf => extract_pdf(data, budget),
        Format::Email => extract_email(data, budget),
        Format::SevenZip => extract_7z(data, budget),
        Format::Iso => extract_iso(data, budget),
        Format::Lha => extract_lha(data, budget),
        Format::Upx => extract_upx(data, budget),
    }
}

/// True if `data` looks like a UPX-packed executable (a valid `PackHeader` is
/// present). Used by callers whose file-type classifier already recognises
/// PE/ELF/Mach-O and wants to additionally unpack UPX.
pub fn is_upx(data: &[u8]) -> bool {
    find_packheader(data).is_some()
}







/// Reject a stream whose decompressed size dwarfs its declared input size.
/// Absolute byte caps are the primary bomb defense; this is a fast reject
/// for the obvious cases. A declared input of 0 is ignored (we cannot trust
/// it) and left to the absolute caps.
pub(crate) fn ratio_guard(input: u64, output: u64, budget: &Budget) -> Result<(), LimitHit> {
    if input > 0 && output / input > budget.limits.max_ratio {
        return Err(LimitHit::new(format!(
            "compression ratio {} > {}",
            output / input,
            budget.limits.max_ratio
        )));
    }
    Ok(())
}

/// Read up to `cap` bytes; the returned flag is true if the source had more
/// (so the caller can treat it as exceeding the budget rather than silently
/// truncating).
pub fn bounded_read<R: Read>(mut r: R, cap: u64) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut buf = Vec::new();
    (&mut r).take(cap.saturating_add(1)).read_to_end(&mut buf)?;
    let truncated = buf.len() as u64 > cap;
    if truncated {
        buf.truncate(cap as usize);
    }
    Ok((buf, truncated))
}





/// A `Write` sink bounded to `cap` bytes; sets `over` and errors once exceeded,
/// so a writer-based decoder (lzma-rs) can't decode a bomb past the budget.
pub(crate) struct CapWriter {
    pub(crate) buf: Vec<u8>,
    cap: usize,
    pub(crate) over: bool,
}

impl CapWriter {
    pub(crate) fn new(cap: u64) -> Self {
        Self {
            buf: Vec::new(),
            cap: cap.min(usize::MAX as u64) as usize,
            over: false,
        }
    }
}

impl std::io::Write for CapWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() + data.len() > self.cap {
            // `saturating_sub` + `min`: if a decoder writes again after the cap
            // error (buf already at/over cap), `take` is 0 rather than an
            // underflow panic.
            let take = self.cap.saturating_sub(self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            self.over = true;
            return Err(std::io::Error::other("output cap exceeded"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}






#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{Cursor, Write};

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            for (name, data) in members {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, *data).unwrap();
            }
            b.finish().unwrap();
        }
        buf
    }

    #[test]
    fn gzip_roundtrip() {
        let payload = b"hello exav inside gzip";
        let blob = gz(payload);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Gzip, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn gzip_bomb_trips_ratio() {
        let blob = gz(&vec![0u8; 50 * 1024 * 1024]);
        let mut budget = Budget::new(Limits {
            max_ratio: 100,
            ..Default::default()
        });
        let err = extract(Format::Gzip, &blob, &mut budget).unwrap_err();
        assert!(err.reason.contains("ratio"), "got: {}", err.reason);
    }

    #[test]
    fn total_bytes_budget_enforced() {
        let blob = gz(&vec![b'A'; 4096]);
        let mut budget = Budget::new(Limits {
            max_total_bytes: 1024,
            max_ratio: u64::MAX,
            ..Default::default()
        });
        let err = extract(Format::Gzip, &blob, &mut budget).unwrap_err();
        assert!(err.reason.contains("exceeds budget") || err.reason.contains("extracted"));
    }

    // Regression for the "many members each allocating before accounting"
    // OOM (review finding C3): the total budget must bound the sum of all
    // members, not just trip after the fact.
    #[test]
    fn many_members_bounded_by_total() {
        let big = vec![b'X'; 200_000];
        let members: Vec<(&str, &[u8])> = (0..50).map(|_| ("m", big.as_slice())).collect();
        let blob = tar_of(&members);
        // total budget only allows ~3 members' worth.
        let mut budget = Budget::new(Limits {
            max_total_bytes: 600_000,
            max_entry_bytes: 200_000,
            max_ratio: u64::MAX,
            ..Default::default()
        });
        let err = extract(Format::Tar, &blob, &mut budget).unwrap_err();
        assert!(err.reason.contains("budget") || err.reason.contains("extracted"));
        // never accounted more than the cap (+ at most one in-flight member)
        assert!(budget.total_out <= 600_000);
    }

    #[test]
    fn bzip2_roundtrip() {
        // Fixed bzip2 stream of "hello exav inside bzip2" (bzip2-rs decodes only).
        let blob: &[u8] = &[
            66, 90, 104, 57, 49, 65, 89, 38, 83, 89, 213, 127, 182, 220, 0, 0, 5, 25, 128, 64, 0,
            16, 0, 54, 101, 201, 80, 32, 0, 49, 76, 0, 19, 66, 154, 105, 163, 77, 168, 242, 145,
            94, 233, 129, 65, 248, 112, 129, 150, 100, 114, 190, 46, 228, 138, 112, 161, 33, 170,
            255, 109, 184,
        ];
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Bzip2, blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"hello exav inside bzip2");
    }

    #[test]
    fn xz_roundtrip_and_bomb() {
        let payload = b"hello exav inside xz";
        let mut blob = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(payload), &mut blob).unwrap();
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xz, &blob, &mut budget).unwrap();
        assert_eq!(entries[0].data, payload);

        // A compressible bomb must trip the total-bytes cap, not decode fully.
        let mut bomb = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(vec![0u8; 4096].as_slice()), &mut bomb).unwrap();
        let mut budget = Budget::new(Limits {
            max_total_bytes: 1024,
            max_ratio: u64::MAX,
            ..Default::default()
        });
        let err = extract(Format::Xz, &bomb, &mut budget).unwrap_err();
        assert!(err.reason.contains("budget") || err.reason.contains("extracted"));
    }

    #[test]
    fn cab_roundtrip() {
        // Build a small uncompressed cabinet, then extract it.
        let mut builder = cab::CabinetBuilder::new();
        let folder = builder.add_folder(cab::CompressionType::None);
        folder.add_file("payload.txt");
        let mut blob = Vec::new();
        let mut writer = builder.build(Cursor::new(&mut blob)).unwrap();
        while let Some(mut w) = writer.next_file().unwrap() {
            std::io::Write::write_all(&mut w, b"hello exav inside cab").unwrap();
        }
        writer.finish().unwrap();

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Cab, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "payload.txt");
        assert_eq!(entries[0].data, b"hello exav inside cab");
    }

    const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

    fn has_eicar(entries: &[Entry]) -> bool {
        entries
            .iter()
            .any(|e| e.data.windows(4).any(|w| w == b"X5O!"))
    }

    #[test]
    fn ole_streams_extracted() {
        // Build an OLE2/CFB with a stream holding EICAR, then extract it.
        let mut buf = Cursor::new(Vec::new());
        {
            let mut comp = cfb::CompoundFile::create(&mut buf).unwrap();
            comp.create_storage("Macros").unwrap();
            let mut s = comp.create_stream("Macros/Module1").unwrap();
            std::io::Write::write_all(&mut s, EICAR).unwrap();
        }
        let data = buf.into_inner();
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Ole, &data, &mut budget).unwrap();
        assert!(has_eicar(&entries), "EICAR not found in OLE streams");
    }

    #[test]
    fn pdf_stream_extracted() {
        use lopdf::{dictionary, Document, Object, Stream};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let content_id = doc.add_object(Stream::new(dictionary! {}, EICAR.to_vec()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pdf, &out, &mut budget).unwrap();
        assert!(has_eicar(&entries), "EICAR not found in PDF streams");
    }

    #[test]
    fn email_attachment_extracted() {
        // base64(EICAR) attachment in a multipart message.
        let b64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=";
        let msg = format!(
            "From: a@b\r\nTo: c@d\r\nSubject: x\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
             --BB\r\nContent-Type: text/plain\r\n\r\nhello\r\n\
             --BB\r\nContent-Type: application/octet-stream\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BB--\r\n"
        );
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Email, msg.as_bytes(), &mut budget).unwrap();
        assert!(has_eicar(&entries), "EICAR not found in email parts");
    }

    #[test]
    fn file_count_capped() {
        let members: Vec<(&str, &[u8])> = (0..20).map(|_| ("e", b"x".as_slice())).collect();
        let blob = tar_of(&members);
        let mut budget = Budget::new(Limits {
            max_files: 5,
            ..Default::default()
        });
        let err = extract(Format::Tar, &blob, &mut budget).unwrap_err();
        assert!(err.reason.contains("file count"));
    }

    #[test]
    fn sevenz_roundtrip() {
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
        let payload = b"hello exav inside 7zip archive";
        let mut sink = Cursor::new(Vec::new());
        {
            let mut w = ArchiveWriter::new(&mut sink).unwrap();
            w.push_archive_entry(
                ArchiveEntry::new_file("payload.bin"),
                Some(Cursor::new(payload.to_vec())),
            )
            .unwrap();
            w.finish().unwrap();
        }
        let blob = sink.into_inner();
        assert_eq!(detect(&blob), Some(Format::SevenZip));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::SevenZip, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload);
    }

    /// Build a minimal single-file ISO 9660 image in memory: header sectors,
    /// a primary volume descriptor (sector 16) pointing at a root directory
    /// (sector 17) with one file record, and the file's data (sector 18).
    fn iso_with_file(name: &str, content: &[u8]) -> Vec<u8> {
        const S: usize = 2048;
        let mut img = vec![0u8; 19 * S + content.len().div_ceil(S) * S];
        // --- Primary Volume Descriptor at sector 16 ---
        let pvd = 16 * S;
        img[pvd] = 1; // type = primary
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 6] = 1; // version
                          // Root directory record at PVD+156 (length 34).
        let rd = pvd + 156;
        img[rd] = 34; // record length
        img[rd + 2..rd + 6].copy_from_slice(&17u32.to_le_bytes()); // extent LBA (LE)
        img[rd + 10..rd + 14].copy_from_slice(&(S as u32).to_le_bytes()); // dir size
        img[rd + 25] = 0x02; // flags: directory
        img[rd + 32] = 1; // name len
        img[rd + 33] = 0; // name "\0" (self)
                          // --- Root directory at sector 17 ---
        let dir = 17 * S;
        let mut p = dir;
        // "." record
        img[p] = 34;
        img[p + 2..p + 6].copy_from_slice(&17u32.to_le_bytes());
        img[p + 10..p + 14].copy_from_slice(&(S as u32).to_le_bytes());
        img[p + 25] = 0x02;
        img[p + 32] = 1;
        img[p + 33] = 0;
        p += 34;
        // ".." record
        img[p] = 34;
        img[p + 2..p + 6].copy_from_slice(&17u32.to_le_bytes());
        img[p + 10..p + 14].copy_from_slice(&(S as u32).to_le_bytes());
        img[p + 25] = 0x02;
        img[p + 32] = 1;
        img[p + 33] = 1;
        p += 34;
        // file record
        let nm = name.as_bytes();
        let rec_len = 33 + nm.len() + (1 - nm.len() % 2); // padded to even
        img[p] = rec_len as u8;
        img[p + 2..p + 6].copy_from_slice(&18u32.to_le_bytes()); // file at sector 18
        img[p + 10..p + 14].copy_from_slice(&(content.len() as u32).to_le_bytes());
        img[p + 25] = 0; // flags: file
        img[p + 32] = nm.len() as u8;
        img[p + 33..p + 33 + nm.len()].copy_from_slice(nm);
        // --- file content at sector 18 ---
        img[18 * S..18 * S + content.len()].copy_from_slice(content);
        img
    }

    #[test]
    fn iso9660_single_file() {
        let payload = b"malware-marker inside an ISO image";
        let img = iso_with_file("EVIL.BIN;1", payload);
        assert_eq!(detect(&img), Some(Format::Iso));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Iso, &img, &mut budget).unwrap();
        assert_eq!(entries.len(), 1, "one file in the ISO");
        assert_eq!(entries[0].name, "EVIL.BIN"); // ";1" version suffix stripped
        assert_eq!(entries[0].data, payload);
    }
}
