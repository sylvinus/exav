//! What exav's readers say of a file named as a format the viewer opens: that
//! it is not what its name says, or is damaged (for a file that failed to
//! open), or that its ZIP directory goes past a limit (before it is opened).
//! The first bytes go through [`super::content`], and a package's central
//! directory through exav-unpack's ZIP reader. A format this does not know is
//! not inspected.

use exav_unpack::{
    DirectoryLimit, Limits, Part, TailDirectory, directory_in_tail, has_parts, package_parts,
};

use super::content::content_type;

/// What the check found. `Valid` means examined and sound, which is not the
/// same as `NotInspected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    NotInspected,
    /// The check reads the end of the file: ask again with it.
    NeedsTail,
    /// The first bytes are not those of a file of this format.
    SignatureMismatch,
    /// The ZIP package has no readable central directory.
    InvalidPackage,
    /// The package lacks a part its format requires.
    MissingPart,
    /// The members add up to more than `max_extracted_bytes`.
    TooLarge,
    /// A member past `max_compression_ratio`.
    TooCompressed,
    /// More members than `max_members`.
    TooManyEntries,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Valid => "valid",
            Verdict::NotInspected => "not-inspected",
            Verdict::NeedsTail => "needs-tail",
            Verdict::SignatureMismatch => "signature-mismatch",
            Verdict::InvalidPackage => "invalid-package",
            Verdict::MissingPart => "missing-part",
            Verdict::TooLarge => "too-large",
            Verdict::TooCompressed => "too-compressed",
            Verdict::TooManyEntries => "too-many-entries",
        }
    }
}

/// A verdict, and what goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub verdict: Verdict,
    /// With `NeedsTail`: the offset from which the reader needs the bytes,
    /// when it knows.
    pub needs: Option<u64>,
    /// With a limit verdict: the reason exav-unpack gives for it.
    pub reason: String,
}

impl From<Verdict> for Finding {
    fn from(verdict: Verdict) -> Self {
        Finding {
            verdict,
            needs: None,
            reason: String::new(),
        }
    }
}

/// How a format's file is checked. The parts an OPC or ODF package must have
/// are exav-unpack's (`package_parts`).
#[derive(Clone, Copy)]
enum Check {
    /// An OPC package: always a ZIP.
    Opc,
    /// An ODF package, or a flat XML document, which is not checked.
    Odf,
    /// A ZIP, which has no part to require.
    Zip,
    /// A PDF.
    Pdf,
}

/// The formats that are checked, by their viewer id.
const CHECKS: &[(&str, Check)] = &[
    ("docx", Check::Opc),
    ("xlsx", Check::Opc),
    ("pptx", Check::Opc),
    ("odt", Check::Odf),
    ("ods", Check::Odf),
    ("odp", Check::Odf),
    ("odg", Check::Zip),
    ("visio", Check::Zip),
    ("keynote", Check::Zip),
    ("numbers", Check::Zip),
    ("pages", Check::Zip),
    ("archive", Check::Zip),
    ("pdf", Check::Pdf),
];

fn check_of(kind: &str) -> Option<Check> {
    CHECKS.iter().find(|(id, _)| *id == kind).map(|(_, c)| *c)
}

/// The formats whose file is a ZIP checked against the limits on its
/// directory: every check but the PDF's.
pub fn package_kinds() -> Vec<&'static str> {
    CHECKS
        .iter()
        .filter(|(_, check)| !matches!(check, Check::Pdf))
        .map(|(id, _)| *id)
        .collect()
}

/// The finding for a `size`-byte file named as format `kind`, whose first
/// bytes are `head` and last bytes `tail` (empty when not read yet). A ZIP
/// whose directory goes past `limits` is found `TooLarge`, `TooCompressed` or
/// `TooManyEntries`, before anything is said of its parts.
pub fn inspect(kind: &str, head: &[u8], tail: &[u8], size: u64, limits: &Limits) -> Finding {
    let Some(check) = check_of(kind) else {
        return Verdict::NotInspected.into();
    };
    let ty = content_type(head, usize::try_from(size).unwrap_or(usize::MAX));
    let parts: &[Part] = package_parts(kind).unwrap_or(&[]);
    match check {
        Check::Pdf => {
            return if ty == "application/pdf" {
                Verdict::NotInspected
            } else {
                Verdict::SignatureMismatch
            }
            .into();
        }
        Check::Opc => {
            if size == 0 {
                return Verdict::InvalidPackage.into();
            }
            // An encrypted package is a compound file.
            if ty == "application/x-ole-storage" {
                return Verdict::NotInspected.into();
            }
            if ty != "application/zip" {
                return Verdict::SignatureMismatch.into();
            }
        }
        Check::Odf | Check::Zip => {
            if ty != "application/zip" {
                return Verdict::NotInspected.into();
            }
        }
    }
    if tail.is_empty() {
        return Verdict::NeedsTail.into();
    }
    match directory_in_tail(tail, size) {
        TailDirectory::NotZip => Verdict::InvalidPackage.into(),
        TailDirectory::Needs(at) => Finding {
            needs: Some(at),
            ..Verdict::NeedsTail.into()
        },
        TailDirectory::Found(d) => {
            if let Some((which, hit)) = d.exceeds(limits) {
                return Finding {
                    verdict: match which {
                        DirectoryLimit::Extracted => Verdict::TooLarge,
                        DirectoryLimit::Ratio => Verdict::TooCompressed,
                        DirectoryLimit::Members => Verdict::TooManyEntries,
                    },
                    needs: None,
                    reason: hit.reason,
                };
            }
            let names: Vec<&str> = d.members.iter().map(|m| m.name.as_str()).collect();
            if has_parts(&names, parts) {
                Verdict::Valid
            } else {
                Verdict::MissingPart
            }
            .into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::zip;
    use super::*;

    fn run(kind: &str, bytes: &[u8]) -> Verdict {
        inspect(kind, bytes, bytes, bytes.len() as u64, &Limits::default()).verdict
    }

    const DOCX: &[(&str, &[u8])] = &[
        ("[Content_Types].xml", b"<a/>"),
        ("word/document.xml", b"<b/>"),
    ];

    #[test]
    fn a_sound_package_is_valid_and_a_part_short_is_missing() {
        assert_eq!(run("docx", &zip(DOCX, b"", 0, false)), Verdict::Valid);
        let no_body = zip(
            &[
                ("[Content_Types].xml", b"<a/>"),
                ("word/other.xml", b"<b/>"),
            ],
            b"",
            0,
            false,
        );
        assert_eq!(run("docx", &no_body), Verdict::MissingPart);
        let no_types = zip(&[("word/document.xml", b"<b/>")], b"", 0, false);
        assert_eq!(run("docx", &no_types), Verdict::MissingPart);
        // The same ZIP is a sound workbook only with a workbook part.
        assert_eq!(run("xlsx", &zip(DOCX, b"", 0, false)), Verdict::MissingPart);
        assert_eq!(
            run("odt", &zip(&[("content.xml", b"<a/>")], b"", 0, false)),
            Verdict::Valid
        );
        assert_eq!(run("odt", &zip(DOCX, b"", 0, false)), Verdict::MissingPart);
    }

    #[test]
    fn a_package_without_a_directory_is_invalid() {
        let mut cut = zip(DOCX, b"", 0, false);
        cut.truncate(cut.len() - 30);
        assert_eq!(run("docx", &cut), Verdict::InvalidPackage);
        assert_eq!(run("docx", b""), Verdict::InvalidPackage);
    }

    #[test]
    fn bytes_of_another_format_are_a_mismatch() {
        assert_eq!(run("docx", b"just some text\n"), Verdict::SignatureMismatch);
        assert_eq!(run("pdf", b"just some text\n"), Verdict::SignatureMismatch);
        assert_eq!(run("pdf", b"%PDF-1.4\n"), Verdict::NotInspected);
        // A flat ODF document is XML, an encrypted package a compound file.
        assert_eq!(
            run("odt", b"<?xml version=\"1.0\"?><office:document/>"),
            Verdict::NotInspected
        );
        let ole = [
            &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1][..],
            &[0; 600],
        ]
        .concat();
        assert_eq!(run("docx", &ole), Verdict::NotInspected);
    }

    #[test]
    fn the_package_kinds_are_the_zip_checks() {
        let kinds = package_kinds();
        assert!(kinds.contains(&"docx") && kinds.contains(&"archive"));
        assert!(!kinds.contains(&"pdf"));
        // Each one reads the end of a ZIP: its head alone asks for the tail.
        let z = zip(DOCX, b"", 0, false);
        for kind in kinds {
            let found = inspect(kind, &z, &[], z.len() as u64, &Limits::default());
            assert_eq!(found.verdict, Verdict::NeedsTail, "{kind}");
        }
    }

    #[test]
    fn what_is_not_examined_is_not_valid() {
        assert_eq!(run("png", b"\x89PNG\r\n\x1a\n"), Verdict::NotInspected);
        let z = zip(DOCX, b"", 0, false);
        let limits = Limits::default();
        // The end of the file not read yet.
        let found = inspect("docx", &z, &[], z.len() as u64, &limits);
        assert_eq!((found.verdict, found.needs), (Verdict::NeedsTail, None));
        // A tail too short for the directory: the reader says where it needs bytes from.
        let found = inspect("docx", &z, &z[z.len() - 10..], z.len() as u64, &limits);
        assert_eq!(found.verdict, Verdict::NeedsTail);
        assert!(found.needs.is_some_and(|at| at < z.len() as u64 - 10));
    }

    /// A directory longer than the end the reader was first given: the verdict
    /// asks for more, and is a verdict once it has it.
    #[test]
    fn a_directory_past_the_first_tail_is_asked_for_and_then_judged() {
        let big = vec![7u8; 200_000];
        let z = zip(
            &[
                ("[Content_Types].xml", &big),
                ("word/document.xml", b"<b/>"),
            ],
            b"",
            0,
            false,
        );
        let size = z.len() as u64;
        let limits = Limits::default();
        let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        let first = inspect("docx", &z, &z[cd + 10..], size, &limits);
        assert_eq!(first.verdict, Verdict::NeedsTail);
        let from = first.needs.unwrap() as usize;
        assert_eq!(
            inspect("docx", &z, &z[from..], size, &limits).verdict,
            Verdict::Valid
        );
    }

    #[test]
    fn a_directory_past_a_limit_is_refused_with_the_reason_of_its_limit() {
        let big = vec![0u8; 5 << 20];
        let z = zip(
            &[
                ("[Content_Types].xml", b"<a/>"),
                ("word/document.xml", &big),
                ("word/b.xml", b"<b/>"),
            ],
            b"",
            0,
            false,
        );
        let with = |change: &dyn Fn(&mut Limits)| {
            let mut limits = Limits::default();
            change(&mut limits);
            inspect("docx", &z, &z, z.len() as u64, &limits)
        };
        assert_eq!(with(&|_| {}).verdict, Verdict::Valid);
        let found = with(&|l| l.max_members = 2);
        assert_eq!(found.verdict, Verdict::TooManyEntries);
        assert!(found.reason.contains("file count > 2"), "{}", found.reason);
        let found = with(&|l| l.max_extracted_bytes = 1 << 20);
        assert_eq!(found.verdict, Verdict::TooLarge);
        assert!(
            found.reason.contains("extracted bytes > 1048576"),
            "{}",
            found.reason
        );
        // The zip helper stores its members, so their ratio is 1: a limit of
        // 0 is the one that member goes past (the TypeScript side turns "no
        // limit" into the largest number before it gets here). The ratio is
        // asked only of a member past the object limit.
        assert_eq!(
            with(&|l| l.max_compression_ratio = 0).verdict,
            Verdict::Valid
        );
        assert_eq!(
            with(&|l| {
                l.max_compression_ratio = 0;
                l.max_buffer_bytes = 1;
            })
            .verdict,
            Verdict::TooCompressed
        );
    }

    #[test]
    fn a_zip_without_required_parts_is_checked_for_limits_only() {
        let z = zip(&[("a.bin", b"x"), ("b.bin", b"y")], b"", 0, false);
        let mut limits = Limits::default();
        let found = |limits: &Limits| inspect("archive", &z, &z, z.len() as u64, limits).verdict;
        assert_eq!(found(&limits), Verdict::Valid);
        limits.max_members = 1;
        assert_eq!(found(&limits), Verdict::TooManyEntries);
        assert_eq!(run("archive", b"just some text\n"), Verdict::NotInspected);
    }
}
