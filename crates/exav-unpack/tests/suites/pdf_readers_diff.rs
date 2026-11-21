//! The two readings of a PDF, over the PDFs the repository has and over
//! damaged variants of one.
//!
//! exav-unpack's reader gives the scanner a PDF's members and hayro its text.
//! `pdf_readers::compare` runs a file through both. Each file here is either
//! in a table below with the differences it has today and the reason, or has
//! none. A change in either reader that moves a difference in or out fails
//! here, to be looked at; it is not necessarily a regression.

#[path = "../pdf_readers/mod.rs"]
mod pdf_readers;

use exav_unpack::Limits;
use pdf_readers::{Kind, compare};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

/// Where the repository's PDFs are, from the crate directory.
const DIRS: &[&str] = &[
    "test_data/pdf",
    "tests/fixtures/pdf",
    "../exav-core/tests/testdata",
    "../exav-viewer/demo/examples/files/pdf",
    "../exav-viewer/e2e/fixtures/pdf-images",
];

type Known = &'static [(&'static str, &'static [Kind], &'static str)];

/// The repository's PDFs that differ, by file name.
const FIXTURES: Known = &[
    (
        "qr_ccitt_g4.pdf",
        &[Kind::OnlyExavOpens],
        "an image object and no page tree: hayro refuses a file without pages",
    ),
    (
        "qr_jbig2.pdf",
        &[Kind::OnlyExavOpens],
        "an image object and no page tree: hayro refuses a file without pages",
    ),
    (
        "qr_jbig2_symbols.pdf",
        &[Kind::OnlyExavOpens],
        "an image object and no page tree: hayro refuses a file without pages",
    ),
];

/// The damaged variants of `document` that differ, by case name.
const REPAIRS: Known = &[
    (
        "unknown_filter",
        &[Kind::OnlyHayroDecodes],
        "a filter nobody here decodes ahead of /FlateDecode: exav-unpack stops there and flags \
         the member, hayro leaves the name out and inflates",
    ),
    (
        "predictor_partial_row",
        &[Kind::DecodedDiffers],
        "the data ends part way into a row of a /Predictor: exav-unpack undoes the predictor \
         on the bytes of that row, hayro leaves them out",
    ),
    (
        "nested_dicts_40",
        &[Kind::StreamOnlyExav],
        "dictionaries nested 40 deep in the dictionary, the innermost key with no value: hayro \
         drops the object, exav-unpack reads it (with a value, both read it)",
    ),
    (
        "nested_600",
        &[Kind::StreamOnlyExav],
        "an array nested 600 deep in the dictionary: exav-unpack passes over what is past its \
         depth and reads the object, hayro (nesting limit 512) drops it",
    ),
    (
        "array_open",
        &[Kind::StreamOnlyExav],
        "an array left open in the dictionary: hayro drops the object, exav-unpack reads it",
    ),
    (
        "hex_string_bad",
        &[Kind::StreamOnlyExav],
        "a hex string with a letter outside 0-9a-f: hayro drops the object, exav-unpack reads it",
    ),
];

fn fixtures() -> Vec<(String, Vec<u8>)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in DIRS {
        let path = root.join(dir);
        for entry in std::fs::read_dir(&path).unwrap_or_else(|e| panic!("{path:?}: {e}")) {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "pdf") {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                files.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    files.sort();
    files
}

/// The kinds `data` differs in, against what `known` says of `name`.
fn check(name: &str, data: &[u8], known: Known) -> Option<String> {
    let got = compare(data, &Limits::default()).kinds();
    let want: BTreeSet<Kind> = known
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, kinds, _)| kinds.iter().copied().collect())
        .unwrap_or_default();
    (got != want).then(|| format!("{name}: differs in {got:?}, recorded {want:?}"))
}

#[test]
fn the_repository_pdfs_differ_only_as_recorded() {
    let files = fixtures();
    assert!(files.len() >= 40, "{} PDFs found", files.len());
    let wrong: Vec<String> = files
        .iter()
        .filter_map(|(name, data)| check(name, data, FIXTURES))
        .collect();
    assert!(wrong.is_empty(), "{wrong:#?}");
    // Every recorded file is still there to differ.
    for (name, _, _) in FIXTURES {
        assert!(files.iter().any(|(n, _)| n == name), "{name} is gone");
    }
    // The files with page text and many streams were compared stream by stream.
    for name in [
        "application-form.pdf",
        "handbook-tagged.pdf",
        "field-report.pdf",
    ] {
        let (_, data) = files.iter().find(|(n, _)| n == name).unwrap();
        let c = compare(data, &Limits::default());
        assert!(
            c.compared() > 10,
            "{name}: {} streams compared",
            c.compared()
        );
        assert!(c.hayro.pages > 0, "{name}");
    }
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// A PDF written object by object, with a cross-reference table when finished.
struct Doc {
    buf: Vec<u8>,
    offsets: Vec<(u32, usize)>,
}

impl Doc {
    fn new() -> Self {
        Doc {
            buf: b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec(),
            offsets: Vec::new(),
        }
    }

    fn obj(&mut self, id: u32, body: &str) {
        self.offsets.push((id, self.buf.len()));
        self.buf
            .extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
    }

    /// A stream whose `/Length` is `length` if given, else the data's.
    fn stream(&mut self, id: u32, dict: &str, data: &[u8], length: Option<&str>) {
        let len = length.map_or(data.len().to_string(), str::to_string);
        self.offsets.push((id, self.buf.len()));
        self.buf.extend_from_slice(
            format!("{id} 0 obj\n<< /Length {len} {dict} >>\nstream\n").as_bytes(),
        );
        self.buf.extend_from_slice(data);
        self.buf.extend_from_slice(b"\nendstream\nendobj\n");
    }

    fn finish(mut self, root: u32) -> Vec<u8> {
        let start = self.buf.len();
        let top = self.offsets.iter().map(|(id, _)| *id).max().unwrap();
        let mut x = format!("xref\n0 {}\n0000000000 65535 f \n", top + 1);
        for id in 1..=top {
            match self.offsets.iter().find(|(i, _)| *i == id) {
                Some((_, at)) => x.push_str(&format!("{at:010} 00000 n \n")),
                None => x.push_str("0000000000 65535 f \n"),
            }
        }
        x.push_str(&format!(
            "trailer\n<< /Size {} /Root {root} 0 R >>\nstartxref\n{start}\n%%EOF\n",
            top + 1
        ));
        self.buf.extend_from_slice(x.as_bytes());
        self.buf
    }
}

const CONTENT: &[u8] = b"BT /F1 12 Tf 20 100 Td (hello world) Tj ET";

/// A one-page document with text, a script, a link and an embedded file. The
/// content stream is object 4: `content` as its data, `dict` the rest of its
/// dictionary, `length` its `/Length` if not the data's.
fn document(content: &[u8], dict: &str, length: Option<&str>) -> Doc {
    let mut d = Doc::new();
    d.obj(
        1,
        "<< /Type /Catalog /Pages 2 0 R /OpenAction 7 0 R \
         /Names << /EmbeddedFiles << /Names [(a.txt) 6 0 R] >> >> >>",
    );
    d.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    d.obj(
        3,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> /Annots [8 0 R] >>",
    );
    d.stream(4, dict, content, length);
    d.obj(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    d.obj(6, "<< /Type /Filespec /F (a.txt) /EF << /F 9 0 R >> >>");
    d.obj(7, "<< /S /JavaScript /JS (app.alert\\(1\\)) >>");
    d.obj(
        8,
        "<< /Type /Annot /Subtype /Link /Rect [0 0 50 50] \
         /A << /S /URI /URI (http://example.com/x) >> >>",
    );
    d.stream(
        9,
        "/Type /EmbeddedFile /Filter /FlateDecode",
        &zlib(b"embedded payload"),
        None,
    );
    d
}

fn flate_document() -> Doc {
    document(&zlib(CONTENT), "/Filter /FlateDecode", None)
}

/// Damaged variants of `flate_document`, by name.
fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let z = zlib(CONTENT);
    let intact = flate_document().finish(1);
    let with = |dict: &str, length: Option<&str>| document(&z, dict, length).finish(1);
    // `intact` with the first `from` written as `to`.
    let patch = |from: &[u8], to: &[u8]| {
        let at = intact.windows(from.len()).position(|w| w == from).unwrap();
        [&intact[..at], to, &intact[at + from.len()..]].concat()
    };
    // The head of object 4, with `extra` at the start of its dictionary.
    let head = |extra: &str| {
        let from = format!(
            "4 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream",
            z.len()
        );
        let to = format!(
            "4 0 obj\n<< {extra}/Length {} /Filter /FlateDecode >>\nstream",
            z.len()
        );
        patch(from.as_bytes(), to.as_bytes())
    };

    let mut v: Vec<(&'static str, Vec<u8>)> = vec![("intact", intact.clone())];

    // Without a table, then without a trailer either.
    let mut no_xref = flate_document().buf;
    no_xref.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    v.push(("no_xref", no_xref));
    v.push(("no_trailer", flate_document().buf));
    v.push(("truncated", intact[..intact.len() * 85 / 100].to_vec()));
    v.push(("no_header", intact[9..].to_vec()));
    v.push(("lead_garbage", [vec![b'x'; 1000], intact.clone()].concat()));

    // A second revision of the content stream, as an incremental update writes it.
    let at = intact.len();
    let mut update = intact.clone();
    update.extend_from_slice(b"4 0 obj\n<< /Length 4 >>\nstream\nq Q \nendstream\nendobj\n");
    update.extend_from_slice(
        format!(
            "xref\n4 1\n{at:010} 00000 n \ntrailer\n<< /Size 10 /Root 1 0 R /Prev 0 >>\n\
             startxref\n{}\n%%EOF\n",
            at + 57
        )
        .as_bytes(),
    );
    v.push(("update", update));

    // The stream's own description.
    v.push(("length_short", with("/Filter /FlateDecode", Some("5"))));
    v.push(("length_long", with("/Filter /FlateDecode", Some("100000"))));
    v.push((
        "length_missing",
        with("/Filter /FlateDecode", Some("99 0 R")),
    ));
    v.push(("escaped_filter_name", with("/Filter /Flate#44ecode", None)));
    v.push(("filter_array", with("/Filter [ /FlateDecode ]", None)));
    v.push((
        "unknown_filter",
        with("/Filter [ /NoSuchDecode /FlateDecode ]", None),
    ));
    // The content is 42 bytes: 6 rows of 7 with their tags, or 8 rows of 5
    // and 2 bytes over.
    v.push((
        "predictor",
        with(
            "/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 6 >>",
            None,
        ),
    ));
    v.push((
        "predictor_partial_row",
        with(
            "/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >>",
            None,
        ),
    ));
    v.push((
        "flate_cut",
        document(&z[..20], "/Filter /FlateDecode", None).finish(1),
    ));
    let hex: String = z.iter().map(|b| format!("{b:02x}")).collect();
    v.push((
        "hex_flate",
        document(
            format!("{hex}>").as_bytes(),
            "/Filter [ /ASCIIHexDecode /FlateDecode ]",
            None,
        )
        .finish(1),
    ));
    v.push((
        "stream_crlf",
        patch(b"/FlateDecode >>\nstream\n", b"/FlateDecode >>\nstream\r\n"),
    ));
    v.push((
        "stream_cr",
        patch(b"/FlateDecode >>\nstream\n", b"/FlateDecode >>\nstream\r"),
    ));
    v.push((
        "comment_before_stream",
        patch(
            b"/FlateDecode >>\nstream\n",
            b"/FlateDecode >> % x\nstream\n",
        ),
    ));

    // Keywords and objects where they do not belong.
    let text = b"BT ET\n10 0 obj\n<< /S /JavaScript /JS (hidden) >>\nendobj\n";
    v.push(("object_in_stream_data", document(text, "", None).finish(1)));
    v.push((
        "endstream_in_data",
        document(b"BT ET\nendstream\nendobj\n", "", None).finish(1),
    ));
    v.push(("stream_keyword_in_dictionary", head("/X [ stream ] ")));
    v.push(("endobj_keyword_in_dictionary", head("/X [ endobj ] ")));
    let mut comment = flate_document().buf;
    comment.extend_from_slice(b"% 10 0 obj << /S /JavaScript /JS (hidden) >> endobj\n");
    comment.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    v.push(("object_in_comment", comment));
    v.push((
        "no_endobj",
        patch(b"endstream\nendobj\n5 0 obj", b"endstream\n5 0 obj"),
    ));

    // A dictionary written in a way that is not the usual one.
    v.push((
        "dict_without_spaces",
        patch(
            format!(
                "4 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream",
                z.len()
            )
            .as_bytes(),
            format!("4 0 obj<</Length {}/Filter/FlateDecode>>stream", z.len()).as_bytes(),
        ),
    ));
    v.push((
        "comment_in_dict",
        patch(b"4 0 obj\n<< /Length", b"4 0 obj % a\n<< % b\n /Length"),
    ));
    v.push(("array_open", head("/X [ 1 ")));
    v.push(("hex_string_bad", head("/X <zz1> ")));
    v.push(("odd_numbers", head("/X 1.5.3 /Y --5 /Z +.5 /W 1e5 ")));
    v.push(("name_escape_bad", head("/X#zz 1 /Y#4 2 ")));
    v.push(("string_open", head("/X (open ")));
    v.push((
        "many_keys",
        head(&(0..2000).map(|i| format!("/K{i} {i} ")).collect::<String>()),
    ));
    v.push((
        "nested_20",
        head(&format!("/X {}{} ", "[".repeat(20), "]".repeat(20))),
    ));
    v.push((
        "nested_21",
        head(&format!("/X {}{} ", "[".repeat(21), "]".repeat(21))),
    ));
    v.push((
        "nested_dicts_40",
        head(&format!("/X {}{} ", "<</A ".repeat(40), ">>".repeat(40))),
    ));
    v.push((
        "nested_300",
        head(&format!("/X {}{} ", "[".repeat(300), "]".repeat(300))),
    ));
    v.push((
        "nested_600",
        head(&format!("/X {}{} ", "[".repeat(600), "]".repeat(600))),
    ));

    // An object stream holding the script's action, no table naming it.
    let mut stream = Doc::new();
    stream.obj(1, "<< /Type /Catalog /Pages 2 0 R /OpenAction 12 0 R >>");
    stream.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    stream.obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 9 9] >>");
    stream.stream(
        11,
        "/Type /ObjStm /N 1 /First 5",
        b"12 0 << /S /JavaScript /JS (hidden) >>",
        None,
    );
    stream
        .buf
        .extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    v.push(("object_stream", stream.buf));
    v
}

#[test]
fn damaged_files_differ_only_as_recorded() {
    let wrong: Vec<String> = cases()
        .iter()
        .filter_map(|(name, data)| check(name, data, REPAIRS))
        .collect();
    assert!(wrong.is_empty(), "{wrong:#?}");
    let cases = cases();
    for (name, _, _) in REPAIRS {
        assert!(cases.iter().any(|(n, _)| n == name), "{name} is not a case");
    }
}

/// The comparison reads each fact it claims to: on the plain file both
/// readings find the same two streams, the script and the two strings.
#[test]
fn the_comparison_reaches_every_fact_it_compares() {
    let intact = flate_document().finish(1);
    let c = compare(&intact, &Limits::default());
    assert_eq!(c.differences, []);
    assert_eq!(c.compared(), 2);
    assert_eq!(c.hayro.pages, 1);
    let set = |s: &[&[u8]]| s.iter().map(|b| b.to_vec()).collect::<BTreeSet<_>>();
    assert_eq!(c.exav.scripts, set(&[b"app.alert(1)"]));
    assert_eq!(c.hayro.scripts, c.exav.scripts);
    assert_eq!(c.exav.targets, set(&[b"a.txt", b"http://example.com/x"]));
    assert_eq!(c.hayro.targets, c.exav.targets);
}
