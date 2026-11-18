//! Email past the buffer limit, read from a source that is not in memory: a
//! mailbox split message by message, and a message larger than the limit
//! read part by part, its bodies decoded as they are read.

use exav_unpack::source::BlockCache;
use exav_unpack::{Budget, Format, Limits, Member};
use std::io::Cursor;

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";
const CAP: u64 = 64 * 1024;

/// Name, bytes, read as it went.
type Got = (String, Vec<u8>, bool);

fn walk(blob: &[u8], cap: u64) -> (Vec<Got>, Result<(), String>) {
    let cache = BlockCache::with_sizes(Cursor::new(blob.to_vec()), 4096, 64 * 1024).unwrap();
    let mut limits = Limits::default();
    limits.max_buffer_bytes = cap;
    let mut budget = Budget::new(limits);
    let mut out = Vec::new();
    let end = exav_unpack::walk(
        Format::Email,
        &cache,
        &mut budget,
        &mut |meta, content, _| {
            let (data, streamed) = match content {
                Some(Member::Stream(r)) => {
                    let mut b = Vec::new();
                    r.read_to_end(&mut b).unwrap();
                    (b, true)
                }
                Some(Member::Bytes(b)) => (b, false),
                #[allow(unreachable_patterns)]
                Some(_) => panic!("{}: an unexpected kind of member", meta.name),
                None => (Vec::new(), false),
            };
            assert!(meta.unsupported.is_none(), "{}", meta.name);
            out.push((meta.name.clone(), data, streamed));
            None::<()>
        },
    );
    (out, end.map(|_| ()).map_err(|e| e.to_string()))
}

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for (i, c) in data.chunks(3).enumerate() {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= c.len() {
                s.push(A[(n >> (18 - 6 * k) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
        if i % 19 == 18 {
            s.push_str("\r\n");
        }
    }
    s
}

fn attachment(n: usize) -> Vec<u8> {
    let mut v: Vec<u8> = (0..n as u32)
        .map(|i| (i.wrapping_mul(31) >> 2) as u8)
        .collect();
    v.extend_from_slice(EICAR);
    v
}

fn message(att: &[u8]) -> String {
    format!(
        "From: a@example.com\r\nTo: b@example.com\r\nSubject: big\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed;\r\n boundary=\"OUTER\"\r\n\r\n\
         preamble\r\n--OUTER\r\nContent-Type: text/plain\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\r\n\
         Caf=C3=A9 one=\r\n two\r\nthree\r\n\
         --OUTER\r\nContent-Type: multipart/alternative; boundary=INNER\r\n\r\n\
         --INNER\r\nContent-Type: text/plain\r\n\r\nplain body\r\n\
         --INNER\r\nContent-Type: text/html\r\n\r\n<p>html body</p>\r\n\
         --INNER--\r\nepilogue\r\n\
         --OUTER\r\nContent-Type: application/octet-stream; name=\"a.bin\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n--OUTER--\r\n",
        b64(att)
    )
}

fn find<'a>(got: &'a [Got], name: &str) -> &'a Got {
    got.iter().find(|g| g.0 == name).unwrap_or_else(|| {
        panic!(
            "no member {name}: {:?}",
            got.iter().map(|g| &g.0).collect::<Vec<_>>()
        )
    })
}

/// A message five times the buffer limit: every leaf reached, read as it
/// goes, decoded as the in-memory reader decodes it, the signature at the
/// end of the attachment there.
#[test]
fn a_message_past_the_limit_is_read_part_by_part() {
    let att = attachment(250_000);
    let blob = message(&att).into_bytes();
    assert!(blob.len() as u64 > 5 * CAP);
    let (got, end) = walk(&blob, CAP);
    end.unwrap();
    assert!(got.iter().all(|g| g.2));
    let a = find(&got, "email-part-5");
    assert_eq!(a.1, att);
    assert!(a.1.ends_with(EICAR));
    assert_eq!(
        find(&got, "email-part-1").1,
        "Café one two\r\nthree".as_bytes()
    );
    assert_eq!(find(&got, "email-part-3").1, b"plain body");
    assert_eq!(find(&got, "email-part-4").1, b"<p>html body</p>");
    assert_eq!(got.len(), 4);

    // The in-memory reader gives the same leaves under the same names.
    let mut budget = Budget::new(Limits::default());
    let whole = exav_unpack::extract(Format::Email, &blob, &mut budget).unwrap();
    for e in &whole {
        let g = find(&got, &e.name);
        assert_eq!(
            String::from_utf8_lossy(&g.1).trim_end(),
            String::from_utf8_lossy(&e.data).trim_end(),
            "{}",
            e.name
        );
    }
    assert_eq!(whole.len(), got.len());
}

/// A mailbox past the limit: each message within it read whole under its own
/// name, one past it read part by part, the last message reached.
#[test]
fn a_mailbox_past_the_limit_is_split_message_by_message() {
    let mut mbox = String::new();
    for i in 0..40 {
        mbox.push_str(&format!(
            "From sender@example.com Mon Jan  1 00:00:00 2024\r\n\
             From: s@example.com\r\nSubject: m{i}\r\n\r\nbody of message {i}\r\n{}\r\n\r\n",
            "x".repeat(2000)
        ));
    }
    mbox.push_str("From sender@example.com Mon Jan  1 00:00:00 2024\r\n");
    mbox.push_str(&message(&attachment(100_000)));
    mbox.push_str("From sender@example.com Mon Jan  1 00:00:00 2024\r\n");
    mbox.push_str(&message(&attachment(1_000)));
    let blob = mbox.into_bytes();
    assert!(blob.len() as u64 > 2 * CAP);
    let (got, end) = walk(&blob, CAP);
    end.unwrap();
    let first = find(&got, "mbox-0/email-part-0");
    assert!(!first.2 && first.1.starts_with(b"body of message 0"));
    assert!(
        find(&got, "mbox-39/email-part-0")
            .1
            .starts_with(b"body of message 39")
    );
    let big = find(&got, "mbox-40/email-part-5");
    assert!(big.2 && big.1 == attachment(100_000));
    let last = find(&got, "mbox-41/email-part-5");
    assert!(!last.2 && last.1.ends_with(EICAR));
}

/// Cut through the attachment, a message gives the part of it that is there,
/// and no error: what is missing is not in the file.
#[test]
fn a_cut_message_gives_what_it_holds() {
    let att = attachment(250_000);
    let blob = message(&att).into_bytes();
    let cut = &blob[..blob.len() * 3 / 4];
    let (got, end) = walk(cut, CAP);
    end.unwrap();
    let a = find(&got, "email-part-5");
    assert!(a.1.len() > 100_000 && att.starts_with(&a.1));
}

/// A header block larger than the buffer limit is not held: the walk stops,
/// and says why.
#[test]
fn a_header_block_past_the_limit_is_a_limit() {
    let mut blob = String::from("From: a@example.com\r\n");
    for i in 0..4000 {
        blob.push_str(&format!("X-Filler-{i}: {}\r\n", "y".repeat(40)));
    }
    blob.push_str("\r\nbody\r\n");
    let (_, end) = walk(blob.as_bytes(), CAP);
    assert!(end.unwrap_err().contains("header block"));
}

/// A byte outside the base64 alphabet is skipped, as the mail readers do: `-`
/// and `_` too, which only the URL-safe alphabet has. Read whole or part by
/// part, the same body gives the same attachment.
#[test]
fn base64_skips_what_is_outside_its_alphabet_whole_or_by_parts() {
    let att = attachment(250_000);
    let clean = b64(&att);
    let mut dirty = clean.clone();
    dirty.insert(5000, '_');
    dirty.insert(1, '-');
    dirty.insert(3, '*');
    let blob = message(&att).replace(&clean, &dirty).into_bytes();
    assert!(blob.len() as u64 > 4 * CAP);

    let (got, end) = walk(&blob, CAP);
    end.unwrap();
    assert!(find(&got, "email-part-5").1 == att, "by parts");

    let mut budget = Budget::new(Limits::default());
    let whole = exav_unpack::extract(Format::Email, &blob, &mut budget).unwrap();
    let decoded: Vec<&str> = whole
        .iter()
        .filter(|e| e.data == att)
        .map(|e| e.name.as_str())
        .collect();
    assert!(
        decoded.iter().any(|n| n.starts_with("email-part-5")),
        "whole: {:?}",
        whole.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

/// A message of `depth` multiparts, each the only part of the one around it,
/// the innermost holding a text leaf of 100,000 bytes and the signature.
fn nested(depth: usize) -> Vec<u8> {
    let mut m = String::from("From: a@example.com\r\nMIME-Version: 1.0\r\n");
    for i in 0..depth {
        m.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"B{i}\"\r\n\r\n--B{i}\r\n"
        ));
    }
    m.push_str("Content-Type: text/plain\r\n\r\n");
    m.push_str(&"x".repeat(100_000));
    m.push_str(std::str::from_utf8(EICAR).unwrap());
    for i in (0..depth).rev() {
        m.push_str(&format!("\r\n--B{i}--\r\n"));
    }
    m.into_bytes()
}

/// A member: name, why not whole, bytes.
type Reported = (String, Option<&'static str>, Vec<u8>);

/// Every member of `blob` walked under `CAP`.
fn reported(blob: &[u8]) -> Vec<Reported> {
    reported_at(blob, CAP)
}

/// Every member of `blob` walked under a buffer limit of `cap`.
fn reported_at(blob: &[u8], cap: u64) -> Vec<Reported> {
    let cache = BlockCache::with_sizes(Cursor::new(blob.to_vec()), 4096, 64 * 1024).unwrap();
    let mut limits = Limits::default();
    limits.max_buffer_bytes = cap;
    let mut budget = Budget::new(limits);
    let mut out = Vec::new();
    exav_unpack::walk(
        Format::Email,
        &cache,
        &mut budget,
        &mut |meta, content, _| {
            let mut data = Vec::new();
            match content {
                Some(Member::Stream(r)) => {
                    r.read_to_end(&mut data).unwrap();
                }
                Some(Member::Bytes(b)) => data = b,
                #[allow(unreachable_patterns)]
                _ => {}
            }
            out.push((meta.name.clone(), meta.unsupported, data));
            None::<()>
        },
    )
    .unwrap();
    out
}

/// Multiparts nested past what is read part by part are not dropped quietly:
/// the one that is too deep comes out as a member that says so, with its
/// bytes, the signature inside them included.
#[test]
fn multiparts_nested_too_deep_are_reported_with_their_bytes() {
    let ok = reported(&nested(10));
    assert!(ok.iter().all(|m| m.1.is_none()));
    assert!(
        ok.iter()
            .any(|m| m.2.windows(EICAR.len()).any(|w| w == EICAR))
    );

    let deep = reported(&nested(200));
    let said: Vec<_> = deep.iter().filter(|m| m.1.is_some()).collect();
    assert_eq!(said.len(), 1, "{} members", deep.len());
    assert!(said[0].1.unwrap().contains("nested too deep"));
    assert!(said[0].2.windows(EICAR.len()).any(|w| w == EICAR));
}

/// An attachment whose base64 is pieces encoded apart, each padded, decodes
/// as the in-memory reader decodes it: padding ends a quantum.
#[test]
fn base64_padded_in_the_middle_decodes_as_in_memory() {
    let one = attachment(100_001);
    let two = attachment(100_000);
    let mut blob = message(&one).into_bytes();
    let joined = format!("{}\r\n{}", b64(&one), b64(&two));
    blob = String::from_utf8(blob)
        .unwrap()
        .replace(&b64(&one), &joined)
        .into_bytes();
    assert!(b64(&one).trim_end().ends_with('='));
    let (got, end) = walk(&blob, CAP);
    end.unwrap();
    let mut want = one.clone();
    want.extend_from_slice(&two);
    assert!(find(&got, "email-part-5").1 == want);
    let mut budget = Budget::new(Limits::default());
    let whole = exav_unpack::extract(Format::Email, &blob, &mut budget).unwrap();
    let w = whole.iter().find(|e| e.name == "email-part-5").unwrap();
    assert!(w.data == want);
}

/// The same with a byte outside the alphabet, which the parser in memory
/// does not decode past: its own lenient decoding ends a quantum at the
/// padding too.
#[test]
fn base64_padded_in_the_middle_with_a_stray_byte_decodes_as_in_memory() {
    let one = attachment(100_001);
    let two = attachment(100_000);
    let mut dirty = b64(&two);
    dirty.insert(7, '*');
    let joined = format!("{}\r\n{dirty}", b64(&one));
    let blob = message(&one).replace(&b64(&one), &joined).into_bytes();
    let mut want = one.clone();
    want.extend_from_slice(&two);
    let (got, end) = walk(&blob, CAP);
    end.unwrap();
    assert!(find(&got, "email-part-5").1 == want, "by parts");
    let mut budget = Budget::new(Limits::default());
    let whole = exav_unpack::extract(Format::Email, &blob, &mut budget).unwrap();
    assert!(
        whole
            .iter()
            .any(|e| e.name.starts_with("email-part-5") && e.data == want),
        "whole: {:?}",
        whole.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

/// Every member of `blob` read in memory.
fn in_memory(blob: &[u8]) -> Vec<Reported> {
    let mut budget = Budget::new(Limits::default());
    exav_unpack::extract(Format::Email, &blob, &mut budget)
        .unwrap()
        .into_iter()
        .map(|e| (e.name, e.unsupported, e.data))
        .collect()
}

/// Names, reasons and sizes, for a failure message.
fn brief(members: &[Reported]) -> Vec<(&str, Option<&str>, usize)> {
    members
        .iter()
        .map(|m| (m.0.as_str(), m.1, m.2.len()))
        .collect()
}

fn has(members: &[Reported], needle: &[u8]) -> bool {
    members
        .iter()
        .any(|m| m.2.windows(needle.len()).any(|w| w == needle))
}

/// A message of that `Content-Type` and body.
fn mime(content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "From: a@example.com\r\nTo: b@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n\
         Content-Type: {content_type}\r\n\r\n{body}"
    )
    .into_bytes()
}

/// A filler part longer than `CAP`, then an attachment whose base64 holds the
/// signature: the message is read part by part, and the signature is found
/// only if the parts are told apart and the second is decoded.
fn filler_and_attachment(open: &str, close: &str, attachment_headers: &str) -> String {
    format!(
        "{open}\r\nContent-Type: text/plain\r\n\r\n{}\r\n{open}\r\n{attachment_headers}\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n{close}\r\n",
        "x".repeat(100_000),
        b64(EICAR)
    )
}

/// The two parts of [`filler_and_attachment`] as `delim` delimits them.
fn two_parts(delim: &str) -> String {
    filler_and_attachment(
        &format!("--{delim}"),
        &format!("--{delim}--"),
        "Content-Type: application/octet-stream\r\n",
    )
}

/// Both parts, told apart and the second decoded, nothing reported.
fn assert_told_apart(who: &str, got: &[Reported]) {
    let names: Vec<_> = got.iter().map(|m| m.0.as_str()).collect();
    assert_eq!(names, ["email-part-1", "email-part-2"], "{who}");
    assert!(got.iter().all(|m| m.1.is_none()), "{who}: {:?}", brief(got));
    assert!(got[1].2 == EICAR, "{who}: {} bytes", got[1].2.len());
}

/// Past the buffer limit and within it, a message with the signature in plain
/// text and a multipart header that finds no delimiter: the body comes out as
/// one part, with the reason, and its bytes.
#[test]
fn a_multipart_with_no_delimiter_is_handed_over_and_reported() {
    let eicar = std::str::from_utf8(EICAR).unwrap();
    let long = format!("{}\r\n{eicar}\r\n", "x".repeat(100_000));
    let short = format!("preamble\r\n{eicar}\r\n");
    let other =
        format!("preamble\r\n--OTHER\r\nContent-Type: text/plain\r\n\r\n{eicar}\r\n--OTHER--\r\n");
    for (what, body) in [
        ("long", &long),
        ("short", &short),
        ("other boundary", &other),
    ] {
        for ct in ["multipart/mixed; boundary=\"NOPE\"", "multipart/mixed"] {
            let blob = mime(ct, body);
            for (who, got) in [("in memory", in_memory(&blob)), ("walked", reported(&blob))] {
                let what = format!("{what}, {ct}, {who}");
                assert_eq!(got.len(), 1, "{what}: {:?}", brief(&got));
                assert_eq!(got[0].0, "email-part-0", "{what}");
                assert!(got[0].1.is_some_and(|r| r.contains("not found")), "{what}");
                assert!(has(&got, EICAR), "{what}");
            }
        }
    }
}

/// A multipart inside another one, its own delimiter never coming: its body
/// runs up to the delimiter of the one around it, and the parts after it are
/// still read.
#[test]
fn a_nested_multipart_with_no_delimiter_is_handed_over_up_to_the_outer_delimiter() {
    let eicar = std::str::from_utf8(EICAR).unwrap();
    let body = format!(
        "--OUT\r\nContent-Type: text/plain\r\n\r\n{}\r\n--OUT\r\n\
         Content-Type: multipart/mixed; boundary=\"NOPE\"\r\n\r\ninner {eicar}\r\n\
         --OUT\r\nContent-Type: text/plain\r\n\r\nafter\r\n--OUT--\r\n",
        "x".repeat(100_000)
    );
    let blob = mime("multipart/mixed; boundary=\"OUT\"", &body);
    for (who, got) in [
        ("in memory", in_memory(&blob)),
        ("by parts", reported(&blob)),
    ] {
        let names: Vec<_> = got.iter().map(|m| m.0.as_str()).collect();
        assert_eq!(
            names,
            ["email-part-1", "email-part-2", "email-part-3"],
            "{who}"
        );
        assert!(got[1].1.is_some_and(|r| r.contains("not found")), "{who}");
        assert_eq!(got[1].2, format!("inner {eicar}").as_bytes(), "{who}");
        assert!(got[0].1.is_none() && got[2].1.is_none(), "{who}");
        assert_eq!(got[2].2, b"after", "{who}");
    }
}

/// A multipart whose body is blank has nothing to report.
#[test]
fn a_multipart_with_a_blank_body_is_not_reported() {
    let blob = mime("multipart/mixed; boundary=\"NOPE\"", &"\r\n".repeat(50_000));
    assert!(blob.len() as u64 > CAP);
    assert!(reported(&blob).iter().all(|m| m.1.is_none()));
    assert!(in_memory(&blob).iter().all(|m| m.1.is_none()));
}

/// The same inside a mailbox: the message is read whole when it fits the
/// limit, part by part when it does not, under the name of its place.
#[test]
fn a_multipart_with_no_delimiter_in_a_mailbox_is_handed_over_and_reported() {
    let eicar = std::str::from_utf8(EICAR).unwrap();
    let from = "From sender@example.com Mon Jan  1 00:00:00 2024\r\n";
    let filler = |i: usize| {
        format!(
            "{from}From: s@example.com\r\nSubject: m{i}\r\n\r\n{}\r\n\r\n",
            "x".repeat(30_000)
        )
    };
    let target = |pad: usize| {
        let body = format!("{}\r\n{eicar}\r\n", "y".repeat(pad));
        format!(
            "{from}{}",
            String::from_utf8(mime("multipart/mixed; boundary=\"NOPE\"", &body)).unwrap()
        )
    };
    let mbox = format!(
        "{}{}{}{}",
        filler(0),
        target(100),
        filler(2),
        target(100_000)
    );
    let got = reported(mbox.as_bytes());
    for name in ["mbox-1/email-part-0", "mbox-3/email-part-0"] {
        let m = got
            .iter()
            .find(|m| m.0 == name)
            .unwrap_or_else(|| panic!("{name}: {:?}", brief(&got)));
        assert!(m.1.is_some_and(|r| r.contains("not found")), "{name}");
        assert!(m.2.windows(EICAR.len()).any(|w| w == EICAR), "{name}");
    }
    assert!(
        got.iter().filter(|m| m.1.is_some()).count() == 2,
        "{:?}",
        brief(&got)
    );
}

/// A boundary longer than the piece a line is read in is still a delimiter:
/// both readers tell the parts apart. 65,532 is the longest whose closing
/// delimiter fit in a piece before the piece grew with the boundary.
#[test]
fn a_boundary_longer_than_a_line_piece_is_read_by_both_readers() {
    for len in [65_532usize, 65_533, 70_000, 140_000] {
        let boundary = "b".repeat(len);
        let blob = mime(
            &format!("multipart/mixed; boundary=\"{boundary}\""),
            &two_parts(&boundary).replace(&"x".repeat(100_000), "hello"),
        );
        let cap = len as u64 * 2;
        assert!(blob.len() as u64 > cap, "{len}");
        assert_told_apart(&format!("in memory, {len}"), &in_memory(&blob));
        assert_told_apart(&format!("by parts, {len}"), &reported_at(&blob, cap));
    }
}

/// A boundary folded onto the next line, next to its `=`, quoted or not: both
/// readers tell the parts apart.
#[test]
fn a_boundary_folded_onto_the_next_line_is_read_by_both_readers() {
    for (what, ct) in [
        ("quoted, after =", "multipart/mixed; boundary=\r\n \"XYZ\""),
        ("bare, after =", "multipart/mixed; boundary=\r\n XYZ"),
        ("before =", "multipart/mixed; boundary\r\n =XYZ"),
        ("LF only", "multipart/mixed; boundary=\n \"XYZ\""),
        ("tab", "multipart/mixed; boundary=\r\n\t\"XYZ\""),
        (
            "after trailing space",
            "multipart/mixed; boundary= \r\n \"XYZ\"",
        ),
        ("twice", "multipart/mixed;\r\n boundary=\r\n \"XYZ\""),
        ("after ;", "multipart/mixed;\r\n boundary=\"XYZ\""),
    ] {
        let blob = mime(ct, &two_parts("XYZ"));
        assert!(blob.len() as u64 > CAP);
        assert_told_apart(&format!("in memory, {what}"), &in_memory(&blob));
        assert_told_apart(&format!("by parts, {what}"), &reported(&blob));
    }
}

/// A fold next to the `=` of a `name` that comes before the boundary in the
/// same header.
#[test]
fn a_name_folded_before_the_boundary_does_not_hide_it() {
    for ct in [
        "multipart/mixed; name=\r\n \"x\"; boundary=\"XYZ\"",
        "multipart/mixed; name=\r\n x; boundary=XYZ",
        "multipart/mixed; name\r\n = x; boundary=\r\n XYZ",
    ] {
        let blob = mime(ct, &two_parts("XYZ"));
        assert_told_apart("in memory", &in_memory(&blob));
        assert_told_apart("by parts", &reported(&blob));
    }
}

/// `name` and `filename` folded onto the next line, quoted or not. Neither
/// reader names a member after them, so the attachment is read the same.
#[test]
fn a_name_and_a_filename_folded_onto_the_next_line_leave_the_attachment_read() {
    for (what, name, filename) in [
        ("quoted", "name=\r\n \"a.com\"", "filename=\r\n \"a.com\""),
        ("bare", "name=\r\n a.com", "filename=\r\n a.com"),
        ("before =", "name\r\n =\"a.com\"", "filename\r\n =\"a.com\""),
        (
            "in the quotes",
            "name=\"\r\n a.com\"",
            "filename=\"\r\n a.com\"",
        ),
        (
            "continuations",
            "name*0=\"a\";\r\n name*1=\".com\"",
            "filename*0=\"a\";\r\n filename*1=\".com\"",
        ),
    ] {
        let headers = format!(
            "Content-Type: application/octet-stream; {name}\r\n\
             Content-Disposition: attachment; {filename}\r\n"
        );
        let blob = mime(
            "multipart/mixed; boundary=\"XYZ\"",
            &filler_and_attachment("--XYZ", "--XYZ--", &headers),
        );
        assert_told_apart(&format!("in memory, {what}"), &in_memory(&blob));
        assert_told_apart(&format!("by parts, {what}"), &reported(&blob));
    }
}

/// A boundary the in-memory parser reads and the part-by-part reader does not
/// (a fold after the opening quote, RFC 2231, a delimiter inside a line or
/// longer than the boundary) is not dropped: the signature is found, or the
/// message says it was not taken apart.
#[test]
fn a_boundary_only_the_in_memory_parser_reads_is_reported_by_parts() {
    for (what, ct, open, close) in [
        (
            "fold after the quote",
            "multipart/mixed; boundary=\"\r\n XYZ\"",
            "--XYZ",
            "--XYZ--",
        ),
        (
            "continuation",
            "multipart/mixed; boundary*0=\"XY\"; boundary*1=\"Z\"",
            "--XYZ",
            "--XYZ--",
        ),
        (
            "extended",
            "multipart/mixed; boundary*=utf-8''XYZ",
            "--XYZ",
            "--XYZ--",
        ),
        (
            "semicolon in a quoted name",
            "multipart/mixed; name=\"a; boundary=FAKE\"; boundary=XYZ",
            "--XYZ",
            "--XYZ--",
        ),
        (
            "inside a line",
            "multipart/mixed; boundary=XYZ",
            "text--XYZ",
            "text--XYZ--",
        ),
        (
            "longer",
            "multipart/mixed; boundary=XYZ",
            "--XYZ-extra",
            "--XYZ-extra--",
        ),
    ] {
        let blob = mime(
            ct,
            &filler_and_attachment(open, close, "Content-Type: application/octet-stream\r\n"),
        );
        let mem = in_memory(&blob);
        assert!(has(&mem, EICAR), "in memory, {what}: {:?}", brief(&mem));
        let got = reported(&blob);
        assert!(
            has(&got, EICAR) || got.iter().any(|m| m.1.is_some()),
            "by parts, {what}: {:?}",
            brief(&got)
        );
    }
}

/// The fold is only undone for a multipart the parser could not take apart: a
/// line of a body that looks like a header keeps its break.
#[test]
fn a_body_line_that_looks_like_a_folded_header_keeps_its_break() {
    let text = "Content-Type: x; boundary=\r\n  y\r\nend";
    let blob = mime("text/plain", text);
    let got = in_memory(&blob);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].2, text.as_bytes());
}

/// A message attached to a message past the buffer limit is handed over as its
/// bytes, and says so: the reader in memory takes it apart. That is
/// `message/rfc822` and `message/global` as they stand, and a part of a digest
/// that has no type. Encoded, both readers hand over the decoded bytes, and
/// nothing is said.
#[test]
fn an_attached_message_is_reported_by_parts() {
    let inner = "From: c@example.com\r\nSubject: s\r\n\r\nattached";
    let filler = "x".repeat(100_000);
    for (what, outer, headers, body, said) in [
        (
            "rfc822",
            "multipart/mixed",
            "Content-Type: message/rfc822\r\n",
            inner.to_string(),
            true,
        ),
        (
            "global",
            "multipart/mixed",
            "Content-Type: message/global\r\n",
            inner.to_string(),
            true,
        ),
        (
            "digest, no type",
            "multipart/digest",
            "",
            inner.to_string(),
            true,
        ),
        (
            "digest, typed",
            "multipart/digest",
            "Content-Type: text/plain\r\n",
            inner.to_string(),
            false,
        ),
        (
            "mixed, no type",
            "multipart/mixed",
            "",
            inner.to_string(),
            false,
        ),
        (
            "rfc822, base64",
            "multipart/mixed",
            "Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n",
            b64(inner.as_bytes()),
            false,
        ),
    ] {
        let parts = format!(
            "--OUT\r\n{headers}\r\n{body}\r\n--OUT\r\nContent-Type: text/plain\r\n\r\n{filler}\r\n--OUT--\r\n"
        );
        let blob = mime(&format!("{outer}; boundary=\"OUT\""), &parts);
        let got = reported(&blob);
        let first = got.iter().find(|m| m.0 == "email-part-1").unwrap();
        let why = first.1.unwrap_or("");
        assert_eq!(why.contains("attached message"), said, "{what}: {why:?}");
        assert_eq!(
            got.iter().filter(|m| m.1.is_some()).count(),
            usize::from(said)
        );
        let mem = in_memory(&blob);
        assert!(mem.iter().all(|m| m.1.is_none()), "{what}");
        if said {
            assert!(first.2.starts_with(b"From: c@example.com"), "{what}");
            // Taken apart in memory: the body of the attached message.
            assert!(
                mem.iter().any(|m| m.2 == b"attached"),
                "{what}: {:?}",
                brief(&mem)
            );
        }
    }
}

/// An attached message that holds a multipart with a folded boundary.
#[test]
fn a_boundary_folded_in_an_attached_message_is_read() {
    let inner = format!(
        "From: c@example.com\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\r\n \"IN\"\r\n\r\n{}",
        two_parts("IN")
    );
    let body = format!("--OUT\r\nContent-Type: message/rfc822\r\n\r\n{inner}\r\n--OUT--\r\n");
    let got = in_memory(&mime("multipart/mixed; boundary=\"OUT\"", &body));
    assert!(has(&got, EICAR), "{:?}", brief(&got));
    assert!(got.iter().all(|m| m.1.is_none()), "{:?}", brief(&got));
}
