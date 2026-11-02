//! MIME email: every part that holds bytes is a member, those of attached
//! messages included.

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits};

/// Members as `(name, bytes)`.
type Members = Vec<(String, Vec<u8>)>;

/// Every member of `data` read as an email, and how the walk ended.
fn members(data: &[u8]) -> (Members, Result<(), String>) {
    let mut out = vec![];
    let mut budget = Budget::new(Limits::default());
    let r = extract_each(
        Format::Email,
        data,
        &mut budget,
        &mut |e: Entry, _: &mut Budget| {
            out.push((e.name, e.data));
            None::<()>
        },
    );
    (out, r.map(|_| ()).map_err(|e| e.reason))
}

const B64_X: &str = "WFhYWFhYWFg="; // XXXXXXXX
const B64_Y: &str = "WVlZWVlZWVk="; // YYYYYYYY

fn mail(attached: &str) -> String {
    format!(
        "From: a@b\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"out\"\r\n\r\n\
         --out\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
         --out\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n{B64_X}\r\n\
         --out\r\nContent-Type: message/rfc822\r\n\r\n{attached}\r\n--out--\r\n"
    )
}

fn inner() -> String {
    format!(
        "From: c@d\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"in\"\r\n\r\n\
         --in\r\nContent-Type: text/plain\r\n\r\ninner body\r\n\
         --in\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n{B64_Y}\r\n--in--\r\n"
    )
}

#[test]
fn a_part_is_a_member_decoded() {
    let (m, r) = members(mail(&inner()).as_bytes());
    assert_eq!(r, Ok(()));
    assert!(m.iter().any(|(_, d)| d == b"XXXXXXXX"), "{m:?}");
    assert!(m.iter().any(|(_, d)| d.starts_with(b"body")), "{m:?}");
}

#[test]
fn the_parts_of_an_attached_message_are_members_too() {
    let (m, r) = members(mail(&inner()).as_bytes());
    assert_eq!(r, Ok(()));
    let inner_attachment = m
        .iter()
        .find(|(_, d)| d == b"YYYYYYYY")
        .unwrap_or_else(|| panic!("the attachment of the attached message was not read: {m:?}"));
    assert!(
        inner_attachment.0.matches('-').count() >= 2,
        "{}",
        inner_attachment.0
    );
    assert!(m.iter().any(|(_, d)| d.starts_with(b"inner body")), "{m:?}");
    let mut names: Vec<_> = m.iter().map(|(n, _)| n.as_str()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), m.len(), "names are distinct: {names:?}");
}

/// A message attached to a message, `levels` deep, with an attachment at the
/// bottom.
fn chain(levels: usize) -> String {
    let mut body = inner();
    for i in 0..levels {
        body = format!(
            "From: a@b\r\nContent-Type: multipart/mixed; boundary=\"b{i}\"\r\n\r\n\
             --b{i}\r\nContent-Type: message/rfc822\r\n\r\n{body}\r\n--b{i}--\r\n"
        );
    }
    body
}

#[test]
fn a_chain_of_attached_messages_is_read_to_a_bound_and_refused_past_it() {
    let (m, r) = members(chain(8).as_bytes());
    assert_eq!(r, Ok(()));
    assert!(m.iter().any(|(_, d)| d == b"YYYYYYYY"), "{m:?}");
    let (_, r) = members(chain(200).as_bytes());
    let why = r.expect_err("a chain this deep is not read");
    assert!(why.contains("attached to messages"), "{why}");
}
