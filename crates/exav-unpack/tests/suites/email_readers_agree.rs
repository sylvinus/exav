//! What a mail reader shows of a message is what exav scans.
//!
//! The parser leaves out three things a reader shows: the last part of a
//! multipart that nothing closed, a base64 part with a byte in it outside the
//! alphabet, and a file uuencoded into the text. The payload is base64 or
//! uuencoded EICAR, so the string is nowhere in the message itself.

use exav_unpack::{Budget, Entry, Format, Limits, extract};

fn eicar() -> &'static [u8] {
    exav_unpack::eicar()
}

fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// 76 columns, as a mail client writes it.
fn wrapped(b64: &str) -> String {
    b64.as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn message(body_after_headers: &str) -> Vec<u8> {
    format!(
        "From: a@example.org\r\nTo: b@example.org\r\nSubject: s\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n{body_after_headers}"
    )
    .into_bytes()
}

fn entries(msg: &[u8]) -> Vec<Entry> {
    let mut budget = Budget::new(Limits::default());
    extract(Format::Email, &msg, &mut budget).unwrap()
}

fn has_payload(entries: &[Entry]) -> bool {
    entries
        .iter()
        .any(|e| e.data.windows(eicar().len()).any(|w| w == eicar()))
}

fn attachment(encoded: &str) -> String {
    format!(
        "--b1\r\nContent-Type: text/plain\r\n\r\nSee the attachment.\r\n\
         --b1\r\nContent-Type: application/octet-stream; name=\"e.com\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
    )
}

fn assert_hidden_from_a_byte_search(msg: &[u8]) {
    assert!(
        !msg.windows(eicar().len()).any(|w| w == eicar()),
        "the string must not be in the message's bytes"
    );
}

#[test]
fn a_closed_multipart_is_read() {
    let msg = message(&format!(
        "{}--b1--\r\n",
        attachment(&wrapped(&base64(eicar())))
    ));
    assert_hidden_from_a_byte_search(&msg);
    assert!(has_payload(&entries(&msg)));
}

#[test]
fn the_last_part_of_a_multipart_nothing_closed_is_read() {
    let msg = message(&attachment(&wrapped(&base64(eicar()))));
    assert_hidden_from_a_byte_search(&msg);
    assert!(has_payload(&entries(&msg)));
}

#[test]
fn an_inner_multipart_nothing_closed_is_read_with_the_outer_one() {
    let inner = format!(
        "--b1\r\nContent-Type: multipart/mixed; boundary=\"b2\"\r\n\r\n\
         --b2\r\nContent-Type: application/octet-stream\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        wrapped(&base64(eicar()))
    );
    let msg = message(&inner);
    assert_hidden_from_a_byte_search(&msg);
    assert!(has_payload(&entries(&msg)));
}

#[test]
fn a_base64_part_with_a_byte_outside_the_alphabet_is_read_as_far_as_it_goes() {
    let mut enc = wrapped(&base64(eicar()));
    enc.insert(30, '!');
    let msg = message(&format!("{}--b1--\r\n", attachment(&enc)));
    assert_hidden_from_a_byte_search(&msg);
    assert!(has_payload(&entries(&msg)));
}

#[cfg(feature = "uuencode")]
#[test]
fn a_file_uuencoded_into_the_text_is_read() {
    fn uu(name: &str, data: &[u8]) -> String {
        let enc = |v: u8| (if v == 0 { b'`' } else { v + 32 }) as char;
        let mut out = format!("begin 644 {name}\n");
        for line in data.chunks(45) {
            out.push(enc(line.len() as u8));
            for g in line.chunks(3) {
                let b = [g[0], *g.get(1).unwrap_or(&0), *g.get(2).unwrap_or(&0)];
                out.push(enc(b[0] >> 2));
                out.push(enc((b[0] << 4 | b[1] >> 4) & 63));
                out.push(enc((b[1] << 2 | b[2] >> 6) & 63));
                out.push(enc(b[2] & 63));
            }
            out.push('\n');
        }
        out.push_str("`\nend\n");
        out
    }
    let text = format!(
        "--b1\r\nContent-Type: text/plain\r\n\r\nHere is the file.\n\n{}\r\n--b1--\r\n",
        uu("e.com", eicar())
    );
    let msg = message(&text);
    assert_hidden_from_a_byte_search(&msg);
    assert!(has_payload(&entries(&msg)));
}
