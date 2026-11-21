//! The objects inside a PDF object stream (ISO 32000-1, 7.5.7): `/N` pairs of
//! "number offset" at the start of the decoded stream, then the objects, the
//! offsets counted from `/First`.

use std::collections::HashMap;

use super::pdf_parse::lex::{Lexer, Token};
use super::pdf_parse::parse::parse_object;
use super::pdf_parse::types::Primitive;

/// An object stream of the file.
pub(super) struct ObjStm {
    pub(super) number: u32,
    pub(super) generation: u32,
    /// Where its body starts, after `obj`.
    pub(super) start: usize,
    /// What it decodes to: empty until it is read, and when it cannot be.
    pub(super) decoded: Vec<u8>,
}

/// Whether a stream with this dictionary may be an object stream: it is typed
/// `/ObjStm`, or it has no `/Type` and a `/N` and a `/First`. A reader that
/// goes by the cross-reference data reaches an object stream through its
/// entries and need not check the type. Settled by [`is_object_stream`] once
/// the stream is decoded.
pub(super) fn may_be_object_stream(info: &HashMap<String, Primitive>) -> bool {
    match info.get("Type") {
        Some(Primitive::Name(name)) => name == "ObjStm",
        Some(_) => false,
        None => ["N", "First"].iter().all(|key| {
            matches!(
                info.get(*key),
                Some(Primitive::Integer(_) | Primitive::Reference(_))
            )
        }),
    }
}

/// Whether the stream with this dictionary, decoded to `decoded`, is an object
/// stream; `count` and `first` are its `/N` and `/First`. One typed `/ObjStm`
/// is. One without a `/Type` is when its header is `count` pairs of integers
/// before `first`: an ICC profile also has an `/N`, and no such header.
pub(super) fn is_object_stream(
    info: &HashMap<String, Primitive>,
    count: i64,
    first: i64,
    decoded: &[u8],
) -> bool {
    match info.get("Type") {
        Some(Primitive::Name(name)) => name == "ObjStm",
        Some(_) => false,
        None => has_header(decoded, count, first),
    }
}

/// Whether `decoded` begins with `count` pairs of integers, all before `first`.
fn has_header(decoded: &[u8], count: i64, first: i64) -> bool {
    let Some(first) = usize::try_from(first)
        .ok()
        .filter(|&first| first <= decoded.len())
    else {
        return false;
    };
    let mut lex = Lexer::new(&decoded[..first]);
    count > 0
        && (0..count).all(|_| {
            matches!(
                (lex.next_token(), lex.next_token()),
                (Token::Integer(_), Token::Integer(_))
            )
        })
}

/// The `(number, offset)` of each object in `decoded`, in the order of its
/// header, the offsets counted from the start of `decoded`. `count` is `/N` and
/// `first` is `/First`, both taken from the file: the header is read as far as
/// the bytes before `first` go, and an object that starts past the end is left
/// out. At most `at_most` pairs are read.
pub(super) fn table(decoded: &[u8], count: i64, first: i64, at_most: u64) -> Vec<(u32, usize)> {
    let Some(first) = usize::try_from(first)
        .ok()
        .filter(|&first| first <= decoded.len())
    else {
        return Vec::new();
    };
    let mut lex = Lexer::new(&decoded[..first]);
    let mut found = Vec::new();
    for _ in 0..count.max(0) {
        if found.len() as u64 >= at_most {
            break;
        }
        let (Token::Integer(number), Token::Integer(offset)) = (lex.next_token(), lex.next_token())
        else {
            break;
        };
        let start = usize::try_from(offset)
            .ok()
            .and_then(|offset| first.checked_add(offset));
        if let (Ok(number), Some(start)) = (u32::try_from(number), start)
            && start < decoded.len()
        {
            found.push((number, start));
        }
    }
    found
}

/// The object that starts at `offset` in `decoded`, and where its parse ended.
/// An object that does not parse can have run to the end. The last value is
/// whether a value of the object was passed over for its depth.
pub(super) fn object_at(decoded: &[u8], offset: usize) -> (Option<Primitive>, usize, bool) {
    let mut lex = Lexer::new(decoded);
    lex.set_pos(offset);
    let object = parse_object(&mut lex);
    let passed_over = lex.take_passed_over();
    (object, lex.pos(), passed_over)
}
