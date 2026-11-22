use crate::formats::pdf_parse::lex::{Lexer, Token, is_white};
use crate::formats::pdf_parse::types::Primitive;
use std::collections::HashMap;

/// How deep arrays and dictionaries are read; this bounds the recursion. A
/// value nested deeper is passed over as a null and the object goes on.
pub(crate) const MAX_DEPTH: usize = 64;

/// How many bytes of white space are looked past between the end of a stream's
/// `/Length` bytes and `endstream`. It bounds a look-ahead, not the scan.
const MAX_WHITE_BEFORE_ENDSTREAM: usize = 256;

/// The value of `/Length` when it names another object: its number to the
/// integer that object is, if the caller can tell.
type LengthOf<'a> = &'a mut dyn FnMut(u32) -> Option<u64>;

pub(crate) fn parse_object(lex: &mut Lexer) -> Option<Primitive> {
    parse_object_depth(lex, 0, &mut |_| None)
}

fn parse_object_depth(lex: &mut Lexer, depth: usize, length_of: LengthOf) -> Option<Primitive> {
    let mut tok = lex.next_token();
    // A bare "obj" keyword is passed over.
    while tok == Token::Obj {
        tok = lex.next_token();
    }
    match tok {
        Token::ArrayStart | Token::DictStart if depth > MAX_DEPTH => {
            skip_container(lex);
            lex.pass_over();
            Some(Primitive::Null)
        }
        Token::Null => Some(Primitive::Null),
        Token::True => Some(Primitive::Boolean(true)),
        Token::False => Some(Primitive::Boolean(false)),
        Token::Integer(n) => {
            // An integer may begin an indirect reference `n g R` (e.g. a dict
            // value like `/Root 1 0 R`). Consume the `g R` so the enclosing dict
            // or array stays token-aligned; otherwise the dangling `g R` derails
            // the rest of the parse (this dropped the trailer's `/ID`, breaking
            // encrypted-PDF key derivation). The reference target isn't resolved
            // here, so it surfaces as the leading integer.
            let saved = lex.pos();
            if let Token::Integer(_gen) = lex.next_token()
                && let Token::R = lex.next_token()
            {
                return Some(Primitive::Reference(n as u32));
            }
            lex.set_pos(saved);
            Some(Primitive::Integer(n))
        }
        Token::Real(r) => Some(Primitive::Real(r)),
        Token::Name(n) => Some(Primitive::Name(n)),
        Token::String(s) => Some(Primitive::String(s)),
        Token::ArrayStart => Some(parse_array(lex, depth, length_of)),
        Token::DictStart => {
            // Could be dictionary OR stream
            let dict = parse_dict_entries(lex, depth, length_of);
            // Check for stream
            let saved = lex.pos();
            let tok2 = lex.next_token();
            match tok2 {
                Token::Stream => {
                    // Read stream data
                    let stream_data = read_stream_data(lex, Some(&dict), length_of);
                    Some(Primitive::Stream {
                        info: dict,
                        data: stream_data,
                    })
                }
                _ => {
                    // Not a stream, backtrack
                    lex.set_pos(saved);
                    Some(Primitive::Dictionary(dict))
                }
            }
        }
        // Inside an array or a dictionary a keyword is read as a null, as a
        // reader that goes by the cross-reference table does, and the object
        // goes on after it.
        Token::Stream | Token::EndObj | Token::EndStream if depth > 0 => Some(Primitive::Null),
        Token::Obj
        | Token::EndObj
        | Token::EndStream
        | Token::Eof
        | Token::DictEnd
        | Token::ArrayEnd => None,
        Token::Stream => {
            // Bare "stream" without dict: read and ignore
            let _ = read_stream_data(lex, None, length_of);
            Some(Primitive::Null)
        }
        Token::R => {
            // Bare "R" without preceding numbers: shouldn't happen in valid parse
            Some(Primitive::Null)
        }
    }
}

/// Moves past the array or dictionary whose opening has just been read, to
/// after the closing that matches it, or to the end of the data.
fn skip_container(lex: &mut Lexer) {
    let mut open = 1usize;
    while open > 0 {
        match lex.next_token() {
            Token::ArrayStart | Token::DictStart => open += 1,
            Token::ArrayEnd | Token::DictEnd => open -= 1,
            Token::Eof => break,
            _ => {}
        }
    }
}

fn parse_array(lex: &mut Lexer, depth: usize, length_of: LengthOf) -> Primitive {
    let mut items = Vec::new();
    loop {
        let saved = lex.pos();
        match lex.next_token() {
            Token::ArrayEnd => break,
            Token::Eof => break,
            _ => {
                lex.set_pos(saved);
                if let Some(val) = parse_object_depth(lex, depth + 1, length_of) {
                    items.push(val);
                } else {
                    break;
                }
            }
        }
    }
    Primitive::Array(items)
}

fn parse_dict_entries(
    lex: &mut Lexer,
    depth: usize,
    length_of: LengthOf,
) -> HashMap<String, Primitive> {
    let mut map = HashMap::new();
    loop {
        let saved = lex.pos();
        match lex.next_token() {
            Token::DictEnd => break,
            Token::Eof => break,
            Token::Name(key) => {
                if let Some(val) = parse_object_depth(lex, depth + 1, length_of) {
                    map.insert(key, val);
                } else {
                    break;
                }
            }
            _ => {
                // Not a name: might be end of dict, skip
                lex.set_pos(saved);
                break;
            }
        }
    }
    map
}

/// The data of a stream whose `stream` keyword was just read. It ends at the
/// first `endstream` keyword, or where the dictionary's `/Length` says when
/// that is further on and an `endstream` keyword follows it. The reading
/// goes on after the first keyword, so the objects between the two ends are
/// found by the scan as well.
fn read_stream_data(
    lex: &mut Lexer,
    dict: Option<&HashMap<String, Primitive>>,
    length_of: LengthOf,
) -> Vec<u8> {
    // After "stream" keyword, data starts at current position
    let start = lex.pos();
    // Look for endstream
    let remaining = lex.remaining();
    if let Some(end) = find_endstream(remaining) {
        let stream_end = start + end;
        // The end of line before `endstream` is not part of the data.
        let data = &remaining[..end];
        let data = data
            .strip_suffix(b"\r\n")
            .or_else(|| data.strip_suffix(b"\n"))
            .or_else(|| data.strip_suffix(b"\r"))
            .unwrap_or(data);
        let declared = dict
            .and_then(|d| declared_length(d, length_of))
            .filter(|&n| n > end as u64 && n <= remaining.len() as u64)
            .map(|n| n as usize)
            .filter(|&n| endstream_follows(&remaining[n..]));
        let data = declared.map_or(data, |n| &remaining[..n]).to_vec();
        lex.set_pos(stream_end);
        // Skip "endstream"
        let _ = lex.next_token();
        data
    } else {
        // No endstream found: take remaining
        let data = remaining.to_vec();
        lex.set_pos(lex.data().len());
        data
    }
}

/// The `/Length` of a stream dictionary: a number, or the one the object it
/// names is.
fn declared_length(dict: &HashMap<String, Primitive>, length_of: LengthOf) -> Option<u64> {
    match dict.get("Length")? {
        Primitive::Integer(n) => u64::try_from(*n).ok(),
        Primitive::Reference(id) => length_of(*id),
        _ => None,
    }
}

/// Whether `data` begins with up to [`MAX_WHITE_BEFORE_ENDSTREAM`] bytes of
/// white space and the `endstream` keyword.
fn endstream_follows(data: &[u8]) -> bool {
    let white = data
        .iter()
        .take(MAX_WHITE_BEFORE_ENDSTREAM)
        .take_while(|&&b| is_white(b))
        .count();
    data[white..]
        .strip_prefix(b"endstream")
        .is_some_and(|after| after.first().is_none_or(|b| !b.is_ascii_alphanumeric()))
}

fn find_endstream(data: &[u8]) -> Option<usize> {
    // Search for "endstream" followed by whitespace or EOF
    let needle = b"endstream";
    let mut i = 0;
    while i + needle.len() <= data.len() {
        if &data[i..i + needle.len()] == needle {
            // Check it's not "endstream" as part of a longer word
            let after = i + needle.len();
            if after >= data.len() || !data[after].is_ascii_alphanumeric() {
                return Some(i);
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
    None
}

/// Moves past the data of a stream whose `stream` keyword was just read: to
/// after its `endstream`, or to the end of the data when it has none. This is
/// the extent [`parse_object`] gives the stream.
pub(crate) fn skip_stream_data(lex: &mut Lexer) {
    match find_endstream(lex.remaining()) {
        Some(end) => {
            lex.set_pos(lex.pos() + end);
            let _ = lex.next_token();
        }
        None => lex.set_pos(lex.data().len()),
    }
}

/// The dictionary of a stream object, read without the stream's data. `None`
/// when the object is not a dictionary followed by the `stream` keyword.
pub(crate) fn parse_stream_head(lex: &mut Lexer) -> Option<HashMap<String, Primitive>> {
    if lex.next_token() != Token::DictStart {
        return None;
    }
    let dict = parse_dict_entries(lex, 0, &mut |_| None);
    (lex.next_token() == Token::Stream).then_some(dict)
}

/// Parse a PDF indirect object body: after "N G obj", read until "endobj".
/// Returns the object content and the byte offset of endobj. A stream's
/// `/Length` is used when it is a number.
pub(crate) fn parse_indirect_object_body(lex: &mut Lexer) -> Option<(Primitive, usize)> {
    parse_indirect_object_with(lex, &mut |_| None)
}

/// [`parse_indirect_object_body`] for a caller that can tell the integer an
/// object is, for a stream whose `/Length` names one.
pub(crate) fn parse_indirect_object_with(
    lex: &mut Lexer,
    length_of: &mut dyn FnMut(u32) -> Option<u64>,
) -> Option<(Primitive, usize)> {
    let obj = parse_object_depth(lex, 0, length_of)?;
    let end = lex.pos();
    Some((obj, end))
}
