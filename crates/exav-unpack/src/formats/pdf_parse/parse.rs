use crate::formats::pdf_parse::lex::{Lexer, Token};
use crate::formats::pdf_parse::types::Primitive;
use std::collections::HashMap;

const MAX_DEPTH: usize = 20;

pub(crate) fn parse_object(lex: &mut Lexer) -> Option<Primitive> {
    parse_object_depth(lex, 0)
}

fn parse_object_depth(lex: &mut Lexer, depth: usize) -> Option<Primitive> {
    if depth > MAX_DEPTH {
        return None;
    }
    let tok = lex.next_token();
    match tok {
        Token::Null => Some(Primitive::Null),
        Token::True => Some(Primitive::Boolean(true)),
        Token::False => Some(Primitive::Boolean(false)),
        Token::Integer(n) => Some(Primitive::Integer(n)),
        Token::Real(_) => Some(Primitive::Real),
        Token::Name(n) => Some(Primitive::Name(n)),
        Token::String(s) => Some(Primitive::String(s)),
        Token::ArrayStart => Some(parse_array(lex, depth)),
        Token::DictStart => {
            // Could be dictionary OR stream
            let dict = parse_dict_entries(lex, depth);
            // Check for stream
            let saved = lex.pos();
            let tok2 = lex.next_token();
            match tok2 {
                Token::Stream => {
                    // Read stream data
                    let stream_data = read_stream_data(lex);
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
        Token::Obj => {
            // Bare "obj" keyword — skip and try again
            parse_object_depth(lex, depth)
        }
        Token::EndObj | Token::EndStream | Token::Eof | Token::DictEnd | Token::ArrayEnd => None,
        Token::Stream => {
            // Bare "stream" without dict — read and ignore
            let _ = read_stream_data(lex);
            Some(Primitive::Null)
        }
        Token::R => {
            // Bare "R" without preceding numbers — shouldn't happen in valid parse
            Some(Primitive::Null)
        }
    }
}

fn parse_array(lex: &mut Lexer, depth: usize) -> Primitive {
    let mut items = Vec::new();
    loop {
        let saved = lex.pos();
        match lex.next_token() {
            Token::ArrayEnd => break,
            Token::Eof => break,
            _ => {
                lex.set_pos(saved);
                if let Some(val) = parse_object_depth(lex, depth + 1) {
                    items.push(val);
                } else {
                    break;
                }
            }
        }
    }
    Primitive::Array(items)
}

fn parse_dict_entries(lex: &mut Lexer, depth: usize) -> HashMap<String, Primitive> {
    let mut map = HashMap::new();
    loop {
        let saved = lex.pos();
        match lex.next_token() {
            Token::DictEnd => break,
            Token::Eof => break,
            Token::Name(key) => {
                if let Some(val) = parse_object_depth(lex, depth + 1) {
                    map.insert(key, val);
                } else {
                    break;
                }
            }
            _ => {
                // Not a name — might be end of dict, skip
                lex.set_pos(saved);
                break;
            }
        }
    }
    map
}

fn read_stream_data(lex: &mut Lexer) -> Vec<u8> {
    // After "stream" keyword, data starts at current position
    // Stream ends at "endstream" keyword
    let start = lex.pos();
    // Look for endstream
    let remaining = lex.remaining();
    if let Some(end) = find_endstream(remaining) {
        let stream_end = start + end;
        let data = lex.remaining()[..end].to_vec();
        lex.set_pos(stream_end);
        // Skip "endstream"
        let _ = lex.next_token();
        data
    } else {
        // No endstream found — take remaining
        let data = remaining.to_vec();
        lex.set_pos(lex.data().len());
        data
    }
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

/// Parse a PDF indirect object body: after "N G obj", read until "endobj".
/// Returns the object content and the byte offset of endobj.
pub(crate) fn parse_indirect_object_body(lex: &mut Lexer) -> Option<(Primitive, usize)> {
    let obj = parse_object(lex)?;
    let end = lex.pos();
    Some((obj, end))
}

/// Quick check: does the data at this position look like a stream dictionary
/// that contains FlateDecode in its /Filter?
pub(crate) fn dict_has_flate(dict: &HashMap<String, Primitive>) -> bool {
    match dict.get("Filter") {
        Some(Primitive::Name(n)) => n == "FlateDecode",
        Some(Primitive::Array(arr)) => arr
            .iter()
            .any(|p| matches!(p, Primitive::Name(n) if n == "FlateDecode")),
        _ => false,
    }
}
