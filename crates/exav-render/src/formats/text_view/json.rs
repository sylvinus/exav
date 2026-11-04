//! A JSON pretty printer that works on the tokens and copies each one as it
//! is written: numbers keep their text (2^70 or 1.10 are not rounded by a
//! parse and a print), strings keep their escapes, key order and duplicates
//! stay. Strict: a trailing comma, a comment or a bare word make the text
//! invalid, and `None` is returned.

use super::{Formatted, LineBuilder, class, indent};

/// Deeper than this is refused: the output indents by two spaces per level.
pub const MAX_DEPTH: usize = 100;

#[derive(Clone, Copy, PartialEq)]
enum State {
    Value,
    Key,
    After,
    End,
}

/// The lines of `text` indented, at most `max_lines` of them, or `None` when
/// it is not valid JSON (or nests deeper than [`MAX_DEPTH`]). The whole text
/// is read either way.
pub fn format_json(text: &str, max_lines: usize) -> Option<Formatted<'_>> {
    let b = text.as_bytes();
    let n = b.len();
    let mut out = LineBuilder::new(max_lines);
    let mut i = 0;
    // true for an object, false for an array.
    let mut stack: Vec<bool> = Vec::new();
    let mut state = State::Value;

    loop {
        while i < n && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= n {
            break;
        }
        let ch = b[i];
        if state == State::End {
            return None;
        }
        match state {
            State::Key => {
                if ch != b'"' {
                    return None;
                }
                let e = string_end(b, i)?;
                out.add(&text[i..e], Some(class::KEY));
                i = skip_space(b, e);
                if b.get(i) != Some(&b':') {
                    return None;
                }
                i += 1;
                out.add(": ", None);
                state = State::Value;
            }
            State::After => {
                let object = *stack.last()?;
                if ch == b',' {
                    i += 1;
                    out.add(",", None);
                    out.end();
                    out.add(indent(stack.len()), None);
                    state = if object { State::Key } else { State::Value };
                } else if ch == if object { b'}' } else { b']' } {
                    stack.pop();
                    out.end();
                    out.add(indent(stack.len()), None);
                    out.add(&text[i..i + 1], None);
                    i += 1;
                    state = after(&stack);
                } else {
                    return None;
                }
            }
            State::Value if ch == b'{' || ch == b'[' => {
                if stack.len() >= MAX_DEPTH {
                    return None;
                }
                i = skip_space(b, i + 1);
                let (open, close) = if ch == b'{' { ("{", "}") } else { ("[", "]") };
                if b.get(i) == Some(&close.as_bytes()[0]) {
                    i += 1;
                    out.add(if ch == b'{' { "{}" } else { "[]" }, None);
                    state = after(&stack);
                } else {
                    stack.push(ch == b'{');
                    out.add(open, None);
                    out.end();
                    out.add(indent(stack.len()), None);
                    state = if ch == b'{' { State::Key } else { State::Value };
                }
            }
            State::Value if ch == b'"' => {
                let e = string_end(b, i)?;
                out.add(&text[i..e], Some(class::STR));
                i = e;
                state = after(&stack);
            }
            State::Value => {
                let mut e = None;
                let mut cls = class::LIT;
                for word in ["true", "false", "null"] {
                    if b[i..].starts_with(word.as_bytes()) {
                        e = Some(i + word.len());
                    }
                }
                if e.is_none() {
                    e = number_end(b, i);
                    cls = class::NUM;
                }
                let e = e?;
                out.add(&text[i..e], Some(cls));
                i = e;
                state = after(&stack);
            }
            State::End => return None,
        }
    }
    if state != State::End {
        return None;
    }
    out.finish();
    Some(Formatted {
        lines: out.lines,
        more: out.full,
        well_formed: true,
    })
}

fn after(stack: &[bool]) -> State {
    if stack.is_empty() {
        State::End
    } else {
        State::After
    }
}

fn skip_space(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// The end of the string starting at `i`.
fn string_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < b.len() {
        let c = b[j];
        if c == b'"' {
            return Some(j + 1);
        }
        if c < 0x20 {
            return None;
        }
        if c == b'\\' {
            match b.get(j + 1)? {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => j += 2,
                b'u' => {
                    let hex = b.get(j + 2..j + 6)?;
                    if !hex.iter().all(u8::is_ascii_hexdigit) {
                        return None;
                    }
                    j += 6;
                }
                _ => return None,
            }
        } else {
            j += 1;
        }
    }
    None
}

fn digits(b: &[u8], mut j: usize) -> Option<usize> {
    let start = j;
    while j < b.len() && b[j].is_ascii_digit() {
        j += 1;
    }
    (j > start).then_some(j)
}

/// The end of the number starting at `i`.
fn number_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    if b.get(j) == Some(&b'-') {
        j += 1;
    }
    if b.get(j) == Some(&b'0') {
        j += 1;
    } else {
        j = digits(b, j)?;
    }
    if b.get(j) == Some(&b'.') {
        j = digits(b, j + 1)?;
    }
    if matches!(b.get(j), Some(b'e' | b'E')) {
        j += 1;
        if matches!(b.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        j = digits(b, j)?;
    }
    Some(j)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn show(text: &str, max: usize) -> Option<String> {
        format_json(text, max).map(|f| {
            f.lines
                .iter()
                .map(|l| l.text())
                .collect::<Vec<_>>()
                .join("\n")
        })
    }

    fn show_all(text: &str) -> Option<String> {
        show(text, 50_000)
    }

    #[test]
    fn indents_by_two_spaces_one_value_per_line() {
        assert_eq!(
            show_all(r#"{"a":[1,2,{"b":null}],"c":"x","d":true}"#).unwrap(),
            [
                "{",
                r#"  "a": ["#,
                "    1,",
                "    2,",
                "    {",
                r#"      "b": null"#,
                "    }",
                "  ],",
                r#"  "c": "x","#,
                r#"  "d": true"#,
                "}",
            ]
            .join("\n")
        );
    }

    #[test]
    fn keeps_empty_containers_on_one_line() {
        assert_eq!(
            show_all(r#"{"a":{},"b":[ ],"c":[[]]}"#).unwrap(),
            [
                "{",
                r#"  "a": {},"#,
                r#"  "b": [],"#,
                r#"  "c": ["#,
                "    []",
                "  ]",
                "}"
            ]
            .join("\n")
        );
    }

    #[test]
    fn keeps_the_text_of_numbers_and_strings_exactly() {
        let src = r#"[12345678901234567890123,1.10,-0,1E+2,0.1e-7,"é\n\/","é"]"#;
        let out = show_all(src).unwrap();
        for token in [
            "12345678901234567890123",
            "1.10",
            "-0",
            "1E+2",
            "0.1e-7",
            r#""é\n\/""#,
            r#""é""#,
        ] {
            assert!(out.contains(token), "{token}");
        }
    }

    #[test]
    fn keeps_key_order_and_duplicate_keys() {
        assert_eq!(
            show_all(r#"{"b":1,"a":2,"b":3}"#).unwrap(),
            "{\n  \"b\": 1,\n  \"a\": 2,\n  \"b\": 3\n}"
        );
    }

    /// `s` without the whitespace outside its strings.
    fn compact(s: &str) -> String {
        let (mut out, mut inside, mut escaped) = (String::new(), false, false);
        for c in s.chars() {
            if inside {
                out.push(c);
                match (escaped, c) {
                    (true, _) => escaped = false,
                    (false, '\\') => escaped = true,
                    (false, '"') => inside = false,
                    _ => {}
                }
            } else if !c.is_whitespace() {
                inside = c == '"';
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn says_the_same_thing_as_the_input() {
        for s in [
            r#"{"menu":{"id":"file","items":[{"label":"New","shortcut":null},{"label":"Open","n":[1,2.5,-3e2]}],"on":false}}"#,
            r#"[[],{},[[[]]],"a\"b"]"#,
            r#""just a string""#,
            "  42  ",
            "{ \"a\" : 1 ,\n\t\"b\" : [ 1 , 2 ] }",
        ] {
            assert_eq!(compact(&show_all(s).unwrap()), compact(s), "{s}");
        }
    }

    #[test]
    fn marks_the_parts_so_that_they_can_be_coloured_without_changing_the_text() {
        let f = format_json(r#"{"k":"v","n":1,"t":null}"#, 100).unwrap();
        let of = |cls: &str| -> Vec<&str> {
            f.lines
                .iter()
                .flat_map(|l| match l {
                    super::super::Line::Segs(s) => s.clone(),
                    _ => vec![],
                })
                .filter(|s| s.class == Some(cls))
                .map(|s| s.text)
                .collect()
        };
        assert_eq!(of(class::KEY), [r#""k""#, r#""n""#, r#""t""#]);
        assert_eq!(of(class::STR), [r#""v""#]);
        assert_eq!(of(class::NUM), ["1"]);
        assert_eq!(of(class::LIT), ["null"]);
    }

    #[test]
    fn refuses_what_is_not_strict_json() {
        for bad in [
            "",
            "   ",
            "{",
            "}",
            "[1,]",
            "[,1]",
            r#"{"a":1,}"#,
            "{'a':1}",
            "{a:1}",
            "[1 2]",
            r#"{"a" 1}"#,
            r#"{"a":}"#,
            "[1]x",
            "[1][2]",
            "// c\n[1]",
            "[1 /* c */]",
            "NaN",
            "[Infinity]",
            "[01]",
            "[1.]",
            "[.5]",
            "[+1]",
            "[1e]",
            "[-]",
            "[tru]",
            "[nulll]",
            "[True]",
            "\"unterminated",
            r#""bad \x escape""#,
            r#""\u12G4""#,
            "\"raw\nnewline\"",
            "\"raw\ttab\"",
            r#"{"a":1 "b":2}"#,
            r#"{"a":1:2}"#,
            "{1:2}",
            "[{]}",
        ] {
            assert!(format_json(bad, 50_000).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn refuses_nesting_deeper_than_the_limit_and_accepts_it_at_the_limit() {
        let deep = |n: usize| "[".repeat(n) + &"]".repeat(n);
        assert!(format_json(&deep(MAX_DEPTH), 50_000).is_some());
        assert!(format_json(&deep(MAX_DEPTH + 1), 50_000).is_none());
        let objects = |n: usize| r#"{"a":"#.repeat(n) + "1" + &"}".repeat(n);
        assert!(format_json(&objects(MAX_DEPTH), 50_000).is_some());
        assert!(format_json(&objects(MAX_DEPTH + 1), 50_000).is_none());
    }

    #[test]
    fn stops_keeping_lines_at_the_cap_and_says_so() {
        let items: Vec<String> = (0..1000).map(|i| i.to_string()).collect();
        let text = format!("[{}]", items.join(","));
        let f = format_json(&text, 100).unwrap();
        assert_eq!(f.lines.len(), 100);
        assert!(f.more);
        let first: Vec<String> = f.lines.iter().take(3).map(|l| l.text()).collect();
        assert_eq!(first, ["[", "  0,", "  1,"]);
        assert!(!format_json(&text, 5000).unwrap().more);
    }

    #[test]
    fn is_quick_on_hostile_input() {
        let t = Instant::now();
        for s in [
            "[".repeat(2_000_000),
            r#"{"a":"#.repeat(400_000),
            format!("[\"{}", "\\".repeat(1_000_001)),
            format!("[{}1]", "1,".repeat(1_000_000)),
            format!("[{}\"x\"", "\"x\",".repeat(500_000)),
            format!("\"{}\"", "a".repeat(2_000_000)),
            format!("[{}{{}}]", "{\"a\":[]},".repeat(200_000)),
        ] {
            format_json(&s, 50_000);
        }
        // The page's test allowed 5 s in a JavaScript engine; this one runs unoptimised.
        assert!(t.elapsed().as_secs() < 20, "{:?}", t.elapsed());
    }
}
