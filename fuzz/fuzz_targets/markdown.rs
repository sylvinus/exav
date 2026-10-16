#![no_main]
//! Markdown on hostile text: exav-render's reader, as @exav/viewer's text
//! module runs it. In the browser a panic traps the wasm instance, so every
//! one is a finding, and so is a tree that breaks one of its bounds.
use exav_render::markdown::{
    parse, visible_text, Block, Inline, MAX_BLOCK_DEPTH, MAX_INLINE_DEPTH, MAX_TARGET,
};
use libfuzzer_sys::fuzz_target;

fn inline_depth(c: &[Inline]) -> usize {
    c.iter()
        .map(|n| match n {
            Inline::Em(c) | Inline::Strong(c) | Inline::Del(c) => 1 + inline_depth(c),
            Inline::Link { url, children } => {
                // What the page is allowed to follow, checked on its own terms.
                let lower = url.to_ascii_lowercase();
                assert!(url.len() <= MAX_TARGET);
                assert!(lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("mailto:"), "{url}");
                let bad = |c: char| {
                    c == ' ' || c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
                };
                assert!(!url.chars().any(bad), "{url:?}");
                1 + inline_depth(children)
            }
            _ => 0,
        })
        .max()
        .unwrap_or(0)
}

fn check(blocks: &[Block], depth: usize, truncated: bool) {
    assert!(depth <= MAX_BLOCK_DEPTH);
    for b in blocks {
        match b {
            Block::Para(c) | Block::Heading { children: c, .. } => assert!(inline_depth(c) <= MAX_INLINE_DEPTH),
            Block::Quote(c) => check(c, depth + 1, truncated),
            Block::List { items, .. } => items.iter().for_each(|i| check(i, depth + 1, truncated)),
            Block::Table { align, head, rows } => {
                // A row cut by the node limit is as far as it got.
                assert!(truncated || (rows.iter().all(|r| r.len() == align.len()) && head.len() == align.len()));
                assert!(head.len() <= align.len() && rows.iter().all(|r| r.len() <= align.len()));
                head.iter().chain(rows.iter().flatten()).for_each(|c| assert!(inline_depth(c) <= MAX_INLINE_DEPTH));
            }
            Block::Code(_) | Block::Rule | Block::Raw(_) => {}
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // The page reads at most 2 MiB; the target keeps runs short.
    let Ok(text) = std::str::from_utf8(&data[..data.len().min(1 << 20)]).or_else(|e| std::str::from_utf8(&data[..e.valid_up_to()])) else { return };
    let doc = parse(text);
    check(&doc.blocks, 0, doc.truncated);
    // The JSON the page parses: balanced, and ending as it should.
    let json = doc.to_json();
    assert!(json.starts_with("{\"blocks\":[") && json.ends_with(if doc.truncated { ",\"truncated\":true}" } else { ",\"truncated\":false}" }));
    let (mut depth, mut in_string, mut escaped) = (0i64, false, false);
    for b in json.bytes() {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                (false, b) => assert!(b >= 0x20),
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0);
        }
    }
    assert!(depth == 0 && !in_string);
    // The text a reader sees, for the scanner and for search: within its cap,
    // and cut exactly when it says so.
    let cap = text.len().saturating_mul(4) + (64 << 10);
    let visible = visible_text(text, cap);
    assert!(visible.text.len() <= cap);
    assert!(!visible.truncated || visible.text.len() > cap - 4);
});
