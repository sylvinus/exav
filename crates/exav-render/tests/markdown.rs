//! Markdown into blocks and inlines: what a document shows, what a link may
//! be, that raw HTML is only ever text, and that hostile input is bounded in
//! time, stack and size.

use exav_render::markdown::{
    Align, Block, Document, Inline, MAX_BLOCK_DEPTH, MAX_COLUMNS, MAX_INLINE_DEPTH, MAX_NODES,
    MAX_TARGET, parse,
};

fn doc(md: &str) -> Document {
    parse(md)
}

/// The text of inlines, as read: no marks, links as their labels, images as their alt.
fn text(c: &[Inline]) -> String {
    let mut s = String::new();
    for n in c {
        match n {
            Inline::Text(t) | Inline::Code(t) => s.push_str(t),
            Inline::Br => {}
            Inline::Em(c) | Inline::Strong(c) | Inline::Del(c) => s.push_str(&text(c)),
            Inline::Link { children, .. } => s.push_str(&text(children)),
            Inline::Image { alt } => s.push_str(alt),
        }
    }
    s
}

/// Every inline of the document, depth first.
fn inlines(blocks: &[Block], out: &mut Vec<Inline>) {
    fn inl(c: &[Inline], out: &mut Vec<Inline>) {
        for n in c {
            out.push(n.clone());
            match n {
                Inline::Em(c)
                | Inline::Strong(c)
                | Inline::Del(c)
                | Inline::Link { children: c, .. } => inl(c, out),
                _ => {}
            }
        }
    }
    for b in blocks {
        match b {
            Block::Para(c) | Block::Heading { children: c, .. } => inl(c, out),
            Block::Quote(c) => inlines(c, out),
            Block::List { items, .. } => items.iter().for_each(|i| inlines(i, out)),
            Block::Table { head, rows, .. } => {
                head.iter().for_each(|c| inl(c, out));
                rows.iter().flatten().for_each(|c| inl(c, out));
            }
            Block::Code(_) | Block::Rule | Block::Raw(_) => {}
        }
    }
}

fn all_inlines(d: &Document) -> Vec<Inline> {
    let mut v = Vec::new();
    inlines(&d.blocks, &mut v);
    v
}

fn links(d: &Document) -> Vec<(String, String)> {
    all_inlines(d)
        .into_iter()
        .filter_map(|n| match n {
            Inline::Link { url, children } => Some((url, text(&children))),
            _ => None,
        })
        .collect()
}

fn paras(blocks: &[Block]) -> Vec<String> {
    blocks
        .iter()
        .filter_map(|b| match b {
            Block::Para(c) => Some(text(c)),
            _ => None,
        })
        .collect()
}

fn heading(d: &Document, level: u8) -> Vec<String> {
    d.blocks
        .iter()
        .filter_map(|b| match b {
            Block::Heading { level: l, children } if *l == level => Some(text(children)),
            _ => None,
        })
        .collect()
}

fn marks(d: &Document, f: fn(&Inline) -> Option<&Vec<Inline>>) -> Vec<String> {
    all_inlines(d)
        .iter()
        .filter_map(|n| f(n).map(|c| text(c)))
        .collect()
}

fn em(n: &Inline) -> Option<&Vec<Inline>> {
    if let Inline::Em(c) = n { Some(c) } else { None }
}
fn strong(n: &Inline) -> Option<&Vec<Inline>> {
    if let Inline::Strong(c) = n {
        Some(c)
    } else {
        None
    }
}
fn del(n: &Inline) -> Option<&Vec<Inline>> {
    if let Inline::Del(c) = n {
        Some(c)
    } else {
        None
    }
}

// ── blocks ───────────────────────────────────────────────────────────────────

#[test]
fn headings_atx_and_setext_with_closing_hashes_dropped() {
    let d = doc("# One #\n\n## Two\n\nThree\n=====\n\nFour\n----\n\n####### seven\n\n#nospace");
    assert_eq!(heading(&d, 1), ["One", "Three"]);
    assert_eq!(heading(&d, 2), ["Two", "Four"]);
    assert_eq!(paras(&d.blocks), ["####### seven", "#nospace"]);
}

#[test]
fn emphasis_strong_strike_and_code_spans() {
    let d = doc(
        "a *em* and **strong** and ~~gone~~ and `co*de*` and _under_ and __bold__ and ***both***",
    );
    assert_eq!(marks(&d, em), ["em", "under", "both"]);
    assert_eq!(marks(&d, strong), ["strong", "bold", "both"]);
    assert_eq!(marks(&d, del), ["gone"]);
    let codes: Vec<_> = all_inlines(&d)
        .into_iter()
        .filter_map(|n| {
            if let Inline::Code(s) = n {
                Some(s)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(codes, ["co*de*"]);
    assert_eq!(
        paras(&d.blocks),
        ["a em and strong and gone and co*de* and under and bold and both"]
    );
}

#[test]
fn snake_case_and_a_lone_star_are_not_emphasis() {
    let d = doc("snake_case_name and 2 * 3 * 4 and a*b");
    assert!(marks(&d, em).is_empty());
    assert_eq!(paras(&d.blocks), ["snake_case_name and 2 * 3 * 4 and a*b"]);
}

#[test]
fn code_is_opaque() {
    let d = doc("```js\n# not a heading\n<b>x</b>\n```\n\n    indented *code*\n\n~~~\ntilde\n~~~");
    let codes: Vec<_> = d
        .blocks
        .iter()
        .filter_map(|b| {
            if let Block::Code(s) = b {
                Some(s.as_str())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        codes,
        ["# not a heading\n<b>x</b>", "indented *code*", "tilde"]
    );
    assert_eq!(d.blocks.len(), 3);
}

#[test]
fn an_unclosed_fence_runs_to_the_end() {
    assert_eq!(
        doc("```\nopen\nstill code").blocks,
        [Block::Code("open\nstill code".into())]
    );
}

#[test]
fn block_quotes_nest_and_continue_lazily() {
    let d = doc("> quoted\ncontinued\n>\n> > inner\n\nafter");
    let Block::Quote(outer) = &d.blocks[0] else {
        panic!("{:?}", d.blocks)
    };
    assert_eq!(
        text(match &outer[0] {
            Block::Para(c) => c,
            b => panic!("{b:?}"),
        }),
        "quoted\ncontinued"
    );
    let Block::Quote(inner) = &outer[1] else {
        panic!("{outer:?}")
    };
    assert_eq!(paras(inner), ["inner"]);
    assert_eq!(paras(&d.blocks), ["after"]);
}

#[test]
fn lists_nest_and_ordered_ones_keep_their_start() {
    let d = doc("- a\n- b\n  - b1\n  - b2\n- c\n\n3. three\n4. four\n   1. sub");
    let Block::List {
        ordered: false,
        items,
        tight: true,
        ..
    } = &d.blocks[0]
    else {
        panic!("{:?}", d.blocks[0])
    };
    assert_eq!(items.len(), 3);
    assert_eq!(paras(&items[0]), ["a"]);
    let Block::List { items: sub, .. } = &items[1][1] else {
        panic!("{:?}", items[1])
    };
    assert_eq!(
        sub.iter().map(|i| paras(i)[0].clone()).collect::<Vec<_>>(),
        ["b1", "b2"]
    );
    let Block::List {
        ordered: true,
        start: 3,
        items,
        ..
    } = &d.blocks[1]
    else {
        panic!("{:?}", d.blocks[1])
    };
    assert_eq!(paras(&items[0]), ["three"]);
    assert!(matches!(
        &items[1][1],
        Block::List {
            ordered: true,
            start: 1,
            ..
        }
    ));
}

#[test]
fn a_list_is_tight_unless_an_item_has_paragraphs_of_its_own() {
    assert!(matches!(
        doc("- a\n- b").blocks[0],
        Block::List { tight: true, .. }
    ));
    assert!(matches!(
        doc("- a\n\n- b").blocks[0],
        Block::List { tight: false, .. }
    ));
    assert!(matches!(
        doc("- a\n- b\n\n  more").blocks[0],
        Block::List { tight: false, .. }
    ));
}

#[test]
fn a_number_in_the_middle_of_a_paragraph_starts_no_list() {
    let d = doc("the year\n2024. was long");
    assert_eq!(paras(&d.blocks), ["the year\n2024. was long"]);
    assert_eq!(d.blocks.len(), 1);
}

#[test]
fn rules() {
    let d = doc("a\n\n---\n\n***\n\n___\n\n- - -");
    assert_eq!(d.blocks.iter().filter(|b| **b == Block::Rule).count(), 4);
}

#[test]
fn tables_keep_alignment_and_pad_short_rows() {
    let d = doc("| Name | Qty | Note |\n|:-----|----:|:----:|\n| a | 1 | x \\| y |\n| b | 22 |\n");
    let Block::Table { align, head, rows } = &d.blocks[0] else {
        panic!("{:?}", d.blocks)
    };
    assert_eq!(
        align,
        &[Some(Align::Left), Some(Align::Right), Some(Align::Center)]
    );
    assert_eq!(
        head.iter().map(|c| text(c)).collect::<Vec<_>>(),
        ["Name", "Qty", "Note"]
    );
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| text(c)).collect())
        .collect();
    assert_eq!(rows, [["a", "1", "x | y"], ["b", "22", ""]]);
}

#[test]
fn hard_and_soft_breaks() {
    let d = doc("one  \ntwo\\\nthree\nfour");
    assert_eq!(
        all_inlines(&d).iter().filter(|n| **n == Inline::Br).count(),
        2
    );
    assert_eq!(paras(&d.blocks), ["onetwothree\nfour"]);
}

#[test]
fn entities_are_decoded_to_text() {
    assert_eq!(
        paras(&doc("fish &amp; chips &lt;b&gt; &hearts; &#x41;").blocks),
        ["fish & chips <b> \u{2665} A"]
    );
}

// ── links ────────────────────────────────────────────────────────────────────

fn one(md: &str) -> Vec<(String, String)> {
    links(&doc(md))
}

fn pair(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

#[test]
fn http_https_and_mailto_targets_are_kept() {
    assert_eq!(
        one("[docs](https://example.com/a?b=1)"),
        [pair("https://example.com/a?b=1", "docs")]
    );
    assert_eq!(
        one("[site](HTTP://example.com)"),
        [pair("HTTP://example.com", "site")]
    );
    assert_eq!(
        one("[write](mailto:me@example.com)"),
        [pair("mailto:me@example.com", "write")]
    );
    assert_eq!(
        one("<https://example.com/x>"),
        [pair("https://example.com/x", "https://example.com/x")]
    );
    assert_eq!(
        one("<me@example.com>"),
        [pair("mailto:me@example.com", "me@example.com")]
    );
    // An @ after the host is not a credential.
    assert_eq!(
        one("[q](https://example.com?next=a@b)"),
        [pair("https://example.com?next=a@b", "q")]
    );
    assert_eq!(
        one("[q](https://example.com/a@b)"),
        [pair("https://example.com/a@b", "q")]
    );
}

#[test]
fn a_link_reference_is_resolved() {
    assert_eq!(
        one("[ref][1] and [two]\n\n[1]: https://example.com/one\n[two]: https://example.com/two"),
        [
            pair("https://example.com/one", "ref"),
            pair("https://example.com/two", "two"),
        ]
    );
    // Through a reference too, only the label is kept of a refused target.
    let d = doc("[ref][1]\n\n[1]: javascript:alert(1)");
    assert!(links(&d).is_empty());
}

#[test]
fn any_other_target_is_its_label_alone() {
    let long = "x".repeat(3000);
    let refused = [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "  javascript:alert(1)",
        "java\nscript:alert(1)",
        "java\tscript:alert(1)",
        "&#106;avascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "blob:https://example.com/1",
        "about:blank",
        "/relative/path",
        "../up",
        "page.html",
        "#anchor",
        "//evil.example/x",
        "https://user:pass@example.com/",
        "https://google.com@evil.example/",
        "https://google.com\\@evil.example/",
        "https://",
        "https:///x",
        "http://?x",
        "mailto:",
        "tel:+123",
        "https://exa\u{202e}mple.com/",
        "https://example.com/a\u{2028}b",
        "https://example.com/a\u{85}b",
        "https://example.com/a b",
        "https://example.com/\u{7f}",
        &long,
    ];
    for target in refused {
        // In angle brackets, which allow spaces, and bare, for a target with none.
        let inside = target.replace(['<', '>', '\n'], " ");
        let mut forms = vec![format!("[click me](<{inside}>)")];
        if !target
            .contains(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '<' || c == '>')
        {
            forms.push(format!("[click me]({target})"));
        }
        for md in forms {
            let d = doc(&md);
            assert!(links(&d).is_empty(), "{md:?} -> {:?}", d.blocks);
            assert!(paras(&d.blocks).concat().contains("click me"), "{md:?}");
        }
    }
}

#[test]
fn a_target_of_the_longest_size_is_kept_and_one_byte_more_is_not() {
    let base = "https://example.com/";
    let fits = format!("{base}{}", "a".repeat(MAX_TARGET - base.len()));
    assert_eq!(one(&format!("[x](<{fits}>)")).len(), 1);
    assert!(one(&format!("[x](<{fits}a>)")).is_empty());
}

#[test]
fn an_image_is_its_alt_text_and_loads_nothing() {
    let d = doc(
        "![a diagram](https://example.com/d.png) ![](https://example.com/e.png) ![x *y* `z`](data:image/png;base64,AAAA)",
    );
    let alts: Vec<_> = all_inlines(&d)
        .into_iter()
        .filter_map(|n| {
            if let Inline::Image { alt } = n {
                Some(alt)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(alts, ["a diagram", "", "x y z"]);
    assert!(links(&d).is_empty());
    let json = d.to_json();
    assert!(
        !json.contains("example.com") && !json.contains("base64"),
        "{json}"
    );
}

#[test]
fn an_image_inside_a_link_keeps_the_link() {
    let d = doc("[![logo](https://example.com/l.png)](https://example.com/home)");
    assert_eq!(links(&d), [pair("https://example.com/home", "logo")]);
}

// ── raw HTML ─────────────────────────────────────────────────────────────────

const HOSTILE_HTML: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)><script>1</script></svg>",
    "<iframe src=javascript:alert(1)></iframe>",
    "<a href=\"javascript:alert(1)\">x</a>",
    "<style>*{background:url(https://evil.example/x)}</style>",
    "<form action=https://evil.example><input name=p></form>",
    "<details open ontoggle=alert(1)>",
    "<!-- comment --><b>bold</b>",
    "<math><mi xlink:href=data:x,alert(1)>",
    "<meta http-equiv=refresh content='0;url=https://evil.example'>",
    "<link rel=stylesheet href=https://evil.example/x.css>",
    "<base href=https://evil.example/>",
    "</p><script>alert(1)</script>",
];

#[test]
fn raw_html_is_text_exactly_as_written() {
    for html in HOSTILE_HTML {
        let d = doc(html);
        // A block of HTML, or a paragraph that has tags in it: the characters are all there is.
        let shown = match d.blocks.as_slice() {
            [Block::Raw(s)] => s.clone(),
            [Block::Para(c)] => text(c),
            other => panic!("{html}: {other:?}"),
        };
        assert_eq!(shown, *html);
        assert!(
            all_inlines(&d).iter().all(|n| matches!(n, Inline::Text(_))),
            "{html}"
        );
    }
}

#[test]
fn raw_html_is_text_inside_every_construct() {
    let html = "<img src=x onerror=alert(1)>";
    let wrapped = [
        format!("# {html}"),
        format!("> {html}"),
        format!("- {html}"),
        format!("1. {html}"),
        format!("*{html}*"),
        format!("**{html}**"),
        format!("[{html}](https://example.com)"),
        format!("![{html}](https://example.com/i.png)"),
        format!("| {html} |\n|---|\n| {html} |"),
        format!("`{html}`"),
        format!("```\n{html}\n```"),
        format!("    {html}"),
        format!("a {html} b"),
    ];
    for md in wrapped {
        let d = doc(&md);
        // Whatever the shape, the tag's characters are somewhere as text,
        // and nothing but the node kinds of this tree exists.
        let json = d.to_json();
        assert!(
            json.contains("<img src=x onerror=alert(1)>") || json.contains("<img"),
            "{md}: {json}"
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_kinds(&v);
    }
}

/// Only the node kinds the page draws, and only the keys it reads.
fn assert_kinds(v: &serde_json::Value) {
    const KINDS: &[&str] = &[
        "text", "code", "br", "em", "strong", "del", "link", "image", "p", "h", "hr", "quote",
        "list", "table", "raw",
    ];
    const KEYS: &[&str] = &[
        "t", "s", "c", "url", "alt", "level", "ordered", "start", "tight", "items", "align",
        "head", "rows",
    ];
    match v {
        serde_json::Value::Object(m) => {
            if let Some(t) = m.get("t") {
                assert!(KINDS.contains(&t.as_str().unwrap()), "{t}");
                assert!(m.keys().all(|k| KEYS.contains(&k.as_str())), "{m:?}");
            }
            m.values().for_each(assert_kinds);
        }
        serde_json::Value::Array(a) => a.iter().for_each(assert_kinds),
        _ => {}
    }
}

// ── the JSON the page reads ──────────────────────────────────────────────────

#[test]
fn the_json_is_valid_and_has_the_shape_the_page_reads() {
    let d = doc(
        "# H\n\ntext **b** [l](https://example.com/\"q\")\n\n- a\n- b\n\n| x | y |\n|:-|-:|\n| 1 | 2 |\n\n> q\n\n```\ncode\n```\n\n---\n\n<div>raw</div>\n",
    );
    let v: serde_json::Value = serde_json::from_str(&d.to_json()).unwrap();
    assert_eq!(v["truncated"], false);
    let kinds: Vec<_> = v["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["t"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        ["h", "p", "list", "table", "quote", "code", "hr", "raw"]
    );
    assert_eq!(
        v["blocks"][0],
        serde_json::json!({"t": "h", "level": 1, "c": [{"t": "text", "s": "H"}]})
    );
    assert_eq!(v["blocks"][2]["tight"], true);
    assert_eq!(v["blocks"][2]["start"], 1);
    assert_eq!(
        v["blocks"][3]["align"],
        serde_json::json!(["left", "right"])
    );
    assert_eq!(v["blocks"][3]["head"][0][0]["s"], "x");
    // The quotes in the target are the link's own, not a break out of the string.
    assert_eq!(v["blocks"][1]["c"][3]["url"], "https://example.com/\"q\"");
    assert_eq!(v["blocks"][7]["s"], "<div>raw</div>");
    assert_kinds(&v);
}

#[test]
fn strings_survive_the_json() {
    let nasty =
        "quote \" slash \\ tab \t nul \u{0} bell \u{7} sep \u{2028} emoji \u{1F600} close ]}";
    let d = doc(&format!("```\n{nasty}\n```"));
    let v: serde_json::Value = serde_json::from_str(&d.to_json()).unwrap();
    assert_eq!(v["blocks"][0]["s"], nasty);
}

// ── limits ───────────────────────────────────────────────────────────────────

fn depth(blocks: &[Block]) -> usize {
    blocks
        .iter()
        .map(|b| match b {
            Block::Quote(c) => 1 + depth(c),
            Block::List { items, .. } => 1 + items.iter().map(|i| depth(i)).max().unwrap_or(0),
            _ => 0,
        })
        .max()
        .unwrap_or(0)
}

fn inline_depth(c: &[Inline]) -> usize {
    c.iter()
        .map(|n| match n {
            Inline::Em(c)
            | Inline::Strong(c)
            | Inline::Del(c)
            | Inline::Link { children: c, .. } => 1 + inline_depth(c),
            _ => 0,
        })
        .max()
        .unwrap_or(0)
}

fn raws(blocks: &[Block], out: &mut String) {
    for b in blocks {
        match b {
            Block::Raw(s) => out.push_str(s),
            Block::Quote(c) => raws(c, out),
            Block::List { items, .. } => items.iter().for_each(|i| raws(i, out)),
            _ => {}
        }
    }
}

#[test]
fn quotes_stop_nesting_at_the_limit_and_the_rest_is_text() {
    let d = doc(&format!("{}deep text", "> ".repeat(50)));
    assert_eq!(depth(&d.blocks), MAX_BLOCK_DEPTH);
    let mut raw = String::new();
    raws(&d.blocks, &mut raw);
    assert!(raw.contains("deep text"), "{:?}", d.blocks);
}

#[test]
fn lists_stop_nesting_at_the_limit_and_the_rest_is_text() {
    let md: Vec<String> = (0..50)
        .map(|i| format!("{}- level{i}", "  ".repeat(i)))
        .collect();
    let d = doc(&md.join("\n"));
    assert_eq!(depth(&d.blocks), MAX_BLOCK_DEPTH);
    let mut raw = String::new();
    raws(&d.blocks, &mut raw);
    assert!(raw.contains("level49"), "{raw:?}");
    assert!(
        raw.contains("level10") && !raw.contains("level9"),
        "{raw:?}"
    );
}

#[test]
fn quotes_and_lists_count_toward_one_limit() {
    let d = doc(&format!("{}x", "> - ".repeat(30)));
    assert_eq!(depth(&d.blocks), MAX_BLOCK_DEPTH);
}

#[test]
fn inlines_stop_nesting_at_the_limit_and_keep_their_text() {
    let d = doc(&format!("{}x{}", "*a **b ".repeat(60), "** b* ".repeat(60)));
    let Block::Para(c) = &d.blocks[0] else {
        panic!("{:?}", d.blocks)
    };
    assert!(inline_depth(c) <= MAX_INLINE_DEPTH, "{}", inline_depth(c));
    assert!(text(c).contains('x'));
    // And links nested in emphasis nested in links.
    let d = doc(&format!(
        "{}x{}",
        "*[a ".repeat(100),
        "](https://example.com)*".repeat(100)
    ));
    let Block::Para(c) = &d.blocks[0] else {
        panic!("{:?}", d.blocks)
    };
    assert!(inline_depth(c) <= MAX_INLINE_DEPTH);
}

#[test]
fn a_document_stops_at_the_node_limit_and_says_so() {
    let d = doc(&"x *y*\n\n".repeat(150_000));
    assert!(d.truncated);
    assert!(d.blocks.len() < 150_000 && d.blocks.len() > 1000);
    assert!(d.to_json().ends_with("\"truncated\":true}"));
    assert!(!doc("# small").truncated);
}

#[test]
fn what_was_open_at_the_node_limit_is_kept() {
    let d = doc(&"- a *b*\n".repeat(200_000));
    assert!(d.truncated);
    let Block::List { items, .. } = &d.blocks[0] else {
        panic!("{} blocks", d.blocks.len())
    };
    assert!(
        items.len() > 1000 && items.len() < 200_000,
        "{}",
        items.len()
    );
}

#[test]
fn the_node_limit_counts_table_cells_and_the_padding_of_short_rows() {
    let head = format!(
        "|{}\n|{}\n",
        "a|".repeat(MAX_COLUMNS),
        "-|".repeat(MAX_COLUMNS)
    );
    let d = doc(&format!("{head}{}", "|1|\n".repeat(20_000)));
    assert!(d.truncated);
    let Block::Table { rows, .. } = &d.blocks[0] else {
        panic!("{:?}", d.blocks.len())
    };
    assert!(
        rows.len() * MAX_COLUMNS <= MAX_NODES + MAX_COLUMNS,
        "{}",
        rows.len()
    );
}

#[test]
fn a_table_keeps_at_most_the_column_limit() {
    let n = MAX_COLUMNS + 40;
    let md = format!(
        "|{}\n|{}\n|{}\n",
        "a|".repeat(n),
        "-|".repeat(n),
        "b|".repeat(n)
    );
    let d = doc(&md);
    let Block::Table { align, head, rows } = &d.blocks[0] else {
        panic!("{:?}", d.blocks)
    };
    assert_eq!(
        (align.len(), head.len(), rows[0].len()),
        (MAX_COLUMNS, MAX_COLUMNS, MAX_COLUMNS)
    );
}

#[test]
fn a_list_start_is_nine_digits_at_most() {
    let d = doc("999999999. a\n\n1234567890. b");
    assert!(matches!(
        d.blocks[0],
        Block::List {
            start: 999_999_999,
            ..
        }
    ));
    assert!(
        d.blocks
            .iter()
            .all(|b| !matches!(b, Block::List { start, .. } if *start > 999_999_999))
    );
}

fn rep(n: usize, s: &str) -> String {
    s.repeat(n)
}

fn hostile() -> Vec<(&'static str, String)> {
    let lines =
        |n: usize, f: &dyn Fn(usize) -> String| (0..n).map(f).collect::<Vec<_>>().join("\n");
    vec![
        ("100k stars", rep(100_000, "*")),
        ("100k stars and letters", rep(50_000, "*a ")),
        ("100k underscores", rep(100_000, "_")),
        ("closers only", rep(40, &format!("{}\n", rep(3000, "a* ")))),
        (
            "closers that fail the rule of three",
            rep(40, &format!("{}\n", rep(1500, "a** b* "))),
        ),
        (
            "underscore closers",
            rep(40, &format!("{}\n", rep(3000, "a_ "))),
        ),
        ("alternating emphasis", rep(50_000, "*a_b")),
        ("100k open brackets", rep(100_000, "[")),
        ("100k link openers", rep(100_000, "[](")),
        (
            "link openers filling the limit",
            rep(200, &format!("{}\n", rep(3333, "[]("))),
        ),
        ("100k image openers", rep(100_000, "![")),
        (
            "brackets then parens",
            rep(50_000, "[a]") + &rep(50_000, "("),
        ),
        ("nested links", rep(20_000, "[a](") + &rep(20_000, ")")),
        ("100k backticks", rep(100_000, "`")),
        (
            "ascending backtick runs",
            (0..1500)
                .map(|i| "`".repeat(i + 1))
                .collect::<Vec<_>>()
                .join(" "),
        ),
        ("100k angle brackets", rep(100_000, "<")),
        ("autolink openers", rep(30_000, "<http://a")),
        ("100k backslashes", rep(100_000, "\\")),
        ("100k tildes", rep(100_000, "~~a")),
        ("one 1 MB line", rep(1_000_000, "a")),
        ("one 1 MB line of words", rep(200_000, "word ")),
        ("100k quote markers", rep(100_000, ">")),
        ("10k nested quotes", rep(10_000, "> ") + "deep"),
        (
            "quote staircase",
            lines(2000, &|i| format!("{}x", "> ".repeat(i % 40))),
        ),
        ("nested list on one line", rep(10_000, "- ") + "deep"),
        (
            "list staircase",
            lines(3000, &|i| format!("{}- item", " ".repeat(2 * (i % 60)))),
        ),
        (
            "ordered list staircase",
            lines(3000, &|i| format!("{}1. item", " ".repeat(3 * (i % 60)))),
        ),
        ("20k tiny items", rep(20_000, "- a\n")),
        ("20k blank-separated items", rep(20_000, "- a\n\n")),
        ("50k headings", rep(50_000, "# h\n")),
        ("50k hr", rep(50_000, "---\n")),
        (
            "wide table",
            format!(
                "|{}\n|{}\n{}",
                rep(5000, "a|"),
                rep(5000, "-|"),
                rep(2000, &format!("|{}\n", rep(100, "x|")))
            ),
        ),
        (
            "long table",
            format!("|a|b|\n|-|-|\n{}", rep(50_000, "|1|2|\n")),
        ),
        ("fence storms", rep(30_000, "```\n")),
        ("setext storms", rep(30_000, "a\n===\n")),
        ("html storm", rep(30_000, "<div><script>")),
        (
            "emphasis inside a link inside a quote",
            rep(5000, "> [*a **b ") + &rep(5000, "](x)"),
        ),
        (
            "reference definitions used many times",
            format!("[a]: https://example.com\n\n{}", rep(100_000, "[a] ")),
        ),
        ("entities", rep(100_000, "&amp;&#x41;&bogus;")),
    ]
}

#[test]
fn hostile_input_is_bounded_in_time_in_stack_and_in_size() {
    for (name, md) in hostile() {
        // The thread's stack is half the 1 MiB a wasm instance has.
        let started = std::time::Instant::now();
        let d = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || {
                let d = parse(&md);
                (depth(&d.blocks), d.to_json().len(), d)
            })
            .unwrap()
            .join()
            .unwrap_or_else(|_| panic!("{name}: panicked or overflowed the stack"));
        let elapsed = started.elapsed();
        assert!(elapsed.as_secs() < 20, "{name}: {elapsed:?}");
        assert!(d.0 <= MAX_BLOCK_DEPTH, "{name}: {}", d.0);
        // The tree, as JSON, stays proportionate to the 1 MB inputs.
        assert!(d.1 < 64 << 20, "{name}: {} bytes", d.1);
        let mut v = Vec::new();
        inlines(&d.2.blocks, &mut v);
        assert!(v.len() <= MAX_NODES + 1, "{name}: {} inlines", v.len());
    }
}

#[test]
fn every_inline_nests_within_the_limit_whatever_the_input() {
    for (name, md) in hostile() {
        let d = parse(&md);
        fn check(blocks: &[Block], name: &str) {
            for b in blocks {
                match b {
                    Block::Para(c) | Block::Heading { children: c, .. } => {
                        assert!(inline_depth(c) <= MAX_INLINE_DEPTH, "{name}")
                    }
                    Block::Quote(c) => check(c, name),
                    Block::List { items, .. } => items.iter().for_each(|i| check(i, name)),
                    Block::Table { head, rows, .. } => head
                        .iter()
                        .chain(rows.iter().flatten())
                        .for_each(|c| assert!(inline_depth(c) <= MAX_INLINE_DEPTH, "{name}")),
                    _ => {}
                }
            }
        }
        check(&d.blocks, name);
    }
}

#[test]
fn nothing_panics_on_odd_bytes_and_shapes() {
    for md in [
        "",
        "\n",
        "\0",
        "\u{FEFF}# bom",
        "\r\n\r\n",
        "\r",
        "a\r\nb\rc\nd",
        "|",
        "|a|\n|-|",
        "> ",
        "- ",
        "1.",
        "```",
        "[",
        "![",
        "<",
        "&",
        "\\",
        "\u{1F600}".repeat(1000).as_str(),
    ] {
        let d = parse(md);
        let _ = d.to_json();
    }
}
