//! The text of a Markdown document as a reader sees it, for the scanner and
//! for search: `markdown::visible_text`.

use exav_render::markdown::visible_text;

fn text(md: &str) -> String {
    visible_text(md, 1 << 20).text
}

#[test]
fn blocks_are_lines_and_marks_are_gone() {
    assert_eq!(
        text(
            "# Title\n\nSome *em* and **strong** and ~~gone~~ and `code`.\n\n> quoted\n\n- one\n- two\n\n3. three\n\n---\n\nend\n"
        ),
        "Title\nSome em and strong and gone and code.\nquoted\none\ntwo\nthree\nend\n"
    );
}

#[test]
fn code_and_raw_html_are_text_as_written() {
    assert_eq!(text("```\nlet x = <b>1</b>;\n```\n"), "let x = <b>1</b>;\n");
    assert_eq!(
        text("<div onclick=\"x()\">hello</div>\n"),
        "<div onclick=\"x()\">hello</div>\n"
    );
    assert_eq!(text("a <i>b</i> c"), "a <i>b</i> c\n");
}

#[test]
fn entities_are_decoded_and_breaks_are_lines() {
    assert_eq!(
        text("fish &amp; chips &hearts;\nsecond  \nthird"),
        "fish & chips \u{2665}\nsecond\nthird\n"
    );
}

#[test]
fn a_table_row_is_a_line_with_its_cells_apart_by_tabs() {
    assert_eq!(
        text("| A | B |\n|---|---|\n| 1 | 2 |\n| 3 |\n"),
        "A\tB\n1\t2\n3\t\n"
    );
}

#[test]
fn a_link_shows_its_label_and_where_it_goes() {
    assert_eq!(
        text("[docs](https://example.com/a)"),
        "docs (https://example.com/a)\n"
    );
    // A label that is the address says it once.
    assert_eq!(text("<https://example.com/x>"), "https://example.com/x\n");
    assert_eq!(text("<me@example.com>"), "me@example.com\n");
    // Whatever the target is: a scanner looks for where the reader is led.
    assert_eq!(
        text("[click](javascript:alert(1)) [bank](https://bank.example@evil.example/)"),
        "click (javascript:alert(1)) bank (https://bank.example@evil.example/)\n"
    );
    assert_eq!(
        text("[ref][1]\n\n[1]: https://example.com/r"),
        "ref (https://example.com/r)\n"
    );
}

#[test]
fn a_label_that_names_one_site_over_another_is_there_to_see() {
    let t = text("[https://www.paypal.com/login](https://evil.example/steal)");
    assert!(
        t.contains("https://www.paypal.com/login") && t.contains("(https://evil.example/steal)"),
        "{t}"
    );
}

#[test]
fn an_image_is_its_alt_text() {
    assert_eq!(
        text("![a *diagram*](https://example.com/d.png)"),
        "a diagram\n"
    );
}

#[test]
fn the_text_is_cut_at_the_limit_on_a_character_boundary() {
    let v = visible_text(&"\u{e9}".repeat(1000), 101);
    assert!(v.truncated);
    assert_eq!(v.text.len(), 100);
    assert!(!visible_text("short", 100).truncated);
}

#[test]
fn a_reference_used_many_times_cannot_make_more_than_the_limit() {
    let md = format!(
        "[a]: https://example.com/{}\n\n{}",
        "x".repeat(1000),
        "[a] ".repeat(50_000)
    );
    let v = visible_text(&md, 64 * 1024);
    assert!(v.truncated);
    assert!(v.text.len() <= 64 * 1024);
}

#[test]
fn hostile_input_is_bounded_in_time_and_stack() {
    let inputs = [
        "> ".repeat(100_000) + "x",
        "- ".repeat(50_000) + "x",
        "[".repeat(100_000),
        "*a ".repeat(100_000),
        "<".repeat(100_000),
        "|a".repeat(50_000) + "|\n" + &"|-".repeat(50_000) + "|\n" + &"|x".repeat(50_000),
    ];
    for md in inputs {
        let started = std::time::Instant::now();
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || visible_text(&md, 1 << 22).text.len())
            .unwrap()
            .join()
            .expect("no panic, no stack overflow");
        assert!(started.elapsed().as_secs() < 20, "{:?}", started.elapsed());
    }
}

#[test]
fn nothing_panics_on_odd_input() {
    for md in [
        "",
        "\n",
        "\0",
        "\r\n\r\n",
        "|",
        "|a|\n|-|",
        "> ",
        "- ",
        "[",
        "![",
        "<",
        "&",
        "\\",
        "[a]()",
        "[](x)",
        "[a](b",
        "\u{1F600}".repeat(100).as_str(),
    ] {
        let _ = visible_text(md, 1 << 20);
    }
}
