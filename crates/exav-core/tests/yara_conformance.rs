//! Conformance tests ported from yara-x's `lib/src/tests/mod.rs`.
//
// Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X. The test
// assertions and the `condition_true!`/`condition_false!`/`rule_true!`/
// `rule_false!`/`pattern_true!`/`pattern_false!`/`pattern_match!` macros are
// adapted from yara-x, reimplemented against the exav public API. Only
// assertions within Phase-A scope are included; module-gated (`test_proto2`),
// `for`-loop, `with`, `uintN`/`intN` and `wide`-regexp assertions are omitted
// (those constructs are a compile error in exav by design).

fn test_condition(cond: &str, data: &[u8], expected: bool) {
    let src = format!("rule t {{condition: {cond} }}");
    let rules =
        exav_core::yara::compile(&src).unwrap_or_else(|e| panic!("compile `{cond}` failed: {e}"));
    let n = rules.scan(data).matching_rules().len();
    assert_eq!(
        n, expected as usize,
        "\n\n`{cond}` should be {expected}, but it is {}",
        !expected
    );
}

fn test_rule(rule: &str, data: &[u8], expected: bool) {
    let rules =
        exav_core::yara::compile(rule).unwrap_or_else(|e| panic!("compile failed: {e}\n{rule}"));
    let n = rules.scan(data).matching_rules().len();
    assert_eq!(
        n, expected as usize,
        "\n\n`{rule}` expected {expected} ({} rules matched)",
        n
    );
}

fn pattern_data(pattern: &str, data: &[u8]) -> Option<Vec<u8>> {
    let src = format!("rule test {{ strings: $a = {pattern} condition: $a}}");
    let rules = exav_core::yara::compile(&src)
        .unwrap_or_else(|e| panic!("compile `{pattern}` failed: {e}"));
    let results = rules.scan(data);
    let m = results.matching_rules().next()?;
    let p = m.patterns().next()?;
    let mm = p.matches().next()?;
    Some(mm.data().to_vec())
}

macro_rules! condition_true {
    ($cond:literal, $data:expr) => {
        test_condition($cond, $data, true)
    };
    ($cond:literal) => {
        test_condition($cond, &[], true)
    };
}
macro_rules! condition_false {
    ($cond:literal, $data:expr) => {
        test_condition($cond, $data, false)
    };
    ($cond:literal) => {
        test_condition($cond, &[], false)
    };
}
macro_rules! rule_true {
    ($rule:expr, $data:expr) => {
        test_rule($rule, $data, true)
    };
    ($rule:expr) => {
        test_rule($rule, &[], true)
    };
}
macro_rules! rule_false {
    ($rule:expr, $data:expr) => {
        test_rule($rule, $data, false)
    };
    ($rule:expr) => {
        test_rule($rule, &[], false)
    };
}
macro_rules! pattern_true {
    ($pattern:literal, $data:expr) => {
        assert!(
            pattern_data($pattern, $data).is_some(),
            "pattern `{}` should match {:?}",
            $pattern,
            $data
        )
    };
}
macro_rules! pattern_false {
    ($pattern:literal, $data:expr) => {
        assert!(
            pattern_data($pattern, $data).is_none(),
            "pattern `{}` should NOT match {:?}",
            $pattern,
            $data
        )
    };
}
macro_rules! pattern_match {
    ($pattern:literal, $data:expr, $expected:expr) => {{
        let got = pattern_data($pattern, $data)
            .unwrap_or_else(|| panic!("pattern `{}` should match", $pattern));
        assert_eq!(
            got.as_slice(),
            &$expected[..],
            "\n\n`{}` applied to {:?} should match {:?}, got {:?}",
            $pattern,
            $data,
            $expected,
            got
        );
    }};
}

const JUMPS_DATA: &[u8; 1664] = include_bytes!("testdata/jumps.bin");

#[test]
fn arithmetic_operations() {
    condition_true!("1 == 1");
    condition_true!("1 + 1 == 2");
    condition_true!("1 - 1 == 0");
    condition_true!("2 * 2 == 4");
    condition_true!("4 \\ 2 == 2");
    condition_true!("5 % 2 == 1");
    condition_true!("2 * (1 + 1) == 4");
    condition_true!("2 * (1 + -1) == 0");
    condition_true!("2 * -(1) == -2");
    condition_true!("(1 + 1) * 2 == (9 - 1) \\ 2 ");
    condition_true!("1.5 + 1.5 == 3");
    condition_true!("3 \\ 2 == 1");
    condition_true!("3.0 \\ 2 == 1.5");
    condition_true!("1 + -1 == 0");
    condition_true!("-1 + -1 == -2");
    condition_true!("4 --2 * 2 == 8");
    condition_true!("-1.0 * 1 == -1.0");
    condition_true!("1-1 == 0");
    condition_true!("-2.0-3.0 == -5");
    condition_true!("--1 == 1");
    condition_true!("--1.0 == 1.0");
    condition_true!("-1.0-1.5 == -2.5");
    condition_true!("1--1 == 2");
    condition_true!("2 * -2 == -4");
    condition_true!("-4 * 2 == -8");
    condition_true!("-4 * -4 == 16");
    condition_true!("-0x01 == -1");
    condition_true!("-0o10 == -8");
    condition_true!("0o100 == 64");
    condition_true!("0o755 == 493");
    condition_true!("1 + 2 + 3 == 6");
    condition_true!("2 - 1 - 1 == 0");
    condition_true!("2 * 3 * 4 == 24");
    condition_true!("5 \\ 2 \\ 2 == 1");
    condition_true!("7 \\ 2 \\ 2.0 == 1.5");
    condition_true!("7 % 4 % 2 == 1");
}

#[test]
fn comparison_operations() {
    condition_true!("2 > 1");
    condition_true!("1 < 2");
    condition_true!("2 >= 1");
    condition_true!("2 >= 2");
    condition_true!("1 <= 1");
    condition_true!("1 <= 2");
    condition_true!("1 == 1");
    condition_true!("1.5 == 1.5");
    condition_true!("1.0 == 1");
    condition_true!("1.0 != 1.000000000000001");
    condition_true!("1.0 < 1.000000000000001");
}

#[test]
fn bitwise_operations() {
    condition_true!("0x55 | 0xAA == 0xFF");
    condition_true!("0x55555555 | 0xAAAAAAAA == 0xFFFFFFFF");
    condition_true!("~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF)");
    condition_true!("~0xAA ^ 0x5A & 0xFF != 0x0F");
    condition_true!("~0x55 & 0xFF == 0xAA");
    condition_true!("1 << 0 == 1");
    condition_true!("1 >> 0 == 1");
    condition_true!("1 << 3 == 8");
    condition_true!("8 >> 2 == 2");
    condition_true!("1 << 64 == 0");
    condition_true!("1 >> 64 == 0");
    condition_true!("1 << 65 == 0");
    condition_true!("1 >> 65 == 0");
    condition_true!("1 | 3 ^ 3 != (1 | 3) ^ 3");
}

#[test]
fn string_operations() {
    condition_true!(r#""foo" == "foo""#);
    condition_true!(r#""foo\nbar" == "foo\nbar""#);
    condition_true!(r#""foo\x00bar" == "foo\x00bar""#);
    condition_true!(r#""foo" != "bar""#);
    condition_true!(r#""aab" > "aaa""#);
    condition_true!(r#""aab" >= "aaa""#);
    condition_true!(r#""aaa" >= "aaa""#);
    condition_true!(r#""aaa" < "aab""#);
    condition_true!(r#""aaa" <= "aab""#);
    condition_true!(r#""aaa" <= "aaa""#);
    condition_true!(r#""foo" contains "foo""#);
    condition_true!(r#""foo\x00" contains "\x00""#);
    condition_true!(r#""foo" contains "oo""#);
    condition_true!(r#""foo" startswith "fo""#);
    condition_true!(r#""foo" endswith "oo""#);
    condition_true!(r#""foo" icontains "FOO""#);
    condition_true!(r#""foo" icontains "OO""#);
    condition_true!(r#""CAFÉ" icontains "fé""#);
    condition_true!(r#""mañana" istartswith "MAÑ""#);
    condition_true!(r#""foo" istartswith "Fo""#);
    condition_true!(r#""foo" iendswith "OO""#);
    condition_false!(r#""foo" contains "OO""#);
    condition_false!(r#""foo" startswith "Fo""#);
    condition_false!(r#""foo" endswith "OO""#);
    condition_true!(r#""foo" iequals "FOO""#);
    condition_true!(r#""foo" iequals "FoO""#);
    condition_false!(r#""foo" iequals "bar""#);
    condition_true!(r#""foo" matches /foo/"#);
    condition_true!(r#""foo" matches /FOO/i"#);
    condition_false!(r#""foo" matches /bar/"#);
    condition_true!(r#""xxfooxx" matches /foo/"#);
    condition_false!(r#""xxfooxx" matches /^foo/"#);
    condition_false!(r#""xxfooxx" matches /\Afoo/i"#);
    condition_false!(r#""xxfooxx" matches /foo$/"#);
    condition_true!(r#""xxFoOxx" matches /fOo/i"#);
    condition_false!(r#""xxFoOxx" matches /^fOo/i"#);
    condition_false!(r#""xxFoOxx" matches /\AfOo/i"#);
    condition_false!(r#""xxFoOxx" matches /fOo$/i"#);
    condition_true!(r#""foobar" matches /^foo/"#);
    condition_false!(r#""bar\nfoo" matches /^foo/"#);
    condition_false!(r#""bar\nfoo" matches /\Afoo/"#);
    condition_true!(r#""bar\nfoo" matches /(?m)^foo/"#);
    condition_false!(r#""bar\nfoo" matches /(?m)\Afoo/"#);
    condition_true!(r#""foobar" matches /bar$/"#);
    condition_true!(r#""foobar" matches /^foobar$/"#);
    condition_true!(r#""foo\nbar" matches /foo.*bar/s"#);
    condition_false!(r#""foo\nbar" matches /foo.*bar/"#);
    condition_true!(r#""foobar" matches /fo{,2}bar/"#);
    condition_true!(r#""" matches /a|b|/"#);
    condition_true!(r#""タイトル" matches /タイトル/"#);
    condition_true!(r#""\xF7\xFF" matches /\xF7\xFF/"#);
    condition_true!(r#""\xe2\x28\xa1" matches /\xe2\x28\xa1/"#);
    condition_false!(r#""🙈🙉🙊" matches /^...$/"#);
    condition_true!(r#""🙈🙉🙊" matches /(?u)^...$/"#);
    condition_false!(r#""🙈🙉🙊" matches /(?u)^.(?-u)..$/"#);
}

#[test]
fn boolean_operations() {
    condition_true!("true");
    condition_false!("false");
    condition_true!("true and true");
    condition_false!("true and false");
    condition_true!("false or true");
    condition_true!("not false");
    condition_false!("not true");
    condition_true!("true or (false and false)");
    condition_false!("not (true or true)");
}

#[test]
fn boolean_casting() {
    condition_true!("1");
    condition_true!("0.5");
    condition_false!("0.0");
    condition_false!("0");
    condition_true!("1 and true");
    condition_false!("0 and true");
    condition_true!("1.0 and true");
    condition_false!("0.0 and true");
    condition_true!("1 or false");
    condition_false!("0 or false");
    condition_true!("1.0 or false");
    condition_false!("0.0 or false");
    condition_true!("not 0");
    condition_false!("not 1");
    condition_true!("not 0.0");
    condition_false!("not 1.0");
    condition_true!(r#""foo""#);
    condition_false!(r#""""#);
}

#[test]
fn text_patterns() {
    pattern_true!(r#""issi""#, b"mississippi");
    pattern_true!(r#""issi" ascii"#, b"mississippi");
    pattern_false!(r#""issi" wide "#, b"mississippi");
    pattern_false!(r#""ssippis""#, b"mississippi");
    pattern_true!(r#""IssI" nocase"#, b"mississippi");
    pattern_true!(r#""IssISSi" nocase"#, b"mississippi");
    pattern_false!(r#""IssISi" nocase"#, b"mississippi");
    pattern_true!(
        r#""issi" wide "#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );
    pattern_true!(
        r#""issi" ascii wide"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );
    pattern_true!(
        r#""🙈🙉🙊""#,
        b"\xF0\x9F\x99\x88\xF0\x9F\x99\x89\xF0\x9F\x99\x8A"
    );
}

#[test]
fn match_at() {
    rule_true!(
        r#"rule test { strings: $a = "foo" condition: $a at 0 }"#,
        b"foobar"
    );
    rule_true!(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: 2 of ($a, $b) or $b at 0 }"#,
        b"foobar"
    );
    rule_false!(
        r#"rule test { strings: $a = "foo" condition: $a at 3 }"#,
        b"foobar"
    );
    rule_true!(
        r#"rule test { strings: $a = "foo" condition: $a at 3 }"#,
        b"barfoo"
    );
    rule_true!(
        r#"rule test { strings: $a = "fofo" condition: $a at 0 and $a at 2 and $a at 4 }"#,
        b"fofofofo"
    );
    rule_true!(
        r#"rule test1 { strings: $a = "bar" condition: $a at 0 }
           rule test2 { strings: $a = "bar" condition: $a }"#,
        b"foobar"
    );
}

#[test]
fn match_in() {
    rule_true!(
        r#"rule test { strings: $a = "foo" condition: $a in (0..1) }"#,
        b"foobar"
    );
    rule_false!(
        r#"rule test { strings: $a = "foo" condition: $a in (1..6) }"#,
        b"foobar"
    );
    rule_false!(
        r#"rule test { strings: $a = "foo" condition: $a in (2..6) }"#,
        b"foobar"
    );
    rule_true!(
        r#"rule test { strings: $a = "fofo" condition: $a in (0..1) and $a in (2..3) and $a in (4..5) }"#,
        b"fofofofo"
    );
    rule_true!(
        r#"rule test { strings: $a = "sippi" condition: $a in (0..6) }"#,
        b"mississippi"
    );
    rule_true!(
        r#"rule test { strings: $a = "sippi" condition: $a in (6..6) }"#,
        b"mississippi"
    );
    rule_false!(
        r#"rule test { strings: $a = "sippi" condition: $a in (7..20) }"#,
        b"mississippi"
    );
}

#[test]
fn match_count() {
    rule_true!(
        r#"rule test { strings: $a = "foo" condition: #a == 1 }"#,
        b"foobar"
    );
    rule_true!(
        r#"rule test { strings: $a = "foo" private condition: #a == 1 }"#,
        b"foobar"
    );
    rule_true!(
        r#"rule test { strings: $a = "foo" condition: #a == 2 }"#,
        b"foobarfoo"
    );
    rule_true!(
        r#"rule test { strings: $a = "foo" condition: #a in (0..5) == 1 }"#,
        b"foobarfoo"
    );
    rule_true!(
        r#"rule test { strings: $a = "foo" condition: #a in (0..6) == 2 }"#,
        b"foobarfoo"
    );
    rule_true!(
        r#"rule test { strings: $a = "aaaa" condition: #a == 3 }"#,
        b"aaaaaa"
    );
    rule_true!(
        r#"rule test { strings: $a = "aaa" condition: #a in (4..5) == 2 }"#,
        b"xxxaaaaa"
    );
}

#[test]
fn match_offset() {
    rule_true!(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: @a == 0 and @b == 3 }"#,
        b"foobarfoobar"
    );
    rule_true!(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: @a[1] == 0 and @b[1] == 3 }"#,
        b"foobarfoobar"
    );
    rule_true!(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: @a[2] == 6 and @b[2] == 9 }"#,
        b"foobarfoobar"
    );
    rule_false!(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: @a[3] == 0 or @b[3] == 0 }"#,
        b"foobarfoobar"
    );
}

#[test]
fn match_length() {
    rule_true!(
        r#"rule test { strings: $a = "foo" condition: !a == 3 }"#,
        b"foobarfoobar"
    );
    rule_true!(
        r#"rule test { strings: $a = "foo" condition: !a[1] == 3 }"#,
        b"foobarfoobar"
    );
    rule_true!(
        r#"rule test { strings: $a = "foo" condition: !a[2] == 3 }"#,
        b"foobarfoobar"
    );
    rule_false!(
        r#"rule test { strings: $a = "foo" condition: !a[3] == 3 }"#,
        b"foobarfoobar"
    );
}

#[test]
fn filesize() {
    let rules = exav_core::yara::compile(
        r#"
        rule filesize_0 { condition: filesize == 0 }
        rule filesize_1 { condition: filesize == 1 }
        rule filesize_2 { condition: filesize == 2 }
        "#,
    )
    .unwrap();
    assert_eq!(rules.scan(b"").matching_rules().len(), 1);
    assert_eq!(rules.scan(b"a").matching_rules().len(), 1);
    assert_eq!(rules.scan(b"ab").matching_rules().len(), 1);
}

#[test]
fn filesize_bounds() {
    let rules = exav_core::yara::compile(
        r#"
        rule test_1 { strings: $a = /foo.*bar/ condition: $a and filesize > 1000 }
        rule test_2 { strings: $a = /foo.*bar/ condition: $a }
        "#,
    )
    .unwrap();
    assert_eq!(rules.scan(b"foobar").matching_rules().len(), 1);

    let rules = exav_core::yara::compile(
        r#"
        rule test_1 { strings: $a = /foo.*bar/ condition: $a and filesize > 6.1 }
        rule test_2 { strings: $a = /foo.*bar/ condition: $a }
        "#,
    )
    .unwrap();
    assert_eq!(rules.scan(b"foobar").matching_rules().len(), 1);

    let rules = exav_core::yara::compile(
        r#"rule test { strings: $a = /foo.*bar/ condition: $a and filesize == 6 }"#,
    )
    .unwrap();
    assert_eq!(rules.scan(b"foobar").matching_rules().len(), 1);
}

#[test]
fn of() {
    condition_true!(r#"any of (false, true)"#);
    condition_true!(r#"all of (true, true)"#);
    condition_true!(r#"none of (false, false)"#);
    condition_false!(r#"any of (false, false)"#);
    condition_false!(r#"all of (false, true)"#);
    condition_true!(r#"none of (1 == 0, 2 == 0)"#);
    condition_true!(r#"all of (1 == 1, 2 == 2)"#);
    condition_true!(
        r#"all of ( all of (true, true), none of (false, false), any of (false, true) )"#
    );
    rule_true!(
        r#"rule test { strings: $a1 = "foo" $a2 = "bar" $b1 = "baz" condition: none of ($a*, $b1) }"#,
        &[]
    );
    rule_true!(
        r#"rule test { strings: $a1 = "foo" $a2 = "bar" $b1 = "baz" condition: none of them }"#,
        &[]
    );
    rule_true!(
        r#"rule test { strings: $a1 = "foo" $a2 = "bar" $b1 = "baz" condition: all of ($a*, $b*) }"#,
        b"foobarbaz"
    );
    rule_true!(
        r#"rule test { strings: $ = "foo" $ = "bar" $ = "baz" condition: all of them }"#,
        b"foobarbaz"
    );
    rule_false!(
        r#"rule test { strings: $a1 = "foo" $a2 = "bar" $b1 = "baz" condition: all of them }"#,
        b"foobar"
    );
    rule_false!(
        r#"rule test { strings: $ = "foo" $ = "bar" $ = "baz" condition: 2 of them }"#,
        b"bar"
    );
    rule_false!(
        r#"rule test { strings: $ = "foo" $ = "bar" $ = "baz" condition: 100% of them }"#,
        b"barbaz"
    );
    rule_true!(
        r#"rule test { strings: $ = "foo" $ = "bar" $ = "baz" condition: any of them in (3..3) }"#,
        b"barbaz"
    );
    rule_true!(
        r#"rule test { strings: $ = "foo" $ = "bar" $ = "baz" condition: any of them at 3 }"#,
        b"barbaz"
    );
    rule_true!(
        r#"rule test_1 { strings: $ = "foo" $ = "bar" $ = "baz" condition: all of them }
           rule test_2 { strings: $ = "foo" $ = "qux" condition: any of them }"#,
        b"foo"
    );
    rule_true!(
        r#"rule test { strings: $ = "foo" condition: 1 of them }"#,
        b"foo"
    );
}

#[test]
fn rule_reuse() {
    let rules = exav_core::yara::compile(
        r#"
        rule rule_1 { condition: true }
        rule rule_2 { condition: rule_1 }
        rule rule_3 { condition: rule_2 }
        rule rule_4 { condition: rule_3 }
        rule rule_5 { condition: rule_4 }
        "#,
    )
    .unwrap();
    assert_eq!(rules.scan(&[]).matching_rules().len(), 5);

    let rules = exav_core::yara::compile(
        r#"
        rule rule_1 { condition: true }
        rule rule_2 { condition: false }
        rule rule_3 { condition: rule_1 and not rule_2 }
        "#,
    )
    .unwrap();
    assert_eq!(rules.scan(&[]).matching_rules().len(), 2);
}

#[test]
fn eight_rules() {
    let rules = exav_core::yara::compile(
        r#"
        rule rule_1 { strings: $a = "foo" condition: $a }
        rule rule_2 { condition: false }
        rule rule_3 { condition: true }
        rule rule_4 { condition: false }
        rule rule_5 { condition: true }
        rule rule_6 { condition: false }
        rule rule_7 { condition: true }
        rule rule_8 { condition: false }
        "#,
    )
    .unwrap();
    assert_eq!(rules.scan(b"foo").matching_rules().len(), 4);
}

#[test]
fn duplicate_pattern() {
    rule_true!(
        r#"rule test { strings: $a = "foo" $b = "foo" condition: $a and $b }"#,
        b"foo"
    );
}

#[test]
fn defined() {
    condition_true!(r#"defined 1"#);
    condition_true!(r#"defined 1.0"#);
    condition_true!(r#"defined false"#);
    condition_true!(r#"defined "foo""#);
    condition_false!(r#"defined 1 and false"#);
    condition_true!(r#"defined (true and false)"#);
    condition_false!(r#"defined true and false"#);
}

#[test]
fn xor() {
    pattern_true!(r#""mississippi" xor"#, b"mississippi");
    pattern_false!(r#""mississippi" xor"#, b"mississippp");
    pattern_true!(r#""mississippi" xor"#, b"lhrrhrrhqqh");
    pattern_false!(r#""mississippi" xor"#, b"lhrrhrrhqqq");
    pattern_true!(r#""ssi" xor"#, b"lhrrhrrhqqh");
    pattern_false!(r#""miss" xor fullword"#, b"lhrrhrrhqqh");
    pattern_false!(r#""ppi" xor fullword"#, b"lhrrhrrhqqh");
    pattern_false!(r#""ssi" xor fullword"#, b"lhrrhrrhqqh");
    pattern_false!(r#""ssis" xor fullword"#, b"lhrrhrrhqqh");
    pattern_true!(r#""mississippi" xor fullword "#, b"y!lhrrhrrhqqh");
    pattern_true!(r#""mississippi" xor fullword "#, b"lhrrhrrhqqh!y");
    pattern_false!(r#""mississippi" xor fullword "#, b"ylhrrhrrhqqh");
    pattern_false!(r#""mississippi" xor fullword "#, b"lhrrhrrhqqhy");
    pattern_true!(r#""mississippi" xor ascii"#, b"lhrrhrrhqqh");
    pattern_true!(r#""mississippi" xor ascii wide"#, b"lhrrhrrhqqh");
    pattern_false!(r#""mississippi" xor wide"#, b"lhrrhrrhqqh");
    pattern_false!(r#""mississippi" xor(1) fullword"#, b"{lhrrhrrhqqh}");
    pattern_true!(
        r#""mississippi" xor wide"#,
        b"l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01"
    );
    pattern_true!(
        r#""mississippi" xor fullword wide"#,
        b"l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01"
    );
    pattern_false!(
        r#""mississippi" xor fullword wide"#,
        b"y\x01l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01"
    );
    pattern_true!(
        r#""mississippi" xor fullword wide"#,
        b"\x01\x02l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01"
    );
    pattern_true!(
        r#""mississippi" xor fullword wide"#,
        b"l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01\x02\x01"
    );
    pattern_false!(
        r#""mississippi" xor fullword wide"#,
        b"l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01y\x01"
    );
    pattern_true!(
        r#""mississippi" xor ascii wide"#,
        b"l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01"
    );
    pattern_false!(r#""mississippi" xor(2-255)"#, b"lhrrhrrhqqh");
    pattern_true!(
        r#""mississippi" xor(255)"#,
        &[0x92, 0x96, 0x8C, 0x8C, 0x96, 0x8C, 0x8C, 0x96, 0x8F, 0x8F, 0x96]
    );
}

#[test]
fn fullword() {
    pattern_true!(r#""mississippi" fullword"#, b"mississippi");
    pattern_true!(r#""mississippi" fullword"#, b"mississippi ");
    pattern_true!(r#""mississippi" fullword"#, b" mississippi");
    pattern_true!(r#""mississippi" fullword"#, b" mississippi ");
    pattern_true!(r#""mississippi" fullword"#, b"\x00mississippi\x00");
    pattern_true!(r#""mississippi" fullword"#, b"\x01mississippi\x02");
    pattern_false!(r#""miss" fullword"#, b"mississippi");
    pattern_false!(r#""ippi" fullword"#, b"mississippi");
    pattern_false!(r#""issi" fullword"#, b"mississippi");

    pattern_true!(r#"/mississippi/ fullword"#, b"mississippi");
    pattern_true!(r#"/mississippi/ fullword"#, b" mississippi ");
    pattern_true!(r#"/mi.*pi/ fullword"#, b"mississippi");
    pattern_true!(r#"/mississippi|missouri/ fullword"#, b"mississippi");
    pattern_false!(r#"/mississippi|missouri/ fullword"#, b"xmississippix");
    pattern_false!(r#"/ssissi/ fullword"#, b"mississippi");
    pattern_false!(r#"/ss.ssi/ fullword"#, b"mississippi");
    pattern_true!(r#"/mis.*?ppi/s fullword"#, b"mississippi");
    pattern_true!(r#"/mis.*?ss.*?ppi/s fullword"#, b"x mississippi x");
    pattern_false!(r#"/mis.*?ppi/s fullword"#, b"xmississippi");
    pattern_false!(r#"/mis.*?ppi/s fullword"#, b"mississippix");
    pattern_false!(r#"/miss/ fullword"#, b"mississippi");
    pattern_false!(r#"/miss|ippi/ fullword"#, b"mississippi");
    pattern_true!(r#"/miss|ippi/ fullword"#, b"miss issippi");
    pattern_true!(r#"/miss|ippi/ fullword"#, b"mississ ippi");
    pattern_true!("/^mississippi/ fullword", b"mississippi\tfoo");
    pattern_true!("/mississippi$/ fullword", b"foo\tmississippi");

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );
    pattern_true!(
        r#""mississippi" wide fullword"#,
        b" \x00m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );
    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"\x00\x00m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00\x00\x00"
    );
    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"x\x01m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );
    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00x\x01"
    );
    pattern_false!(
        r#""miss" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );
    pattern_false!(
        r#""ippi" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );
    pattern_false!(
        r#""issi" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );
}

#[test]
fn base64() {
    pattern_true!(r#""foobar" base64"#, b"Zm9vYmFy");
    pattern_true!(r#""foobar" base64"#, b"eGZvb2Jhcg");
    pattern_true!(r#""foobar" base64"#, b"eHhmb29iYXI");
    pattern_true!(r#""foobar" base64"#, b"eHh4Zm9vYmFy");
    pattern_true!(r#""fooba" base64"#, b"Zm9vYmE");
    pattern_true!(r#""fooba" base64"#, b"Zm9vYmE=");
    pattern_true!(r#""fooba" base64"#, b"eGZvb2Jh");
    pattern_true!(r#""fooba" base64"#, b"eHhmb29iYQ");
    pattern_true!(r#""foob" base64"#, b"Zm9vYg");
    pattern_true!(r#""foob" base64"#, b"Zm9vYg==");
    pattern_true!(r#""foob" base64"#, b"eGZvb2I");
    pattern_true!(r#""foob" base64"#, b"eHhmb29i");
    pattern_true!(r#""foob" base64"#, b"eHhmb29i\x01");
    pattern_true!(
        r#""foobar" base64("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")"#,
        b"Xk7tWkDw"
    );
    pattern_true!(r#""foobar" base64 wide"#, b"ZgBvAG8AYgBhAHIA");
    pattern_false!(r#""foobar" base64 wide"#, b"Zm9vYmFy");
    pattern_true!(r#""foobar" base64 wide ascii"#, b"Zm9vYmFy");
    pattern_false!(r#""foobar" base64"#, b"foobar");
    pattern_false!(r#""foobar" base64 ascii"#, b"foobar");
    pattern_false!(r#""foobar" base64 wide"#, b"f\x00o\x00o\x00b\x00a\x00r\x00");
    pattern_false!(r#""foobar" base64"#, b"Zm9vYmE");
    pattern_false!(r#""foobar" base64"#, b"eHhmb29iYQ");
    pattern_false!(r#""foobar" base64"#, b"eHhmb29i");
    pattern_false!(r#""foobar" base64"#, b"Zvb2Jhcg");
    pattern_false!(r#""foobar" base64"#, b"mb29iYQ");
    pattern_false!(r#""foobar" base64"#, b":::mb29iYXI");
    pattern_false!(
        r#""Dhis program cannow" base64"#,
        b"QVRoaXMgcHJvZ3JhbSBjYW5ub3Q"
    );
    pattern_true!(
        r#""This program cannot" base64"#,
        b"QVRoaXMgcHJvZ3JhbSBjYW5ub3Q"
    );
    pattern_true!(
        r#""foobar" base64wide"#,
        b"Z\x00m\x009\x00v\x00Y\x00m\x00F\x00y\x00"
    );
    pattern_true!(r#""foob" base64wide "#, b"Z\x00m\x009\x00v\x00Y\x00g\x00");
    pattern_true!(
        r#""fooba" base64wide"#,
        b"Z\x00m\x009\x00v\x00Y\x00m\x00E\x00=\x00"
    );
    pattern_false!(
        r#""foobar" base64wide"#,
        b"Z\x00m\x009\x00v\x00Y\x00m\x00F\x00y\x01"
    );
    pattern_true!(
        r#""foobar" base64wide"#,
        b"e\x00G\x00Z\x00v\x00b\x002\x00J\x00h\x00c\x00g\x00"
    );
    pattern_true!(
        r#""foobar" base64wide("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")"#,
        b"X\x00k\x007\x00t\x00W\x00k\x00D\x00w\x00"
    );

    rule_true!(
        r#"rule test { strings: $a = "mississippi" base64 condition: $a at 6 and !a == 14 }"#,
        b"dGhlIG1pc3Npc3NpcHBpIHJpdmVy"
    );
    rule_true!(
        r#"rule test { strings: $a = "mississippi" base64 condition: $a at 7 and !a == 14 }"#,
        b"IHRoZSBtaXNzaXNzaXBwaSByaXZlcg"
    );
    rule_true!(
        r#"rule test { strings: $a = "mississippi" base64 condition: $a at 8 and !a == 14 }"#,
        b"ICB0aGUgbWlzc2lzc2lwcGkgcml2ZXI"
    );
}

#[test]
fn hex_patterns() {
    pattern_true!(r#"{ 01 }"#, &[0x01]);
    pattern_true!(r#"{ 01 02 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_true!(r#"{ 01 ?? 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_false!(r#"{ 01 1? 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_true!(r#"{ 01 0? 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_false!(r#"{ 01 ?0 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_true!(r#"{ 01 ?2 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_true!(
        r#"{ (01 02 03 04 | 05 06 07 08) }"#,
        &[0x01, 0x02, 0x03, 0x04]
    );
    pattern_match!(
        r#"{ 01 02 03 04 (05 0? | 06 0?) }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x06, 0x07],
        [0x01, 0x02, 0x03, 0x04, 0x06, 0x07]
    );
    pattern_match!(
        r#"{ 01 02 [-] 03 04 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x04],
        [0x01, 0x02, 0xFF, 0x03, 0x04]
    );
    pattern_match!(
        r#"{ 01 ?? 02 [-] 03 ?? 04 }"#,
        &[0x01, 0xFF, 0x02, 0xFF, 0x03, 0xFF, 0x04],
        [0x01, 0xFF, 0x02, 0xFF, 0x03, 0xFF, 0x04]
    );
    pattern_match!(
        r#"{ 01 02 [1] 03 04 [2] 05 06 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0xFF, 0xFF, 0x05, 0x06],
        [0x01, 0x02, 0xFF, 0x03, 0x04, 0xFF, 0xFF, 0x05, 0x06]
    );
    pattern_match!(
        r#"{ 01 02 [0-2] 03 04 05 [1] 06 07 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07],
        [0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07]
    );
    pattern_match!(
        r#"{ 01 02 [1-] 03 04 05 [1-] 06 07 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07],
        [0x01, 0x02, 0xFF, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07]
    );
    pattern_match!(
        r#"{ 01 02 03 04 [1-2] (06 07 | 07 08) }"#,
        &[0x01, 0x02, 0x03, 0x04, 0xFF, 0x06, 0x07],
        [0x01, 0x02, 0x03, 0x04, 0xFF, 0x06, 0x07]
    );
    pattern_false!(
        r#"{ 01 02 03 04 [1-2] (06 07 | 07 08) }"#,
        &[0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0x06, 0x06, 0x07]
    );
    pattern_match!(
        r#"{ (01 02 | 03 04) [1-2] 05 06 07 08 }"#,
        &[0x01, 0x02, 0xFF, 0x05, 0x06, 0x07, 0x08],
        [0x01, 0x02, 0xFF, 0x05, 0x06, 0x07, 0x08]
    );
    pattern_match!(
        r#"{ 01 02 [0-2] 03 [0-2] 03 }"#,
        &[0x01, 0x2, 0x03, 0x03, 0x03, 0x03],
        [0x01, 0x2, 0x03, 0x03]
    );
    pattern_match!(
        r#"{ 01 02 [0-2] 03 [0-2] 03 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x03, 0x03, 0x03],
        [0x01, 0x02, 0xFF, 0x03, 0x03]
    );
    pattern_match!(
        r#"{ 01 02 ~03 04 05 }"#,
        &[0x01, 0x02, 0xFF, 0x04, 0x05],
        [0x01, 0x02, 0xFF, 0x04, 0x05]
    );
    pattern_match!(
        r#"{ 01 02 ~?2 04 05 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05],
        [0x01, 0x02, 0x03, 0x04, 0x05]
    );
    pattern_match!(
        r#"{ 01 02 ~2? 04 05 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05],
        [0x01, 0x02, 0x03, 0x04, 0x05]
    );
    pattern_false!(r#"{ 01 02 ~03 04 05 }"#, &[0x01, 0x02, 0x03, 0x04, 0x05]);
    pattern_false!(r#"{ 01 02 ~2? 04 05 }"#, &[0x01, 0x02, 0x20, 0x04, 0x05]);
    pattern_match!(
        r#"{ (01|11) (02|12) (03|13) (04|14) (05|15) (06|16) (07|17) }"#,
        &[0x01, 0x12, 0x03, 0x14, 0x05, 0x16, 0x07],
        [0x01, 0x12, 0x03, 0x14, 0x05, 0x16, 0x07]
    );
    pattern_match!(
        r#"{ 01 02 (0? | 1? | 2?) 03 04 }"#,
        &[0x01, 0x02, 0x1F, 0x03, 0x04],
        [0x01, 0x02, 0x1F, 0x03, 0x04]
    );
    pattern_match!(
        r#"{ 01 ?? 2? 3? }"#,
        &[0x01, 0xFF, 0x22, 0x33],
        [0x01, 0xFF, 0x22, 0x33]
    );
    pattern_match!(
        r#"{ E8 ?? ?? [1-512] (AA | BB B?) 01 02 03 04 }"#,
        &[0xE8, 0xFF, 0xFF, 0xFF, 0xBB, 0xB1, 0x01, 0x02, 0x03, 0x04],
        [0xE8, 0xFF, 0xFF, 0xFF, 0xBB, 0xB1, 0x01, 0x02, 0x03, 0x04]
    );
    pattern_match!(
        r#"{ 01 02 03 04 (05 | 06 0?) }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        [0x01, 0x02, 0x03, 0x04, 0x05]
    );
    pattern_false!(r#"{ 03 04 [-] 01 02 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_false!(r#"{ 01 02 [2-] 03 04 }"#, &[0x01, 0x02, 0xFF, 0x03, 0x04]);
}

#[test]
fn hex_large_jumps() {
    rule_true!(
        r#"rule test {
            strings:
                $a = { 61 61 61 61 [-] 62 62 62 62 [-] 63 63 63 63 [-] 64 64 64 64 }
            condition:
                #a == 4 and
                @a[1] == 0x4 and !a[1] == 0x604 and
                @a[2] == 0x24 and !a[2] == 0x5e4 and
                @a[3] == 0x44 and !a[3] == 0x5c4 and
                @a[4] == 0x324 and !a[4] == 0x2e4
        }"#,
        JUMPS_DATA
    );
    rule_true!(
        r#"rule test {
            strings:
                $a = { 61 61 61 61 [0-0x1fc] 62 62 62 62 [0-0x1fc] 63 63 63 63 [0-0x1fc] 64 64 64 64 }
            condition:
                #a == 4 and @a[1] == 0x4 and @a[4] == 0x324
        }"#,
        JUMPS_DATA
    );
    pattern_false!(
        "{ 61 61 61 61 [0-0x17b] 62 62 62 62 [-] 63 63 63 63 [-] 64 64 64 64 }",
        JUMPS_DATA
    );
    pattern_true!(
        "{ 61 61 61 61 [0-0x19c] 63 [0-0x13f] 64 64 64 64 }",
        JUMPS_DATA
    );
    rule_true!(
        r#"rule test {
            strings:
                $a = /aaaa.*?bbbb.*?cccc.*?dddd/s
            condition:
                #a == 4 and
                @a[1] == 0x4 and !a[1] == 0x604 and
                @a[4] == 0x324 and !a[4] == 0x2e4
        }"#,
        JUMPS_DATA
    );
    rule_false!(r#"rule test { strings: $a = /dddd.{0,28}?DDDD.{0,28}?dddd/i condition: $a }"#);
}

#[test]
fn regexp_patterns_basic() {
    pattern_match!(r#"/abc/"#, b"abc", b"abc");
    pattern_false!(r#"/abc/"#, b"xbc");
    pattern_match!(r#"/abc/"#, b"xabcx", b"abc");
    pattern_match!(r#"/abc/"#, b"ababc", b"abc");
    pattern_match!(r#"/a.c/"#, b"abc", b"abc");
    pattern_match!(r#"/a.b/"#, b"a\rb", b"a\rb");
    pattern_match!(r#"/ab*c/"#, b"abc", b"abc");
    pattern_match!(r#"/ab*c/"#, b"ac", b"ac");
    pattern_match!(r#"/a.*?bbb/"#, b"abbbbbb", b"abbb");
    pattern_match!(r#"/ab+c/"#, b"abbc", b"abbc");
    pattern_false!(r#"/ab+c/"#, b"ac");
    pattern_match!(r#"/ab+?/"#, b"abbbb", b"ab");
    pattern_match!(r#"/a(b|x)c/"#, b"axc", b"axc");
    pattern_match!(r#"/(a+|b)+/"#, b"aab", b"aab");
    pattern_match!(r#"/a|b|c|d|e/"#, b"e", b"e");
    pattern_match!(r#"/(a|b|c|d|e)f/"#, b"ef", b"ef");
    pattern_match!(
        r#"/the (caterpillar|cat)/"#,
        b"the caterpillar",
        b"the caterpillar"
    );
    pattern_match!(r#"/the (cat|caterpillar)/"#, b"the caterpillar", b"the cat");
    pattern_match!(r#"/ab{2,3}c/"#, b"abbbc", b"abbbc");
    pattern_false!(r#"/ab{1}c/"#, b"abbc");
    pattern_match!(r#"/ab{1,2}c/"#, b"abbc", b"abbc");
    pattern_false!(r#"/ab{1,2}c/"#, b"abbbc");
    pattern_match!(r#"/a[bx]c/"#, b"abc", b"abc");
    pattern_match!(r#"/[0-9a-f]+/"#, b"xyz0123456789xyz", b"0123456789");
    pattern_false!(r#"/[x-z]+/"#, b"abc");
    pattern_match!(r#"/a[^bc]d/"#, b"aed", b"aed");
    pattern_false!(r#"/a[^bc]d/"#, b"abd");
    pattern_match!(r"/a\sb/", b"a b", b"a b");
    pattern_false!(r"/a\Sb/", b"a b");
    pattern_match!(r"/a\wc/", b"a_c", b"a_c");
    pattern_false!(r"/a\wc/", b"a*c");
    pattern_match!(r"/\w+/", b"--ab_cd0123--", b"ab_cd0123");
    pattern_match!(r"/\D+/", b"1234abc5678", b"abc");
    pattern_match!(r"/\x01\x02\x03/", b"\x01\x02\x03", b"\x01\x02\x03");
    pattern_match!(r#"/^abc/"#, b"abc", b"abc");
    pattern_false!(r#"/^abc/"#, b"xyz\nabc");
    pattern_false!(r#"/abc$/"#, b"abc\nxyz");
    pattern_match!(r#"/(?m)^abc/"#, b"xyz\nabc", b"abc");
    pattern_match!(r#"/(?m)abc$/"#, b"abc\nxyz", b"abc");
    pattern_match!(r#"/\Aabc/"#, b"abcd", b"abc");
    pattern_match!(r#"/bcd\z/"#, b"abcd", b"bcd");
    pattern_match!(r#"/^abc$/"#, b"abc", b"abc");
    pattern_false!(r#"/^abc$/"#, b"abcc");
    pattern_match!(r#"/foo|bar|baz/"#, b"bar", b"bar");
    pattern_false!(r#"/foo|bar|baz/"#, b"BAR");
    pattern_match!(r#"/foo|bar|baz/i"#, b"BAR", b"BAR");
    pattern_match!(r#"/a{1,}/"#, b"aaaaa", b"aaaaa");
}

#[test]
fn regexp_patterns_1() {
    pattern_match!(r#"/abc/"#, b"abc", b"abc");
    pattern_false!(r#"/abc/"#, b"xbc");
    pattern_match!(r#"/abc/"#, b"xabcx", b"abc");
    pattern_match!(r#"/abc/"#, b"ababc", b"abc");
    pattern_match!(r#"/a.c/"#, b"abc", b"abc");
    pattern_false!(r#"/a.{4,5}b/"#, b"acc\nccb");
    pattern_match!(r#"/a.b/"#, b"a\rb", b"a\rb");
    pattern_match!(r#"/ab*c/"#, b"abc", b"abc");
    pattern_match!(r#"/ab*c/"#, b"ac", b"ac");
    pattern_match!(r#"/ab*bc/"#, b"abc", b"abc");
    pattern_match!(r#"/ab*bc/"#, b"abbc", b"abbc");
    pattern_match!(r#"/a.*bb/"#, b"abbbb", b"abbbb");
    pattern_match!(r#"/a.*?bbb/"#, b"abbbbbb", b"abbb");
    pattern_match!(r#"/a.*c/"#, b"ac", b"ac");
    pattern_match!(r#"/a.*c/"#, b"axyzc", b"axyzc");
    pattern_match!(r#"/ab+c/"#, b"abbc", b"abbc");
    pattern_false!(r#"/ab+c/"#, b"ac");
    pattern_match!(r#"/ab+/"#, b"abbbb", b"abbbb");
    pattern_match!(r#"/ab+?/"#, b"abbbb", b"ab");
    pattern_false!(r#"/ab+bc/"#, b"abc");
    pattern_match!(r#"/a+b+c/"#, b"aabbabc", b"abc");
    pattern_false!(r#"/ab?bc/"#, b"abbbbc");
    pattern_match!(r#"/ab?c/"#, b"abc", b"abc");
    pattern_match!(r#"/ab*?/"#, b"abbb", b"a");
    pattern_match!(r#"/ab??/"#, b"ab", b"a");
    pattern_match!(r#"/a(b|x)c/"#, b"abc", b"abc");
    pattern_match!(r#"/a(b|x)c/"#, b"axc", b"axc");
    pattern_match!(r#"/a(b|.)c/"#, b"axc", b"axc");
    pattern_match!(r#"/a(b|x|y)c/"#, b"ayc", b"ayc");
    pattern_match!(r#"/(a+|b)+/"#, b"a", b"a");
    pattern_match!(r#"/(a+|b)+/"#, b"aa", b"aa");
    pattern_match!(r#"/(a+|b)+/"#, b"ab", b"ab");
    pattern_match!(r#"/(a+|b)+/"#, b"aab", b"aab");
    pattern_match!(r#"/a|b|c|d|e/"#, b"e", b"e");
    pattern_match!(r#"/(a|b|c|d|e)f/"#, b"ef", b"ef");
    pattern_match!(r#"/a|b/"#, b"a", b"a");
    pattern_match!(r#"/(F?FF?|f?ff?)abcd/"#, b"fabcd", b"fabcd");
    pattern_match!(r#"/abcd.*ef/"#, b"abcdef", b"abcdef");
    pattern_match!(r#"/ab.*cdef/"#, b"abcdef", b"abcdef");
    pattern_false!(r#"/abcd.*ef/"#, b"abcd\nef");
    pattern_false!(r#"/abcd.{3}aaa/"#, b"abcd\naaaaaa");
    pattern_match!(r#"/abcd.*ef/s"#, b"abcd\nef", b"abcd\nef");
    pattern_match!(r#"/abcd.{3}aaa/s"#, b"abcd\naaaaaaaaa", b"abcd\naaaaa");
    pattern_false!(r#"/abcd.{1,2}ef/"#, b"abcdef");
    pattern_match!(r#"/abcd.{1,2}ef/"#, b"abcdxef", b"abcdxef");
    pattern_match!(r#"/ab.{1, 2}cdef/"#, b"abxcdef", b"abxcdef");
    pattern_match!(r#"/ab.{1  ,  2}cdef/"#, b"abxcdef", b"abxcdef");
    pattern_match!(r#"/a(.*)*/"#, b"a", b"a");
    pattern_match!(r#"/a(.*){2}/"#, b"a", b"a");
    pattern_match!(r#"/a(bb|b)b/"#, b"abbbbbbbb", b"abbb");
    pattern_match!(r#"/a(b|bb)b/"#, b"abbbbbbbb", b"abb");
}

#[test]
fn regexp_patterns_2() {
    pattern_match!(r#"/.b{2}/"#, b"abb", b"abb");
    pattern_match!(r#"/.b{2,3}/"#, b"abb", b"abb");
    pattern_match!(r#"/.b{2,3}/"#, b"abbb", b"abbb");
    pattern_match!(r#"/.b{2,3}?/"#, b"abbb", b"abb");
    pattern_match!(r#"/.{2,3}c/s"#, b"abbc", b"abbc");
    pattern_match!(r#"/ab{2,3}?c/"#, b"abbbc", b"abbbc");
    pattern_match!(r#"/ab{0,1}?c/"#, b"abc", b"abc");
    pattern_match!(r#"/ab{,1}?c/"#, b"abc", b"abc");
    pattern_match!(r#"/a{0,1}bc/"#, b"bbc", b"bc");
    pattern_match!(r#"/ab{0,}c/"#, b"ac", b"ac");
    pattern_match!(r#"/ab{0,}c/"#, b"abbbc", b"abbbc");
    pattern_match!(r#"/aa{0,1}bc/"#, b"abc", b"abc");
    pattern_match!(r#"/ab{1}c/"#, b"abc", b"abc");
    pattern_false!(r#"/ab{1}c/"#, b"abbc");
    pattern_false!(r#"/ab{1}c/"#, b"ac");
    pattern_match!(r#"/ab{1,2}c/"#, b"abbc", b"abbc");
    pattern_false!(r#"/ab{1,2}c/"#, b"abbbc");
    pattern_match!(r#"/ab{1,}c/"#, b"abbbc", b"abbbc");
    pattern_false!(r#"/ab{1,}b/"#, b"ab");
    pattern_match!(r#"/ab{0,3}c/"#, b"abbbc", b"abbbc");
    pattern_match!(r#"/ab{,3}c/"#, b"abbbc", b"abbbc");
    pattern_false!(r#"/ab{0,2}c/"#, b"abbbc");
    pattern_false!(r#"/ab{,2}c/"#, b"abbbc");
    pattern_false!(r#"/ab{4,5}c/"#, b"abbbc");
    pattern_false!(r#"/ab{3}c/"#, b"abbbbc");
    pattern_match!(r#"/ab{0,2}/"#, b"abbbbb", b"abb");
    pattern_match!(r#"/ab{1,3}/"#, b"abbbbb", b"abbb");
    pattern_match!(r#"/ab{2,4}/"#, b"abbbbc", b"abbbb");
    pattern_match!(r#"/ab{3,5}/"#, b"abbbbb", b"abbbbb");
    pattern_match!(r#"/ab{1,3}?/"#, b"abbbbb", b"ab");
    pattern_match!(r#"/(a{2,3}b){2,3}/"#, b"aabaaabaab", b"aabaaabaab");
    pattern_match!(r#"/(a{2,3}?b){2,3}?/"#, b"aabaaabaab", b"aabaaab");
    pattern_match!(r#"/.(abc){0,1}/"#, b"xabcabcabcabc", b"xabc");
    pattern_match!(r#"/.(abc){0,2}/"#, b"xabcabcabcabc", b"xabcabc");
    pattern_match!(r#"/x{1,2}abcd/"#, b"xxxxabcd", b"xxabcd");
    pattern_match!(r#"/.(aa){1,2}/"#, b"aaaaaaaaaa", b"aaaaa");
    pattern_match!(r#"/a.(bc.){2}/"#, b"aabcabca", b"aabcabca");
    pattern_match!(r#"/ab(c|cc){1,3}d/"#, b"abccccccd", b"abccccccd");
    pattern_match!(r#"/abc.{0,3}def/s"#, b"abcdef", b"abcdef");
    pattern_match!(r#"/abc.{1,3}def/s"#, b"abcxdef", b"abcxdef");
    pattern_false!(r#"/abc.{1,3}def/s"#, b"abcxxxxdef");
    pattern_match!(r#"/abc.*ddd/s"#, b"abcdddddd", b"abcdddddd");
    pattern_match!(r#"/abc.*?ddd/s"#, b"abcdddddd", b"abcddd");
}

#[test]
fn regexp_patterns_3() {
    pattern_match!(r#"/.b{15}/"#, b"abbbbbbbbbbbbbbb", b"abbbbbbbbbbbbbbb");
    pattern_match!(r#"/.b{15,16}/"#, b"abbbbbbbbbbbbbbbb", b"abbbbbbbbbbbbbbbb");
    pattern_match!(r#"/.b{15,16}?/"#, b"abbbbbbbbbbbbbbbb", b"abbbbbbbbbbbbbbb");
    pattern_match!(
        r#"/abcd.{0,11}efgh.{0,11}ijk/"#,
        b"abcd123456789ABefgh123456789ABijk",
        b"abcd123456789ABefgh123456789ABijk"
    );
    pattern_match!(r#"/abcd.{0,11}?abcd/"#, b"abcdabcdabcd", b"abcdabcd");
    pattern_match!(r#"/ab{2,15}c/"#, b"abbbc", b"abbbc");
    pattern_match!(r#"/ab{,15}?c/"#, b"abc", b"abc");
    pattern_match!(r#"/a{0,15}bc/"#, b"bbc", b"bc");
    pattern_match!(r#"/ab{11}c/"#, b"abbbbbbbbbbbc", b"abbbbbbbbbbbc");
    pattern_false!(r#"/ab{11}c/"#, b"ac");
    pattern_match!(r#"/ab{11,}c/"#, b"abbbbbbbbbbbbc", b"abbbbbbbbbbbbc");
    pattern_match!(r#"/(a{2,13}b){2,13}/"#, b"aabaaabaab", b"aabaaabaab");
}

#[test]
fn regexp_patterns_4() {
    pattern_match!(r#"/a[bx]c/"#, b"abc", b"abc");
    pattern_match!(r#"/a[bx]c/"#, b"axc", b"axc");
    pattern_match!(r#"/a[0-9]*b/"#, b"ab", b"ab");
    pattern_match!(r#"/a[0-9]*b/"#, b"a0123456789b", b"a0123456789b");
    pattern_match!(r#"/[0-9a-f]+/"#, b"0123456789abcdef", b"0123456789abcdef");
    pattern_match!(r#"/[0-9a-f]+/"#, b"xyz0123456789xyz", b"0123456789");
    pattern_false!(r#"/[x-z]+/"#, b"abc");
    pattern_match!(r#"/[a-z]{1,2}ab/"#, b"xyab", b"xyab");
    pattern_match!(r#"/a[-]?c/"#, b"ac", b"ac");
    pattern_match!(r#"/a[-b]/"#, b"a-", b"a-");
    pattern_match!(r#"/a[-b]/"#, b"ab", b"ab");
    pattern_match!(r#"/a[b-]/"#, b"a-", b"a-");
    pattern_match!(r#"/[a-c-e]/"#, b"b", b"b");
    pattern_match!(r#"/[a-c-e]/"#, b"-", b"-");
    pattern_false!(r#"/[a-c-e]/"#, b"d");
    pattern_match!(r"/a[\-b]/", b"a-", b"a-");
    pattern_match!(r#"/a]/"#, b"a]", b"a]");
    pattern_match!(r#"/a[]]b/"#, b"a]b", b"a]b");
    pattern_match!(r#"/a[]-]b/"#, b"a]b", b"a]b");
    pattern_match!(r#"/a[]-]b/"#, b"a-b", b"a-b");
    pattern_match!(r"/a[\]]b/", b"a]b", b"a]b");
    pattern_match!(r#"/a[^bc]d/"#, b"aed", b"aed");
    pattern_false!(r#"/a[^bc]d/"#, b"abd");
    pattern_match!(r#"/a[^-b]c/"#, b"adc", b"adc");
    pattern_false!(r#"/a[^-b]c/"#, b"a-c");
    pattern_false!(r#"/a[^]b]c/"#, b"a]c");
    pattern_match!(r#"/a[^]b]c/"#, b"adc", b"adc");
    pattern_match!(r#"/[^ab]+/"#, b"cde", b"cde");
    pattern_match!(r"/a[\s]b/", b"a b", b"a b");
    pattern_false!(r"/a[\S]b/", b"a b");
    pattern_match!(r"/a[\d]b/", b"a1b", b"a1b");
    pattern_false!(r"/a[\D]b/", b"a1b");
    pattern_match!(r"/a\sb/", b"a b", b"a b");
    pattern_match!(r"/a\sb/", b"a\tb", b"a\tb");
    pattern_match!(r"/a\sb/", b"a\nb", b"a\nb");
    pattern_false!(r"/a\Sb/", b"a b");
    pattern_match!(r"/foo[^\s]*/", b"foobar\n", b"foobar");
    pattern_match!(r"/\n\r\t\f\a/", b"\n\r\t\x0c\x07", b"\n\r\t\x0c\x07");
    pattern_match!(r"/\x01\x02\x03/", b"\x01\x02\x03", b"\x01\x02\x03");
    pattern_match!(r"/[\x01-\x03]+/", b"\x01\x02\x03", b"\x01\x02\x03");
    pattern_false!(r"/[\x00-\x02]+/", b"\x03\x04\x05");
    pattern_match!(r"/[\x5D]/", b"]", b"]");
    pattern_match!(r"/a\wc/", b"abc", b"abc");
    pattern_match!(r"/a\wc/", b"a_c", b"a_c");
    pattern_match!(r"/a\wc/", b"a0c", b"a0c");
    pattern_false!(r"/a\wc/", b"a*c");
    pattern_match!(r"/\w+/", b"--ab_cd0123--", b"ab_cd0123");
    pattern_match!(r"/\D+/", b"1234abc5678", b"abc");
    pattern_match!(r"/[\da-fA-F]+/", b"123abcDEF", b"123abcDEF");
    pattern_match!(r#"/(abc|)ef/"#, b"abcdef", b"ef");
    pattern_match!(r#"/(abc|)ef/"#, b"abcef", b"abcef");
    pattern_match!(r#"/(|abc)ef/"#, b"abcef", b"abcef");
    pattern_match!(r#"/((a)(b)c)(d)/"#, b"abcd", b"abcd");
    pattern_match!(r#"/(a|b)c*d/"#, b"abcd", b"bcd");
    pattern_match!(r#"/(ab|ab*)bc/"#, b"abc", b"abc");
    pattern_match!(r#"/a([bc]*)c*/"#, b"abc", b"abc");
    pattern_match!(r#"/a([bc]*)(c*d)/"#, b"abcd", b"abcd");
    pattern_match!(r#"/a[bcd]*dcdcde/"#, b"adcdcde", b"adcdcde");
    pattern_false!(r#"/a[bcd]+dcdcde/"#, b"adcdcde");
    pattern_match!(r"/\((.*), (.*)\)/", b"(a, b)", b"(a, b)");
    pattern_match!(r#"/^abc/"#, b"abc", b"abc");
    pattern_match!(r#"/^abc/"#, b"abcd", b"abc");
    pattern_false!(r#"/^abc/"#, b"xyz\nabc");
    pattern_false!(r#"/abc$/"#, b"abc\nxyz");
    pattern_match!(r#"/(?m)^abc/"#, b"xyz\nabc", b"abc");
    pattern_match!(r#"/(?m)abc$/"#, b"abc\nxyz", b"abc");
    pattern_match!(r#"/\Aabc/"#, b"abcd", b"abc");
    pattern_match!(r#"/bcd\z/"#, b"abcd", b"bcd");
    pattern_false!(r#"/^def/"#, b"abcdef");
    pattern_match!(r#"/abc|^123/"#, b"123", b"123");
    pattern_false!(r#"/abc|^123/"#, b"x123");
    pattern_match!(r#"/^abc$/"#, b"abc", b"abc");
    pattern_false!(r#"/^abc$/"#, b"abcc");
    pattern_match!(r#"/abc$/"#, b"aabc", b"abc");
    pattern_false!(r#"/$abc/"#, b"abc");
    pattern_match!(r#"/(bc+d$|ef*g.|h?i(j|k))/"#, b"effgz", b"effgz");
    pattern_match!(r#"/(bc+d$|ef*g.|h?i(j|k))/"#, b"ij", b"ij");
    pattern_false!(r#"/(bc+d$|ef*g.|h?i(j|k))/"#, b"effg");
}

#[test]
fn regexp_patterns_5() {
    pattern_match!(r"/\\/", b"\\", b"\\");
    pattern_match!(r"/\babc/", b"abc", b"abc");
    pattern_match!(r"/abc\b/", b"abc", b"abc");
    pattern_false!(r"/\babc/", b"1abc");
    pattern_false!(r"/\babc/", b"_abc");
    pattern_false!(r"/abc\b/", b"abc1");
    pattern_match!(r"/\babc\b/", b" abc ", b"abc");
    pattern_match!(r"/\b\w\w\w\b/", b" abc ", b"abc");
    pattern_false!(r"/\Babc/", b"abc");
    pattern_false!(r"/abc\B/", b"abc");
    pattern_match!(r"/\Babc/", b"1abc", b"abc");
    pattern_match!(r"/abc\B/", b"abc1", b"abc");
    // NOTE: `\<` / `\>` are omitted — the Rust regex crate treats them as
    // zero-width word boundaries, whereas yara-x treats them as literals.
    pattern_match!(r"/\b{start}abc/", b"abc", b"abc");
    pattern_match!(r"/abc\b{end}/", b"abc", b"abc");
    pattern_match!(r"/\b{start}abc/", b" abc", b"abc");
    pattern_match!(r"/abc\b{end}/", b"abc ", b"abc");
    pattern_false!(r#"/a.b/"#, b"a\nb");
    pattern_match!(r#"/foo/"#, b"foo", b"foo");
    pattern_match!(r#"/bar/i"#, b"bar", b"bar");
    pattern_match!(r#"/foo|bar|baz/"#, b"bar", b"bar");
    pattern_false!(r#"/foo|bar|baz/"#, b"BAR");
    pattern_match!(r#"/foo|bar|baz/i"#, b"BAR", b"BAR");
    pattern_match!(r#"/acid(p[pv]r|s[cs]a)/i"#, b"acidpvr", b"acidpvr");
    pattern_match!(r#"/acid(p[pv]r|s[cs]a)/i"#, b"ACidSSa", b"ACidSSa");
    pattern_match!(r"/foo\x01bar/", b"foo\x01bar", b"foo\x01bar");
    pattern_true!(
        r#"/🙈🙉🙊/i"#,
        b"\xF0\x9F\x99\x88\xF0\x9F\x99\x89\xF0\x9F\x99\x8A"
    );
    pattern_match!(r"/^abc \bxyz$/", b"abc xyz", b"abc xyz");
    pattern_false!(r"/^abc\bxyz$/", b"abcxyz");
    pattern_match!(r"/^abc\Bxyz$/", b"abcxyz", b"abcxyz");
}

#[test]
fn regexp_word_boundaries() {
    pattern_match!(r"/\babc/", b"abc", b"abc");
    pattern_match!(r"/abc\b/", b"abc", b"abc");
    pattern_false!(r"/\babc/", b"1abc");
    pattern_false!(r"/\babc/", b"_abc");
    pattern_false!(r"/abc\b/", b"abc1");
    pattern_match!(r"/\babc\b/", b" abc ", b"abc");
    pattern_match!(r"/\b\w\w\w\b/", b" abc ", b"abc");
    pattern_false!(r"/\Babc/", b"abc");
    pattern_match!(r"/\Babc/", b"1abc", b"abc");
    pattern_match!(r"/abc\B/", b"abc1", b"abc");
}

#[test]
fn regexp_counts() {
    rule_true!(
        r#"rule test { strings: $a = /a{1,}/ condition: #a == 5 }"#,
        b"aaaaa"
    );
    rule_true!(
        r#"rule test {
            strings: $a = /.b{2,3}?cccc/
            condition: #a == 2 and @a[1] == 0 and @a[2] == 1
        }"#,
        b"abbbcccc"
    );
}

#[test]
fn regexp_nocase() {
    pattern_match!(r#"/abc/ nocase"#, b"ABC", b"ABC");
    pattern_match!(r#"/a[bx]c/ nocase"#, b"ABC", b"ABC");
    pattern_match!(r#"/[a-z]+/ nocase"#, b"AbC", b"AbC");
    pattern_match!(r#"/(abc|xyz)+/ nocase"#, b"AbCxYz", b"AbCxYz");
    pattern_match!(r#"/abc[^d]/ nocase"#, b"ABCE", b"ABCE");
    pattern_false!(r#"/abc[^d]/ nocase"#, b"abcd");
}

/// These constructs must be REJECTED at compile time (never silently
/// mis-evaluated).
#[test]
fn unsupported_is_rejected() {
    for src in [
        // Still unsupported constructs:
        // `$`/`#`/`@`/`!` are only valid inside a `for ... of` body.
        r#"rule t { strings: $a = "x" condition: for any i in (0..1): ($) }"#,
        // A scalar loop variable cannot be field-accessed.
        r#"rule t { condition: for any i in (0..1): (i.foo == 1) }"#,
        // A non-iterable expression cannot drive a `for ... in`.
        r#"import "pe" rule t { condition: for any x in pe.machine: (x == 1) }"#,
        // Unknown field on a struct loop variable is a compile error.
        r#"import "pe" rule t { condition: for any s in pe.sections: (s.bogus == 1) }"#,
        // Float file reads are not implemented (integer reads are).
        r#"rule t { condition: float32(0) == 0.0 }"#,
        // Unknown module.
        r#"import "cuckoo" rule t { condition: cuckoo.network.http_get(/x/) }"#,
        // Using a module without importing it.
        r#"rule t { condition: pe.number_of_sections == 1 }"#,
        // Unimplemented pe fields/functions must be an explicit compile error.
        r#"import "pe" rule t { condition: pe.rich_signature.length > 0 }"#,
        r#"import "pe" rule t { condition: pe.version_info["CompanyName"] == "x" }"#,
        r#"import "pe" rule t { condition: pe.number_of_resources == 0 }"#,
        r#"import "pe" rule t { condition: pe.imports(/kernel32/, /Create/) > 0 }"#,
        // Unknown module function.
        r#"import "math" rule t { condition: math.bogus(1) == 1 }"#,
    ] {
        assert!(
            exav_core::yara::compile(src).is_err(),
            "expected compile error for: {src}"
        );
    }
}

/// Newly-supported Phase-B constructs must COMPILE (they were rejected in
/// Phase A).
#[test]
fn phase_b_constructs_compile() {
    for src in [
        // `wide` on a regexp is now supported (matches the UTF-16LE form).
        r#"rule t { strings: $a = /foo/ wide condition: $a }"#,
        r#"rule t { condition: uint16(0) == 0x5a4d }"#,
        r#"rule t { condition: int8(0) == 1 }"#,
        r#"rule t { condition: uint32be(0) == 0x7f454c46 }"#,
        r#"rule t { condition: entrypoint == 0 }"#,
        r#"import "pe" rule t { condition: pe.number_of_sections == 1 }"#,
        r#"import "pe" rule t { condition: pe.sections[0].name == ".text" }"#,
        r#"import "pe" rule t { condition: pe.machine == pe.MACHINE_AMD64 }"#,
        r#"import "pe" rule t { condition: pe.imphash() == "x" }"#,
        r#"import "math" rule t { condition: math.entropy(0, filesize) > 0.0 }"#,
        r#"import "hash" rule t { condition: hash.md5(0, filesize) == "x" }"#,
        // The `elf` and `dotnet` modules landed after this list was written; both
        // used to sit in the reject list above, which is exactly the kind of
        // stale assertion a conformance suite is supposed to catch.
        r#"import "elf" rule t { condition: elf.type == elf.ET_EXEC }"#,
        r#"import "dotnet" rule t { condition: dotnet.is_dotnet }"#,
    ] {
        assert!(
            exav_core::yara::compile(src).is_ok(),
            "expected successful compile for: {src}"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase C: `for … in`, `for … of`, and `with`.
//
// Ported from yara-x's `lib/src/tests/mod.rs` (`for_in`, `with`, `for_of`,
// `match_count`/`match_offset`/`match_length` for-of assertions). Assertions
// gated on the `test_proto2` module in yara-x are omitted — exav does not
// ship a test module — but every non-module `for`/`with`/`for-of` assertion is
// reproduced here.
// ---------------------------------------------------------------------------

#[test]
fn for_in_ranges() {
    condition_true!("for any i in (0..1): ( 1 )");
    condition_false!("for any i in (0..1): ( 0 )");
    condition_true!(r#"for any i in (0..1): ( "a" )"#);
    condition_false!(r#"for any i in (0..1): ( "" )"#);
    condition_true!("for all i in (0..0) : ( true )");
    condition_false!("for all i in (0..0) : ( false )");
    condition_false!("for none i in (0..0) : ( true )");
    condition_true!("for none i in (0..0) : ( false )");
    condition_true!("for none i in (0..10) : ( false )");
    condition_false!("for none i in (0..10) : ( true )");
    condition_true!("for all i in (0..10) : ( true )");
    condition_false!("for all i in (0..10) : ( false )");
    condition_true!("for any i in (0..10) : ( i == 5 )");
    condition_false!("for none i in (0..10) : ( i == 5 )");
    condition_true!("for all i in (0..10) : ( i <= 10 )");
    condition_true!("for none i in (0..10) : ( i > 10 )");
    condition_true!("for all i in (3..5) : ( i >= 3 and i <= 5 )");

    // `for 0 …` must behave as `for none …`.
    condition_true!("for 0 i in (0..10) : ( i > 10 )");
    condition_false!("for 0 i in (0..10) : ( i == 5 )");

    condition_true!(
        "for all i in (0..10) : (
            for all j in (i..10) : (
                 j >= i
            )
        )"
    );

    condition_true!("for 1 i in (0..10) : ( i == 0 )");
    condition_true!("for 11 i in (0..10) : ( i == i )");
    condition_true!("for 1 i in (0..10) : ( i <= 1 )");
    condition_true!("for 2 i in (0..10) : ( i <= 1 )");
    condition_true!("for 1+1 i in (0..10) : ( i <= 1 )");
    condition_true!("for 50% i in (0..10) : ( i < 6 )");
    condition_false!("for 50% i in (0..10) : ( i >= 6 )");
    condition_true!("for 10% i in (0..9) : ( i == 0 )");
    condition_false!("for 11% i in (0..9) : ( i == 0 )");
}

#[test]
fn for_in_empty_range_is_false() {
    // If the lower bound exceeds the upper bound the `for` loop is always
    // false, regardless of the quantifier. The outer loop lets us build the
    // range `(i+1..i)` without writing a literal inverted range (a parse error).
    condition_false!(
        "for any i in (1..1) : (
            for all j in (i + 1..i) : ( true )
        )"
    );
    condition_false!(
        "for any i in (1..1) : (
            for all j in (i + 1..i) : ( false )
        )"
    );
    condition_false!(
        "for any i in (1..1) : (
            for none j in (i + 1..i) : ( true )
        )"
    );
    condition_false!(
        "for any i in (1..1) : (
            for none j in (i + 1..i) : ( false )
        )"
    );
}

#[test]
fn for_in_tuples() {
    condition_true!(r#"for any e in (1,2,3) : (e == 3)"#);
    condition_true!(r#"for any e in (1+1,2+2) : (e == 2)"#);
    condition_false!(r#"for any e in (1+1,2+2) : (e == 3)"#);
    condition_true!(r#"for all e in (1+1,2+2) : (e < 5)"#);
    condition_true!(r#"for 2 s in ("foo", "bar", "baz") : (s contains "ba")"#);
    condition_true!(r#"for all x in (1.0, 2.0, 3.0) : (x >= 1.0)"#);
    condition_true!(r#"for none x in (1.0, 2.0, 3.0) : (x > 4.0)"#);
}

#[test]
fn with_expr() {
    condition_true!(r#"with foo = 1 + 1 : (foo == 2)"#);
    condition_false!(r#"with foo = 1 + 1 : (foo == 3)"#);
    condition_true!(r#"with foo = 1 + 1, bar = 2 + 2 : (foo + bar == 6)"#);
    condition_false!(r#"with foo = 1 + 1, bar = 2 + 2 : (foo + bar == 7)"#);
    // A later declaration may reference an earlier one.
    condition_true!(r#"with a = 3, b = a + 1 : (b == 4)"#);
    // Nested `with`.
    condition_true!(r#"with one = 1 : ( with two = one + one : (two == 2) )"#);
}

// `for … of` over pattern sets, binding `$`/`#`/`@`/`!` to the current pattern.
#[test]
fn for_of_patterns() {
    rule_true!(
        r#"rule t { strings: $a = "foo" $b = "bar"
           condition: for all of them : ( # == 2 ) }"#,
        b"foobarfoobar"
    );
    rule_true!(
        r#"rule t { strings: $a = "foo" $b = "bar"
           condition: for all of ($a, $b) : ( @ <= 3 ) }"#,
        b"foobarfoobar"
    );
    rule_true!(
        r#"rule t { strings: $a = "foo" $b = "bar"
           condition: for all of ($a, $b) : ( @[2] >= 6 ) }"#,
        b"foobarfoobar"
    );
    rule_true!(
        r#"rule t { strings: $a = "foo"
           condition: for any i in (1..#a) : ( @a[i] >= 6 ) }"#,
        b"foobarfoobar"
    );
    rule_true!(
        r#"rule t { strings: $a = "foo" $b = "bar"
           condition: for all of ($a, $b) : ( ! == 3 ) }"#,
        b"foobarfoobar"
    );
    rule_true!(
        r#"rule t { strings: $a = "foo" $b = "bar"
           condition: for all of ($a, $b) : ( ![2] == 3 ) }"#,
        b"foobarfoobar"
    );
    // The anonymous `$` = the current pattern's presence.
    rule_true!(
        r#"rule t { strings: $a = "foo" $b = "bar"
           condition: for none of ($a, $b) : ($) }"#,
        &[]
    );
    rule_true!(
        r#"rule t { strings: $a = "foo" $b = "bar"
           condition: for all of them : ($) }"#,
        b"foobar"
    );
    rule_true!(
        r#"rule t { strings: $a = "foo" $b = "bar"
           condition: for 1 of them : ( # == 2 ) }"#,
        b"foobarbar"
    );
    rule_true!(
        r#"rule t { strings: $a = "foo" $b = "bar"
           condition: for 1 of them : ( @ > 0 ) }"#,
        b"foobarbar"
    );
}

// `for any <var> in pe.sections` — a struct-typed loop variable navigated in
// the body — plus `with` bound to `pe` sub-values.
#[test]
fn for_in_pe_sections() {
    const PE: &[u8] = include_bytes!("testdata/tiny_pe32.exe");
    fn t(cond: &str, data: &[u8]) -> bool {
        let src = format!("import \"pe\" rule r {{ condition: {cond} }}");
        let rules = exav_core::yara::compile(&src).expect("compile");
        rules.scan(data).matching_rules().len() == 1
    }
    assert!(t(r#"for any s in pe.sections : (s.name == ".text")"#, PE));
    assert!(t(
        r#"for all s in pe.sections : (s.virtual_address == 0x1000)"#,
        PE
    ));
    assert!(t(
        r#"for any s in pe.sections : (s.characteristics & pe.SECTION_MEM_EXECUTE != 0)"#,
        PE
    ));
    assert!(!t(r#"for any s in pe.sections : (s.name == ".data")"#, PE));
    // `with` bound to a section struct, then a scalar field.
    assert!(t(
        r#"with s = pe.sections[0] : (s.name == ".text" and s.raw_data_offset == 0x200)"#,
        PE
    ));
    // `with` binding the whole `pe` struct.
    assert!(t(
        r#"with p = pe : (p.is_pe and p.machine == pe.MACHINE_I386)"#,
        PE
    ));
    // A non-PE input: `for any s in pe.sections` over an empty section list is
    // false (empty iterable).
    assert!(!t(r#"for any s in pe.sections : (true)"#, b"not a pe"));
}
