//! Field instructions as the formats write them.

/// `HYPERLINK "target" \l "anchor" \o "tip"`: the target, the anchor and the
/// tooltip. Targets that run script are dropped.
pub fn parse_hyperlink(instr: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut target = None;
    let mut anchor = None;
    let mut tip = None;
    let mut words: Vec<String> = vec![];
    let mut cur = String::new();
    let mut quoted = false;
    let mut had = false;
    for c in instr.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                had = true;
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() || had {
                    words.push(std::mem::take(&mut cur));
                    had = false;
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() || had {
        words.push(cur);
    }
    let mut i = 1;
    while i < words.len() {
        match words[i].as_str() {
            "\\l" => {
                anchor = words.get(i + 1).cloned();
                i += 1;
            }
            "\\o" => {
                tip = words.get(i + 1).cloned();
                i += 1;
            }
            "\\t" | "\\m" | "\\n" => {
                i += 1;
            }
            w if !w.starts_with('\\') && target.is_none() => target = Some(w.to_string()),
            _ => {}
        }
        i += 1;
    }
    let target = target.filter(|t| safe_target(t));
    (target, anchor, tip)
}

/// Whether a link target is one a viewer may follow: not a script or data
/// URL.
pub fn safe_target(t: &str) -> bool {
    let l = t.trim().to_ascii_lowercase();
    !(l.starts_with("javascript:") || l.starts_with("vbscript:") || l.starts_with("data:"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hyperlink_instructions() {
        let (t, a, tip) = parse_hyperlink("HYPERLINK \"http://example.org/a b\" \\o \"Tip\"");
        assert_eq!(t.as_deref(), Some("http://example.org/a b"));
        assert_eq!(tip.as_deref(), Some("Tip"));
        assert!(a.is_none());
        let (t, a, _) = parse_hyperlink("HYPERLINK \\l \"_Toc1\"");
        assert!(t.is_none());
        assert_eq!(a.as_deref(), Some("_Toc1"));
        let (t, _, _) = parse_hyperlink("HYPERLINK \"javascript:alert(1)\"");
        assert!(t.is_none());
    }
}
