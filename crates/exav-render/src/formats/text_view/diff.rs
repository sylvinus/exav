//! A diff's lines, each marked by what it adds, removes or introduces.

use super::{Formatted, Line, Seg, class, split_lines};

/// A diff line's class: what it adds, removes or introduces.
fn diff_class(line: &str) -> Option<&'static str> {
    if ["+++", "---", "diff ", "index "]
        .iter()
        .any(|p| line.starts_with(p))
    {
        Some(class::META)
    } else if line.starts_with("@@") {
        Some(class::HUNK)
    } else {
        match line.as_bytes().first() {
            Some(b'+') => Some(class::ADD),
            Some(b'-') => Some(class::DEL),
            _ => None,
        }
    }
}

/// The lines of `text`, at most `max_lines` of them; one with a class is a
/// single piece, the others are plain.
pub fn format_diff(text: &str, max_lines: usize) -> Formatted<'_> {
    let (lines, more) = split_lines(text, max_lines);
    Formatted {
        lines: lines
            .into_iter()
            .map(|text| match diff_class(text) {
                Some(class) => Line::Segs(vec![Seg {
                    text,
                    class: Some(class),
                }]),
                None => Line::Plain(text),
            })
            .collect(),
        more,
        well_formed: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_what_a_line_adds_removes_or_introduces() {
        let diff = [
            "diff --git a/f b/f",
            "index 1..2 100644",
            "--- a/f",
            "+++ b/f",
            "@@ -1,2 +1,2 @@",
            " same",
            "-old",
            "+new",
            "",
        ]
        .join("\n");
        let f = format_diff(&diff, 100);
        let class_of = |i: usize| match &f.lines[i] {
            Line::Segs(s) => s[0].class,
            Line::Plain(_) => None,
        };
        let meta = Some(class::META);
        assert_eq!(
            (0..9).map(class_of).collect::<Vec<_>>(),
            [
                meta,
                meta,
                meta,
                meta,
                Some(class::HUNK),
                None,
                Some(class::DEL),
                Some(class::ADD),
                None
            ]
        );
        assert!(matches!(f.lines[5], Line::Plain(" same")));
        assert_eq!(
            f.lines
                .iter()
                .map(Line::text)
                .collect::<Vec<_>>()
                .join("\n"),
            diff
        );
        assert!(!f.more);
    }

    #[test]
    fn says_when_there_are_more_lines_than_the_cap() {
        let f = format_diff("+a\n+b\n+c", 2);
        assert_eq!(f.lines.len(), 2);
        assert!(f.more);
    }
}
