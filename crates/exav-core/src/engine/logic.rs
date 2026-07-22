//! `.ldb` logical-signature boolean-expression parser and evaluator. Split out
//! of `mod.rs`; every item is `pub(super)` (internal to the `engine` module).

use super::*;

/// A parsed logical expression.
#[derive(Serialize, Deserialize)]
pub(super) enum Node {
    /// Bare subsig: matched at least once.
    Sub(usize),
    /// Subsig match-count compared to x.
    SubCmp(usize, Cmp, u32),
    /// Group: total matches across `ids` compared to x, and (if Some) at least
    /// y *distinct* subsigs in the group matched.
    GroupCmp(Vec<usize>, Cmp, u32, Option<u32>),
    And(Vec<Node>),
    Or(Vec<Node>),
}

pub(super) fn cmp_ok(c: Cmp, v: u32, x: u32) -> bool {
    match c {
        Cmp::Eq => v == x,
        Cmp::Gt => v > x,
        Cmp::Lt => v < x,
    }
}

impl Node {
    pub(super) fn eval(&self, count: &dyn Fn(usize) -> u32) -> bool {
        match self {
            Node::Sub(i) => count(*i) > 0,
            Node::SubCmp(i, c, x) => cmp_ok(*c, count(*i), *x),
            Node::GroupCmp(ids, c, x, y) => {
                let total: u32 = ids.iter().map(|&i| count(i)).sum();
                if !cmp_ok(*c, total, *x) {
                    return false;
                }
                match y {
                    Some(y) => ids.iter().filter(|&&i| count(i) > 0).count() as u32 >= *y,
                    None => true,
                }
            }
            Node::And(v) => v.iter().all(|n| n.eval(count)),
            Node::Or(v) => v.iter().any(|n| n.eval(count)),
        }
    }

    /// Sound satisfiability over-approximation: can this expression *possibly*
    /// evaluate true, given that subsigs for which `unknown(i)` is true have a
    /// not-yet-computed binary count (0 or 1 — PCRE/bcomp/fuzzy subsigs), while
    /// the rest have the fixed count `count(i)`? Returns false only when NO
    /// assignment of the unknowns can satisfy the expression, so a caller may
    /// safely skip evaluating those (expensive) subsigs. Unknowns appearing in
    /// multiple leaves are treated independently (an over-approximation), so the
    /// result can be a false "possible" but never a false "impossible" — pruning
    /// stays FN-safe.
    pub(super) fn can_be_true(
        &self,
        count: &dyn Fn(usize) -> u32,
        unknown: &dyn Fn(usize) -> bool,
    ) -> bool {
        match self {
            Node::Sub(i) => unknown(*i) || count(*i) > 0,
            Node::SubCmp(i, c, x) => {
                if unknown(*i) {
                    cmp_ok(*c, 0, *x) || cmp_ok(*c, 1, *x)
                } else {
                    cmp_ok(*c, count(*i), *x)
                }
            }
            Node::GroupCmp(ids, c, x, y) => {
                let known_sum: u32 = ids.iter().filter(|&&i| !unknown(i)).map(|&i| count(i)).sum();
                let nunk = ids.iter().filter(|&&i| unknown(i)).count() as u32;
                // Unknown subsigs each contribute 0 or 1, so the group total is
                // achievable anywhere in [known_sum, known_sum + nunk].
                let total_ok = match c {
                    Cmp::Gt => known_sum + nunk > *x,
                    Cmp::Lt => known_sum < *x,
                    Cmp::Eq => *x >= known_sum && *x <= known_sum + nunk,
                };
                if !total_ok {
                    return false;
                }
                match y {
                    Some(y) => {
                        let known_distinct = ids
                            .iter()
                            .filter(|&&i| !unknown(i) && count(i) > 0)
                            .count() as u32;
                        known_distinct + nunk >= *y
                    }
                    None => true,
                }
            }
            Node::And(v) => v.iter().all(|n| n.can_be_true(count, unknown)),
            Node::Or(v) => v.iter().any(|n| n.can_be_true(count, unknown)),
        }
    }

    fn collect_ids(&self, out: &mut Vec<usize>) {
        match self {
            Node::Sub(i) | Node::SubCmp(i, _, _) => out.push(*i),
            Node::GroupCmp(ids, ..) => out.extend_from_slice(ids),
            Node::And(v) | Node::Or(v) => v.iter().for_each(|n| n.collect_ids(out)),
        }
    }

    /// True if every subsig id referenced is `< nsubs`.
    pub(super) fn ids_within(&self, nsubs: usize) -> bool {
        match self {
            Node::Sub(i) | Node::SubCmp(i, _, _) => *i < nsubs,
            Node::GroupCmp(ids, ..) => ids.iter().all(|&i| i < nsubs),
            Node::And(v) | Node::Or(v) => v.iter().all(|n| n.ids_within(nsubs)),
        }
    }
}

pub(super) fn parse_expr(expr: &str) -> Option<Node> {
    let tokens: Vec<u8> = expr.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut p = Parser { s: &tokens, i: 0 };
    let node = p.or()?;
    if p.i == p.s.len() {
        Some(node)
    } else {
        None
    }
}

pub(super) struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn or(&mut self) -> Option<Node> {
        let mut v = vec![self.and()?];
        while self.peek() == Some(b'|') {
            self.i += 1;
            v.push(self.and()?);
        }
        Some(if v.len() == 1 {
            v.pop().unwrap()
        } else {
            Node::Or(v)
        })
    }

    fn and(&mut self) -> Option<Node> {
        let mut v = vec![self.atom()?];
        while self.peek() == Some(b'&') {
            self.i += 1;
            v.push(self.atom()?);
        }
        Some(if v.len() == 1 {
            v.pop().unwrap()
        } else {
            Node::And(v)
        })
    }

    fn atom(&mut self) -> Option<Node> {
        match self.peek()? {
            b'(' => {
                self.i += 1;
                let inner = self.or()?;
                if self.peek() != Some(b')') {
                    return None;
                }
                self.i += 1;
                // A count modifier on a group counts total matches across the
                // group's subsigs (and, with `,y`, distinct subsigs matched).
                if let Some(cmp) = self.cmp() {
                    let (x, y) = self.count_args()?;
                    let mut ids = Vec::new();
                    inner.collect_ids(&mut ids);
                    Some(Node::GroupCmp(ids, cmp, x, y))
                } else {
                    Some(inner)
                }
            }
            b'0'..=b'9' => {
                let sub = self.number()?;
                if let Some(cmp) = self.cmp() {
                    let (x, _y) = self.count_args()?; // single subsig: y is ignored
                    Some(Node::SubCmp(sub, cmp, x))
                } else {
                    self.skip_colon_suffix();
                    Some(Node::Sub(sub))
                }
            }
            _ => None,
        }
    }

    /// Discard a `:`-suffix on a subsignature reference.
    ///
    /// `0:0` means `0`. This is not in any grammar and looks like a typo, but a
    /// live `daily` signature (`Win.Trojan.Agent-6825810-0-6852456-0`) carries
    /// `0:0&((1>20&2>10&3)|(4))` and clamscan loads and fires it, so refusing
    /// the line cost a real detection. Three probes pinned the behaviour down:
    /// `0:1&0` fails to load with "the number of subsignatures doesn't match the
    /// IDs" while `0:1&1` loads, so the reference is the number BEFORE the
    /// colon; and `0:1&1` then requires both subsignatures to match, so the
    /// reference is live rather than inert. Everything after the colon is
    /// discarded.
    fn skip_colon_suffix(&mut self) {
        if self.peek() != Some(b':') {
            return;
        }
        self.i += 1;
        // Discard everything up to the next operator. The suffix is not always
        // numeric — two live `.lnk` signatures carry the *header bytes* they
        // match on there (`0:4C202020011402`) — so stopping at the first
        // non-digit would leave the rest of it to be parsed as an expression.
        while !matches!(self.peek(), None | Some(b'&' | b'|' | b')')) {
            self.i += 1;
        }
    }

    fn cmp(&mut self) -> Option<Cmp> {
        let c = match self.peek()? {
            b'=' => Cmp::Eq,
            b'>' => Cmp::Gt,
            b'<' => Cmp::Lt,
            _ => return None,
        };
        self.i += 1;
        // `==` for equality: not the documented spelling, but a live signature
        // (`Win.Trojan.DownloadGuide-6335034-0`) writes `(8==9)` and it loads,
        // so the second `=` is absorbed rather than left to fail the parse.
        if c == Cmp::Eq && self.peek() == Some(b'=') {
            self.i += 1;
        }
        Some(c)
    }

    /// Parse `x` or `x,y` after a comparison operator.
    fn count_args(&mut self) -> Option<(u32, Option<u32>)> {
        let x = self.number()? as u32;
        if self.peek() == Some(b',') {
            self.i += 1;
            // A trailing comma with no second count — `0=2,&1&2` in
            // `Unix.Trojan.Elknot-2` — is tolerated and means the same as no
            // comma at all.
            return Some((x, self.number().map(|y| y as u32)));
        }
        Some((x, None))
    }

    fn number(&mut self) -> Option<usize> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        std::str::from_utf8(&self.s[start..self.i])
            .ok()?
            .parse()
            .ok()
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `:`-suffixed subsignature reference means the number before the colon,
    /// and the reference stays live. Established against clamscan, not guessed —
    /// see [`Parser::skip_colon_suffix`].
    #[test]
    fn a_colon_suffix_on_a_subsig_reference_is_discarded() {
        let plain = parse_expr("0&1").expect("baseline");
        let colon = parse_expr("0:1&1").expect("a colon suffix must parse");
        for a in 0..2u32 {
            for b in 0..2u32 {
                let c = [a, b];
                assert_eq!(
                    colon.eval(&|i| c[i]),
                    plain.eval(&|i| c[i]),
                    "`0:1&1` must behave exactly as `0&1` for counts {c:?}"
                );
            }
        }
        // And the whole live signature that motivated this parses.
        let real = parse_expr("0:0&((1>20&2>10&3)|(4))").expect("the daily signature");
        let mut ids = Vec::new();
        real.collect_ids(&mut ids);
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids, vec![0, 1, 2, 3, 4], "all five subsignatures referenced");
        // Subsig 0 alone is not enough; 0 plus the right-hand branch is.
        assert!(!real.eval(&|i| u32::from(i == 0)));
        assert!(real.eval(&|i| u32::from(i == 0 || i == 4)));
    }

    /// `can_be_true` must agree with an exhaustive check: for any fixed body
    /// counts and any set of binary "unknown" subsigs, it returns false only when
    /// NO 0/1 assignment of the unknowns makes `eval` true (sound, FN-safe), and
    /// it is exact whenever each unknown appears at most once in the expression.
    fn brute_satisfiable(node: &Node, base: &[u32], unk: &[usize]) -> bool {
        for mask in 0u32..(1u32 << unk.len()) {
            let mut c = base.to_vec();
            for (bit, &i) in unk.iter().enumerate() {
                c[i] = (mask >> bit) & 1;
            }
            if node.eval(&|i| c.get(i).copied().unwrap_or(0)) {
                return true;
            }
        }
        false
    }

    fn check(expr: &str, base: &[u32], unk: &[usize]) {
        let node = parse_expr(expr).unwrap();
        let is_unknown = |i: usize| unk.contains(&i);
        let over = node.can_be_true(&|i| base.get(i).copied().unwrap_or(0), &is_unknown);
        let exact = brute_satisfiable(&node, base, unk);
        // Sound: whenever truly satisfiable, the over-approximation must say so.
        assert!(
            over || !exact,
            "expr `{expr}` base={base:?} unk={unk:?}: pruned a satisfiable expr (FN!)"
        );
    }

    #[test]
    fn gate_never_prunes_satisfiable() {
        // Absent required AND-body → unsatisfiable regardless of the PCRE.
        let node = parse_expr("0&1").unwrap();
        assert!(!node.can_be_true(&|_| 0, &|i| i == 1)); // subsig0 absent
        assert!(node.can_be_true(&|i| (i == 0) as u32, &|i| i == 1)); // subsig0 present
        // OR keeps it satisfiable through the unknown branch.
        let n2 = parse_expr("(0&1)|2").unwrap();
        assert!(n2.can_be_true(&|_| 0, &|i| i == 2));
    }

    #[test]
    fn gate_matches_brute_force() {
        // Exhaustively cross-check the over-approximation against brute force on
        // a range of shapes, including `<`/`=` counts and grouped thresholds.
        for base in [[0u32, 0, 0, 0], [1, 0, 1, 0], [0, 2, 0, 3], [1, 1, 1, 1]] {
            for unk in [
                vec![],
                vec![1],
                vec![3],
                vec![1, 3],
                vec![0, 1, 2, 3],
            ] {
                check("0&1&2&3", &base, &unk);
                check("(0|1)&(2|3)", &base, &unk);
                check("0&1<1", &base, &unk); // subsig1 count must be < 1 (i.e. 0)
                check("(0|1|2|3)>2", &base, &unk);
                check("(0|1|2|3)=1", &base, &unk);
                check("((0|1)&2)|(3=0)", &base, &unk);
            }
        }
    }
}

