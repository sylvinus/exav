//! Adobe XDP (XML Data Package) — an XML wrapper carrying a base64-encoded PDF.
//!
//! A malicious PDF is frequently smuggled inside an `.xdp`: the bytes live in one
//! or more `<chunk>…</chunk>` elements under `<pdf>` (itself under the `<xdp>`
//! root). We concatenate every chunk's base64 payload, decode it, and emit the
//! reconstructed PDF as a single member for the engine to recurse into.
//!
//! Parsing is a plain byte scan (no XML entity handling needed for the base64
//! text), fully bounds-checked so truncated/hostile input cannot panic.

use crate::*;
use base64::Engine;

/// True if `data` looks like an Adobe XDP document. Conservative: requires the
/// `<pdf` + `<chunk>` pair (the smuggled-PDF shape) or an explicit `<xdp` root.
pub(crate) fn looks_like_xdp(data: &[u8]) -> bool {
    let head = &data[..data.len().min(65536)];
    let has = |needle: &[u8]| memchr::memmem::find(head, needle).is_some();
    (has(b"<pdf") && has(b"<chunk")) || has(b"<xdp")
}

pub(crate) fn extract_xdp<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Collect the base64 text of every <chunk>…</chunk>, whitespace stripped.
    let mut b64: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        // Find the next "<chunk" start tag.
        let Some(rel) = memchr::memmem::find(&data[pos..], b"<chunk") else {
            break;
        };
        let tag_start = pos + rel;
        // The chunk body begins after the '>' that closes the opening tag.
        let Some(gt) = memchr::memchr(b'>', &data[tag_start.min(data.len())..]) else {
            break;
        };
        let body_start = (tag_start + gt + 1).min(data.len());
        // The body ends at the next "</chunk" (or EOF for a truncated doc).
        let body_end = memchr::memmem::find(&data[body_start..], b"</chunk")
            .map(|r| body_start + r)
            .unwrap_or(data.len());
        b64.extend(
            data[body_start..body_end]
                .iter()
                .filter(|b| !b.is_ascii_whitespace()),
        );
        // Bound the accumulated base64 so an XDP bomb can't blow past the budget
        // before we decode (4 base64 chars -> 3 bytes).
        let cap_peek = budget
            .limits
            .max_entry_bytes
            .min(budget.limits.max_total_bytes);
        if b64.len() as u64 > cap_peek.saturating_mul(2).saturating_add(64) {
            return Err(LimitHit::new(
                "xdp: embedded PDF exceeds budget".to_string(),
            ));
        }
        pos = body_end.saturating_add(7).min(data.len()); // past "</chunk"
    }

    if b64.is_empty() {
        return Ok(None);
    }

    budget.count_entry()?;
    let cap = budget.reserve()?;
    let out = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| LimitHit::corrupt(format!("xdp base64: {e}")))?;
    if out.len() as u64 > cap {
        return Err(LimitHit::new(
            "xdp: embedded PDF exceeds budget".to_string(),
        ));
    }
    budget.commit(out.len() as u64);
    if let Some(r) = visit(Entry::new("embedded.pdf".to_string(), out), budget) {
        return Ok(Some(r));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdp_single_chunk_roundtrip() {
        let pdf = b"%PDF-1.4 MALWARETEST body \nendobj\n%%EOF";
        let b64 = base64::engine::general_purpose::STANDARD.encode(pdf);
        let xdp = format!(
            "<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\">\
             <pdf xmlns=\"http://ns.adobe.com/xdp/pdf/\"><document><chunk>{b64}</chunk>\
             </document></pdf></xdp:xdp>"
        )
        .into_bytes();
        assert!(looks_like_xdp(&xdp));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xdp, &xdp, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "embedded.pdf");
        assert_eq!(entries[0].data, pdf);
    }

    #[test]
    fn xdp_multi_chunk_concatenated() {
        // Two chunks whose base64 concatenates to the full PDF (whitespace and
        // newlines between/within chunks must be ignored).
        let pdf = b"%PDF-1.5 MALWARETEST split across chunks";
        let full = base64::engine::general_purpose::STANDARD.encode(pdf);
        let (a, b) = full.split_at(full.len() / 2);
        let xdp = format!("<xdp><pdf><chunk>\n  {a}\n</chunk><chunk>{b}\n</chunk></pdf></xdp>")
            .into_bytes();
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xdp, &xdp, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, pdf);
    }

    #[test]
    fn truncated_chunk_does_not_panic() {
        let xdp = b"<xdp><pdf><chunk>QUJD".to_vec(); // no closing tag
        let mut budget = Budget::new(Limits::default());
        let _ = extract(Format::Xdp, &xdp, &mut budget);
    }
}
