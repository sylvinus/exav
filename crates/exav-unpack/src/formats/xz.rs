use crate::*;

pub(crate) fn extract_xz<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let (out, truncated) = decode_xz(data, cap)?;
    if truncated {
        return Err(LimitHit::new("xz member exceeds budget".to_string()));
    }
    ratio_guard(data.len() as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(visit(Entry::new("xz-content".to_string(), out), budget))
}

/// Decode all concatenated XZ streams using xz4rust's block-based API
/// (pure Rust, no unsafe, zero runtime deps with no_unsafe + no sha256).
fn decode_xz(data: &[u8], cap: u64) -> Result<(Vec<u8>, bool), LimitHit> {
    let mut decoder = xz4rust::XzDecoder::with_alloc_dict_size(8192, 64 * 1024 * 1024);
    let mut out = Vec::new();
    let mut input_pos = 0;
    let mut out_buf = [0u8; 8192];

    loop {
        let remaining = cap.saturating_sub(out.len() as u64);
        if remaining == 0 {
            return Ok((out, true));
        }

        let feed = data[input_pos..].len().min(out_buf.len());
        if feed == 0 {
            break;
        }

        match decoder.decode(&data[input_pos..input_pos + feed], &mut out_buf) {
            Ok(result) => {
                let produced = result.output_produced();
                if produced > 0 {
                    out.extend_from_slice(&out_buf[..produced]);
                    // Check budget after each output chunk (catches bombs).
                    if out.len() as u64 > cap {
                        return Ok((out, true));
                    }
                }
                input_pos += result.input_consumed();
                if let xz4rust::XzNextBlockResult::EndOfStream(_, _) = result {
                    decoder.reset();
                    // Skip padding zeros between concatenated streams
                    while input_pos < data.len() && data[input_pos] == 0 {
                        input_pos += 1;
                    }
                    if input_pos >= data.len() {
                        break;
                    }
                }
            }
            Err(xz4rust::XzError::NeedsLargerInputBuffer) => {
                input_pos += feed;
            }
            Err(e) => {
                return Err(LimitHit::new(format!("xz: {e}")));
            }
        }
    }
    Ok((out, false))
}
