//! The HTML page and the pictures of a MIME-wrapped page: what Word saves as
//! "Single File Web Page" (MHTML), often under the name `.doc`. A multipart
//! message whose first HTML part is the page and whose image parts are named by
//! their `Content-Location` or `Content-ID`.

use crate::formats::office::common::base64;
use crate::formats::office::docs::error::Result;
use crate::formats::office::docs::limits::Budget;
use crate::formats::office::sheets::textenc::html_utf8;

/// Parts read, and levels of multipart in multipart.
const MAX_PARTS: usize = 4096;
const MAX_DEPTH: usize = 3;

pub(super) struct Picture {
    /// What the page may call it: the location as given, its last component,
    /// the content ID. Lower case.
    pub names: Vec<String>,
    pub data: Vec<u8>,
}

pub(super) struct Mime {
    pub html: String,
    pub pictures: Vec<Picture>,
}

/// The page and pictures of `input` when it is a MIME message with an HTML part.
pub(super) fn parse(input: &[u8], budget: &mut Budget) -> Result<Option<Mime>> {
    let head = String::from_utf8_lossy(&input[..input.len().min(2048)]).to_ascii_lowercase();
    if !head.trim_start().starts_with("mime-version:")
        && !(head.contains("\nmime-version:") && head.contains("content-type:"))
    {
        return Ok(None);
    }
    let mut mime = Mime {
        html: String::new(),
        pictures: vec![],
    };
    let mut parts = 0;
    let found = walk(input, 0, &mut parts, &mut mime, budget)?;
    Ok((found && !mime.html.is_empty()).then_some(mime))
}

/// A message or part: its headers, and its body.
fn split(data: &[u8]) -> (Vec<(String, String)>, &[u8]) {
    let (end, skip) = ["\r\n\r\n", "\n\n"]
        .iter()
        .filter_map(|sep| find(data, sep.as_bytes()).map(|at| (at, sep.len())))
        .min()
        .unwrap_or((data.len(), 0));
    let block = String::from_utf8_lossy(&data[..end]).to_string();
    let mut headers: Vec<(String, String)> = vec![];
    for line in block.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    (headers, &data[(end + skip).min(data.len())..])
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// A parameter of a header value: `charset=utf-8`, `boundary="x"`.
fn param(value: &str, name: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let at = lower.find(&format!("{name}="))?;
    let rest = &value[at + name.len() + 1..];
    let rest = rest.trim_start();
    Some(if let Some(q) = rest.strip_prefix('"') {
        q.split('"').next()?.to_string()
    } else {
        rest.split([';', ' ', '\t']).next()?.to_string()
    })
}

fn walk(
    data: &[u8],
    depth: usize,
    parts: &mut usize,
    out: &mut Mime,
    budget: &mut Budget,
) -> Result<bool> {
    *parts += 1;
    if *parts > MAX_PARTS || depth > MAX_DEPTH {
        return Ok(false);
    }
    let (h, body) = split(data);
    let ctype = header(&h, "content-type").unwrap_or("text/plain");
    let lower = ctype.to_ascii_lowercase();
    if lower.starts_with("multipart/") {
        let Some(boundary) = param(ctype, "boundary") else {
            return Ok(false);
        };
        let delim = format!("--{boundary}");
        let mut found = false;
        let mut at = 0;
        // The parts: between one delimiter line and the next.
        let mut starts = vec![];
        while let Some(p) = find(&body[at..], delim.as_bytes()).map(|p| p + at) {
            if p == 0 || body[p - 1] == b'\n' {
                starts.push(p);
            }
            at = p + delim.len();
        }
        for pair in starts.windows(2) {
            let after = pair[0] + delim.len();
            // The delimiter's line ends; the part follows, up to the line break
            // that belongs to the next delimiter.
            let Some(nl) = body[after..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|n| after + n + 1)
            else {
                continue;
            };
            let mut end = pair[1];
            if end > nl && body[end - 1] == b'\n' {
                end -= 1;
                if end > nl && body[end - 1] == b'\r' {
                    end -= 1;
                }
            }
            if end < nl {
                continue;
            }
            found |= walk(&body[nl..end], depth + 1, parts, out, budget)?;
        }
        return Ok(found);
    }
    let decoded = decode(&h, body, budget)?;
    if lower.starts_with("text/html") {
        if out.html.is_empty() {
            let text = match param(ctype, "charset")
                .and_then(|c| encoding_rs::Encoding::for_label(c.as_bytes()))
            {
                Some(enc) => enc.decode_without_bom_handling(&decoded).0.into_owned(),
                None => html_utf8(&decoded).into_owned(),
            };
            out.html = text;
            return Ok(true);
        }
    } else if lower.starts_with("image/") {
        let mut names = vec![];
        if let Some(l) = header(&h, "content-location") {
            let l = l.trim().to_ascii_lowercase();
            if let Some(last) = l.rsplit(['/', '\\']).next() {
                names.push(last.to_string());
            }
            names.push(l);
        }
        if let Some(id) = header(&h, "content-id") {
            names.push(id.trim().trim_matches(['<', '>']).to_ascii_lowercase());
        }
        if !names.is_empty() {
            out.pictures.push(Picture {
                names,
                data: decoded,
            });
        }
    }
    Ok(false)
}

/// A body with its transfer encoding undone.
fn decode(h: &[(String, String)], body: &[u8], budget: &mut Budget) -> Result<Vec<u8>> {
    let max = budget.limits.max_part as usize;
    let out = match header(h, "content-transfer-encoding")
        .map(|e| e.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("quoted-printable") => quoted_printable(body),
        Some("base64") => {
            let text = String::from_utf8_lossy(body);
            base64::decode(&text, max).unwrap_or_default()
        }
        _ => body.to_vec(),
    };
    budget.alloc(out.len() as u64)?;
    Ok(out)
}

fn quoted_printable(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'=' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        // A soft line break, or a byte in hexadecimal.
        match (b.get(i + 1), b.get(i + 2)) {
            (Some(b'\r'), Some(b'\n')) => i += 3,
            (Some(b'\n'), _) => i += 2,
            (Some(&a), Some(&c)) => {
                let hex = |x: u8| (x as char).to_digit(16);
                match (hex(a), hex(c)) {
                    (Some(a), Some(c)) => {
                        out.push((a * 16 + c) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'=');
                        i += 1;
                    }
                }
            }
            _ => {
                out.push(b'=');
                i += 1;
            }
        }
    }
    out
}
