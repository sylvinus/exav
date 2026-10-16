//! Wavefront OBJ into a [`Scene`] with one element per group or object.
//!
//! Read: `v` (with the `r g b` some exporters add), `vn` and `f`, in the
//! `v`, `v/vt`, `v//vn` and `v/vt/vn` forms, with negative indices counted
//! back from the vertices read so far; `g` and `o` start an element; a line
//! may continue on the next with a trailing backslash. Polygons are
//! triangulated, see [`Soup`].
//!
//! Ignored: texture coordinates, `usemtl`, `mtllib` and every other
//! statement. A material library is never opened, so a model has its
//! vertex colours or none. Lines, points and free-form curves and surfaces
//! are counted in `warnings.unsupported`. A face that names a vertex not yet
//! defined, or index 0, is dropped and counted in `warnings.invalid`; a
//! normal that does not exist is replaced by the face's.
//!
//! The file has no up axis: coordinates are returned as written.

use std::fmt;

use super::mesh::Scene;
use super::soup::{number, unit_byte, Corner, Soup};

/// Why a file was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Binary, or without a single vertex or face.
    NotObj,
    /// Faces, but none that could be drawn.
    NoValidFaces,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotObj => f.write_str("not an OBJ file"),
            Error::NoValidFaces => f.write_str("no face of the OBJ file can be drawn"),
        }
    }
}

impl std::error::Error for Error {}

/// Reads at most `max_triangles`; past them the rest is left out and
/// `warnings.truncated` is 1.
pub fn read(bytes: &[u8], max_triangles: usize) -> Result<Scene, Error> {
    if bytes[..bytes.len().min(8192)].contains(&0) {
        return Err(Error::NotObj);
    }
    let mut soup = Soup::new(max_triangles);
    let mut positions: Vec<[f32; 3]> = Vec::new();
    // Per vertex, alpha 0 for none; empty until a vertex has a colour.
    let mut colors: Vec<[u8; 4]> = Vec::new();
    let mut normals: Vec<[f32; 3]> = Vec::new();
    let mut corners: Vec<Corner> = Vec::new();
    let mut unsupported = std::collections::BTreeMap::<String, u32>::new();
    let (mut seen, mut faces, mut damaged) = (false, false, false);
    let mut joined: Vec<u8> = Vec::new();

    let mut lines = bytes.split(|&b| b == b'\n');
    while let Some(first) = lines.next() {
        let mut line = first;
        // A backslash continues the statement on the next line.
        if ends_with_backslash(line) {
            joined.clear();
            let mut part = first;
            loop {
                joined.extend_from_slice(trim_backslash(part));
                joined.push(b' ');
                if !ends_with_backslash(part) {
                    break;
                }
                match lines.next() {
                    Some(next) => part = next,
                    None => break,
                }
            }
            line = &joined;
        }
        let mut tokens = line
            .split(|b| b.is_ascii_whitespace())
            .filter(|t| !t.is_empty());
        let Some(keyword) = tokens.next() else {
            continue;
        };
        match keyword {
            b"v" => {
                let values: Vec<Option<f64>> = tokens.take(7).map(number).collect();
                seen = true;
                let ok = values.len() >= 3 && values[..3].iter().all(Option::is_some);
                if !ok {
                    damaged = true;
                }
                let at = |i: usize| values.get(i).copied().flatten().unwrap_or(f64::NAN);
                // NaN placeholders keep the indices of the vertices after it.
                positions.push(if ok {
                    [at(0) as f32, at(1) as f32, at(2) as f32]
                } else {
                    [f32::NAN; 3]
                });
                // Six values are x y z r g b; four are x y z w.
                let rgb = values.len() >= 6 && values[3..6].iter().all(Option::is_some);
                if rgb || !colors.is_empty() {
                    colors.resize(positions.len() - 1, [0; 4]);
                    colors.push(if rgb {
                        [unit_byte(at(3)), unit_byte(at(4)), unit_byte(at(5)), 1]
                    } else {
                        [0; 4]
                    });
                }
            }
            b"vn" => {
                let v: Vec<f64> = tokens.take(3).filter_map(number).collect();
                normals.push(if v.len() == 3 {
                    [v[0] as f32, v[1] as f32, v[2] as f32]
                } else {
                    [f32::NAN; 3]
                });
            }
            b"f" => {
                seen = true;
                faces = true;
                corners.clear();
                let mut valid = true;
                for t in tokens {
                    let mut parts = t.split(|&b| b == b'/');
                    let v = parts.next().and_then(|s| index(s, positions.len()));
                    let n = parts
                        .nth(1)
                        .and_then(|s| index(s, normals.len()))
                        .and_then(|i| normals.get(i).copied());
                    match v.and_then(|i| positions.get(i).map(|p| (i, *p))) {
                        Some((i, p)) => {
                            let c = colors
                                .get(i)
                                .filter(|c| c[3] != 0)
                                .map(|c| [c[0], c[1], c[2]]);
                            corners.push(Corner { p, n, c });
                        }
                        None => {
                            valid = false;
                            break;
                        }
                    }
                }
                if !valid || corners.len() < 3 {
                    soup.invalid = soup.invalid.saturating_add(1);
                } else if !soup.polygon(&corners) {
                    break;
                }
            }
            b"g" | b"o" => {
                let rest: Vec<u8> = tokens.collect::<Vec<_>>().join(&b' ');
                soup.begin(&String::from_utf8_lossy(&rest));
            }
            b"l" | b"p" | b"curv" | b"curv2" | b"surf" => {
                let key = String::from_utf8_lossy(keyword).into_owned();
                let n = unsupported.entry(key).or_insert(0);
                *n = n.saturating_add(1);
            }
            _ => {}
        }
    }
    if !seen {
        return Err(Error::NotObj);
    }
    let invalid = soup.invalid;
    let truncated = soup.truncated;
    let triangles = soup.triangles();
    let mut scene = soup.finish();
    if faces && triangles == 0 && invalid > 0 && !truncated {
        return Err(Error::NoValidFaces);
    }
    scene.warnings.unsupported = unsupported;
    scene.warnings.damaged = damaged;
    Ok(scene)
}

fn ends_with_backslash(line: &[u8]) -> bool {
    line.trim_ascii_end().last() == Some(&b'\\')
}

fn trim_backslash(line: &[u8]) -> &[u8] {
    let t = line.trim_ascii_end();
    t.strip_suffix(b"\\").unwrap_or(t)
}

/// A 1-based index, or a negative one counted back from `count`, as an
/// offset into the `count` items read so far.
fn index(token: &[u8], count: usize) -> Option<usize> {
    let n: i64 = std::str::from_utf8(token).ok()?.parse().ok()?;
    let at = match n {
        1.. => n - 1,
        0 => return None,
        _ => i64::try_from(count).ok()?.checked_add(n)?,
    };
    usize::try_from(at).ok().filter(|&i| i < count)
}
