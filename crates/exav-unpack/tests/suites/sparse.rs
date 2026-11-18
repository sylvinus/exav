//! A sparse file in a filesystem: its holes come out as zeros, charged to
//! `max_hole_bytes` and not to the scan budget, so a file far larger than the
//! scan budget, made of holes, does not end the walk before the rest of the
//! volume.
//!
//! `ext4_sparse.img.gz` (`e2fsprogs`):
//! ```sh
//! mkdir root
//! printf 'start of the sparse file\n' > root/a-sparse.bin
//! truncate -s 48M root/a-sparse.bin
//! printf 'end of the sparse file\n' >> root/a-sparse.bin
//! printf 'the last file of the volume\n' > root/z-last.txt
//! mke2fs -q -t ext4 -b 4096 -d root -L sparse sparse.img 8M
//! gzip -9 sparse.img
//! ```

use super::fs_tree::image;
use exav_unpack::{Budget, Format, Limits, Member, walk};

/// Name, length, first and last bytes, of a file the walk gave.
type Came = (String, usize, Vec<u8>);

fn walked(limits: Limits) -> (Vec<Came>, Result<(), String>) {
    let img = image("ext4_sparse");
    let mut budget = Budget::new(limits);
    let mut out = Vec::new();
    let end = walk(Format::Ext, &img, &mut budget, &mut |meta, content, _| {
        let data = match content {
            Some(Member::Stream(r)) => {
                let mut b = Vec::new();
                r.read_to_end(&mut b).ok();
                b
            }
            Some(Member::Bytes(b)) => b,
            #[allow(unreachable_patterns)]
            _ => Vec::new(),
        };
        let edges = [
            &data[..data.len().min(32)],
            &data[data.len().saturating_sub(32)..],
        ]
        .concat();
        out.push((meta.name.clone(), data.len(), edges));
        None::<()>
    });
    (out, end.map(|_| ()).map_err(|e| e.to_string()))
}

fn limits() -> Limits {
    let mut l = Limits::default();
    l.max_buffer_bytes = 64 * 1024;
    l.max_scanned_bytes = 4 * 1024 * 1024;
    l
}

/// The sparse file is twelve times the scan budget and comes out whole, and
/// the file after it is reached.
#[test]
fn a_sparse_file_past_the_scan_budget_does_not_end_the_walk() {
    let (got, end) = walked(limits());
    end.unwrap();
    let sparse = got
        .iter()
        .find(|g| g.0.ends_with("a-sparse.bin"))
        .unwrap_or_else(|| panic!("{got:?}"));
    assert_eq!(sparse.1, 50_331_671);
    assert!(sparse.2.starts_with(b"start of the sparse file\n"));
    assert!(sparse.2.ends_with(b"end of the sparse file\n"));
    let last = got
        .iter()
        .find(|g| g.0.ends_with("z-last.txt"))
        .unwrap_or_else(|| panic!("{got:?}"));
    assert_eq!(last.1, 28);
    assert!(last.2.starts_with(b"the last file of the volume\n"));
}

/// Holes are bounded by their own setting: past it the walk stops, and says
/// why.
#[test]
fn holes_past_their_own_limit_are_a_limit() {
    let mut l = limits();
    l.max_hole_bytes = 1024 * 1024;
    let (_, end) = walked(l);
    let e = end.unwrap_err();
    assert!(e.contains("holes"), "{e}");
}
