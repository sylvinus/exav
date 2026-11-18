//! The superblock of an ext2, ext3 or ext4 volume: the fields that give a
//! volume its shape, and the check that a thousand bytes are one. Layout:
//! the kernel's ext4 documentation, "Super Block".
//!
//! This is read by [`crate::detect`] (in every build) and by the reader of the
//! volume (`ext`, behind its feature), so the two cannot disagree on what a
//! superblock is. Pure byte arithmetic.

pub(crate) const INCOMPAT_JOURNAL_DEV: u32 = 0x8;
pub(crate) const INCOMPAT_64BIT: u32 = 0x80;
pub(crate) const RO_COMPAT_BIGALLOC: u32 = 0x200;

fn le16(d: &[u8], off: usize) -> u16 {
    d.get(off..off + 2)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
}

fn le32(d: &[u8], off: usize) -> u32 {
    d.get(off..off + 4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The fields of a superblock that give the volume its shape, as far as they
/// are consistent with each other.
// Only the `ext` reader reads all of the fields.
#[cfg_attr(not(feature = "ext"), allow(dead_code))]
pub(crate) struct Geometry {
    pub(crate) bs: u64,
    /// The block count the superblock states.
    pub(crate) blocks: u64,
    pub(crate) first_data: u64,
    pub(crate) bpg: u64,
    pub(crate) ipg: u64,
    pub(crate) inode_size: usize,
    pub(crate) desc_size: usize,
    pub(crate) compat: u32,
    pub(crate) incompat: u32,
    pub(crate) ro_compat: u32,
}

/// The shape of the volume `sb` (the 1024 bytes at offset 1024) describes, or
/// `None` where its fields cannot be a volume's: the magic, a block size of
/// 64 KiB at most, counts that fit a bitmap block, an inode and a descriptor
/// size that are powers of two. The size of the object is not looked at.
pub(crate) fn geometry(sb: &[u8]) -> Option<Geometry> {
    if sb.len() < 1024 || le16(sb, 56) != 0xEF53 {
        return None;
    }
    let bs = 1024u64
        .checked_shl(le32(sb, 24))
        .filter(|&b| b <= 1 << 16)?;
    let (compat, incompat, ro_compat) = (le32(sb, 92), le32(sb, 96), le32(sb, 100));
    // A journal kept apart from the files it journals holds none of them.
    if incompat & INCOMPAT_JOURNAL_DEV != 0 {
        return None;
    }
    let wide = incompat & INCOMPAT_64BIT != 0;
    let hi = if wide { u64::from(le32(sb, 336)) } else { 0 };
    let blocks = u64::from(le32(sb, 4)) | hi.checked_shl(32)?;
    let first_data = u64::from(le32(sb, 20));
    let (bpg, ipg) = (u64::from(le32(sb, 32)), u64::from(le32(sb, 40)));
    // A bitmap bit stands for a cluster, which is a block unless bigalloc says more.
    let ratio = if ro_compat & RO_COMPAT_BIGALLOC != 0 {
        let shift = le32(sb, 28).checked_sub(le32(sb, 24))?;
        1u64.checked_shl(shift).filter(|&r| r <= 1 << 16)?
    } else {
        1
    };
    let per_bitmap = bs.checked_mul(8)?;
    if bpg == 0
        || ipg == 0
        || bpg > per_bitmap.checked_mul(ratio)?
        || ipg > per_bitmap
        || blocks <= first_data
    {
        return None;
    }
    let inode_size = if le32(sb, 76) == 0 {
        128
    } else {
        usize::from(le16(sb, 88))
    };
    if !inode_size.is_power_of_two() || inode_size < 128 || inode_size as u64 > bs {
        return None;
    }
    let desc_size = if wide { usize::from(le16(sb, 254)) } else { 32 };
    if !desc_size.is_power_of_two() || desc_size < 32 || (wide && desc_size < 64) {
        return None;
    }
    if desc_size as u64 > bs {
        return None;
    }
    Some(Geometry {
        bs,
        blocks,
        first_data,
        bpg,
        ipg,
        inode_size,
        desc_size,
        compat,
        incompat,
        ro_compat,
    })
}

/// Whether the 1024 bytes at offset 1024 of an object are the superblock of
/// an ext2, ext3 or ext4 volume, going by the fields every one of them has and
/// that the two bytes of the magic, which a file holds by chance once in
/// 65536, do not give: the shape of [`geometry`], revision 0 or 1, a first
/// data block of 1 for a 1 KiB block (0 for the others, and for bigalloc), a
/// cluster as large as a block unless bigalloc says otherwise, and as many
/// inodes as the groups hold. The size of the object is not looked at: an
/// image can be cut.
pub(crate) fn is_superblock(sb: &[u8]) -> bool {
    let Some(g) = geometry(sb) else {
        return false;
    };
    let bigalloc = g.ro_compat & RO_COMPAT_BIGALLOC != 0;
    let groups = (g.blocks - g.first_data).div_ceil(g.bpg);
    le32(sb, 76) <= 1
        && (g.first_data == 0 || (g.first_data == 1 && g.bs == 1024))
        && (bigalloc || le32(sb, 28) == le32(sb, 24))
        && u64::from(le32(sb, 0)) == groups.saturating_mul(g.ipg)
}
