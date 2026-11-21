//! The TLSH digest as yara-x's `elf.telfhash()` computes it.
//!
//! This is not `tlsh2`'s (the crate `fuzzy` uses) and not the reference
//! implementation's, because three results of yara-x 1.23 differ from both and
//! `telfhash()` has to give yara-x's:
//!
//! * the input must be at least 50 bytes, and nothing else rejects a sparse
//!   input (the reference also wants more than half of the buckets used);
//! * the first and third quartile are only searched where the search for the
//!   median left a boundary, so for about one input in twenty `q1` stays 0 (the
//!   digest then has a first ratio of 0) or `q3` stays 0 (no digest);
//! * the digest has 128 buckets and a one-byte checksum.
//!
//! The algorithm, the Pearson table and the table of lengths are TLSH's,
//! Copyright 2013 Trend Micro Incorporated, BSD-3-Clause (the project is also
//! offered under Apache-2.0), https://github.com/trendmicro/tlsh.

/// Pearson's table.
static V_TABLE: [u8; 256] = [
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163, 14, 197, 213, 181, 161,
    85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200, 110, 177, 104, 103, 141, 253, 255, 50, 77,
    101, 81, 18, 45, 96, 31, 222, 25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227,
    149, 235, 97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248, 174, 169,
    211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243, 132, 56, 148, 75, 128, 133,
    158, 100, 130, 126, 91, 13, 153, 246, 216, 219, 119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92,
    32, 136, 114, 52, 10, 138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131, 125, 173, 15, 238, 79,
    95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123, 118, 73, 2, 157, 46, 116, 9, 145, 134, 228,
    207, 212, 202, 215, 69, 229, 27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39,
    203, 233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76, 140, 36, 210,
    172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120, 51, 65, 28, 144, 254, 221, 93, 189,
    194, 139, 112, 43, 71, 109, 184, 209,
];

/// The upper bound of the input length for each value of the length byte.
static TOPVAL: [u32; 170] = [
    1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854, 1110, 1443, 1876, 2439,
    3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772, 7450, 8195, 9014, 9916, 10907, 11998,
    13198, 14518, 15970, 17567, 19323, 21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422,
    45564, 50121, 55133, 60646, 66711, 73382, 80721, 88793, 97672, 107439, 118183, 130002, 143002,
    157302, 173032, 190335, 209369, 230306, 253337, 278670, 306538, 337191, 370911, 408002, 448802,
    493682, 543050, 597356, 657091, 722800, 795081, 874589, 962048, 1058252, 1164078, 1280486,
    1408534, 1549388, 1704327, 1874759, 2062236, 2268459, 2495305, 2744836, 3019320, 3321252,
    3653374, 4018711, 4420582, 4862641, 5348905, 5883796, 6472176, 7119394, 7831333, 8614467,
    9475909, 10423501, 11465851, 12612437, 13873681, 15261050, 16787154, 18465870, 20312458,
    22343706, 24578077, 27035886, 29739474, 32713425, 35984770, 39583245, 43541573, 47895730,
    52685306, 57953837, 63749221, 70124148, 77136564, 84850228, 93335252, 102668779, 112935659,
    124229227, 136652151, 150317384, 165349128, 181884040, 200072456, 220079703, 242087671,
    266296456, 292926096, 322218735, 354440623, 389884688, 428873168, 471760495, 518936559,
    570830240, 627913311, 690704607, 759775136, 835752671, 919327967, 1011260767, 1112386880,
    1223623232, 1345985727, 1480584256, 1628642751, 1791507135, 1970657856, 2167723648, 2384496256,
    2622945920, 2885240448, 3173764736, 3491141248, 3840255616, 4224281216,
];

/// Shortest input that has a digest.
const MIN_LEN: usize = 50;
/// Buckets that count, and bytes of code (four buckets each).
const BUCKETS: usize = 128;
const CODE_SIZE: usize = BUCKETS / 4;

/// The Pearson hash of three bytes, from a salt that is already mapped.
fn mapping(salt: u8, i: u8, j: u8, k: u8) -> u8 {
    let h = V_TABLE[usize::from(salt ^ i)];
    let h = V_TABLE[usize::from(h ^ j)];
    V_TABLE[usize::from(h ^ k)]
}

/// The value of the length byte for an input of `len` bytes.
fn length_byte(len: u32) -> u8 {
    let idx = TOPVAL.partition_point(|&top| top < len);
    // `len` over the last bound does not occur for 32-bit lengths.
    idx.min(TOPVAL.len() - 1) as u8
}

/// Partitions `buf[left..=right]` around its middle value, returning the final
/// position of that value.
fn partition(buf: &mut [u32], left: usize, right: usize) -> usize {
    if left == right {
        return left;
    }
    if left + 1 == right {
        if buf[left] > buf[right] {
            buf.swap(left, right);
        }
        return left;
    }
    let pivot = (left + right) >> 1;
    let val = buf[pivot];
    buf.swap(pivot, right);
    let mut ret = left;
    for i in left..right {
        if buf[i] < val {
            buf.swap(ret, i);
            ret += 1;
        }
    }
    buf[right] = buf[ret];
    buf[ret] = val;
    ret
}

/// The three quartiles, the way yara-x finds them: the median first, noting the
/// boundaries of each partition, then each outer quartile inside the boundaries
/// noted on its side. A quartile that is not inside a noted boundary is 0.
fn quartiles(buckets: &[u32; BUCKETS]) -> (u32, u32, u32) {
    let mut copy = *buckets;
    let mut left_cuts = [0usize; BUCKETS];
    let mut right_cuts = [0usize; BUCKETS];
    let (mut spl, mut spr) = (0, 0);
    let p1 = BUCKETS / 4 - 1;
    let p2 = BUCKETS / 2 - 1;
    let p3 = BUCKETS - BUCKETS / 4 - 1;
    let end = BUCKETS - 1;

    let (mut l, mut r) = (0, end);
    let q2 = loop {
        let ret = partition(&mut copy, l, r);
        match ret.cmp(&p2) {
            std::cmp::Ordering::Greater => {
                r = ret - 1;
                right_cuts[spr] = ret;
                spr += 1;
            }
            std::cmp::Ordering::Less => {
                l = ret + 1;
                left_cuts[spl] = ret;
                spl += 1;
            }
            std::cmp::Ordering::Equal => break copy[p2],
        }
    };

    let mut q1 = 0;
    let mut l = 0;
    for &cut in &left_cuts[..spl] {
        let mut r = cut;
        if r > p1 {
            loop {
                let ret = partition(&mut copy, l, r);
                match ret.cmp(&p1) {
                    std::cmp::Ordering::Greater => r = ret - 1,
                    std::cmp::Ordering::Less => l = ret + 1,
                    std::cmp::Ordering::Equal => {
                        q1 = copy[p1];
                        break;
                    }
                }
            }
            break;
        } else if r < p1 {
            l = r;
        } else {
            q1 = copy[p1];
            break;
        }
    }

    let mut q3 = 0;
    let mut r = end;
    for &cut in &right_cuts[..spr] {
        let mut l = cut;
        if l < p3 {
            loop {
                let ret = partition(&mut copy, l, r);
                match ret.cmp(&p3) {
                    std::cmp::Ordering::Greater => r = ret - 1,
                    std::cmp::Ordering::Less => l = ret + 1,
                    std::cmp::Ordering::Equal => {
                        q3 = copy[p3];
                        break;
                    }
                }
            }
            break;
        } else if l > p3 {
            r = l;
        } else {
            q3 = copy[p3];
            break;
        }
    }
    (q1, q2, q3)
}

/// The digest of `data` as yara-x gives it, uppercase hex with the `T1`
/// prefix; `None` when the input is shorter than 50 bytes or `q3` is 0.
pub(crate) fn digest(data: &[u8]) -> Option<String> {
    if data.len() < MIN_LEN {
        return None;
    }
    // The table has 256 slots and only the first 128 are used.
    let mut buckets = [0u32; 256];
    let mut checksum = 0u8;
    for window in data.windows(5) {
        // `window[4]` is the newest byte, `window[0]` the oldest.
        let (b0, b1, b2, b3, b4) = (window[4], window[3], window[2], window[1], window[0]);
        checksum = mapping(1, b0, b1, checksum);
        for (salt, x, y, z) in [
            (49, b0, b1, b2),
            (12, b0, b1, b3),
            (84, b0, b1, b4),
            (178, b0, b2, b3),
            (166, b0, b2, b4),
            (230, b0, b3, b4),
        ] {
            buckets[usize::from(mapping(salt, x, y, z))] += 1;
        }
    }
    let mut counted = [0u32; BUCKETS];
    counted.copy_from_slice(&buckets[..BUCKETS]);
    let (q1, q2, q3) = quartiles(&counted);
    if q3 == 0 {
        return None;
    }

    let mut code = [0u8; CODE_SIZE];
    for (c, four) in code.iter_mut().zip(counted.chunks(4)) {
        *c = four.iter().rev().fold(0u8, |h, &k| {
            let bits = if q3 < k {
                3
            } else if q2 < k {
                2
            } else {
                u8::from(q1 < k)
            };
            bits | h << 2
        });
    }
    let ratio = |q: u32| ((((u64::from(q) * 100) as f32) / (q3 as f32)) as u32 % 16) as u8;
    let swap = |b: u8| b.rotate_left(4);

    let mut out = String::with_capacity(2 + 2 * (3 + CODE_SIZE));
    out.push_str("T1");
    let mut hex = |b: u8| out.push_str(&format!("{b:02X}"));
    hex(swap(checksum));
    hex(swap(length_byte(data.len() as u32)));
    hex(ratio(q1) << 4 | ratio(q2));
    for &c in code.iter().rev() {
        hex(c);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::digest;

    // The expected digests are those of `yr` 1.23.0 on the same bytes.

    #[test]
    fn a_digest_where_every_quartile_is_found() {
        let names = "isl_options_set_schedule_separate_components,isl_poly_neginfty,\
                     menu_driver,sd_varlink_server_listen_fd";
        assert_eq!(
            digest(names.as_bytes()).as_deref(),
            Some("T1C9B012D72504440F8EC2A1EFC9336996B39542C09546914ED171A4C78000C468648841")
        );
    }

    #[test]
    fn a_sparse_input_has_a_digest_from_50_bytes() {
        let names = "scipy_sf_error_get_action,scipy_sf_error_set_action";
        assert_eq!(names.len(), 51);
        assert_eq!(
            digest(names.as_bytes()).as_deref(),
            Some("T14B90000028A8B8E3800A08200832A22200A382C80AB880082C2080A00A300CFAE22280")
        );
        // One byte short of the minimum, and the same with one more.
        let short = "zikghg_djprtheruvqaia_pfz_gq_mfkkdcryirpghgccgwro";
        assert_eq!(short.len(), 49);
        assert_eq!(digest(short.as_bytes()), None);
        assert_eq!(
            digest(format!("{short}x").as_bytes()).as_deref(),
            Some("T13C900258144299E0AC1C155292581528E05984C84265901501C80375111349760A5217")
        );
    }

    const LONG: &str = "audit_log_user_command,blkid_dev_iterate_end,blkid_get_dev,\
        g_list_store_get_type,gcry_strdup,glframeterminatorgremedy,\
        glnvencinteropfunctionnvx,isl_map_apply_domain,isl_obj_val_vtable,\
        isl_sched_node_update_vmap,isl_space_set_tuple_name,krb5_kt_remove_entry,localtime,\
        nettle_sha384_init,nettle_sha3_128_shake,ntdelayexecution,panel_getselectedindex,\
        set_field_init,ss_perror";

    /// The first quartile is not found for this input, as in yara-x: its ratio
    /// in the digest is 0 where the reference implementation's is 4.
    #[test]
    fn the_first_quartile_can_stay_zero() {
        assert_eq!(
            digest(LONG.as_bytes()).as_deref(),
            Some("T18FE001555569A76D59E96D757D5D5757555D9596E55595D5FE59559DA55569EE55D7DD")
        );
    }

    /// The third quartile is not found for this input: no digest, though the
    /// input is long enough.
    #[test]
    fn the_third_quartile_can_stay_zero() {
        let names = "acc_present_or_copyin,glstencilopseparate,isl_map_fixed_power,\
                     pr_gethostbyname";
        assert_eq!(names.len(), 78);
        assert_eq!(digest(names.as_bytes()), None);
    }
}
