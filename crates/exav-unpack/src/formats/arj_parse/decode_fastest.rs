use bitstream_io::{BigEndian, BitRead, BitReader};

pub fn decode_val(r: &mut BitReader<&[u8], BigEndian>, from: u32, to: u32) -> Option<u16> {
    let mut res = 0;
    let mut add = 0;
    let mut exp = 1 << from;
    let mut bit = from;
    while bit < to {
        res = r.read::<1, u16>().ok()?;
        if res == 0 {
            break;
        }
        add += exp;
        exp <<= 1;
        bit += 1;
    }
    if bit != 0 {
        res = r.read_var::<u16>(bit).ok()?;
    }
    res += add;
    Some(res)
}

const THRESHOLD: usize = 3;

pub fn decode_fastest(data: &[u8], original_size: usize) -> Option<Vec<u8>> {
    let mut res = Vec::with_capacity(original_size);
    let mut r = BitReader::endian(data, BigEndian);
    while res.len() < original_size {
        let len = decode_val(&mut r, 0, 7)?;
        if len == 0 {
            let next_char = r.read::<8, u8>().ok()?;
            res.push(next_char);
        } else {
            let rep_count = len as usize + THRESHOLD - 1;
            let back_ptr = decode_val(&mut r, 9, 13)? as usize;
            if back_ptr > res.len() {
                return None;
            }
            let start = res.len() - 1 - back_ptr;
            for i in start..start + rep_count {
                let ch = res[i];
                res.push(ch);
            }
        }
    }
    Some(res)
}
