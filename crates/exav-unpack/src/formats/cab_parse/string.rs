use std::io::{self, Read};

use byteorder::ReadBytesExt;

use crate::formats::cab_parse::consts;

pub(crate) fn read_null_terminated_string<R: Read>(
    reader: &mut R,
    _is_utf8: bool,
) -> io::Result<String> {
    let mut bytes = Vec::<u8>::with_capacity(consts::MAX_STRING_SIZE);
    loop {
        let byte = reader.read_u8()?;
        if byte == 0 {
            break;
        } else if bytes.len() == consts::MAX_STRING_SIZE {
            invalid_data!(
                "String longer than maximum of {} bytes",
                consts::MAX_STRING_SIZE
            );
        }
        bytes.push(byte);
    }
    Ok(String::from_utf8_lossy(&bytes).to_string())
}
