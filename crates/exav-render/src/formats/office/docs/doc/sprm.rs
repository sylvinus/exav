//! Property modifiers ([MS-DOC] 2.6): a 16-bit opcode and an operand whose
//! size the opcode's top bits give.

/// One modifier: its opcode and operand bytes.
#[derive(Clone, Copy, Debug)]
pub struct Prl<'a> {
    pub op: u16,
    pub val: &'a [u8],
}

pub const SGC_PARA: u16 = 1;
pub const SGC_CHAR: u16 = 2;
pub const SGC_TABLE: u16 = 5;

impl<'a> Prl<'a> {
    /// 1 paragraph, 2 character, 3 picture, 4 section, 5 table.
    pub fn sgc(&self) -> u16 {
        (self.op >> 10) & 7
    }

    pub fn u8(&self) -> u8 {
        self.val.first().copied().unwrap_or(0)
    }

    pub fn u16(&self) -> u16 {
        match self.val {
            [a, b, ..] => u16::from_le_bytes([*a, *b]),
            [a] => u16::from(*a),
            _ => 0,
        }
    }

    pub fn i16(&self) -> i16 {
        self.u16() as i16
    }

    pub fn u32(&self) -> u32 {
        match self.val {
            [a, b, c, d, ..] => u32::from_le_bytes([*a, *b, *c, *d]),
            _ => 0,
        }
    }

    pub fn i32(&self) -> i32 {
        self.u32() as i32
    }

    /// The operand after a length prefix (one byte; two for sprmTDefTable).
    pub fn var(&self) -> &'a [u8] {
        let skip = if self.op == 0xD608 { 2 } else { 1 };
        self.val.get(skip..).unwrap_or(&[])
    }
}

/// The modifiers of a grpprl. A truncated last one ends the list.
pub fn parse(g: &[u8]) -> Vec<Prl<'_>> {
    let mut out = vec![];
    let mut p = 0usize;
    while p + 2 <= g.len() && out.len() < 4096 {
        let op = u16::from_le_bytes([g[p], g[p + 1]]);
        p += 2;
        let rest = &g[p..];
        let n = match op >> 13 {
            0 | 1 => 1,
            2 | 4 | 5 => 2,
            3 => 4,
            7 => 3,
            _ => {
                if op == 0xD608 {
                    match rest {
                        [a, b, ..] => usize::from(u16::from_le_bytes([*a, *b])) + 1,
                        _ => break,
                    }
                } else if op == 0xC615 && rest.first() == Some(&255) {
                    // The size is that of the deleted and added tab lists.
                    let del = usize::from(rest.get(1).copied().unwrap_or(0));
                    let add_at = 2 + 4 * del;
                    let add = usize::from(rest.get(add_at).copied().unwrap_or(0));
                    add_at + 1 + 3 * add
                } else {
                    match rest.first() {
                        Some(&c) => usize::from(c) + 1,
                        None => break,
                    }
                }
            }
        };
        if n > rest.len() {
            // Operand cut short: keep what is there for fixed sizes only.
            break;
        }
        out.push(Prl {
            op,
            val: &rest[..n],
        });
        p += n;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operand_sizes_follow_the_opcode() {
        // sprmCFBold on, sprmCHps 24, sprmCCv, sprmPChgTabsPapx with 3 bytes.
        let g = [
            0x35, 0x08, 1, 0x43, 0x4A, 24, 0, 0x70, 0x68, 1, 2, 3, 0, 0x0D, 0xC6, 3, 9, 9, 9,
        ];
        let p = parse(&g);
        assert_eq!(p.len(), 4);
        assert_eq!((p[0].op, p[0].u8()), (0x0835, 1));
        assert_eq!(p[1].u16(), 24);
        assert_eq!(p[2].val, &[1, 2, 3, 0]);
        assert_eq!(p[3].var(), &[9, 9, 9]);
        assert_eq!(p[1].sgc(), SGC_CHAR);
    }

    #[test]
    fn table_definition_has_a_two_byte_size() {
        // cb = 5: four more bytes after the size field.
        let g = [0x08, 0xD6, 5, 0, 1, 2, 3, 4, 0x35, 0x08, 0];
        let p = parse(&g);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].val.len(), 6);
        assert_eq!(p[0].var(), &[1, 2, 3, 4]);
        assert_eq!(p[1].op, 0x0835);
        // The group of an opcode: table, section, paragraph.
        assert_eq!(p[0].sgc(), SGC_TABLE);
        assert_eq!(parse(&[0x09, 0x30, 1])[0].sgc(), 4);
        assert_eq!(parse(&[0x03, 0x24, 1])[0].sgc(), SGC_PARA);
    }

    #[test]
    fn truncated_operands_end_the_list() {
        assert_eq!(parse(&[0x43, 0x4A, 24]).len(), 0);
        assert_eq!(parse(&[0x0D, 0xC6, 9, 1]).len(), 0);
    }
}
