//! The key state of PKWARE's traditional ZIP encryption (APPNOTE.TXT 6.1),
//! shared by the member decryption and the ZIP writer.

/// The three 32-bit keys of the cipher.
#[derive(Clone, Copy)]
pub(crate) struct ZipCryptoKeys {
    key0: u32,
    key1: u32,
    key2: u32,
}

impl ZipCryptoKeys {
    pub(crate) fn new(password: &[u8]) -> Self {
        let mut k = ZipCryptoKeys {
            key0: 0x1234_5678,
            key1: 0x2345_6789,
            key2: 0x3456_7890,
        };
        for &b in password {
            k.update(b);
        }
        k
    }

    /// Takes in one plaintext byte.
    pub(crate) fn update(&mut self, byte: u8) {
        self.key0 = crc32(self.key0, byte);
        self.key1 = self
            .key1
            .wrapping_add(self.key0 & 0xff)
            .wrapping_mul(0x0808_8405)
            .wrapping_add(1);
        let t = (self.key1 >> 24) as u8;
        self.key2 = crc32(self.key2, t);
    }

    /// The next byte of the key stream.
    pub(crate) fn stream_byte(&self) -> u8 {
        let temp = (self.key2 | 2) as u16;
        ((temp.wrapping_mul(temp ^ 1)) >> 8) as u8
    }
}

/// One step of the CRC-32 used by ZipCrypto (reflected, poly 0xEDB88320).
pub(crate) fn crc32(crc: u32, byte: u8) -> u32 {
    let mut c = (crc ^ byte as u32) & 0xff;
    for _ in 0..8 {
        c = if c & 1 != 0 {
            (c >> 1) ^ 0xEDB8_8320
        } else {
            c >> 1
        };
    }
    (crc >> 8) ^ c
}
