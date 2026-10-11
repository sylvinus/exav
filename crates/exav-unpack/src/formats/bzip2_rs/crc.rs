pub struct Hasher {
    // CRC32B hasher
    val: crc32fast::Hasher,
    // reversed bits
    bytes: [u8; 512],
}

impl Hasher {
    pub fn new() -> Self {
        Self {
            val: crc32fast::Hasher::new(),
            bytes: [0; 512],
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let len = bytes.len().min(self.bytes.len());
            self.bytes[..len].copy_from_slice(&bytes[..len]);
            bytes = &bytes[len..];

            for byte in self.bytes.iter_mut() {
                *byte = byte.reverse_bits();
            }
            self.val.update(&self.bytes[..len]);
        }
    }

    pub fn finalyze(&self) -> u32 {
        let reversed = self.val.clone().finalize();
        // CRC32B to CRC32
        reversed.reverse_bits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc() {
        let mut hasher = Hasher::new();
        hasher.update(b"123456789");
        assert_eq!(hasher.finalyze(), 0xFC891918);
    }
}
