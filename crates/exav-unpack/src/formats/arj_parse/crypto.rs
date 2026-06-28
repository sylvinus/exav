#![allow(dead_code)]
use super::encryption::ArjEncryption;

const SBOX: [[u8; 16]; 8] = [
    [
        0x01, 0x0F, 0x0D, 0x00, 0x05, 0x07, 0x0A, 0x04, 0x09, 0x02, 0x03, 0x0E, 0x06, 0x0B, 0x08,
        0x0C,
    ],
    [
        0x0D, 0x0B, 0x04, 0x01, 0x03, 0x0F, 0x05, 0x09, 0x00, 0x0A, 0x0E, 0x07, 0x06, 0x08, 0x02,
        0x0C,
    ],
    [
        0x04, 0x0B, 0x0A, 0x00, 0x07, 0x02, 0x01, 0x0D, 0x03, 0x06, 0x08, 0x05, 0x09, 0x0C, 0x0F,
        0x0E,
    ],
    [
        0x06, 0x0C, 0x07, 0x01, 0x05, 0x0F, 0x0D, 0x08, 0x04, 0x0A, 0x09, 0x0E, 0x00, 0x03, 0x0B,
        0x02,
    ],
    [
        0x07, 0x0D, 0x0A, 0x01, 0x00, 0x08, 0x09, 0x0F, 0x0E, 0x04, 0x06, 0x0C, 0x0B, 0x02, 0x05,
        0x03,
    ],
    [
        0x05, 0x08, 0x01, 0x0D, 0x0A, 0x03, 0x04, 0x02, 0x0E, 0x0F, 0x0C, 0x07, 0x06, 0x00, 0x09,
        0x0B,
    ],
    [
        0x0E, 0x0B, 0x04, 0x0C, 0x06, 0x0D, 0x0F, 0x0A, 0x02, 0x03, 0x08, 0x01, 0x00, 0x07, 0x05,
        0x09,
    ],
    [
        0x04, 0x0A, 0x09, 0x02, 0x0D, 0x08, 0x00, 0x0E, 0x06, 0x0B, 0x01, 0x0C, 0x07, 0x0F, 0x05,
        0x03,
    ],
];

const GOST_ROTATION: u32 = 11;
const KEY_ITERATIONS: usize = 2048;
const BOOTSTRAP_KEY: [u32; 8] = [3, 10, 6, 12, 5, 9, 0, 7];

struct SboxTable {
    table: [[u8; 256]; 4],
}

impl SboxTable {
    fn new() -> Self {
        let mut table = [[0u8; 256]; 4];
        for i in 0..256 {
            table[0][i] = (SBOX[0][i >> 4] << 4) | SBOX[1][i & 0x0F];
            table[1][i] = (SBOX[2][i >> 4] << 4) | SBOX[3][i & 0x0F];
            table[2][i] = (SBOX[4][i >> 4] << 4) | SBOX[5][i & 0x0F];
            table[3][i] = (SBOX[6][i >> 4] << 4) | SBOX[7][i & 0x0F];
        }
        SboxTable { table }
    }

    fn apply(&self, data: u32) -> u32 {
        let bytes = data.to_le_bytes();
        let s0 = self.table[3][bytes[0] as usize];
        let s1 = self.table[2][bytes[1] as usize];
        let s2 = self.table[1][bytes[2] as usize];
        let s3 = self.table[0][bytes[3] as usize];

        let p1 = ((s3 as u16) << 8) | (s2 as u16);
        let p2 = ((s1 as u16) << 8) | (s0 as u16);

        let hi = (p1 << GOST_ROTATION as u16) | (p2 >> (16 - GOST_ROTATION as u16));
        let lo = (p2 << GOST_ROTATION as u16) | (p1 >> (16 - GOST_ROTATION as u16));

        ((hi as u32) << 16) | (lo as u32)
    }
}

pub struct Gost40 {
    sbox: SboxTable,
    subkeys: [u32; 8],
    feedback: [u32; 2],
    byte_offset: usize,
}

impl Gost40 {
    pub fn new(password: &str, modifier: u8, file_time: u32) -> Self {
        let sbox = SboxTable::new();
        let initial_key = Self::build_key_from_password(password);
        let iv: [u32; 2] = [file_time, modifier as i8 as i32 as u32];

        let mut cipher = Gost40 {
            sbox,
            subkeys: initial_key,
            feedback: [0, 0],
            byte_offset: 0,
        };

        cipher.derive_key(&iv);
        cipher.feedback = cipher.encrypt_block(&iv);
        cipher
    }

    fn build_key_from_password(password: &str) -> [u32; 8] {
        let mut key = [0u32; 8];
        let pwd_bytes = password.as_bytes();
        if pwd_bytes.is_empty() {
            return key;
        }

        let mut pwd_idx = 0;
        for round in 0..64 {
            let byte_idx = round % 5;
            let word = &mut key[byte_idx];
            let bytes = word.to_le_bytes();
            let mut new_bytes = bytes;
            new_bytes[0] = new_bytes[0].wrapping_add(pwd_bytes[pwd_idx] << (round % 7));
            *word = u32::from_le_bytes(new_bytes);
            pwd_idx += 1;
            if pwd_idx >= pwd_bytes.len() {
                pwd_idx = 0;
            }
        }

        key
    }

    fn encrypt_block(&self, block: &[u32; 2]) -> [u32; 2] {
        let mut left = block[0];
        let mut right = block[1];

        for _ in 0..3 {
            for i in 0..8 {
                let round_output = self.sbox.apply(left.wrapping_add(self.subkeys[i]));
                let temp = right ^ round_output;
                right = left;
                left = temp;
            }
        }

        for i in (0..8).rev() {
            let round_output = self.sbox.apply(left.wrapping_add(self.subkeys[i]));
            let temp = right ^ round_output;
            right = left;
            left = temp;
        }

        [right, left]
    }

    fn derive_key(&mut self, iv: &[u32; 2]) {
        let mut work_key = self.subkeys;

        let saved_keys = self.subkeys;
        self.subkeys = BOOTSTRAP_KEY;
        self.feedback = self.encrypt_block(iv);
        self.subkeys = saved_keys;

        for _ in 0..KEY_ITERATIONS {
            let mut work_bytes = Self::u32s_to_bytes(&work_key);
            self.cfb_encrypt(&mut work_bytes);
            work_key = Self::bytes_to_u32s(&work_bytes);
        }

        self.subkeys = work_key;
    }

    fn u32s_to_bytes(words: &[u32; 8]) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, word) in words.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn bytes_to_u32s(bytes: &[u8; 32]) -> [u32; 8] {
        let mut words = [0u32; 8];
        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        words
    }

    fn cfb_encrypt(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_mut(8) {
            self.feedback = self.encrypt_block(&self.feedback);
            let fb_bytes = Self::u32s_to_bytes_le(self.feedback);

            for (i, byte) in chunk.iter_mut().enumerate() {
                let encrypted = *byte ^ fb_bytes[i];
                *byte = encrypted;
            }
            self.feedback = Self::bytes_to_u32s_le(chunk);
        }
    }

    fn u32s_to_bytes_le(words: [u32; 2]) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&words[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&words[1].to_le_bytes());
        bytes
    }

    fn bytes_to_u32s_le(bytes: &[u8]) -> [u32; 2] {
        [
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ]
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        let len = data.len();

        if len % 8 == 0 && self.byte_offset == 0 {
            for chunk in data.chunks_mut(8) {
                self.feedback = self.encrypt_block(&self.feedback);

                let ct_lo = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let ct_hi = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);

                let pt_lo = ct_lo ^ self.feedback[0];
                let pt_hi = ct_hi ^ self.feedback[1];

                self.feedback = [ct_lo, ct_hi];

                chunk[0..4].copy_from_slice(&pt_lo.to_le_bytes());
                chunk[4..8].copy_from_slice(&pt_hi.to_le_bytes());
            }
        } else {
            for byte in data.iter_mut() {
                if self.byte_offset == 0 {
                    self.feedback = self.encrypt_block(&self.feedback);
                }

                let mut fb_bytes = Self::u32s_to_bytes_le(self.feedback);
                let ciphertext = *byte;
                *byte = ciphertext ^ fb_bytes[self.byte_offset];
                fb_bytes[self.byte_offset] = ciphertext;
                self.feedback = Self::bytes_to_u32s_le(&fb_bytes);

                self.byte_offset = (self.byte_offset + 1) % 8;
            }
        }
    }
}

pub fn garble_decrypt(data: &mut [u8], password: &str, modifier: u8) {
    if password.is_empty() {
        return;
    }

    let pwd_bytes = password.as_bytes();
    let mut pwd_idx = 0;

    for byte in data.iter_mut() {
        *byte ^= modifier.wrapping_add(pwd_bytes[pwd_idx]);
        pwd_idx += 1;
        if pwd_idx >= pwd_bytes.len() {
            pwd_idx = 0;
        }
    }
}

pub fn decrypt_arj_data(
    data: &mut [u8],
    encryption_type: Option<ArjEncryption>,
    password: &str,
    modifier: u8,
    file_time: u32,
) {
    match encryption_type {
        None => {}
        Some(ArjEncryption::Garble) => {
            garble_decrypt(data, password, modifier);
        }
        Some(ArjEncryption::Gost40) => {
            let mut gost = Gost40::new(password, modifier, file_time);
            gost.decrypt(data);
        }
        Some(ArjEncryption::Gost256) | Some(ArjEncryption::Unknown) => {}
    }
}
