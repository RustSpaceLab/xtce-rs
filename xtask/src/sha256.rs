//! SHA-256 (FIPS 180-4).
//!
//! Implemented here rather than pulled in as a dependency: the golden files are digested by
//! Python's `hashlib`, so this side needs to agree with a standard, and ~90 lines of a fully
//! specified algorithm with the NIST vectors as tests is a smaller commitment than another
//! crate in the tree. `CONTRIBUTING.md` keeps the dependency list short on purpose.

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Streaming SHA-256 hasher.
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// A fresh hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: INITIAL,
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    /// Feeds more data.
    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);

        if self.buffered > 0 {
            let want = 64 - self.buffered;
            let take = want.min(data.len());
            if let (Some(dst), Some(src)) = (
                self.buffer.get_mut(self.buffered..self.buffered + take),
                data.get(..take),
            ) {
                dst.copy_from_slice(src);
            }
            self.buffered += take;
            data = data.get(take..).unwrap_or_default();
            if self.buffered < 64 {
                // The input ran out before the block did. Returning here matters: falling
                // through would overwrite `buffered` with the (empty) remainder below and
                // silently drop everything held in the buffer.
                return;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }

        let mut chunks = data.chunks_exact(64);
        for chunk in &mut chunks {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            self.compress(&block);
        }

        let rest = chunks.remainder();
        if let Some(dst) = self.buffer.get_mut(..rest.len()) {
            dst.copy_from_slice(rest);
        }
        self.buffered = rest.len();
    }

    /// Finishes and returns the 32-byte digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.length.wrapping_mul(8);

        // Pad with 0x80 then zeros until 56 bytes mod 64, then the length as 64 big-endian
        // bits.
        self.update_raw(&[0x80]);
        while self.buffered != 56 {
            self.update_raw(&[0x00]);
        }
        self.update_raw(&bit_length.to_be_bytes());

        let mut out = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            if let Some(slot) = out.get_mut(index * 4..index * 4 + 4) {
                slot.copy_from_slice(&word.to_be_bytes());
            }
        }
        out
    }

    /// Like [`Self::update`] but does not count toward the message length; used for padding.
    fn update_raw(&mut self, data: &[u8]) {
        let length = self.length;
        self.update(data);
        self.length = length;
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (index, slot) in w.iter_mut().take(16).enumerate() {
            let mut word = [0u8; 4];
            if let Some(src) = block.get(index * 4..index * 4 + 4) {
                word.copy_from_slice(src);
            }
            *slot = u32::from_be_bytes(word);
        }
        for index in 16..64 {
            let a = w.get(index - 15).copied().unwrap_or(0);
            let b = w.get(index - 2).copied().unwrap_or(0);
            let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
            let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
            let value = w
                .get(index - 16)
                .copied()
                .unwrap_or(0)
                .wrapping_add(s0)
                .wrapping_add(w.get(index - 7).copied().unwrap_or(0))
                .wrapping_add(s1);
            if let Some(slot) = w.get_mut(index) {
                *slot = value;
            }
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K.get(index).copied().unwrap_or(0))
                .wrapping_add(w.get(index).copied().unwrap_or(0));
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (slot, value) in self
            .state
            .iter_mut()
            .zip([a, b, c, d, e, f, g, h])
        {
            *slot = slot.wrapping_add(value);
        }
    }
}

/// The digest of `data` as lowercase hex.
#[cfg(test)]
#[must_use]
pub fn hex_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    to_hex(&hasher.finalize())
}

/// Formats a byte slice as lowercase hex.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_vectors() {
        assert_eq!(
            hex_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex_digest(&[b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
        let one_shot = hex_digest(&data);

        for chunk_size in [1usize, 7, 63, 64, 65, 1000] {
            let mut hasher = Sha256::new();
            for chunk in data.chunks(chunk_size) {
                hasher.update(chunk);
            }
            assert_eq!(
                to_hex(&hasher.finalize()),
                one_shot,
                "chunk size {chunk_size}"
            );
        }
    }

    #[test]
    fn block_boundaries() {
        // Lengths straddling the 55/56/64-byte padding boundaries.
        for len in [54usize, 55, 56, 57, 63, 64, 65, 119, 120] {
            let data = vec![0x5Au8; len];
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let streamed = to_hex(&hasher.finalize());
            assert_eq!(streamed, hex_digest(&data), "length {len}");
            assert_eq!(streamed.len(), 64);
        }
    }
}
