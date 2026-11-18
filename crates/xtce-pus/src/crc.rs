//! ECSS-E-ST-70-41C Annex B / CCSDS 131.0-B CRC-16-CCITT packet error control.
//!
//! Generator polynomial: $G(x) = x^{16} + x^{12} + x^5 + 1$ (`0x1021`), initial syndrome
//! `0xFFFF`, no input reflection, no final XOR. Over the ASCII string `"123456789"` this
//! produces `0x29B1`, and computing the syndrome over a frame followed by its two big-endian
//! CRC octets yields `0x0000`.

const POLY: u16 = 0x1021;

const fn build_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ POLY;
            } else {
                crc <<= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Precomputed 256-entry lookup table for CRC-16-CCITT (`0x1021`).
const TABLE: [u16; 256] = build_table();

/// Computes the 16-bit ECSS PUS Packet Error Control (CRC-16-CCITT) over `bytes`.
#[must_use]
pub const fn crc16_ccitt(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    let mut idx = 0usize;
    while idx < bytes.len() {
        let lookup = ((crc >> 8) as u8) ^ bytes[idx];
        crc = (crc << 8) ^ TABLE[lookup as usize];
        idx += 1;
    }
    crc
}

/// Returns `true` if `frame` ends with a valid 2-byte big-endian CRC-16-CCITT syndrome.
#[must_use]
pub const fn verify_crc16_ccitt(frame: &[u8]) -> bool {
    if frame.len() < 2 {
        return false;
    }
    crc16_ccitt(frame) == 0
}

#[cfg(test)]
mod tests {
    use super::{crc16_ccitt, verify_crc16_ccitt};

    #[test]
    fn matches_ecss_annex_b_standard_check_value() {
        assert_eq!(crc16_ccitt(b""), 0xFFFF);
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
    }

    #[test]
    fn appended_big_endian_syndrome_verifies_to_zero_residue() {
        let mut frame = [b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', 0, 0];
        let crc = crc16_ccitt(&frame[..9]);
        let [hi, lo] = crc.to_be_bytes();
        frame[9] = hi;
        frame[10] = lo;

        assert!(verify_crc16_ccitt(&frame));
        frame[4] ^= 0x01;
        assert!(!verify_crc16_ccitt(&frame));
    }

    #[test]
    fn rejects_frames_shorter_than_two_bytes() {
        assert!(!verify_crc16_ccitt(&[]));
        assert!(!verify_crc16_ccitt(&[0xFF]));
    }
}
