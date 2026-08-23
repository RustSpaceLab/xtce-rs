//! MSB-first bit cursor over a byte slice.
//!
//! CCSDS packets are bit-packed big-endian: a field starts at an arbitrary bit offset and
//! runs most-significant bit first, straddling byte boundaries freely. Everything the
//! decoder reads goes through [`BitCursor`].
//!
//! # The 9-byte case
//!
//! A 64-bit field at a non-zero bit offset spans **nine** bytes. The obvious implementation
//! — load eight bytes and shift — silently truncates it. Every read here goes through a
//! `u128` accumulator, which covers the widest possible span (7 offset bits + 64 width) with
//! room to spare. The property tests deliberately generate that case.
//!
//! # No panics
//!
//! Every out-of-range read returns [`BitError`]. A corrupt or hostile packet must never
//! bring down a decoder that is processing a live downlink.

use std::borrow::Cow;

/// Reading past the end of the data, or asking for more bits than fit in the result.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum BitError {
    /// The requested field extends past the end of the buffer.
    #[error("read of {width} bit(s) at bit {position} exceeds the {available}-bit buffer")]
    OutOfBounds {
        /// Bit offset the read started at.
        position: usize,
        /// Width requested, in bits.
        width: usize,
        /// Total size of the buffer, in bits.
        available: usize,
    },

    /// More than 64 bits were requested as an integer.
    #[error("integer read of {width} bits exceeds the 64-bit maximum")]
    TooWide {
        /// Width requested, in bits.
        width: u32,
    },
}

/// A big-endian, MSB-first bit reader.
#[derive(Clone, Copy, Debug)]
pub struct BitCursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> BitCursor<'a> {
    /// Creates a cursor at bit 0 of `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// The underlying buffer.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Current position, in bits from the start of the buffer.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Total size of the buffer, in bits.
    #[must_use]
    pub const fn len_bits(&self) -> usize {
        self.data.len() * 8
    }

    /// Bits between the cursor and the end of the buffer.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.len_bits().saturating_sub(self.position)
    }

    /// Moves the cursor to an absolute bit position.
    ///
    /// Positions past the end are allowed; the failure surfaces on the next read. XTCE
    /// `LocationInContainerInBits` can legitimately seek forward past unparsed padding.
    pub const fn seek(&mut self, position: usize) {
        self.position = position;
    }

    /// Advances the cursor without reading.
    ///
    /// # Errors
    ///
    /// Returns [`BitError::OutOfBounds`] if the skip would pass the end of the buffer.
    pub fn skip(&mut self, bits: usize) -> Result<(), BitError> {
        let end = self.position.saturating_add(bits);
        if end > self.len_bits() {
            return Err(BitError::OutOfBounds {
                position: self.position,
                width: bits,
                available: self.len_bits(),
            });
        }
        self.position = end;
        Ok(())
    }

    /// Reads `width` bits as an unsigned integer and advances the cursor.
    ///
    /// Width 0 yields 0, matching the reference implementation's treatment of an empty
    /// field. Widths above 64 are rejected.
    ///
    /// # Errors
    ///
    /// [`BitError::TooWide`] above 64 bits, [`BitError::OutOfBounds`] past the end.
    #[inline]
    pub fn read_uint(&mut self, width: u32) -> Result<u64, BitError> {
        let value = self.peek_uint(self.position, width)?;
        self.position += width as usize;
        Ok(value)
    }

    /// Reads `width` bits as an unsigned integer at an absolute position, without moving
    /// the cursor.
    ///
    /// # Errors
    ///
    /// [`BitError::TooWide`] above 64 bits, [`BitError::OutOfBounds`] past the end.
    #[inline]
    pub fn peek_uint(&self, position: usize, width: u32) -> Result<u64, BitError> {
        if width > 64 {
            return Err(BitError::TooWide { width });
        }
        if width == 0 {
            return Ok(0);
        }
        let end = position.saturating_add(width as usize);
        if end > self.len_bits() {
            return Err(BitError::OutOfBounds {
                position,
                width: width as usize,
                available: self.len_bits(),
            });
        }

        let byte = position / 8;
        let bit_in_byte = (position % 8) as u32;

        // A 16-byte window always covers the widest field (7 offset bits + 64 width = 71),
        // so one `u128` load and one shift handles every case uniformly. Near the end of
        // the buffer the window is assembled in a zeroed stack array instead; the padding
        // bits are never part of the result because the bounds check above already
        // guaranteed the field itself is in range.
        let window = if let Some(slice) = self.data.get(byte..byte + 16) {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(slice);
            u128::from_be_bytes(buf)
        } else {
            let mut buf = [0u8; 16];
            let tail = self.data.get(byte..).unwrap_or_default();
            let take = tail.len().min(16);
            if let (Some(dst), Some(src)) = (buf.get_mut(..take), tail.get(..take)) {
                dst.copy_from_slice(src);
            }
            u128::from_be_bytes(buf)
        };

        let shift = 128 - u32::from(bit_in_byte as u8) - width;
        let mask = if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        Ok(((window >> shift) as u64) & mask)
    }

    /// Reads `width` bits as an unsigned integer without advancing the cursor.
    ///
    /// # Errors
    ///
    /// As [`Self::peek_uint`].
    #[inline]
    pub fn peek_next(&self, width: u32) -> Result<u64, BitError> {
        self.peek_uint(self.position, width)
    }

    /// Reads `width` bits as bytes, right-aligned in the result.
    ///
    /// The result is `ceil(width / 8)` bytes holding the field as a big-endian integer, so a
    /// 12-bit field becomes two bytes with four leading zero bits. This is the layout the
    /// reference implementation produces for binary fields, and the layout XTCE implies by
    /// treating a binary field as an integer of that width.
    ///
    /// Byte-aligned whole-byte reads borrow from the packet; everything else allocates.
    ///
    /// # Errors
    ///
    /// [`BitError::OutOfBounds`] past the end of the buffer.
    pub fn read_bytes(&mut self, width: usize) -> Result<Cow<'a, [u8]>, BitError> {
        let out_len = width.div_ceil(8);
        let pad = out_len * 8 - width;

        if let Some(slice) = self.aligned_slice(width) {
            return Ok(Cow::Borrowed(slice));
        }

        let start = self.position;
        self.bounds_check(width)?;

        let mut out = vec![0u8; out_len];
        for (index, slot) in out.iter_mut().enumerate() {
            // Output byte `index` holds source bits `[8*index - pad, 8*index - pad + 8)`;
            // the first byte is short by `pad` bits, which stay zero.
            let (from, take) = match (index * 8).checked_sub(pad) {
                Some(offset) => (start + offset, 8),
                None => (start, 8 - pad as u32),
            };
            *slot = self.peek_uint(from, take)? as u8;
        }
        self.position = start + width;
        Ok(Cow::Owned(out))
    }

    /// Reads `width` bits as bytes, left-aligned in the result.
    ///
    /// The result is `ceil(width / 8)` bytes holding the field starting at bit 0, with any
    /// slack **at the end**. This is what a string buffer needs: characters are read from
    /// the front, so padding must not displace them.
    ///
    /// # Errors
    ///
    /// [`BitError::OutOfBounds`] past the end of the buffer.
    pub fn read_bytes_left_aligned(&mut self, width: usize) -> Result<Cow<'a, [u8]>, BitError> {
        if let Some(slice) = self.aligned_slice(width) {
            return Ok(Cow::Borrowed(slice));
        }

        let start = self.position;
        self.bounds_check(width)?;

        let out_len = width.div_ceil(8);
        let mut out = vec![0u8; out_len];
        for (index, slot) in out.iter_mut().enumerate() {
            let offset = index * 8;
            let take = u32::try_from(width - offset).unwrap_or(8).min(8);
            // Left-align the final partial byte, matching the shift the reference applies
            // to the whole buffer.
            *slot = (self.peek_uint(start + offset, take)? as u8) << (8 - take);
        }
        self.position = start + width;
        Ok(Cow::Owned(out))
    }

    /// Borrows the next `width` bits when the read is byte-aligned in both position and
    /// length, advancing the cursor. Returns `None` when a copy is required.
    fn aligned_slice(&mut self, width: usize) -> Option<&'a [u8]> {
        if self.position % 8 != 0 || width % 8 != 0 {
            return None;
        }
        let start = self.position / 8;
        let end = start.checked_add(width / 8)?;
        let slice = self.data.get(start..end)?;
        self.position += width;
        Some(slice)
    }

    fn bounds_check(&self, width: usize) -> Result<(), BitError> {
        let end = self.position.saturating_add(width);
        if end > self.len_bits() {
            return Err(BitError::OutOfBounds {
                position: self.position,
                width,
                available: self.len_bits(),
            });
        }
        Ok(())
    }
}

/// Reinterprets an unsigned field of `width` bits as a signed integer.
///
/// Sign-extends by shifting rather than by subtracting `2^width`. The subtraction form
/// overflows at width 63 — `1i64 << 63` is `i64::MIN`, so `positive - i64::MIN` wraps — which
/// release builds happen to get right and debug builds panic on, so no differential test
/// against real packets would ever have caught it. Shifting is branchless and correct for
/// every width from 1 to 64.
#[must_use]
pub fn twos_complement(value: u64, width: u32) -> i64 {
    if width == 0 || width > 64 {
        return value as i64;
    }
    let shift = 64 - width;
    ((value << shift) as i64) >> shift
}

/// Sign extension for the one case where the value can be wider than the field it came from.
///
/// After a `leastSignificantByteFirst` swap of a field whose width is not a whole number of
/// bytes, the value carries bits above `width`: a twelve-bit `0x0AB` comes back as `0xAB00`.
/// The reference does not mask those away. It tests bit `width - 1` and subtracts `2^width`
/// if it is set, leaving the high bits in place — so a twelve-bit field can report 43274.
///
/// [`twos_complement`] masks, and for every value that fits its width the two agree exactly.
/// This is a separate function rather than a change to that one because the masking form is
/// the right answer everywhere else, and because it is branchless.
///
/// Returns `None` when the reference's answer does not fit an `i64`. That needs a width
/// between 57 and 63 bits, not a whole number of bytes, whose swap widened it past `2^63` —
/// where the reference's arbitrary-precision integers can hold a number this cannot.
#[must_use]
pub fn twos_complement_unmasked(value: u64, width: u32) -> Option<i64> {
    // At 64 bits, and above, the swap cannot widen anything: the value already fills its
    // field, and the two forms coincide.
    if width == 0 || width >= 64 {
        return Some(value as i64);
    }
    if value & (1u64 << (width - 1)) == 0 {
        return i64::try_from(value).ok();
    }
    // In `i128` so that the range check is exact rather than a wrap that happens to be
    // caught. `value` is at most `2^64 - 1` and the subtrahend at most `2^63`.
    i64::try_from(i128::from(value) - (1i128 << width)).ok()
}

/// Reinterprets an unsigned field as sign-magnitude: top bit is the sign, rest the
/// magnitude.
#[must_use]
pub fn sign_magnitude(value: u64, width: u32) -> i64 {
    if width == 0 || width > 64 {
        return value as i64;
    }
    let sign_bit = 1u64 << (width - 1);
    let magnitude = (value & (sign_bit - 1)) as i64;
    if value & sign_bit == 0 {
        magnitude
    } else {
        -magnitude
    }
}

/// Reinterprets an unsigned field as ones' complement.
#[must_use]
pub fn ones_complement(value: u64, width: u32) -> i64 {
    if width == 0 || width > 64 {
        return value as i64;
    }
    let sign_bit = 1u64 << (width - 1);
    if value & sign_bit == 0 {
        value as i64
    } else {
        let mask = if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        -(((!value) & mask) as i64)
    }
}

/// Reverses the byte order of a field, for `leastSignificantByteFirst` encodings.
///
/// The field is first read MSB-first as an integer; this then reverses the
/// `ceil(width / 8)` bytes of that integer, which is what the reference implementation does
/// and what little-endian on the wire means for a byte-aligned field.
#[must_use]
pub fn swap_byte_order(value: u64, width: u32) -> u64 {
    let bytes = (width as usize).div_ceil(8);
    if bytes <= 1 {
        return value;
    }
    let mut out = 0u64;
    let mut remaining = value;
    for _ in 0..bytes {
        out = (out << 8) | (remaining & 0xFF);
        remaining >>= 8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deliberately naive reference: walk one bit at a time. Slow, obviously correct, and
    /// the oracle the property tests compare against.
    fn naive_read(data: &[u8], position: usize, width: u32) -> Option<u64> {
        if position + width as usize > data.len() * 8 {
            return None;
        }
        let mut value: u64 = 0;
        for offset in 0..width as usize {
            let bit_index = position + offset;
            let byte = *data.get(bit_index / 8)?;
            let bit = (byte >> (7 - (bit_index % 8))) & 1;
            value = (value << 1) | u64::from(bit);
        }
        Some(value)
    }

    #[test]
    fn documented_example_matches() {
        // 0b00110101 0b11001010, start at bit 2, take 9 -> 0b110101110
        let data = [0b0011_0101u8, 0b1100_1010];
        let mut cursor = BitCursor::new(&data);
        cursor.seek(2);
        assert_eq!(cursor.read_uint(9), Ok(0b1_1010_1110));
        assert_eq!(cursor.position(), 11);
    }

    #[test]
    fn sixty_four_bits_at_a_bit_offset_spans_nine_bytes() {
        // Nine bytes, so a 64-bit read starting at bit 1 needs all of them.
        let data: [u8; 9] = [0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF];
        for offset in 0..8 {
            let mut cursor = BitCursor::new(&data);
            cursor.seek(offset);
            let got = cursor.read_uint(64).expect("in range");
            let want = naive_read(&data, offset, 64).expect("in range");
            assert_eq!(got, want, "offset {offset}");
        }
    }

    #[test]
    fn reads_past_the_end_are_errors_not_panics() {
        let data = [0xAAu8; 2];
        let mut cursor = BitCursor::new(&data);
        cursor.seek(9);
        assert!(matches!(
            cursor.read_uint(8),
            Err(BitError::OutOfBounds { .. })
        ));
        assert!(matches!(
            cursor.read_uint(65),
            Err(BitError::TooWide { .. })
        ));

        let mut empty = BitCursor::new(&[]);
        assert!(matches!(
            empty.read_uint(1),
            Err(BitError::OutOfBounds { .. })
        ));
        assert_eq!(empty.read_uint(0), Ok(0));
    }

    #[test]
    fn aligned_byte_reads_borrow() {
        let data = [1u8, 2, 3, 4];
        let mut cursor = BitCursor::new(&data);
        let bytes = cursor.read_bytes(16).expect("in range");
        assert!(matches!(bytes, Cow::Borrowed(_)));
        assert_eq!(&*bytes, &[1, 2]);
        assert_eq!(cursor.position(), 16);
    }

    #[test]
    fn unaligned_bytes_are_right_aligned() {
        // 12 bits starting at bit 4 of 0xAB 0xCD -> 0xBCD -> [0x0B, 0xCD]
        let data = [0xABu8, 0xCD];
        let mut cursor = BitCursor::new(&data);
        cursor.seek(4);
        let bytes = cursor.read_bytes(12).expect("in range");
        assert_eq!(&*bytes, &[0x0B, 0xCD]);
    }

    #[test]
    fn left_aligned_bytes_pad_on_the_right() {
        // Same 12 bits, left-aligned -> [0xBC, 0xD0]
        let data = [0xABu8, 0xCD];
        let mut cursor = BitCursor::new(&data);
        cursor.seek(4);
        let bytes = cursor.read_bytes_left_aligned(12).expect("in range");
        assert_eq!(&*bytes, &[0xBC, 0xD0]);
    }

    /// Sign extension written the slow, obvious way, as an oracle.
    fn naive_twos_complement(value: u64, width: u32) -> i128 {
        let modulus = 1i128 << width;
        let value = i128::from(value) % modulus;
        if value >= modulus / 2 {
            value - modulus
        } else {
            value
        }
    }

    #[test]
    fn signed_interpretations() {
        assert_eq!(twos_complement(0xFF, 8), -1);
        assert_eq!(twos_complement(0x80, 8), -128);
        assert_eq!(twos_complement(0x7F, 8), 127);
        assert_eq!(twos_complement(u64::MAX, 64), -1);
        // Width 63 is where subtracting 2^width overflows; nothing else reaches it.
        assert_eq!(twos_complement(1 << 62, 63), -(1i64 << 62));
        assert_eq!(twos_complement((1 << 62) - 1, 63), (1i64 << 62) - 1);
        assert_eq!(twos_complement(u64::MAX >> 1, 63), -1);
        assert_eq!(twos_complement(1, 1), -1);
        assert_eq!(twos_complement(0, 1), 0);

        assert_eq!(sign_magnitude(0b1000_0001, 8), -1);
        assert_eq!(sign_magnitude(0b0000_0001, 8), 1);

        assert_eq!(ones_complement(0b1111_1110, 8), -1);
        assert_eq!(ones_complement(0b0000_0001, 8), 1);
    }

    #[test]
    fn byte_order_swap() {
        assert_eq!(swap_byte_order(0x1234, 16), 0x3412);
        assert_eq!(swap_byte_order(0x12345678, 32), 0x78563412);
        assert_eq!(swap_byte_order(0x12, 8), 0x12);
    }

    proptest::proptest! {
        /// Every width at every offset, against the one-bit-at-a-time oracle.
        ///
        /// The generator is written so that width 64 at a non-byte-aligned offset — the
        /// nine-byte case — is actually reachable, rather than being buried under a uniform
        /// distribution that would hit it once in a thousand runs.
        #[test]
        fn matches_naive_reference(
            data in proptest::collection::vec(proptest::num::u8::ANY, 1..24),
            offset_seed in 0usize..200,
            width in 0u32..=64,
        ) {
            let total_bits = data.len() * 8;
            let offset = offset_seed % (total_bits + 1);
            let mut cursor = BitCursor::new(&data);
            cursor.seek(offset);
            let got = cursor.read_uint(width);
            match naive_read(&data, offset, width) {
                Some(want) => {
                    proptest::prop_assert_eq!(got, Ok(want));
                    proptest::prop_assert_eq!(cursor.position(), offset + width as usize);
                }
                None => proptest::prop_assert!(got.is_err()),
            }
        }

        /// Wide fields specifically: nine-byte spans and everything around them.
        #[test]
        fn wide_reads_at_every_bit_offset(
            data in proptest::collection::vec(proptest::num::u8::ANY, 9..17),
            offset in 0usize..8,
            width in 57u32..=64,
        ) {
            let mut cursor = BitCursor::new(&data);
            cursor.seek(offset);
            let want = naive_read(&data, offset, width).expect("buffer is long enough");
            proptest::prop_assert_eq!(cursor.read_uint(width), Ok(want));
        }

        /// Reading N bits as bytes and as an integer must agree for N <= 64.
        #[test]
        fn bytes_and_integers_agree(
            data in proptest::collection::vec(proptest::num::u8::ANY, 1..20),
            offset_seed in 0usize..200,
            width in 1usize..=64,
        ) {
            let total_bits = data.len() * 8;
            let offset = offset_seed % (total_bits + 1);
            if offset + width > total_bits {
                return Ok(());
            }
            let mut as_int = BitCursor::new(&data);
            as_int.seek(offset);
            let integer = as_int.read_uint(width as u32).expect("in range");

            let mut as_bytes = BitCursor::new(&data);
            as_bytes.seek(offset);
            let bytes = as_bytes.read_bytes(width).expect("in range");

            let mut rebuilt = 0u64;
            for byte in bytes.iter() {
                rebuilt = (rebuilt << 8) | u64::from(*byte);
            }
            proptest::prop_assert_eq!(rebuilt, integer);
            proptest::prop_assert_eq!(as_int.position(), as_bytes.position());
        }

        /// Sign extension at every width, against the arbitrary-precision oracle.
        ///
        /// Width 63 is the interesting one and a uniform generator finds it once in sixty
        /// runs, so widths are drawn across the whole range deliberately.
        #[test]
        fn twos_complement_matches_naive_reference(
            bits in proptest::num::u64::ANY,
            width in 1u32..=64,
        ) {
            let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
            let value = bits & mask;
            proptest::prop_assert_eq!(
                i128::from(twos_complement(value, width)),
                naive_twos_complement(value, width),
                "value {} width {}", value, width
            );
        }

        /// The unmasked form agrees with the masking one wherever the value fits its field,
        /// and follows the reference wherever it does not.
        #[test]
        fn unmasked_sign_extension_agrees_within_the_field(
            bits in proptest::num::u64::ANY,
            width in 1u32..=64,
        ) {
            let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
            let value = bits & mask;
            proptest::prop_assert_eq!(
                twos_complement_unmasked(value, width),
                Some(twos_complement(value, width)),
                "value {} width {}", value, width
            );
        }

        /// Above the field's width the two part company, and the unmasked one is right.
        #[test]
        fn unmasked_sign_extension_keeps_the_high_bits(
            bits in proptest::num::u64::ANY,
            width in 1u32..=56,
        ) {
            // What the reference computes, in arbitrary precision.
            let expected = if bits & (1u64 << (width - 1)) == 0 {
                i128::from(bits)
            } else {
                i128::from(bits) - (1i128 << width)
            };
            proptest::prop_assert_eq!(
                twos_complement_unmasked(bits, width).map(i128::from),
                i64::try_from(expected).ok().map(i128::from),
                "value {} width {}", bits, width
            );
        }

        /// A read never panics and never moves the cursor on failure.
        #[test]
        fn failures_leave_the_cursor_untouched(
            data in proptest::collection::vec(proptest::num::u8::ANY, 0..8),
            offset in 0usize..200,
            width in 0u32..=80,
        ) {
            let mut cursor = BitCursor::new(&data);
            cursor.seek(offset);
            if cursor.read_uint(width).is_err() {
                proptest::prop_assert_eq!(cursor.position(), offset);
            }
        }
    }
}
