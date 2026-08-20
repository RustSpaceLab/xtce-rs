//! CCSDS Space Packet framing.
//!
//! A telemetry file is a bare concatenation of packets with no index. Each begins with the
//! six-byte primary header of CCSDS 133.0-B, whose last two octets give the length count
//! `C = (octets in the data field) − 1`, so a packet is `6 + C + 1` bytes long.
//!
//! Some ground-system "raw record" formats prepend a per-packet wrapper; `skip_header_bytes`
//! steps over it. The SUDA test file in this repository needs four.

use std::fmt;

/// Size of the CCSDS primary header.
pub const PRIMARY_HEADER_BYTES: usize = 6;

/// A view of one CCSDS packet, with its primary header fields decoded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SpacePacketBytes<'a> {
    bytes: &'a [u8],
}

impl<'a> SpacePacketBytes<'a> {
    /// Wraps a byte slice that starts with a CCSDS primary header.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The whole packet, header included.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    fn header_word(self, index: usize) -> u16 {
        let hi = self.bytes.get(index).copied().unwrap_or(0);
        let lo = self.bytes.get(index + 1).copied().unwrap_or(0);
        u16::from_be_bytes([hi, lo])
    }

    /// Packet version number, bits 0–2.
    #[must_use]
    pub fn version(self) -> u8 {
        (self.header_word(0) >> 13) as u8
    }

    /// Packet type: 0 for telemetry, 1 for telecommand.
    #[must_use]
    pub fn packet_type(self) -> u8 {
        ((self.header_word(0) >> 12) & 0x1) as u8
    }

    /// Secondary header flag.
    #[must_use]
    pub fn secondary_header_flag(self) -> bool {
        (self.header_word(0) >> 11) & 0x1 == 1
    }

    /// Application process identifier, bits 5–15.
    #[must_use]
    pub fn apid(self) -> u16 {
        self.header_word(0) & 0x07FF
    }

    /// Sequence flags, bits 16–17.
    #[must_use]
    pub fn sequence_flags(self) -> u8 {
        (self.header_word(2) >> 14) as u8
    }

    /// Packet sequence count, bits 18–31.
    #[must_use]
    pub fn sequence_count(self) -> u16 {
        self.header_word(2) & 0x3FFF
    }

    /// The length count `C` as it appears in the header.
    #[must_use]
    pub fn data_length(self) -> u16 {
        self.header_word(4)
    }

    /// The user data field, i.e. everything after the primary header.
    #[must_use]
    pub fn user_data(self) -> &'a [u8] {
        self.bytes.get(PRIMARY_HEADER_BYTES..).unwrap_or_default()
    }
}

impl fmt::Debug for SpacePacketBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpacePacketBytes")
            .field("apid", &self.apid())
            .field("sequence_count", &self.sequence_count())
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// A malformed packet stream.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum FramingError {
    /// The remaining bytes cannot hold a primary header.
    #[error(
        "{remaining} byte(s) left at offset {offset} cannot hold a {PRIMARY_HEADER_BYTES}-byte CCSDS header"
    )]
    ShortHeader {
        /// Byte offset in the stream.
        offset: usize,
        /// Bytes left from that offset.
        remaining: usize,
    },

    /// The header declares a packet longer than the bytes that remain.
    #[error("packet at offset {offset} declares {declared} bytes but only {remaining} remain")]
    ShortPacket {
        /// Byte offset in the stream.
        offset: usize,
        /// Length the header declares.
        declared: usize,
        /// Bytes actually left.
        remaining: usize,
    },
}

/// Iterates the CCSDS packets in a byte stream.
///
/// Yields `Result`, so a truncated tail surfaces as an error on the final item rather than
/// silently ending the stream — quietly dropping a partial packet is how a decoder ends up
/// reporting fewer packets than a file contains without anyone noticing.
pub struct PacketIter<'a> {
    data: &'a [u8],
    offset: usize,
    skip_header_bytes: usize,
    finished: bool,
}

impl<'a> PacketIter<'a> {
    /// Iterates packets in `data`, skipping `skip_header_bytes` before each one.
    #[must_use]
    pub const fn new(data: &'a [u8], skip_header_bytes: usize) -> Self {
        Self {
            data,
            offset: 0,
            skip_header_bytes,
            finished: false,
        }
    }

    /// Byte offset of the next packet.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = Result<SpacePacketBytes<'a>, FramingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let start = self.offset.checked_add(self.skip_header_bytes)?;
        if start >= self.data.len() {
            self.finished = true;
            // A clean end: the stream stopped exactly at a packet boundary. Any wrapper
            // bytes with no packet behind them are treated as padding, matching how the
            // reference implementation ends its generator.
            return None;
        }

        let remaining = self.data.len() - start;
        if remaining < PRIMARY_HEADER_BYTES {
            self.finished = true;
            return Some(Err(FramingError::ShortHeader {
                offset: start,
                remaining,
            }));
        }

        let count = u16::from_be_bytes([
            self.data.get(start + 4).copied().unwrap_or(0),
            self.data.get(start + 5).copied().unwrap_or(0),
        ]);
        let total = PRIMARY_HEADER_BYTES + usize::from(count) + 1;

        let Some(bytes) = self.data.get(start..start + total) else {
            self.finished = true;
            return Some(Err(FramingError::ShortPacket {
                offset: start,
                declared: total,
                remaining,
            }));
        };

        self.offset = start + total;
        Some(Ok(SpacePacketBytes::new(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a packet with the given APID and user data length.
    fn packet(apid: u16, data_len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; PRIMARY_HEADER_BYTES + data_len];
        let first = 0x0800 | (apid & 0x07FF); // version 0, type 0, secondary header flag 1
        bytes[0] = (first >> 8) as u8;
        bytes[1] = (first & 0xFF) as u8;
        let count = (data_len - 1) as u16;
        bytes[4] = (count >> 8) as u8;
        bytes[5] = (count & 0xFF) as u8;
        bytes
    }

    #[test]
    fn splits_a_stream_into_packets() {
        let mut stream = packet(11, 10);
        stream.extend(packet(42, 4));

        let packets: Vec<_> = PacketIter::new(&stream, 0)
            .collect::<Result<_, _>>()
            .expect("well-formed stream");
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].apid(), 11);
        assert_eq!(packets[0].bytes().len(), 16);
        assert_eq!(packets[0].user_data().len(), 10);
        assert!(packets[0].secondary_header_flag());
        assert_eq!(packets[1].apid(), 42);
        assert_eq!(packets[1].bytes().len(), 10);
    }

    #[test]
    fn skips_per_packet_wrappers() {
        let mut stream = vec![0xDE, 0xAD, 0xBE, 0xEF];
        stream.extend(packet(7, 3));
        stream.extend([0xDE, 0xAD, 0xBE, 0xEF]);
        stream.extend(packet(8, 3));

        let packets: Vec<_> = PacketIter::new(&stream, 4)
            .collect::<Result<_, _>>()
            .expect("well-formed stream");
        assert_eq!(
            packets.iter().map(|p| p.apid()).collect::<Vec<_>>(),
            vec![7, 8]
        );
    }

    #[test]
    fn a_truncated_tail_is_reported_not_swallowed() {
        let mut stream = packet(11, 10);
        stream.truncate(12);
        let results: Vec<_> = PacketIter::new(&stream, 0).collect();
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results.first(),
            Some(Err(FramingError::ShortPacket { .. }))
        ));

        let stub = [0u8; 3];
        let results: Vec<_> = PacketIter::new(&stub, 0).collect();
        assert!(matches!(
            results.first(),
            Some(Err(FramingError::ShortHeader { .. }))
        ));
    }

    #[test]
    fn an_empty_stream_yields_nothing() {
        assert_eq!(PacketIter::new(&[], 0).count(), 0);
        assert_eq!(PacketIter::new(&[0xAA; 4], 4).count(), 0);
    }

    #[test]
    fn header_fields_decode() {
        // version 3, type 1, secondary header 1, apid 0x2AB; seq flags 2, count 0x1234
        let bytes = [0xFA, 0xAB, 0xD2, 0x34, 0x00, 0x01, 0x00, 0x00];
        let packet = SpacePacketBytes::new(&bytes);
        assert_eq!(packet.version(), 7);
        assert_eq!(packet.packet_type(), 1);
        assert!(packet.secondary_header_flag());
        assert_eq!(packet.apid(), 0x2AB);
        assert_eq!(packet.sequence_flags(), 3);
        assert_eq!(packet.sequence_count(), 0x1234);
        assert_eq!(packet.data_length(), 1);
    }
}
