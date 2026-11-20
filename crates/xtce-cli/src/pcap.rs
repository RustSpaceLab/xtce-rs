//! `xtce pcap` — wrap a CCSDS space packet stream in a libpcap (`.pcap`) capture file.
//!
//! Wireshark and `tshark` dissect raw space packets over the `USER0` data-link type
//! (`DLT_USER0 = 147`). Writing a standard 24-byte global header and a 16-byte record header
//! around each framed CCSDS packet lets an engineer open any telemetry recording directly in
//! Wireshark alongside the Lua dissector produced by `xtce wireshark`.

use std::io::{Read, Write};
use std::path::Path;

use xtce_decode::{PacketReadError, PacketReader};

/// Standard libpcap magic number for microsecond-resolution little-endian captures.
#[cfg(test)]
pub const PCAP_MAGIC_LE: u32 = 0xA1B2_C3D4;

/// `DLT_USER0` (147), the conventional link-layer header type for raw CCSDS packets.
#[cfg(test)]
pub const LINKTYPE_USER0: u32 = 147;

/// Maximum packet length advertised in the PCAP global header.
const SNAPLEN: u32 = 65_535;

/// Pre-encoded 24-byte little-endian PCAP global header (version 2.4, `LINKTYPE_USER0`).
const GLOBAL_HEADER: [u8; 24] = [
    0xD4, 0xC3, 0xB2, 0xA1, // magic_number: 0xa1b2c3d4
    0x02, 0x00, // version_major: 2
    0x04, 0x00, // version_minor: 4
    0x00, 0x00, 0x00, 0x00, // thiszone: 0
    0x00, 0x00, 0x00, 0x00, // sigfigs: 0
    0xFF, 0xFF, 0x00, 0x00, // snaplen: 65535
    0x93, 0x00, 0x00, 0x00, // network: 147 (LINKTYPE_USER0)
];

/// Configuration for `xtce pcap`.
pub struct Options<'a> {
    pub packets: &'a Path,
    pub out: Option<&'a Path>,
    pub skip_header_bytes: usize,
    pub limit: Option<usize>,
}

/// Summary of packets written to a PCAP stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub packets: usize,
    pub payload_bytes: u64,
}

fn open_packet_source(packets: &Path) -> std::io::Result<Box<dyn Read>> {
    if packets.as_os_str() == "-" {
        Ok(Box::new(std::io::BufReader::new(std::io::stdin())))
    } else {
        let file = std::fs::File::open(packets)?;
        Ok(Box::new(std::io::BufReader::new(file)))
    }
}

/// Streams packets from `reader` into `out` formatted as a libpcap capture.
///
/// Synthetic timestamps advance by 1 millisecond per packet so that Wireshark I/O graphs and
/// timeline filters have a monotonic time axis even when the raw recording carries no ground
/// receipt timestamps.
///
/// # Errors
///
/// Returns [`PacketReadError::Framing`] if the input stream ends mid-packet, or
/// [`PacketReadError::Io`] if reading or writing fails.
pub fn write_stream<R: Read, W: Write>(
    reader: &mut PacketReader<R>,
    out: &mut W,
    limit: Option<usize>,
) -> Result<Stats, PacketReadError> {
    out.write_all(&GLOBAL_HEADER)
        .map_err(|source| PacketReadError::Io { offset: 0, source })?;

    let mut stats = Stats::default();

    while let Some(framed) = reader.next_packet()? {
        if limit.is_some_and(|max| stats.packets >= max) {
            break;
        }

        let bytes = framed.bytes();
        let pkt_len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let index_u32 = u32::try_from(stats.packets).unwrap_or(u32::MAX);
        let seconds = index_u32 / 1_000;
        let micros = (index_u32 % 1_000) * 1_000;

        let s = seconds.to_le_bytes();
        let u = micros.to_le_bytes();
        let inc = pkt_len.min(SNAPLEN).to_le_bytes();
        let orig = pkt_len.to_le_bytes();

        let record_header: [u8; 16] = [
            s[0], s[1], s[2], s[3], u[0], u[1], u[2], u[3], inc[0], inc[1], inc[2], inc[3],
            orig[0], orig[1], orig[2], orig[3],
        ];

        let write_len = (pkt_len.min(SNAPLEN)) as usize;
        out.write_all(&record_header)
            .and_then(|()| out.write_all(&bytes[..write_len]))
            .map_err(|source| PacketReadError::Io {
                offset: reader.offset(),
                source,
            })?;

        stats.packets += 1;
        stats.payload_bytes += write_len as u64;
    }

    Ok(stats)
}

/// Executes `xtce pcap`.
///
/// # Errors
///
/// Returns an error if the packet source or output destination cannot be opened, or if the
/// packet stream is malformed.
pub fn run(options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let source = open_packet_source(options.packets)?;
    let mut reader = PacketReader::new(source, options.skip_header_bytes);

    match options.out {
        Some(path) if path.as_os_str() != "-" => {
            let file = std::fs::File::create(path)?;
            let mut out = std::io::BufWriter::new(file);
            let stats = write_stream(&mut reader, &mut out, options.limit)?;
            out.flush()?;
            eprintln!(
                "wrote {} packet(s) ({} payload bytes) to {}",
                stats.packets,
                stats.payload_bytes,
                path.display()
            );
        }
        _ => {
            let stdout = std::io::stdout();
            let mut out = std::io::BufWriter::new(stdout.lock());
            let stats = write_stream(&mut reader, &mut out, options.limit)?;
            out.flush()?;
            eprintln!(
                "wrote {} packet(s) ({} payload bytes) to <stdout>",
                stats.packets, stats.payload_bytes
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use xtce_decode::{FramingError, PacketReadError, PacketReader};

    use super::{GLOBAL_HEADER, LINKTYPE_USER0, PCAP_MAGIC_LE, write_stream};

    fn make_packet(apid: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(6 + payload.len());
        let word0 = 0x0800 | (apid & 0x07FF);
        pkt.extend_from_slice(&word0.to_be_bytes());
        pkt.extend_from_slice(&0xC000u16.to_be_bytes());
        let len_field = u16::try_from(payload.len().saturating_sub(1)).unwrap_or(0);
        pkt.extend_from_slice(&len_field.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn writes_valid_pcap_global_and_packet_headers() {
        let mut raw = make_packet(0x10, &[1, 2, 3, 4]);
        raw.extend(make_packet(0x20, &[5, 6]));

        let mut reader = PacketReader::new(Cursor::new(raw), 0);
        let mut out = Vec::new();
        let stats = write_stream(&mut reader, &mut out, None).expect("pcap writes");

        assert_eq!(stats.packets, 2);
        assert_eq!(stats.payload_bytes, 18);
        assert_eq!(out.len(), 24 + (16 + 10) + (16 + 8));

        let magic = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let linktype = u32::from_le_bytes(out[20..24].try_into().unwrap());
        assert_eq!(magic, PCAP_MAGIC_LE);
        assert_eq!(linktype, LINKTYPE_USER0);

        // First packet record header at offset 24: ts_sec=0, ts_usec=0, incl_len=10, orig_len=10
        assert_eq!(u32::from_le_bytes(out[24..28].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(out[28..32].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(out[32..36].try_into().unwrap()), 10);
        assert_eq!(u32::from_le_bytes(out[36..40].try_into().unwrap()), 10);

        // Second packet record header at offset 50: ts_sec=0, ts_usec=1000, incl_len=8, orig_len=8
        assert_eq!(u32::from_le_bytes(out[50..54].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(out[54..58].try_into().unwrap()), 1_000);
        assert_eq!(u32::from_le_bytes(out[58..62].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(out[62..66].try_into().unwrap()), 8);
    }

    #[test]
    fn respects_packet_limit_and_skip_header_bytes() {
        let mut raw = vec![0xAA, 0xBB, 0xCC, 0xDD];
        raw.extend(make_packet(1, &[0x11, 0x22]));
        raw.extend([0xAA, 0xBB, 0xCC, 0xDD]);
        raw.extend(make_packet(2, &[0x33, 0x44]));

        let mut reader = PacketReader::new(Cursor::new(raw), 4);
        let mut out = Vec::new();
        let stats = write_stream(&mut reader, &mut out, Some(1)).expect("limited pcap");

        assert_eq!(stats.packets, 1);
        assert_eq!(stats.payload_bytes, 8);
        assert_eq!(out.len(), 24 + 16 + 8);
    }

    #[test]
    fn empty_stream_writes_only_global_header() {
        let mut reader = PacketReader::new(Cursor::new(Vec::<u8>::new()), 0);
        let mut out = Vec::new();
        let stats = write_stream(&mut reader, &mut out, None).expect("empty pcap");

        assert_eq!(stats.packets, 0);
        assert_eq!(stats.payload_bytes, 0);
        assert_eq!(out.as_slice(), &GLOBAL_HEADER);
    }

    #[test]
    fn truncated_packet_surfaces_framing_error() {
        let mut raw = make_packet(1, &[1, 2, 3, 4]);
        raw.truncate(8);

        let mut reader = PacketReader::new(Cursor::new(raw), 0);
        let mut out = Vec::new();
        let err = write_stream(&mut reader, &mut out, None).expect_err("truncated");
        assert!(matches!(
            err,
            PacketReadError::Framing(FramingError::ShortPacket {
                offset: 0,
                declared: 10,
                remaining: 8,
            })
        ));
    }
}
