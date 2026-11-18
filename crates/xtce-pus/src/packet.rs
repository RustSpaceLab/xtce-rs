//! Zero-copy ECSS-E-ST-70-41C (PUS-C) packet parsing and encoding over CCSDS 133.0-B.

use core::fmt;

use crate::crc::crc16_ccitt;

/// Size of the CCSDS 133.0-B Primary Header in octets.
pub const PRIMARY_HEADER_LEN: usize = 6;

/// Size of the PUS-C Telemetry Secondary Header (with 4+2 CUC timestamp) in octets.
pub const TM_SECONDARY_HEADER_LEN: usize = 13;

/// Size of the PUS-C Telecommand Secondary Header in octets.
pub const TC_SECONDARY_HEADER_LEN: usize = 5;

/// Size of the trailing Packet Error Control (CRC-16-CCITT) field in octets.
pub const PEC_LEN: usize = 2;

/// ECSS PUS version number for ECSS-E-ST-70-41C (PUS-C).
pub const PUS_VERSION_C: u8 = 2;

/// Errors returned while decoding or encoding an ECSS PUS packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PusError {
    /// The frame is shorter than the minimum header + CRC size.
    ShortPacket {
        /// Bytes provided by the caller.
        actual: usize,
        /// Minimum bytes required for this frame type.
        minimum: usize,
    },
    /// The CCSDS primary header length field disagrees with the slice length.
    LengthMismatch {
        /// Total frame length declared by the CCSDS primary header (`6 + C + 1`).
        declared: usize,
        /// Actual slice length.
        actual: usize,
    },
    /// The CCSDS Secondary Header Flag (bit 4) is 0; ECSS PUS requires a secondary header.
    MissingSecondaryHeader,
    /// Unknown or unsupported ECSS PUS version nibble.
    UnsupportedPusVersion(u8),
    /// Trailing 16-bit CRC-16-CCITT does not match the computed syndrome.
    CrcMismatch {
        /// 16-bit CRC read from the last two octets of the packet.
        expected: u16,
        /// 16-bit CRC computed over the preceding octets.
        computed: u16,
    },
    /// The output slice passed to an encoder is too small to hold the frame.
    BufferTooSmall {
        /// Bytes needed to encode the packet.
        required: usize,
        /// Bytes available in the caller's slice.
        available: usize,
    },
    /// Service-specific application data is shorter than required or invalid.
    MalformedServiceData {
        /// ECSS service type (`ST[x]`).
        service: u8,
        /// ECSS message subtype (`TM/TC[x,y]`).
        subtype: u8,
    },
}

impl fmt::Display for PusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortPacket { actual, minimum } => {
                write!(
                    f,
                    "packet of {actual} byte(s) is shorter than minimum {minimum}"
                )
            }
            Self::LengthMismatch { declared, actual } => {
                write!(
                    f,
                    "CCSDS header declares {declared} byte(s) but frame has {actual}"
                )
            }
            Self::MissingSecondaryHeader => {
                write!(
                    f,
                    "CCSDS secondary header flag is 0 (required for ECSS PUS)"
                )
            }
            Self::UnsupportedPusVersion(ver) => {
                write!(f, "unsupported ECSS PUS version {ver} (expected 1 or 2)")
            }
            Self::CrcMismatch { expected, computed } => {
                write!(
                    f,
                    "CRC-16-CCITT mismatch: packet carries 0x{expected:04X}, computed 0x{computed:04X}"
                )
            }
            Self::BufferTooSmall {
                required,
                available,
            } => {
                write!(
                    f,
                    "output buffer of {available} byte(s) cannot hold {required}-byte PUS frame"
                )
            }
            Self::MalformedServiceData { service, subtype } => {
                write!(f, "malformed application data for PUS[{service},{subtype}]")
            }
        }
    }
}

impl core::error::Error for PusError {}

/// Telecommand acknowledgement flags in the PUS-C TC secondary header (`ST[01]` stages).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct AckFlags {
    /// Emit `TM[1,1]` / `TM[1,2]` upon telecommand acceptance check.
    pub acceptance: bool,
    /// Emit `TM[1,3]` / `TM[1,4]` upon start of execution.
    pub start: bool,
    /// Emit `TM[1,5]` / `TM[1,6]` during execution progress.
    pub progress: bool,
    /// Emit `TM[1,7]` / `TM[1,8]` upon execution completion.
    pub completion: bool,
}

impl AckFlags {
    /// Requests both acceptance (`TM[1,1]`) and completion (`TM[1,7]`) verification reports.
    pub const ACCEPT_AND_COMPLETE: Self = Self {
        acceptance: true,
        start: false,
        progress: false,
        completion: true,
    };

    /// Decodes the 4-bit acknowledgement nibble from the first octet of a TC secondary header.
    #[must_use]
    pub const fn from_nibble(nibble: u8) -> Self {
        Self {
            acceptance: (nibble & 0b0001) != 0,
            start: (nibble & 0b0010) != 0,
            progress: (nibble & 0b0100) != 0,
            completion: (nibble & 0b1000) != 0,
        }
    }

    /// Encodes the flags into the lower 4 bits of an octet.
    #[must_use]
    pub const fn to_nibble(self) -> u8 {
        (self.acceptance as u8)
            | ((self.start as u8) << 1)
            | ((self.progress as u8) << 2)
            | ((self.completion as u8) << 3)
    }
}

/// CCSDS Unsegmented Time Code (CUC 4+2: 32-bit coarse seconds, 16-bit fine sub-seconds).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CucTimestamp {
    /// Whole seconds since mission epoch.
    pub coarse_seconds: u32,
    /// Sub-second fraction in units of $2^{-16}$ seconds ($\approx 15.26\ \mu\text{s}$).
    pub fine_subseconds: u16,
}

/// Decoded ECSS PUS secondary header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PusHeader {
    /// Telemetry secondary header (`Packet Type = 0`).
    Telemetry {
        /// PUS version number (`1` for PUS-A, `2` for PUS-C).
        version: u8,
        /// Spacecraft time reference status (4 bits).
        time_ref_status: u8,
        /// ECSS service type (`ST[x]`).
        service: u8,
        /// ECSS message subtype (`TM[x,y]`).
        subtype: u8,
        /// Monotonic per-type message counter.
        msg_counter: u16,
        /// Ground destination identifier.
        destination_id: u16,
        /// On-board CUC generation timestamp.
        timestamp: CucTimestamp,
    },
    /// Telecommand secondary header (`Packet Type = 1`).
    Telecommand {
        /// PUS version number (`1` for PUS-A, `2` for PUS-C).
        version: u8,
        /// Requested `ST[01]` verification stages.
        ack: AckFlags,
        /// ECSS service type (`ST[x]`).
        service: u8,
        /// ECSS message subtype (`TC[x,y]`).
        subtype: u8,
        /// Ground source identifier.
        source_id: u16,
    },
}

impl PusHeader {
    /// The ECSS service type (`ST[x]`).
    #[must_use]
    pub const fn service(&self) -> u8 {
        match *self {
            Self::Telemetry { service, .. } | Self::Telecommand { service, .. } => service,
        }
    }

    /// The ECSS message subtype (`TM/TC[x,y]`).
    #[must_use]
    pub const fn subtype(&self) -> u8 {
        match *self {
            Self::Telemetry { subtype, .. } | Self::Telecommand { subtype, .. } => subtype,
        }
    }

    /// Returns `true` if this is a telecommand (`TC`), `false` if telemetry (`TM`).
    #[must_use]
    pub const fn is_telecommand(&self) -> bool {
        matches!(self, Self::Telecommand { .. })
    }
}

/// A validated, zero-copy view of a CCSDS + ECSS PUS packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PusPacket<'a> {
    /// 11-bit CCSDS Application Process Identifier.
    pub apid: u16,
    /// 14-bit CCSDS Packet Sequence Count.
    pub sequence_count: u16,
    /// First 32 bits of the CCSDS primary header (`Packet ID || Packet Sequence Control`),
    /// used by `ST[01]` Request Verification reports to identify a telecommand.
    pub request_id: u32,
    /// Decoded PUS secondary header.
    pub header: PusHeader,
    /// Service-specific application data slice (between the secondary header and the 2-byte CRC).
    pub app_data: &'a [u8],
    /// Verified 16-bit CRC-16-CCITT carried in the final two octets.
    pub crc: u16,
}

impl<'a> PusPacket<'a> {
    /// Parses and validates a complete CCSDS + ECSS PUS frame, including its trailing CRC-16-CCITT.
    ///
    /// # Errors
    ///
    /// Returns [`PusError`] if the frame is truncated, lacks a secondary header, carries an
    /// unknown PUS version, or fails CRC-16-CCITT verification.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PusError> {
        let min_base = PRIMARY_HEADER_LEN + TC_SECONDARY_HEADER_LEN + PEC_LEN;
        if bytes.len() < min_base {
            return Err(PusError::ShortPacket {
                actual: bytes.len(),
                minimum: min_base,
            });
        }

        let word0 = u16::from_be_bytes([bytes[0], bytes[1]]);
        let word1 = u16::from_be_bytes([bytes[2], bytes[3]]);
        let data_len = u16::from_be_bytes([bytes[4], bytes[5]]);
        let declared_total = PRIMARY_HEADER_LEN + usize::from(data_len) + 1;

        if declared_total != bytes.len() {
            return Err(PusError::LengthMismatch {
                declared: declared_total,
                actual: bytes.len(),
            });
        }

        let sec_hdr_flag = ((word0 >> 11) & 0x01) != 0;
        if !sec_hdr_flag {
            return Err(PusError::MissingSecondaryHeader);
        }

        let is_tc = ((word0 >> 12) & 0x01) != 0;
        let apid = word0 & 0x07FF;
        let sequence_count = word1 & 0x3FFF;
        let request_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        let body_end = bytes.len() - PEC_LEN;
        let expected_crc = u16::from_be_bytes([bytes[body_end], bytes[body_end + 1]]);
        let computed_crc = crc16_ccitt(&bytes[..body_end]);
        if expected_crc != computed_crc {
            return Err(PusError::CrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let sec = &bytes[PRIMARY_HEADER_LEN..body_end];
        let version = sec[0] >> 4;
        if version != 1 && version != PUS_VERSION_C {
            return Err(PusError::UnsupportedPusVersion(version));
        }

        if is_tc {
            let ack = AckFlags::from_nibble(sec[0] & 0x0F);
            let service = sec[1];
            let subtype = sec[2];
            let source_id = u16::from_be_bytes([sec[3], sec[4]]);
            let app_data = &sec[TC_SECONDARY_HEADER_LEN..];

            Ok(Self {
                apid,
                sequence_count,
                request_id,
                header: PusHeader::Telecommand {
                    version,
                    ack,
                    service,
                    subtype,
                    source_id,
                },
                app_data,
                crc: expected_crc,
            })
        } else {
            let min_tm = PRIMARY_HEADER_LEN + TM_SECONDARY_HEADER_LEN + PEC_LEN;
            if bytes.len() < min_tm {
                return Err(PusError::ShortPacket {
                    actual: bytes.len(),
                    minimum: min_tm,
                });
            }
            let time_ref_status = sec[0] & 0x0F;
            let service = sec[1];
            let subtype = sec[2];
            let msg_counter = u16::from_be_bytes([sec[3], sec[4]]);
            let destination_id = u16::from_be_bytes([sec[5], sec[6]]);
            let coarse_seconds = u32::from_be_bytes([sec[7], sec[8], sec[9], sec[10]]);
            let fine_subseconds = u16::from_be_bytes([sec[11], sec[12]]);
            let app_data = &sec[TM_SECONDARY_HEADER_LEN..];

            Ok(Self {
                apid,
                sequence_count,
                request_id,
                header: PusHeader::Telemetry {
                    version,
                    time_ref_status,
                    service,
                    subtype,
                    msg_counter,
                    destination_id,
                    timestamp: CucTimestamp {
                        coarse_seconds,
                        fine_subseconds,
                    },
                },
                app_data,
                crc: expected_crc,
            })
        }
    }
}

/// Parameters for encoding a PUS-C Telemetry (`TM`) packet.
#[derive(Clone, Copy, Debug)]
pub struct TmParams {
    /// 11-bit CCSDS APID.
    pub apid: u16,
    /// 14-bit CCSDS sequence counter.
    pub sequence_count: u16,
    /// ECSS service type (`ST[x]`).
    pub service: u8,
    /// ECSS message subtype (`TM[x,y]`).
    pub subtype: u8,
    /// Per-type message counter.
    pub msg_counter: u16,
    /// Ground destination identifier.
    pub destination_id: u16,
    /// Spacecraft CUC timestamp.
    pub timestamp: CucTimestamp,
}

/// Encodes a complete PUS-C Telemetry (`TM`) frame with trailing CRC-16-CCITT into `out`.
///
/// Returns the total number of bytes written.
///
/// # Errors
///
/// Returns [`PusError::BufferTooSmall`] if `out` cannot hold `21 + app_data.len()` bytes.
pub fn encode_tm(params: &TmParams, app_data: &[u8], out: &mut [u8]) -> Result<usize, PusError> {
    let total = PRIMARY_HEADER_LEN + TM_SECONDARY_HEADER_LEN + app_data.len() + PEC_LEN;
    if out.len() < total {
        return Err(PusError::BufferTooSmall {
            required: total,
            available: out.len(),
        });
    }

    let word0: u16 = 0x0800 | (params.apid & 0x07FF); // TM (type 0), sec_hdr=1
    let word1: u16 = 0xC000 | (params.sequence_count & 0x3FFF); // unsegmented (3)
    let data_len = (total - PRIMARY_HEADER_LEN - 1) as u16;

    out[0..2].copy_from_slice(&word0.to_be_bytes());
    out[2..4].copy_from_slice(&word1.to_be_bytes());
    out[4..6].copy_from_slice(&data_len.to_be_bytes());

    out[6] = PUS_VERSION_C << 4;
    out[7] = params.service;
    out[8] = params.subtype;
    out[9..11].copy_from_slice(&params.msg_counter.to_be_bytes());
    out[11..13].copy_from_slice(&params.destination_id.to_be_bytes());
    out[13..17].copy_from_slice(&params.timestamp.coarse_seconds.to_be_bytes());
    out[17..19].copy_from_slice(&params.timestamp.fine_subseconds.to_be_bytes());

    let app_end = 19 + app_data.len();
    out[19..app_end].copy_from_slice(app_data);

    let crc = crc16_ccitt(&out[..app_end]);
    out[app_end..app_end + 2].copy_from_slice(&crc.to_be_bytes());

    Ok(total)
}

/// Parameters for encoding a PUS-C Telecommand (`TC`) packet.
#[derive(Clone, Copy, Debug)]
pub struct TcParams {
    /// 11-bit CCSDS APID.
    pub apid: u16,
    /// 14-bit CCSDS sequence counter.
    pub sequence_count: u16,
    /// Requested `ST[01]` verification stages.
    pub ack: AckFlags,
    /// ECSS service type (`ST[x]`).
    pub service: u8,
    /// ECSS message subtype (`TC[x,y]`).
    pub subtype: u8,
    /// Ground source identifier.
    pub source_id: u16,
}

/// Encodes a complete PUS-C Telecommand (`TC`) frame with trailing CRC-16-CCITT into `out`.
///
/// Returns the total number of bytes written.
///
/// # Errors
///
/// Returns [`PusError::BufferTooSmall`] if `out` cannot hold `13 + app_data.len()` bytes.
pub fn encode_tc(params: &TcParams, app_data: &[u8], out: &mut [u8]) -> Result<usize, PusError> {
    let total = PRIMARY_HEADER_LEN + TC_SECONDARY_HEADER_LEN + app_data.len() + PEC_LEN;
    if out.len() < total {
        return Err(PusError::BufferTooSmall {
            required: total,
            available: out.len(),
        });
    }

    let word0: u16 = 0x1800 | (params.apid & 0x07FF); // TC (type 1), sec_hdr=1
    let word1: u16 = 0xC000 | (params.sequence_count & 0x3FFF);
    let data_len = (total - PRIMARY_HEADER_LEN - 1) as u16;

    out[0..2].copy_from_slice(&word0.to_be_bytes());
    out[2..4].copy_from_slice(&word1.to_be_bytes());
    out[4..6].copy_from_slice(&data_len.to_be_bytes());

    out[6] = (PUS_VERSION_C << 4) | params.ack.to_nibble();
    out[7] = params.service;
    out[8] = params.subtype;
    out[9..11].copy_from_slice(&params.source_id.to_be_bytes());

    let app_end = 11 + app_data.len();
    out[11..app_end].copy_from_slice(app_data);

    let crc = crc16_ccitt(&out[..app_end]);
    out[app_end..app_end + 2].copy_from_slice(&crc.to_be_bytes());

    Ok(total)
}
