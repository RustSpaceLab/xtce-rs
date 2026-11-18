//! `#![no_std]` Hardware-in-the-Loop (HIL) On-Board Computer (OBC) ECSS PUS responder.
//!
//! `PusResponder` implements a deterministic, zero-allocation spacecraft command and telemetry
//! handler suitable for flashing onto an STM32 (`thumbv7em-none-eabihf`), RP2040/RP2350, or
//! ESP32 microcontroller connected over UART/CAN/UDP, as well as running in closed-loop
//! desktop integration tests.

use crate::packet::{CucTimestamp, PusError, PusHeader, PusPacket, TmParams, encode_tm};
use crate::services::ObcHousekeeping;

///Maximum byte size of a single response frame emitted by [`PusResponder`].
pub const MAX_HIL_FRAME_LEN: usize = 64;

/// Failure code reported in `TM[1,2]` when a telecommand fails CRC-16-CCITT verification.
pub const ERR_CODE_CRC_MISMATCH: u16 = 0xBAD0;

/// Failure code reported in `TM[1,2]` when a frame is not a telecommand.
pub const ERR_CODE_NOT_A_TC: u16 = 0xBAD1;

/// Failure code reported in `TM[1,8]` when a service, subtype, or `SID` is unsupported.
pub const ERR_CODE_UNSUPPORTED: u16 = 0x0404;

/// Event ID emitted in `TM[5,2]` when a corrupted telecommand is rejected.
pub const EVENT_ID_CORRUPTED_TC: u16 = 0x0101;

/// Event ID emitted in `TM[5,1]` when periodic housekeeping is enabled.
pub const EVENT_ID_HK_ENABLED: u16 = 0x0305;

/// Deterministic, zero-heap ECSS PUS spacecraft responder state machine.
#[derive(Clone, Debug)]
pub struct PusResponder {
    /// 11-bit CCSDS Application Process ID for emitted telemetry.
    pub apid: u16,
    /// Ground destination ID written into PUS-C telemetry secondary headers.
    pub destination_id: u16,
    /// 14-bit monotonic CCSDS sequence counter.
    pub tm_seq_count: u16,
    /// 16-bit monotonic PUS message counter.
    pub msg_counter: u16,
    /// Current on-board housekeeping values.
    pub hk: ObcHousekeeping,
    /// Whether periodic `TM[3,25]` housekeeping generation is enabled.
    pub periodic_hk_enabled: bool,
}

impl PusResponder {
    /// Creates a new responder in `NOMINAL` mode (`mode = 2`, 28.20 V bus, 22.50 °C OBC).
    #[must_use]
    pub const fn new(apid: u16, destination_id: u16) -> Self {
        Self {
            apid: apid & 0x07FF,
            destination_id,
            tm_seq_count: 0,
            msg_counter: 0,
            hk: ObcHousekeeping {
                uptime_s: 1,
                bus_voltage_mv: 28_200,
                obc_temp_cdeg: 2_250,
                mode: 2,
            },
            periodic_hk_enabled: false,
        }
    }

    /// Advances on-board time by 1 second and updates simulated bus voltage and temperature.
    pub const fn tick_second(&mut self) {
        self.hk.uptime_s = self.hk.uptime_s.wrapping_add(1);
        let phase = (self.hk.uptime_s % 8) as i16;
        self.hk.bus_voltage_mv = 28_150 + (phase as u16) * 15;
        self.hk.obc_temp_cdeg = 2_240 + (phase - 4) * 5;
    }

    /// Processes one incoming telecommand frame and writes the resulting telemetry response
    /// frames into `out_frames[..count]` with their byte lengths in `out_lens[..count]`.
    ///
    /// Returns the number of telemetry frames emitted.
    ///
    /// # Errors
    ///
    /// Returns [`PusError`] only if `out_frames` / `out_lens` lack capacity for the response
    /// packets or if a frame is shorter than the 4-byte CCSDS request identifier.
    pub fn process_telecommand(
        &mut self,
        tc_frame: &[u8],
        out_frames: &mut [[u8; MAX_HIL_FRAME_LEN]],
        out_lens: &mut [usize],
    ) -> Result<usize, PusError> {
        let max_slots = out_frames.len().min(out_lens.len());
        let mut count = 0usize;

        let packet = match PusPacket::parse(tc_frame) {
            Ok(pkt) => pkt,
            Err(PusError::CrcMismatch { expected, .. }) if tc_frame.len() >= 4 => {
                let req_id =
                    u32::from_be_bytes([tc_frame[0], tc_frame[1], tc_frame[2], tc_frame[3]]);
                self.push_tm_1_2(
                    req_id,
                    ERR_CODE_CRC_MISMATCH,
                    out_frames,
                    out_lens,
                    &mut count,
                    max_slots,
                )?;
                let aux = expected.to_be_bytes();
                self.push_event(
                    2,
                    EVENT_ID_CORRUPTED_TC,
                    &aux,
                    out_frames,
                    out_lens,
                    &mut count,
                    max_slots,
                )?;
                return Ok(count);
            }
            Err(err) => return Err(err),
        };

        let PusHeader::Telecommand {
            ack,
            service,
            subtype,
            ..
        } = packet.header
        else {
            self.push_tm_1_2(
                packet.request_id,
                ERR_CODE_NOT_A_TC,
                out_frames,
                out_lens,
                &mut count,
                max_slots,
            )?;
            return Ok(count);
        };

        if ack.acceptance {
            self.push_tm_1_1(
                packet.request_id,
                out_frames,
                out_lens,
                &mut count,
                max_slots,
            )?;
        }

        let exec_ok = self.execute_service(
            service,
            subtype,
            packet.app_data,
            out_frames,
            out_lens,
            &mut count,
            max_slots,
        )?;

        if exec_ok {
            if ack.completion {
                self.push_tm_1_7(
                    packet.request_id,
                    out_frames,
                    out_lens,
                    &mut count,
                    max_slots,
                )?;
            }
        } else {
            self.push_tm_1_8(
                packet.request_id,
                ERR_CODE_UNSUPPORTED,
                out_frames,
                out_lens,
                &mut count,
                max_slots,
            )?;
        }

        Ok(count)
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_service(
        &mut self,
        service: u8,
        subtype: u8,
        app_data: &[u8],
        out_frames: &mut [[u8; MAX_HIL_FRAME_LEN]],
        out_lens: &mut [usize],
        count: &mut usize,
        max_slots: usize,
    ) -> Result<bool, PusError> {
        match (service, subtype) {
            (17, 1) => {
                self.emit_frame(17, 2, &[], out_frames, out_lens, count, max_slots)?;
                Ok(true)
            }
            (3, 27) if app_data.len() >= 2 => {
                let sid = u16::from_be_bytes([app_data[0], app_data[1]]);
                if sid != ObcHousekeeping::SID {
                    return Ok(false);
                }
                let payload = self.hk.to_app_data();
                self.emit_frame(3, 25, &payload, out_frames, out_lens, count, max_slots)?;
                Ok(true)
            }
            (3, 5) if app_data.len() >= 2 => {
                let sid = u16::from_be_bytes([app_data[0], app_data[1]]);
                if sid != ObcHousekeeping::SID {
                    return Ok(false);
                }
                self.periodic_hk_enabled = true;
                self.push_event(
                    1,
                    EVENT_ID_HK_ENABLED,
                    &app_data[..2],
                    out_frames,
                    out_lens,
                    count,
                    max_slots,
                )?;
                Ok(true)
            }
            (3, 6) if app_data.len() >= 2 => {
                let sid = u16::from_be_bytes([app_data[0], app_data[1]]);
                if sid != ObcHousekeeping::SID {
                    return Ok(false);
                }
                self.periodic_hk_enabled = false;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn push_tm_1_1(
        &mut self,
        request_id: u32,
        out_frames: &mut [[u8; MAX_HIL_FRAME_LEN]],
        out_lens: &mut [usize],
        count: &mut usize,
        max_slots: usize,
    ) -> Result<(), PusError> {
        let payload = request_id.to_be_bytes();
        self.emit_frame(1, 1, &payload, out_frames, out_lens, count, max_slots)
    }

    fn push_tm_1_2(
        &mut self,
        request_id: u32,
        failure_code: u16,
        out_frames: &mut [[u8; MAX_HIL_FRAME_LEN]],
        out_lens: &mut [usize],
        count: &mut usize,
        max_slots: usize,
    ) -> Result<(), PusError> {
        let r = request_id.to_be_bytes();
        let c = failure_code.to_be_bytes();
        let payload = [r[0], r[1], r[2], r[3], c[0], c[1]];
        self.emit_frame(1, 2, &payload, out_frames, out_lens, count, max_slots)
    }

    fn push_tm_1_7(
        &mut self,
        request_id: u32,
        out_frames: &mut [[u8; MAX_HIL_FRAME_LEN]],
        out_lens: &mut [usize],
        count: &mut usize,
        max_slots: usize,
    ) -> Result<(), PusError> {
        let payload = request_id.to_be_bytes();
        self.emit_frame(1, 7, &payload, out_frames, out_lens, count, max_slots)
    }

    fn push_tm_1_8(
        &mut self,
        request_id: u32,
        failure_code: u16,
        out_frames: &mut [[u8; MAX_HIL_FRAME_LEN]],
        out_lens: &mut [usize],
        count: &mut usize,
        max_slots: usize,
    ) -> Result<(), PusError> {
        let r = request_id.to_be_bytes();
        let c = failure_code.to_be_bytes();
        let payload = [r[0], r[1], r[2], r[3], c[0], c[1]];
        self.emit_frame(1, 8, &payload, out_frames, out_lens, count, max_slots)
    }

    #[allow(clippy::too_many_arguments)]
    fn push_event(
        &mut self,
        subtype: u8,
        event_id: u16,
        aux: &[u8],
        out_frames: &mut [[u8; MAX_HIL_FRAME_LEN]],
        out_lens: &mut [usize],
        count: &mut usize,
        max_slots: usize,
    ) -> Result<(), PusError> {
        let mut buf = [0u8; 16];
        let id = event_id.to_be_bytes();
        buf[0] = id[0];
        buf[1] = id[1];
        let copy_len = aux.len().min(buf.len() - 2);
        buf[2..2 + copy_len].copy_from_slice(&aux[..copy_len]);
        self.emit_frame(
            5,
            subtype,
            &buf[..2 + copy_len],
            out_frames,
            out_lens,
            count,
            max_slots,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_frame(
        &mut self,
        service: u8,
        subtype: u8,
        app_data: &[u8],
        out_frames: &mut [[u8; MAX_HIL_FRAME_LEN]],
        out_lens: &mut [usize],
        count: &mut usize,
        max_slots: usize,
    ) -> Result<(), PusError> {
        if *count >= max_slots {
            return Err(PusError::BufferTooSmall {
                required: *count + 1,
                available: max_slots,
            });
        }

        let params = TmParams {
            apid: self.apid,
            sequence_count: self.tm_seq_count,
            service,
            subtype,
            msg_counter: self.msg_counter,
            destination_id: self.destination_id,
            timestamp: CucTimestamp {
                coarse_seconds: self.hk.uptime_s,
                fine_subseconds: 0,
            },
        };

        let len = encode_tm(&params, app_data, &mut out_frames[*count])?;
        out_lens[*count] = len;
        *count += 1;
        self.tm_seq_count = (self.tm_seq_count + 1) & 0x3FFF;
        self.msg_counter = self.msg_counter.wrapping_add(1);
        Ok(())
    }
}
