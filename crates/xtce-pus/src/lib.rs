//! `#![no_std]` implementation of ECSS-E-ST-70-41C Packet Utilization Standard (PUS-C)
//! over CCSDS 133.0-B Space Packets, with a deterministic Hardware-in-the-Loop (HIL)
//! On-Board Computer responder and dual-use telecommand authentication.
//!
//! # Guarantees
//!
//! * **`#![no_std]` and zero heap allocations.** Every parser, encoder, security gate, and HIL
//!   responder method operates on caller-supplied byte slices so the crate can run unmodified
//!   on bare-metal flight targets (`thumbv7em-none-eabihf` Cortex-M, RISC-V, LEON/SPARC) and
//!   ground tools.
//! * **No panics.** `unwrap`, `expect`, and `panic!` are denied across the library.
//! * **End-to-end CRC-16-CCITT and SipHash-2-4 protection.** Every frame is verified against
//!   the ECSS-E-ST-70-41C Annex B syndrome (`0x1021`, initial `0xFFFF`), and critical dual-use
//!   telecommands can be protected against spoofing and replay via [`TcSecurityGate`].

#![no_std]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::todo, clippy::unimplemented)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod crc;
pub mod hil;
pub mod packet;
pub mod security;
pub mod services;

pub use crc::{crc16_ccitt, verify_crc16_ccitt};
pub use hil::{
    ERR_CODE_CRC_MISMATCH, ERR_CODE_NOT_A_TC, ERR_CODE_UNSUPPORTED, EVENT_ID_CORRUPTED_TC,
    EVENT_ID_DPU_INFERENCE, EVENT_ID_EO_CAPTURE, EVENT_ID_HK_ENABLED, FUNC_DPU_AI_INFERENCE,
    FUNC_ENTER_SAFE_MODE, FUNC_EO_OPTICAL_CAPTURE, MAX_HIL_FRAME_LEN, OBC_SCRATCHPAD_LEN,
    PARAM_EO_EXPOSURE_US, PusResponder,
};
pub use packet::{
    AckFlags, CucTimestamp, PEC_LEN, PRIMARY_HEADER_LEN, PUS_VERSION_C, PusError, PusHeader,
    PusPacket, TC_SECONDARY_HEADER_LEN, TM_SECONDARY_HEADER_LEN, TcParams, TmParams, encode_tc,
    encode_tm,
};
pub use security::{
    AUTH_KEY_LEN, ERR_CODE_AUTH_FAILED, ERR_CODE_REPLAY_DETECTED, SecurityError,
    TC_AUTH_TRAILER_LEN, TcSecurityGate, build_auth_trailer, compute_mac_tag,
};
pub use services::{
    EventReport, EventSeverity, FunctionCall, HousekeepingMessage, MemoryMessage,
    MonitoringMessage, ObcHousekeeping, ParameterManagementMessage, PusService, ScheduleMessage,
    TestMessage, VerificationReport,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hil_responder_handles_st17_are_you_alive_closed_loop() {
        let mut responder = PusResponder::new(0x010, 0x0001);
        let mut tc_buf = [0u8; 32];
        let tc_len = encode_tc(
            &TcParams {
                apid: 0x010,
                sequence_count: 7,
                ack: AckFlags::ACCEPT_AND_COMPLETE,
                service: 17,
                subtype: 1,
                source_id: 0x0042,
            },
            &[],
            &mut tc_buf,
        )
        .expect("encodes TC[17,1]");

        let parsed_tc = PusPacket::parse(&tc_buf[..tc_len]).expect("valid TC");
        assert_eq!(
            parsed_tc.decode_service().expect("service"),
            PusService::Test(TestMessage::AreYouAliveCommand)
        );

        let mut out_frames = [[0u8; MAX_HIL_FRAME_LEN]; 4];
        let mut out_lens = [0usize; 4];
        let count = responder
            .process_telecommand(&tc_buf[..tc_len], &mut out_frames, &mut out_lens)
            .expect("HIL processes TC[17,1]");
        assert_eq!(count, 3);

        let tm0 = PusPacket::parse(&out_frames[0][..out_lens[0]]).expect("TM[1,1]");
        assert_eq!(
            tm0.decode_service().expect("ST[01]"),
            PusService::Verification(VerificationReport::AcceptanceSuccess {
                request_id: parsed_tc.request_id,
            })
        );

        let tm1 = PusPacket::parse(&out_frames[1][..out_lens[1]]).expect("TM[17,2]");
        assert_eq!(
            tm1.decode_service().expect("ST[17]"),
            PusService::Test(TestMessage::AreYouAliveReport)
        );

        let tm2 = PusPacket::parse(&out_frames[2][..out_lens[2]]).expect("TM[1,7]");
        assert_eq!(
            tm2.decode_service().expect("ST[01]"),
            PusService::Verification(VerificationReport::ExecutionCompleteSuccess {
                request_id: parsed_tc.request_id,
            })
        );
    }

    #[test]
    fn hil_responder_emits_housekeeping_report_on_st03_one_shot() {
        let mut responder = PusResponder::new(0x010, 0x0001);
        responder.tick_second();

        let mut tc_buf = [0u8; 32];
        let sid_bytes = ObcHousekeeping::SID.to_be_bytes();
        let tc_len = encode_tc(
            &TcParams {
                apid: 0x010,
                sequence_count: 8,
                ack: AckFlags::ACCEPT_AND_COMPLETE,
                service: 3,
                subtype: 27,
                source_id: 0x0042,
            },
            &sid_bytes,
            &mut tc_buf,
        )
        .expect("encodes TC[3,27]");

        let mut out_frames = [[0u8; MAX_HIL_FRAME_LEN]; 4];
        let mut out_lens = [0usize; 4];
        let count = responder
            .process_telecommand(&tc_buf[..tc_len], &mut out_frames, &mut out_lens)
            .expect("HIL processes TC[3,27]");
        assert_eq!(count, 3);

        let hk_pkt = PusPacket::parse(&out_frames[1][..out_lens[1]]).expect("TM[3,25]");
        let PusService::Housekeeping(HousekeepingMessage::ParameterReport { sid, parameters }) =
            hk_pkt.decode_service().expect("decodes ST[03]")
        else {
            panic!("expected TM[3,25] ParameterReport");
        };
        assert_eq!(sid, ObcHousekeeping::SID);
        let decoded_hk = ObcHousekeeping::from_parameter_bytes(parameters).expect("OBC HK");
        assert_eq!(decoded_hk, responder.hk);
    }

    #[test]
    fn hil_responder_loads_dumps_and_scrubs_on_board_memory_st06() {
        let mut responder = PusResponder::new(0x010, 0x0001);
        let mut tc_buf = [0u8; 64];
        let mut out_frames = [[0u8; MAX_HIL_FRAME_LEN]; 4];
        let mut out_lens = [0usize; 4];

        // 1. TC[6,2] Load b"CAMILA" into memory_id=1 at offset 0x0000_0008
        let load_app = [1, 0, 0, 0, 8, b'C', b'A', b'M', b'I', b'L', b'A'];
        let tc_len = encode_tc(
            &TcParams {
                apid: 0x010,
                sequence_count: 10,
                ack: AckFlags::ACCEPT_AND_COMPLETE,
                service: 6,
                subtype: 2,
                source_id: 0x0042,
            },
            &load_app,
            &mut tc_buf,
        )
        .expect("encodes TC[6,2]");
        let count = responder
            .process_telecommand(&tc_buf[..tc_len], &mut out_frames, &mut out_lens)
            .expect("TC[6,2] runs");
        assert_eq!(count, 2); // TM[1,1] + TM[1,7]
        assert_eq!(&responder.scratchpad[8..14], b"CAMILA");

        // 2. TC[6,9] Check CRC-16-CCITT over [8..14] (length = 6)
        let check_app = [1, 0, 0, 0, 8, 0, 6];
        let tc_len = encode_tc(
            &TcParams {
                apid: 0x010,
                sequence_count: 11,
                ack: AckFlags::ACCEPT_AND_COMPLETE,
                service: 6,
                subtype: 9,
                source_id: 0x0042,
            },
            &check_app,
            &mut tc_buf,
        )
        .expect("encodes TC[6,9]");
        let count = responder
            .process_telecommand(&tc_buf[..tc_len], &mut out_frames, &mut out_lens)
            .expect("TC[6,9] runs");
        assert_eq!(count, 3); // TM[1,1] + TM[6,10] + TM[1,7]

        let tm_check = PusPacket::parse(&out_frames[1][..out_lens[1]]).expect("TM[6,10]");
        assert_eq!(
            tm_check.decode_service().expect("ST[06]"),
            PusService::Memory(MemoryMessage::CheckRawReport {
                memory_id: 1,
                address: 8,
                length: 6,
                checksum: crc16_ccitt(b"CAMILA"),
            })
        );
    }

    #[test]
    fn hil_responder_executes_st08_eo_imaging_and_st11_schedule() {
        let mut responder = PusResponder::new(0x010, 0x0001);
        let mut tc_buf = [0u8; 64];
        let mut out_frames = [[0u8; MAX_HIL_FRAME_LEN]; 4];
        let mut out_lens = [0usize; 4];

        // TC[8,1] Function Call: FUNC_EO_OPTICAL_CAPTURE (0x0010) with target_id = 0x01 (Warsaw)
        let fn_id = FUNC_EO_OPTICAL_CAPTURE.to_be_bytes();
        let fn_app = [fn_id[0], fn_id[1], 0x01];
        let tc_len = encode_tc(
            &TcParams {
                apid: 0x010,
                sequence_count: 12,
                ack: AckFlags::ACCEPT_AND_COMPLETE,
                service: 8,
                subtype: 1,
                source_id: 0x0042,
            },
            &fn_app,
            &mut tc_buf,
        )
        .expect("TC[8,1]");
        let count = responder
            .process_telecommand(&tc_buf[..tc_len], &mut out_frames, &mut out_lens)
            .expect("ST[08] runs");
        assert_eq!(count, 3); // TM[1,1] + TM[5,1] EO_CAPTURE + TM[1,7]
        assert_eq!(responder.hk.mode, 3);

        // TC[11,1] Enable schedule, then TC[11,4] Insert time-tagged activity at T=600s
        let enable_len = encode_tc(
            &TcParams {
                apid: 0x010,
                sequence_count: 13,
                ack: AckFlags::ACCEPT_AND_COMPLETE,
                service: 11,
                subtype: 1,
                source_id: 0x0042,
            },
            &[],
            &mut tc_buf,
        )
        .expect("TC[11,1]");
        responder
            .process_telecommand(&tc_buf[..enable_len], &mut out_frames, &mut out_lens)
            .expect("enables schedule");
        assert!(responder.schedule_enabled);

        let sched_app = [0x00, 0x00, 0x02, 0x58, 0x00, 0x20]; // release_time=600s, DPU task
        let tc_ins = encode_tc(
            &TcParams {
                apid: 0x010,
                sequence_count: 14,
                ack: AckFlags::ACCEPT_AND_COMPLETE,
                service: 11,
                subtype: 4,
                source_id: 0x0042,
            },
            &sched_app,
            &mut tc_buf,
        )
        .expect("TC[11,4]");
        let count = responder
            .process_telecommand(&tc_buf[..tc_ins], &mut out_frames, &mut out_lens)
            .expect("inserts scheduled activity");
        assert_eq!(count, 3); // TM[1,1] + TM[11,13] + TM[1,7]

        let tm_sched = PusPacket::parse(&out_frames[1][..out_lens[1]]).expect("TM[11,13]");
        assert_eq!(
            tm_sched.decode_service().expect("ST[11]"),
            PusService::Schedule(ScheduleMessage::SummaryReport {
                enabled: true,
                pending_count: 1,
            })
        );
    }

    #[test]
    fn hil_responder_rejects_corrupted_crc_with_tm_1_2_and_tm_5_2() {
        let mut responder = PusResponder::new(0x010, 0x0001);
        let mut tc_buf = [0u8; 32];
        let tc_len = encode_tc(
            &TcParams {
                apid: 0x010,
                sequence_count: 9,
                ack: AckFlags::ACCEPT_AND_COMPLETE,
                service: 17,
                subtype: 1,
                source_id: 0x0042,
            },
            &[],
            &mut tc_buf,
        )
        .expect("encodes TC");

        tc_buf[7] ^= 0x80;

        let mut out_frames = [[0u8; MAX_HIL_FRAME_LEN]; 4];
        let mut out_lens = [0usize; 4];
        let count = responder
            .process_telecommand(&tc_buf[..tc_len], &mut out_frames, &mut out_lens)
            .expect("HIL handles corrupted TC gracefully");
        assert_eq!(count, 2);

        let tm0 = PusPacket::parse(&out_frames[0][..out_lens[0]]).expect("TM[1,2]");
        assert!(matches!(
            tm0.decode_service().expect("ST[01]"),
            PusService::Verification(VerificationReport::AcceptanceFailure {
                failure_code: ERR_CODE_CRC_MISMATCH,
                ..
            })
        ));

        let tm1 = PusPacket::parse(&out_frames[1][..out_lens[1]]).expect("TM[5,2]");
        assert!(matches!(
            tm1.decode_service().expect("ST[05]"),
            PusService::Event(EventReport {
                severity: EventSeverity::LowAnomaly,
                event_id: EVENT_ID_CORRUPTED_TC,
                ..
            })
        ));
    }
}
