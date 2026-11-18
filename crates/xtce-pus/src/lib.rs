//! `#![no_std]` implementation of ECSS-E-ST-70-41C Packet Utilization Standard (PUS-C)
//! over CCSDS 133.0-B Space Packets, with a deterministic Hardware-in-the-Loop (HIL)
//! On-Board Computer responder.
//!
//! # Guarantees
//!
//! * **`#![no_std]` and zero heap allocations.** Every parser, encoder, and HIL responder
//!   method operates on caller-supplied byte slices so the crate can run unmodified on bare-metal
//!   flight targets (`thumbv7em-none-eabihf` Cortex-M, RISC-V, LEON/SPARC) and ground tools.
//! * **No panics.** `unwrap`, `expect`, and `panic!` are denied across the library.
//! * **End-to-end CRC-16-CCITT protection.** Every parsed and encoded frame is checked or
//!   stamped with the ECSS-E-ST-70-41C Annex B syndrome (`0x1021`, initial `0xFFFF`).

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
pub mod services;

pub use crc::{crc16_ccitt, verify_crc16_ccitt};
pub use hil::{
    ERR_CODE_CRC_MISMATCH, ERR_CODE_NOT_A_TC, ERR_CODE_UNSUPPORTED, EVENT_ID_CORRUPTED_TC,
    EVENT_ID_HK_ENABLED, MAX_HIL_FRAME_LEN, PusResponder,
};
pub use packet::{
    AckFlags, CucTimestamp, PEC_LEN, PRIMARY_HEADER_LEN, PUS_VERSION_C, PusError, PusHeader,
    PusPacket, TC_SECONDARY_HEADER_LEN, TM_SECONDARY_HEADER_LEN, TcParams, TmParams, encode_tc,
    encode_tm,
};
pub use services::{
    EventReport, EventSeverity, HousekeepingMessage, ObcHousekeeping, PusService, TestMessage,
    VerificationReport,
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

        // 1. TM[1,1] Acceptance Success
        let tm0 = PusPacket::parse(&out_frames[0][..out_lens[0]]).expect("TM[1,1]");
        assert_eq!(
            tm0.decode_service().expect("ST[01]"),
            PusService::Verification(VerificationReport::AcceptanceSuccess {
                request_id: parsed_tc.request_id,
            })
        );

        // 2. TM[17,2] Are-You-Alive Connection Test Report
        let tm1 = PusPacket::parse(&out_frames[1][..out_lens[1]]).expect("TM[17,2]");
        assert_eq!(
            tm1.decode_service().expect("ST[17]"),
            PusService::Test(TestMessage::AreYouAliveReport)
        );

        // 3. TM[1,7] Execution Complete Success
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

        // Flip one bit in the service byte to corrupt the frame over the link
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
