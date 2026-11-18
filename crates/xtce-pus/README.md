# xtce-pus

[![crates.io](https://img.shields.io/crates/v/xtce-pus.svg)](https://crates.io/crates/xtce-pus)
[![docs.rs](https://docs.rs/xtce-pus/badge.svg)](https://docs.rs/xtce-pus)

`#![no_std]`, zero-allocation implementation of the European Cooperation for Space
Standardization **ECSS-E-ST-70-41C Packet Utilization Standard (PUS-C)** over CCSDS 133.0-B
Space Packets, with a bare-metal Hardware-in-the-Loop (HIL) spacecraft responder.

## Capabilities

- **CRC-16-CCITT (`0x1021`, initial `0xFFFF`)** per ECSS-E-ST-70-41C Annex B (compile-time lookup table, zero branches).
- **PUS-C Telemetry (`TM`) and Telecommand (`TC`) secondary headers**, including CUC (4+2 octet) spacecraft time and telecommand acknowledgement flags (`AckFlags`).
- **Core ECSS PUS Services**:
  - **ST\[01\] Request Verification**: `TM[1,1]` Acceptance Success, `TM[1,2]` Acceptance Failure, `TM[1,3]` Execution Start, `TM[1,7]` Execution Complete Success, `TM[1,8]` Execution Complete Failure.
  - **ST\[03\] Housekeeping**: `TC[3,5]` Enable HK, `TC[3,6]` Disable HK, `TC[3,27]` One-Shot HK Request, `TM[3,25]` Housekeeping Parameter Report (`ObcHousekeeping`).
  - **ST\[05\] Event Reporting**: `TM[5,1]` Informative Event through `TM[5,4]` High-Severity Anomaly.
  - **ST\[17\] Test Service**: `TC[17,1]` Are-You-Alive Connection Test and `TM[17,2]` Are-You-Alive Connection Report.
- **`PusResponder` HIL State Machine**: deterministic, zero-heap flight responder suitable for `thumbv7em-none-eabihf` (STM32 Cortex-M), RISC-V (ESP32), RP2040/RP2350, or desktop HIL benches.

## Installation

```toml
[dependencies]
xtce-pus = "0.1"
```

## Example: Closed-Loop `ST[17]` Ping & `ST[01]` Verification (`#![no_std]`)

```rust
use xtce_pus::{
    AckFlags, MAX_HIL_FRAME_LEN, PusPacket, PusResponder, PusService, TcParams, TestMessage,
    VerificationReport, encode_tc,
};

let mut obc = PusResponder::new(0x010, 0x0001);

// 1. Ground encodes a TC[17,1] Are-You-Alive telecommand into a stack buffer
let mut tc_buf = [0u8; 32];
let tc_len = encode_tc(
    &TcParams {
        apid: 0x010,
        sequence_count: 1,
        ack: AckFlags::ACCEPT_AND_COMPLETE,
        service: 17,
        subtype: 1,
        source_id: 0x0042,
    },
    &[],
    &mut tc_buf,
)?;

// 2. Bare-metal OBC responder processes the telecommand without heap allocations
let mut tm_frames = [[0u8; MAX_HIL_FRAME_LEN]; 4];
let mut tm_lens = [0usize; 4];
let emitted = obc.process_telecommand(&tc_buf[..tc_len], &mut tm_frames, &mut tm_lens)?;
assert_eq!(emitted, 3); // TM[1,1] Acceptance + TM[17,2] Alive Report + TM[1,7] Complete

// 3. Ground parses and verifies the downlinked TM[17,2] frame (including CRC-16-CCITT)
let report = PusPacket::parse(&tm_frames[1][..tm_lens[1]])?;
assert_eq!(
    report.decode_service()?,
    PusService::Test(TestMessage::AreYouAliveReport)
);
# Ok::<(), xtce_pus::PusError>(())
```

Part of [RustSpaceLab/xtce-rs](https://github.com/RustSpaceLab/xtce-rs).
