# xtce-pus

`#![no_std]`, zero-allocation implementation of the European Cooperation for Space
Standardization **ECSS-E-ST-70-41C Packet Utilization Standard (PUS-C)** over CCSDS 133.0-B
Space Packets, with a bare-metal Hardware-in-the-Loop (HIL) spacecraft responder.

## Capabilities

- **CRC-16-CCITT (`0x1021`, initial `0xFFFF`)** per ECSS-E-ST-70-41C Annex B (compile-time lookup table, zero branches).
- **PUS-C Telemetry (`TM`) and Telecommand (`TC`) secondary headers**, including CUC (4+2 octet) spacecraft time and telecommand acknowledgement flags.
- **Core ECSS PUS Services**:
  - **ST\[01\] Request Verification**: `TM[1,1]` Acceptance Success, `TM[1,2]` Acceptance Failure, `TM[1,7]` Execution Complete Success, `TM[1,8]` Execution Complete Failure.
  - **ST\[03\] Housekeeping**: `TC[3,5]` Enable HK, `TC[3,6]` Disable HK, `TC[3,27]` One-Shot HK Request, `TM[3,25]` Housekeeping Parameter Report.
  - **ST\[05\] Event Reporting**: `TM[5,1]` Informative Event through `TM[5,4]` High-Severity Anomaly.
  - **ST\[17\] Test Service**: `TC[17,1]` Are-You-Alive Connection Test and `TM[17,2]` Are-You-Alive Connection Report.
- **`PusResponder` HIL State Machine**: zero-heap flight responder suitable for `thumbv7em-none-eabihf` (STM32), RISC-V (ESP32), or desktop HIL benches.
