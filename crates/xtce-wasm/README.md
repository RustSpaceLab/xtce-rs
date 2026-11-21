# `xtce-wasm`

Zero-bindgen client-side WebAssembly (`wasm32-unknown-unknown`) XTCE 1.2 and ECSS-E-ST-70-41C (PUS-C) telemetry, Wireshark `.pcap` decoder, and closed-loop `#![no_std]` HIL OBC Telecommand & SipHash-2-4 cryptographic builder.

## Build

```bash
rustup target add wasm32-unknown-unknown
cargo build -p xtce-wasm --target wasm32-unknown-unknown --release
```

## Exported WebAssembly C-ABI Functions

- `wasm_alloc(len: usize) -> *mut u8`
- `wasm_free(ptr: *mut u8, len: usize)`
- `wasm_result_ptr() -> *const u8`
- `wasm_result_len() -> usize`
- `wasm_inspect_xtce(xml_ptr: *const u8, xml_len: usize) -> i32`
- `wasm_decode_xtce_and_packets(xml_ptr: *const u8, xml_len: usize, pkt_ptr: *const u8, pkt_len: usize, max_packets: usize) -> i32`
- `wasm_generate_pus_stream(scenario_id: u32, packet_count: usize, seed: u64, as_pcap: u32) -> i32`
- `wasm_encode_pus_tc_and_hil(apid: u16, seq_count: u16, service: u8, subtype: u8, source_id: u16, app_data_ptr: *const u8, app_data_len: usize, corrupt_crc: u32, sign_auth: u32, counter: u32) -> i32`

