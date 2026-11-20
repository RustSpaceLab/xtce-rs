# xtce-cli

[![crates.io](https://img.shields.io/crates/v/xtce-cli.svg)](https://crates.io/crates/xtce-cli)

The `xtce` command-line tool: inspect XTCE definitions, stream-decode CCSDS telemetry, compile
static Rust decoders and Wireshark Lua dissectors, convert raw recordings to `.pcap`, and run
ECSS-E-ST-70-41C (PUS-C) Hardware-in-the-Loop (HIL) sessions.

## Installation

```console
$ cargo install xtce-cli
```

## Usage

```console
# 1. Inspect an XTCE definition (parameters, containers, telecommands)
$ xtce info mission.xml --verbose

# 2. Decode a CCSDS packet stream (from a file or '-' standard input) as a table, JSONL, or CSV
$ xtce decode mission.xml downlink.dat --format table
$ xtce decode mission.xml downlink.dat --format csv --raw > telemetry.csv
$ cat downlink.dat | xtce decode mission.xml - --param 'ADGPSPOS*' --no-summary

# 3. Compile an XTCE definition into a zero-allocation static Rust decoder
$ xtce codegen mission.xml -o decoder.rs

# 4. Generate a standalone Wireshark Lua dissector and wrap raw CCSDS frames in a .pcap file
$ xtce wireshark mission.xml --udp-port 5005 -o mission.lua
$ xtce pcap downlink.dat -o downlink.pcap
$ wireshark -X lua_script:mission.lua downlink.pcap

# 5. Assemble a binary CCSDS telemetry or telecommand packet from an XTCE definition
$ xtce encode ecss_pus.xml TM_3_25_ObcHousekeeping \
    --set CCSDS_SEC_HDR=1 --set CCSDS_APID=0x010 --set PUS_VERSION=2 \
    --set HK_SID=1 --set OBC_UPTIME_S=3600 --set OBC_MODE=EO_IMAGING --crc --hex

# 6. Inspect ECSS-E-ST-70-41C (PUS-C) frames, run a live UDP HIL OBC server, or emit XTCE XML
$ xtce pus --hil-demo -o hil_session.bin
$ xtce pus --hil-udp 127.0.0.1:5006
$ xtce pus --emit-xtce -o ecss_pus.xml
$ xtce decode ecss_pus.xml hil_session.bin --format table

# 7. Validate an XTCE definition or export a normalized JSON metadata dictionary
$ xtce validate ecss_pus.xml --strict
$ xtce validate ecss_pus.xml --json > metadata.json

# 8. Compare two XTCE definitions and classify changes (BREAKING, WARNING, COMPATIBLE)
$ xtce diff mission_v1.xml mission_v2.xml --fail-on-breaking

# 9. Simulate a deterministic CCSDS / ECSS PUS-C telemetry stream (with fault injection)
$ xtce sim --scenario voltage-drop --packets 20 --seed 42 -o fault_pass.bin
$ xtce sim --scenario overheat --packets 20 --seed 42 --pcap -o overheat_pass.pcap
$ xtce sim --scenario attitude-loss --packets 20 --seed 42 -o adcs_tumble.bin

# 10. Multi-target XTCE mission compiler (rust-ground, wireshark, json-schema, docs, dashboard)
$ xtce compile ecss_pus.xml --target rust-ground -o decoder.rs
$ xtce compile ecss_pus.xml --target wireshark   -o mission.lua
$ xtce compile ecss_pus.xml --target json-schema -o mission.schema.json
$ xtce compile ecss_pus.xml --target docs        -o MISSION_DICTIONARY.md
$ xtce compile ecss_pus.xml --target dashboard   -o telemetry_studio.json

# 11. Run the XTCE 1.2 Language Server Protocol (LSP) JSON-RPC server over stdio
$ xtce lsp
```

Part of [RustSpaceLab/xtce-rs](https://github.com/RustSpaceLab/xtce-rs).
