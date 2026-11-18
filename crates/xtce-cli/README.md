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
```

Part of [RustSpaceLab/xtce-rs](https://github.com/RustSpaceLab/xtce-rs).
