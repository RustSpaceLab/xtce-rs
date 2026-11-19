//! `xtce sim` — deterministic mission telemetry simulator with fault-injection scenarios.
//!
//! Generates reproducible CCSDS / ECSS-E-ST-70-41C (PUS-C) telemetry streams driven by a
//! deterministic 64-bit SplitMix64 PRNG (`--seed`). Every packet produced is described by the
//! canonical `xtce pus --emit-xtce` mission definition, enabling end-to-end testing of
//! `xtce decode`, `xtce pus`, `xtce pcap`, and Wireshark dissectors under both nominal
//! orbital conditions and realistic spacecraft fault scenarios.

use std::io::{Cursor, Write};
use std::path::Path;

use xtce_decode::PacketReader;
use xtce_pus::{CucTimestamp, MAX_HIL_FRAME_LEN, ObcHousekeeping, TmParams, encode_tm};

use crate::pcap;

/// Fault-injection or nominal simulation profile.
#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Scenario {
    /// Nominal orbital pass: stable 28.2 V bus, 22.5 °C OBC, and periodic `TM[3,25]` / `TM[17,2]`.
    Nominal,
    /// Eclipse battery under-voltage: bus drops to 21.4 V, triggering `TM[5,2]` and `SAFE` mode.
    VoltageDrop,
    /// Thermal runaway: OBC rises to +68.5 °C, triggering `TM[5,2]` anomaly and `SAFE` mode.
    Overheat,
    /// RF downlink dropout: sequence counter jumps across a lost window, followed by link recovery.
    CommLoss,
    /// On-board watchdog reset mid-pass: uptime and sequence counters reset with a boot event.
    Reboot,
}

/// Configuration for `xtce sim`.
pub struct Options<'a> {
    pub scenario: Scenario,
    pub packets: usize,
    pub seed: u64,
    pub pcap_format: bool,
    pub out: Option<&'a Path>,
}

/// Deterministic SplitMix64 pseudo-random number generator.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    const fn jitter_i16(&mut self, span: u16) -> i16 {
        if span == 0 {
            return 0;
        }
        let r = (self.next_u64() % ((span as u64) * 2 + 1)) as i16;
        r - (span as i16)
    }
}

/// Generates a deterministic sequence of CCSDS / ECSS PUS-C packets for `scenario`.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub fn generate_stream(scenario: Scenario, packet_count: usize, seed: u64) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    let mut stream = Vec::with_capacity(packet_count * 36);

    let apid: u16 = 0x010;
    let destination_id: u16 = 0x0001;
    let mut seq_count: u16 = 0;
    let mut msg_counter: u16 = 0;
    let mut uptime_s: u32 = 100;
    let mut mode: u8 = 2; // NOMINAL
    let mut frame_buf = [0u8; MAX_HIL_FRAME_LEN];

    let fault_step = (packet_count / 2).max(1);

    for step in 0..packet_count {
        uptime_s = uptime_s.wrapping_add(1);
        let v_jitter = rng.jitter_i16(25);
        let t_jitter = rng.jitter_i16(10);

        let mut bus_voltage_mv: u16 = (28_200i32 + i32::from(v_jitter)) as u16;
        let mut obc_temp_cdeg: i16 = 2_250 + t_jitter;

        match scenario {
            Scenario::VoltageDrop if step >= fault_step => {
                let drop = ((step - fault_step + 1) * 900).min(6_800) as u16;
                bus_voltage_mv = bus_voltage_mv.saturating_sub(drop);
                if bus_voltage_mv < 24_000 {
                    mode = 0; // SAFE
                }
            }
            Scenario::Overheat if step >= fault_step => {
                let rise = ((step - fault_step + 1) * 650).min(4_600) as i16;
                obc_temp_cdeg = obc_temp_cdeg.saturating_add(rise);
                if obc_temp_cdeg > 5_500 {
                    mode = 0; // SAFE
                }
            }
            Scenario::CommLoss if step == fault_step => {
                seq_count = (seq_count + 17) & 0x3FFF;
            }
            Scenario::Reboot if step == fault_step => {
                uptime_s = 1;
                seq_count = 0;
                mode = 0; // Boot into SAFE mode
            }
            _ => {}
        }

        let (service, subtype, payload_len, payload) =
            if step == fault_step && scenario != Scenario::Nominal {
                let (ev_id, aux_val): (u16, u16) = match scenario {
                    Scenario::VoltageDrop => (0x1201, bus_voltage_mv),
                    Scenario::Overheat => (0x1202, obc_temp_cdeg as u16),
                    Scenario::CommLoss => (0x0502, 17),
                    Scenario::Reboot => (0x0503, 1),
                    Scenario::Nominal => (0x0000, 0),
                };
                let id_b = ev_id.to_be_bytes();
                let aux_b = aux_val.to_be_bytes();
                let mut app = [0u8; 11];
                app[0] = id_b[0];
                app[1] = id_b[1];
                app[2] = aux_b[0];
                app[3] = aux_b[1];
                (5u8, 2u8, 4usize, app)
            } else if step % 5 == 4 {
                (17u8, 2u8, 0usize, [0u8; 11])
            } else {
                let hk = ObcHousekeeping {
                    uptime_s,
                    bus_voltage_mv,
                    obc_temp_cdeg,
                    mode,
                };
                (3u8, 25u8, 11usize, hk.to_app_data())
            };

        let params = TmParams {
            apid,
            sequence_count: seq_count,
            service,
            subtype,
            msg_counter,
            destination_id,
            timestamp: CucTimestamp {
                coarse_seconds: uptime_s,
                fine_subseconds: 0,
            },
        };

        if let Ok(written) = encode_tm(&params, &payload[..payload_len], &mut frame_buf) {
            stream.extend_from_slice(&frame_buf[..written]);
        }

        seq_count = (seq_count + 1) & 0x3FFF;
        msg_counter = msg_counter.wrapping_add(1);
    }

    stream
}

/// Executes `xtce sim`.
///
/// # Errors
///
/// Returns an error if writing to the output file or stdout fails.
pub fn run(options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let raw_stream = generate_stream(options.scenario, options.packets, options.seed);

    let output_bytes = if options.pcap_format {
        let mut reader = PacketReader::new(Cursor::new(raw_stream), 0);
        let mut pcap_buf = Vec::new();
        pcap::write_stream(&mut reader, &mut pcap_buf, None)?;
        pcap_buf
    } else {
        raw_stream
    };

    match options.out {
        Some(path) if path.as_os_str() != "-" => {
            std::fs::write(path, &output_bytes)?;
            eprintln!(
                "simulated {} packet(s) (scenario={:?}, seed={}, {} bytes) to {}",
                options.packets,
                options.scenario,
                options.seed,
                output_bytes.len(),
                path.display()
            );
        }
        _ => {
            let stdout = std::io::stdout();
            let mut out = std::io::BufWriter::new(stdout.lock());
            out.write_all(&output_bytes)?;
            out.flush()?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use xtce_decode::{Decoder, PacketIter};
    use xtce_model::XtceDb;
    use xtce_pus::PusPacket;

    use super::{Scenario, generate_stream};
    use crate::pus::ECSS_PUS_XTCE_XML;

    #[test]
    fn same_seed_produces_identical_byte_stream() {
        let s1 = generate_stream(Scenario::VoltageDrop, 16, 42);
        let s2 = generate_stream(Scenario::VoltageDrop, 16, 42);
        let s3 = generate_stream(Scenario::VoltageDrop, 16, 99);

        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
    }

    #[test]
    fn every_scenario_decodes_end_to_end_through_xtce_and_pus() {
        let db = XtceDb::from_xml(ECSS_PUS_XTCE_XML).expect("PUS XTCE loads");
        let decoder = Decoder::new(&db).expect("decoder");

        for scenario in [
            Scenario::Nominal,
            Scenario::VoltageDrop,
            Scenario::Overheat,
            Scenario::CommLoss,
            Scenario::Reboot,
        ] {
            let stream = generate_stream(scenario, 12, 1337);
            let mut count = 0usize;
            for framed in PacketIter::new(&stream, 0) {
                let framed = framed.expect("well-framed CCSDS packet");
                let pus = PusPacket::parse(framed.bytes()).expect("valid CRC-16-CCITT PUS frame");
                pus.decode_service().expect("valid ECSS PUS service");

                let xtce_pkt = decoder
                    .decode(framed.bytes())
                    .expect("decodes against ECSS_PUS_XTCE_XML");
                assert!(xtce_pkt.len() >= 15);
                count += 1;
            }
            assert_eq!(count, 12);
        }
    }
}
