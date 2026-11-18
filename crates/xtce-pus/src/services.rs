//! ECSS-E-ST-70-41C service payload decoders and encoders (`ST[01]`, `ST[03]`, `ST[05]`, `ST[17]`).

use crate::packet::{PusError, PusPacket};

/// ECSS Service 1 (`ST[01]`) Request Verification telemetry report.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerificationReport {
    /// `TM[1,1]` — Telecommand acceptance verification succeeded.
    AcceptanceSuccess {
        /// 32-bit CCSDS Request ID of the accepted telecommand.
        request_id: u32,
    },
    /// `TM[1,2]` — Telecommand acceptance verification failed.
    AcceptanceFailure {
        /// 32-bit CCSDS Request ID of the rejected telecommand.
        request_id: u32,
        /// Mission-defined failure reason code.
        failure_code: u16,
    },
    /// `TM[1,3]` — Telecommand start of execution succeeded.
    ExecutionStartSuccess {
        /// 32-bit CCSDS Request ID of the started telecommand.
        request_id: u32,
    },
    /// `TM[1,7]` — Telecommand completion of execution succeeded.
    ExecutionCompleteSuccess {
        /// 32-bit CCSDS Request ID of the completed telecommand.
        request_id: u32,
    },
    /// `TM[1,8]` — Telecommand completion of execution failed.
    ExecutionCompleteFailure {
        /// 32-bit CCSDS Request ID of the failed telecommand.
        request_id: u32,
        /// Mission-defined failure reason code.
        failure_code: u16,
    },
}

/// ECSS Service 3 (`ST[03]`) Housekeeping & Diagnostic message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HousekeepingMessage<'a> {
    /// `TC[3,5]` — Enable periodic generation of housekeeping structure `sid`.
    EnablePeriodic {
        /// Structure Identifier (`SID`).
        sid: u16,
    },
    /// `TC[3,6]` — Disable periodic generation of housekeeping structure `sid`.
    DisablePeriodic {
        /// Structure Identifier (`SID`).
        sid: u16,
    },
    /// `TC[3,27]` — Request a one-shot housekeeping report for structure `sid`.
    OneShotRequest {
        /// Structure Identifier (`SID`).
        sid: u16,
    },
    /// `TM[3,25]` — Housekeeping parameter report for structure `sid`.
    ParameterReport {
        /// Structure Identifier (`SID`).
        sid: u16,
        /// Raw parameter values following the 16-bit `SID`.
        parameters: &'a [u8],
    },
}

/// Standard 9-octet On-Board Computer (OBC) housekeeping structure (`SID = 1`) for HIL testing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObcHousekeeping {
    /// Spacecraft uptime in seconds.
    pub uptime_s: u32,
    /// Primary power bus voltage in millivolts (e.g. `28_150` for 28.15 V).
    pub bus_voltage_mv: u16,
    /// OBC board temperature in centi-degrees Celsius (e.g. `2350` for 23.50 °C).
    pub obc_temp_cdeg: i16,
    /// Operational mode (`0 = SAFE`, `1 = IDLE`, `2 = NOMINAL`, `3 = SCIENCE`).
    pub mode: u8,
}

impl ObcHousekeeping {
    /// Structure Identifier (`SID`) used for OBC core housekeeping in `TM[3,25]`.
    pub const SID: u16 = 1;

    /// Encodes the structure into a 11-byte `TM[3,25]` application data payload (`SID` + 9 bytes).
    #[must_use]
    pub const fn to_app_data(self) -> [u8; 11] {
        let sid = Self::SID.to_be_bytes();
        let up = self.uptime_s.to_be_bytes();
        let v = self.bus_voltage_mv.to_be_bytes();
        let t = self.obc_temp_cdeg.to_be_bytes();
        [
            sid[0], sid[1], up[0], up[1], up[2], up[3], v[0], v[1], t[0], t[1], self.mode,
        ]
    }

    /// Decodes an `ObcHousekeeping` payload from the `parameters` slice of a `TM[3,25]` report.
    #[must_use]
    pub const fn from_parameter_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 {
            return None;
        }
        let uptime_s = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let bus_voltage_mv = u16::from_be_bytes([bytes[4], bytes[5]]);
        let obc_temp_cdeg = i16::from_be_bytes([bytes[6], bytes[7]]);
        let mode = bytes[8];
        Some(Self {
            uptime_s,
            bus_voltage_mv,
            obc_temp_cdeg,
            mode,
        })
    }
}

/// Severity level of an ECSS Service 5 (`ST[05]`) on-board event report.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventSeverity {
    /// `TM[5,1]` — Informative nominal event.
    Informative = 1,
    /// `TM[5,2]` — Low-severity anomaly (warning).
    LowAnomaly = 2,
    /// `TM[5,3]` — Medium-severity anomaly (recoverable fault).
    MediumAnomaly = 3,
    /// `TM[5,4]` — High-severity anomaly (critical fault / safe-mode trigger).
    HighAnomaly = 4,
}

/// ECSS Service 5 (`ST[05]`) Event Reporting telemetry payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventReport<'a> {
    /// Event severity derived from subtype `1..=4`.
    pub severity: EventSeverity,
    /// Mission-defined Event Definition ID (`Event_ID`).
    pub event_id: u16,
    /// Auxiliary diagnostic bytes following the `Event_ID`.
    pub aux_data: &'a [u8],
}

/// ECSS Service 17 (`ST[17]`) Test service message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TestMessage {
    /// `TC[17,1]` — Perform an Are-You-Alive connection test.
    AreYouAliveCommand,
    /// `TM[17,2]` — Are-You-Alive connection test report.
    AreYouAliveReport,
}

/// High-level decoded ECSS PUS service payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PusService<'a> {
    /// `ST[01]` Request Verification report.
    Verification(VerificationReport),
    /// `ST[03]` Housekeeping & Diagnostic message.
    Housekeeping(HousekeepingMessage<'a>),
    /// `ST[05]` Event Report.
    Event(EventReport<'a>),
    /// `ST[17]` Test service message.
    Test(TestMessage),
    /// Any other service/subtype pair with its raw application data slice.
    Custom {
        /// ECSS service type (`ST[x]`).
        service: u8,
        /// ECSS message subtype (`TM/TC[x,y]`).
        subtype: u8,
        /// Uninterpreted application data.
        app_data: &'a [u8],
    },
}

impl<'a> PusPacket<'a> {
    /// Decodes the service-specific application data of this packet into a [`PusService`].
    ///
    /// # Errors
    ///
    /// Returns [`PusError::MalformedServiceData`] if a known service/subtype has fewer
    /// application data bytes than the ECSS standard mandates.
    pub fn decode_service(&self) -> Result<PusService<'a>, PusError> {
        let service = self.header.service();
        let subtype = self.header.subtype();
        let data = self.app_data;

        match (self.header.is_telecommand(), service, subtype) {
            (false, 1, 1 | 3 | 7) => {
                if data.len() < 4 {
                    return Err(PusError::MalformedServiceData { service, subtype });
                }
                let request_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let report = match subtype {
                    1 => VerificationReport::AcceptanceSuccess { request_id },
                    3 => VerificationReport::ExecutionStartSuccess { request_id },
                    _ => VerificationReport::ExecutionCompleteSuccess { request_id },
                };
                Ok(PusService::Verification(report))
            }
            (false, 1, 2 | 8) => {
                if data.len() < 6 {
                    return Err(PusError::MalformedServiceData { service, subtype });
                }
                let request_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let failure_code = u16::from_be_bytes([data[4], data[5]]);
                let report = if subtype == 2 {
                    VerificationReport::AcceptanceFailure {
                        request_id,
                        failure_code,
                    }
                } else {
                    VerificationReport::ExecutionCompleteFailure {
                        request_id,
                        failure_code,
                    }
                };
                Ok(PusService::Verification(report))
            }
            (true, 3, 5 | 6 | 27) => {
                if data.len() < 2 {
                    return Err(PusError::MalformedServiceData { service, subtype });
                }
                let sid = u16::from_be_bytes([data[0], data[1]]);
                let msg = match subtype {
                    5 => HousekeepingMessage::EnablePeriodic { sid },
                    6 => HousekeepingMessage::DisablePeriodic { sid },
                    _ => HousekeepingMessage::OneShotRequest { sid },
                };
                Ok(PusService::Housekeeping(msg))
            }
            (false, 3, 25) => {
                if data.len() < 2 {
                    return Err(PusError::MalformedServiceData { service, subtype });
                }
                let sid = u16::from_be_bytes([data[0], data[1]]);
                Ok(PusService::Housekeeping(
                    HousekeepingMessage::ParameterReport {
                        sid,
                        parameters: &data[2..],
                    },
                ))
            }
            (false, 5, 1..=4) => {
                if data.len() < 2 {
                    return Err(PusError::MalformedServiceData { service, subtype });
                }
                let severity = match subtype {
                    1 => EventSeverity::Informative,
                    2 => EventSeverity::LowAnomaly,
                    3 => EventSeverity::MediumAnomaly,
                    _ => EventSeverity::HighAnomaly,
                };
                let event_id = u16::from_be_bytes([data[0], data[1]]);
                Ok(PusService::Event(EventReport {
                    severity,
                    event_id,
                    aux_data: &data[2..],
                }))
            }
            (true, 17, 1) => Ok(PusService::Test(TestMessage::AreYouAliveCommand)),
            (false, 17, 2) => Ok(PusService::Test(TestMessage::AreYouAliveReport)),
            _ => Ok(PusService::Custom {
                service,
                subtype,
                app_data: data,
            }),
        }
    }
}
