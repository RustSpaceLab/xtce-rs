//! ECSS-E-ST-70-41C service payload decoders and encoders (`ST[01]`, `ST[03]`, `ST[05]`, `ST[06]`,
//! `ST[08]`, `ST[11]`, `ST[12]`, `ST[17]`).

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
    /// Operational mode (`0 = SAFE`, `1 = IDLE`, `2 = NOMINAL`, `3 = EO_IMAGING`).
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

/// ECSS Service 6 (`ST[06]`) On-Board Memory Management message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemoryMessage<'a> {
    /// `TC[6,2]` — Load raw data bytes into on-board memory `memory_id` at `address`.
    LoadRaw {
        /// Target memory partition identifier (e.g. `1 = OBC_RAM`, `2 = DPU_FLASH`).
        memory_id: u8,
        /// 32-bit start address.
        address: u32,
        /// Bytes to write.
        data: &'a [u8],
    },
    /// `TC[6,5]` — Request a raw memory dump from `memory_id` at `address`.
    DumpRawRequest {
        /// Target memory partition identifier.
        memory_id: u8,
        /// 32-bit start address.
        address: u32,
        /// Number of octets requested.
        length: u16,
    },
    /// `TM[6,6]` — Raw memory dump telemetry report.
    DumpRawReport {
        /// Source memory partition identifier.
        memory_id: u8,
        /// 32-bit start address.
        address: u32,
        /// Dumped memory octets.
        data: &'a [u8],
    },
    /// `TC[6,9]` — Request a CRC-16-CCITT memory integrity scrub over `[address..address+length]`.
    CheckRawRequest {
        /// Target memory partition identifier.
        memory_id: u8,
        /// 32-bit start address.
        address: u32,
        /// Number of octets to scrub.
        length: u16,
    },
    /// `TM[6,10]` — Memory integrity check report carrying the computed CRC-16-CCITT checksum.
    CheckRawReport {
        /// Source memory partition identifier.
        memory_id: u8,
        /// 32-bit start address.
        address: u32,
        /// Number of octets scrubbed.
        length: u16,
        /// Computed CRC-16-CCITT syndrome over the region.
        checksum: u16,
    },
}

/// ECSS Service 8 (`ST[08]`) Function Management telecommand.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FunctionCall<'a> {
    /// 16-bit Mission Function Identifier (`Function_ID`).
    pub function_id: u16,
    /// Raw argument bytes passed to the on-board function.
    pub args: &'a [u8],
}

/// ECSS Service 11 (`ST[11]`) Time-Based Scheduling message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScheduleMessage<'a> {
    /// `TC[11,1]` — Enable execution of time-tagged on-board schedule activities.
    Enable,
    /// `TC[11,2]` — Disable execution of time-tagged on-board schedule activities.
    Disable,
    /// `TC[11,3]` — Reset (clear) all queued activities in the on-board command schedule.
    Reset,
    /// `TC[11,4]` — Insert a time-tagged activity into the on-board schedule.
    InsertActivity {
        /// Spacecraft CUC coarse release time (seconds) when the activity shall execute.
        release_time_s: u32,
        /// Encoded telecommand or action payload to release at `release_time_s`.
        activity_data: &'a [u8],
    },
    /// `TM[11,13]` — Schedule summary status report.
    SummaryReport {
        /// Whether the time-based scheduler is currently enabled.
        enabled: bool,
        /// Number of pending time-tagged activities waiting in the queue.
        pending_count: u16,
    },
}

/// ECSS Service 12 (`ST[12]`) On-Board Monitoring (FDIR) message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MonitoringMessage {
    /// `TC[12,1]` — Enable autonomous on-board parameter limit monitoring (FDIR).
    Enable,
    /// `TC[12,2]` — Disable autonomous on-board parameter limit monitoring.
    Disable,
    /// `TM[12,12]` — Check transition report emitted when a monitored parameter crosses a limit.
    CheckTransitionReport {
        /// Monitored parameter identifier (`Param_ID`).
        param_id: u16,
        /// Observed parameter value that triggered the transition.
        observed_value: i32,
        /// Limit threshold that was crossed.
        limit_value: i32,
    },
}

/// ECSS Service 17 (`ST[17]`) Test service message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TestMessage {
    /// `TC[17,1]` — Perform an Are-You-Alive connection test.
    AreYouAliveCommand,
    /// `TM[17,2]` — Are-You-Alive connection test report.
    AreYouAliveReport,
}

/// ECSS Service 20 (`ST[20]`) On-Board Parameter Management message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParameterManagementMessage {
    /// `TC[20,1]` — Request the current value of on-board parameter `param_id`.
    ReportRequest {
        /// 16-bit On-Board Parameter Identifier (`Param_ID`).
        param_id: u16,
    },
    /// `TM[20,2]` — Telemetry report carrying the current value of `param_id`.
    ValueReport {
        /// 16-bit On-Board Parameter Identifier (`Param_ID`).
        param_id: u16,
        /// Current 32-bit parameter value.
        value: i32,
    },
    /// `TC[20,3]` — Set the value of on-board parameter `param_id` in flight.
    SetValue {
        /// 16-bit On-Board Parameter Identifier (`Param_ID`).
        param_id: u16,
        /// New 32-bit parameter value.
        value: i32,
    },
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
    /// `ST[06]` On-Board Memory Management message.
    Memory(MemoryMessage<'a>),
    /// `ST[08]` Function Management call (`TC[8,1]`).
    Function(FunctionCall<'a>),
    /// `ST[11]` Time-Based Scheduling message.
    Schedule(ScheduleMessage<'a>),
    /// `ST[12]` On-Board Monitoring (FDIR) message.
    Monitoring(MonitoringMessage),
    /// `ST[17]` Test service message.
    Test(TestMessage),
    /// `ST[20]` On-Board Parameter Management message.
    ParameterManagement(ParameterManagementMessage),
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

        match service {
            1 => Self::decode_st01(self.header.is_telecommand(), subtype, data),
            3 => Self::decode_st03(self.header.is_telecommand(), subtype, data),
            5 => Self::decode_st05(self.header.is_telecommand(), subtype, data),
            6 => Self::decode_st06(self.header.is_telecommand(), subtype, data),
            8 => Self::decode_st08(self.header.is_telecommand(), subtype, data),
            11 => Self::decode_st11(self.header.is_telecommand(), subtype, data),
            12 => Self::decode_st12(self.header.is_telecommand(), subtype, data),
            17 => match (self.header.is_telecommand(), subtype) {
                (true, 1) => Ok(PusService::Test(TestMessage::AreYouAliveCommand)),
                (false, 2) => Ok(PusService::Test(TestMessage::AreYouAliveReport)),
                _ => Ok(PusService::Custom {
                    service,
                    subtype,
                    app_data: data,
                }),
            },
            20 => Self::decode_st20(self.header.is_telecommand(), subtype, data),
            _ => Ok(PusService::Custom {
                service,
                subtype,
                app_data: data,
            }),
        }
    }

    fn decode_st01(is_tc: bool, subtype: u8, data: &'a [u8]) -> Result<PusService<'a>, PusError> {
        match (is_tc, subtype) {
            (false, 1 | 3 | 7) => {
                if data.len() < 4 {
                    return Err(PusError::MalformedServiceData {
                        service: 1,
                        subtype,
                    });
                }
                let request_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let report = match subtype {
                    1 => VerificationReport::AcceptanceSuccess { request_id },
                    3 => VerificationReport::ExecutionStartSuccess { request_id },
                    _ => VerificationReport::ExecutionCompleteSuccess { request_id },
                };
                Ok(PusService::Verification(report))
            }
            (false, 2 | 8) => {
                if data.len() < 6 {
                    return Err(PusError::MalformedServiceData {
                        service: 1,
                        subtype,
                    });
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
            _ => Ok(PusService::Custom {
                service: 1,
                subtype,
                app_data: data,
            }),
        }
    }

    fn decode_st03(is_tc: bool, subtype: u8, data: &'a [u8]) -> Result<PusService<'a>, PusError> {
        match (is_tc, subtype) {
            (true, 5 | 6 | 27) => {
                if data.len() < 2 {
                    return Err(PusError::MalformedServiceData {
                        service: 3,
                        subtype,
                    });
                }
                let sid = u16::from_be_bytes([data[0], data[1]]);
                let msg = match subtype {
                    5 => HousekeepingMessage::EnablePeriodic { sid },
                    6 => HousekeepingMessage::DisablePeriodic { sid },
                    _ => HousekeepingMessage::OneShotRequest { sid },
                };
                Ok(PusService::Housekeeping(msg))
            }
            (false, 25) => {
                if data.len() < 2 {
                    return Err(PusError::MalformedServiceData {
                        service: 3,
                        subtype,
                    });
                }
                let sid = u16::from_be_bytes([data[0], data[1]]);
                Ok(PusService::Housekeeping(
                    HousekeepingMessage::ParameterReport {
                        sid,
                        parameters: &data[2..],
                    },
                ))
            }
            _ => Ok(PusService::Custom {
                service: 3,
                subtype,
                app_data: data,
            }),
        }
    }

    fn decode_st05(is_tc: bool, subtype: u8, data: &'a [u8]) -> Result<PusService<'a>, PusError> {
        if is_tc || !(1..=4).contains(&subtype) {
            return Ok(PusService::Custom {
                service: 5,
                subtype,
                app_data: data,
            });
        }
        if data.len() < 2 {
            return Err(PusError::MalformedServiceData {
                service: 5,
                subtype,
            });
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

    fn decode_st06(is_tc: bool, subtype: u8, data: &'a [u8]) -> Result<PusService<'a>, PusError> {
        match (is_tc, subtype) {
            (true, 2) | (false, 6) => {
                if data.len() < 5 {
                    return Err(PusError::MalformedServiceData {
                        service: 6,
                        subtype,
                    });
                }
                let memory_id = data[0];
                let address = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let msg = if is_tc {
                    MemoryMessage::LoadRaw {
                        memory_id,
                        address,
                        data: &data[5..],
                    }
                } else {
                    MemoryMessage::DumpRawReport {
                        memory_id,
                        address,
                        data: &data[5..],
                    }
                };
                Ok(PusService::Memory(msg))
            }
            (true, 5 | 9) => {
                if data.len() < 7 {
                    return Err(PusError::MalformedServiceData {
                        service: 6,
                        subtype,
                    });
                }
                let memory_id = data[0];
                let address = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let length = u16::from_be_bytes([data[5], data[6]]);
                let msg = if subtype == 5 {
                    MemoryMessage::DumpRawRequest {
                        memory_id,
                        address,
                        length,
                    }
                } else {
                    MemoryMessage::CheckRawRequest {
                        memory_id,
                        address,
                        length,
                    }
                };
                Ok(PusService::Memory(msg))
            }
            (false, 10) => {
                if data.len() < 9 {
                    return Err(PusError::MalformedServiceData {
                        service: 6,
                        subtype,
                    });
                }
                let memory_id = data[0];
                let address = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let length = u16::from_be_bytes([data[5], data[6]]);
                let checksum = u16::from_be_bytes([data[7], data[8]]);
                Ok(PusService::Memory(MemoryMessage::CheckRawReport {
                    memory_id,
                    address,
                    length,
                    checksum,
                }))
            }
            _ => Ok(PusService::Custom {
                service: 6,
                subtype,
                app_data: data,
            }),
        }
    }

    fn decode_st08(is_tc: bool, subtype: u8, data: &'a [u8]) -> Result<PusService<'a>, PusError> {
        if !is_tc || subtype != 1 {
            return Ok(PusService::Custom {
                service: 8,
                subtype,
                app_data: data,
            });
        }
        if data.len() < 2 {
            return Err(PusError::MalformedServiceData {
                service: 8,
                subtype,
            });
        }
        let function_id = u16::from_be_bytes([data[0], data[1]]);
        Ok(PusService::Function(FunctionCall {
            function_id,
            args: &data[2..],
        }))
    }

    fn decode_st11(is_tc: bool, subtype: u8, data: &'a [u8]) -> Result<PusService<'a>, PusError> {
        match (is_tc, subtype) {
            (true, 1) => Ok(PusService::Schedule(ScheduleMessage::Enable)),
            (true, 2) => Ok(PusService::Schedule(ScheduleMessage::Disable)),
            (true, 3) => Ok(PusService::Schedule(ScheduleMessage::Reset)),
            (true, 4) => {
                if data.len() < 4 {
                    return Err(PusError::MalformedServiceData {
                        service: 11,
                        subtype,
                    });
                }
                let release_time_s = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(PusService::Schedule(ScheduleMessage::InsertActivity {
                    release_time_s,
                    activity_data: &data[4..],
                }))
            }
            (false, 13) => {
                if data.len() < 3 {
                    return Err(PusError::MalformedServiceData {
                        service: 11,
                        subtype,
                    });
                }
                let enabled = data[0] != 0;
                let pending_count = u16::from_be_bytes([data[1], data[2]]);
                Ok(PusService::Schedule(ScheduleMessage::SummaryReport {
                    enabled,
                    pending_count,
                }))
            }
            _ => Ok(PusService::Custom {
                service: 11,
                subtype,
                app_data: data,
            }),
        }
    }

    fn decode_st12(is_tc: bool, subtype: u8, data: &'a [u8]) -> Result<PusService<'a>, PusError> {
        match (is_tc, subtype) {
            (true, 1) => Ok(PusService::Monitoring(MonitoringMessage::Enable)),
            (true, 2) => Ok(PusService::Monitoring(MonitoringMessage::Disable)),
            (false, 12) => {
                if data.len() < 10 {
                    return Err(PusError::MalformedServiceData {
                        service: 12,
                        subtype,
                    });
                }
                let param_id = u16::from_be_bytes([data[0], data[1]]);
                let observed_value = i32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                let limit_value = i32::from_be_bytes([data[6], data[7], data[8], data[9]]);
                Ok(PusService::Monitoring(
                    MonitoringMessage::CheckTransitionReport {
                        param_id,
                        observed_value,
                        limit_value,
                    },
                ))
            }
            _ => Ok(PusService::Custom {
                service: 12,
                subtype,
                app_data: data,
            }),
        }
    }

    fn decode_st20(is_tc: bool, subtype: u8, data: &'a [u8]) -> Result<PusService<'a>, PusError> {
        match (is_tc, subtype) {
            (true, 1) => {
                if data.len() < 2 {
                    return Err(PusError::MalformedServiceData {
                        service: 20,
                        subtype,
                    });
                }
                let param_id = u16::from_be_bytes([data[0], data[1]]);
                Ok(PusService::ParameterManagement(
                    ParameterManagementMessage::ReportRequest { param_id },
                ))
            }
            (false, 2) | (true, 3) => {
                if data.len() < 6 {
                    return Err(PusError::MalformedServiceData {
                        service: 20,
                        subtype,
                    });
                }
                let param_id = u16::from_be_bytes([data[0], data[1]]);
                let value = i32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                let msg = if is_tc {
                    ParameterManagementMessage::SetValue { param_id, value }
                } else {
                    ParameterManagementMessage::ValueReport { param_id, value }
                };
                Ok(PusService::ParameterManagement(msg))
            }
            _ => Ok(PusService::Custom {
                service: 20,
                subtype,
                app_data: data,
            }),
        }
    }
}
