//! Python bindings for `xtce-rs`.
//!
//! ```python
//! import xtce
//!
//! definition = xtce.Definition("jpss1_geolocation_xtce_v1.xml")
//! with open("telemetry.dat", "rb") as fh:
//!     packets = definition.decode_stream(fh.read())
//!
//! print(len(packets), packets[0]["PKT_APID"])
//! ```
//!
//! # Why the API is batch-shaped
//!
//! The decoder is roughly a hundred times faster than the Python reference, and a per-packet
//! call would give none of that back: the cost would be the interpreter round trip, not the
//! decoding. [`Definition::decode_stream`] frames and decodes a whole buffer in one call and
//! releases the GIL for the Rust part, so other threads run while it works and the speed-up
//! survives contact with Python.
//!
//! Values are decoded into owned Rust values with the GIL released, then converted in one
//! pass with it held. Parameter names become interned Python strings once, when the
//! definition is loaded, so building a packet's dictionary does not allocate a string per
//! field per packet.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic)]
#![allow(clippy::needless_pass_by_value)]

use std::path::PathBuf;

use pyo3::exceptions::{PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyString};
use xtce_decode::{DecodeError, Decoder, EngValue, PacketIter, RawValue};
use xtce_model::{ParamId, XtceDb};

/// A decoded value on its way from Rust to Python.
///
/// Materialised while the GIL is released, so it cannot hold Python objects, and owned, so it
/// cannot borrow from the packet buffer.
enum Value {
    Int(i128),
    Float(f64),
    Bool(bool),
    Text(String),
    Bytes(Vec<u8>),
}

impl Value {
    fn from_raw(raw: &RawValue<'_>) -> Self {
        match raw {
            RawValue::Unsigned(value) => Self::Int(i128::from(*value)),
            RawValue::Signed(value) => Self::Int(i128::from(*value)),
            RawValue::Float(value) => Self::Float(*value),
            RawValue::Bytes(bytes) => Self::Bytes(bytes.to_vec()),
        }
    }

    fn from_eng(eng: &EngValue<'_, '_>) -> Self {
        match eng {
            EngValue::Unsigned(value) => Self::Int(i128::from(*value)),
            EngValue::Signed(value) => Self::Int(i128::from(*value)),
            EngValue::Float(value) => Self::Float(*value),
            EngValue::Bool(value) => Self::Bool(*value),
            EngValue::Label(text) => Self::Text((*text).to_owned()),
            EngValue::Text(text) => Self::Text(text.as_ref().to_owned()),
            EngValue::Bytes(bytes) => Self::Bytes(bytes.to_vec()),
        }
    }

    fn into_py(self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        Ok(match self {
            // XTCE integers are at most 64 bits wide, so this never loses precision; `i128`
            // is only the carrier that holds both signed and unsigned ranges.
            Self::Int(value) => value.into_pyobject(py)?.into_any().unbind(),
            Self::Float(value) => value.into_pyobject(py)?.into_any().unbind(),
            Self::Bool(value) => value
                .into_pyobject(py)
                .map(|value| value.to_owned().into_any().unbind())?,
            Self::Text(value) => value.into_pyobject(py)?.into_any().unbind(),
            Self::Bytes(value) => PyBytes::new(py, &value).into_any().unbind(),
        })
    }
}

/// One decoded packet, before it becomes a Python dictionary.
struct DecodedRow {
    container: &'static str,
    fields: Vec<(ParamId, Value)>,
}

/// An XTCE telemetry definition, loaded and ready to decode against.
#[pyclass(module = "xtce", frozen)]
struct Definition {
    db: XtceDb,
    /// Parameter names as interned Python strings, indexed by parameter id.
    ///
    /// Built once. Every decoded packet reuses them as dictionary keys, so a stream of seven
    /// thousand packets allocates no strings for names at all.
    names: Vec<Py<PyString>>,
    source: Option<PathBuf>,
}

#[pymethods]
impl Definition {
    /// Loads a definition from an XTCE file.
    #[new]
    #[pyo3(signature = (path))]
    fn new(py: Python<'_>, path: PathBuf) -> PyResult<Self> {
        let db = XtceDb::from_path(&path).map_err(to_py_error)?;
        let names = intern_names(py, &db)?;
        Ok(Self {
            db,
            names,
            source: Some(path),
        })
    }

    /// Loads a definition from a string of XTCE XML.
    #[staticmethod]
    fn from_string(py: Python<'_>, xml: &str) -> PyResult<Self> {
        let db = XtceDb::from_xml(xml).map_err(to_py_error)?;
        let names = intern_names(py, &db)?;
        Ok(Self {
            db,
            names,
            source: None,
        })
    }

    /// The file this definition was loaded from, if it came from one.
    #[getter]
    fn source(&self) -> Option<&str> {
        self.source.as_deref().and_then(|path| path.to_str())
    }

    /// Number of parameters defined.
    #[getter]
    fn parameter_count(&self) -> usize {
        self.db.parameters().len()
    }

    /// Number of containers defined.
    #[getter]
    fn container_count(&self) -> usize {
        self.db.containers().len()
    }

    /// Every parameter name, in definition order.
    fn parameter_names(&self) -> Vec<&str> {
        self.db
            .parameters()
            .iter()
            .map(|parameter| self.db.name(parameter.name))
            .collect()
    }

    /// Every container name, in definition order.
    fn container_names(&self) -> Vec<&str> {
        self.db
            .containers()
            .iter()
            .map(|container| self.db.name(container.name))
            .collect()
    }

    /// Constructs this crate lists as modelled but not decodable.
    ///
    /// Each entry is `(element, path, reason)`. An empty list means every construct in the
    /// file is within the decodable subset.
    fn unsupported(&self) -> Vec<(String, String, String)> {
        self.db
            .unsupported()
            .iter()
            .map(|item| {
                (
                    item.element.clone(),
                    item.path.clone(),
                    item.reason.to_owned(),
                )
            })
            .collect()
    }

    /// Decodes every CCSDS packet in `data`.
    ///
    /// Returns one dictionary per packet, mapping parameter name to value. The Rust decoding
    /// runs with the GIL released.
    ///
    /// `raw=True` returns the values as encoded in the packet rather than after calibration
    /// and enumeration lookup. `skip_unrecognized=True` drops packets whose type the
    /// definition does not describe instead of raising.
    #[pyo3(signature = (data, *, skip_header_bytes = 0, root = None, raw = false, skip_unrecognized = false))]
    fn decode_stream(
        &self,
        py: Python<'_>,
        data: &[u8],
        skip_header_bytes: usize,
        root: Option<&str>,
        raw: bool,
        skip_unrecognized: bool,
    ) -> PyResult<Vec<Py<PyDict>>> {
        let decoder = self.decoder(root)?;

        // The Rust half runs without the GIL, so other Python threads keep running. Nothing
        // in here touches a Python object: values are materialised as owned Rust values and
        // converted below.
        let rows = py.detach(|| {
            decode_rows(&decoder, data, skip_header_bytes, raw, skip_unrecognized)
        })?;

        rows.into_iter()
            .map(|row| self.row_to_dict(py, row))
            .collect()
    }

    /// Decodes one CCSDS packet, header included.
    #[pyo3(signature = (data, *, root = None, raw = false))]
    fn decode(
        &self,
        py: Python<'_>,
        data: &[u8],
        root: Option<&str>,
        raw: bool,
    ) -> PyResult<Py<PyDict>> {
        let decoder = self.decoder(root)?;
        let packet = decoder.decode(data).map_err(decode_error)?;
        let row = row_from_packet(&packet, raw);
        self.row_to_dict(py, row)
    }

    /// Decodes every packet and returns the container each matched.
    ///
    /// Useful for surveying a stream without materialising its values.
    #[pyo3(signature = (data, *, skip_header_bytes = 0, root = None))]
    fn container_of_each(
        &self,
        py: Python<'_>,
        data: &[u8],
        skip_header_bytes: usize,
        root: Option<&str>,
    ) -> PyResult<Vec<&'static str>> {
        let decoder = self.decoder(root)?;
        py.detach(|| {
            let mut out = Vec::new();
            let mut packet = decoder.new_packet(data);
            for framed in PacketIter::new(data, skip_header_bytes) {
                let framed = framed.map_err(|error| PyValueError::new_err(error.to_string()))?;
                decoder
                    .decode_into(&mut packet, framed.bytes())
                    .map_err(decode_error)?;
                out.push(container_name(&decoder, packet.container()));
            }
            Ok(out)
        })
    }

    fn __repr__(&self) -> String {
        let stats = self.db.stats();
        format!(
            "<xtce.Definition {} parameter(s), {} container(s){}>",
            stats.parameters,
            stats.containers,
            self.source
                .as_deref()
                .and_then(|path| path.to_str())
                .map(|path| format!(" from {path}"))
                .unwrap_or_default()
        )
    }
}

impl Definition {
    fn decoder(&self, root: Option<&str>) -> PyResult<Decoder<'_>> {
        match root {
            Some(name) => Decoder::with_root(&self.db, name),
            None => Decoder::new(&self.db),
        }
        .map_err(decode_error)
    }

    fn row_to_dict(&self, py: Python<'_>, row: DecodedRow) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        for (parameter, value) in row.fields {
            let key = self
                .names
                .get(parameter.index())
                .ok_or_else(|| PyKeyError::new_err("parameter index out of range"))?;
            dict.set_item(key, value.into_py(py)?)?;
        }
        // Recorded under a dunder key so it cannot collide with a parameter name.
        dict.set_item("__container__", row.container)?;
        Ok(dict.unbind())
    }
}

/// Decodes a whole stream into owned rows, with no Python involvement.
fn decode_rows(
    decoder: &Decoder<'_>,
    data: &[u8],
    skip_header_bytes: usize,
    raw: bool,
    skip_unrecognized: bool,
) -> PyResult<Vec<DecodedRow>> {
    let mut rows = Vec::new();
    let mut packet = decoder.new_packet(data);

    for framed in PacketIter::new(data, skip_header_bytes) {
        let framed = framed.map_err(|error| PyValueError::new_err(error.to_string()))?;
        match decoder.decode_into(&mut packet, framed.bytes()) {
            Ok(()) => rows.push(row_from_packet(&packet, raw)),
            Err(DecodeError::UnrecognizedPacket { .. }) if skip_unrecognized => {}
            Err(error) => return Err(decode_error(error)),
        }
    }
    Ok(rows)
}

fn row_from_packet(packet: &xtce_decode::DecodedPacket<'_, '_>, raw: bool) -> DecodedRow {
    DecodedRow {
        container: container_name_from(packet),
        fields: packet
            .values()
            .iter()
            .map(|value| {
                let converted = if raw {
                    Value::from_raw(&value.raw)
                } else {
                    Value::from_eng(&value.eng)
                };
                (value.parameter, converted)
            })
            .collect(),
    }
}

/// Container names are borrowed from the definition, which outlives every call into it, but
/// the row type has to be free of borrows to survive `Python::detach`. Leaking the name once
/// per distinct container is bounded by the number of containers in the file, which is a
/// property of the definition and not of the traffic.
fn container_name_from(packet: &xtce_decode::DecodedPacket<'_, '_>) -> &'static str {
    let db = packet.db();
    db.container(packet.container())
        .map_or("?", |container| leak_name(db.name(container.name)))
}

fn container_name(decoder: &Decoder<'_>, id: xtce_model::ContainerId) -> &'static str {
    let db = decoder.db();
    db.container(id)
        .map_or("?", |container| leak_name(db.name(container.name)))
}

/// Interns a container name for the lifetime of the process.
fn leak_name(name: &str) -> &'static str {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};

    static NAMES: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let names = NAMES.get_or_init(|| Mutex::new(HashSet::new()));
    let Ok(mut names) = names.lock() else {
        return "?";
    };
    if let Some(existing) = names.get(name) {
        return existing;
    }
    let leaked: &'static str = Box::leak(name.to_owned().into_boxed_str());
    names.insert(leaked);
    leaked
}

fn intern_names(py: Python<'_>, db: &XtceDb) -> PyResult<Vec<Py<PyString>>> {
    db.parameters()
        .iter()
        .map(|parameter| {
            PyString::new(py, db.name(parameter.name))
                .into_pyobject(py)
                .map(pyo3::Bound::unbind)
                .map_err(PyErr::from)
        })
        .collect()
}

fn to_py_error(error: xtce_model::XtceError) -> PyErr {
    PyValueError::new_err(error.to_string())
}

fn decode_error(error: DecodeError) -> PyErr {
    PyValueError::new_err(error.to_string())
}

/// The `xtce` extension module.
#[pymodule]
fn xtce(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Definition>()?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add(
        "__doc__",
        "Decode CCSDS telemetry packets against an XTCE definition.",
    )?;
    Ok(())
}
