//! The loaded telemetry database.

use std::path::{Path, PathBuf};

use crate::containers::{Container, Entry, SpaceSystem};
use crate::error::XtceError;
use crate::ids::{ContainerId, ParamId, SpaceSystemId, TypeId};
use crate::intern::{FxHashMap, Interner, NameId};
use crate::lower::Lowering;
use crate::types::{Parameter, ParameterType, TypeKind};
use crate::xml::Dom;

/// An XTCE construct that was modelled structurally but cannot be decoded.
///
/// Recording these instead of failing the load is what lets `xtce info` succeed on every
/// real mission database while still telling the truth about coverage. The corresponding
/// `XtceError::Unsupported` is raised by the decoder, at the point a value actually depends
/// on the construct.
#[derive(Clone, Debug)]
pub struct Unsupported {
    /// The element that is out of scope.
    pub element: String,
    /// Where it appeared in the document.
    pub path: String,
    /// Why it could not be modelled for decoding.
    pub reason: &'static str,
}

/// A loaded XTCE telemetry database.
///
/// Every entity lives in a flat arena addressed by a typed index; see [`crate::ids`]. The
/// database is immutable once built, and `Send + Sync`, so one instance can be shared by any
/// number of decoding threads.
pub struct XtceDb {
    interner: Interner,
    space_systems: Vec<SpaceSystem>,
    types: Vec<ParameterType>,
    parameters: Vec<Parameter>,
    containers: Vec<Container>,
    entries: Vec<Entry>,
    root_containers: Vec<ContainerId>,

    type_by_qualified: FxHashMap<NameId, TypeId>,
    type_by_leaf: FxHashMap<NameId, TypeId>,
    param_by_qualified: FxHashMap<NameId, ParamId>,
    param_by_leaf: FxHashMap<NameId, ParamId>,
    container_by_qualified: FxHashMap<NameId, ContainerId>,
    container_by_leaf: FxHashMap<NameId, ContainerId>,

    unsupported: Vec<Unsupported>,
    source: Option<PathBuf>,
    xmlns: Option<String>,
    skipped_sections: Vec<String>,
}

/// Everything [`Lowering`] produces, handed over in one struct to keep the constructor from
/// growing a dozen positional parameters.
pub(crate) struct Parts {
    pub interner: Interner,
    pub space_systems: Vec<SpaceSystem>,
    pub types: Vec<ParameterType>,
    pub parameters: Vec<Parameter>,
    pub containers: Vec<Container>,
    pub entries: Vec<Entry>,
    pub root_containers: Vec<ContainerId>,
    pub type_by_qualified: FxHashMap<NameId, TypeId>,
    pub type_by_leaf: FxHashMap<NameId, TypeId>,
    pub param_by_qualified: FxHashMap<NameId, ParamId>,
    pub param_by_leaf: FxHashMap<NameId, ParamId>,
    pub container_by_qualified: FxHashMap<NameId, ContainerId>,
    pub container_by_leaf: FxHashMap<NameId, ContainerId>,
    pub unsupported: Vec<Unsupported>,
    pub xmlns: Option<String>,
    pub skipped_sections: Vec<String>,
}

impl XtceDb {
    pub(crate) fn assemble(parts: Parts) -> Self {
        Self {
            interner: parts.interner,
            space_systems: parts.space_systems,
            types: parts.types,
            parameters: parts.parameters,
            containers: parts.containers,
            entries: parts.entries,
            root_containers: parts.root_containers,
            type_by_qualified: parts.type_by_qualified,
            type_by_leaf: parts.type_by_leaf,
            param_by_qualified: parts.param_by_qualified,
            param_by_leaf: parts.param_by_leaf,
            container_by_qualified: parts.container_by_qualified,
            container_by_leaf: parts.container_by_leaf,
            unsupported: parts.unsupported,
            source: None,
            xmlns: parts.xmlns,
            skipped_sections: parts.skipped_sections,
        }
    }

    /// Loads an XTCE document from disk.
    ///
    /// # Errors
    ///
    /// Returns [`XtceError::Io`] if the file cannot be read, and any [`XtceError`] the
    /// parser or lowering pass produces.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, XtceError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| XtceError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut db = Self::from_xml(&text)?;
        db.source = Some(path.to_path_buf());
        Ok(db)
    }

    /// Parses an XTCE document held in memory.
    ///
    /// # Errors
    ///
    /// Returns [`XtceError`] if the document is not well-formed XML, is not rooted at
    /// `<SpaceSystem>`, contains an unresolvable reference, or defines cyclic container
    /// inheritance.
    pub fn from_xml(text: &str) -> Result<Self, XtceError> {
        let dom = Dom::parse(text)?;
        Lowering::new(&dom).run()
    }

    /// The file this database was loaded from, when it came from disk.
    #[must_use]
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    /// The XML namespace declared on the root element, which identifies the XTCE version.
    #[must_use]
    pub fn xmlns(&self) -> Option<&str> {
        self.xmlns.as_deref()
    }

    /// Document sections dropped during parsing because telemetry decoding never reads
    /// them, such as `CommandMetaData`.
    #[must_use]
    pub fn skipped_sections(&self) -> &[String] {
        &self.skipped_sections
    }

    /// Constructs that were modelled but cannot be decoded.
    #[must_use]
    pub fn unsupported(&self) -> &[Unsupported] {
        &self.unsupported
    }

    /// The string interner backing every name in this database.
    #[must_use]
    pub fn interner(&self) -> &Interner {
        &self.interner
    }

    /// Resolves an interned handle to its text.
    #[must_use]
    pub fn name(&self, id: NameId) -> &str {
        self.interner.resolve(id)
    }

    /// All space systems, the root first.
    #[must_use]
    pub fn space_systems(&self) -> &[SpaceSystem] {
        &self.space_systems
    }

    /// All parameter types, in document order.
    #[must_use]
    pub fn types(&self) -> &[ParameterType] {
        &self.types
    }

    /// All parameters, in document order.
    #[must_use]
    pub fn parameters(&self) -> &[Parameter] {
        &self.parameters
    }

    /// All containers, in document order.
    #[must_use]
    pub fn containers(&self) -> &[Container] {
        &self.containers
    }

    /// The shared entry arena. Slice it with [`Container::entries`].
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Containers that declare no `<BaseContainer>`, i.e. candidate decoding roots.
    #[must_use]
    pub fn root_containers(&self) -> &[ContainerId] {
        &self.root_containers
    }

    /// A space system by index.
    #[must_use]
    pub fn space_system(&self, id: SpaceSystemId) -> Option<&SpaceSystem> {
        self.space_systems.get(id.index())
    }

    /// A parameter by index.
    #[must_use]
    pub fn parameter(&self, id: ParamId) -> Option<&Parameter> {
        self.parameters.get(id.index())
    }

    /// A parameter type by index.
    #[must_use]
    pub fn parameter_type(&self, id: TypeId) -> Option<&ParameterType> {
        self.types.get(id.index())
    }

    /// A container by index.
    #[must_use]
    pub fn container(&self, id: ContainerId) -> Option<&Container> {
        self.containers.get(id.index())
    }

    /// The entries of a container, as a slice of the shared arena.
    #[must_use]
    pub fn container_entries(&self, id: ContainerId) -> &[Entry] {
        self.container(id)
            .map_or(&[], |container| container.entries.slice(&self.entries))
    }

    /// The type of a parameter.
    #[must_use]
    pub fn type_of(&self, id: ParamId) -> Option<&ParameterType> {
        self.parameter(id)
            .and_then(|parameter| self.parameter_type(parameter.type_id))
    }

    /// Looks up a parameter by fully qualified name (`/Root/PKT_APID`) or, failing that, by
    /// unqualified name.
    #[must_use]
    pub fn find_parameter(&self, name: &str) -> Option<ParamId> {
        let id = self.interner.get(name)?;
        self.param_by_qualified
            .get(&id)
            .or_else(|| self.param_by_leaf.get(&id))
            .copied()
    }

    /// Looks up a container by fully qualified name or, failing that, by unqualified name.
    #[must_use]
    pub fn find_container(&self, name: &str) -> Option<ContainerId> {
        let id = self.interner.get(name)?;
        self.container_by_qualified
            .get(&id)
            .or_else(|| self.container_by_leaf.get(&id))
            .copied()
    }

    /// Looks up a parameter type by fully qualified name or, failing that, by unqualified
    /// name.
    #[must_use]
    pub fn find_type(&self, name: &str) -> Option<TypeId> {
        let id = self.interner.get(name)?;
        self.type_by_qualified
            .get(&id)
            .or_else(|| self.type_by_leaf.get(&id))
            .copied()
    }

    /// The display label a boolean parameter type gives to `value`.
    ///
    /// XTCE calls booleans "a restricted form of enumeration", and this exposes the
    /// `zeroStringValue` / `oneStringValue` labels. The decoder itself yields a plain
    /// `bool`, matching the reference implementation.
    #[must_use]
    pub fn boolean_label(&self, id: TypeId, value: bool) -> Option<&str> {
        let TypeKind::Boolean {
            zero_label,
            one_label,
        } = self.parameter_type(id)?.kind
        else {
            return None;
        };
        let label = if value { one_label } else { zero_label }?;
        Some(self.interner.resolve(label))
    }

    /// The container a decoder should start from when none is named.
    ///
    /// Prefers the conventional CCSDS root names, then falls back to the only base-less
    /// container if the document has exactly one.
    #[must_use]
    pub fn default_root_container(&self) -> Option<ContainerId> {
        for candidate in ["CCSDSPacket", "CCSDSTelemetryPacket"] {
            if let Some(id) = self.find_container(candidate) {
                return Some(id);
            }
        }
        match self.root_containers.as_slice() {
            [only] => Some(*only),
            _ => None,
        }
    }

    /// Counts for reporting, computed on demand.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let decodable_types = self
            .types
            .iter()
            .filter(|ty| !matches!(ty.kind, TypeKind::Unsupported { .. }))
            .count();
        Stats {
            space_systems: self.space_systems.len(),
            parameters: self.parameters.len(),
            parameter_types: self.types.len(),
            decodable_parameter_types: decodable_types,
            containers: self.containers.len(),
            abstract_containers: self.containers.iter().filter(|c| c.is_abstract).count(),
            entries: self.entries.len(),
            interned_names: self.interner.len(),
            interned_bytes: self.interner.bytes(),
            unsupported: self.unsupported.len(),
        }
    }
}

/// Summary counts for a loaded database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    /// Number of `SpaceSystem` nodes.
    pub space_systems: usize,
    /// Number of parameters.
    pub parameters: usize,
    /// Number of parameter types.
    pub parameter_types: usize,
    /// Parameter types this crate can decode.
    pub decodable_parameter_types: usize,
    /// Number of sequence containers.
    pub containers: usize,
    /// Containers marked `abstract="true"`.
    pub abstract_containers: usize,
    /// Total entries across all containers.
    pub entries: usize,
    /// Distinct interned strings.
    pub interned_names: usize,
    /// Bytes of unique string data.
    pub interned_bytes: usize,
    /// Constructs modelled but not decodable.
    pub unsupported: usize,
}
