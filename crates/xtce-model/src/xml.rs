//! A compact, arena-backed XML tree tuned for XTCE.
//!
//! # Why a tree and not a pure SAX pass
//!
//! XTCE is not a stream: `<BaseContainer>` points backwards or forwards, `<ParameterRefEntry>`
//! names types defined earlier or later, and several elements are only meaningful together
//! with siblings. A single streaming pass would need a hand-rolled state machine with a
//! deferred-fixup table for every one of those cases. Building a tree first keeps the
//! semantic pass declarative (`node.child(Tag::EntryList)`) at the cost of one compact
//! arena.
//!
//! # Why it is still fast
//!
//! Nothing here allocates per element. Element names, attribute names, attribute values and
//! text are appended to one shared `String` arena and addressed by `(start, len)`, so the
//! tree is three flat `Vec`s of `Copy` records with no `String`, no `Rc`, and no per-node
//! allocation.
//!
//! The arena deliberately does *not* deduplicate. An earlier version interned every
//! attribute value, which sounds attractive — `encoding="unsigned"` appears 205 times in one
//! test file — but interning costs a hash lookup per value where the arena costs a memcpy of
//! about eight bytes, and the 1.6 MB test file has roughly a quarter of a million of them.
//! Deduplication belongs in the IR, which keeps only the names it actually needs; the tree is
//! transient and is dropped as soon as lowering finishes.
//!
//! Tag and attribute-key recognition is a `match` on the local name rather than a hash
//! lookup: the vocabulary is a small closed set of short strings, which `rustc` compiles into
//! a length switch and a handful of comparisons.

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::{ParseError, ParseErrorKind};
use crate::ids::Span;

/// Sentinel for "no node"; the arena can never hold `u32::MAX` nodes.
const NONE: u32 = u32::MAX;

macro_rules! symbols {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($variant:ident => $text:literal),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        $vis enum $name {
            $(
                #[doc = concat!("The XML symbol `", $text, "`.")]
                $variant,
            )*
            /// Any symbol outside the vocabulary this crate understands.
            Other,
        }

        impl $name {
            /// Every named variant, in declaration order.
            $vis const ALL: &'static [$name] = &[$($name::$variant,)*];

            /// The XML spelling of this symbol; `""` for [`Self::Other`].
            #[must_use]
            $vis const fn text(self) -> &'static str {
                match self {
                    $($name::$variant => $text,)*
                    $name::Other => "",
                }
            }

            /// Recognises a local name, returning [`Self::Other`] for anything outside the
            /// vocabulary.
            #[must_use]
            $vis fn from_text(text: &str) -> Self {
                match text {
                    $($text => $name::$variant,)*
                    _ => $name::Other,
                }
            }
        }
    };
}

symbols! {
    /// XTCE element local names that carry meaning for telemetry decoding.
    ///
    /// Namespace prefixes are stripped before lookup, so `<xtce:SpaceSystem>`,
    /// `<SpaceSystem>` and a default-namespaced `<SpaceSystem>` all map to
    /// [`Tag::SpaceSystem`]. All three spellings occur in the wild — the reference
    /// implementation ships a test file for each.
    pub enum Tag {
        SpaceSystem => "SpaceSystem",
        TelemetryMetaData => "TelemetryMetaData",
        CommandMetaData => "CommandMetaData",
        ArgumentTypeSet => "ArgumentTypeSet",
        MetaCommandSet => "MetaCommandSet",
        MetaCommand => "MetaCommand",
        BaseMetaCommand => "BaseMetaCommand",
        ArgumentAssignmentList => "ArgumentAssignmentList",
        ArgumentAssignment => "ArgumentAssignment",
        ArgumentList => "ArgumentList",
        Argument => "Argument",
        CommandContainer => "CommandContainer",
        CommandContainerSet => "CommandContainerSet",
        ArgumentRefEntry => "ArgumentRefEntry",
        ArrayArgumentRefEntry => "ArrayArgumentRefEntry",
        FixedValueEntry => "FixedValueEntry",
        IntegerArgumentType => "IntegerArgumentType",
        FloatArgumentType => "FloatArgumentType",
        StringArgumentType => "StringArgumentType",
        BinaryArgumentType => "BinaryArgumentType",
        BooleanArgumentType => "BooleanArgumentType",
        EnumeratedArgumentType => "EnumeratedArgumentType",
        AbsoluteTimeArgumentType => "AbsoluteTimeArgumentType",
        RelativeTimeArgumentType => "RelativeTimeArgumentType",
        ArrayArgumentType => "ArrayArgumentType",
        AggregateArgumentType => "AggregateArgumentType",
        ParameterTypeSet => "ParameterTypeSet",
        ParameterSet => "ParameterSet",
        ContainerSet => "ContainerSet",
        Parameter => "Parameter",
        SequenceContainer => "SequenceContainer",
        BaseContainer => "BaseContainer",
        RestrictionCriteria => "RestrictionCriteria",
        EntryList => "EntryList",
        ParameterRefEntry => "ParameterRefEntry",
        ContainerRefEntry => "ContainerRefEntry",
        IndirectParameterRefEntry => "IndirectParameterRefEntry",
        ArrayParameterRefEntry => "ArrayParameterRefEntry",
        LocationInContainerInBits => "LocationInContainerInBits",
        IntegerParameterType => "IntegerParameterType",
        FloatParameterType => "FloatParameterType",
        StringParameterType => "StringParameterType",
        BinaryParameterType => "BinaryParameterType",
        BooleanParameterType => "BooleanParameterType",
        EnumeratedParameterType => "EnumeratedParameterType",
        AbsoluteTimeParameterType => "AbsoluteTimeParameterType",
        RelativeTimeParameterType => "RelativeTimeParameterType",
        ArrayParameterType => "ArrayParameterType",
        DimensionList => "DimensionList",
        Dimension => "Dimension",
        StartingIndex => "StartingIndex",
        EndingIndex => "EndingIndex",
        AggregateParameterType => "AggregateParameterType",
        MemberList => "MemberList",
        Member => "Member",
        IntegerDataEncoding => "IntegerDataEncoding",
        FloatDataEncoding => "FloatDataEncoding",
        StringDataEncoding => "StringDataEncoding",
        BinaryDataEncoding => "BinaryDataEncoding",
        Encoding => "Encoding",
        SizeInBits => "SizeInBits",
        Fixed => "Fixed",
        FixedValue => "FixedValue",
        Variable => "Variable",
        DynamicValue => "DynamicValue",
        DiscreteLookupList => "DiscreteLookupList",
        DiscreteLookup => "DiscreteLookup",
        LeadingSize => "LeadingSize",
        TerminationChar => "TerminationChar",
        ParameterInstanceRef => "ParameterInstanceRef",
        LinearAdjustment => "LinearAdjustment",
        EnumerationList => "EnumerationList",
        Enumeration => "Enumeration",
        Comparison => "Comparison",
        ComparisonList => "ComparisonList",
        BooleanExpression => "BooleanExpression",
        Condition => "Condition",
        ANDedConditions => "ANDedConditions",
        ORedConditions => "ORedConditions",
        ComparisonOperator => "ComparisonOperator",
        Value => "Value",
        DefaultCalibrator => "DefaultCalibrator",
        ContextCalibratorList => "ContextCalibratorList",
        ContextCalibrator => "ContextCalibrator",
        ContextMatch => "ContextMatch",
        Calibrator => "Calibrator",
        PolynomialCalibrator => "PolynomialCalibrator",
        SplineCalibrator => "SplineCalibrator",
        MathOperationCalibrator => "MathOperationCalibrator",
        Term => "Term",
        SplinePoint => "SplinePoint",
        CustomAlgorithm => "CustomAlgorithm",
        UnitSet => "UnitSet",
        Unit => "Unit",
        LongDescription => "LongDescription",
        ReferenceTime => "ReferenceTime",
        Epoch => "Epoch",
        OffsetFrom => "OffsetFrom",
        RepeatEntry => "RepeatEntry",
        Count => "Count",
        ServiceSet => "ServiceSet",
        MessageSet => "MessageSet",
        StreamSet => "StreamSet",
        AlgorithmSet => "AlgorithmSet",
        AliasSet => "AliasSet",
        AncillaryDataSet => "AncillaryDataSet",
    }
}

impl Tag {
    /// Whether this element opens a section telemetry decoding never reads.
    ///
    /// Checked as an enum comparison rather than by scanning a list of strings: this runs
    /// once per element, and the largest test file has twenty thousand of them.
    #[must_use]
    const fn is_skipped_section(self) -> bool {
        matches!(
            self,
            Self::ServiceSet
                | Self::MessageSet
                | Self::StreamSet
                | Self::AlgorithmSet
                | Self::AliasSet
                | Self::AncillaryDataSet
        )
    }
}

symbols! {
    /// XTCE attribute names that carry meaning for telemetry decoding.
    pub enum AttrKey {
        Name => "name",
        Abstract => "abstract",
        ShortDescription => "shortDescription",
        ParameterRef => "parameterRef",
        ContainerRef => "containerRef",
        ParameterTypeRef => "parameterTypeRef",
        ArgumentTypeRef => "argumentTypeRef",
        ArgumentRef => "argumentRef",
        ArgumentName => "argumentName",
        ArgumentValue => "argumentValue",
        MetaCommandRef => "metaCommandRef",
        BinaryValue => "binaryValue",
        ArrayTypeRef => "arrayTypeRef",
        TypeRef => "typeRef",
        SizeInBits => "sizeInBits",
        Encoding => "encoding",
        ByteOrder => "byteOrder",
        Value => "value",
        Label => "label",
        MaxValue => "maxValue",
        ComparisonOperator => "comparisonOperator",
        UseCalibratedValue => "useCalibratedValue",
        Slope => "slope",
        Intercept => "intercept",
        Order => "order",
        Extrapolate => "extrapolate",
        Raw => "raw",
        Calibrated => "calibrated",
        Coefficient => "coefficient",
        Exponent => "exponent",
        Offset => "offset",
        Scale => "scale",
        Units => "units",
        SizeInBitsOfSizeTag => "sizeInBitsOfSizeTag",
        InitialValue => "initialValue",
        ReferenceLocation => "referenceLocation",
        ZeroStringValue => "zeroStringValue",
        OneStringValue => "oneStringValue",
    }
}

// Sections of an XTCE document that nothing here reads are dropped during parsing rather
// than materialised and ignored — see `Tag::is_skipped_section`. Skipped sections are
// recorded so `xtce info` can report what the file contained but this crate did not model.
//
// `CommandMetaData` used to be on that list, and dropping it was the larger saving: in a
// real mission database the command half can be bigger than the telemetry half. It is kept
// now because a spacecraft has to read what the ground sends it, and a telecommand is
// defined there and nowhere else.

/// One element in the arena.
#[derive(Clone, Copy, Debug)]
pub struct Node {
    tag: Tag,
    name: Span,
    parent: u32,
    first_child: u32,
    next_sibling: u32,
    attr_start: u32,
    attr_len: u32,
    /// Text content, present only for elements with no element children.
    text: Span,
    has_text: bool,
}

#[derive(Clone, Copy, Debug)]
struct Attr {
    key: AttrKey,
    name: Span,
    value: Span,
}

/// A parsed XTCE document: a flat arena of elements plus the interner backing every name.
pub struct Dom {
    nodes: Vec<Node>,
    attrs: Vec<Attr>,
    /// `last_child[i]` is the most recently appended child of node `i`, or [`NONE`].
    /// Keeping it out of [`Node`] costs one extra `Vec` during construction but makes
    /// appending O(1) for wide parents such as `ParameterSet`, which holds thousands of
    /// children in the larger test files.
    last_child: Vec<u32>,
    /// Every name, attribute value and text run, concatenated.
    arena: String,
    skipped_sections: Vec<String>,
    xmlns: Option<String>,
}

/// A borrowed handle to one element, carrying the arena it came from.
///
/// This is the type the semantic pass works with. It is `Copy` and two words wide, so
/// navigation (`child`, `children`, `attr`) is free of allocation and of lifetime noise.
#[derive(Clone, Copy)]
pub struct Element<'d> {
    dom: &'d Dom,
    index: u32,
}

impl Dom {
    /// Parses an XTCE document from a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the input is not well-formed XML or contains no root
    /// element.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        // Sized from the largest file in `testdata` (1.6 MB, ~46 k elements, ~100 k
        // attributes) so that a typical document never reallocates mid-parse. The arena
        // holds names and values only, which is a fraction of the source.
        let approx_elements = input.len() / 48;
        let mut dom = Self {
            nodes: Vec::with_capacity(approx_elements),
            attrs: Vec::with_capacity(approx_elements * 2),
            last_child: Vec::with_capacity(approx_elements),
            // Only unrecognised names and attribute values reach the arena, which on real
            // XTCE is a small fraction of the source; a quarter of the input length has
            // never needed to grow on the bundled files.
            arena: String::with_capacity(input.len() / 4),
            skipped_sections: Vec::new(),
            xmlns: None,
        };
        dom.run(input)?;
        Ok(dom)
    }

    /// Appends `text` to the arena and returns its span.
    #[inline]
    fn push_text(&mut self, text: &str) -> Span {
        let start = self.arena.len();
        self.arena.push_str(text);
        Span::between(start, self.arena.len())
    }

    #[inline]
    fn str_at(&self, span: Span) -> &str {
        let start = span.start();
        self.arena
            .get(start..start + span.len())
            .unwrap_or_default()
    }

    fn run(&mut self, input: &str) -> Result<(), ParseError> {
        let mut reader = Reader::from_str(input);
        let config = reader.config_mut();
        config.trim_text(true);
        config.expand_empty_elements = false;
        config.check_end_names = true;

        // Ancestors of the element currently being filled; `open.last()` is its index.
        let mut open: Vec<u32> = Vec::with_capacity(32);
        // Depth of the skipped subtree we are inside, if any.
        let mut skipping: Option<usize> = None;
        // Character data seen since the last tag. quick-xml splits a text run at every
        // entity reference (`&amp;` arrives as its own event), so text must be accumulated
        // rather than taken from a single event.
        let mut scratch = String::new();

        loop {
            let event = match reader.read_event() {
                Ok(event) => event,
                Err(source) => return Err(ParseError::at_offset(reader.buffer_position(), source)),
            };

            match event {
                Event::Start(start) => {
                    if let Some(depth) = skipping.as_mut() {
                        *depth += 1;
                        continue;
                    }
                    match self.open_element(&start, open.last().copied())? {
                        Some(index) => open.push(index),
                        None => skipping = Some(1),
                    }
                    scratch.clear();
                }
                Event::Empty(start) => {
                    if skipping.is_some() {
                        continue;
                    }
                    self.open_element(&start, open.last().copied())?;
                }
                Event::End(_) => match skipping.as_mut() {
                    Some(1) => skipping = None,
                    Some(depth) => *depth -= 1,
                    None => {
                        if let Some(index) = open.pop() {
                            if !scratch.trim().is_empty() {
                                let span = self.push_text(&scratch);
                                if let Some(node) = self.nodes.get_mut(index as usize) {
                                    node.text = span;
                                    node.has_text = true;
                                }
                            }
                        }
                        scratch.clear();
                    }
                },
                Event::Text(text) => {
                    if skipping.is_some() || open.is_empty() {
                        continue;
                    }
                    let offset = reader.buffer_position();
                    let decoded = text
                        .xml_content()
                        .map_err(|source| ParseError::at_offset(offset, source))?;
                    scratch.push_str(&decoded);
                }
                Event::CData(cdata) => {
                    if skipping.is_some() || open.is_empty() {
                        continue;
                    }
                    let offset = reader.buffer_position();
                    let decoded = cdata
                        .decode()
                        .map_err(|source| ParseError::at_offset(offset, source))?;
                    scratch.push_str(&decoded);
                }
                Event::GeneralRef(entity) => {
                    if skipping.is_some() || open.is_empty() {
                        continue;
                    }
                    let offset = reader.buffer_position();
                    push_entity(&mut scratch, &entity)
                        .map_err(|source| ParseError::at_offset(offset, source))?;
                }
                Event::Eof => break,
                Event::Decl(_) | Event::PI(_) | Event::Comment(_) | Event::DocType(_) => {}
            }
        }

        if self.nodes.is_empty() {
            return Err(ParseError::new(ParseErrorKind::EmptyDocument));
        }
        Ok(())
    }

    /// Materialises one element.
    ///
    /// Returns the new node's index, or `None` when the element opens an out-of-scope
    /// section whose whole subtree the caller should skip.
    fn open_element(
        &mut self,
        start: &quick_xml::events::BytesStart<'_>,
        parent: Option<u32>,
    ) -> Result<Option<u32>, ParseError> {
        let local = start.local_name();
        let local = std::str::from_utf8(local.as_ref()).unwrap_or_default();
        let tag = Tag::from_text(local);
        if tag.is_skipped_section() {
            self.skipped_sections.push(local.to_owned());
            return Ok(None);
        }
        let index = self.push_node(tag, local, parent);
        self.push_attributes(index, start)?;
        if index == 0 {
            self.xmlns = element_namespace(start);
        }
        Ok(Some(index))
    }

    fn push_node(&mut self, tag: Tag, local: &str, parent: Option<u32>) -> u32 {
        // A recognised tag already carries its spelling, so only unknown names go in the
        // arena. On the largest test file that is most of a megabyte of memcpy avoided.
        let name = if tag == Tag::Other {
            self.push_text(local)
        } else {
            Span::EMPTY
        };
        let index = u32::try_from(self.nodes.len()).unwrap_or(NONE);
        self.nodes.push(Node {
            tag,
            name,
            parent: parent.unwrap_or(NONE),
            first_child: NONE,
            next_sibling: NONE,
            attr_start: u32::try_from(self.attrs.len()).unwrap_or(0),
            attr_len: 0,
            text: Span::EMPTY,
            has_text: false,
        });
        self.last_child.push(NONE);

        if let Some(parent) = parent {
            match self.last_child.get(parent as usize).copied() {
                Some(NONE) | None => {
                    if let Some(node) = self.nodes.get_mut(parent as usize) {
                        node.first_child = index;
                    }
                }
                Some(previous) => {
                    if let Some(node) = self.nodes.get_mut(previous as usize) {
                        node.next_sibling = index;
                    }
                }
            }
            if let Some(slot) = self.last_child.get_mut(parent as usize) {
                *slot = index;
            }
        }
        index
    }

    fn push_attributes(
        &mut self,
        index: u32,
        start: &quick_xml::events::BytesStart<'_>,
    ) -> Result<(), ParseError> {
        let start_len = self.attrs.len();
        for attr in start.attributes() {
            let attr = attr.map_err(|source| ParseError::new(source.into()))?;
            let key_bytes = attr.key.as_ref();
            if key_bytes == b"xmlns" || key_bytes.starts_with(b"xmlns:") {
                continue;
            }
            let key_local = attr.key.local_name();
            let key_local = std::str::from_utf8(key_local.as_ref()).unwrap_or_default();
            let value = attr
                .unescape_value()
                .map_err(|source| ParseError::new(source.into()))?;
            let key = AttrKey::from_text(key_local);
            let name = if key == AttrKey::Other {
                self.push_text(key_local)
            } else {
                Span::EMPTY
            };
            let value = self.push_text(&value);
            self.attrs.push(Attr { key, name, value });
        }
        if let Some(node) = self.nodes.get_mut(index as usize) {
            node.attr_start = u32::try_from(start_len).unwrap_or(0);
            node.attr_len = u32::try_from(self.attrs.len() - start_len).unwrap_or(0);
        }
        Ok(())
    }

    /// The document element.
    #[must_use]
    pub fn root(&self) -> Element<'_> {
        Element {
            dom: self,
            index: 0,
        }
    }

    /// Names of sections dropped during parsing, in document order.
    #[must_use]
    pub fn skipped_sections(&self) -> &[String] {
        &self.skipped_sections
    }

    /// The default XML namespace declared on the root element, if any.
    #[must_use]
    pub fn xmlns(&self) -> Option<&str> {
        self.xmlns.as_deref()
    }

    /// Number of elements retained in the arena.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the arena holds no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl<'d> Element<'d> {
    fn node(self) -> &'d Node {
        // The index always comes from this arena, but a missing node degrades to a
        // detached placeholder rather than panicking.
        self.dom.nodes.get(self.index as usize).unwrap_or(&DETACHED)
    }

    /// This element's tag.
    #[must_use]
    pub fn tag(self) -> Tag {
        self.node().tag
    }

    /// This element's local name as written in the document.
    #[must_use]
    pub fn name(self) -> &'d str {
        let node = self.node();
        match node.tag {
            Tag::Other => self.dom.str_at(node.name),
            tag => tag.text(),
        }
    }

    /// The parent element, or `None` at the root.
    #[must_use]
    pub fn parent(self) -> Option<Element<'d>> {
        let parent = self.node().parent;
        (parent != NONE).then_some(Element {
            dom: self.dom,
            index: parent,
        })
    }

    /// Direct children, in document order.
    #[must_use]
    pub fn children(self) -> Children<'d> {
        Children {
            dom: self.dom,
            next: self.node().first_child,
        }
    }

    /// Direct children with the given tag.
    pub fn children_with(self, tag: Tag) -> impl Iterator<Item = Element<'d>> {
        self.children().filter(move |child| child.tag() == tag)
    }

    /// The first direct child with the given tag.
    #[must_use]
    pub fn child(self, tag: Tag) -> Option<Element<'d>> {
        self.children().find(|child| child.tag() == tag)
    }

    /// The first descendant with the given tag, searched depth-first.
    ///
    /// Mirrors the reference implementation's `element.find(".//Tag")`, which is how it
    /// locates a data encoding anywhere under a parameter type.
    #[must_use]
    pub fn descendant(self, tag: Tag) -> Option<Element<'d>> {
        self.children().find_map(|child| {
            if child.tag() == tag {
                Some(child)
            } else {
                child.descendant(tag)
            }
        })
    }

    /// The first descendant matching any of `tags`, searched depth-first, preferring the
    /// shallowest match and then document order.
    #[must_use]
    pub fn descendant_any(self, tags: &[Tag]) -> Option<Element<'d>> {
        for child in self.children() {
            if tags.contains(&child.tag()) {
                return Some(child);
            }
        }
        self.children().find_map(|child| child.descendant_any(tags))
    }

    /// An attribute value by well-known key.
    #[must_use]
    pub fn attr(self, key: AttrKey) -> Option<&'d str> {
        self.attrs_raw()
            .iter()
            .find(|attr| attr.key == key)
            .map(|attr| self.dom.str_at(attr.value))
    }

    /// An attribute value by literal name, for attributes outside [`AttrKey`].
    #[must_use]
    pub fn attr_named(self, name: &str) -> Option<&'d str> {
        self.attrs_raw()
            .iter()
            .find(|attr| self.attr_name(attr) == name)
            .map(|attr| self.dom.str_at(attr.value))
    }

    /// Attribute names present on this element, in document order.
    pub fn attr_names(self) -> impl Iterator<Item = &'d str> {
        self.attrs_raw()
            .iter()
            .map(move |attr| self.attr_name(attr))
    }

    fn attr_name(self, attr: &Attr) -> &'d str {
        match attr.key {
            AttrKey::Other => self.dom.str_at(attr.name),
            key => key.text(),
        }
    }

    fn attrs_raw(self) -> &'d [Attr] {
        let node = self.node();
        let start = node.attr_start as usize;
        let end = start + node.attr_len as usize;
        self.dom.attrs.get(start..end).unwrap_or_default()
    }

    /// Text content, if this element has any and no element children.
    #[must_use]
    pub fn text(self) -> Option<&'d str> {
        let node = self.node();
        node.has_text.then(|| self.dom.str_at(node.text).trim())
    }

    /// The `/`-joined element path from the root to this element, for diagnostics.
    #[must_use]
    pub fn path(self) -> String {
        let mut parts = Vec::new();
        let mut cursor = Some(self);
        while let Some(element) = cursor {
            parts.push(element.name());
            cursor = element.parent();
        }
        parts.reverse();
        parts.join("/")
    }
}

static DETACHED: Node = Node {
    tag: Tag::Other,
    name: Span::EMPTY,
    parent: NONE,
    first_child: NONE,
    next_sibling: NONE,
    attr_start: 0,
    attr_len: 0,
    text: Span::EMPTY,
    has_text: false,
};

/// Iterator over the direct children of an element.
pub struct Children<'d> {
    dom: &'d Dom,
    next: u32,
}

impl<'d> Iterator for Children<'d> {
    type Item = Element<'d>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == NONE {
            return None;
        }
        let index = self.next;
        self.next = self
            .dom
            .nodes
            .get(index as usize)
            .map_or(NONE, |n| n.next_sibling);
        Some(Element {
            dom: self.dom,
            index,
        })
    }
}

impl std::iter::FusedIterator for Children<'_> {}

/// Appends the expansion of a general entity reference to `out`.
///
/// The five XML predefined entities and numeric character references are expanded;
/// anything else (a DTD-declared entity, which XTCE does not use) is written back
/// literally so that no character data is silently lost.
fn push_entity(
    out: &mut String,
    entity: &quick_xml::events::BytesRef<'_>,
) -> Result<(), quick_xml::encoding::EncodingError> {
    if entity.is_char_ref() {
        if let Ok(Some(ch)) = entity.resolve_char_ref() {
            out.push(ch);
            return Ok(());
        }
    }
    let name = entity.decode()?;
    match name.as_ref() {
        "amp" => out.push('&'),
        "lt" => out.push('<'),
        "gt" => out.push('>'),
        "apos" => out.push('\''),
        "quot" => out.push('"'),
        other => {
            out.push('&');
            out.push_str(other);
            out.push(';');
        }
    }
    Ok(())
}

/// The namespace URI actually bound to an element's own name.
///
/// XTCE documents appear with the vocabulary prefixed (`<xtce:SpaceSystem xmlns:xtce=..>`),
/// default-namespaced (`<SpaceSystem xmlns=..>`) or with no namespace at all. Only the
/// binding for *this* element's prefix identifies the XTCE version — picking the first
/// `xmlns:*` attribute instead would report `xsi` for a document whose only declaration is
/// the schema-instance one.
fn element_namespace(start: &quick_xml::events::BytesStart<'_>) -> Option<String> {
    let qname = start.name();
    let wanted: Vec<u8> = match qname.prefix() {
        Some(prefix) => [b"xmlns:".as_slice(), prefix.as_ref()].concat(),
        None => b"xmlns".to_vec(),
    };
    start
        .attributes()
        .flatten()
        .find(|attr| attr.key.as_ref() == wanted.as_slice())
        .and_then(|attr| String::from_utf8(attr.value.into_owned()).ok())
}
