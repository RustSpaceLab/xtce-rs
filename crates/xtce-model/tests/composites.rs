//! What `<ArrayParameterType>` and `<AggregateParameterType>` expand into, exactly.
//!
//! Both are containers of other things, and both are laid out packed and in order, so both
//! flatten the same way: an entry naming one is turned into one parameter per leaf when the
//! file is loaded. Nothing downstream — the interpreter, the code generator, the flight
//! encoder — has to know either exists. That makes the expansion the only place the semantics
//! live, and these tests pin it by name rather than by "it decodes".
//!
//! There is no reference to check against. `space_packet_parser` raises
//! `NotImplementedError` for both and says supporting them is on its roadmap, so the oracle is
//! XTCE 1.2 itself. Four clauses of it do the work:
//!
//! * `DimensionType`: "For partial entries of an array, the starting and ending index for
//!   each dimension … Indexes are zero based." Both ends are inclusive.
//! * `DimensionListType`: "Array[1stDim][2ndDim][lastDim]. The last dimension is assumed to
//!   be the least significant — that is this dimension will cycle through its combination
//!   before the next to last dimension changes." Row-major.
//! * `AggregateDataType`: "The data members are ordered and contiguous in the MemberList
//!   element (packed). Each member may be addressed by the dot syntax similar to C such as
//!   `P.voltage`."
//! * `MemberType`: "Circular references are not allowed."

use xtce_model::{EntryKind, XtceDb};

/// Wraps a parameter type set, parameter set and entry list in a loadable document.
fn definition(types: &str, parameters: &str, entries: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="T">
  <TelemetryMetaData>
    <ParameterTypeSet>
      <IntegerParameterType name="U8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
      {types}
    </ParameterTypeSet>
    <ParameterSet>{parameters}</ParameterSet>
    <ContainerSet>
      <SequenceContainer name="Only"><EntryList>{entries}</EntryList></SequenceContainer>
    </ContainerSet>
  </TelemetryMetaData>
</SpaceSystem>"#
    )
}

/// A `<Dimension>` from `start` to `end`, inclusive.
fn dimension(start: i64, end: i64) -> String {
    format!(
        "<Dimension><StartingIndex><FixedValue>{start}</FixedValue></StartingIndex>\
         <EndingIndex><FixedValue>{end}</FixedValue></EndingIndex></Dimension>"
    )
}

/// The parameter names the only container's entries resolve to, in order.
fn expanded(xml: &str) -> Vec<String> {
    let db = XtceDb::from_xml(xml).expect("the definition loads");
    let container = db.containers().first().expect("one container");
    container
        .entries
        .slice(db.entries())
        .iter()
        .map(|entry| match entry.kind {
            EntryKind::Parameter(id) => {
                let parameter = db.parameter(id).expect("the parameter resolves");
                db.name(parameter.name).to_owned()
            }
            _ => "<not a parameter>".to_owned(),
        })
        .collect()
}

#[test]
fn one_dimension_expands_in_order() {
    let xml = definition(
        &format!(
            r#"<ArrayParameterType name="ARR_T" arrayTypeRef="U8"><DimensionList>{}</DimensionList></ArrayParameterType>"#,
            dimension(0, 4)
        ),
        r#"<Parameter name="ARR" parameterTypeRef="ARR_T"/>"#,
        r#"<ParameterRefEntry parameterRef="ARR"/>"#,
    );
    assert_eq!(
        expanded(&xml),
        ["ARR[0]", "ARR[1]", "ARR[2]", "ARR[3]", "ARR[4]"],
        "five inclusive indices, named by their own index"
    );
}

/// Two dimensions, with **different** extents.
///
/// The extents differ on purpose. With a square array a transposed expansion produces the
/// same number of fields covering the same bits, and every test passes; 2 by 3 is the
/// smallest shape where row-major and column-major disagree about which name sits where.
#[test]
fn two_dimensions_expand_with_the_last_varying_fastest() {
    let xml = definition(
        &format!(
            r#"<ArrayParameterType name="ARR_T" arrayTypeRef="U8"><DimensionList>{}{}</DimensionList></ArrayParameterType>"#,
            dimension(0, 1),
            dimension(0, 2)
        ),
        r#"<Parameter name="ARR" parameterTypeRef="ARR_T"/>"#,
        r#"<ParameterRefEntry parameterRef="ARR"/>"#,
    );
    assert_eq!(
        expanded(&xml),
        [
            "ARR[0][0]",
            "ARR[0][1]",
            "ARR[0][2]",
            "ARR[1][0]",
            "ARR[1][1]",
            "ARR[1][2]",
        ],
        "XTCE says the last dimension cycles before the one before it changes"
    );
}

/// A `<DimensionList>` on the *entry* subsets the array, and keeps the array's own indices.
///
/// XTCE: "Only used for subsetting an array. The array's maximum dimension sizes are set in
/// the type." Renumbering the subset from zero would make its fields impossible to line up
/// with the same array read whole.
#[test]
fn a_subset_keeps_the_indices_it_covers() {
    let xml = definition(
        &format!(
            r#"<ArrayParameterType name="ARR_T" arrayTypeRef="U8"><DimensionList>{}</DimensionList></ArrayParameterType>"#,
            dimension(0, 9)
        ),
        r#"<Parameter name="ARR" parameterTypeRef="ARR_T"/>"#,
        &format!(
            r#"<ArrayParameterRefEntry parameterRef="ARR"><DimensionList>{}</DimensionList></ArrayParameterRefEntry>"#,
            dimension(2, 4)
        ),
    );
    assert_eq!(expanded(&xml), ["ARR[2]", "ARR[3]", "ARR[4]"]);
}

/// A subset that runs past the type's declared size is a definition error.
#[test]
fn a_subset_outside_the_declared_dimensions_is_refused() {
    let xml = definition(
        &format!(
            r#"<ArrayParameterType name="ARR_T" arrayTypeRef="U8"><DimensionList>{}</DimensionList></ArrayParameterType>"#,
            dimension(0, 3)
        ),
        r#"<Parameter name="ARR" parameterTypeRef="ARR_T"/>"#,
        &format!(
            r#"<ArrayParameterRefEntry parameterRef="ARR"><DimensionList>{}</DimensionList></ArrayParameterRefEntry>"#,
            dimension(2, 9)
        ),
    );
    let Err(error) = XtceDb::from_xml(&xml) else {
        panic!("a subset past the end cannot load");
    };
    assert!(
        error.to_string().contains("outside the declared"),
        "unexpected error: {error}"
    );
}

/// An index the packet supplies cannot be expanded when the file is loaded.
#[test]
fn a_dimension_read_from_the_packet_is_not_expanded() {
    let xml = definition(
        r#"<ArrayParameterType name="ARR_T" arrayTypeRef="U8"><DimensionList>
             <Dimension>
               <StartingIndex><FixedValue>0</FixedValue></StartingIndex>
               <EndingIndex><DynamicValue><ParameterInstanceRef parameterRef="N"/></DynamicValue></EndingIndex>
             </Dimension>
           </DimensionList></ArrayParameterType>"#,
        r#"<Parameter name="N" parameterTypeRef="U8"/><Parameter name="ARR" parameterTypeRef="ARR_T"/>"#,
        r#"<ParameterRefEntry parameterRef="N"/><ParameterRefEntry parameterRef="ARR"/>"#,
    );
    // The type loads — `xtce info` should still name it — but the container that uses it is
    // blocked rather than silently short.
    let db = XtceDb::from_xml(&xml).expect("the definition loads");
    assert!(
        db.unsupported()
            .iter()
            .any(|item| item.element.contains("ArrayParameterType")),
        "the array should be reported as represented but not decodable"
    );
}

/// The synthetic parameters are not visible to a `parameterRef`.
///
/// They live in the arena so that entries can point at them, but not in the index that
/// `<Comparison parameterRef=…>`, `DynamicValue` and context calibrators search. A synthetic
/// `ARR[0]` there could shadow a real parameter of that name, and nothing would say so.
#[test]
fn synthetic_elements_cannot_be_referenced_by_name() {
    let xml = definition(
        &format!(
            r#"<ArrayParameterType name="ARR_T" arrayTypeRef="U8"><DimensionList>{}</DimensionList></ArrayParameterType>"#,
            dimension(0, 2)
        ),
        r#"<Parameter name="ARR" parameterTypeRef="ARR_T"/>"#,
        r#"<ParameterRefEntry parameterRef="ARR"/>"#,
    );
    let db = XtceDb::from_xml(&xml).expect("the definition loads");

    // Present in the arena…
    let names: Vec<&str> = db
        .parameters()
        .iter()
        .map(|parameter| db.name(parameter.name))
        .collect();
    assert!(names.contains(&"ARR[0]"), "{names:?}");

    // …and a definition that tries to name one does not load.
    let referencing = definition(
        &format!(
            r#"<ArrayParameterType name="ARR_T" arrayTypeRef="U8"><DimensionList>{}</DimensionList></ArrayParameterType>"#,
            dimension(0, 2)
        ),
        r#"<Parameter name="ARR" parameterTypeRef="ARR_T"/><Parameter name="OTHER" parameterTypeRef="U8"/>"#,
        r#"<ParameterRefEntry parameterRef="ARR"/><ParameterRefEntry parameterRef="ARR[0]"/>"#,
    );
    assert!(
        XtceDb::from_xml(&referencing).is_err(),
        "a synthetic element must not resolve as a reference"
    );
}

/// The expansion has a ceiling, and the refusal names it and the entry.
///
/// It does not name the total. Counting the leaves of an arbitrary nesting first would mean a
/// second traversal that has to agree with the one that builds them, and the pair drifting
/// apart is a worse failure than a message that says "more than this".
#[test]
fn an_array_larger_than_the_ceiling_is_refused() {
    let xml = definition(
        &format!(
            r#"<ArrayParameterType name="ARR_T" arrayTypeRef="U8"><DimensionList>{}</DimensionList></ArrayParameterType>"#,
            dimension(0, 9999)
        ),
        r#"<Parameter name="ARR" parameterTypeRef="ARR_T"/>"#,
        r#"<ParameterRefEntry parameterRef="ARR"/>"#,
    );
    let Err(error) = XtceDb::from_xml(&xml) else {
        panic!("ten thousand elements is too many");
    };
    let message = error.to_string();
    assert!(
        message.contains("4096"),
        "the refusal should name the ceiling: {message}"
    );
    assert!(
        message.contains("ParameterRefEntry"),
        "and the entry it gave up on: {message}"
    );
}

/// An aggregate becomes its members, in order, under the dot syntax.
#[test]
fn an_aggregate_expands_into_its_members() {
    let xml = definition(
        r#"<AggregateParameterType name="RAIL_T"><MemberList>
             <Member name="voltage" typeRef="U8"/>
             <Member name="current" typeRef="U8"/>
             <Member name="ok" typeRef="U8"/>
           </MemberList></AggregateParameterType>"#,
        r#"<Parameter name="RAIL" parameterTypeRef="RAIL_T"/>"#,
        r#"<ParameterRefEntry parameterRef="RAIL"/>"#,
    );
    assert_eq!(
        expanded(&xml),
        ["RAIL.voltage", "RAIL.current", "RAIL.ok"],
        "members are ordered and contiguous, and addressed by the dot syntax"
    );
}

/// An array of aggregates, and an aggregate holding an array, both compose.
///
/// The two nest in either direction, and the name spells the path either way. Three members
/// and two elements rather than two and two: the counts differ so that a mix-up between the
/// axis and the member list cannot produce the same list.
#[test]
fn arrays_and_aggregates_nest_in_both_directions() {
    let outer_array = definition(
        r#"<AggregateParameterType name="RAIL_T"><MemberList>
             <Member name="voltage" typeRef="U8"/>
             <Member name="current" typeRef="U8"/>
             <Member name="ok" typeRef="U8"/>
           </MemberList></AggregateParameterType>
           <ArrayParameterType name="RAILS_T" arrayTypeRef="RAIL_T"><DimensionList>
             <Dimension><StartingIndex><FixedValue>0</FixedValue></StartingIndex>
                        <EndingIndex><FixedValue>1</FixedValue></EndingIndex></Dimension>
           </DimensionList></ArrayParameterType>"#,
        r#"<Parameter name="RAILS" parameterTypeRef="RAILS_T"/>"#,
        r#"<ParameterRefEntry parameterRef="RAILS"/>"#,
    );
    assert_eq!(
        expanded(&outer_array),
        [
            "RAILS[0].voltage",
            "RAILS[0].current",
            "RAILS[0].ok",
            "RAILS[1].voltage",
            "RAILS[1].current",
            "RAILS[1].ok",
        ]
    );

    let outer_aggregate = definition(
        r#"<ArrayParameterType name="TRIPLE_T" arrayTypeRef="U8"><DimensionList>
             <Dimension><StartingIndex><FixedValue>0</FixedValue></StartingIndex>
                        <EndingIndex><FixedValue>2</FixedValue></EndingIndex></Dimension>
           </DimensionList></ArrayParameterType>
           <AggregateParameterType name="STATE_T"><MemberList>
             <Member name="mode" typeRef="U8"/>
             <Member name="samples" typeRef="TRIPLE_T"/>
           </MemberList></AggregateParameterType>"#,
        r#"<Parameter name="STATE" parameterTypeRef="STATE_T"/>"#,
        r#"<ParameterRefEntry parameterRef="STATE"/>"#,
    );
    assert_eq!(
        expanded(&outer_aggregate),
        [
            "STATE.mode",
            "STATE.samples[0]",
            "STATE.samples[1]",
            "STATE.samples[2]",
        ]
    );
}

/// A type that contains itself cannot be expanded, and says so rather than not returning.
///
/// XTCE forbids it — `MemberType`: "Circular references are not allowed" — but a file can
/// still say it, and following it would recurse until the stack ran out.
#[test]
fn a_type_that_contains_itself_is_refused() {
    let xml = definition(
        r#"<AggregateParameterType name="LOOP_T"><MemberList>
             <Member name="head" typeRef="U8"/>
             <Member name="tail" typeRef="LOOP_T"/>
           </MemberList></AggregateParameterType>"#,
        r#"<Parameter name="LOOP" parameterTypeRef="LOOP_T"/>"#,
        r#"<ParameterRefEntry parameterRef="LOOP"/>"#,
    );
    let Err(error) = XtceDb::from_xml(&xml) else {
        panic!("a self-referential aggregate cannot load");
    };
    assert!(
        error.to_string().contains("contains itself"),
        "unexpected error: {error}"
    );
}

/// An aggregate with no members has nothing to place, which is a definition error.
#[test]
fn an_aggregate_with_no_members_is_reported() {
    let xml = definition(
        r#"<AggregateParameterType name="EMPTY_T"><MemberList/></AggregateParameterType>"#,
        r#"<Parameter name="EMPTY" parameterTypeRef="EMPTY_T"/>"#,
        r#"<ParameterRefEntry parameterRef="EMPTY"/>"#,
    );
    let db = XtceDb::from_xml(&xml).expect("the definition still loads");
    assert!(
        db.unsupported()
            .iter()
            .any(|item| item.element.contains("AggregateParameterType")),
        "an empty aggregate should be reported as represented but not decodable"
    );
}

/// The ceiling counts leaves, not one array's elements.
///
/// An aggregate of arrays of aggregates reaches large numbers without any single dimension
/// looking unreasonable, which is why the limit is where it is.
#[test]
fn the_ceiling_counts_leaves_across_the_whole_nesting() {
    let xml = definition(
        r#"<AggregateParameterType name="PAIR_T"><MemberList>
             <Member name="a" typeRef="U8"/>
             <Member name="b" typeRef="U8"/>
           </MemberList></AggregateParameterType>
           <ArrayParameterType name="MANY_T" arrayTypeRef="PAIR_T"><DimensionList>
             <Dimension><StartingIndex><FixedValue>0</FixedValue></StartingIndex>
                        <EndingIndex><FixedValue>2999</FixedValue></EndingIndex></Dimension>
           </DimensionList></ArrayParameterType>"#,
        r#"<Parameter name="MANY" parameterTypeRef="MANY_T"/>"#,
        r#"<ParameterRefEntry parameterRef="MANY"/>"#,
    );
    // Three thousand pairs is six thousand leaves, from a dimension that on its own is under
    // the limit.
    let Err(error) = XtceDb::from_xml(&xml) else {
        panic!("six thousand leaves is too many");
    };
    assert!(
        error.to_string().contains("4096"),
        "the refusal should name the ceiling: {error}"
    );
}
