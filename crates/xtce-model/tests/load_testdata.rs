//! Loads every bundled XTCE file and asserts the model comes out coherent.
//!
//! This is the M1 exit condition from the project specification, expressed as a test so it
//! runs in CI rather than only from the command line.

use std::path::PathBuf;

use xtce_model::{EntryKind, TypeKind, XtceDb};

fn testdata(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/spp")
        .join(relative)
}

const FILES: &[&str] = &[
    "test_xtce.xml",
    "test_xtce_no_namespace.xml",
    "test_xtce_default_namespace.xml",
    "test_xtce_4byte.xml",
    "udp_packet.xml",
    "jpss/jpss1_geolocation_xtce_v1.xml",
    "jpss/contrived_inheritance_structure.xml",
    "ctim/ctim_xtce_v1.xml",
    "suda/suda_combined_science_definition.xml",
    "idex/idex_combined_science_definition.xml",
];

#[test]
fn every_bundled_file_loads() {
    for file in FILES {
        let db =
            XtceDb::from_path(testdata(file)).unwrap_or_else(|error| panic!("{file}: {error}"));
        let stats = db.stats();

        assert!(stats.space_systems >= 1, "{file}: no space systems");
        assert!(stats.parameters > 0, "{file}: no parameters");
        assert!(stats.containers > 0, "{file}: no containers");

        // Every entry must point at something that exists in the arenas.
        for entry in db.entries() {
            match entry.kind {
                EntryKind::Parameter(id) => {
                    assert!(db.parameter(id).is_some(), "{file}: dangling parameter id");
                    assert!(db.type_of(id).is_some(), "{file}: dangling type id");
                }
                EntryKind::Container(id) => {
                    assert!(db.container(id).is_some(), "{file}: dangling container id");
                }
                EntryKind::Unsupported { .. } => {}
            }
        }

        // Inheritance links must be symmetric.
        for (index, container) in db.containers().iter().enumerate() {
            if let Some(base) = container.base {
                let parent = db.container(base).expect("base container exists");
                assert!(
                    parent.inheritors.iter().any(|id| id.index() == index),
                    "{file}: {} is not listed as an inheritor of its base",
                    db.name(container.name)
                );
            }
        }
    }
}

#[test]
fn jpss_geolocation_matches_reference_expectations() {
    let db = XtceDb::from_path(testdata("jpss/jpss1_geolocation_xtce_v1.xml"))
        .expect("jpss definition loads");

    let usec = db.find_parameter("USEC").expect("USEC exists");
    let parameter = db.parameter(usec).expect("USEC resolves");
    assert_eq!(
        parameter.short_description.map(|id| db.name(id)),
        Some("Secondary Header Fine Time (microsecond)")
    );
    assert_eq!(
        parameter.long_description.map(|id| db.name(id)),
        Some("CCSDS Packet 2nd Header Fine Time in microseconds.")
    );

    let apid = db.find_parameter("PKT_APID").expect("PKT_APID exists");
    let apid_type = db.type_of(apid).expect("PKT_APID has a type");
    assert!(matches!(apid_type.kind, TypeKind::Integer));
    assert_eq!(apid_type.fixed_size_in_bits(), Some(11));

    let root = db.find_container("CCSDSPacket").expect("root container");
    assert!(db.container(root).expect("root resolves").base.is_none());
    assert_eq!(db.default_root_container(), Some(root));
}

#[test]
fn namespace_variants_produce_identical_models() {
    let prefixed = XtceDb::from_path(testdata("test_xtce.xml")).expect("prefixed loads");
    let defaulted =
        XtceDb::from_path(testdata("test_xtce_default_namespace.xml")).expect("default ns loads");
    let bare = XtceDb::from_path(testdata("test_xtce_no_namespace.xml")).expect("no ns loads");

    // The three files differ only in namespace declarations and in a couple of parameters,
    // so compare the shape that must be namespace-independent.
    for db in [&defaulted, &bare] {
        assert_eq!(
            db.stats().containers,
            prefixed.stats().containers,
            "container count differs between namespace variants"
        );
    }
    // Only the binding for the element's own prefix counts: the no-namespace file still
    // declares `xmlns:xsi`, which must not be mistaken for an XTCE namespace.
    assert_eq!(
        prefixed.xmlns(),
        Some("http://www.omg.org/spec/XTCE/20180204")
    );
    assert_eq!(
        defaulted.xmlns(),
        Some("http://www.omg.org/spec/XTCE/20180204")
    );
    assert_eq!(bare.xmlns(), None);
}

#[test]
fn ctim_string_and_signed_types_are_modelled() {
    let db = XtceDb::from_path(testdata("ctim/ctim_xtce_v1.xml")).expect("ctim loads");
    let stats = db.stats();
    assert!(stats.parameters > 1000, "ctim should be a large database");

    let has_string = db
        .types()
        .iter()
        .any(|ty| matches!(ty.kind, TypeKind::String));
    assert!(has_string, "ctim defines a StringParameterType");

    let has_signed = db.types().iter().any(|ty| {
        matches!(
            &ty.encoding,
            xtce_model::DataEncoding::Integer(encoding)
                if encoding.coding == xtce_model::IntegerCoding::TwosComplement
        )
    });
    assert!(has_signed, "ctim defines a twosComplement integer");
}

#[test]
fn idex_dynamic_binary_size_resolves_to_a_parameter() {
    let db = XtceDb::from_path(testdata("idex/idex_combined_science_definition.xml"))
        .expect("idex loads");

    let dynamic = db
        .types()
        .iter()
        .filter_map(|ty| match &ty.encoding {
            xtce_model::DataEncoding::Binary(encoding) => Some(&encoding.size),
            _ => None,
        })
        .find_map(|size| match size {
            xtce_model::SizeSpec::Dynamic {
                parameter,
                adjustment,
                ..
            } => Some((*parameter, *adjustment)),
            _ => None,
        })
        .expect("idex has a dynamically sized binary field");

    let (parameter, adjustment) = dynamic;
    assert_eq!(
        db.name(db.parameter(parameter).expect("resolves").name),
        "PKT_LEN"
    );
    let adjustment = adjustment.expect("idex declares a LinearAdjustment");
    assert!((adjustment.slope - 8.0).abs() < f64::EPSILON);
    assert!((adjustment.intercept - -328.0).abs() < f64::EPSILON);
}
