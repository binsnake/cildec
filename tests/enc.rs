//! The uncompressed `#-` table stream and its `*Ptr` indirection tables.
//!
//! An edit-and-continue image stores its tables in a `#-` stream and may carry
//! `FieldPtr`, `MethodPtr`, `ParamPtr`, `EventPtr` and `PropertyPtr` tables that
//! remap logical RIDs onto physical rows. No compiler emits such an image on
//! demand, so the fixture here is built byte by byte: the layout is exactly what
//! ECMA-335 II.24.2.6 specifies, and building it in the test keeps the fixture
//! readable and reproducible without a committed binary.

mod common;

use common::{MetadataBuilder, module_row};

use cildec::tables::{FieldRow, MethodDefRow, TypeDefRow};
use cildec::{Metadata, Rid, Strictness, StringIndex, TableId, marker};

/// Two fields and two methods, each reversed by its `*Ptr` table.
fn reversed_image(stream_name: &str) -> Vec<u8> {
    let mut b = MetadataBuilder::new();
    let module_name = b.string("Enc.dll");
    let type_name = b.string("Widget");
    let namespace = b.string("Fixtures");
    let alpha = b.string("Alpha");
    let beta = b.string("Beta");
    let first = b.string("First");
    let second = b.string("Second");

    b.table(TableId::Module, 1, module_row(module_name));

    let mut type_def = Vec::new();
    type_def.extend_from_slice(&0x0010_0001u32.to_le_bytes()); // Flags
    type_def.extend_from_slice(&type_name.to_le_bytes());
    type_def.extend_from_slice(&namespace.to_le_bytes());
    type_def.extend_from_slice(&0u16.to_le_bytes()); // Extends: null
    type_def.extend_from_slice(&1u16.to_le_bytes()); // FieldList
    type_def.extend_from_slice(&1u16.to_le_bytes()); // MethodList
    b.table(TableId::TypeDef, 1, type_def);

    // FieldPtr: logical 1 -> physical 2, logical 2 -> physical 1.
    let mut field_ptr = Vec::new();
    field_ptr.extend_from_slice(&2u16.to_le_bytes());
    field_ptr.extend_from_slice(&1u16.to_le_bytes());
    b.table(TableId::FieldPtr, 2, field_ptr);

    let mut fields = Vec::new();
    for name in [alpha, beta] {
        fields.extend_from_slice(&0x0006u16.to_le_bytes()); // Flags
        fields.extend_from_slice(&name.to_le_bytes());
        fields.extend_from_slice(&0u16.to_le_bytes()); // Signature
    }
    b.table(TableId::Field, 2, fields);

    let mut method_ptr = Vec::new();
    method_ptr.extend_from_slice(&2u16.to_le_bytes());
    method_ptr.extend_from_slice(&1u16.to_le_bytes());
    b.table(TableId::MethodPtr, 2, method_ptr);

    let mut methods = Vec::new();
    for (rva, name) in [(0x2050u32, first), (0x2060u32, second)] {
        methods.extend_from_slice(&rva.to_le_bytes());
        methods.extend_from_slice(&0u16.to_le_bytes()); // ImplFlags
        methods.extend_from_slice(&0x0086u16.to_le_bytes()); // Flags
        methods.extend_from_slice(&name.to_le_bytes());
        methods.extend_from_slice(&0u16.to_le_bytes()); // Signature
        methods.extend_from_slice(&1u16.to_le_bytes()); // ParamList
    }
    b.table(TableId::MethodDef, 2, methods);

    b.build(stream_name)
}

fn name_of(metadata: &Metadata<'_>, index: StringIndex) -> String {
    metadata.strings().str(index).expect("name").to_owned()
}

#[test]
fn the_uncompressed_stream_is_recognised() {
    let bytes = reversed_image("#-");
    let metadata = Metadata::parse(&bytes).expect("parse");
    assert!(metadata.is_uncompressed());
    assert!(metadata.tables().is_uncompressed());
    assert_eq!(metadata.tables().row_count(TableId::FieldPtr), 2);
    assert_eq!(metadata.tables().row_count(TableId::MethodPtr), 2);

    let compressed = reversed_image("#~");
    assert!(!Metadata::parse(&compressed).expect("parse").is_uncompressed());
}

#[test]
fn typed_accessors_follow_the_ptr_indirection() {
    let bytes = reversed_image("#-");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let tables = metadata.tables();

    // Logical RID 1 resolves through FieldPtr to physical row 2, "Beta".
    let logical: FieldRow = tables.field(1).expect("field 1");
    assert_eq!(name_of(&metadata, logical.name), "Beta");
    let logical: FieldRow = tables.field(2).expect("field 2");
    assert_eq!(name_of(&metadata, logical.name), "Alpha");

    // The raw accessor bypasses it.
    let raw: FieldRow = tables.row::<FieldRow>(1).expect("raw field 1");
    assert_eq!(name_of(&metadata, raw.name), "Alpha");

    let logical: MethodDefRow = tables.method_def(1).expect("method 1");
    assert_eq!(name_of(&metadata, logical.name), "Second");
    assert_eq!(logical.rva, 0x2060);
    let raw: MethodDefRow = tables.row::<MethodDefRow>(1).expect("raw method 1");
    assert_eq!(name_of(&metadata, raw.name), "First");
    assert_eq!(raw.rva, 0x2050);

    assert_eq!(tables.resolve_indirection(TableId::Field, 1).unwrap(), 2);
    assert_eq!(tables.resolve_indirection(TableId::MethodDef, 2).unwrap(), 1);
    // A table with no indirection resolves to itself.
    assert_eq!(tables.resolve_indirection(TableId::TypeDef, 1).unwrap(), 1);
}

#[test]
fn list_ranges_address_the_ptr_table() {
    let bytes = reversed_image("#-");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let tables = metadata.tables();
    let type_def: Rid<marker::TypeDef> = Rid::new(1);

    assert_eq!(tables.logical_row_count(TableId::Field), 2);
    assert_eq!(tables.field_range(type_def).expect("fields"), 1..3);
    assert_eq!(tables.method_range(type_def).expect("methods"), 1..3);

    // Walking the range through the typed accessor yields the logical order.
    let names: Vec<String> = tables
        .field_range(type_def)
        .expect("fields")
        .map(|rid| name_of(&metadata, tables.field(rid).expect("field").name))
        .collect();
    assert_eq!(names, ["Beta", "Alpha"]);
}

#[test]
fn indirect_iteration_matches_the_typed_accessor() {
    let bytes = reversed_image("#-");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let tables = metadata.tables();

    let indirect: Vec<String> = tables
        .iter_indirect::<FieldRow>()
        .map(|(_, row)| name_of(&metadata, row.expect("row").name))
        .collect();
    assert_eq!(indirect, ["Beta", "Alpha"]);

    let raw: Vec<String> = tables
        .iter::<FieldRow>()
        .map(|(_, row)| name_of(&metadata, row.expect("row").name))
        .collect();
    assert_eq!(raw, ["Alpha", "Beta"]);
}

#[test]
fn a_compressed_stream_with_no_ptr_tables_is_unaffected() {
    let mut b = MetadataBuilder::new();
    let module_name = b.string("Plain.dll");
    let alpha = b.string("Alpha");
    b.table(TableId::Module, 1, module_row(module_name));
    let mut fields = Vec::new();
    fields.extend_from_slice(&0x0006u16.to_le_bytes());
    fields.extend_from_slice(&alpha.to_le_bytes());
    fields.extend_from_slice(&0u16.to_le_bytes());
    b.table(TableId::Field, 1, fields);

    let bytes = b.build("#~");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let tables = metadata.tables();
    assert_eq!(tables.row_count(TableId::FieldPtr), 0);
    assert_eq!(tables.resolve_indirection(TableId::Field, 1).unwrap(), 1);
    let row: FieldRow = tables.field(1).expect("field");
    assert_eq!(name_of(&metadata, row.name), "Alpha");
}

#[test]
fn a_type_def_row_reads_back_what_was_written() {
    let bytes = reversed_image("#-");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let row: TypeDefRow = metadata.tables().type_def(1).expect("type");
    assert_eq!(name_of(&metadata, row.type_name), "Widget");
    assert_eq!(name_of(&metadata, row.type_namespace), "Fixtures");
    assert_eq!(row.flags, 0x0010_0001);
    assert!(row.extends.is_null());
}

#[test]
fn every_truncation_of_the_enc_image_is_handled() {
    let bytes = reversed_image("#-");
    for len in 0..bytes.len() {
        let _ = Metadata::parse(&bytes[..len]);
        let _ = Metadata::parse_with(&bytes[..len], Strictness::Strict);
    }
    assert!(Metadata::parse(&bytes).is_ok());
}
