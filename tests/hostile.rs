//! Metadata that is structurally valid but semantically hostile.
//!
//! Every region here parses: the streams are well formed, the row counts are
//! honest, and the indices are in range. What is wrong is the *graph* the rows
//! describe — a type that encloses itself, a `TypeRef` scoped to itself, a
//! `TypeSpec` that names itself, a table that claims to be sorted and is not.
//!
//! Random mutation finds these only by luck, so they are written out by hand.
//! Each one must terminate with a bounded answer rather than recursing,
//! looping, or returning something wrong.

mod common;

use common::{MetadataBuilder, module_row, type_def_or_ref_or_spec};

use cildec::tables::CustomAttributeRow;
use cildec::{DiagnosticCode, ErrorKind, Metadata, Names, Rid, TableId, Token, marker};

/// Two `TypeRef` rows whose resolution scopes point at each other.
#[test]
fn a_type_ref_scope_cycle_terminates() {
    let mut b = MetadataBuilder::new();
    let module_name = b.string("Cycle.dll");
    let alpha = b.string("Alpha");
    let beta = b.string("Beta");
    let namespace = b.string("N");
    b.table(TableId::Module, 1, module_row(module_name));

    // ResolutionScope is a 2-bit coded index; tag 3 is TypeRef.
    let scope_of = |rid: u32| ((rid << 2) | 3) as u16;
    let mut rows = Vec::new();
    for (scope, name) in [(scope_of(2), alpha), (scope_of(1), beta)] {
        rows.extend_from_slice(&scope.to_le_bytes());
        rows.extend_from_slice(&name.to_le_bytes());
        rows.extend_from_slice(&namespace.to_le_bytes());
    }
    b.table(TableId::TypeRef, 2, rows);

    let bytes = b.build("#~");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let names = Names::new(&metadata);

    // The cycle is cut, not followed. `type_ref` reports the depth cap, and
    // `token` renders the documented `Table[rid]` fallback instead of looping.
    let deep = names.type_ref(Rid::new(1));
    assert_eq!(deep.unwrap_err().kind, ErrorKind::RecursionLimit);
    let rendered = names.token(Token::new(TableId::TypeRef, 1));
    assert_eq!(rendered, "TypeRef[1]");
    // The cap is small enough that the recursion it allows is cheap, and large
    // enough that no real nesting depth reaches it.
    assert_eq!(Names::<'_, '_>::MAX_DEPTH, 32);

    // A TypeRef with an ordinary scope still renders its name, so the cap has
    // not simply disabled TypeRef naming.
    let mut b = MetadataBuilder::new();
    let module_name = b.string("Plain.dll");
    let name = b.string("Alpha");
    let namespace = b.string("N");
    b.table(TableId::Module, 1, module_row(module_name));
    let mut rows = Vec::new();
    rows.extend_from_slice(&0u16.to_le_bytes()); // scope: Module 0, i.e. none
    rows.extend_from_slice(&name.to_le_bytes());
    rows.extend_from_slice(&namespace.to_le_bytes());
    b.table(TableId::TypeRef, 1, rows);
    let bytes = b.build("#~");
    let metadata = Metadata::parse(&bytes).expect("parse");
    assert_eq!(Names::new(&metadata).token(Token::new(TableId::TypeRef, 1)), "N.Alpha");
}

/// A `TypeSpec` whose signature names the same `TypeSpec`.
#[test]
fn a_type_spec_self_reference_terminates() {
    let mut b = MetadataBuilder::new();
    let module_name = b.string("Spec.dll");
    b.table(TableId::Module, 1, module_row(module_name));

    // `SZARRAY CLASS <TypeSpec 1>`: an array of the type this very row names.
    let self_ref = type_def_or_ref_or_spec(2, 1);
    let signature = b.blob(&[0x1D, 0x12, self_ref]);
    let mut rows = Vec::new();
    rows.extend_from_slice(&signature.to_le_bytes());
    b.table(TableId::TypeSpec, 1, rows);

    let bytes = b.build("#~");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let names = Names::new(&metadata);

    let rendered = names.token(Token::new(TableId::TypeSpec, 1));
    assert!(rendered.len() < 4096, "bounded, got {} chars", rendered.len());
    assert!(rendered.contains("[]"), "{rendered}");
}

/// A `NestedClass` row that makes a type enclose itself.
#[test]
fn a_nested_class_cycle_terminates() {
    let mut b = MetadataBuilder::new();
    let module_name = b.string("Nested.dll");
    let name = b.string("Loop");
    let namespace = b.string("N");
    b.table(TableId::Module, 1, module_row(module_name));

    let mut type_def = Vec::new();
    type_def.extend_from_slice(&0u32.to_le_bytes()); // Flags
    type_def.extend_from_slice(&name.to_le_bytes());
    type_def.extend_from_slice(&namespace.to_le_bytes());
    type_def.extend_from_slice(&0u16.to_le_bytes()); // Extends
    type_def.extend_from_slice(&1u16.to_le_bytes()); // FieldList
    type_def.extend_from_slice(&1u16.to_le_bytes()); // MethodList
    b.table(TableId::TypeDef, 1, type_def);

    // NestedClass 1 -> enclosed by itself.
    let mut nested = Vec::new();
    nested.extend_from_slice(&1u16.to_le_bytes());
    nested.extend_from_slice(&1u16.to_le_bytes());
    b.table(TableId::NestedClass, 1, nested);

    let bytes = b.build("#~");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let names = Names::new(&metadata);
    let rendered = names.type_def(Rid::new(1)).expect("name");
    assert_eq!(rendered, "N.Loop", "a self-enclosing type must not repeat itself");
}

/// A long but acyclic nesting chain still renders, and stays bounded.
#[test]
fn a_deep_nesting_chain_renders() {
    let depth = 64u32;
    let mut b = MetadataBuilder::new();
    let module_name = b.string("Deep.dll");
    b.table(TableId::Module, 1, module_row(module_name));

    let mut names_idx = Vec::new();
    for i in 0..depth {
        names_idx.push(b.string(&format!("T{i}")));
    }
    let namespace = b.string("N");

    let mut type_defs = Vec::new();
    for &name in &names_idx {
        type_defs.extend_from_slice(&0u32.to_le_bytes());
        type_defs.extend_from_slice(&name.to_le_bytes());
        type_defs.extend_from_slice(&namespace.to_le_bytes());
        type_defs.extend_from_slice(&0u16.to_le_bytes());
        type_defs.extend_from_slice(&1u16.to_le_bytes());
        type_defs.extend_from_slice(&1u16.to_le_bytes());
    }
    b.table(TableId::TypeDef, depth, type_defs);

    // Type i+1 is nested inside type i, so the last one is deepest.
    let mut nested = Vec::new();
    for i in 2..=depth {
        nested.extend_from_slice(&(i as u16).to_le_bytes());
        nested.extend_from_slice(&((i - 1) as u16).to_le_bytes());
    }
    b.table(TableId::NestedClass, depth - 1, nested);

    let bytes = b.build("#~");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let names = Names::new(&metadata);
    let rendered = names.type_def(Rid::new(depth)).expect("name");
    assert_eq!(rendered.matches('/').count(), depth as usize - 1);
    assert!(rendered.starts_with("N.T0/"), "{rendered}");
    assert!(rendered.ends_with(&format!("N.T{}", depth - 1)), "{rendered}");
}

/// A table the header calls sorted but whose key column descends.
#[test]
fn an_unsorted_sorted_table_falls_back_to_a_scan() {
    let mut b = MetadataBuilder::new();
    let module_name = b.string("Unsorted.dll");
    b.table(TableId::Module, 1, module_row(module_name));

    let value = b.blob(&[0x01, 0x00, 0x00, 0x00]);
    // CustomAttribute is sorted by Parent, a 5-bit coded index. Tag 7 is
    // Module, so parent = (rid << 5) | 7. These rows go 3, 2, 1: descending.
    let parent_of = |rid: u32| ((rid << 5) | 7) as u16;
    // CustomAttributeType is a 3-bit coded index; tag 2 is MethodDef.
    let constructor = ((1u32 << 3) | 2) as u16;
    let mut rows = Vec::new();
    for rid in [3u32, 2, 1] {
        rows.extend_from_slice(&parent_of(rid).to_le_bytes());
        rows.extend_from_slice(&constructor.to_le_bytes());
        rows.extend_from_slice(&value.to_le_bytes());
    }
    b.table(TableId::CustomAttribute, 3, rows);
    b.declare_sorted(TableId::CustomAttribute);

    let bytes = b.build("#~");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let tables = metadata.tables();

    assert!(tables.is_declared_sorted(TableId::CustomAttribute), "the header claims sorted");
    assert!(!tables.is_sorted(TableId::CustomAttribute), "but the rows are not");
    assert!(
        metadata.diagnostics().iter().any(|d| d.code == DiagnosticCode::TableNotSorted),
        "the deviation must be reported"
    );

    // The lookup still finds the right rows, by scanning.
    let module = Token::new(TableId::Module, 2);
    let found = tables.custom_attributes(module).expect("lookup");
    assert_eq!(found, vec![2], "row 2 is the one whose parent is Module 2");
    for rid in [1u32, 2, 3] {
        let row: CustomAttributeRow = tables.custom_attribute(rid).expect("row");
        assert_eq!(row.parent.table(), Some(TableId::Module));
    }

    // Strict mode refuses an image that lies about sortedness.
    assert!(Metadata::parse_with(&bytes, cildec::Strictness::Strict).is_err());
}

/// A `TypeDef` list column that runs backwards.
#[test]
fn a_descending_list_column_still_yields_a_usable_range() {
    let mut b = MetadataBuilder::new();
    let module_name = b.string("Lists.dll");
    let namespace = b.string("N");
    let first = b.string("First");
    let second = b.string("Second");
    let field_name = b.string("f");
    b.table(TableId::Module, 1, module_row(module_name));

    // Type 1 claims its fields start at 3, type 2 claims 1: a run that goes
    // backwards, which ECMA-335 forbids.
    let mut type_defs = Vec::new();
    for (name, field_list) in [(first, 3u16), (second, 1u16)] {
        type_defs.extend_from_slice(&0u32.to_le_bytes());
        type_defs.extend_from_slice(&name.to_le_bytes());
        type_defs.extend_from_slice(&namespace.to_le_bytes());
        type_defs.extend_from_slice(&0u16.to_le_bytes());
        type_defs.extend_from_slice(&field_list.to_le_bytes());
        type_defs.extend_from_slice(&1u16.to_le_bytes());
    }
    b.table(TableId::TypeDef, 2, type_defs);

    let signature = b.blob(&[0x06, 0x08]); // FIELD int32
    let mut fields = Vec::new();
    for _ in 0..3 {
        fields.extend_from_slice(&0x0006u16.to_le_bytes());
        fields.extend_from_slice(&field_name.to_le_bytes());
        fields.extend_from_slice(&signature.to_le_bytes());
    }
    b.table(TableId::Field, 3, fields);

    let bytes = b.build("#~");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let tables = metadata.tables();

    // The range is clamped rather than wrapping around into a huge count.
    let first_range = tables.field_range(Rid::new(1)).expect("range");
    assert!(first_range.start <= first_range.end, "a range must not be inverted");
    assert!(first_range.end <= 4);
    let second_range = tables.field_range(Rid::new(2)).expect("range");
    assert!(second_range.start <= second_range.end);
    assert!(second_range.end <= 4);

    // Owner lookup terminates for every field, answering consistently.
    for rid in 1..=3u32 {
        let field: Rid<marker::Field> = Rid::new(rid);
        let owner = tables.type_of_field(field).expect("lookup");
        if let Some(owner) = owner {
            assert!(tables.field_range(owner).expect("range").contains(&rid));
        }
    }
}

/// A list column whose start index is past the end of the target table.
#[test]
fn an_out_of_range_list_column_is_clamped() {
    let mut b = MetadataBuilder::new();
    let module_name = b.string("Wild.dll");
    let namespace = b.string("N");
    let name = b.string("T");
    b.table(TableId::Module, 1, module_row(module_name));

    let mut type_def = Vec::new();
    type_def.extend_from_slice(&0u32.to_le_bytes());
    type_def.extend_from_slice(&name.to_le_bytes());
    type_def.extend_from_slice(&namespace.to_le_bytes());
    type_def.extend_from_slice(&0u16.to_le_bytes());
    type_def.extend_from_slice(&0xFFFFu16.to_le_bytes()); // FieldList, way past the end
    type_def.extend_from_slice(&0xFFFFu16.to_le_bytes()); // MethodList
    b.table(TableId::TypeDef, 1, type_def);

    let bytes = b.build("#~");
    let metadata = Metadata::parse(&bytes).expect("parse");
    let tables = metadata.tables();
    let range = tables.field_range(Rid::new(1)).expect("range");
    assert!(range.is_empty(), "there are no fields, so the range must be empty");
    assert!(range.end <= 1);
    let range = tables.method_range(Rid::new(1)).expect("range");
    assert!(range.is_empty());
}
