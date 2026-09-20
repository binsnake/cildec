//! Golden tests: cildec against System.Reflection.Metadata.
//!
//! `tools/gen-golden` dumps a fixture with System.Reflection.Metadata and the
//! runtime opcode table; this test dumps the same fixture with cildec in the
//! same format and compares line by line. A difference is either a bug here or
//! a deliberate change, in which case regenerate the golden file with
//! `fixtures/build.sh` and say why in the commit.

mod common;

use common::dump::{dump, first_difference};

use std::collections::BTreeMap;

use cildec::tables::MethodDefRow;
use cildec::{HandlerKind, MethodBody, OpCode, PeImage, TableId};

const FIXTURES: &[&str] = &["Features", "IlFeatures"];

#[test]
fn fixtures_match_their_golden_dumps() {
    for name in FIXTURES {
        let image_path = format!("{}/fixtures/{name}.dll", env!("CARGO_MANIFEST_DIR"));
        let golden_path = format!("{}/fixtures/golden/{name}.txt", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&image_path).unwrap_or_else(|e| panic!("read {image_path}: {e}"));
        let expected = std::fs::read_to_string(&golden_path)
            .unwrap_or_else(|e| panic!("read {golden_path}: {e}"))
            .replace("\r\n", "\n");
        let actual = dump(&bytes);

        if actual != expected {
            let diff = first_difference(&expected, &actual);
            std::fs::write(
                format!("{}/target/{name}.actual.txt", env!("CARGO_MANIFEST_DIR")),
                &actual,
            )
            .ok();
            panic!("{name} does not match its golden dump\n{diff}");
        }
    }
}

#[test]
fn every_fixture_method_tiles_its_code_and_branches_to_boundaries() {
    for name in FIXTURES {
        let path = format!("{}/fixtures/{name}.dll", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&path).expect("read fixture");
        let image = PeImage::parse(&bytes).expect("parse PE");
        let metadata = image.metadata().expect("metadata");
        let tables = metadata.tables();
        for (rid, row) in tables.iter::<MethodDefRow>() {
            let row: MethodDefRow = row.expect("MethodDef row");
            let Some(body) = MethodBody::from_image(&image, &row).expect("body") else {
                continue;
            };
            let offsets = body.instruction_offsets();
            let total: u32 = body.instructions().map(|i| i.expect("decode").size).sum();
            assert_eq!(
                total as usize,
                body.code_size(),
                "{name} MethodDef {rid}: instruction sizes do not tile the code"
            );
            for item in body.instructions() {
                let instruction = item.expect("decode");
                for &target in instruction.operand.branch_targets() {
                    assert!(
                        offsets.binary_search(&target).is_ok(),
                        "{name} MethodDef {rid}: branch target {target:#x} is not a boundary"
                    );
                }
            }
            body.validate_handlers()
                .unwrap_or_else(|e| panic!("{name} MethodDef {rid} exception table: {e}"));
        }
    }
}

#[test]
fn the_fixtures_cover_the_features_they_are_meant_to() {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    let mut handler_kinds: BTreeMap<&str, usize> = BTreeMap::new();
    let mut tables_present: BTreeMap<&str, u32> = BTreeMap::new();

    for name in FIXTURES {
        let path = format!("{}/fixtures/{name}.dll", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&path).expect("read fixture");
        let image = PeImage::parse(&bytes).expect("parse PE");
        let metadata = image.metadata().expect("metadata");
        let tables = metadata.tables();
        for &id in TableId::ALL {
            if tables.row_count(id) > 0 {
                *tables_present.entry(id.name()).or_default() += tables.row_count(id);
            }
        }
        for (_, row) in tables.iter::<MethodDefRow>() {
            let row: MethodDefRow = row.expect("MethodDef row");
            let Some(body) = MethodBody::from_image(&image, &row).expect("body") else {
                continue;
            };
            for handler in &body.exception_handlers {
                let kind = match handler.kind {
                    HandlerKind::Catch(_) => "catch",
                    HandlerKind::Filter { .. } => "filter",
                    HandlerKind::Finally => "finally",
                    HandlerKind::Fault => "fault",
                };
                *handler_kinds.entry(kind).or_default() += 1;
            }
            for item in body.folded_instructions() {
                let folded = item.expect("fold");
                if folded.prefixes.volatile {
                    *seen.entry("volatile.").or_default() += 1;
                }
                if folded.prefixes.tail {
                    *seen.entry("tail.").or_default() += 1;
                }
                if folded.prefixes.unaligned.is_some() {
                    *seen.entry("unaligned.").or_default() += 1;
                }
                if folded.prefixes.constrained.is_some() {
                    *seen.entry("constrained.").or_default() += 1;
                }
                if !folded.prefixes.no.is_empty() {
                    *seen.entry("no.").or_default() += 1;
                }
                *seen.entry(folded.instruction.opcode.name()).or_default() += 1;
            }
        }
    }

    for required in [
        "switch",
        "calli",
        "arglist",
        "localloc",
        "initblk",
        "cpblk",
        "ldc.i8",
        "ldc.r4",
        "ldc.r8",
        "ldc.i4.s",
        "ldc.i4.m1",
        "ldc.i4.8",
        "conv.ovf.i1",
        "conv.ovf.u8.un",
        "ldstr",
        "ldtoken",
        "ldelema",
        "leave",
        "endfilter",
        "endfinally",
        "isinst",
        "newobj",
        "volatile.",
        "tail.",
        "unaligned.",
        "constrained.",
        "no.",
    ] {
        assert!(seen.contains_key(required), "fixtures do not cover {required}");
    }
    for kind in ["catch", "filter", "finally", "fault"] {
        assert!(handler_kinds.contains_key(kind), "fixtures do not cover a {kind} handler");
    }
    for table in [
        "TypeDef",
        "Field",
        "MethodDef",
        "Param",
        "InterfaceImpl",
        "MemberRef",
        "Constant",
        "CustomAttribute",
        "FieldMarshal",
        "ClassLayout",
        "FieldLayout",
        "StandAloneSig",
        "EventMap",
        "Event",
        "PropertyMap",
        "Property",
        "MethodSemantics",
        "MethodImpl",
        "ModuleRef",
        "TypeSpec",
        "ImplMap",
        "FieldRva",
        "NestedClass",
        "GenericParam",
        "MethodSpec",
        "GenericParamConstraint",
    ] {
        assert!(tables_present.contains_key(table), "fixtures have no {table} rows");
    }
}

/// `canonical()` is what a consumer dispatches on, so check it against the
/// encodings the fixtures actually contain.
#[test]
fn fixture_opcodes_canonicalise_sensibly() {
    assert_eq!(OpCode::Ldarg0.canonical(), OpCode::Ldarg);
    assert_eq!(OpCode::LdargS.canonical(), OpCode::Ldarg);
    assert_eq!(OpCode::LdcI4M1.canonical(), OpCode::LdcI4);
    assert_eq!(OpCode::LeaveS.canonical(), OpCode::Leave);
}
