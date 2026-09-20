//! Walks the path the first consumer takes, in the order it takes it.
//!
//! This is a conformance test for the API rather than for the format: it drives
//! everything a CIL-to-semantics frontend needs, on the fixtures, and asserts
//! the answers rather than just that nothing panicked. If a refactor makes one
//! of these steps awkward or impossible, this test is where that shows.

use std::collections::BTreeSet;

use cildec::tables::{
    FieldRow, GenericParamRow, MemberRefRow, MethodDefRow, MethodSpecRow, StandAloneSigRow,
    TypeDefRow, TypeSpecRow,
};
use cildec::{
    CallConv, FieldSig, HandlerKind, LocalVarSig, MethodBody, MethodSig, MethodSpecSig, Names,
    Operand, PeImage, Rid, TableId, Type, TypeSpecSig, marker,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.dll", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn find_method(
    metadata: &cildec::Metadata<'_>,
    name: &str,
) -> (Rid<marker::MethodDef>, MethodDefRow) {
    for (rid, row) in metadata.tables().iter::<MethodDefRow>() {
        let row: MethodDefRow = row.expect("MethodDef row");
        if metadata.strings().str_opt(row.name) == Some(name) {
            return (Rid::new(rid), row);
        }
    }
    panic!("no method named {name}");
}

/// Step 1: bitness decision, then metadata.
#[test]
fn step_1_header_flags_drive_the_bitness_decision() {
    let bytes = fixture("Features");
    let image = PeImage::parse(&bytes).expect("parse");
    let header = image.cli_header().expect("CLI header");
    assert!(header.flags.il_only());
    // Both bitness flags are exposed separately so the consumer can decide.
    let pointer_bits = if header.flags.requires_32bit() && !header.flags.prefers_32bit() {
        32
    } else if image.is_pe32_plus() {
        64
    } else {
        32
    };
    assert!(pointer_bits == 32 || pointer_bits == 64);
    assert!(image.metadata().is_ok());
}

/// Step 2: body, locals, signature, owner type, and the method RVA.
#[test]
fn step_2_a_method_yields_its_body_locals_signature_and_owner() {
    let bytes = fixture("Features");
    let image = PeImage::parse(&bytes).expect("parse");
    let metadata = image.metadata().expect("metadata");
    let tables = metadata.tables();
    let (rid, row) = find_method(&metadata, "FirstByte");

    let body = MethodBody::from_image(&image, &row).expect("body").expect("has a body");
    assert_eq!(body.code_size(), 34);
    assert!(body.flags.init_locals());
    // The code RVA is where the IL starts, past the header.
    assert!(body.code_rva > row.rva);

    let token = body.local_var_sig.expect("has locals");
    assert_eq!(token.table(), Some(TableId::StandAloneSig));
    let sig_row: StandAloneSigRow = tables.stand_alone_sig(token.rid()).expect("row");
    let locals = LocalVarSig::parse(metadata.blobs().get(sig_row.signature).expect("blob"))
        .expect("LocalVarSig");
    assert_eq!(locals.locals.len(), 2);
    assert!(matches!(locals.locals[0].type_, Type::Ptr(_, _)));
    assert!(locals.locals[1].pinned, "the second local is the pinned array");

    let sig =
        MethodSig::parse(metadata.blobs().get(row.signature).expect("blob")).expect("MethodDefSig");
    assert!(!sig.has_this, "FirstByte is static");
    assert_eq!(sig.calling_convention, CallConv::Default);
    assert_eq!(sig.params.len(), 1);
    assert!(sig.has_return());

    let owner = tables.type_of_method(rid).expect("owner").expect("has an owner");
    let owner_row: TypeDefRow = tables.type_def(owner.get()).expect("TypeDef");
    assert_eq!(metadata.strings().str_opt(owner_row.type_name), Some("Shapes"));
    // A value type is known from its base type, which the consumer needs for
    // the shape of `this`.
    assert!(!owner_row.extends.is_null());
}

/// The `this` type of an instance method on a value type.
#[test]
fn step_2_value_type_this_is_recoverable() {
    let bytes = fixture("Features");
    let image = PeImage::parse(&bytes).expect("parse");
    let metadata = image.metadata().expect("metadata");
    let tables = metadata.tables();
    let names = Names::new(&metadata);

    let mut value_types = 0;
    for (rid, row) in tables.iter::<TypeDefRow>() {
        let row: TypeDefRow = row.expect("TypeDef row");
        if row.extends.is_null() {
            continue;
        }
        if names.token(row.extends).ends_with("System.ValueType") {
            value_types += 1;
            // Every method of a value type takes `this` by reference.
            for method_rid in tables.method_range(Rid::new(rid)).expect("methods") {
                let method: MethodDefRow = tables.method_def(method_rid).expect("method");
                let sig = MethodSig::parse(metadata.blobs().get(method.signature).expect("blob"))
                    .expect("sig");
                assert_eq!(sig.has_this, !method.is_static());
            }
        }
    }
    assert!(value_types >= 2, "the fixture defines Overlapped and Packed");
}

/// Step 3: folded instructions with absolute targets and opcode facts.
#[test]
fn step_3_folded_instructions_carry_targets_and_opcode_facts() {
    let bytes = fixture("IlFeatures");
    let image = PeImage::parse(&bytes).expect("parse");
    let metadata = image.metadata().expect("metadata");
    let (_, row) = find_method(&metadata, "Switch");
    let body = MethodBody::from_image(&image, &row).expect("body").expect("has a body");

    let mut saw_switch = false;
    let offsets = body.instruction_offsets();
    for folded in body.folded_instructions() {
        let folded = folded.expect("fold");
        let instruction = &folded.instruction;
        if let Operand::Switch(targets) = &instruction.operand {
            saw_switch = true;
            assert_eq!(targets.len(), 8);
            for &target in targets {
                assert!(offsets.binary_search(&target).is_ok(), "{target:#x} is not a boundary");
            }
            // The static facts a consumer dispatches on.
            let info = instruction.info();
            assert_eq!(info.flow, cildec::FlowControl::CondBranch);
            assert_eq!(info.pop.count(), Some(1));
            assert_eq!(info.push.count(), Some(0));
        }
    }
    assert!(saw_switch);

    // Widened short and macro operands.
    let (_, row) = find_method(&metadata, "LoadConstants");
    let body = MethodBody::from_image(&image, &row).expect("body").expect("has a body");
    let constants: Vec<i32> = body
        .instructions()
        .filter_map(|i| match i.expect("decode").operand {
            Operand::I32(value) => Some(value),
            _ => None,
        })
        .collect();
    for expected in [-1, 0, 8, -128, 127, i32::MIN, i32::MAX] {
        assert!(constants.contains(&expected), "{expected} was not decoded");
    }
}

/// Step 4: every token operand resolves to a signature.
#[test]
fn step_4_every_operand_token_resolves() {
    for name in ["Features", "IlFeatures"] {
        let bytes = fixture(name);
        let image = PeImage::parse(&bytes).expect("parse");
        let metadata = image.metadata().expect("metadata");
        let tables = metadata.tables();

        let mut resolved = BTreeSet::new();
        for (_, row) in tables.iter::<MethodDefRow>() {
            let row: MethodDefRow = row.expect("MethodDef row");
            let Some(body) = MethodBody::from_image(&image, &row).expect("body") else {
                continue;
            };
            for item in body.instructions() {
                let instruction = item.expect("decode");
                let Some(token) = instruction.operand.token() else { continue };
                if token.is_null() {
                    continue;
                }
                let table = token.table().expect("a known table");
                resolved.insert(table);
                match table {
                    TableId::MethodDef => {
                        let row: MethodDefRow = tables.method_def(token.rid()).expect("row");
                        MethodSig::parse(metadata.blobs().get(row.signature).expect("blob"))
                            .expect("MethodDefSig");
                    }
                    TableId::MemberRef => {
                        let row: MemberRefRow = tables.member_ref(token.rid()).expect("row");
                        let blob = metadata.blobs().get(row.signature).expect("blob");
                        // A MemberRef is a method or a field reference.
                        if blob.first().copied().map(|b| b & 0x0F) == Some(0x06) {
                            FieldSig::parse(blob).expect("FieldSig");
                        } else {
                            MethodSig::parse(blob).expect("MethodRefSig");
                        }
                    }
                    TableId::Field => {
                        let row: FieldRow = tables.field(token.rid()).expect("row");
                        FieldSig::parse(metadata.blobs().get(row.signature).expect("blob"))
                            .expect("FieldSig");
                    }
                    TableId::TypeSpec => {
                        let row: TypeSpecRow = tables.type_spec(token.rid()).expect("row");
                        TypeSpecSig::parse(metadata.blobs().get(row.signature).expect("blob"))
                            .expect("TypeSpecSig");
                    }
                    TableId::MethodSpec => {
                        let row: MethodSpecRow = tables.method_spec(token.rid()).expect("row");
                        MethodSpecSig::parse(
                            metadata.blobs().get(row.instantiation).expect("blob"),
                        )
                        .expect("MethodSpecSig");
                    }
                    TableId::StandAloneSig => {
                        // `calli` names a StandAloneMethodSig.
                        let row: StandAloneSigRow =
                            tables.stand_alone_sig(token.rid()).expect("row");
                        let sig =
                            MethodSig::parse(metadata.blobs().get(row.signature).expect("blob"))
                                .expect("StandAloneMethodSig");
                        assert!(sig.calling_convention.is_unmanaged() || !sig.has_this);
                    }
                    TableId::TypeDef | TableId::TypeRef => {}
                    other => panic!("unexpected operand table {other}"),
                }
            }
        }
        assert!(resolved.contains(&TableId::MemberRef), "{name}");
    }

    // The fixtures between them cover every token-bearing operand kind.
    let bytes = fixture("IlFeatures");
    let image = PeImage::parse(&bytes).expect("parse");
    let metadata = image.metadata().expect("metadata");
    let (_, row) = find_method(&metadata, "IndirectAdd");
    let body = MethodBody::from_image(&image, &row).expect("body").expect("has a body");
    assert!(
        body.instructions().any(|i| matches!(i.expect("decode").operand, Operand::Sig(_))),
        "IndirectAdd should carry a calli signature operand"
    );
}

/// Step 4, continued: field layout and class layout.
#[test]
fn step_4_field_and_class_layout_are_available() {
    let bytes = fixture("Features");
    let image = PeImage::parse(&bytes).expect("parse");
    let metadata = image.metadata().expect("metadata");
    let tables = metadata.tables();

    let mut explicit = None;
    for (rid, row) in tables.iter::<TypeDefRow>() {
        let row: TypeDefRow = row.expect("TypeDef row");
        if metadata.strings().str_opt(row.type_name) == Some("Overlapped") {
            explicit = Some(Rid::<marker::TypeDef>::new(rid));
        }
    }
    let explicit = explicit.expect("Overlapped");
    let layout = tables.class_layout_of(explicit).expect("lookup").expect("has a layout");
    assert_eq!(layout.class_size, 16);
    assert_eq!(layout.packing_size, 4);

    let offsets: Vec<u32> = tables
        .field_range(explicit)
        .expect("fields")
        .map(|rid| tables.field_layout_of(Rid::new(rid)).expect("lookup").expect("has an offset"))
        .collect();
    assert_eq!(offsets, [0, 0, 8], "two fields overlap at 0 and one sits at 8");

    // Primitive widths for the same fields.
    let widths: Vec<Option<u16>> = tables
        .field_range(explicit)
        .expect("fields")
        .map(|rid| {
            let row: FieldRow = tables.field(rid).expect("field");
            let sig = FieldSig::parse(metadata.blobs().get(row.signature).expect("blob"))
                .expect("FieldSig");
            sig.type_.primitive_width(64)
        })
        .collect();
    assert_eq!(widths, [Some(32), Some(32), Some(64)]);
}

/// Step 5: exception handlers, validated.
#[test]
fn step_5_exception_handlers_validate() {
    let bytes = fixture("IlFeatures");
    let image = PeImage::parse(&bytes).expect("parse");
    let metadata = image.metadata().expect("metadata");
    let (_, row) = find_method(&metadata, "NestedRegions");
    let body = MethodBody::from_image(&image, &row).expect("body").expect("has a body");
    body.validate_handlers().expect("the fixture is well formed");

    assert_eq!(body.exception_handlers.len(), 2);
    assert!(matches!(body.exception_handlers[0].kind, HandlerKind::Filter { .. }));
    assert_eq!(body.exception_handlers[1].kind, HandlerKind::Finally);
    // The filter clause is lexically inside the finally clause.
    let inner = body.exception_handlers[0];
    let outer = body.exception_handlers[1];
    assert!(inner.try_offset >= outer.try_offset && inner.try_end() <= outer.try_end());
}

/// Step 6: `#US` for `ldstr`, `FieldRVA` data, and `ImplMap` for P/Invoke.
#[test]
fn step_6_strings_field_data_and_pinvoke() {
    let bytes = fixture("Features");
    let image = PeImage::parse(&bytes).expect("parse");
    let metadata = image.metadata().expect("metadata");
    let tables = metadata.tables();

    let mut strings = Vec::new();
    for (_, row) in tables.iter::<MethodDefRow>() {
        let row: MethodDefRow = row.expect("MethodDef row");
        let Some(body) = MethodBody::from_image(&image, &row).expect("body") else { continue };
        for item in body.instructions() {
            if let Operand::String(token) = item.expect("decode").operand {
                let text = metadata.user_strings().get(token).expect("#US entry");
                strings.push(text.to_string_lossy());
            }
        }
    }
    assert!(strings.iter().any(|s| s == "Good evening"));
    assert!(strings.iter().any(|s| s.contains('\u{4e2d}')), "the non-ASCII literal survives");

    // A field with an RVA: the initial data is readable through the image.
    let mut found_rva = false;
    for (rid, _) in tables.iter::<FieldRow>() {
        let Some(rva) = tables.field_rva_of(Rid::new(rid)).expect("lookup") else { continue };
        let data = image.rva_slice(rva, 6).expect("initial data");
        assert_eq!(data, &[0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00]);
        found_rva = true;
    }
    assert!(found_rva, "the fixture has a FieldRVA row");

    // P/Invoke methods are reported as body-less, with their mapping available.
    let (rid, row) = find_method(&metadata, "GetTickCount64");
    assert!(row.is_pinvoke());
    assert!(row.has_no_body());
    assert!(MethodBody::from_image(&image, &row).expect("body").is_none());
    let import = tables.impl_map_of(rid.token()).expect("lookup").expect("has a mapping");
    assert_eq!(metadata.strings().str_opt(import.import_name), Some("GetTickCount64"));
    let module = tables.module_ref(import.import_scope.get()).expect("ModuleRef");
    assert_eq!(metadata.strings().str_opt(module.name), Some("kernel32.dll"));
}

/// Step 7: the generic context of a method and its owner.
#[test]
fn step_7_generic_context_is_reachable() {
    let bytes = fixture("Features");
    let image = PeImage::parse(&bytes).expect("parse");
    let metadata = image.metadata().expect("metadata");
    let tables = metadata.tables();

    let (rid, row) = find_method(&metadata, "Map");
    let sig = MethodSig::parse(metadata.blobs().get(row.signature).expect("blob")).expect("sig");
    assert_eq!(sig.calling_convention, CallConv::Generic(1));

    // The method's own generic parameters.
    let method_params = tables.generic_params(rid.token()).expect("generic params");
    assert_eq!(method_params.len(), 1);
    let param: GenericParamRow = tables.generic_param(method_params[0]).expect("row");
    assert_eq!(param.number, 0);
    assert_eq!(metadata.strings().str_opt(param.name), Some("TResult"));

    // And those of the declaring type, which `Var` indices refer to.
    let owner = tables.type_of_method(rid).expect("owner").expect("has an owner");
    let type_params = tables.generic_params(owner.token()).expect("generic params");
    assert_eq!(type_params.len(), 1);
    let param: GenericParamRow = tables.generic_param(type_params[0]).expect("row");
    assert_eq!(metadata.strings().str_opt(param.name), Some("T"));
    // The constraint list is reachable from the parameter.
    let constraints = tables.generic_param_constraints(Rid::new(type_params[0])).expect("lookup");
    assert!(!constraints.is_empty(), "T is constrained to struct, IComparable<T>");

    // MethodSpec instantiations, for a later substitution phase.
    let mut instantiations = 0;
    for (rid, row) in tables.iter::<MethodSpecRow>() {
        let row: MethodSpecRow = row.expect("MethodSpec row");
        let sig = MethodSpecSig::parse(metadata.blobs().get(row.instantiation).expect("blob"))
            .expect("MethodSpecSig");
        assert!(!sig.args.is_empty(), "MethodSpec {rid} has no type arguments");
        instantiations += 1;
    }
    assert!(instantiations > 0);
}

/// `Var` and `MVar` appear where the consumer expects to substitute them.
#[test]
fn generic_parameters_appear_in_signatures() {
    let bytes = fixture("Features");
    let image = PeImage::parse(&bytes).expect("parse");
    let metadata = image.metadata().expect("metadata");
    let (_, row) = find_method(&metadata, "Map");
    let sig = MethodSig::parse(metadata.blobs().get(row.signature).expect("blob")).expect("sig");
    assert_eq!(sig.return_type.type_, Type::MVar(0));
    // The first parameter is Func<!0, !!0>: a type parameter and a method one.
    match &sig.params[0].type_ {
        Type::GenericInst { args, .. } => {
            assert_eq!(args[0], Type::Var(0));
            assert_eq!(args[1], Type::MVar(0));
        }
        other => panic!("unexpected parameter type {other:?}"),
    }
}
