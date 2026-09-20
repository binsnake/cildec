//! The canonical text dump of an image, as produced by cildec.
//!
//! `tools/gen-golden` produces the same format from System.Reflection.Metadata.
//! Two drivers compare them: `tests/golden.rs` against the committed fixture
//! dumps, and `tests/differential.rs` against whatever real assemblies are
//! installed. Keeping one dumper means a format change cannot silently make the
//! two disagree about what they are comparing.
//!
//! Every value that both sides can observe goes in: header flags, table row
//! counts, type and member signatures, layouts, locals, the full disassembly
//! and the exception table. Floats are rendered as their bit patterns so that
//! two formatters cannot disagree about rounding.

#![allow(dead_code)]

use std::fmt::Write as _;

use cildec::tables::{
    ClassLayoutRow, FieldRow, ImplMapRow, MethodDefRow, ModuleRefRow, StandAloneSigRow, TypeDefRow,
};
use cildec::{
    FieldSig, HandlerKind, LocalVarSig, Metadata, MethodBody, MethodSig, MethodSpecSig, Names,
    Operand, OperandKind, PeImage, Rid, TableId, Token, TypeSpecSig, marker,
};

pub fn first_difference(expected: &str, actual: &str) -> String {
    let mut out = String::new();
    let expected: Vec<&str> = expected.lines().collect();
    let actual: Vec<&str> = actual.lines().collect();
    for i in 0..expected.len().max(actual.len()) {
        let e = expected.get(i).copied();
        let a = actual.get(i).copied();
        if e != a {
            let _ = writeln!(out, "first difference at line {}:", i + 1);
            for context in i.saturating_sub(3)..i {
                let _ = writeln!(out, "  {}", expected.get(context).copied().unwrap_or(""));
            }
            let _ = writeln!(out, "- expected: {}", e.unwrap_or("<end of file>"));
            let _ = writeln!(out, "+ actual:   {}", a.unwrap_or("<end of file>"));
            let _ =
                writeln!(out, "({} expected lines, {} actual lines)", expected.len(), actual.len());
            return out;
        }
    }
    out
}

/// The table names System.Reflection.Metadata uses, where they differ from
/// this crate. Only capitalisation differs.
fn table_name(id: TableId) -> &'static str {
    match id {
        TableId::AssemblyOs => "AssemblyOS",
        TableId::AssemblyRefOs => "AssemblyRefOS",
        other => other.name(),
    }
}

pub fn dump(bytes: &[u8]) -> String {
    let image = PeImage::parse(bytes).expect("parse PE");
    let header = image.cli_header().expect("CLI header");
    let metadata = image.metadata().expect("metadata");
    let names = Names::new(&metadata);
    let tables = metadata.tables();
    let mut out = String::new();

    let _ =
        writeln!(out, "image pe32plus={} machine=0x{:04x}", image.is_pe32_plus(), image.machine());
    let _ = writeln!(
        out,
        "cli runtime={}.{} ilonly={} bit32required={} bit32preferred={}",
        header.major_runtime_version,
        header.minor_runtime_version,
        header.flags.il_only(),
        header.flags.requires_32bit(),
        header.flags.prefers_32bit()
    );
    let _ = writeln!(out, "metadata version={}", metadata.version_string());

    for &id in TableId::ALL {
        let count = tables.row_count(id);
        if count > 0 {
            let _ = writeln!(out, "tablerows {}={count}", table_name(id));
        }
    }

    for rid in 1..=tables.row_count(TableId::TypeDef) {
        dump_type(&mut out, &image, &metadata, &names, Rid::new(rid));
    }
    dump_rows(&mut out, &metadata, &names);
    out
}

/// A `Token` as the reference reader spells it: a null coded index is 0, not a
/// table byte with a zero RID.
fn raw(token: Token) -> u32 {
    if token.is_null() { 0 } else { token.value() }
}

fn text(metadata: &Metadata<'_>, index: cildec::StringIndex) -> String {
    metadata.strings().lossy(index).map(|s| s.into_owned()).unwrap_or_default()
}

fn blob_len(metadata: &Metadata<'_>, index: cildec::BlobIndex) -> usize {
    metadata.blobs().get(index).map(|b| b.len()).unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Quotes a plain string with the same escaping the C# side uses.
fn quote_str(value: &str) -> String {
    quote(value.encode_utf16())
}

/// Every table the type walk does not already cover, one line per row in RID
/// order.
///
/// Coded-index columns print as raw tokens rather than as names: the token is
/// exactly what the coded index decodes to, so comparing it tests the tag
/// tables of II.24.2.6 directly, and neither side has to agree with the other
/// about any naming convention to do it.
fn dump_rows(out: &mut String, metadata: &Metadata<'_>, names: &Names<'_, '_>) {
    use cildec::tables::{
        AssemblyRefRow, AssemblyRow, ConstantRow, CustomAttributeRow, DeclSecurityRow,
        ExportedTypeRow, FileRow, GenericParamConstraintRow, GenericParamRow, InterfaceImplRow,
        ManifestResourceRow, MemberRefRow, MethodImplRow, MethodSpecRow, ModuleRefRow,
        StandAloneSigRow, TypeSpecRow,
    };
    let tables = metadata.tables();

    for (rid, row) in tables.iter::<InterfaceImplRow>() {
        let row: InterfaceImplRow = row.expect("InterfaceImpl");
        let _ = writeln!(
            out,
            "row InterfaceImpl {rid} class={:#010x} interface={:#010x}",
            raw(row.class.token()),
            raw(row.interface)
        );
    }
    for (rid, row) in tables.iter::<MemberRefRow>() {
        let row: MemberRefRow = row.expect("MemberRef");
        let blob = metadata.blobs().get(row.signature).expect("MemberRef signature");
        // A MemberRef is a field reference when its signature says FIELD.
        let sig = if blob.first().copied().map(|b| b & 0x0F) == Some(0x06) {
            FieldSig::parse(blob).map(|s| names.field_sig(&s)).unwrap_or_default()
        } else {
            MethodSig::parse(blob).map(|s| names.method_sig(&s, "")).unwrap_or_default()
        };
        let _ = writeln!(
            out,
            "row MemberRef {rid} class={:#010x} name={} sig={sig}",
            raw(row.class),
            quote_str(&text(metadata, row.name))
        );
    }
    for (rid, row) in tables.iter::<ConstantRow>() {
        let row: ConstantRow = row.expect("Constant");
        let value = metadata.blobs().get(row.value).expect("Constant value");
        let _ = writeln!(
            out,
            "row Constant {rid} type={:#04x} parent={:#010x} value={}",
            row.element_type(),
            raw(row.parent),
            hex(value)
        );
    }
    for (rid, row) in tables.iter::<CustomAttributeRow>() {
        let row: CustomAttributeRow = row.expect("CustomAttribute");
        let _ = writeln!(
            out,
            "row CustomAttribute {rid} parent={:#010x} ctor={:#010x} value={}",
            raw(row.parent),
            raw(row.constructor),
            blob_len(metadata, row.value)
        );
    }
    for (rid, row) in tables.iter::<DeclSecurityRow>() {
        let row: DeclSecurityRow = row.expect("DeclSecurity");
        let _ = writeln!(
            out,
            "row DeclSecurity {rid} action={:#06x} parent={:#010x} permission={}",
            row.action,
            raw(row.parent),
            blob_len(metadata, row.permission_set)
        );
    }
    for (rid, row) in tables.iter::<StandAloneSigRow>() {
        let row: StandAloneSigRow = row.expect("StandAloneSig");
        let _ = writeln!(out, "row StandAloneSig {rid} len={}", blob_len(metadata, row.signature));
    }
    for (rid, row) in tables.iter::<MethodImplRow>() {
        let row: MethodImplRow = row.expect("MethodImpl");
        let _ = writeln!(
            out,
            "row MethodImpl {rid} class={:#010x} body={:#010x} decl={:#010x}",
            raw(row.class.token()),
            raw(row.method_body),
            raw(row.method_declaration)
        );
    }
    for (rid, row) in tables.iter::<ModuleRefRow>() {
        let row: ModuleRefRow = row.expect("ModuleRef");
        let _ = writeln!(out, "row ModuleRef {rid} name={}", quote_str(&text(metadata, row.name)));
    }
    for (rid, row) in tables.iter::<TypeSpecRow>() {
        let row: TypeSpecRow = row.expect("TypeSpec");
        let blob = metadata.blobs().get(row.signature).expect("TypeSpec signature");
        let sig = TypeSpecSig::parse(blob).map(|s| names.type_(&s.type_)).unwrap_or_default();
        let _ = writeln!(out, "row TypeSpec {rid} sig={sig}");
    }
    for (rid, row) in tables.iter::<AssemblyRow>() {
        let row: AssemblyRow = row.expect("Assembly");
        let _ = writeln!(
            out,
            "row Assembly {rid} name={} version={}.{}.{}.{} flags={:#010x} hashalg={:#010x} culture={} publickey={}",
            quote_str(&text(metadata, row.name)),
            row.major_version,
            row.minor_version,
            row.build_number,
            row.revision_number,
            row.flags,
            row.hash_alg_id,
            quote_str(&text(metadata, row.culture)),
            blob_len(metadata, row.public_key)
        );
    }
    for (rid, row) in tables.iter::<AssemblyRefRow>() {
        let row: AssemblyRefRow = row.expect("AssemblyRef");
        let _ = writeln!(
            out,
            "row AssemblyRef {rid} name={} version={}.{}.{}.{} flags={:#010x} culture={} publickey={} hash={}",
            quote_str(&text(metadata, row.name)),
            row.major_version,
            row.minor_version,
            row.build_number,
            row.revision_number,
            row.flags,
            quote_str(&text(metadata, row.culture)),
            blob_len(metadata, row.public_key_or_token),
            blob_len(metadata, row.hash_value)
        );
    }
    for (rid, row) in tables.iter::<FileRow>() {
        let row: FileRow = row.expect("File");
        let _ = writeln!(
            out,
            "row File {rid} flags={:#010x} name={} hash={}",
            row.flags,
            quote_str(&text(metadata, row.name)),
            blob_len(metadata, row.hash_value)
        );
    }
    for (rid, row) in tables.iter::<ExportedTypeRow>() {
        let row: ExportedTypeRow = row.expect("ExportedType");
        let _ = writeln!(
            out,
            "row ExportedType {rid} flags={:#010x} typedefid={:#010x} name={} namespace={} implementation={:#010x}",
            row.flags,
            row.type_def_id,
            quote_str(&text(metadata, row.type_name)),
            quote_str(&text(metadata, row.type_namespace)),
            raw(row.implementation)
        );
    }
    for (rid, row) in tables.iter::<ManifestResourceRow>() {
        let row: ManifestResourceRow = row.expect("ManifestResource");
        let _ = writeln!(
            out,
            "row ManifestResource {rid} offset={:#010x} flags={:#010x} name={} implementation={:#010x}",
            row.offset,
            row.flags,
            quote_str(&text(metadata, row.name)),
            raw(row.implementation)
        );
    }
    for (rid, row) in tables.iter::<GenericParamRow>() {
        let row: GenericParamRow = row.expect("GenericParam");
        let _ = writeln!(
            out,
            "row GenericParam {rid} number={} flags={:#06x} owner={:#010x} name={}",
            row.number,
            row.flags,
            raw(row.owner),
            quote_str(&text(metadata, row.name))
        );
    }
    for (rid, row) in tables.iter::<MethodSpecRow>() {
        let row: MethodSpecRow = row.expect("MethodSpec");
        let blob = metadata.blobs().get(row.instantiation).expect("MethodSpec instantiation");
        let args = MethodSpecSig::parse(blob)
            .map(|s| s.args.iter().map(|t| names.type_(t)).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        let _ =
            writeln!(out, "row MethodSpec {rid} method={:#010x} args=<{args}>", raw(row.method));
    }
    for (rid, row) in tables.iter::<GenericParamConstraintRow>() {
        let row: GenericParamConstraintRow = row.expect("GenericParamConstraint");
        let _ = writeln!(
            out,
            "row GenericParamConstraint {rid} owner={:#010x} constraint={:#010x}",
            raw(row.owner.token()),
            raw(row.constraint)
        );
    }
}

/// The properties and events a type owns, with their accessor methods.
///
/// `MethodSemantics` has no row enumeration in the reference reader, so it is
/// reached the way that reader can reach it: through the accessors of each
/// property and event. Getting the `HasSemantics` coded index wrong would
/// attach an accessor to the wrong member and show up here.
fn dump_members(
    out: &mut String,
    metadata: &Metadata<'_>,
    names: &Names<'_, '_>,
    rid: Rid<marker::TypeDef>,
) {
    use cildec::tables::{EventRow, PropertyRow};
    let tables = metadata.tables();

    if let Some(map) = tables.property_map_of(rid).expect("PropertyMap") {
        for property_rid in tables.property_range(map).expect("property range") {
            let row: PropertyRow = tables.property(property_rid).expect("Property");
            let blob = metadata.blobs().get(row.type_signature).expect("PropertySig blob");
            let sig = cildec::PropertySig::parse(blob)
                .map(|s| {
                    let params: Vec<String> = s.params.iter().map(|p| names.param(p)).collect();
                    format!(
                        "{}{} ({})",
                        if s.has_this { "instance " } else { "" },
                        names.param(&s.return_type),
                        params.join(", ")
                    )
                })
                .unwrap_or_default();
            let token = Token::new(TableId::Property, property_rid);
            let (getter, setter) = accessors(metadata, token, &[0x0002], &[0x0001]);
            let _ = writeln!(
                out,
                "  property {property_rid} {} sig={sig} flags={:#06x} getter={getter:#010x} setter={setter:#010x}",
                quote_str(&text(metadata, row.name)),
                row.flags
            );
        }
    }

    if let Some(map) = tables.event_map_of(rid).expect("EventMap") {
        for event_rid in tables.event_range(map).expect("event range") {
            let row: EventRow = tables.event(event_rid).expect("Event");
            let token = Token::new(TableId::Event, event_rid);
            let (adder, remover) = accessors(metadata, token, &[0x0008], &[0x0010]);
            let (raiser, _) = accessors(metadata, token, &[0x0020], &[]);
            let _ = writeln!(
                out,
                "  event {event_rid} {} type={:#010x} flags={:#06x} adder={adder:#010x} remover={remover:#010x} raiser={raiser:#010x}",
                quote_str(&text(metadata, row.name)),
                raw(row.event_type),
                row.event_flags
            );
        }
    }
}

/// The first method attached to `association` with each of two semantic masks.
fn accessors(metadata: &Metadata<'_>, association: Token, a: &[u16], b: &[u16]) -> (u32, u32) {
    use cildec::tables::MethodSemanticsRow;
    let tables = metadata.tables();
    let mut first = 0u32;
    let mut second = 0u32;
    for rid in tables.semantics_for(association).expect("MethodSemantics") {
        let row: MethodSemanticsRow = tables.method_semantics(rid).expect("MethodSemantics row");
        let token = raw(row.method.token());
        if a.iter().any(|m| row.semantics & m != 0) && first == 0 {
            first = token;
        }
        if b.iter().any(|m| row.semantics & m != 0) && second == 0 {
            second = token;
        }
    }
    (first, second)
}

fn dump_type(
    out: &mut String,
    image: &PeImage<'_>,
    metadata: &Metadata<'_>,
    names: &Names<'_, '_>,
    rid: Rid<marker::TypeDef>,
) {
    let tables = metadata.tables();
    let row: TypeDefRow = tables.type_def(rid.get()).expect("TypeDef row");
    let extends = if row.extends.is_null() { "-".to_owned() } else { names.token(row.extends) };
    let _ = writeln!(
        out,
        "type {} {} flags=0x{:08x} extends={extends}",
        rid.get(),
        names.type_def(rid).expect("type name"),
        row.flags
    );

    // System.Reflection.Metadata reports a layout through `TypeLayout`, whose
    // `IsDefault` is true when both fields are zero, so it cannot distinguish
    // "no ClassLayout row" from "a row of zeros" — which C++/CLI does emit.
    // The comparison can only cover what both sides can express, so a
    // degenerate row is skipped here too.
    if let Some(layout) = tables.class_layout_of(rid).expect("ClassLayout") {
        let layout: ClassLayoutRow = layout;
        if layout.class_size != 0 || layout.packing_size != 0 {
            let _ =
                writeln!(out, "  layout size={} pack={}", layout.class_size, layout.packing_size);
        }
    }

    for field_rid in tables.field_range(rid).expect("field range") {
        dump_field(out, metadata, names, Rid::new(field_rid));
    }
    for method_rid in tables.method_range(rid).expect("method range") {
        dump_method(out, image, metadata, names, Rid::new(method_rid));
    }
    dump_members(out, metadata, names, rid);
}

fn dump_field(
    out: &mut String,
    metadata: &Metadata<'_>,
    names: &Names<'_, '_>,
    rid: Rid<marker::Field>,
) {
    let tables = metadata.tables();
    let row: FieldRow = tables.field(rid.get()).expect("Field row");
    let blob = metadata.blobs().get(row.signature).expect("field signature");
    let sig = FieldSig::parse(blob).expect("FieldSig");
    let mut line = format!(
        "  field {} {} sig={} flags=0x{:04x}",
        rid.get(),
        metadata.strings().lossy(row.name).expect("field name"),
        names.field_sig(&sig),
        row.flags
    );
    if let Some(offset) = tables.field_layout_of(rid).expect("FieldLayout") {
        let _ = write!(line, " offset={offset}");
    }
    if let Some(marshal) = tables.field_marshal_of(rid.token()).expect("FieldMarshal") {
        let _ = write!(line, " marshal={}", blob_len(metadata, cildec::BlobIndex(marshal)));
    }
    // As with `ClassLayout`, the reference reader returns 0 both for "no
    // FieldRVA row" and "a row that says 0", so a zero RVA is skipped on both
    // sides. It carries no data either way.
    if let Some(rva) = tables.field_rva_of(rid).expect("FieldRVA") {
        if rva != 0 {
            let _ = write!(line, " rva=0x{rva:08x}");
        }
    }
    let _ = writeln!(out, "{line}");
}

fn dump_method(
    out: &mut String,
    image: &PeImage<'_>,
    metadata: &Metadata<'_>,
    names: &Names<'_, '_>,
    rid: Rid<marker::MethodDef>,
) {
    let tables = metadata.tables();
    let row: MethodDefRow = tables.method_def(rid.get()).expect("MethodDef row");
    let blob = metadata.blobs().get(row.signature).expect("method signature");
    let sig = MethodSig::parse(blob).expect("MethodDefSig");
    let _ = writeln!(
        out,
        "  method {} {} sig={} flags=0x{:04x} implflags=0x{:04x} rva=0x{:08x}",
        rid.get(),
        metadata.strings().lossy(row.name).expect("method name"),
        names.method_sig(&sig, ""),
        row.flags,
        row.impl_flags,
        row.rva
    );

    if let Some(import) = tables.impl_map_of(rid.token()).expect("ImplMap") {
        let import: ImplMapRow = import;
        let module: ModuleRefRow =
            tables.module_ref(import.import_scope.get()).expect("ModuleRef row");
        let _ = writeln!(
            out,
            "    pinvoke module={} name={} flags=0x{:04x}",
            metadata.strings().lossy(module.name).expect("module name"),
            metadata.strings().lossy(import.import_name).expect("import name"),
            import.mapping_flags
        );
    }

    let Some(body) = MethodBody::from_image(image, &row).expect("method body") else {
        return;
    };
    let _ = writeln!(
        out,
        "    maxstack {} initlocals={} codesize={}",
        body.max_stack,
        body.flags.init_locals(),
        body.code_size()
    );

    if let Some(token) = body.local_var_sig {
        let sig_row: StandAloneSigRow =
            tables.stand_alone_sig(token.rid()).expect("StandAloneSig row");
        let blob = metadata.blobs().get(sig_row.signature).expect("locals blob");
        let locals = LocalVarSig::parse(blob).expect("LocalVarSig");
        for (slot, local) in locals.locals.iter().enumerate() {
            let _ = writeln!(out, "    local {slot} {}", names.local(local));
        }
    }

    for item in body.instructions() {
        let instruction = item.expect("decode IL");
        let mut line =
            format!("    il IL_{:04x} {}", instruction.offset, instruction.opcode.name());
        if let Some(operand) = render_operand(metadata, names, &instruction) {
            let _ = write!(line, " {operand}");
        }
        let _ = writeln!(out, "{line}");
    }

    for handler in &body.exception_handlers {
        let kind = match handler.kind {
            HandlerKind::Catch(_) => "Catch",
            HandlerKind::Filter { .. } => "Filter",
            HandlerKind::Finally => "Finally",
            HandlerKind::Fault => "Fault",
        };
        let mut line = format!(
            "    eh {kind} try=IL_{:04x}..IL_{:04x} handler=IL_{:04x}..IL_{:04x}",
            handler.try_offset,
            handler.try_end(),
            handler.handler_offset,
            handler.handler_end()
        );
        match handler.kind {
            HandlerKind::Catch(token) => {
                let _ = write!(line, " type={}", token_or_dash(names, token));
            }
            HandlerKind::Filter { filter_offset } => {
                let _ = write!(line, " filter=IL_{filter_offset:04x}");
            }
            _ => {}
        }
        let _ = writeln!(out, "{line}");
    }
}

fn token_or_dash(names: &Names<'_, '_>, token: Token) -> String {
    if token.is_null() { "-".to_owned() } else { names.token(token) }
}

fn render_operand(
    metadata: &Metadata<'_>,
    names: &Names<'_, '_>,
    instruction: &cildec::Instruction,
) -> Option<String> {
    if instruction.info().operand == OperandKind::InlineNone {
        return None;
    }
    Some(match &instruction.operand {
        Operand::None => return None,
        Operand::I8(value) => format!("{value}"),
        Operand::I32(value) => format!("{value}"),
        Operand::I64(value) => format!("{value}"),
        // Floats print as their bit patterns, so that two formatters cannot
        // disagree about rounding or about how a NaN is spelled.
        Operand::R32(value) => format!("0x{:08x}", value.to_bits()),
        Operand::R64(value) => format!("0x{:016x}", value.to_bits()),
        Operand::Var(index) => format!("{index}"),
        Operand::BranchTarget(target) => format!("IL_{target:04x}"),
        Operand::Switch(targets) => {
            let list: Vec<String> = targets.iter().map(|t| format!("IL_{t:04x}")).collect();
            format!("({})", list.join(","))
        }
        Operand::String(token) => {
            let text = metadata.user_strings().get(*token).expect("#US entry");
            quote(text.code_units())
        }
        operand => match operand.token() {
            Some(token) => token_or_dash(names, token),
            None => return None,
        },
    })
}

/// Escapes a UTF-16 string the way the C# side does, one code unit at a time.
fn quote(units: impl Iterator<Item = u16>) -> String {
    let mut out = String::from("\"");
    for unit in units {
        match unit {
            0x22 => out.push_str("\\\""),
            0x5C => out.push_str("\\\\"),
            0x0A => out.push_str("\\n"),
            0x0D => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            c if (0x20..=0x7E).contains(&c) => out.push(c as u8 as char),
            c => {
                let _ = write!(out, "\\u{c:04x}");
            }
        }
    }
    out.push('"');
    out
}
