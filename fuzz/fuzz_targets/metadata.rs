#![no_main]
//! Fuzzes `Metadata::parse` on a bare metadata blob: the stream directory, the
//! four heaps, and every row of every table.

use libfuzzer_sys::fuzz_target;

use cildec::{Metadata, Names, Strictness, TableId};

/// How many rows of one table a single input may drive.
const ROW_LIMIT: u32 = 1 << 14;

/// How many names to resolve. Name rendering allocates and formats, so it is
/// the most expensive thing per row here; a small sample still reaches every
/// branch of `Names` because the interesting cases are which token kind a row
/// points at, not how many rows there are.
const NAME_LIMIT: u32 = 64;

macro_rules! walk {
    ($tables:expr, $($row:ty),* $(,)?) => {
        $(
            for (_, row) in $tables.iter::<$row>().take(ROW_LIMIT as usize) {
                let _ = row.is_ok();
            }
            // `iter_indirect` only differs from `iter` when the matching `*Ptr`
            // table has rows; walking it otherwise is the same work twice.
            if <$row as cildec::TableRow>::TABLE
                .ptr_source()
                .is_some_and(|ptr| $tables.row_count(ptr) > 0)
            {
                for (_, row) in $tables.iter_indirect::<$row>().take(ROW_LIMIT as usize) {
                    let _ = row.is_ok();
                }
            }
        )*
    };
}

fuzz_target!(|data: &[u8]| {
    for strictness in [Strictness::Permissive, Strictness::Strict] {
        let Ok(metadata) = Metadata::parse_with(data, strictness) else { continue };
        let _ = metadata.version_string();
        let _ = metadata.has_pdb_stream();
        for stream in metadata.streams() {
            let _ = stream.name_lossy();
        }
        for (_, bytes) in metadata.strings().iter().take(ROW_LIMIT as usize) {
            let _ = core::str::from_utf8(bytes);
        }
        for (_, blob) in metadata.blobs().iter().take(ROW_LIMIT as usize) {
            let _ = blob.len();
        }
        for (_, text) in metadata.user_strings().iter().take(NAME_LIMIT as usize) {
            let _ = text.to_string_lossy();
        }
        for (_, guid) in metadata.guids().iter().take(ROW_LIMIT as usize) {
            let _ = guid;
        }

        let tables = metadata.tables();
        let names = Names::new(&metadata);
        for &id in TableId::ALL {
            let count = tables.row_count(id).min(ROW_LIMIT);
            let columns = tables.layout(id).column_count as usize;
            for rid in 1..=count {
                let _ = tables.row_bytes(id, rid);
                for column in 0..columns {
                    let _ = tables.raw_column(id, rid, column);
                }
            }
        }

        walk!(
            tables,
            cildec::tables::ModuleRow,
            cildec::tables::TypeRefRow,
            cildec::tables::TypeDefRow,
            cildec::tables::FieldRow,
            cildec::tables::MethodDefRow,
            cildec::tables::ParamRow,
            cildec::tables::InterfaceImplRow,
            cildec::tables::MemberRefRow,
            cildec::tables::ConstantRow,
            cildec::tables::CustomAttributeRow,
            cildec::tables::ClassLayoutRow,
            cildec::tables::FieldLayoutRow,
            cildec::tables::StandAloneSigRow,
            cildec::tables::EventRow,
            cildec::tables::PropertyRow,
            cildec::tables::MethodSemanticsRow,
            cildec::tables::MethodImplRow,
            cildec::tables::TypeSpecRow,
            cildec::tables::ImplMapRow,
            cildec::tables::FieldRvaRow,
            cildec::tables::AssemblyRow,
            cildec::tables::AssemblyRefRow,
            cildec::tables::ExportedTypeRow,
            cildec::tables::ManifestResourceRow,
            cildec::tables::NestedClassRow,
            cildec::tables::GenericParamRow,
            cildec::tables::MethodSpecRow,
            cildec::tables::GenericParamConstraintRow,
            cildec::tables::CustomDebugInformationRow,
        );

        // The lookups do their own arithmetic on row counts and list columns,
        // so they run over every row; only the name rendering is sampled.
        let type_count = tables.row_count(TableId::TypeDef).min(ROW_LIMIT);
        for rid in 1..=type_count {
            let type_def = cildec::Rid::new(rid);
            let _ = tables.field_range(type_def);
            let _ = tables.method_range(type_def);
            let _ = tables.class_layout_of(type_def);
            let _ = tables.interface_impls(type_def);
            let _ = tables.enclosing_type(type_def);
            if rid <= NAME_LIMIT {
                let _ = names.type_def(type_def);
            }
        }
        let method_count = tables.row_count(TableId::MethodDef).min(ROW_LIMIT);
        for rid in 1..=method_count {
            let method = cildec::Rid::new(rid);
            let _ = tables.param_range(method);
            let _ = tables.type_of_method(method);
            let _ = tables.generic_params(method.token());
            let _ = tables.impl_map_of(method.token());
            if rid <= NAME_LIMIT {
                let _ = names.method_def_full(method);
            }
        }
        let field_count = tables.row_count(TableId::Field).min(ROW_LIMIT);
        for rid in 1..=field_count {
            let field = cildec::Rid::new(rid);
            let _ = tables.type_of_field(field);
            let _ = tables.field_rva_of(field);
            let _ = tables.field_layout_of(field);
        }
        // Token naming covers the kinds a row can point at, not every row.
        for &id in TableId::ALL {
            for rid in 1..=tables.row_count(id).min(4) {
                let _ = names.token(cildec::Token::new(id, rid));
            }
        }
    }
});
