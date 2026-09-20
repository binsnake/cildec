//! Self-consistency checks over real assemblies.
//!
//! The differential test catches anything cildec reads differently from
//! System.Reflection.Metadata. These checks catch a different class of bug: the
//! places where cildec must agree with *itself*. A binary search and a linear
//! scan over the same column must find the same rows; a member found through a
//! list column must name the same owner when asked in reverse; a coded index
//! must survive a decode-and-re-encode. None of that needs a second
//! implementation, so these run wherever assemblies exist, with no .NET SDK.
//!
//! These are the properties a fuzzer would be checking if one were running, but
//! driven by real metadata rather than random bytes, which reaches deep
//! structure a mutation almost never builds.

mod common;

use common::sources::real_assemblies;

use cildec::tables::{MethodDefRow, sort_key_column};
use cildec::{CodedIndex, ColumnKind, Metadata, MethodBody, PeImage, Rid, TableId, Tables, marker};

/// Parses every assembly once and hands it to `check`.
fn for_each_assembly(check: impl Fn(&str, &PeImage<'_>, &Metadata<'_>)) {
    let images = real_assemblies();
    if images.is_empty() {
        eprintln!("no .NET assemblies found; skipping");
        return;
    }
    let mut managed = 0usize;
    for path in &images {
        let Ok(bytes) = std::fs::read(path) else { continue };
        let Ok(image) = PeImage::parse(&bytes) else { continue };
        let Ok(metadata) = image.metadata() else { continue };
        managed += 1;
        check(&path.display().to_string(), &image, &metadata);
    }
    eprintln!("checked {managed} managed assemblies");
    assert!(managed > 20, "expected real assemblies, found {managed}");
}

/// Every sorted-table lookup must agree with a linear scan of the same column.
///
/// `rows_with_key` binary-searches when the table verified as sorted. If the
/// search were wrong — an off-by-one bound, a bad comparison — it would return
/// a subset or a superset, and a scan of the same column catches it.
#[test]
fn binary_search_agrees_with_a_linear_scan() {
    for_each_assembly(|path, _image, metadata| {
        let tables = metadata.tables();
        for &id in TableId::ALL {
            let Some(column) = sort_key_column(id) else { continue };
            let count = tables.row_count(id);
            if count == 0 {
                continue;
            }

            // Every distinct key in the table, plus two that are not in it.
            // Comparing a search against a scan is quadratic, so a large table
            // contributes an evenly spread sample rather than every key; the
            // interesting cases are run boundaries, which a spread still hits.
            let mut keys = Vec::new();
            for rid in 1..=count {
                keys.push(tables.raw_column(id, rid, column).expect("column"));
            }
            keys.sort_unstable();
            keys.dedup();
            const KEY_SAMPLE: usize = 256;
            if keys.len() > KEY_SAMPLE {
                let stride = keys.len().div_ceil(KEY_SAMPLE);
                // Keep the first and last runs as well as the spread.
                let mut sampled: Vec<u32> = keys.iter().copied().step_by(stride).collect();
                sampled.extend(keys.iter().rev().take(2).copied());
                sampled.sort_unstable();
                sampled.dedup();
                keys = sampled;
            }
            keys.push(0);
            keys.push(u32::MAX);

            for key in keys {
                let found = tables.rows_with_key(id, key).expect("lookup");
                let scanned: Vec<u32> = (1..=count)
                    .filter(|&rid| tables.raw_column(id, rid, column).expect("column") == key)
                    .collect();
                assert_eq!(
                    found,
                    scanned,
                    "{path}: {} lookup for key {key:#x} disagrees with a scan (sorted={})",
                    id.name(),
                    tables.is_sorted(id)
                );
            }
        }
    });
}

/// A member reached through a list column must name the same owner in reverse.
///
/// `TypeDef.FieldList` is a run-length encoding: the owner of a field is
/// whichever type run contains it. Walking forward and backward must agree, and
/// every member must belong to exactly one owner.
#[test]
fn list_ranges_and_owner_lookups_are_inverses() {
    for_each_assembly(|path, _image, metadata| {
        let tables = metadata.tables();
        let type_count = tables.row_count(TableId::TypeDef);

        let mut field_owner = vec![0u32; tables.logical_row_count(TableId::Field) as usize + 1];
        let mut method_owner =
            vec![0u32; tables.logical_row_count(TableId::MethodDef) as usize + 1];

        for rid in 1..=type_count {
            let type_def: Rid<marker::TypeDef> = Rid::new(rid);
            for field in tables.field_range(type_def).expect("field range") {
                assert_eq!(
                    field_owner[field as usize], 0,
                    "{path}: Field {field} is owned by two types"
                );
                field_owner[field as usize] = rid;
            }
            for method in tables.method_range(type_def).expect("method range") {
                assert_eq!(
                    method_owner[method as usize], 0,
                    "{path}: MethodDef {method} is owned by two types"
                );
                method_owner[method as usize] = rid;
            }
        }

        for (field, &owner) in field_owner.iter().enumerate().skip(1) {
            let found = tables
                .type_of_field(Rid::new(field as u32))
                .expect("owner lookup")
                .map(|t| t.get())
                .unwrap_or(0);
            assert_eq!(found, owner, "{path}: Field {field} owner disagrees");
        }
        for (method, &owner) in method_owner.iter().enumerate().skip(1) {
            let found = tables
                .type_of_method(Rid::new(method as u32))
                .expect("owner lookup")
                .map(|t| t.get())
                .unwrap_or(0);
            assert_eq!(found, owner, "{path}: MethodDef {method} owner disagrees");
        }

        // The same for parameters, which hang off methods.
        let param_count = tables.logical_row_count(TableId::Param);
        let mut param_owner = vec![0u32; param_count as usize + 1];
        for rid in 1..=tables.row_count(TableId::MethodDef) {
            for param in tables.param_range(Rid::new(rid)).expect("param range") {
                assert_eq!(
                    param_owner[param as usize], 0,
                    "{path}: Param {param} is owned by two methods"
                );
                param_owner[param as usize] = rid;
            }
        }
        for (param, &owner) in param_owner.iter().enumerate().skip(1) {
            let found = tables
                .method_of_param(Rid::new(param as u32))
                .expect("owner lookup")
                .map(|m| m.get())
                .unwrap_or(0);
            assert_eq!(found, owner, "{path}: Param {param} owner disagrees");
        }
    });
}

/// Every coded index must survive a decode and re-encode unchanged.
///
/// This is a direct test of the tag tables in II.24.2.6: a wrong table in a tag
/// slot, or a wrong tag-bit count, shows up as a value that does not round-trip.
#[test]
fn coded_indices_round_trip_through_every_row() {
    for_each_assembly(|path, _image, metadata| {
        let tables = metadata.tables();
        for &id in TableId::ALL {
            let count = tables.row_count(id);
            if count == 0 {
                continue;
            }
            let columns = cildec::tables::columns_of(id);
            for (index, column) in columns.iter().enumerate() {
                let ColumnKind::Coded(kind) = column else { continue };
                for rid in 1..=count {
                    let raw = tables.raw_column(id, rid, index).expect("column");
                    let Ok(token) = kind.decode(raw, 0) else {
                        // An undefined tag is a legal outcome on hostile input;
                        // shipped assemblies should not have one, but this test
                        // is about the round trip, not about validity.
                        continue;
                    };
                    assert_eq!(
                        kind.encode(token),
                        Some(raw),
                        "{path}: {} row {rid} column {index} ({kind:?}) does not round-trip",
                        id.name()
                    );
                }
            }
        }
    });
}

/// `is_instruction_boundary` must agree with `instruction_offsets`.
#[test]
fn instruction_boundaries_agree_with_the_offset_list() {
    for_each_assembly(|path, image, metadata| {
        let tables = metadata.tables();
        // Bounded: this is quadratic in the method length, so sample.
        for (rid, row) in tables.iter::<MethodDefRow>().take(200) {
            let Ok(row) = row else { continue };
            let Ok(Some(body)) = MethodBody::from_image(image, &row) else { continue };
            if body.code_size() > 512 {
                continue;
            }
            let offsets = body.instruction_offsets();
            for offset in 0..body.code_size() as u32 {
                assert_eq!(
                    body.is_instruction_boundary(offset),
                    offsets.contains(&offset),
                    "{path}: MethodDef {rid} disagrees about offset {offset:#x}"
                );
            }
        }
    });
}

/// Parsing the same bytes twice must give the same answer.
#[test]
fn parsing_is_deterministic() {
    let images = real_assemblies();
    let mut checked = 0usize;
    for path in images.iter().take(60) {
        let Ok(bytes) = std::fs::read(path) else { continue };
        if PeImage::parse(&bytes).and_then(|i| i.metadata()).is_err() {
            continue;
        }
        let first = common::dump::dump(&bytes);
        let second = common::dump::dump(&bytes);
        assert!(first == second, "{}: two dumps of the same bytes differ", path.display());
        checked += 1;
    }
    eprintln!("checked {checked} assemblies for determinism");
    assert!(checked > 5);
}

/// A metadata blob read straight from the image must parse the same as the one
/// reached through the PE container.
#[test]
fn a_bare_metadata_blob_matches_the_one_in_the_image() {
    for_each_assembly(|path, image, metadata| {
        let header = image.cli_header().expect("CLI header");
        let Ok(blob) = image.rva_slice(header.metadata.rva, header.metadata.size as usize) else {
            return;
        };
        let bare = Metadata::parse(blob).expect("parse the bare blob");
        for &id in TableId::ALL {
            assert_eq!(
                bare.tables().row_count(id),
                metadata.tables().row_count(id),
                "{path}: {} row count differs when parsed standalone",
                id.name()
            );
        }
        assert_eq!(bare.version_string(), metadata.version_string(), "{path}");
        assert_eq!(bare.streams().len(), metadata.streams().len(), "{path}");
    });
}

/// Every heap index a row carries must resolve.
#[test]
fn every_heap_index_in_every_row_resolves() {
    for_each_assembly(|path, _image, metadata| {
        let tables = metadata.tables();
        for &id in TableId::ALL {
            let count = tables.row_count(id);
            if count == 0 {
                continue;
            }
            let columns = cildec::tables::columns_of(id);
            for (index, column) in columns.iter().enumerate() {
                for rid in 1..=count {
                    let raw = tables.raw_column(id, rid, index).expect("column");
                    match column {
                        ColumnKind::String => {
                            assert!(
                                metadata.strings().bytes(cildec::StringIndex(raw)).is_ok(),
                                "{path}: {} row {rid} has an unreadable #Strings index",
                                id.name()
                            );
                        }
                        ColumnKind::Blob => {
                            assert!(
                                metadata.blobs().get(cildec::BlobIndex(raw)).is_ok(),
                                "{path}: {} row {rid} has an unreadable #Blob index",
                                id.name()
                            );
                        }
                        ColumnKind::Guid if raw != 0 => {
                            assert!(
                                metadata.guids().get(cildec::GuidIndex(raw)).is_ok(),
                                "{path}: {} row {rid} has an unreadable #GUID index",
                                id.name()
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
    });
}

/// A simple index must never point past the table it indexes.
#[test]
fn simple_indices_stay_inside_their_target_table() {
    for_each_assembly(|path, _image, metadata| {
        let tables = metadata.tables();
        for &id in TableId::ALL {
            let count = tables.row_count(id);
            if count == 0 {
                continue;
            }
            let columns = cildec::tables::columns_of(id);
            for (index, column) in columns.iter().enumerate() {
                let ColumnKind::Rid(target) = column else { continue };
                // A list column may point one past the end, which is how an
                // empty run at the end of a table is spelled.
                let limit = tables.logical_row_count(*target) + 1;
                for rid in 1..=count {
                    let raw = tables.raw_column(id, rid, index).expect("column");
                    assert!(
                        raw <= limit,
                        "{path}: {} row {rid} column {index} points at {} row {raw}, past {limit}",
                        id.name(),
                        target.name()
                    );
                }
            }
        }
    });
}

/// The declared `Sorted` bitvector and the verified ordering must agree on
/// shipped assemblies, which are produced by conforming compilers.
#[test]
fn shipped_assemblies_really_are_sorted_where_they_claim() {
    for_each_assembly(|path, _image, metadata| {
        let tables = metadata.tables();
        for &id in TableId::ALL {
            if sort_key_column(id).is_none() || !tables.is_declared_sorted(id) {
                continue;
            }
            assert!(tables.is_sorted(id), "{path}: {} is declared sorted but is not", id.name());
        }
    });
}

/// `Tables::sort_key_column` must name a real column of the right shape.
#[test]
fn sort_key_columns_are_well_formed() {
    let tables = Tables::empty();
    for &id in TableId::ALL {
        let Some(column) = sort_key_column(id) else { continue };
        let columns = cildec::tables::columns_of(id);
        assert!(column < columns.len(), "{} key column out of range", id.name());
        assert!(
            matches!(columns[column], ColumnKind::Rid(_) | ColumnKind::Coded(_)),
            "{} key column is neither a RID nor a coded index",
            id.name()
        );
        assert_eq!(tables.sort_key_column(id), Some(column));
    }
    // A table with no sort key reports none through both spellings.
    assert_eq!(sort_key_column(TableId::TypeDef), None);
    assert_eq!(Tables::empty().sort_key_column(TableId::TypeDef), None);
    let _ = CodedIndex::ALL;
}

/// A census of what strict mode rejects on shipped assemblies.
///
/// Strict mode is only useful if it accepts conforming images, so this reports
/// the rate and fails if it collapses. It is a census rather than an assertion
/// about any one image: a handful of shipped assemblies really do violate
/// ECMA-335, and rejecting those is the point of the mode.
#[test]
fn strict_mode_accepts_almost_every_shipped_assembly() {
    let images = real_assemblies();
    let mut permissive = 0usize;
    let mut strict = 0usize;
    let mut bodies_permissive = 0usize;
    let mut bodies_strict = 0usize;

    for path in &images {
        let Ok(bytes) = std::fs::read(path) else { continue };
        let Ok(image) = PeImage::parse(&bytes) else { continue };
        let Ok(metadata) = image.metadata() else { continue };
        permissive += 1;

        let strict_ok = PeImage::parse_with(&bytes, cildec::Strictness::Strict)
            .and_then(|i| i.metadata())
            .is_ok();
        if strict_ok {
            strict += 1;
        }

        for (_, row) in metadata.tables().iter::<MethodDefRow>().take(400) {
            let Ok(row) = row else { continue };
            let Ok(Some(_)) = MethodBody::from_image(&image, &row) else { continue };
            bodies_permissive += 1;
            let Ok(rest) = image.rva_rest(row.rva) else { continue };
            if MethodBody::parse_with(rest, row.rva, cildec::Strictness::Strict).is_ok() {
                bodies_strict += 1;
            }
        }
    }

    eprintln!(
        "strict mode: {strict}/{permissive} assemblies, {bodies_strict}/{bodies_permissive} bodies"
    );
    assert!(permissive > 20);
    // Strict mode that rejected most of the world would be useless.
    assert!(
        strict * 100 >= permissive * 90,
        "strict mode rejected {} of {permissive} assemblies",
        permissive - strict
    );
    assert!(
        bodies_strict * 100 >= bodies_permissive * 99,
        "strict mode rejected {} of {bodies_permissive} method bodies",
        bodies_permissive - bodies_strict
    );
}
