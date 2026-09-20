//! Replays the committed fuzz corpus and crash artifacts as ordinary tests.
//!
//! `fuzz/corpus/<target>` holds the inputs libFuzzer keeps, and
//! `fuzz/artifacts/<target>` holds any input that once caused a failure. Both
//! are replayed here on stable Rust so that a regression is caught by
//! `cargo test`, without needing a nightly toolchain or cargo-fuzz.
//!
//! The bodies below mirror the fuzz targets in `fuzz/fuzz_targets`. When a
//! target changes, change its twin here.

use std::path::{Path, PathBuf};

use cildec::il::decode_at;
use cildec::tables::MethodDefRow;
use cildec::{
    FieldSig, FoldedIter, InstructionIter, LocalVarSig, Metadata, MethodBody, MethodSig,
    MethodSpecSig, Names, OpCode, Operand, PeImage, PropertySig, SignatureOptions, Strictness,
    TableId, TypeSpecSig,
};

/// Every committed input for a target: the entries of its pack, plus any loose
/// files under `fuzz/corpus/<target>/` and `fuzz/artifacts/<target>/`.
///
/// The pack format is the one `examples/corpus-pack.rs` writes, a repeated
/// `[u32 little-endian length][bytes]`. It is read here rather than unpacked so
/// that `cargo test` needs no tooling and no dependency.
fn inputs(target: &str) -> Vec<(String, Vec<u8>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz");
    let mut out = Vec::new();

    let pack = root.join("corpus").join(format!("{target}.pack"));
    if let Ok(bytes) = std::fs::read(&pack) {
        let mut pos = 0usize;
        let mut index = 0usize;
        while let Some(header) = bytes.get(pos..pos + 4) {
            let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
            let start = pos + 4;
            let Some(entry) = start.checked_add(len).and_then(|end| bytes.get(start..end)) else {
                panic!("{}: truncated record at byte {pos}", pack.display());
            };
            out.push((format!("{target}.pack#{index}"), entry.to_vec()));
            pos = start + len;
            index += 1;
        }
        assert_eq!(pos, bytes.len(), "{}: trailing bytes after the last record", pack.display());
    }

    // Unpacked working directories and crash artifacts stay as loose files.
    for dir in [root.join("corpus").join(target), root.join("artifacts").join(target)] {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        let mut paths: Vec<PathBuf> =
            entries.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
        // Sorted so that a failure names the same file on every machine.
        paths.sort();
        for path in paths {
            if let Ok(bytes) = std::fs::read(&path) {
                out.push((path.display().to_string(), bytes));
            }
        }
    }
    out
}

#[test]
fn pe_corpus_replays_cleanly() {
    for (path, data) in inputs("pe") {
        let _guard = &path;
        for strictness in [Strictness::Permissive, Strictness::Strict] {
            let Ok(image) = PeImage::parse_with(&data, strictness) else { continue };
            let _ = image.cli_header_diagnostics();
            for section in image.sections() {
                let _ = section.name();
                let _ = image.rva_rest(section.virtual_address);
            }
            let Ok(metadata) = image.metadata() else { continue };
            for (_, row) in metadata.tables().iter::<MethodDefRow>().take(4096) {
                let Ok(row) = row else { continue };
                let Ok(Some(body)) = MethodBody::from_image(&image, &row) else { continue };
                let _ = body.validate_handlers();
                for item in body.instructions().take(1 << 16) {
                    if item.is_err() {
                        break;
                    }
                }
                for item in body.folded_instructions().take(1 << 16) {
                    if item.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

#[test]
fn metadata_corpus_replays_cleanly() {
    for (path, data) in inputs("metadata") {
        let _guard = &path;
        for strictness in [Strictness::Permissive, Strictness::Strict] {
            let Ok(metadata) = Metadata::parse_with(&data, strictness) else { continue };
            let _ = metadata.version_string();
            let names = Names::new(&metadata);
            let tables = metadata.tables();
            for &id in TableId::ALL {
                let count = tables.row_count(id).min(1 << 14);
                for rid in 1..=count {
                    let _ = tables.row_bytes(id, rid);
                }
            }
            for rid in 1..=tables.row_count(TableId::TypeDef).min(1024) {
                let type_def = cildec::Rid::new(rid);
                let _ = tables.field_range(type_def);
                let _ = tables.method_range(type_def);
                let _ = names.type_def(type_def);
            }
            for (_, entry) in metadata.strings().iter().take(1 << 14) {
                let _ = core::str::from_utf8(entry);
            }
            for (_, entry) in metadata.blobs().iter().take(1 << 14) {
                let _ = entry.len();
            }
            for (_, entry) in metadata.user_strings().iter().take(1 << 14) {
                let _ = entry.to_string_lossy();
            }
        }
    }
}

#[test]
fn body_corpus_replays_cleanly() {
    for (path, data) in inputs("body") {
        if data.len() < 4 {
            // The target returns early for these, as the seed format is a
            // 4-byte RVA followed by the method header.
            continue;
        }
        let rva = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let body_bytes = &data[4..];
        for strictness in [Strictness::Permissive, Strictness::Strict] {
            let Ok(body) = MethodBody::parse_with(body_bytes, rva, strictness) else { continue };
            assert!(body.code.len() <= body_bytes.len());
            assert!(body.total_size <= body_bytes.len());
            let _ = body.validate_handlers();
            let mut total = 0u64;
            for item in body.instructions() {
                match item {
                    Ok(instruction) => total += u64::from(instruction.size),
                    Err(_) => break,
                }
            }
            assert!(total <= body.code.len() as u64, "{path}");
            let offsets = body.instruction_offsets();
            assert!(offsets.windows(2).all(|w| w[0] < w[1]), "{path}");
        }
    }
}

#[test]
fn signature_corpus_replays_cleanly() {
    for (path, data) in inputs("signature") {
        let _guard = &path;
        for limit in [1u32, 4, 64, 1024] {
            let options = SignatureOptions { recursion_limit: limit };
            if let Ok(sig) = MethodSig::parse_with(&data, options) {
                assert_eq!(sig.param_count(), sig.params.len() + sig.vararg_params.len());
            }
            let _ = FieldSig::parse_with(&data, options);
            if let Ok(sig) = LocalVarSig::parse_with(&data, options) {
                assert!(sig.locals.len() <= data.len());
            }
            let _ = PropertySig::parse_with(&data, options);
            let _ = MethodSpecSig::parse_with(&data, options);
            let _ = TypeSpecSig::parse_with(&data, options);
        }
        let _ = cildec::compressed::read_u32(&data);
        let _ = cildec::compressed::read_i32(&data);
    }
}

#[test]
fn il_corpus_replays_cleanly() {
    for (path, code) in inputs("il") {
        let mut total = 0u64;
        for item in InstructionIter::new(&code) {
            match item {
                Ok(instruction) => {
                    assert!(instruction.size > 0, "{path}");
                    assert_eq!(instruction.offset as u64, total, "{path}");
                    total += u64::from(instruction.size);
                    let again = decode_at(&code, instruction.offset).expect("already decoded");
                    assert_eq!(again.size, instruction.size);
                    assert_eq!(again.opcode, instruction.opcode);
                    assert!(same_operand(&again.operand, &instruction.operand));
                    let info = instruction.opcode.info();
                    let bytes = &info.encoding[..usize::from(info.size)];
                    assert_eq!(OpCode::from_bytes(bytes).unwrap().0, instruction.opcode);
                }
                Err(_) => break,
            }
        }
        assert!(total <= code.len() as u64, "{path}");
        for item in FoldedIter::new(&code) {
            if item.is_err() {
                break;
            }
        }
        let _ = decode_at(&code, code.len() as u32);
        let _ = decode_at(&code, u32::MAX);
    }
}

fn same_operand(a: &Operand, b: &Operand) -> bool {
    match (a, b) {
        (Operand::R32(a), Operand::R32(b)) => a.to_bits() == b.to_bits(),
        (Operand::R64(a), Operand::R64(b)) => a.to_bits() == b.to_bits(),
        _ => a == b,
    }
}

#[test]
fn the_corpus_is_not_empty() {
    // A corpus that silently disappears would make the tests above vacuous.
    // The published package excludes `fuzz/` entirely, so the guard is "if the
    // fuzzing tree is here at all, every target has a corpus".
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz");
    if !root.is_dir() {
        eprintln!("no fuzz/ directory; skipping (this is the published package layout)");
        return;
    }
    for target in ["pe", "metadata", "body", "signature", "il"] {
        assert!(!inputs(target).is_empty(), "no corpus entries for {target}");
    }
}
