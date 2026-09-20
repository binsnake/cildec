//! Deterministic mutation testing that runs on stable Rust everywhere.
//!
//! `cargo fuzz` needs a nightly toolchain and is run on a schedule; this test
//! is the everyday safety net. It mutates the fixtures with a fixed PRNG and
//! drives the whole pipeline over each result, so a panic introduced anywhere
//! in the parser fails `cargo test` on every platform.
//!
//! Set `CILDEC_ROBUSTNESS_ITERS` to raise the iteration count for a longer run.

use cildec::tables::MethodDefRow;
use cildec::{
    FieldSig, FoldedIter, InstructionIter, LocalVarSig, Metadata, MethodBody, MethodSig,
    MethodSpecSig, Names, PeImage, PropertySig, Strictness, TableId, TypeSpecSig,
};

/// xorshift64*, chosen so that a failure reproduces from the seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 { 0 } else { (self.next() % bound as u64) as usize }
    }
}

fn iterations(default: usize) -> usize {
    std::env::var("CILDEC_ROBUSTNESS_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.dll", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Applies one of a few mutation shapes, each of which breaks a different kind
/// of invariant: a flipped byte corrupts one field, a splice corrupts a whole
/// structure, and a truncation cuts a structure in half.
fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut data = base.to_vec();
    if data.is_empty() {
        return data;
    }
    match rng.next() % 5 {
        0 => {
            for _ in 0..1 + rng.below(8) {
                let at = rng.below(data.len());
                data[at] ^= 1u8 << rng.below(8);
            }
        }
        1 => {
            for _ in 0..1 + rng.below(8) {
                let at = rng.below(data.len());
                data[at] = rng.next() as u8;
            }
        }
        2 => {
            // Large values in a length or count field are the interesting case.
            let at = rng.below(data.len().saturating_sub(4).max(1));
            let value = [0xFFu8, 0xFF, 0xFF, 0x7F];
            for (i, byte) in value.iter().enumerate() {
                if at + i < data.len() {
                    data[at + i] = *byte;
                }
            }
        }
        3 => {
            let len = 1 + rng.below(data.len());
            data.truncate(len);
        }
        _ => {
            let from = rng.below(data.len());
            let to = rng.below(data.len());
            let len = rng.below(64).min(data.len() - from.max(to));
            data[to..to + len].copy_from_slice(&base[from..from + len]);
        }
    }
    data
}

/// Everything a consumer would do with an image, so that a panic anywhere in
/// the pipeline is caught.
fn exercise_image(data: &[u8]) {
    for strictness in [Strictness::Permissive, Strictness::Strict] {
        let Ok(image) = PeImage::parse_with(data, strictness) else { continue };
        let _ = image.cli_header_diagnostics();
        for section in image.sections() {
            let _ = section.name();
            let _ = image.rva_rest(section.virtual_address);
        }
        let Ok(metadata) = image.metadata() else { continue };
        exercise_metadata(&metadata);

        let tables = metadata.tables();
        for (_, row) in tables.iter::<MethodDefRow>().take(4096) {
            let Ok(row) = row else { continue };
            let Ok(Some(body)) = MethodBody::from_image(&image, &row) else { continue };
            let _ = body.validate_handlers();
            let mut total = 0u64;
            for item in body.instructions().take(1 << 16) {
                match item {
                    Ok(instruction) => {
                        assert!(instruction.size > 0);
                        total += u64::from(instruction.size);
                    }
                    Err(_) => break,
                }
            }
            assert!(total <= body.code.len() as u64);
            for item in body.folded_instructions().take(1 << 16) {
                if item.is_err() {
                    break;
                }
            }
            if let Some(token) = body.local_var_sig {
                if let Ok(row) = tables.stand_alone_sig(token.rid()) {
                    if let Ok(blob) = metadata.blobs().get(row.signature) {
                        let _ = LocalVarSig::parse(blob);
                    }
                }
            }
        }
    }
}

fn exercise_metadata(metadata: &Metadata<'_>) {
    let names = Names::new(metadata);
    let tables = metadata.tables();
    let _ = metadata.version_string();
    for stream in metadata.streams() {
        let _ = stream.name_lossy();
    }
    for &id in TableId::ALL {
        let count = tables.row_count(id).min(1 << 14);
        for rid in 1..=count {
            let _ = tables.row_bytes(id, rid);
        }
    }
    for rid in 1..=tables.row_count(TableId::TypeDef).min(512) {
        let type_def = cildec::Rid::new(rid);
        let _ = tables.field_range(type_def);
        let _ = tables.method_range(type_def);
        let _ = tables.class_layout_of(type_def);
        let _ = tables.enclosing_type(type_def);
        let _ = names.type_def(type_def);
    }
    for rid in 1..=tables.row_count(TableId::MethodDef).min(512) {
        let method = cildec::Rid::new(rid);
        let _ = tables.type_of_method(method);
        let _ = tables.param_range(method);
        let _ = names.method_def_full(method);
    }
    for (_, entry) in metadata.blobs().iter().take(1 << 13) {
        for limit in [4u32, 64] {
            let options = cildec::SignatureOptions { recursion_limit: limit };
            let _ = MethodSig::parse_with(entry, options);
            let _ = FieldSig::parse_with(entry, options);
            let _ = LocalVarSig::parse_with(entry, options);
            let _ = PropertySig::parse_with(entry, options);
            let _ = MethodSpecSig::parse_with(entry, options);
            let _ = TypeSpecSig::parse_with(entry, options);
        }
    }
    for (_, entry) in metadata.user_strings().iter().take(1 << 13) {
        let _ = entry.to_string_lossy();
    }
}

#[test]
fn mutated_images_never_panic() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    let bases = [fixture("Features"), fixture("IlFeatures")];
    let iterations = iterations(600);
    for i in 0..iterations {
        let base = &bases[i % bases.len()];
        let data = mutate(&mut rng, base);
        exercise_image(&data);
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x0BAD_C0DE_DEAD_BEEF);
    let iterations = iterations(2000);
    for _ in 0..iterations {
        let len = rng.below(512);
        let mut data = vec![0u8; len];
        for byte in data.iter_mut() {
            *byte = rng.next() as u8;
        }
        exercise_image(&data);
        let _ = Metadata::parse(&data);
        let _ = MethodBody::parse(&data, 0x2000);
        let _ = MethodSig::parse(&data);
        for item in InstructionIter::new(&data) {
            if item.is_err() {
                break;
            }
        }
        for item in FoldedIter::new(&data) {
            if item.is_err() {
                break;
            }
        }
    }
}

#[test]
fn every_prefix_of_a_fixture_is_handled() {
    // Truncation at every single byte, which catches off-by-one reads that a
    // random mutation would only find by luck.
    for name in ["Features", "IlFeatures"] {
        let bytes = fixture(name);
        let step = (bytes.len() / 4096).max(1);
        let mut len = 0;
        while len < bytes.len() {
            exercise_image(&bytes[..len]);
            len += step;
        }
        exercise_image(&bytes);
    }
}

#[test]
fn a_declared_count_never_allocates_beyond_the_input() {
    // A blob that claims a huge element count must fail before reserving.
    let huge = [0x07u8, 0xDF, 0xFF, 0xFF, 0xFF];
    assert!(LocalVarSig::parse(&huge).is_err());
    let huge = [0x00u8, 0xDF, 0xFF, 0xFF, 0xFF, 0x01];
    assert!(MethodSig::parse(&huge).is_err());
    let huge = [0x0Au8, 0xDF, 0xFF, 0xFF, 0xFF];
    assert!(MethodSpecSig::parse(&huge).is_err());

    // A switch that claims four billion targets must fail before reserving.
    let mut code = vec![0x45u8];
    code.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(InstructionIter::new(&code).next().unwrap().is_err());

    // A table stream that claims more rows than the stream can hold is clamped
    // in permissive mode and rejected in strict mode, never allocated for.
    let mut stream = Vec::new();
    stream.extend_from_slice(&0u32.to_le_bytes());
    stream.extend_from_slice(&[2, 0, 0, 1]);
    stream.extend_from_slice(&(1u64 << 2).to_le_bytes()); // TypeDef only
    stream.extend_from_slice(&0u64.to_le_bytes());
    stream.extend_from_slice(&u32::MAX.to_le_bytes()); // row count
    let mut diagnostics = Vec::new();
    let tables = cildec::Tables::parse(&stream, 0, false, Strictness::Permissive, &mut diagnostics)
        .expect("permissive parse");
    assert_eq!(tables.row_count(TableId::TypeDef), 0);
    assert!(!diagnostics.is_empty());
    assert!(cildec::Tables::parse(&stream, 0, false, Strictness::Strict, &mut Vec::new()).is_err());
}
