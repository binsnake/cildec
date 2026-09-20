//! Seeds the fuzz corpora from an image.
//!
//! ```text
//! cargo run --example seed-corpus -- <image.dll> fuzz/corpus
//! ```
//!
//! Seeds are named by a hash of their content, so re-running is idempotent and
//! the committed corpus stays stable.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;

use cildec::tables::{
    FieldRow, MemberRefRow, MethodDefRow, MethodSpecRow, PropertyRow, StandAloneSigRow, TypeSpecRow,
};
use cildec::{MethodBody, PeImage};

fn write(dir: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    let name = format!("{:016x}", hasher.finish());
    std::fs::write(dir.join(name), bytes)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let image_path = args.next().ok_or("usage: seed-corpus <image.dll> <corpus-dir>")?;
    let corpus = args.next().unwrap_or_else(|| "fuzz/corpus".to_owned());
    let corpus = Path::new(&corpus);

    let bytes = std::fs::read(&image_path)?;
    write(&corpus.join("pe"), &bytes)?;

    let image = PeImage::parse(&bytes)?;
    let header = image.cli_header()?;
    let metadata_bytes = image.rva_slice(header.metadata.rva, header.metadata.size as usize)?;
    write(&corpus.join("metadata"), metadata_bytes)?;

    let metadata = image.metadata()?;
    let tables = metadata.tables();

    let mut bodies = 0usize;
    for (_, row) in tables.iter::<MethodDefRow>() {
        let row: MethodDefRow = row?;
        if row.has_no_body() {
            continue;
        }
        let Ok(rest) = image.rva_rest(row.rva) else { continue };
        let Ok(body) = MethodBody::parse(rest, row.rva) else { continue };
        // The body target reads a 4-byte RVA prefix before the header.
        let mut seed = row.rva.to_le_bytes().to_vec();
        seed.extend_from_slice(&rest[..body.total_size.min(rest.len())]);
        write(&corpus.join("body"), &seed)?;
        write(&corpus.join("il"), body.code)?;
        bodies += 1;
    }

    let mut signatures = 0usize;
    let seed_blob = |index| -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(blob) = metadata.blobs().get(index) {
            write(&corpus.join("signature"), blob)?;
        }
        Ok(())
    };
    for (_, row) in tables.iter::<MethodDefRow>() {
        seed_blob(row?.signature)?;
        signatures += 1;
    }
    for (_, row) in tables.iter::<FieldRow>() {
        seed_blob(row?.signature)?;
        signatures += 1;
    }
    for (_, row) in tables.iter::<TypeSpecRow>() {
        seed_blob(row?.signature)?;
        signatures += 1;
    }
    for (_, row) in tables.iter::<MethodSpecRow>() {
        seed_blob(row?.instantiation)?;
        signatures += 1;
    }
    for (_, row) in tables.iter::<PropertyRow>() {
        seed_blob(row?.type_signature)?;
        signatures += 1;
    }
    for (_, row) in tables.iter::<MemberRefRow>() {
        seed_blob(row?.signature)?;
        signatures += 1;
    }
    for (_, row) in tables.iter::<StandAloneSigRow>() {
        seed_blob(row?.signature)?;
        signatures += 1;
    }

    println!(
        "{image_path}: {bodies} bodies, {signatures} signatures seeded into {}",
        corpus.display()
    );
    Ok(())
}
