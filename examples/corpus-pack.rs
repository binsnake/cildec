//! Packs and unpacks the fuzz corpora.
//!
//! libFuzzer wants a directory of one file per input, which for this project is
//! nearly seven thousand files averaging under 500 bytes. That is fine to fuzz
//! against and wasteful to keep in a repository: on a 4 KB-cluster filesystem it
//! occupies about four times the bytes it contains, and it makes a checkout of
//! the tree mostly corpus.
//!
//! So the committed form is one `<target>.pack` per target and the directories
//! are generated. The format is deliberately trivial — a repeated
//! `[u32 little-endian length][bytes]` — so that reading it needs no
//! dependency, which matters because this crate has none.
//!
//! ```text
//! cargo run --release --example corpus-pack -- unpack fuzz/corpus
//! cargo run --release --example corpus-pack -- pack   fuzz/corpus
//! ```
//!
//! `pack` is idempotent: entries are written in sorted content order, so
//! re-packing an unchanged corpus produces an identical file and no diff.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const TARGETS: &[&str] = &["pe", "metadata", "body", "signature", "il"];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let root = PathBuf::from(args.next().unwrap_or_else(|| "fuzz/corpus".to_owned()));

    match command.as_str() {
        "pack" => {
            for target in TARGETS {
                let dir = root.join(target);
                let Ok(entries) = std::fs::read_dir(&dir) else { continue };
                // A set keyed by content both deduplicates and fixes the order,
                // so the pack file is a function of the corpus, not of the
                // order the filesystem happened to list it in.
                let mut inputs = BTreeSet::new();
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        inputs.insert(std::fs::read(&path)?);
                    }
                }
                let mut out = Vec::new();
                for input in &inputs {
                    out.extend_from_slice(&(input.len() as u32).to_le_bytes());
                    out.extend_from_slice(input);
                }
                let pack = root.join(format!("{target}.pack"));
                std::fs::write(&pack, &out)?;
                println!("{}: {} inputs, {} bytes", pack.display(), inputs.len(), out.len());
            }
        }
        "unpack" => {
            for target in TARGETS {
                let pack = root.join(format!("{target}.pack"));
                let Ok(bytes) = std::fs::read(&pack) else { continue };
                let dir = root.join(target);
                std::fs::create_dir_all(&dir)?;
                let mut count = 0usize;
                for (index, input) in unpack(&bytes).enumerate() {
                    // Named by index rather than by hash so that unpacking is
                    // cheap; libFuzzer renames what it keeps anyway.
                    std::fs::write(dir.join(format!("{index:06}")), input)?;
                    count += 1;
                }
                println!("{}: {count} inputs", dir.display());
            }
        }
        _ => {
            eprintln!("usage: corpus-pack <pack|unpack> [corpus-dir]");
            return Err("unknown command".into());
        }
    }
    Ok(())
}

/// Iterates the inputs in a pack, stopping at the first malformed record.
fn unpack(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let header = bytes.get(pos..pos + 4)?;
        let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let start = pos + 4;
        let input = bytes.get(start..start.checked_add(len)?)?;
        pos = start + len;
        Some(input)
    })
}

/// The pack path for a target, for callers that want to check it exists.
#[allow(dead_code)]
fn pack_path(root: &Path, target: &str) -> PathBuf {
    root.join(format!("{target}.pack"))
}
