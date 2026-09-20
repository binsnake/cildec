//! Prints the raw bytes of a signature blob, for investigating an encoding.
//!
//! ```text
//! cargo run --example blob -- <image.dll> locals <MethodName>
//! ```

use cildec::tables::MethodDefRow;
use cildec::{MethodBody, PeImage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("usage: blob <image.dll> locals <MethodName>")?;
    let _kind = args.next().unwrap_or_else(|| "locals".to_owned());
    let wanted = args.next().ok_or("give a method name")?;

    let bytes = std::fs::read(&path)?;
    let image = PeImage::parse(&bytes)?;
    let metadata = image.metadata()?;
    let tables = metadata.tables();

    for (rid, row) in tables.iter::<MethodDefRow>() {
        let row: MethodDefRow = row?;
        let by_rid = wanted.strip_prefix('#').and_then(|r| r.parse::<u32>().ok());
        let matched = match by_rid {
            Some(target) => rid == target,
            None => metadata.strings().str_opt(row.name) == Some(wanted.as_str()),
        };
        if !matched {
            continue;
        }
        let sig = metadata.blobs().get(row.signature)?;
        println!("MethodDef {rid}: MethodDefSig blob {} bytes", sig.len());
        for (i, chunk) in sig.chunks(16).enumerate() {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            println!("  {:04x}  {}", i * 16, hex.join(" "));
        }
        let parsed = cildec::MethodSig::parse(sig)?;
        println!("  return mods (blob order): {:?}", parsed.return_type.custom_mods);

        let Some(body) = MethodBody::from_image(&image, &row)? else { continue };
        // The raw body bytes, so the header and any data sections can be read
        // by eye: header, code, 4-byte alignment padding, then sections.
        let raw = image.rva_rest(row.rva)?;
        let shown = (body.total_size + 16).min(raw.len()).min(512);
        println!("  body {} bytes (code {}):", body.total_size, body.code_size());
        let start = body.total_size.saturating_sub(shown);
        let end = (body.total_size + 16).min(raw.len());
        for (i, chunk) in raw[start..end].chunks(16).enumerate() {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            println!("    {:04x}  {}", start + i * 16, hex.join(" "));
        }
        for h in &body.exception_handlers {
            println!(
                "    clause {:?} try {:#x}+{:#x} handler {:#x}+{:#x} flags {:#x}",
                h.kind, h.try_offset, h.try_length, h.handler_offset, h.handler_length, h.raw_flags
            );
        }

        let Some(token) = body.local_var_sig else { continue };
        let sig_row = tables.stand_alone_sig(token.rid())?;
        let blob = metadata.blobs().get(sig_row.signature)?;
        println!("MethodDef {rid} {wanted}: LocalVarSig blob {} bytes", blob.len());
        for (i, chunk) in blob.chunks(16).enumerate() {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            println!("  {:04x}  {}", i * 16, hex.join(" "));
        }
        let parsed = cildec::LocalVarSig::parse(blob)?;
        for (slot, local) in parsed.locals.iter().enumerate() {
            println!(
                "  local {slot}: pinned={} by_ref={} mods={} type={:?}",
                local.pinned,
                local.by_ref,
                local.custom_mods.len(),
                local.type_
            );
        }
        return Ok(());
    }
    Err(format!("no method named {wanted}").into())
}
