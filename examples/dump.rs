//! Dumps an image: header facts, table row counts, and one method disassembly.
//!
//! ```text
//! cargo run --example dump -- <image.dll> [MethodName]
//! ```

use cildec::tables::{MethodDefRow, TypeDefRow};
use cildec::{MethodBody, Names, PeImage, Rid, TableId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("usage: dump <image.dll> [MethodName]")?;
    let wanted = args.next();

    let bytes = std::fs::read(&path)?;
    let image = PeImage::parse(&bytes)?;
    let header = image.cli_header()?;
    println!("{path}");
    println!(
        "  {} machine={:#06x} runtime={}.{} il_only={} 32bit_required={} 32bit_preferred={}",
        if image.is_pe32_plus() { "PE32+" } else { "PE32" },
        image.machine(),
        header.major_runtime_version,
        header.minor_runtime_version,
        header.flags.il_only(),
        header.flags.requires_32bit(),
        header.flags.prefers_32bit(),
    );

    let metadata = image.metadata()?;
    println!("  metadata version {}", metadata.version_string());
    print!("  streams:");
    for stream in metadata.streams() {
        print!(" {}({})", stream.name_lossy(), stream.size);
    }
    println!();

    let tables = metadata.tables();
    let mut populated: Vec<(TableId, u32)> = TableId::ALL
        .iter()
        .map(|&id| (id, tables.row_count(id)))
        .filter(|&(_, count)| count > 0)
        .collect();
    populated.sort_by_key(|&(id, _)| id.to_u8());
    println!("  tables:");
    for (id, count) in &populated {
        println!("    {:<24} {count:>8}", id.name());
    }

    for diagnostic in image.diagnostics().iter().chain(metadata.diagnostics()) {
        println!("  diagnostic: {diagnostic}");
    }

    let names = Names::new(&metadata);
    let Some(wanted) = wanted else { return Ok(()) };
    let wanted_rid: Option<u32> = wanted.strip_prefix('#').and_then(|r| r.parse().ok());
    for (rid, row) in tables.iter::<MethodDefRow>() {
        let row = row?;
        let matched = match wanted_rid {
            Some(target) => rid == target,
            None => metadata.strings().str_opt(row.name) == Some(wanted.as_str()),
        };
        if !matched {
            continue;
        }
        println!("\n{}", names.method_def_full(Rid::new(rid))?);
        let Some(body) = MethodBody::from_image(&image, &row)? else {
            println!("  (no body)");
            continue;
        };
        println!(
            "  .maxstack {}  code {} bytes  handlers {}",
            body.max_stack,
            body.code_size(),
            body.exception_handlers.len()
        );
        if let Some(token) = body.local_var_sig {
            let sig_row = tables.stand_alone_sig(token.rid())?;
            let blob = metadata.blobs().get(sig_row.signature)?;
            let locals = cildec::LocalVarSig::parse(blob)?;
            for (slot, local) in locals.locals.iter().enumerate() {
                println!("  .local [{slot}] {}", names.type_(&local.type_));
            }
        }
        for folded in body.folded_instructions() {
            let folded = folded?;
            let instruction = &folded.instruction;
            let mut line = format!("  IL_{:04x}: ", instruction.offset);
            if folded.prefixes.volatile {
                line.push_str("volatile. ");
            }
            if folded.prefixes.tail {
                line.push_str("tail. ");
            }
            if let Some(token) = folded.prefixes.constrained {
                line.push_str(&format!("constrained. {} ", names.token(token)));
            }
            line.push_str(instruction.opcode.name());
            match &instruction.operand {
                _ if instruction.info().operand == cildec::OperandKind::InlineNone => {}
                cildec::Operand::None => {}
                cildec::Operand::Var(index) => line.push_str(&format!(" {index}")),
                cildec::Operand::I8(value) => line.push_str(&format!(" {value}")),
                cildec::Operand::I32(value) => line.push_str(&format!(" {value}")),
                cildec::Operand::I64(value) => line.push_str(&format!(" {value}")),
                cildec::Operand::R32(value) => line.push_str(&format!(" {value}")),
                cildec::Operand::R64(value) => line.push_str(&format!(" {value}")),
                cildec::Operand::BranchTarget(target) => {
                    line.push_str(&format!(" IL_{target:04x}"));
                }
                cildec::Operand::Switch(targets) => {
                    let list: Vec<String> = targets.iter().map(|t| format!("IL_{t:04x}")).collect();
                    line.push_str(&format!(" ({})", list.join(", ")));
                }
                cildec::Operand::String(token) => {
                    let text = metadata.user_strings().get(*token)?;
                    line.push_str(&format!(" {:?}", text.to_string_lossy()));
                }
                operand => {
                    if let Some(token) = operand.token() {
                        line.push_str(&format!(" {}", names.token(token)));
                    }
                }
            }
            println!("{line}");
        }
        for handler in &body.exception_handlers {
            println!(
                "  .try IL_{:04x}..IL_{:04x} {:?} handler IL_{:04x}..IL_{:04x}",
                handler.try_offset,
                handler.try_end(),
                handler.kind,
                handler.handler_offset,
                handler.handler_end()
            );
        }
        if let Err(e) = body.validate_handlers() {
            println!("  invalid exception table: {e}");
        }
    }

    let type_count = tables.row_count(TableId::TypeDef);
    if type_count > 0 {
        let first: TypeDefRow = tables.type_def(1)?;
        let _ = first;
    }
    Ok(())
}
