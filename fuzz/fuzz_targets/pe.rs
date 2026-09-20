#![no_main]
//! Fuzzes `PeImage::parse` and everything reachable from a parsed image.

use libfuzzer_sys::fuzz_target;

use cildec::tables::MethodDefRow;
use cildec::{MethodBody, PeImage, Strictness};

fuzz_target!(|data: &[u8]| {
    for strictness in [Strictness::Permissive, Strictness::Strict] {
        let Ok(image) = PeImage::parse_with(data, strictness) else { continue };
        let _ = image.diagnostics().len();
        let _ = image.cli_header_diagnostics();
        for section in image.sections() {
            let _ = section.name();
            let _ = image.rva_to_offset(section.virtual_address);
            let _ = image.rva_rest(section.virtual_address);
        }
        let _ = image.entry_point_token();
        let Ok(metadata) = image.metadata() else { continue };

        // Walking every method body is the expensive path a consumer takes, and
        // the one with the most arithmetic on attacker-controlled values.
        let tables = metadata.tables();
        for (_, row) in tables.iter::<MethodDefRow>().take(4096) {
            let Ok(row) = row else { continue };
            let Ok(Some(body)) = MethodBody::from_image(&image, &row) else { continue };
            let _ = body.validate_handlers();
            for instruction in body.instructions().take(1 << 16) {
                if instruction.is_err() {
                    break;
                }
            }
            for folded in body.folded_instructions().take(1 << 16) {
                if folded.is_err() {
                    break;
                }
            }
        }
    }
});
