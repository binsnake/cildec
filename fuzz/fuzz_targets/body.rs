#![no_main]
//! Fuzzes `MethodBody::parse` and the full instruction walk over its code.
//!
//! The first four bytes of the input choose the code RVA, so that the offset
//! arithmetic in `code_rva` is exercised near the ends of the address space.

use libfuzzer_sys::fuzz_target;

use cildec::{MethodBody, Strictness};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let rva = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let body_bytes = &data[4..];

    for strictness in [Strictness::Permissive, Strictness::Strict] {
        let Ok(body) = MethodBody::parse_with(body_bytes, rva, strictness) else { continue };

        // The header must never claim more code than it was given.
        assert!(body.code.len() <= body_bytes.len());
        assert!(body.total_size <= body_bytes.len());

        let _ = body.validate_handlers();
        let _ = body.diagnostics().len();

        let mut total = 0u64;
        for item in body.instructions() {
            match item {
                Ok(instruction) => {
                    assert!(instruction.size > 0, "an instruction must consume bytes");
                    assert_eq!(instruction.offset as u64, total);
                    total += u64::from(instruction.size);
                }
                Err(_) => break,
            }
        }
        assert!(total <= body.code.len() as u64);

        let mut folded_end = 0u64;
        for item in body.folded_instructions() {
            match item {
                Ok(folded) => {
                    assert!(folded.first_offset >= folded_end as u32);
                    folded_end = u64::from(folded.end_offset());
                }
                Err(_) => break,
            }
        }
        assert!(folded_end <= body.code.len() as u64);

        let offsets = body.instruction_offsets();
        assert!(offsets.windows(2).all(|w| w[0] < w[1]), "offsets must be strictly increasing");
        if let Some(&first) = offsets.first() {
            assert!(body.is_instruction_boundary(first));
        }
    }
});
