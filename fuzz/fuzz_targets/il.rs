#![no_main]
//! Fuzzes the instruction decoder directly on a raw code range.
//!
//! This target skips the method header so that libFuzzer spends every byte on
//! instruction encodings rather than on reaching them.

use libfuzzer_sys::fuzz_target;

use cildec::il::decode_at;
use cildec::{FoldedIter, InstructionIter, OpCode, Operand};

fuzz_target!(|code: &[u8]| {
    let mut total = 0u64;
    let mut previous = None;
    for item in InstructionIter::new(code) {
        match item {
            Ok(instruction) => {
                assert!(instruction.size > 0);
                assert_eq!(instruction.offset as u64, total);
                assert!(instruction.offset as u64 + u64::from(instruction.size) <= code.len() as u64);
                if let Some(previous) = previous {
                    assert!(instruction.offset > previous);
                }
                previous = Some(instruction.offset);
                total += u64::from(instruction.size);

                // Decoding the same offset again must give the same answer.
                // Operands hold IEEE floats, so equality is compared on the
                // bit patterns: a NaN constant is not equal to itself.
                let again = decode_at(code, instruction.offset).expect("already decoded");
                assert_eq!(again.offset, instruction.offset);
                assert_eq!(again.size, instruction.size);
                assert_eq!(again.opcode, instruction.opcode);
                assert!(same_operand(&again.operand, &instruction.operand));

                // The encoded opcode round-trips through its own bytes.
                let info = instruction.opcode.info();
                let bytes = &info.encoding[..usize::from(info.size)];
                assert_eq!(OpCode::from_bytes(bytes).unwrap().0, instruction.opcode);
                let _ = instruction.opcode.canonical();
                let _ = instruction.operand.branch_targets();
                let _ = instruction.operand.token();
            }
            Err(_) => break,
        }
    }
    assert!(total <= code.len() as u64);

    for item in FoldedIter::new(code) {
        match item {
            Ok(folded) => {
                assert!(folded.total_size() > 0);
                assert!(!folded.instruction.opcode.is_prefix());
            }
            Err(_) => break,
        }
    }

    // Decoding from an offset past the end must be an error, never a panic.
    let _ = decode_at(code, code.len() as u32);
    let _ = decode_at(code, u32::MAX);
});

/// Bitwise operand equality, so that NaN constants compare equal to themselves.
fn same_operand(a: &Operand, b: &Operand) -> bool {
    match (a, b) {
        (Operand::R32(a), Operand::R32(b)) => a.to_bits() == b.to_bits(),
        (Operand::R64(a), Operand::R64(b)) => a.to_bits() == b.to_bits(),
        _ => a == b,
    }
}
