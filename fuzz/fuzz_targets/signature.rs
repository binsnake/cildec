#![no_main]
//! Fuzzes every signature parser against the same blob.
//!
//! Each parser is fed the whole input so that a blob crafted for one grammar is
//! also tried against the others, which is where a missing guard usually shows.

use libfuzzer_sys::fuzz_target;

use cildec::{
    FieldSig, LocalVarSig, MethodSig, MethodSpecSig, PropertySig, SignatureOptions, TypeSpecSig,
};

fuzz_target!(|data: &[u8]| {
    for limit in [1u32, 4, 64, 1024] {
        let options = SignatureOptions { recursion_limit: limit };

        if let Ok(sig) = MethodSig::parse_with(data, options) {
            assert!(sig.raw.len() <= data.len());
            assert_eq!(sig.param_count(), sig.params.len() + sig.vararg_params.len());
            let _ = sig.has_return();
            let _ = sig.arg_count_with_this();
            for param in sig.params.iter().chain(&sig.vararg_params) {
                let _ = param.type_.primitive_width(64);
                let _ = param.type_.unwrap_modifiers();
            }
        }
        if let Ok(sig) = FieldSig::parse_with(data, options) {
            let _ = sig.type_.primitive_width(32);
            let _ = sig.type_.is_primitive();
        }
        if let Ok(sig) = LocalVarSig::parse_with(data, options) {
            // Each local costs at least one byte, so the count is bounded.
            assert!(sig.locals.len() <= data.len());
            for local in &sig.locals {
                let _ = local.type_.primitive_width(64);
            }
        }
        if let Ok(sig) = PropertySig::parse_with(data, options) {
            assert!(sig.params.len() <= data.len());
        }
        if let Ok(sig) = MethodSpecSig::parse_with(data, options) {
            assert!(sig.args.len() <= data.len());
        }
        if let Ok(sig) = TypeSpecSig::parse_with(data, options) {
            let _ = sig.type_.primitive_width(64);
        }
    }

    let _ = cildec::compressed::read_u32(data);
    let _ = cildec::compressed::read_i32(data);
});
