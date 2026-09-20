//! Readable names for tokens and signatures.
//!
//! This module exists so that errors, test assertions and dumps are legible.
//! It is deliberately small and is not a disassembler: names are spelled as the
//! metadata encodes them, including the generic arity suffix on a type name
//! (`` List`1 ``), and types are printed in ILAsm style.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::error::Result;
use crate::metadata::Metadata;
use crate::signature::{
    ArrayShape, CallConv, CustomMod, FieldSig, LocalVar, MethodSig, Param, Type,
};
use crate::tables::{
    MemberRefRow, MethodDefRow, MethodSpecRow, ModuleRefRow, TypeDefRow, TypeRefRow,
};
use crate::token::{Rid, StringIndex, TableId, Token, marker};

/// A naming helper bound to one metadata region.
///
/// Token resolution is recursive: a `TypeSpec` names types that may be other
/// `TypeSpec`s, and a `TypeRef` may be scoped to another `TypeRef`. Hostile
/// metadata can make those references cyclic, so every step carries a depth
/// that is capped at [`Names::MAX_DEPTH`]; beyond it a name renders as
/// `Table[rid]` rather than recursing again.
#[derive(Clone, Copy, Debug)]
pub struct Names<'m, 'a> {
    metadata: &'m Metadata<'a>,
    depth: u32,
}

impl<'m, 'a> Names<'m, 'a> {
    /// The maximum number of token hops a single name may follow.
    pub const MAX_DEPTH: u32 = 32;

    /// Binds the helper to a metadata region.
    pub const fn new(metadata: &'m Metadata<'a>) -> Self {
        Names { metadata, depth: 0 }
    }

    /// The same helper, one hop deeper.
    const fn deeper(&self) -> Self {
        Names { metadata: self.metadata, depth: self.depth + 1 }
    }

    fn string(&self, index: StringIndex) -> String {
        self.metadata.strings().lossy(index).map(|s| s.into_owned()).unwrap_or_default()
    }

    /// The qualified name of a `TypeDef`, with `/` separating nested types.
    pub fn type_def(&self, rid: Rid<marker::TypeDef>) -> Result<String> {
        let tables = self.metadata.tables();
        let row: TypeDefRow = tables.type_def(rid.get())?;
        let mut name = qualify(&self.string(row.type_namespace), &self.string(row.type_name));
        // Walk outwards through `NestedClass`, bounded by the table row count
        // so that a cycle cannot loop forever.
        let mut current = rid;
        for _ in 0..tables.row_count(TableId::NestedClass) {
            let Some(outer) = tables.enclosing_type(current)? else { break };
            if outer.is_null() || outer == current {
                break;
            }
            let outer_row: TypeDefRow = tables.type_def(outer.get())?;
            let outer_name =
                qualify(&self.string(outer_row.type_namespace), &self.string(outer_row.type_name));
            name = format!("{outer_name}/{name}");
            current = outer;
        }
        Ok(name)
    }

    /// The qualified name of a `TypeRef`, prefixed with its scope.
    pub fn type_ref(&self, rid: Rid<marker::TypeRef>) -> Result<String> {
        if self.depth >= Self::MAX_DEPTH {
            return Err(crate::error::Error::detached(
                crate::error::ErrorKind::RecursionLimit,
                "TypeRef",
            ));
        }
        let tables = self.metadata.tables();
        let row: TypeRefRow = tables.type_ref(rid.get())?;
        let name = qualify(&self.string(row.type_namespace), &self.string(row.type_name));
        let scope = row.resolution_scope;
        Ok(match scope.table() {
            Some(TableId::AssemblyRef) if !scope.is_null() => {
                let assembly = tables.assembly_ref(scope.rid())?;
                format!("[{}]{name}", self.string(assembly.name))
            }
            Some(TableId::ModuleRef) if !scope.is_null() => {
                let module: ModuleRefRow = tables.module_ref(scope.rid())?;
                format!("[.module {}]{name}", self.string(module.name))
            }
            Some(TableId::TypeRef) if !scope.is_null() => {
                let outer = self.deeper().type_ref(Rid::new(scope.rid()))?;
                format!("{outer}/{name}")
            }
            _ => name,
        })
    }

    /// The name of any token this crate can resolve.
    ///
    /// Unresolvable tokens render as `Table[rid]` rather than failing, so this
    /// is safe to call from an error path.
    pub fn token(&self, token: Token) -> String {
        self.try_token(token).unwrap_or_else(|_| match token.table() {
            Some(table) => format!("{}[{}]", table.name(), token.rid()),
            None => format!("{token}"),
        })
    }

    /// The name of a token, failing when a row or heap entry cannot be read.
    pub fn try_token(&self, token: Token) -> Result<String> {
        if self.depth >= Self::MAX_DEPTH {
            return Err(crate::error::Error::detached(
                crate::error::ErrorKind::RecursionLimit,
                "token",
            ));
        }
        let deeper = self.deeper();
        let tables = self.metadata.tables();
        Ok(match token.table() {
            Some(TableId::TypeDef) => deeper.type_def(Rid::new(token.rid()))?,
            Some(TableId::TypeRef) => deeper.type_ref(Rid::new(token.rid()))?,
            Some(TableId::TypeSpec) => {
                let row = tables.type_spec(token.rid())?;
                let blob = self.metadata.blobs().get(row.signature)?;
                match crate::signature::TypeSpecSig::parse(blob) {
                    Ok(sig) => deeper.type_(&sig.type_),
                    Err(_) => format!("TypeSpec[{}]", token.rid()),
                }
            }
            Some(TableId::MethodDef) => {
                let row: MethodDefRow = tables.method_def(token.rid())?;
                let owner = match tables.type_of_method(Rid::new(token.rid()))? {
                    Some(type_def) => deeper.type_def(type_def)?,
                    None => "?".to_owned(),
                };
                format!("{owner}::{}", self.string(row.name))
            }
            Some(TableId::Field) => {
                let row = tables.field(token.rid())?;
                let owner = match tables.type_of_field(Rid::new(token.rid()))? {
                    Some(type_def) => deeper.type_def(type_def)?,
                    None => "?".to_owned(),
                };
                format!("{owner}::{}", self.string(row.name))
            }
            Some(TableId::MemberRef) => {
                let row: MemberRefRow = tables.member_ref(token.rid())?;
                let parent = deeper.token(row.class);
                format!("{parent}::{}", self.string(row.name))
            }
            Some(TableId::MethodSpec) => {
                let row: MethodSpecRow = tables.method_spec(token.rid())?;
                let base = deeper.token(row.method);
                let blob = self.metadata.blobs().get(row.instantiation)?;
                match crate::signature::MethodSpecSig::parse(blob) {
                    Ok(sig) => {
                        let args: Vec<String> = sig.args.iter().map(|t| deeper.type_(t)).collect();
                        format!("{base}<{}>", args.join(", "))
                    }
                    Err(_) => base,
                }
            }
            Some(TableId::ModuleRef) => {
                let row: ModuleRefRow = tables.module_ref(token.rid())?;
                format!("[.module {}]", self.string(row.name))
            }
            Some(TableId::AssemblyRef) => {
                let row = tables.assembly_ref(token.rid())?;
                format!("[{}]", self.string(row.name))
            }
            Some(TableId::StandAloneSig) => format!("StandAloneSig[{}]", token.rid()),
            Some(table) => format!("{}[{}]", table.name(), token.rid()),
            None => format!("{token}"),
        })
    }

    /// An ILAsm-style rendering of a type.
    pub fn type_(&self, type_: &Type<'_>) -> String {
        match type_ {
            Type::Void => "void".to_owned(),
            Type::Boolean => "bool".to_owned(),
            Type::Char => "char".to_owned(),
            Type::I1 => "int8".to_owned(),
            Type::U1 => "uint8".to_owned(),
            Type::I2 => "int16".to_owned(),
            Type::U2 => "uint16".to_owned(),
            Type::I4 => "int32".to_owned(),
            Type::U4 => "uint32".to_owned(),
            Type::I8 => "int64".to_owned(),
            Type::U8 => "uint64".to_owned(),
            Type::R4 => "float32".to_owned(),
            Type::R8 => "float64".to_owned(),
            Type::String => "string".to_owned(),
            Type::Object => "object".to_owned(),
            Type::TypedByRef => "typedref".to_owned(),
            Type::IntPtr => "native int".to_owned(),
            Type::UIntPtr => "native uint".to_owned(),
            Type::Ptr(mods, inner) => format!("{}{}*", self.type_(inner), self.mods(mods)),
            Type::ByRef(inner) => format!("{}&", self.type_(inner)),
            Type::ValueType(token) => format!("valuetype {}", self.token(*token)),
            Type::Class(token) => format!("class {}", self.token(*token)),
            Type::Var(index) => format!("!{index}"),
            Type::MVar(index) => format!("!!{index}"),
            Type::SzArray(mods, inner) => format!("{}{}[]", self.type_(inner), self.mods(mods)),
            Type::Array(inner, shape) => format!("{}{}", self.type_(inner), shape_string(shape)),
            Type::GenericInst { is_value_type, def, args } => {
                let keyword = if *is_value_type { "valuetype" } else { "class" };
                let args: Vec<String> = args.iter().map(|t| self.type_(t)).collect();
                format!("{keyword} {}<{}>", self.token(*def), args.join(", "))
            }
            // A function-pointer type has no name of its own, so the
            // signature is rendered with an empty one.
            Type::FnPtr(sig) => format!("method {}", self.method_sig(sig, "")),
            Type::Modified(mods, inner) => format!("{}{}", self.type_(inner), self.mods(mods)),
            Type::Pinned(inner) => format!("{} pinned", self.type_(inner)),
            Type::Sentinel => "...".to_owned(),
            Type::Internal(value) => format!("internal({value:#x})"),
        }
    }

    /// Renders a modifier list in suffix position.
    ///
    /// `CustomMod* Type` nests: the first modifier in the blob wraps everything
    /// after it, so it is the outermost and is spelled *last* in the ILAsm
    /// suffix form. `20 47 20 32 12 17` therefore prints as
    /// `class T modopt(32) modopt(47)`, which is the order ILDASM and
    /// System.Reflection.Metadata both use.
    ///
    /// [`CustomMod`] lists stay in blob order, so a caller that needs the
    /// encoded order still has it.
    fn mods(&self, mods: &[CustomMod]) -> String {
        let mut out = String::new();
        for m in mods.iter().rev() {
            let keyword = if m.required { "modreq" } else { "modopt" };
            let _ = write!(out, " {keyword}({})", self.token(m.type_token));
        }
        out
    }

    /// An ILAsm-style rendering of a field type, modifiers included.
    pub fn field_sig(&self, sig: &FieldSig<'_>) -> String {
        let mut out = self.type_(&sig.type_);
        out.push_str(&self.mods(&sig.custom_mods));
        out
    }

    /// An ILAsm-style rendering of a local variable slot.
    ///
    /// `LocalVar ::= CustomMod* Constraint* [BYREF] Type` (II.23.2.6), so the
    /// pieces nest outward from the type: any modifiers that follow the `BYREF`
    /// belong to the type itself and [`Names::type_`] prints them, then the
    /// `&`, then `pinned`, and outermost the modifiers that preceded it.
    ///
    /// A C++/CLI pinned local reads `char modopt(IsConst)& pinned
    /// modopt(IsExplicitlyDereferenced)`: two modifier groups on opposite sides
    /// of the `&`. Getting that order wrong is easy and silent, which is why it
    /// lives here rather than in each caller.
    pub fn local(&self, local: &LocalVar<'_>) -> String {
        let mut out = self.type_(&local.type_);
        if local.by_ref {
            out.push('&');
        }
        if local.pinned {
            out.push_str(" pinned");
        }
        out.push_str(&self.mods(&local.custom_mods));
        out
    }

    /// An ILAsm-style rendering of one parameter or return type.
    pub fn param(&self, param: &Param<'_>) -> String {
        // `Param ::= CustomMod* [BYREF] Type` (II.23.2.10): the modifiers
        // precede the `BYREF`, so they modify the managed reference rather than
        // the type it points at, and ILAsm spells them after the `&`.
        let mut out = self.type_(&param.type_);
        if param.by_ref {
            out.push('&');
        }
        out.push_str(&self.mods(&param.custom_mods));
        out
    }

    /// An ILAsm-style rendering of a method signature with the given name.
    pub fn method_sig(&self, sig: &MethodSig<'_>, name: &str) -> String {
        let mut out = String::new();
        if sig.has_this {
            out.push_str("instance ");
        }
        if sig.explicit_this {
            out.push_str("explicit ");
        }
        match sig.calling_convention {
            CallConv::Default | CallConv::Generic(_) => {}
            CallConv::VarArg => out.push_str("vararg "),
            CallConv::C => out.push_str("unmanaged cdecl "),
            CallConv::StdCall => out.push_str("unmanaged stdcall "),
            CallConv::ThisCall => out.push_str("unmanaged thiscall "),
            CallConv::FastCall => out.push_str("unmanaged fastcall "),
            CallConv::Unmanaged => out.push_str("unmanaged "),
            CallConv::NativeVarArg => out.push_str("unmanaged vararg "),
            CallConv::Field => out.push_str("field "),
            CallConv::LocalSig => out.push_str("locals "),
            CallConv::Property => out.push_str("property "),
            CallConv::GenericInst => out.push_str("generic "),
        }
        let _ = write!(out, "{} {name}", self.param(&sig.return_type));
        if let CallConv::Generic(count) = sig.calling_convention {
            let _ = write!(out, "<{count}>");
        }
        let mut parts: Vec<String> = sig.params.iter().map(|p| self.param(p)).collect();
        if !sig.vararg_params.is_empty() {
            parts.push("...".to_owned());
            parts.extend(sig.vararg_params.iter().map(|p| self.param(p)));
        }
        let _ = write!(out, "({})", parts.join(", "));
        out
    }

    /// The full ILAsm-style name of a `MethodDef`, signature included.
    pub fn method_def_full(&self, rid: Rid<marker::MethodDef>) -> Result<String> {
        let tables = self.metadata.tables();
        let row: MethodDefRow = tables.method_def(rid.get())?;
        let blob = self.metadata.blobs().get(row.signature)?;
        let name = self.token(rid.token());
        Ok(match MethodSig::parse(blob) {
            Ok(sig) => self.method_sig(&sig, &name),
            Err(_) => name,
        })
    }
}

fn qualify(namespace: &str, name: &str) -> String {
    if namespace.is_empty() { name.to_owned() } else { format!("{namespace}.{name}") }
}

fn shape_string(shape: &ArrayShape) -> String {
    let mut parts = Vec::with_capacity(shape.rank as usize);
    for dimension in 0..shape.rank as usize {
        let lo = shape.lo_bounds.get(dimension).copied();
        let size = shape.sizes.get(dimension).copied();
        parts.push(match (lo, size) {
            (Some(lo), Some(size)) => format!("{}...{}", lo, i64::from(lo) + i64::from(size) - 1),
            (Some(lo), None) => format!("{lo}..."),
            (None, Some(size)) => format!("{size}"),
            (None, None) => String::new(),
        });
    }
    format!("[{}]", parts.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::TypeSpecSig;
    use alloc::vec;

    #[test]
    fn qualify_omits_an_empty_namespace() {
        assert_eq!(qualify("System", "String"), "System.String");
        assert_eq!(qualify("", "Program"), "Program");
    }

    #[test]
    fn array_shapes_render_like_ilasm() {
        assert_eq!(shape_string(&ArrayShape { rank: 2, sizes: vec![], lo_bounds: vec![] }), "[,]");
        assert_eq!(
            shape_string(&ArrayShape { rank: 1, sizes: vec![5], lo_bounds: vec![1] }),
            "[1...5]"
        );
        assert_eq!(
            shape_string(&ArrayShape { rank: 1, sizes: vec![], lo_bounds: vec![2] }),
            "[2...]"
        );
    }

    #[test]
    fn primitive_types_render_without_metadata() {
        // `Names` only needs metadata for tokens, so an empty region suffices
        // for the primitive cases.
        let bytes = crate::test_support::minimal_metadata();
        let md = Metadata::parse(&bytes).unwrap();
        let names = Names::new(&md);
        assert_eq!(names.type_(&Type::I4), "int32");
        assert_eq!(names.type_(&Type::String), "string");
        assert_eq!(names.type_(&Type::IntPtr), "native int");
        let sig = TypeSpecSig::parse(&[0x1D, 0x08]).unwrap();
        assert_eq!(names.type_(&sig.type_), "int32[]");
        let sig = TypeSpecSig::parse(&[0x0F, 0x1D, 0x05]).unwrap();
        assert_eq!(names.type_(&sig.type_), "uint8[]*");
        assert_eq!(names.type_(&Type::Var(0)), "!0");
        assert_eq!(names.type_(&Type::MVar(2)), "!!2");
    }

    #[test]
    fn method_signatures_render_like_ilasm() {
        let bytes = crate::test_support::minimal_metadata();
        let md = Metadata::parse(&bytes).unwrap();
        let names = Names::new(&md);
        let sig = MethodSig::parse(&[0x20, 0x02, 0x01, 0x08, 0x0E]).unwrap();
        assert_eq!(names.method_sig(&sig, "Foo"), "instance void Foo(int32, string)");
        let sig = MethodSig::parse(&[0x05, 0x02, 0x08, 0x08, 0x41, 0x0E]).unwrap();
        assert_eq!(names.method_sig(&sig, "Bar"), "vararg int32 Bar(int32, ..., string)");
    }

    #[test]
    fn an_unresolvable_token_still_renders() {
        let bytes = crate::test_support::minimal_metadata();
        let md = Metadata::parse(&bytes).unwrap();
        let names = Names::new(&md);
        assert_eq!(names.token(Token::new(TableId::TypeDef, 7)), "TypeDef[7]");
        assert_eq!(names.token(Token(0x2D00_0001)), "0x2d000001");
    }
}
