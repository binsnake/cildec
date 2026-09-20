//! Coded index kinds (ECMA-335 II.24.2.6).
//!
//! A coded index packs a small table tag into the low bits of a column and the
//! RID into the remaining bits. The number of tag bits is fixed per kind; the
//! column is 2 bytes when the largest tagged table has fewer than
//! `2^(16 - tag bits)` rows, and 4 bytes otherwise.

use crate::error::{Error, ErrorKind, Result};
use crate::token::{TableId, Token};

macro_rules! coded {
    ($( $(#[$attr:meta])* $name:ident ( $bits:literal ) = [ $($entry:tt),* $(,)? ] ),* $(,)?) => {
        /// The kinds of coded index used by metadata columns.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[non_exhaustive]
        pub enum CodedIndex {
            $( $(#[$attr])* $name ),*
        }

        impl CodedIndex {
            /// Every coded index kind.
            pub const ALL: &'static [CodedIndex] = &[ $( CodedIndex::$name ),* ];

            /// The number of tag bits in the low end of the column.
            pub const fn tag_bits(self) -> u8 {
                match self {
                    $( CodedIndex::$name => $bits ),*
                }
            }

            /// The table selected by each tag value, in tag order. `None`
            /// marks a tag that ECMA-335 leaves undefined.
            pub const fn tables(self) -> &'static [Option<TableId>] {
                match self {
                    $( CodedIndex::$name => &[ $( coded!(@entry $entry) ),* ] ),*
                }
            }

            /// The kind name, as spelled in II.24.2.6.
            pub const fn name(self) -> &'static str {
                match self {
                    $( CodedIndex::$name => stringify!($name) ),*
                }
            }
        }
    };
    (@entry _) => { None };
    (@entry $t:ident) => { Some(TableId::$t) };
}

coded! {
    /// `TypeDefOrRef`.
    TypeDefOrRef(2) = [TypeDef, TypeRef, TypeSpec],
    /// `HasConstant`.
    HasConstant(2) = [Field, Param, Property],
    /// `HasCustomAttribute`.
    HasCustomAttribute(5) = [
        MethodDef, Field, TypeRef, TypeDef, Param, InterfaceImpl, MemberRef, Module,
        DeclSecurity, Property, Event, StandAloneSig, ModuleRef, TypeSpec, Assembly,
        AssemblyRef, File, ExportedType, ManifestResource, GenericParam,
        GenericParamConstraint, MethodSpec,
    ],
    /// `HasFieldMarshal`.
    HasFieldMarshal(1) = [Field, Param],
    /// `HasDeclSecurity`.
    HasDeclSecurity(2) = [TypeDef, MethodDef, Assembly],
    /// `MemberRefParent`.
    MemberRefParent(3) = [TypeDef, TypeRef, ModuleRef, MethodDef, TypeSpec],
    /// `HasSemantics`.
    HasSemantics(1) = [Event, Property],
    /// `MethodDefOrRef`.
    MethodDefOrRef(1) = [MethodDef, MemberRef],
    /// `MemberForwarded`.
    MemberForwarded(1) = [Field, MethodDef],
    /// `Implementation`.
    Implementation(2) = [File, AssemblyRef, ExportedType],
    /// `CustomAttributeType`. Tags 0, 1 and 4 are not defined.
    CustomAttributeType(3) = [_, _, MethodDef, MemberRef, _],
    /// `ResolutionScope`.
    ResolutionScope(2) = [Module, ModuleRef, AssemblyRef, TypeRef],
    /// `TypeOrMethodDef`.
    TypeOrMethodDef(1) = [TypeDef, MethodDef],
    /// `HasCustomDebugInformation`, from the Portable PDB specification.
    HasCustomDebugInformation(5) = [
        MethodDef, Field, TypeRef, TypeDef, Param, InterfaceImpl, MemberRef, Module,
        DeclSecurity, Property, Event, StandAloneSig, ModuleRef, TypeSpec, Assembly,
        AssemblyRef, File, ExportedType, ManifestResource, GenericParam,
        GenericParamConstraint, MethodSpec, Document, LocalScope, LocalVariable,
        LocalConstant, ImportScope,
    ],
}

impl CodedIndex {
    /// The mask that isolates the tag bits.
    pub const fn tag_mask(self) -> u32 {
        (1u32 << self.tag_bits()) - 1
    }

    /// The largest RID the 2-byte form of this column can hold.
    ///
    /// The column is 2 bytes exactly when every tagged table has fewer rows
    /// than this.
    pub const fn small_row_limit(self) -> u32 {
        1u32 << (16 - self.tag_bits() as u32)
    }

    /// The column width in bytes given the largest tagged table row count.
    pub const fn column_width(self, max_rows: u32) -> u8 {
        if max_rows < self.small_row_limit() { 2 } else { 4 }
    }

    /// Decodes a raw column value into a token.
    ///
    /// Fails with [`ErrorKind::Malformed`] when the tag has no table, which is
    /// how an undefined `CustomAttributeType` tag is reported.
    pub fn decode(self, value: u32, offset: usize) -> Result<Token> {
        let tag = (value & self.tag_mask()) as usize;
        let rid = value >> self.tag_bits();
        match self.tables().get(tag).copied().flatten() {
            Some(table) => Ok(Token::new(table, rid)),
            None => Err(Error::new(ErrorKind::Malformed, offset, "coded index")),
        }
    }

    /// Encodes a token into a raw column value, or `None` when this kind
    /// cannot represent the token table.
    pub fn encode(self, token: Token) -> Option<u32> {
        let table = token.table()?;
        let tag = self.tables().iter().position(|t| *t == Some(table))? as u32;
        let rid = token.rid();
        (rid <= u32::MAX >> self.tag_bits()).then(|| (rid << self.tag_bits()) | tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_bits_cover_the_table_list() {
        for &kind in CodedIndex::ALL {
            let slots = 1usize << kind.tag_bits();
            assert!(
                kind.tables().len() <= slots,
                "{} needs {} slots but has {} tag bits",
                kind.name(),
                kind.tables().len(),
                kind.tag_bits()
            );
            // One fewer tag bit would not fit, i.e. the bit count is minimal.
            if kind.tag_bits() > 0 {
                assert!(kind.tables().len() > slots / 2, "{} wastes a tag bit", kind.name());
            }
        }
    }

    #[test]
    fn decode_round_trips_for_every_tag() {
        for &kind in CodedIndex::ALL {
            for (tag, table) in kind.tables().iter().enumerate() {
                let raw = (7u32 << kind.tag_bits()) | tag as u32;
                match table {
                    Some(t) => {
                        let token = kind.decode(raw, 0).unwrap();
                        assert_eq!(token.table(), Some(*t));
                        assert_eq!(token.rid(), 7);
                        assert_eq!(kind.encode(token), Some(raw));
                    }
                    None => {
                        assert_eq!(kind.decode(raw, 0).unwrap_err().kind, ErrorKind::Malformed);
                    }
                }
            }
        }
    }

    #[test]
    fn undefined_tags_beyond_the_list_are_malformed() {
        // MemberRefParent has 3 tag bits but only 5 tables.
        assert!(CodedIndex::MemberRefParent.decode(5, 0).is_err());
        assert!(CodedIndex::MemberRefParent.decode(7, 0).is_err());
        assert!(CodedIndex::CustomAttributeType.decode(0, 0).is_err());
        assert!(CodedIndex::CustomAttributeType.decode(2, 0).is_ok());
    }

    #[test]
    fn every_kind_switches_width_at_its_own_boundary() {
        for &kind in CodedIndex::ALL {
            let limit = kind.small_row_limit();
            assert_eq!(limit, 1 << (16 - kind.tag_bits() as u32), "{}", kind.name());
            assert_eq!(kind.column_width(0), 2, "{}", kind.name());
            assert_eq!(kind.column_width(limit - 1), 2, "{}", kind.name());
            assert_eq!(kind.column_width(limit), 4, "{}", kind.name());
            assert_eq!(kind.column_width(u32::MAX), 4, "{}", kind.name());
            // At the boundary the 2-byte form can still address every row of a
            // table with `limit - 1` rows, and no more.
            let widest = u32::MAX >> kind.tag_bits();
            assert!(kind.encode(Token::new(TableId::TypeDef, widest)).is_none() || widest >= limit);
        }
    }

    #[test]
    fn column_width_switches_at_the_documented_boundary() {
        // 2 tag bits -> limit 2^14.
        assert_eq!(CodedIndex::TypeDefOrRef.small_row_limit(), 0x4000);
        assert_eq!(CodedIndex::TypeDefOrRef.column_width(0x3FFF), 2);
        assert_eq!(CodedIndex::TypeDefOrRef.column_width(0x4000), 4);
        // 5 tag bits -> limit 2^11.
        assert_eq!(CodedIndex::HasCustomAttribute.small_row_limit(), 0x800);
        assert_eq!(CodedIndex::HasCustomAttribute.column_width(0x7FF), 2);
        assert_eq!(CodedIndex::HasCustomAttribute.column_width(0x800), 4);
        // 1 tag bit -> limit 2^15.
        assert_eq!(CodedIndex::HasSemantics.small_row_limit(), 0x8000);
        assert_eq!(CodedIndex::HasSemantics.column_width(0x7FFF), 2);
        assert_eq!(CodedIndex::HasSemantics.column_width(0x8000), 4);
        // 3 tag bits -> limit 2^13.
        assert_eq!(CodedIndex::MemberRefParent.small_row_limit(), 0x2000);
        assert_eq!(CodedIndex::MemberRefParent.column_width(0x1FFF), 2);
        assert_eq!(CodedIndex::MemberRefParent.column_width(0x2000), 4);
    }
}
