//! Metadata tokens, row identifiers, and heap indices (ECMA-335 II.22, II.24.2.6).
//!
//! A [`Token`] is the 4-byte form used in metadata columns and CIL operands:
//! the table id in the high byte and a 1-based row id (RID) in the low three
//! bytes. A [`Rid`] is the same row id without the table byte, carried in the
//! type system by a marker type so that a `Rid<marker::TypeDef>` cannot be
//! passed where a `Rid<marker::Field>` is expected.

use core::cmp::Ordering;
use core::fmt;
use core::marker::PhantomData;

macro_rules! define_tables {
    ($( $(#[$attr:meta])* $name:ident = $value:literal ),* $(,)?) => {
        /// A metadata table identifier (ECMA-335 II.22).
        ///
        /// Ids `0x00..=0x2C` are the ECMA-335 tables. Ids `0x30..=0x37` are the
        /// Portable PDB tables, which this crate decodes structurally but does
        /// not interpret.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[repr(u8)]
        #[non_exhaustive]
        pub enum TableId {
            $( $(#[$attr])* $name = $value ),*
        }

        impl TableId {
            /// Every table id this crate knows, in ascending numeric order.
            pub const ALL: &'static [TableId] = &[ $( TableId::$name ),* ];

            /// Converts a raw table id byte, or `None` if it is reserved.
            pub const fn from_u8(value: u8) -> Option<TableId> {
                match value {
                    $( $value => Some(TableId::$name), )*
                    _ => None,
                }
            }

            /// The canonical name of the table, as spelled in ECMA-335 II.22.
            pub const fn name(self) -> &'static str {
                match self {
                    $( TableId::$name => stringify!($name), )*
                }
            }
        }

        /// Zero-sized marker types naming each metadata table.
        ///
        /// These exist only to parameterise [`Rid`]; they have no values.
        pub mod marker {
            $(
                $(#[$attr])*
                #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
                pub enum $name {}
            )*

            /// Implemented by every marker type in this module.
            pub trait Table: Copy + core::fmt::Debug {
                /// The table id this marker names.
                const ID: super::TableId;
            }

            $(
                impl Table for $name {
                    const ID: super::TableId = super::TableId::$name;
                }
            )*
        }
    };
}

define_tables! {
    /// `Module` (II.22.30).
    Module = 0x00,
    /// `TypeRef` (II.22.38).
    TypeRef = 0x01,
    /// `TypeDef` (II.22.37).
    TypeDef = 0x02,
    /// `FieldPtr`, an indirection table found only in `#-` streams.
    FieldPtr = 0x03,
    /// `Field` (II.22.15).
    Field = 0x04,
    /// `MethodPtr`, an indirection table found only in `#-` streams.
    MethodPtr = 0x05,
    /// `MethodDef` (II.22.26).
    MethodDef = 0x06,
    /// `ParamPtr`, an indirection table found only in `#-` streams.
    ParamPtr = 0x07,
    /// `Param` (II.22.33).
    Param = 0x08,
    /// `InterfaceImpl` (II.22.23).
    InterfaceImpl = 0x09,
    /// `MemberRef` (II.22.25).
    MemberRef = 0x0A,
    /// `Constant` (II.22.9).
    Constant = 0x0B,
    /// `CustomAttribute` (II.22.10).
    CustomAttribute = 0x0C,
    /// `FieldMarshal` (II.22.17).
    FieldMarshal = 0x0D,
    /// `DeclSecurity` (II.22.11).
    DeclSecurity = 0x0E,
    /// `ClassLayout` (II.22.8).
    ClassLayout = 0x0F,
    /// `FieldLayout` (II.22.16).
    FieldLayout = 0x10,
    /// `StandAloneSig` (II.22.36).
    StandAloneSig = 0x11,
    /// `EventMap` (II.22.12).
    EventMap = 0x12,
    /// `EventPtr`, an indirection table found only in `#-` streams.
    EventPtr = 0x13,
    /// `Event` (II.22.13).
    Event = 0x14,
    /// `PropertyMap` (II.22.35).
    PropertyMap = 0x15,
    /// `PropertyPtr`, an indirection table found only in `#-` streams.
    PropertyPtr = 0x16,
    /// `Property` (II.22.34).
    Property = 0x17,
    /// `MethodSemantics` (II.22.28).
    MethodSemantics = 0x18,
    /// `MethodImpl` (II.22.27).
    MethodImpl = 0x19,
    /// `ModuleRef` (II.22.31).
    ModuleRef = 0x1A,
    /// `TypeSpec` (II.22.39).
    TypeSpec = 0x1B,
    /// `ImplMap` (II.22.22).
    ImplMap = 0x1C,
    /// `FieldRva` (II.22.18).
    FieldRva = 0x1D,
    /// `EncLog`, an edit-and-continue table found only in `#-` streams.
    EncLog = 0x1E,
    /// `EncMap`, an edit-and-continue table found only in `#-` streams.
    EncMap = 0x1F,
    /// `Assembly` (II.22.2).
    Assembly = 0x20,
    /// `AssemblyProcessor` (II.22.4), ignored by the runtime.
    AssemblyProcessor = 0x21,
    /// `AssemblyOS` (II.22.3), ignored by the runtime.
    AssemblyOs = 0x22,
    /// `AssemblyRef` (II.22.5).
    AssemblyRef = 0x23,
    /// `AssemblyRefProcessor` (II.22.7), ignored by the runtime.
    AssemblyRefProcessor = 0x24,
    /// `AssemblyRefOS` (II.22.6), ignored by the runtime.
    AssemblyRefOs = 0x25,
    /// `File` (II.22.19).
    File = 0x26,
    /// `ExportedType` (II.22.14).
    ExportedType = 0x27,
    /// `ManifestResource` (II.22.24).
    ManifestResource = 0x28,
    /// `NestedClass` (II.22.32).
    NestedClass = 0x29,
    /// `GenericParam` (II.22.20).
    GenericParam = 0x2A,
    /// `MethodSpec` (II.22.29).
    MethodSpec = 0x2B,
    /// `GenericParamConstraint` (II.22.21).
    GenericParamConstraint = 0x2C,
    /// Portable PDB `Document`.
    Document = 0x30,
    /// Portable PDB `MethodDebugInformation`.
    MethodDebugInformation = 0x31,
    /// Portable PDB `LocalScope`.
    LocalScope = 0x32,
    /// Portable PDB `LocalVariable`.
    LocalVariable = 0x33,
    /// Portable PDB `LocalConstant`.
    LocalConstant = 0x34,
    /// Portable PDB `ImportScope`.
    ImportScope = 0x35,
    /// Portable PDB `StateMachineMethod`.
    StateMachineMethod = 0x36,
    /// Portable PDB `CustomDebugInformation`.
    CustomDebugInformation = 0x37,
}

impl TableId {
    /// The raw table id byte.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// True for the Portable PDB tables `0x30..=0x37`.
    pub const fn is_pdb(self) -> bool {
        (self as u8) >= 0x30
    }

    /// True for the `*Ptr` indirection tables that only appear in `#-` streams.
    pub const fn is_ptr_table(self) -> bool {
        matches!(
            self,
            TableId::FieldPtr
                | TableId::MethodPtr
                | TableId::ParamPtr
                | TableId::EventPtr
                | TableId::PropertyPtr
        )
    }

    /// For a `*Ptr` table, the table it redirects into.
    pub const fn ptr_target(self) -> Option<TableId> {
        match self {
            TableId::FieldPtr => Some(TableId::Field),
            TableId::MethodPtr => Some(TableId::MethodDef),
            TableId::ParamPtr => Some(TableId::Param),
            TableId::EventPtr => Some(TableId::Event),
            TableId::PropertyPtr => Some(TableId::Property),
            _ => None,
        }
    }

    /// The `*Ptr` table that can redirect into this one, if any.
    pub const fn ptr_source(self) -> Option<TableId> {
        match self {
            TableId::Field => Some(TableId::FieldPtr),
            TableId::MethodDef => Some(TableId::MethodPtr),
            TableId::Param => Some(TableId::ParamPtr),
            TableId::Event => Some(TableId::EventPtr),
            TableId::Property => Some(TableId::PropertyPtr),
            _ => None,
        }
    }
}

impl fmt::Display for TableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A metadata token: a table id in the high byte and a RID in the low 24 bits.
///
/// The all-zero token and any token whose RID is zero are "null"; a null token
/// is a legal encoding meaning "no row".
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Token(pub u32);

impl Token {
    /// The RID mask, `0x00FF_FFFF`.
    pub const RID_MASK: u32 = 0x00FF_FFFF;

    /// Builds a token from a table id and a 1-based RID.
    ///
    /// RIDs wider than 24 bits are truncated; callers that decode untrusted
    /// input should validate the RID against the table row count first.
    pub const fn new(table: TableId, rid: u32) -> Token {
        Token(((table.to_u8() as u32) << 24) | (rid & Token::RID_MASK))
    }

    /// The table this token refers to, or `None` for a reserved table id.
    pub const fn table(self) -> Option<TableId> {
        TableId::from_u8((self.0 >> 24) as u8)
    }

    /// The raw table id byte, even when it is reserved.
    pub const fn table_byte(self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// The 1-based row id.
    pub const fn rid(self) -> u32 {
        self.0 & Token::RID_MASK
    }

    /// True when the RID is zero, meaning "no row".
    pub const fn is_null(self) -> bool {
        self.rid() == 0
    }

    /// The raw 4-byte value.
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Reinterprets this token as a typed [`Rid`], checking the table id.
    pub fn as_rid<T: marker::Table>(self) -> Option<Rid<T>> {
        if self.table() == Some(T::ID) && !self.is_null() {
            Some(Rid::new(self.rid()))
        } else {
            None
        }
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.table() {
            Some(t) => write!(f, "Token({}[{}])", t.name(), self.rid()),
            None => write!(f, "Token({:#010x})", self.0),
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

impl<T: marker::Table> From<Rid<T>> for Token {
    fn from(rid: Rid<T>) -> Token {
        Token::new(T::ID, rid.get())
    }
}

/// A 1-based row identifier within a statically known table.
///
/// Zero means "no row", matching the metadata encoding.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Rid<T> {
    value: u32,
    #[cfg_attr(feature = "serde", serde(skip))]
    _table: PhantomData<fn() -> T>,
}

impl<T> Rid<T> {
    /// Wraps a raw 1-based row id.
    pub const fn new(value: u32) -> Self {
        Rid { value, _table: PhantomData }
    }

    /// The raw 1-based row id.
    pub const fn get(self) -> u32 {
        self.value
    }

    /// True when this refers to no row.
    pub const fn is_null(self) -> bool {
        self.value == 0
    }

    /// The zero-based index into the table, or `None` for a null RID.
    pub const fn index(self) -> Option<usize> {
        if self.value == 0 { None } else { Some(self.value as usize - 1) }
    }
}

impl<T: marker::Table> Rid<T> {
    /// The table id this RID belongs to.
    pub const fn table(self) -> TableId {
        T::ID
    }

    /// The equivalent [`Token`].
    pub const fn token(self) -> Token {
        Token::new(T::ID, self.value)
    }
}

impl<T> Clone for Rid<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Rid<T> {}
impl<T> PartialEq for Rid<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl<T> Eq for Rid<T> {}
impl<T> PartialOrd for Rid<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for Rid<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}
impl<T> core::hash::Hash for Rid<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}
impl<T> Default for Rid<T> {
    fn default() -> Self {
        Rid::new(0)
    }
}
impl<T: marker::Table> fmt::Debug for Rid<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]", T::ID.name(), self.value)
    }
}

macro_rules! heap_index {
    ($(#[$attr:meta])* $name:ident, $heap:literal) => {
        $(#[$attr])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        pub struct $name(pub u32);

        impl $name {
            /// The raw index value.
            pub const fn get(self) -> u32 {
                self.0
            }

            /// True for index 0, which always denotes the empty value.
            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($heap, "[{:#x}]"), self.0)
            }
        }
    };
}

heap_index!(
    /// A byte offset into the `#Strings` heap.
    StringIndex,
    "#Strings"
);
heap_index!(
    /// A byte offset into the `#Blob` heap.
    BlobIndex,
    "#Blob"
);
heap_index!(
    /// A 1-based index into the `#GUID` heap.
    GuidIndex,
    "#GUID"
);

/// A `ldstr` operand: a `0x70` token whose low 24 bits are a `#US` heap offset.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct UserStringToken(pub u32);

impl UserStringToken {
    /// The `#US` heap byte offset carried by this token.
    pub const fn offset(self) -> u32 {
        self.0 & Token::RID_MASK
    }

    /// The raw token value, including the `0x70` table byte.
    pub const fn value(self) -> u32 {
        self.0
    }

    /// True when the high byte is the expected `0x70`.
    pub const fn has_us_table_byte(self) -> bool {
        (self.0 >> 24) == 0x70
    }
}

impl fmt::Debug for UserStringToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#US[{:#x}]", self.offset())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip() {
        let t = Token::new(TableId::MethodDef, 42);
        assert_eq!(t.0, 0x0600_002A);
        assert_eq!(t.table(), Some(TableId::MethodDef));
        assert_eq!(t.rid(), 42);
        assert!(!t.is_null());
        assert!(Token::new(TableId::MethodDef, 0).is_null());
    }

    #[test]
    fn reserved_table_byte_has_no_table() {
        assert_eq!(Token(0x2D00_0001).table(), None);
        assert_eq!(Token(0x2D00_0001).table_byte(), 0x2D);
        assert_eq!(Token(0x7000_0010).table(), None);
    }

    #[test]
    fn all_ids_round_trip() {
        for &id in TableId::ALL {
            assert_eq!(TableId::from_u8(id.to_u8()), Some(id));
        }
        assert_eq!(TableId::ALL.len(), 45 + 8);
        assert_eq!(TableId::from_u8(0x2D), None);
        assert_eq!(TableId::from_u8(0x38), None);
    }

    #[test]
    fn rid_is_typed_and_ordered() {
        let a: Rid<marker::TypeDef> = Rid::new(1);
        let b: Rid<marker::TypeDef> = Rid::new(2);
        assert!(a < b);
        assert_eq!(a.index(), Some(0));
        assert_eq!(Rid::<marker::TypeDef>::new(0).index(), None);
        assert_eq!(a.token(), Token::new(TableId::TypeDef, 1));
        assert_eq!(a.token().as_rid::<marker::TypeDef>(), Some(a));
        assert_eq!(a.token().as_rid::<marker::Field>(), None);
    }

    #[test]
    fn ptr_tables_map_both_ways() {
        for &id in TableId::ALL {
            if let Some(target) = id.ptr_target() {
                assert!(id.is_ptr_table());
                assert_eq!(target.ptr_source(), Some(id));
            }
        }
    }
}
