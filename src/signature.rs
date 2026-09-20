//! Blob signatures (ECMA-335 II.23.1.16, II.23.2).
//!
//! Every parser in this module takes the *body* of a `#Blob` entry, without its
//! length prefix, and reports failures at a byte offset inside that body.
//!
//! Parsing is strict about structure and permissive about semantic legality: an
//! undefined element type byte, a missing sentinel or a nested `PINNED` is an
//! error, while a `VAR` in a non-generic context or a `MVAR` index past the
//! method arity is the caller problem to detect.
//!
//! Recursion is bounded by [`SignatureOptions::recursion_limit`], so a blob of
//! nothing but `PTR` bytes produces [`ErrorKind::RecursionLimit`] rather than a
//! stack overflow.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::compressed;
use crate::error::{Error, ErrorKind, Result};
use crate::token::{TableId, Token};

/// `ELEMENT_TYPE_*` constants (II.23.1.16).
pub mod element_type {
    #![allow(missing_docs)]
    pub const END: u8 = 0x00;
    pub const VOID: u8 = 0x01;
    pub const BOOLEAN: u8 = 0x02;
    pub const CHAR: u8 = 0x03;
    pub const I1: u8 = 0x04;
    pub const U1: u8 = 0x05;
    pub const I2: u8 = 0x06;
    pub const U2: u8 = 0x07;
    pub const I4: u8 = 0x08;
    pub const U4: u8 = 0x09;
    pub const I8: u8 = 0x0A;
    pub const U8: u8 = 0x0B;
    pub const R4: u8 = 0x0C;
    pub const R8: u8 = 0x0D;
    pub const STRING: u8 = 0x0E;
    pub const PTR: u8 = 0x0F;
    pub const BYREF: u8 = 0x10;
    pub const VALUETYPE: u8 = 0x11;
    pub const CLASS: u8 = 0x12;
    pub const VAR: u8 = 0x13;
    pub const ARRAY: u8 = 0x14;
    pub const GENERICINST: u8 = 0x15;
    pub const TYPEDBYREF: u8 = 0x16;
    pub const I: u8 = 0x18;
    pub const U: u8 = 0x19;
    pub const FNPTR: u8 = 0x1B;
    pub const OBJECT: u8 = 0x1C;
    pub const SZARRAY: u8 = 0x1D;
    pub const MVAR: u8 = 0x1E;
    pub const CMOD_REQD: u8 = 0x1F;
    pub const CMOD_OPT: u8 = 0x20;
    pub const INTERNAL: u8 = 0x21;
    pub const MODIFIER: u8 = 0x40;
    pub const SENTINEL: u8 = 0x41;
    pub const PINNED: u8 = 0x45;
}

/// Calling-convention byte constants (II.23.2.3).
pub mod calling_convention {
    #![allow(missing_docs)]
    pub const DEFAULT: u8 = 0x00;
    pub const C: u8 = 0x01;
    pub const STDCALL: u8 = 0x02;
    pub const THISCALL: u8 = 0x03;
    pub const FASTCALL: u8 = 0x04;
    pub const VARARG: u8 = 0x05;
    pub const FIELD: u8 = 0x06;
    pub const LOCAL_SIG: u8 = 0x07;
    pub const PROPERTY: u8 = 0x08;
    pub const UNMANAGED: u8 = 0x09;
    pub const GENERICINST: u8 = 0x0A;
    pub const NATIVEVARARG: u8 = 0x0B;
    pub const MASK: u8 = 0x0F;
    pub const GENERIC: u8 = 0x10;
    pub const HASTHIS: u8 = 0x20;
    pub const EXPLICITTHIS: u8 = 0x40;
}

/// Knobs for the signature parsers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignatureOptions {
    /// The maximum nesting depth of a type before parsing fails.
    pub recursion_limit: u32,
}

impl Default for SignatureOptions {
    fn default() -> Self {
        SignatureOptions { recursion_limit: 64 }
    }
}

/// A `modreq` or `modopt` custom modifier (II.23.2.7).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CustomMod {
    /// True for `CMOD_REQD`, false for `CMOD_OPT`.
    pub required: bool,
    /// The modifier type, a `TypeDefOrRefOrSpec` token.
    pub type_token: Token,
}

/// The shape of a multi-dimensional array (II.23.2.13).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArrayShape {
    /// The number of dimensions.
    pub rank: u32,
    /// Declared sizes, for a prefix of the dimensions.
    pub sizes: Vec<u32>,
    /// Declared lower bounds, for a prefix of the dimensions.
    pub lo_bounds: Vec<i32>,
}

/// A decoded type signature (II.23.2.12).
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Type<'a> {
    /// `ELEMENT_TYPE_VOID`.
    Void,
    /// `ELEMENT_TYPE_BOOLEAN`.
    Boolean,
    /// `ELEMENT_TYPE_CHAR`, a UTF-16 code unit.
    Char,
    /// `ELEMENT_TYPE_I1`.
    I1,
    /// `ELEMENT_TYPE_U1`.
    U1,
    /// `ELEMENT_TYPE_I2`.
    I2,
    /// `ELEMENT_TYPE_U2`.
    U2,
    /// `ELEMENT_TYPE_I4`.
    I4,
    /// `ELEMENT_TYPE_U4`.
    U4,
    /// `ELEMENT_TYPE_I8`.
    I8,
    /// `ELEMENT_TYPE_U8`.
    U8,
    /// `ELEMENT_TYPE_R4`.
    R4,
    /// `ELEMENT_TYPE_R8`.
    R8,
    /// `ELEMENT_TYPE_STRING`.
    String,
    /// `ELEMENT_TYPE_OBJECT`.
    Object,
    /// `ELEMENT_TYPE_TYPEDBYREF`.
    TypedByRef,
    /// `ELEMENT_TYPE_I`, a native signed integer.
    IntPtr,
    /// `ELEMENT_TYPE_U`, a native unsigned integer.
    UIntPtr,
    /// `ELEMENT_TYPE_PTR CustomMod* (Type | VOID)`.
    Ptr(Vec<CustomMod>, Box<Type<'a>>),
    /// `ELEMENT_TYPE_BYREF Type`.
    ByRef(Box<Type<'a>>),
    /// `ELEMENT_TYPE_VALUETYPE TypeDefOrRefOrSpec`.
    ValueType(Token),
    /// `ELEMENT_TYPE_CLASS TypeDefOrRefOrSpec`.
    Class(Token),
    /// `ELEMENT_TYPE_VAR`, a generic type parameter by position.
    Var(u32),
    /// `ELEMENT_TYPE_MVAR`, a generic method parameter by position.
    MVar(u32),
    /// `ELEMENT_TYPE_ARRAY Type ArrayShape`.
    Array(Box<Type<'a>>, ArrayShape),
    /// `ELEMENT_TYPE_SZARRAY CustomMod* Type`, a zero-based one-dimensional array.
    SzArray(Vec<CustomMod>, Box<Type<'a>>),
    /// `ELEMENT_TYPE_GENERICINST (CLASS | VALUETYPE) TypeDefOrRefOrSpec GenArgCount Type*`.
    GenericInst {
        /// True when the instantiated definition is a value type.
        is_value_type: bool,
        /// The generic type definition or reference.
        def: Token,
        /// The type arguments.
        args: Vec<Type<'a>>,
    },
    /// `ELEMENT_TYPE_FNPTR MethodDefSig | MethodRefSig`.
    FnPtr(Box<MethodSig<'a>>),
    /// Custom modifiers found in a type position that the grammar does not
    /// attach to `PTR` or `SZARRAY`.
    Modified(Vec<CustomMod>, Box<Type<'a>>),
    /// `ELEMENT_TYPE_PINNED Type`, legal only in a `LocalVarSig`.
    Pinned(Box<Type<'a>>),
    /// `ELEMENT_TYPE_SENTINEL`.
    ///
    /// Never produced by the parsers here: a sentinel in a vararg signature
    /// splits [`MethodSig::params`] from [`MethodSig::vararg_params`], and a
    /// sentinel anywhere else is an error. The variant exists so that callers
    /// can build signatures of their own.
    Sentinel,
    /// `ELEMENT_TYPE_INTERNAL`, a runtime-internal type handle.
    ///
    /// Never produced by the parsers here; a blob containing `0x21` fails with
    /// [`ErrorKind::Unsupported`] rather than being misparsed.
    Internal(usize),
}

impl Type<'_> {
    /// The width in bits of a primitive, pointer or reference type.
    ///
    /// `pointer_bits` is the platform pointer width, normally 32 or 64.
    /// Value types, generic parameters and arrays return `None` because their
    /// width is not determined by the signature alone.
    pub fn primitive_width(&self, pointer_bits: u16) -> Option<u16> {
        Some(match self {
            Type::Boolean | Type::I1 | Type::U1 => 8,
            Type::Char | Type::I2 | Type::U2 => 16,
            Type::I4 | Type::U4 | Type::R4 => 32,
            Type::I8 | Type::U8 | Type::R8 => 64,
            Type::IntPtr | Type::UIntPtr | Type::Ptr(..) | Type::ByRef(_) | Type::FnPtr(_) => {
                pointer_bits
            }
            Type::String | Type::Object | Type::Class(_) | Type::SzArray(..) | Type::Array(..) => {
                pointer_bits
            }
            Type::Modified(_, inner) | Type::Pinned(inner) => {
                inner.primitive_width(pointer_bits)?
            }
            _ => return None,
        })
    }

    /// True for the built-in primitive element types.
    pub const fn is_primitive(&self) -> bool {
        matches!(
            self,
            Type::Boolean
                | Type::Char
                | Type::I1
                | Type::U1
                | Type::I2
                | Type::U2
                | Type::I4
                | Type::U4
                | Type::I8
                | Type::U8
                | Type::R4
                | Type::R8
                | Type::IntPtr
                | Type::UIntPtr
        )
    }

    /// Strips `Modified` and `Pinned` wrappers.
    pub fn unwrap_modifiers(&self) -> &Type<'_> {
        match self {
            Type::Modified(_, inner) | Type::Pinned(inner) => inner.unwrap_modifiers(),
            other => other,
        }
    }
}

/// A calling convention (II.23.2.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum CallConv {
    /// `DEFAULT`.
    Default,
    /// `VARARG`.
    VarArg,
    /// `DEFAULT` with the `GENERIC` bit, carrying the generic parameter count.
    Generic(u32),
    /// `C`, the unmanaged cdecl convention.
    C,
    /// `STDCALL`.
    StdCall,
    /// `THISCALL`.
    ThisCall,
    /// `FASTCALL`.
    FastCall,
    /// `UNMANAGED`, whose details live in a `modopt` on the return type.
    Unmanaged,
    /// `NATIVEVARARG`.
    NativeVarArg,
    /// `FIELD`.
    Field,
    /// `LOCAL_SIG`.
    LocalSig,
    /// `PROPERTY`.
    Property,
    /// `GENERICINST`, used by `MethodSpec` signatures.
    GenericInst,
}

impl CallConv {
    /// True when the convention is one of the unmanaged ones.
    pub const fn is_unmanaged(self) -> bool {
        matches!(
            self,
            CallConv::C
                | CallConv::StdCall
                | CallConv::ThisCall
                | CallConv::FastCall
                | CallConv::Unmanaged
                | CallConv::NativeVarArg
        )
    }

    /// The generic parameter count, for a generic method signature.
    pub const fn generic_param_count(self) -> u32 {
        match self {
            CallConv::Generic(n) => n,
            _ => 0,
        }
    }
}

/// A parameter or return type, with its custom modifiers (II.23.2.10).
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Param<'a> {
    /// Modifiers that precede the type.
    pub custom_mods: Vec<CustomMod>,
    /// True when the parameter is passed by reference.
    pub by_ref: bool,
    /// The parameter type; `Void` only ever appears on a return type.
    pub type_: Type<'a>,
}

impl Param<'_> {
    /// True when this is a `void` return.
    pub const fn is_void(&self) -> bool {
        matches!(self.type_, Type::Void)
    }
}

/// A method signature: `MethodDefSig`, `MethodRefSig` or `StandAloneMethodSig`
/// (II.23.2.1–II.23.2.3).
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MethodSig<'a> {
    /// The signature bytes this was decoded from.
    #[cfg_attr(feature = "serde", serde(skip, default))]
    pub raw: &'a [u8],
    /// The calling convention, including the generic parameter count.
    pub calling_convention: CallConv,
    /// True when the `HASTHIS` bit is set.
    pub has_this: bool,
    /// True when the `EXPLICITTHIS` bit is set.
    pub explicit_this: bool,
    /// The return type.
    pub return_type: Param<'a>,
    /// Parameters before any `SENTINEL`.
    pub params: Vec<Param<'a>>,
    /// Parameters after a `SENTINEL`, for a vararg call site.
    pub vararg_params: Vec<Param<'a>>,
}

impl<'a> MethodSig<'a> {
    /// The total number of parameters, including varargs.
    pub fn param_count(&self) -> usize {
        self.params.len() + self.vararg_params.len()
    }

    /// True when the method returns something other than `void`.
    pub fn has_return(&self) -> bool {
        !self.return_type.is_void()
    }

    /// The number of arguments a call site pushes, including `this`.
    pub fn arg_count_with_this(&self) -> usize {
        self.param_count() + usize::from(self.has_this)
    }

    /// Parses a `MethodDefSig`, `MethodRefSig` or `StandAloneMethodSig`.
    ///
    /// The three share a grammar, so one parser reads all of them: a
    /// `MethodDef` signature never carries a `SENTINEL`, a `MethodRef` one may,
    /// and the `StandAloneMethodSig` that a `calli` names is distinguished only
    /// by its calling convention, which [`MethodSig::calling_convention`]
    /// reports.
    pub fn parse(blob: &'a [u8]) -> Result<Self> {
        Self::parse_with(blob, SignatureOptions::default())
    }

    /// Parses a method signature with explicit options.
    pub fn parse_with(blob: &'a [u8], options: SignatureOptions) -> Result<Self> {
        let mut p = Parser::new(blob, options);
        let sig = p.method_sig()?;
        Ok(sig)
    }
}

/// A `FieldSig` (II.23.2.4).
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FieldSig<'a> {
    /// The signature bytes this was decoded from.
    #[cfg_attr(feature = "serde", serde(skip, default))]
    pub raw: &'a [u8],
    /// Modifiers that precede the field type.
    pub custom_mods: Vec<CustomMod>,
    /// The field type.
    pub type_: Type<'a>,
}

impl<'a> FieldSig<'a> {
    /// Parses a `FieldSig`.
    pub fn parse(blob: &'a [u8]) -> Result<Self> {
        Self::parse_with(blob, SignatureOptions::default())
    }

    /// Parses a `FieldSig` with explicit options.
    pub fn parse_with(blob: &'a [u8], options: SignatureOptions) -> Result<Self> {
        let mut p = Parser::new(blob, options);
        p.expect_convention(calling_convention::FIELD)?;
        let custom_mods = p.custom_mods()?;
        let type_ = p.type_()?;
        Ok(FieldSig { raw: blob, custom_mods, type_ })
    }
}

/// One entry of a `LocalVarSig` (II.23.2.6).
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LocalVar<'a> {
    /// Modifiers that precede the local type.
    pub custom_mods: Vec<CustomMod>,
    /// True when the local is pinned for the duration of its scope.
    pub pinned: bool,
    /// True when the local holds a managed reference.
    pub by_ref: bool,
    /// The local type.
    pub type_: Type<'a>,
}

/// A `LocalVarSig` (II.23.2.6).
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LocalVarSig<'a> {
    /// The signature bytes this was decoded from.
    #[cfg_attr(feature = "serde", serde(skip, default))]
    pub raw: &'a [u8],
    /// The locals, in slot order.
    pub locals: Vec<LocalVar<'a>>,
}

impl<'a> LocalVarSig<'a> {
    /// Parses a `LocalVarSig`.
    pub fn parse(blob: &'a [u8]) -> Result<Self> {
        Self::parse_with(blob, SignatureOptions::default())
    }

    /// Parses a `LocalVarSig` with explicit options.
    pub fn parse_with(blob: &'a [u8], options: SignatureOptions) -> Result<Self> {
        let mut p = Parser::new(blob, options);
        p.expect_convention(calling_convention::LOCAL_SIG)?;
        let count = p.bounded_count()?;
        let mut locals = Vec::with_capacity(count as usize);
        for _ in 0..count {
            locals.push(p.local_var()?);
        }
        Ok(LocalVarSig { raw: blob, locals })
    }
}

/// A `PropertySig` (II.23.2.5).
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PropertySig<'a> {
    /// The signature bytes this was decoded from.
    #[cfg_attr(feature = "serde", serde(skip, default))]
    pub raw: &'a [u8],
    /// True when the property is an instance property.
    pub has_this: bool,
    /// The property type, with any modifiers.
    pub return_type: Param<'a>,
    /// The index parameters of an indexer.
    pub params: Vec<Param<'a>>,
}

impl<'a> PropertySig<'a> {
    /// Parses a `PropertySig`.
    pub fn parse(blob: &'a [u8]) -> Result<Self> {
        Self::parse_with(blob, SignatureOptions::default())
    }

    /// Parses a `PropertySig` with explicit options.
    pub fn parse_with(blob: &'a [u8], options: SignatureOptions) -> Result<Self> {
        let mut p = Parser::new(blob, options);
        let byte = p.u8()?;
        if byte & calling_convention::MASK != calling_convention::PROPERTY {
            return Err(p.error_at(ErrorKind::Malformed, 0));
        }
        let has_this = byte & calling_convention::HASTHIS != 0;
        let count = p.bounded_count()?;
        let return_type = p.param()?;
        let mut params = Vec::with_capacity(count as usize);
        for _ in 0..count {
            params.push(p.param()?);
        }
        Ok(PropertySig { raw: blob, has_this, return_type, params })
    }
}

/// A `MethodSpec` signature: the type arguments of a generic instantiation
/// (II.23.2.15).
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MethodSpecSig<'a> {
    /// The signature bytes this was decoded from.
    #[cfg_attr(feature = "serde", serde(skip, default))]
    pub raw: &'a [u8],
    /// The type arguments.
    pub args: Vec<Type<'a>>,
}

impl<'a> MethodSpecSig<'a> {
    /// Parses a `MethodSpec` signature.
    pub fn parse(blob: &'a [u8]) -> Result<Self> {
        Self::parse_with(blob, SignatureOptions::default())
    }

    /// Parses a `MethodSpec` signature with explicit options.
    pub fn parse_with(blob: &'a [u8], options: SignatureOptions) -> Result<Self> {
        let mut p = Parser::new(blob, options);
        p.expect_convention(calling_convention::GENERICINST)?;
        let count = p.bounded_count()?;
        let mut args = Vec::with_capacity(count as usize);
        for _ in 0..count {
            args.push(p.type_()?);
        }
        Ok(MethodSpecSig { raw: blob, args })
    }
}

/// A `TypeSpec` signature: a single type (II.23.2.14).
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TypeSpecSig<'a> {
    /// The signature bytes this was decoded from.
    #[cfg_attr(feature = "serde", serde(skip, default))]
    pub raw: &'a [u8],
    /// The type.
    pub type_: Type<'a>,
}

impl<'a> TypeSpecSig<'a> {
    /// Parses a `TypeSpec` signature.
    pub fn parse(blob: &'a [u8]) -> Result<Self> {
        Self::parse_with(blob, SignatureOptions::default())
    }

    /// Parses a `TypeSpec` signature with explicit options.
    pub fn parse_with(blob: &'a [u8], options: SignatureOptions) -> Result<Self> {
        let mut p = Parser::new(blob, options);
        let type_ = p.type_()?;
        Ok(TypeSpecSig { raw: blob, type_ })
    }
}

/// The recursive-descent signature parser.
struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    depth: u32,
    options: SignatureOptions,
    pinned_seen: bool,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8], options: SignatureOptions) -> Self {
        Parser { data, pos: 0, depth: 0, options, pinned_seen: false }
    }

    fn error(&self, kind: ErrorKind) -> Error {
        Error::new(kind, self.pos, "signature")
    }

    fn error_at(&self, kind: ErrorKind, pos: usize) -> Error {
        Error::new(kind, pos, "signature")
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8> {
        let b = *self.data.get(self.pos).ok_or(self.error(ErrorKind::Truncated))?;
        self.pos += 1;
        Ok(b)
    }

    fn peek(&self) -> Result<u8> {
        self.data.get(self.pos).copied().ok_or(self.error(ErrorKind::Truncated))
    }

    fn cu32(&mut self) -> Result<u32> {
        let at = self.pos;
        let (value, used) = compressed::read_u32(&self.data[self.pos.min(self.data.len())..])
            .map_err(|e| e.rebase(at))?;
        self.pos += used;
        Ok(value)
    }

    fn ci32(&mut self) -> Result<i32> {
        let at = self.pos;
        let (value, used) = compressed::read_i32(&self.data[self.pos.min(self.data.len())..])
            .map_err(|e| e.rebase(at))?;
        self.pos += used;
        Ok(value)
    }

    /// A count that cannot exceed the number of bytes left, since every item
    /// takes at least one byte. This is what keeps `Vec::with_capacity` safe.
    fn bounded_count(&mut self) -> Result<u32> {
        let at = self.pos;
        let count = self.cu32()?;
        if count as usize > self.remaining() {
            return Err(self.error_at(ErrorKind::Malformed, at));
        }
        Ok(count)
    }

    fn expect_convention(&mut self, expected: u8) -> Result<u8> {
        let at = self.pos;
        let byte = self.u8()?;
        if byte & calling_convention::MASK != expected {
            return Err(self.error_at(ErrorKind::Malformed, at));
        }
        Ok(byte)
    }

    /// `TypeDefOrRefOrSpecEncoded` (II.23.2.8).
    fn type_token(&mut self) -> Result<Token> {
        let at = self.pos;
        let value = self.cu32()?;
        let table = match value & 0x03 {
            0 => TableId::TypeDef,
            1 => TableId::TypeRef,
            2 => TableId::TypeSpec,
            _ => return Err(self.error_at(ErrorKind::Malformed, at)),
        };
        Ok(Token::new(table, value >> 2))
    }

    fn custom_mods(&mut self) -> Result<Vec<CustomMod>> {
        let mut mods = Vec::new();
        while let Ok(byte) = self.peek() {
            let required = match byte {
                element_type::CMOD_REQD => true,
                element_type::CMOD_OPT => false,
                _ => break,
            };
            self.pos += 1;
            let type_token = self.type_token()?;
            mods.push(CustomMod { required, type_token });
            if mods.len() > self.options.recursion_limit as usize {
                return Err(self.error(ErrorKind::RecursionLimit));
            }
        }
        Ok(mods)
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > self.options.recursion_limit {
            return Err(self.error(ErrorKind::RecursionLimit));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn type_(&mut self) -> Result<Type<'a>> {
        self.enter()?;
        let result = self.type_inner();
        self.leave();
        result
    }

    fn type_inner(&mut self) -> Result<Type<'a>> {
        use element_type as et;
        // Modifiers that the grammar does not attach to a specific constructor.
        let leading = self.custom_mods()?;
        if !leading.is_empty() {
            let inner = self.type_()?;
            return Ok(Type::Modified(leading, Box::new(inner)));
        }

        let at = self.pos;
        let byte = self.u8()?;
        Ok(match byte {
            et::VOID => Type::Void,
            et::BOOLEAN => Type::Boolean,
            et::CHAR => Type::Char,
            et::I1 => Type::I1,
            et::U1 => Type::U1,
            et::I2 => Type::I2,
            et::U2 => Type::U2,
            et::I4 => Type::I4,
            et::U4 => Type::U4,
            et::I8 => Type::I8,
            et::U8 => Type::U8,
            et::R4 => Type::R4,
            et::R8 => Type::R8,
            et::STRING => Type::String,
            et::OBJECT => Type::Object,
            et::TYPEDBYREF => Type::TypedByRef,
            et::I => Type::IntPtr,
            et::U => Type::UIntPtr,
            et::PTR => {
                let mods = self.custom_mods()?;
                Type::Ptr(mods, Box::new(self.type_()?))
            }
            et::BYREF => Type::ByRef(Box::new(self.type_()?)),
            et::VALUETYPE => Type::ValueType(self.type_token()?),
            et::CLASS => Type::Class(self.type_token()?),
            et::VAR => Type::Var(self.cu32()?),
            et::MVAR => Type::MVar(self.cu32()?),
            et::SZARRAY => {
                let mods = self.custom_mods()?;
                Type::SzArray(mods, Box::new(self.type_()?))
            }
            et::ARRAY => {
                let element = self.type_()?;
                let shape = self.array_shape()?;
                Type::Array(Box::new(element), shape)
            }
            et::GENERICINST => {
                let kind = self.u8()?;
                let is_value_type = match kind {
                    et::VALUETYPE => true,
                    et::CLASS => false,
                    _ => return Err(self.error_at(ErrorKind::Malformed, self.pos - 1)),
                };
                let def = self.type_token()?;
                let count = self.bounded_count()?;
                let mut args = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    args.push(self.type_()?);
                }
                Type::GenericInst { is_value_type, def, args }
            }
            et::FNPTR => Type::FnPtr(Box::new(self.method_sig()?)),
            et::PINNED => {
                if self.pinned_seen {
                    return Err(self.error_at(ErrorKind::Malformed, at));
                }
                self.pinned_seen = true;
                let inner = self.type_();
                self.pinned_seen = false;
                Type::Pinned(Box::new(inner?))
            }
            et::INTERNAL => return Err(self.error_at(ErrorKind::Unsupported, at)),
            et::SENTINEL | et::END => return Err(self.error_at(ErrorKind::Malformed, at)),
            _ => return Err(self.error_at(ErrorKind::Malformed, at)),
        })
    }

    fn array_shape(&mut self) -> Result<ArrayShape> {
        let rank = self.cu32()?;
        if rank as usize > self.remaining() + 1 {
            return Err(self.error(ErrorKind::Malformed));
        }
        let num_sizes = self.bounded_count()?;
        let mut sizes = Vec::with_capacity(num_sizes as usize);
        for _ in 0..num_sizes {
            sizes.push(self.cu32()?);
        }
        let num_lo_bounds = self.bounded_count()?;
        let mut lo_bounds = Vec::with_capacity(num_lo_bounds as usize);
        for _ in 0..num_lo_bounds {
            lo_bounds.push(self.ci32()?);
        }
        Ok(ArrayShape { rank, sizes, lo_bounds })
    }

    fn param(&mut self) -> Result<Param<'a>> {
        let custom_mods = self.custom_mods()?;
        let by_ref = if self.peek()? == element_type::BYREF {
            self.pos += 1;
            true
        } else {
            false
        };
        let type_ = self.type_()?;
        Ok(Param { custom_mods, by_ref, type_ })
    }

    fn local_var(&mut self) -> Result<LocalVar<'a>> {
        // `TYPEDBYREF` stands alone, without modifiers or `BYREF`.
        if self.peek()? == element_type::TYPEDBYREF {
            self.pos += 1;
            return Ok(LocalVar {
                custom_mods: Vec::new(),
                pinned: false,
                by_ref: false,
                type_: Type::TypedByRef,
            });
        }
        let mut custom_mods = self.custom_mods()?;
        let mut pinned = false;
        if self.peek()? == element_type::PINNED {
            self.pos += 1;
            pinned = true;
            custom_mods.extend(self.custom_mods()?);
        }
        let by_ref = if self.peek()? == element_type::BYREF {
            self.pos += 1;
            true
        } else {
            false
        };
        let type_ = self.type_()?;
        if matches!(type_, Type::Pinned(_)) {
            return Err(self.error(ErrorKind::Malformed));
        }
        Ok(LocalVar { custom_mods, pinned, by_ref, type_ })
    }

    fn method_sig(&mut self) -> Result<MethodSig<'a>> {
        self.enter()?;
        let result = self.method_sig_inner();
        self.leave();
        result
    }

    fn method_sig_inner(&mut self) -> Result<MethodSig<'a>> {
        let start = self.pos;
        let byte = self.u8()?;
        let has_this = byte & calling_convention::HASTHIS != 0;
        let explicit_this = byte & calling_convention::EXPLICITTHIS != 0;
        let generic = byte & calling_convention::GENERIC != 0;
        let generic_count = if generic { self.cu32()? } else { 0 };

        let calling_convention = match byte & calling_convention::MASK {
            calling_convention::DEFAULT if generic => CallConv::Generic(generic_count),
            calling_convention::DEFAULT => CallConv::Default,
            calling_convention::C => CallConv::C,
            calling_convention::STDCALL => CallConv::StdCall,
            calling_convention::THISCALL => CallConv::ThisCall,
            calling_convention::FASTCALL => CallConv::FastCall,
            calling_convention::VARARG => CallConv::VarArg,
            calling_convention::UNMANAGED => CallConv::Unmanaged,
            calling_convention::NATIVEVARARG => CallConv::NativeVarArg,
            _ => return Err(self.error_at(ErrorKind::Malformed, start)),
        };

        let count = self.bounded_count()?;
        let return_type = self.param()?;
        let mut params = Vec::with_capacity(count as usize);
        let mut vararg_params = Vec::new();
        let mut past_sentinel = false;
        for _ in 0..count {
            if self.peek()? == element_type::SENTINEL {
                if past_sentinel {
                    return Err(self.error(ErrorKind::Malformed));
                }
                self.pos += 1;
                past_sentinel = true;
            }
            let param = self.param()?;
            if past_sentinel {
                vararg_params.push(param);
            } else {
                params.push(param);
            }
        }

        let raw = self.data.get(start..self.pos).unwrap_or(self.data);
        Ok(MethodSig {
            raw,
            calling_convention,
            has_this,
            explicit_this,
            return_type,
            params,
            vararg_params,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::element_type as et;
    use super::*;

    #[test]
    fn parses_a_simple_method_signature() {
        // HASTHIS DEFAULT, 2 params, void(int32, string)
        let blob = [0x20, 0x02, et::VOID, et::I4, et::STRING];
        let sig = MethodSig::parse(&blob).unwrap();
        assert!(sig.has_this);
        assert!(!sig.explicit_this);
        assert_eq!(sig.calling_convention, CallConv::Default);
        assert!(!sig.has_return());
        assert_eq!(sig.param_count(), 2);
        assert_eq!(sig.params[0].type_, Type::I4);
        assert_eq!(sig.params[1].type_, Type::String);
        assert_eq!(sig.arg_count_with_this(), 3);
        assert_eq!(sig.raw, &blob);
    }

    #[test]
    fn parses_a_generic_method_signature() {
        // DEFAULT|GENERIC, 1 generic param, 1 param: !!0 Foo<!!0>(!!0)
        let blob = [0x10, 0x01, 0x01, et::MVAR, 0x00, et::MVAR, 0x00];
        let sig = MethodSig::parse(&blob).unwrap();
        assert_eq!(sig.calling_convention, CallConv::Generic(1));
        assert_eq!(sig.calling_convention.generic_param_count(), 1);
        assert_eq!(sig.return_type.type_, Type::MVar(0));
        assert_eq!(sig.params[0].type_, Type::MVar(0));
    }

    #[test]
    fn splits_vararg_parameters_at_the_sentinel() {
        // VARARG, 3 params, void(int32, ..., string)
        let blob = [0x05, 0x03, et::VOID, et::I4, et::SENTINEL, et::STRING, et::I8];
        let sig = MethodSig::parse(&blob).unwrap();
        assert_eq!(sig.calling_convention, CallConv::VarArg);
        assert_eq!(sig.params.len(), 1);
        assert_eq!(
            sig.vararg_params,
            alloc::vec![
                Param { custom_mods: Vec::new(), by_ref: false, type_: Type::String },
                Param { custom_mods: Vec::new(), by_ref: false, type_: Type::I8 },
            ]
        );
        assert_eq!(sig.param_count(), 3);
    }

    #[test]
    fn a_second_sentinel_is_rejected() {
        let blob = [0x05, 0x03, et::VOID, et::SENTINEL, et::I4, et::SENTINEL, et::I8];
        assert_eq!(MethodSig::parse(&blob).unwrap_err().kind, ErrorKind::Malformed);
    }

    #[test]
    fn parses_byref_and_custom_mods() {
        // DEFAULT, 1 param, void(modreq(TypeRef 1) int32&)
        let blob = [0x00, 0x01, et::VOID, et::CMOD_REQD, 0x05, et::BYREF, et::I4];
        let sig = MethodSig::parse(&blob).unwrap();
        let p = &sig.params[0];
        assert!(p.by_ref);
        assert_eq!(p.custom_mods.len(), 1);
        assert!(p.custom_mods[0].required);
        assert_eq!(p.custom_mods[0].type_token, Token::new(TableId::TypeRef, 1));
        assert_eq!(p.type_, Type::I4);
    }

    #[test]
    fn parses_a_field_signature() {
        let blob = [0x06, et::SZARRAY, et::U1];
        let sig = FieldSig::parse(&blob).unwrap();
        assert_eq!(sig.type_, Type::SzArray(Vec::new(), Box::new(Type::U1)));
        assert_eq!(FieldSig::parse(&[0x07, et::U1]).unwrap_err().kind, ErrorKind::Malformed);
    }

    #[test]
    fn parses_local_variables_including_pinned() {
        // LOCAL_SIG, 3 locals: int32, pinned uint8&, typedbyref
        let blob = [0x07, 0x03, et::I4, et::PINNED, et::BYREF, et::U1, et::TYPEDBYREF];
        let sig = LocalVarSig::parse(&blob).unwrap();
        assert_eq!(sig.locals.len(), 3);
        assert_eq!(sig.locals[0].type_, Type::I4);
        assert!(sig.locals[1].pinned);
        assert!(sig.locals[1].by_ref);
        assert_eq!(sig.locals[1].type_, Type::U1);
        assert_eq!(sig.locals[2].type_, Type::TypedByRef);
    }

    #[test]
    fn parses_generic_instantiation() {
        // TypeSpec: class List`1<int32>
        let blob = [et::GENERICINST, et::CLASS, 0x05, 0x01, et::I4];
        let sig = TypeSpecSig::parse(&blob).unwrap();
        match sig.type_ {
            Type::GenericInst { is_value_type, def, ref args } => {
                assert!(!is_value_type);
                assert_eq!(def, Token::new(TableId::TypeRef, 1));
                assert_eq!(args, &alloc::vec![Type::I4]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_an_array_shape() {
        // int32[2, 3...] : rank 2, 1 size, 1 lower bound
        let blob = [et::ARRAY, et::I4, 0x02, 0x01, 0x05, 0x01, 0x02];
        let sig = TypeSpecSig::parse(&blob).unwrap();
        match sig.type_ {
            Type::Array(ref element, ref shape) => {
                assert_eq!(**element, Type::I4);
                assert_eq!(shape.rank, 2);
                assert_eq!(shape.sizes, alloc::vec![5]);
                assert_eq!(shape.lo_bounds, alloc::vec![1]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_a_method_spec() {
        let blob = [0x0A, 0x02, et::I4, et::STRING];
        let sig = MethodSpecSig::parse(&blob).unwrap();
        assert_eq!(sig.args, alloc::vec![Type::I4, Type::String]);
    }

    #[test]
    fn parses_a_property_signature() {
        // PROPERTY|HASTHIS, 1 index param, int32 this[string]
        let blob = [0x28, 0x01, et::I4, et::STRING];
        let sig = PropertySig::parse(&blob).unwrap();
        assert!(sig.has_this);
        assert_eq!(sig.return_type.type_, Type::I4);
        assert_eq!(sig.params.len(), 1);
    }

    #[test]
    fn parses_a_function_pointer() {
        let blob = [0x06, et::FNPTR, 0x00, 0x01, et::VOID, et::I4];
        let sig = FieldSig::parse(&blob).unwrap();
        match sig.type_ {
            Type::FnPtr(ref m) => {
                assert_eq!(m.params.len(), 1);
                assert_eq!(m.return_type.type_, Type::Void);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn recursion_is_bounded() {
        let mut blob = alloc::vec![0x06u8];
        blob.extend(core::iter::repeat_n(et::PTR, 5000));
        blob.push(et::VOID);
        assert_eq!(FieldSig::parse(&blob).unwrap_err().kind, ErrorKind::RecursionLimit);
        let options = SignatureOptions { recursion_limit: 8 };
        let mut small = alloc::vec![0x06u8];
        small.extend(core::iter::repeat_n(et::PTR, 4));
        small.push(et::VOID);
        assert!(FieldSig::parse_with(&small, options).is_ok());
    }

    #[test]
    fn internal_element_type_is_unsupported() {
        let blob = [0x06, et::INTERNAL, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(FieldSig::parse(&blob).unwrap_err().kind, ErrorKind::Unsupported);
    }

    #[test]
    fn declared_counts_cannot_outrun_the_blob() {
        // 0x7F parameters declared, but only a few bytes follow.
        let blob = [0x00, 0x7F, et::VOID, et::I4];
        assert_eq!(MethodSig::parse(&blob).unwrap_err().kind, ErrorKind::Malformed);
        let blob = [0x07, 0x7F, et::I4];
        assert_eq!(LocalVarSig::parse(&blob).unwrap_err().kind, ErrorKind::Malformed);
    }

    #[test]
    fn errors_carry_a_blob_relative_offset() {
        // Byte 3 is an undefined element type.
        let blob = [0x00, 0x01, et::VOID, 0x7A];
        let e = MethodSig::parse(&blob).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Malformed);
        assert_eq!(e.offset, Some(3));
    }

    #[test]
    fn primitive_widths() {
        assert_eq!(Type::I4.primitive_width(64), Some(32));
        assert_eq!(Type::Char.primitive_width(64), Some(16));
        assert_eq!(Type::IntPtr.primitive_width(32), Some(32));
        assert_eq!(Type::Object.primitive_width(64), Some(64));
        assert_eq!(Type::ValueType(Token(0)).primitive_width(64), None);
        assert_eq!(Type::Var(0).primitive_width(64), None);
        assert_eq!(Type::Void.primitive_width(64), None);
    }

    #[test]
    fn every_truncation_of_a_valid_signature_errors_cleanly() {
        let blob = [0x20, 0x02, et::VOID, et::I4, et::SZARRAY, et::STRING];
        for len in 0..blob.len() {
            let _ = MethodSig::parse(&blob[..len]);
        }
        assert!(MethodSig::parse(&blob).is_ok());
    }
}
