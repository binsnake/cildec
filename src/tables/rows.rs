//! Typed metadata table rows (ECMA-335 II.22) and the Portable PDB tables.
//!
//! Every row is a `Copy` struct with named fields whose types record what the
//! column means: [`StringIndex`], [`BlobIndex`], [`GuidIndex`], a typed
//! [`Rid`] for a simple index, or a [`Token`] for a coded index. Nothing here
//! dereferences a heap or follows a token; that is the caller decision.

use crate::error::Result;
use crate::tables::coded::CodedIndex;
use crate::tables::{ColumnKind, RowCursor, TableRow};
use crate::token::{BlobIndex, GuidIndex, Rid, StringIndex, TableId, Token, marker};

macro_rules! col_kind {
    ([u16]) => {
        ColumnKind::U16
    };
    ([u32]) => {
        ColumnKind::U32
    };
    ([str]) => {
        ColumnKind::String
    };
    ([blob]) => {
        ColumnKind::Blob
    };
    ([guid]) => {
        ColumnKind::Guid
    };
    ([rid $t:ident]) => {
        ColumnKind::Rid(TableId::$t)
    };
    ([coded $k:ident]) => {
        ColumnKind::Coded(CodedIndex::$k)
    };
}

macro_rules! col_ty {
    ([u16]) => { u16 };
    ([u32]) => { u32 };
    ([str]) => { StringIndex };
    ([blob]) => { BlobIndex };
    ([guid]) => { GuidIndex };
    ([rid $t:ident]) => { Rid<marker::$t> };
    ([coded $k:ident]) => { Token };
}

macro_rules! col_read {
    ([u16], $c:expr) => {
        $c.uint().map(|v| v as u16)
    };
    ([u32], $c:expr) => {
        $c.uint()
    };
    ([str], $c:expr) => {
        $c.uint().map(StringIndex)
    };
    ([blob], $c:expr) => {
        $c.uint().map(BlobIndex)
    };
    ([guid], $c:expr) => {
        $c.uint().map(GuidIndex)
    };
    ([rid $t:ident], $c:expr) => {
        $c.uint().map(Rid::<marker::$t>::new)
    };
    ([coded $k:ident], $c:expr) => {
        $c.coded(CodedIndex::$k)
    };
}

macro_rules! define_rows {
    ($(
        $(#[$attr:meta])*
        $table:ident as $one:ident / $many:ident {
            $( $(#[$fattr:meta])* $field:ident : $kind:tt ),* $(,)?
        }
    )*) => {
        $(
            $(#[$attr])*
            #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
            #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
            pub struct $table {
                $( $(#[$fattr])* pub $field : col_ty!($kind), )*
            }

            impl TableRow for $table {
                const TABLE: TableId = TableId::$one;
                const COLUMNS: &'static [ColumnKind] = &[ $( col_kind!($kind) ),* ];

                fn decode(cursor: &mut RowCursor<'_>) -> Result<Self> {
                    $( let $field = col_read!($kind, cursor)?; )*
                    Ok($table { $( $field ),* })
                }
            }
        )*

        impl<'a> crate::tables::Tables<'a> {
            $(
                #[doc = concat!("Reads one `", stringify!($one), "` row by 1-based RID, following the `*Ptr` indirection when the image has one.")]
                pub fn $many(&self, rid: u32) -> Result<$table> {
                    self.row_indirect::<$table>(rid)
                }
            )*
        }
    };
}

// The macro derives the accessor name from the second identifier; the first is
// the row struct and must match `TableId` spelling.
define_rows! {
    /// `Module` (II.22.30).
    ModuleRow as Module / module {
        /// `Generation`, always 0 outside edit-and-continue deltas.
        generation: [u16],
        /// The module file name.
        name: [str],
        /// The module version id.
        mvid: [guid],
        /// `EncId`.
        enc_id: [guid],
        /// `EncBaseId`.
        enc_base_id: [guid],
    }

    /// `TypeRef` (II.22.38).
    TypeRefRow as TypeRef / type_ref {
        /// Where the referenced type is defined.
        resolution_scope: [coded ResolutionScope],
        /// The type name, including any generic arity suffix.
        type_name: [str],
        /// The namespace, empty for the global namespace.
        type_namespace: [str],
    }

    /// `TypeDef` (II.22.37).
    TypeDefRow as TypeDef / type_def {
        /// `TypeAttributes`.
        flags: [u32],
        /// The type name, including any generic arity suffix.
        type_name: [str],
        /// The namespace, empty for nested types and the global namespace.
        type_namespace: [str],
        /// The base type, null for `System.Object` and interfaces.
        extends: [coded TypeDefOrRef],
        /// The first field owned by this type; the run ends where the next type starts.
        field_list: [rid Field],
        /// The first method owned by this type; the run ends where the next type starts.
        method_list: [rid MethodDef],
    }

    /// `FieldPtr`, an indirection table present only in `#-` streams.
    FieldPtrRow as FieldPtr / field_ptr {
        /// The physical `Field` row this logical RID maps to.
        field: [rid Field],
    }

    /// `Field` (II.22.15).
    FieldRow as Field / field {
        /// `FieldAttributes`.
        flags: [u16],
        /// The field name.
        name: [str],
        /// A `FieldSig` blob.
        signature: [blob],
    }

    /// `MethodPtr`, an indirection table present only in `#-` streams.
    MethodPtrRow as MethodPtr / method_ptr {
        /// The physical `MethodDef` row this logical RID maps to.
        method: [rid MethodDef],
    }

    /// `MethodDef` (II.22.26).
    MethodDefRow as MethodDef / method_def {
        /// The RVA of the method body, or 0 when there is none.
        rva: [u32],
        /// `MethodImplAttributes`.
        impl_flags: [u16],
        /// `MethodAttributes`.
        flags: [u16],
        /// The method name.
        name: [str],
        /// A `MethodDefSig` blob.
        signature: [blob],
        /// The first parameter row owned by this method.
        param_list: [rid Param],
    }

    /// `ParamPtr`, an indirection table present only in `#-` streams.
    ParamPtrRow as ParamPtr / param_ptr {
        /// The physical `Param` row this logical RID maps to.
        param: [rid Param],
    }

    /// `Param` (II.22.33).
    ParamRow as Param / param {
        /// `ParamAttributes`.
        flags: [u16],
        /// 1-based parameter position; 0 denotes the return value.
        sequence: [u16],
        /// The parameter name, which may be empty.
        name: [str],
    }

    /// `InterfaceImpl` (II.22.23).
    InterfaceImplRow as InterfaceImpl / interface_impl {
        /// The implementing type.
        class: [rid TypeDef],
        /// The implemented interface.
        interface: [coded TypeDefOrRef],
    }

    /// `MemberRef` (II.22.25).
    MemberRefRow as MemberRef / member_ref {
        /// The scope the member is looked up in.
        class: [coded MemberRefParent],
        /// The member name.
        name: [str],
        /// A `MethodRefSig` or `FieldSig` blob.
        signature: [blob],
    }

    /// `Constant` (II.22.9).
    ConstantRow as Constant / constant {
        /// The low byte is an `ELEMENT_TYPE_*` code; the high byte is padding.
        type_raw: [u16],
        /// The field, parameter or property this value belongs to.
        parent: [coded HasConstant],
        /// The little-endian encoded value.
        value: [blob],
    }

    /// `CustomAttribute` (II.22.10).
    CustomAttributeRow as CustomAttribute / custom_attribute {
        /// The metadata item the attribute is attached to.
        parent: [coded HasCustomAttribute],
        /// The attribute constructor.
        constructor: [coded CustomAttributeType],
        /// The raw attribute blob; this crate does not decode it.
        value: [blob],
    }

    /// `FieldMarshal` (II.22.17).
    FieldMarshalRow as FieldMarshal / field_marshal {
        /// The field or parameter being marshalled.
        parent: [coded HasFieldMarshal],
        /// The raw marshalling descriptor; this crate does not decode it.
        native_type: [blob],
    }

    /// `DeclSecurity` (II.22.11).
    DeclSecurityRow as DeclSecurity / decl_security {
        /// `SecurityAction`.
        action: [u16],
        /// The type, method or assembly the declaration applies to.
        parent: [coded HasDeclSecurity],
        /// The raw permission set blob.
        permission_set: [blob],
    }

    /// `ClassLayout` (II.22.8).
    ClassLayoutRow as ClassLayout / class_layout {
        /// `PackingSize`.
        packing_size: [u16],
        /// `ClassSize`.
        class_size: [u32],
        /// The type being laid out.
        parent: [rid TypeDef],
    }

    /// `FieldLayout` (II.22.16).
    FieldLayoutRow as FieldLayout / field_layout {
        /// The byte offset of the field within its type.
        offset: [u32],
        /// The field.
        field: [rid Field],
    }

    /// `StandAloneSig` (II.22.36).
    StandAloneSigRow as StandAloneSig / stand_alone_sig {
        /// A `LocalVarSig` or `StandAloneMethodSig` blob.
        signature: [blob],
    }

    /// `EventMap` (II.22.12).
    EventMapRow as EventMap / event_map {
        /// The type that owns the events.
        parent: [rid TypeDef],
        /// The first event owned by the type.
        event_list: [rid Event],
    }

    /// `EventPtr`, an indirection table present only in `#-` streams.
    EventPtrRow as EventPtr / event_ptr {
        /// The physical `Event` row this logical RID maps to.
        event: [rid Event],
    }

    /// `Event` (II.22.13).
    EventRow as Event / event {
        /// `EventAttributes`.
        event_flags: [u16],
        /// The event name.
        name: [str],
        /// The delegate type of the event.
        event_type: [coded TypeDefOrRef],
    }

    /// `PropertyMap` (II.22.35).
    PropertyMapRow as PropertyMap / property_map {
        /// The type that owns the properties.
        parent: [rid TypeDef],
        /// The first property owned by the type.
        property_list: [rid Property],
    }

    /// `PropertyPtr`, an indirection table present only in `#-` streams.
    PropertyPtrRow as PropertyPtr / property_ptr {
        /// The physical `Property` row this logical RID maps to.
        property: [rid Property],
    }

    /// `Property` (II.22.34).
    PropertyRow as Property / property {
        /// `PropertyAttributes`.
        flags: [u16],
        /// The property name.
        name: [str],
        /// A `PropertySig` blob.
        type_signature: [blob],
    }

    /// `MethodSemantics` (II.22.28).
    MethodSemanticsRow as MethodSemantics / method_semantics {
        /// `MethodSemanticsAttributes`: getter, setter, adder, remover, fire, other.
        semantics: [u16],
        /// The method that implements the semantic.
        method: [rid MethodDef],
        /// The event or property the method belongs to.
        association: [coded HasSemantics],
    }

    /// `MethodImpl` (II.22.27).
    MethodImplRow as MethodImpl / method_impl {
        /// The type providing the implementation.
        class: [rid TypeDef],
        /// The implementing method.
        method_body: [coded MethodDefOrRef],
        /// The method being overridden.
        method_declaration: [coded MethodDefOrRef],
    }

    /// `ModuleRef` (II.22.31).
    ModuleRefRow as ModuleRef / module_ref {
        /// The referenced module file name.
        name: [str],
    }

    /// `TypeSpec` (II.22.39).
    TypeSpecRow as TypeSpec / type_spec {
        /// A `TypeSpec` signature blob.
        signature: [blob],
    }

    /// `ImplMap` (II.22.22), the P/Invoke mapping.
    ImplMapRow as ImplMap / impl_map {
        /// `PInvokeAttributes`.
        mapping_flags: [u16],
        /// The managed method or field the mapping applies to.
        member_forwarded: [coded MemberForwarded],
        /// The unmanaged entry point name.
        import_name: [str],
        /// The module the entry point lives in.
        import_scope: [rid ModuleRef],
    }

    /// `FieldRVA` (II.22.18).
    FieldRvaRow as FieldRva / field_rva {
        /// The RVA of the initial data.
        rva: [u32],
        /// The field the data initialises.
        field: [rid Field],
    }

    /// `ENCLog`, present only in `#-` streams.
    EncLogRow as EncLog / enc_log {
        /// The token affected by the delta.
        token: [u32],
        /// The function code describing the change.
        func_code: [u32],
    }

    /// `ENCMap`, present only in `#-` streams.
    EncMapRow as EncMap / enc_map {
        /// The token this map entry describes.
        token: [u32],
    }

    /// `Assembly` (II.22.2).
    AssemblyRow as Assembly / assembly {
        /// `AssemblyHashAlgorithm`.
        hash_alg_id: [u32],
        /// Version major.
        major_version: [u16],
        /// Version minor.
        minor_version: [u16],
        /// Version build.
        build_number: [u16],
        /// Version revision.
        revision_number: [u16],
        /// `AssemblyFlags`.
        flags: [u32],
        /// The public key, empty when the assembly is not strong-named.
        public_key: [blob],
        /// The simple assembly name.
        name: [str],
        /// The culture name, empty for a culture-neutral assembly.
        culture: [str],
    }

    /// `AssemblyProcessor` (II.22.4); the runtime ignores this table.
    AssemblyProcessorRow as AssemblyProcessor / assembly_processor {
        /// The processor id.
        processor: [u32],
    }

    /// `AssemblyOS` (II.22.3); the runtime ignores this table.
    AssemblyOsRow as AssemblyOs / assembly_os {
        /// The platform id.
        os_platform_id: [u32],
        /// The major OS version.
        os_major_version: [u32],
        /// The minor OS version.
        os_minor_version: [u32],
    }

    /// `AssemblyRef` (II.22.5).
    AssemblyRefRow as AssemblyRef / assembly_ref {
        /// Version major.
        major_version: [u16],
        /// Version minor.
        minor_version: [u16],
        /// Version build.
        build_number: [u16],
        /// Version revision.
        revision_number: [u16],
        /// `AssemblyFlags`.
        flags: [u32],
        /// The full public key or its 8-byte token.
        public_key_or_token: [blob],
        /// The simple assembly name.
        name: [str],
        /// The culture name.
        culture: [str],
        /// The hash of the referenced assembly, usually empty.
        hash_value: [blob],
    }

    /// `AssemblyRefProcessor` (II.22.7); the runtime ignores this table.
    AssemblyRefProcessorRow as AssemblyRefProcessor / assembly_ref_processor {
        /// The processor id.
        processor: [u32],
        /// The assembly reference.
        assembly_ref: [rid AssemblyRef],
    }

    /// `AssemblyRefOS` (II.22.6); the runtime ignores this table.
    AssemblyRefOsRow as AssemblyRefOs / assembly_ref_os {
        /// The platform id.
        os_platform_id: [u32],
        /// The major OS version.
        os_major_version: [u32],
        /// The minor OS version.
        os_minor_version: [u32],
        /// The assembly reference.
        assembly_ref: [rid AssemblyRef],
    }

    /// `File` (II.22.19).
    FileRow as File / file {
        /// `FileAttributes`.
        flags: [u32],
        /// The file name.
        name: [str],
        /// The file hash.
        hash_value: [blob],
    }

    /// `ExportedType` (II.22.14).
    ExportedTypeRow as ExportedType / exported_type {
        /// `TypeAttributes`.
        flags: [u32],
        /// A hint at the `TypeDef` RID in the target file.
        type_def_id: [u32],
        /// The type name.
        type_name: [str],
        /// The namespace.
        type_namespace: [str],
        /// The file or assembly the type lives in.
        implementation: [coded Implementation],
    }

    /// `ManifestResource` (II.22.24).
    ManifestResourceRow as ManifestResource / manifest_resource {
        /// The offset into the resources directory, when embedded.
        offset: [u32],
        /// `ManifestResourceAttributes`.
        flags: [u32],
        /// The resource name.
        name: [str],
        /// The file or assembly holding the resource; null means this file.
        implementation: [coded Implementation],
    }

    /// `NestedClass` (II.22.32).
    NestedClassRow as NestedClass / nested_class {
        /// The nested type.
        nested_class: [rid TypeDef],
        /// The enclosing type.
        enclosing_class: [rid TypeDef],
    }

    /// `GenericParam` (II.22.20).
    GenericParamRow as GenericParam / generic_param {
        /// The 0-based position of the parameter in its owner list.
        number: [u16],
        /// `GenericParamAttributes`: variance and special constraints.
        flags: [u16],
        /// The generic type or method that declares the parameter.
        owner: [coded TypeOrMethodDef],
        /// The parameter name.
        name: [str],
    }

    /// `MethodSpec` (II.22.29).
    MethodSpecRow as MethodSpec / method_spec {
        /// The generic method being instantiated.
        method: [coded MethodDefOrRef],
        /// A `MethodSpec` signature blob holding the type arguments.
        instantiation: [blob],
    }

    /// `GenericParamConstraint` (II.22.21).
    GenericParamConstraintRow as GenericParamConstraint / generic_param_constraint {
        /// The constrained generic parameter.
        owner: [rid GenericParam],
        /// The constraining type.
        constraint: [coded TypeDefOrRef],
    }

    /// Portable PDB `Document`.
    DocumentRow as Document / document {
        /// The blob-encoded document path.
        name: [blob],
        /// The hash algorithm GUID.
        hash_algorithm: [guid],
        /// The document hash.
        hash: [blob],
        /// The source language GUID.
        language: [guid],
    }

    /// Portable PDB `MethodDebugInformation`.
    MethodDebugInformationRow as MethodDebugInformation / method_debug_information {
        /// The single document, when all sequence points share one.
        document: [rid Document],
        /// The sequence point blob; this crate does not decode it.
        sequence_points: [blob],
    }

    /// Portable PDB `LocalScope`.
    LocalScopeRow as LocalScope / local_scope {
        /// The method the scope belongs to.
        method: [rid MethodDef],
        /// The import scope in effect.
        import_scope: [rid ImportScope],
        /// The first local variable in the scope.
        variable_list: [rid LocalVariable],
        /// The first local constant in the scope.
        constant_list: [rid LocalConstant],
        /// The IL offset the scope starts at.
        start_offset: [u32],
        /// The length of the scope in IL bytes.
        length: [u32],
    }

    /// Portable PDB `LocalVariable`.
    LocalVariableRow as LocalVariable / local_variable {
        /// `LocalVariableAttributes`.
        attributes: [u16],
        /// The slot index in the `LocalVarSig`.
        index: [u16],
        /// The variable name.
        name: [str],
    }

    /// Portable PDB `LocalConstant`.
    LocalConstantRow as LocalConstant / local_constant {
        /// The constant name.
        name: [str],
        /// The constant signature blob.
        signature: [blob],
    }

    /// Portable PDB `ImportScope`.
    ImportScopeRow as ImportScope / import_scope {
        /// The enclosing scope, or null at the top.
        parent: [rid ImportScope],
        /// The imports blob; this crate does not decode it.
        imports: [blob],
    }

    /// Portable PDB `StateMachineMethod`.
    StateMachineMethodRow as StateMachineMethod / state_machine_method {
        /// The generated `MoveNext` method.
        move_next_method: [rid MethodDef],
        /// The original method the state machine came from.
        kickoff_method: [rid MethodDef],
    }

    /// Portable PDB `CustomDebugInformation`.
    CustomDebugInformationRow as CustomDebugInformation / custom_debug_information {
        /// The item the information is attached to.
        parent: [coded HasCustomDebugInformation],
        /// The kind GUID.
        kind: [guid],
        /// The raw value blob.
        value: [blob],
    }
}

impl ConstantRow {
    /// The `ELEMENT_TYPE_*` code of the constant.
    pub const fn element_type(self) -> u8 {
        self.type_raw as u8
    }

    /// The padding byte, which ECMA-335 requires to be zero.
    pub const fn padding(self) -> u8 {
        (self.type_raw >> 8) as u8
    }
}

impl MethodDefRow {
    /// True when `CodeTypeMask` of `ImplFlags` selects CIL (`IL`, value 0).
    pub const fn is_il(self) -> bool {
        self.impl_flags & 0x0003 == 0x0000
    }

    /// True when `ImplFlags` marks the method as native code.
    pub const fn is_native(self) -> bool {
        self.impl_flags & 0x0003 == 0x0001
    }

    /// True when `ImplFlags` marks the method as runtime-provided.
    pub const fn is_runtime(self) -> bool {
        self.impl_flags & 0x0003 == 0x0003
    }

    /// True when `MethodAttributes` marks the method `static`.
    pub const fn is_static(self) -> bool {
        self.flags & 0x0010 != 0
    }

    /// True when `MethodAttributes` marks the method abstract.
    pub const fn is_abstract(self) -> bool {
        self.flags & 0x0400 != 0
    }

    /// True when `MethodAttributes` sets `PInvokeImpl`.
    pub const fn is_pinvoke(self) -> bool {
        self.flags & 0x2000 != 0
    }

    /// True when the method has no body: RVA 0, or a non-CIL implementation.
    pub const fn has_no_body(self) -> bool {
        self.rva == 0 || !self.is_il()
    }
}

impl TypeDefRow {
    /// The `ClassLayout` part of `TypeAttributes`: 0 auto, 1 sequential, 2 explicit.
    pub const fn layout_kind(self) -> u8 {
        (self.flags & 0x0000_0018) as u8 >> 3
    }

    /// True when `TypeAttributes` marks the type an interface.
    pub const fn is_interface(self) -> bool {
        self.flags & 0x0000_0020 != 0
    }

    /// True when the type is nested (any of the nested visibility values).
    pub const fn is_nested(self) -> bool {
        let vis = self.flags & 0x0000_0007;
        vis >= 2
    }
}

impl FieldRow {
    /// True when `FieldAttributes` marks the field `static`.
    pub const fn is_static(self) -> bool {
        self.flags & 0x0010 != 0
    }

    /// True when `FieldAttributes` sets `HasFieldRVA`.
    pub const fn has_rva(self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// True when `FieldAttributes` sets `Literal`.
    pub const fn is_literal(self) -> bool {
        self.flags & 0x0040 != 0
    }
}
