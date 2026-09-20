//! Parent and owner lookups over the sorted metadata tables (ECMA-335 II.22).
//!
//! Two shapes of relationship appear in the tables:
//!
//! * A *list column* such as `TypeDef.FieldList`, where a row owns the run of
//!   rows from its own column value up to the next row column value. The
//!   run-length encoding means the owner of a member is found by locating the
//!   last owner whose run starts at or before it.
//! * A *sorted key column* such as `CustomAttribute.Parent`, where every row
//!   for one parent is contiguous. These are binary-searched.
//!
//! Tables that ECMA-335 marks sorted are verified when the stream is parsed.
//! When an image lies about sortedness, every lookup here falls back to a
//! linear scan rather than returning a wrong answer.

use alloc::vec::Vec;
use core::ops::Range;

use crate::error::{Error, ErrorKind, Result};
use crate::tables::coded::CodedIndex;
use crate::tables::{ClassLayoutRow, ConstantRow, ImplMapRow, Tables};
use crate::token::{Rid, TableId, Token, marker};

/// The column a sorted table is ordered by, or `None` when the table has no
/// sort key that ECMA-335 defines.
///
/// This is the column [`Tables::rows_with_key`] binary-searches, and the one
/// [`Tables::is_sorted`] reports on. It is public so that a caller can verify
/// the ordering itself, or scan the same column without guessing its index.
pub const fn sort_key_column(table: TableId) -> Option<usize> {
    Some(match table {
        TableId::InterfaceImpl => 0,          // Class
        TableId::Constant => 1,               // Parent
        TableId::CustomAttribute => 0,        // Parent
        TableId::FieldMarshal => 0,           // Parent
        TableId::DeclSecurity => 1,           // Parent
        TableId::ClassLayout => 2,            // Parent
        TableId::FieldLayout => 1,            // Field
        TableId::EventMap => 0,               // Parent
        TableId::PropertyMap => 0,            // Parent
        TableId::MethodSemantics => 2,        // Association
        TableId::MethodImpl => 0,             // Class
        TableId::ImplMap => 1,                // MemberForwarded
        TableId::FieldRva => 1,               // Field
        TableId::NestedClass => 0,            // NestedClass
        TableId::GenericParam => 2,           // Owner
        TableId::GenericParamConstraint => 0, // Owner
        TableId::LocalScope => 0,             // Method
        TableId::StateMachineMethod => 0,     // MoveNextMethod
        TableId::CustomDebugInformation => 0, // Parent
        _ => return None,
    })
}

/// The coded index kind of a sorted table key column, when it is coded.
const fn sort_key_coded(table: TableId) -> Option<CodedIndex> {
    Some(match table {
        TableId::Constant => CodedIndex::HasConstant,
        TableId::CustomAttribute => CodedIndex::HasCustomAttribute,
        TableId::FieldMarshal => CodedIndex::HasFieldMarshal,
        TableId::DeclSecurity => CodedIndex::HasDeclSecurity,
        TableId::MethodSemantics => CodedIndex::HasSemantics,
        TableId::ImplMap => CodedIndex::MemberForwarded,
        TableId::GenericParam => CodedIndex::TypeOrMethodDef,
        TableId::CustomDebugInformation => CodedIndex::HasCustomDebugInformation,
        _ => return None,
    })
}

impl<'a> Tables<'a> {
    /// The column this table is sorted by, or `None` when it has no sort key.
    ///
    /// See the free function [`sort_key_column`].
    pub const fn sort_key_column(&self, table: TableId) -> Option<usize> {
        sort_key_column(table)
    }

    /// The RIDs of every row of `table` whose sort key column equals `key`.
    ///
    /// `key` is the raw column value: for a coded key column that is the
    /// encoded tag-and-RID value, which [`Tables::sort_key_for`] computes.
    pub fn rows_with_key(&self, table: TableId, key: u32) -> Result<Vec<u32>> {
        let column = sort_key_column(table)
            .ok_or(Error::detached(ErrorKind::Unsupported, "sorted lookup"))?;
        let count = self.row_count(table);
        let mut out = Vec::new();
        if count == 0 {
            return Ok(out);
        }
        if self.is_sorted(table) {
            let mut lo = 1u32;
            let mut hi = count + 1;
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if self.raw_column(table, mid, column)? < key {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            let mut rid = lo;
            while rid <= count && self.raw_column(table, rid, column)? == key {
                out.push(rid);
                rid += 1;
            }
        } else {
            for rid in 1..=count {
                if self.raw_column(table, rid, column)? == key {
                    out.push(rid);
                }
            }
        }
        Ok(out)
    }

    /// The first row of `table` whose sort key equals `key`.
    pub fn first_row_with_key(&self, table: TableId, key: u32) -> Result<Option<u32>> {
        Ok(self.rows_with_key(table, key)?.first().copied())
    }

    /// Encodes `parent` as the raw sort key of `table`.
    ///
    /// Returns `None` when `table` cannot be keyed by that token, for example
    /// a `TypeRef` parent on a table keyed by `MemberForwarded`.
    pub fn sort_key_for(&self, table: TableId, parent: Token) -> Option<u32> {
        match sort_key_coded(table) {
            Some(kind) => kind.encode(parent),
            None => Some(parent.rid()),
        }
    }

    /// The RIDs of every row of `table` owned by `parent`.
    pub fn rows_for_parent(&self, table: TableId, parent: Token) -> Result<Vec<u32>> {
        match self.sort_key_for(table, parent) {
            Some(key) => self.rows_with_key(table, key),
            None => Ok(Vec::new()),
        }
    }

    /// The half-open RID range a list column describes.
    ///
    /// `column` is the index of the list column in `owner_table`, and `target`
    /// is the table the column indexes. The run ends where the next owner run
    /// begins, or at the end of the target table for the last owner.
    pub fn list_range(
        &self,
        owner_table: TableId,
        owner_rid: u32,
        column: usize,
        target: TableId,
    ) -> Result<Range<u32>> {
        let count = self.row_count(owner_table);
        if owner_rid == 0 || owner_rid > count {
            return Err(Error::detached(ErrorKind::OutOfRange, owner_table.name()));
        }
        let limit = self.logical_row_count(target).saturating_add(1);
        let start = self.raw_column(owner_table, owner_rid, column)?.clamp(1, limit);
        let end = if owner_rid == count {
            limit
        } else {
            self.raw_column(owner_table, owner_rid + 1, column)?.clamp(1, limit)
        };
        Ok(start..end.max(start))
    }

    /// The owner of a member addressed by a list column, if any.
    fn owner_of_list(
        &self,
        owner_table: TableId,
        column: usize,
        target: TableId,
        member_rid: u32,
    ) -> Result<Option<u32>> {
        let count = self.row_count(owner_table);
        if count == 0 || member_rid == 0 {
            return Ok(None);
        }
        // List columns are non-decreasing in a well-formed image, so find the
        // last owner whose run starts at or before the member.
        let mut lo = 1u32;
        let mut hi = count;
        let mut candidate = 0u32;
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            if self.raw_column(owner_table, mid, column)? <= member_rid {
                candidate = mid;
                lo = mid + 1;
            } else if mid == 1 {
                break;
            } else {
                hi = mid - 1;
            }
        }
        if candidate != 0 {
            let range = self.list_range(owner_table, candidate, column, target)?;
            if range.contains(&member_rid) {
                return Ok(Some(candidate));
            }
        }
        // The column was not monotonic; scan.
        for rid in 1..=count {
            if self.list_range(owner_table, rid, column, target)?.contains(&member_rid) {
                return Ok(Some(rid));
            }
        }
        Ok(None)
    }

    /// The logical `Field` RIDs owned by a type (II.22.37, `FieldList`).
    pub fn field_range(&self, type_def: Rid<marker::TypeDef>) -> Result<Range<u32>> {
        self.list_range(TableId::TypeDef, type_def.get(), 4, TableId::Field)
    }

    /// The logical `MethodDef` RIDs owned by a type (II.22.37, `MethodList`).
    pub fn method_range(&self, type_def: Rid<marker::TypeDef>) -> Result<Range<u32>> {
        self.list_range(TableId::TypeDef, type_def.get(), 5, TableId::MethodDef)
    }

    /// The logical `Param` RIDs owned by a method (II.22.26, `ParamList`).
    pub fn param_range(&self, method: Rid<marker::MethodDef>) -> Result<Range<u32>> {
        self.list_range(TableId::MethodDef, method.get(), 5, TableId::Param)
    }

    /// The logical `Event` RIDs owned by an `EventMap` row.
    pub fn event_range(&self, event_map: Rid<marker::EventMap>) -> Result<Range<u32>> {
        self.list_range(TableId::EventMap, event_map.get(), 1, TableId::Event)
    }

    /// The logical `Property` RIDs owned by a `PropertyMap` row.
    pub fn property_range(&self, property_map: Rid<marker::PropertyMap>) -> Result<Range<u32>> {
        self.list_range(TableId::PropertyMap, property_map.get(), 1, TableId::Property)
    }

    /// The type that owns a field.
    pub fn type_of_field(&self, field: Rid<marker::Field>) -> Result<Option<Rid<marker::TypeDef>>> {
        Ok(self.owner_of_list(TableId::TypeDef, 4, TableId::Field, field.get())?.map(Rid::new))
    }

    /// The type that owns a method.
    pub fn type_of_method(
        &self,
        method: Rid<marker::MethodDef>,
    ) -> Result<Option<Rid<marker::TypeDef>>> {
        Ok(self.owner_of_list(TableId::TypeDef, 5, TableId::MethodDef, method.get())?.map(Rid::new))
    }

    /// The method that owns a parameter row.
    pub fn method_of_param(
        &self,
        param: Rid<marker::Param>,
    ) -> Result<Option<Rid<marker::MethodDef>>> {
        Ok(self.owner_of_list(TableId::MethodDef, 5, TableId::Param, param.get())?.map(Rid::new))
    }

    /// The `EventMap` row for a type.
    pub fn event_map_of(
        &self,
        type_def: Rid<marker::TypeDef>,
    ) -> Result<Option<Rid<marker::EventMap>>> {
        Ok(self.first_row_with_key(TableId::EventMap, type_def.get())?.map(Rid::new))
    }

    /// The `PropertyMap` row for a type.
    pub fn property_map_of(
        &self,
        type_def: Rid<marker::TypeDef>,
    ) -> Result<Option<Rid<marker::PropertyMap>>> {
        Ok(self.first_row_with_key(TableId::PropertyMap, type_def.get())?.map(Rid::new))
    }

    /// The `GenericParam` RIDs declared by a type or method, in declaration order.
    pub fn generic_params(&self, owner: Token) -> Result<Vec<u32>> {
        let mut rids = self.rows_for_parent(TableId::GenericParam, owner)?;
        // `Number` orders the run; the spec requires it but obfuscators do not.
        let mut keyed = Vec::with_capacity(rids.len());
        for rid in rids.drain(..) {
            keyed.push((self.raw_column(TableId::GenericParam, rid, 0)?, rid));
        }
        keyed.sort_unstable();
        Ok(keyed.into_iter().map(|(_, rid)| rid).collect())
    }

    /// The `GenericParamConstraint` RIDs for one generic parameter.
    pub fn generic_param_constraints(
        &self,
        generic_param: Rid<marker::GenericParam>,
    ) -> Result<Vec<u32>> {
        self.rows_with_key(TableId::GenericParamConstraint, generic_param.get())
    }

    /// The type that lexically encloses a nested type.
    pub fn enclosing_type(
        &self,
        type_def: Rid<marker::TypeDef>,
    ) -> Result<Option<Rid<marker::TypeDef>>> {
        match self.first_row_with_key(TableId::NestedClass, type_def.get())? {
            Some(rid) => Ok(Some(Rid::new(self.raw_column(TableId::NestedClass, rid, 1)?))),
            None => Ok(None),
        }
    }

    /// The types nested directly inside a type.
    ///
    /// `NestedClass` is sorted by the nested type, not the enclosing one, so
    /// this is always a linear scan.
    pub fn nested_types(&self, type_def: Rid<marker::TypeDef>) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        for rid in 1..=self.row_count(TableId::NestedClass) {
            if self.raw_column(TableId::NestedClass, rid, 1)? == type_def.get() {
                out.push(self.raw_column(TableId::NestedClass, rid, 0)?);
            }
        }
        Ok(out)
    }

    /// The `CustomAttribute` RIDs attached to a metadata item.
    pub fn custom_attributes(&self, parent: Token) -> Result<Vec<u32>> {
        self.rows_for_parent(TableId::CustomAttribute, parent)
    }

    /// The `InterfaceImpl` RIDs of a type.
    pub fn interface_impls(&self, type_def: Rid<marker::TypeDef>) -> Result<Vec<u32>> {
        self.rows_with_key(TableId::InterfaceImpl, type_def.get())
    }

    /// The `MethodImpl` RIDs declared by a type.
    pub fn method_impls(&self, type_def: Rid<marker::TypeDef>) -> Result<Vec<u32>> {
        self.rows_with_key(TableId::MethodImpl, type_def.get())
    }

    /// The `MethodSemantics` RIDs attached to an event or property.
    pub fn semantics_for(&self, association: Token) -> Result<Vec<u32>> {
        self.rows_for_parent(TableId::MethodSemantics, association)
    }

    /// The `DeclSecurity` RIDs attached to an item.
    pub fn decl_security_for(&self, parent: Token) -> Result<Vec<u32>> {
        self.rows_for_parent(TableId::DeclSecurity, parent)
    }

    /// The compile-time constant of a field, parameter or property.
    pub fn constant_of(&self, parent: Token) -> Result<Option<ConstantRow>> {
        match self.sort_key_for(TableId::Constant, parent) {
            Some(key) => match self.first_row_with_key(TableId::Constant, key)? {
                Some(rid) => Ok(Some(self.constant_row(rid)?)),
                None => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// The marshalling descriptor blob index of a field or parameter.
    pub fn field_marshal_of(&self, parent: Token) -> Result<Option<u32>> {
        match self.sort_key_for(TableId::FieldMarshal, parent) {
            Some(key) => match self.first_row_with_key(TableId::FieldMarshal, key)? {
                Some(rid) => Ok(Some(self.raw_column(TableId::FieldMarshal, rid, 1)?)),
                None => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// The RVA of a field initial-data blob, from `FieldRVA`.
    pub fn field_rva_of(&self, field: Rid<marker::Field>) -> Result<Option<u32>> {
        match self.first_row_with_key(TableId::FieldRva, field.get())? {
            Some(rid) => Ok(Some(self.raw_column(TableId::FieldRva, rid, 0)?)),
            None => Ok(None),
        }
    }

    /// The explicit byte offset of a field within its type, from `FieldLayout`.
    pub fn field_layout_of(&self, field: Rid<marker::Field>) -> Result<Option<u32>> {
        match self.first_row_with_key(TableId::FieldLayout, field.get())? {
            Some(rid) => Ok(Some(self.raw_column(TableId::FieldLayout, rid, 0)?)),
            None => Ok(None),
        }
    }

    /// The `ClassLayout` row of a type, when it declares one.
    pub fn class_layout_of(
        &self,
        type_def: Rid<marker::TypeDef>,
    ) -> Result<Option<ClassLayoutRow>> {
        match self.first_row_with_key(TableId::ClassLayout, type_def.get())? {
            Some(rid) => Ok(Some(self.class_layout_row(rid)?)),
            None => Ok(None),
        }
    }

    /// The P/Invoke mapping of a method or field, when it has one.
    pub fn impl_map_of(&self, member: Token) -> Result<Option<ImplMapRow>> {
        match self.sort_key_for(TableId::ImplMap, member) {
            Some(key) => match self.first_row_with_key(TableId::ImplMap, key)? {
                Some(rid) => Ok(Some(self.impl_map_row(rid)?)),
                None => Ok(None),
            },
            None => Ok(None),
        }
    }

    fn constant_row(&self, rid: u32) -> Result<ConstantRow> {
        self.row::<ConstantRow>(rid)
    }

    fn class_layout_row(&self, rid: u32) -> Result<ClassLayoutRow> {
        self.row::<ClassLayoutRow>(rid)
    }

    fn impl_map_row(&self, rid: u32) -> Result<ImplMapRow> {
        self.row::<ImplMapRow>(rid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::TableRow;

    #[test]
    fn sort_key_columns_are_within_the_table() {
        for &id in TableId::ALL {
            if let Some(column) = sort_key_column(id) {
                assert!(
                    column < crate::tables::columns_of(id).len(),
                    "{} key column {} is out of range",
                    id.name(),
                    column
                );
            }
        }
    }

    #[test]
    fn coded_sort_keys_match_the_declared_column() {
        for &id in TableId::ALL {
            let (Some(column), Some(kind)) = (sort_key_column(id), sort_key_coded(id)) else {
                continue;
            };
            assert_eq!(
                crate::tables::columns_of(id)[column],
                crate::tables::ColumnKind::Coded(kind),
                "{} key column kind mismatch",
                id.name()
            );
        }
    }

    #[test]
    fn non_coded_sort_keys_are_simple_indices() {
        for &id in TableId::ALL {
            let Some(column) = sort_key_column(id) else { continue };
            if sort_key_coded(id).is_some() {
                continue;
            }
            assert!(
                matches!(crate::tables::columns_of(id)[column], crate::tables::ColumnKind::Rid(_)),
                "{} key column is neither coded nor a RID",
                id.name()
            );
        }
    }

    #[test]
    fn list_column_indices_match_the_row_layout() {
        use crate::tables::ColumnKind::Rid as R;
        let type_def = <crate::tables::TypeDefRow as TableRow>::COLUMNS;
        assert_eq!(type_def[4], R(TableId::Field));
        assert_eq!(type_def[5], R(TableId::MethodDef));
        let method = <crate::tables::MethodDefRow as TableRow>::COLUMNS;
        assert_eq!(method[5], R(TableId::Param));
        let event_map = <crate::tables::EventMapRow as TableRow>::COLUMNS;
        assert_eq!(event_map[1], R(TableId::Event));
        let property_map = <crate::tables::PropertyMapRow as TableRow>::COLUMNS;
        assert_eq!(property_map[1], R(TableId::Property));
    }
}
