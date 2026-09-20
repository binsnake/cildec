//! The metadata table stream: `#~` (compressed) and `#-` (uncompressed).
//!
//! Row sizes and column widths are computed from the stream header exactly as
//! ECMA-335 II.24.2.6 describes: heap indices are 2 or 4 bytes according to the
//! `HeapSizes` bits, a simple index is 2 bytes when its target table has fewer
//! than 2^16 rows, and a coded index is 2 bytes when the largest table it can
//! tag has fewer than 2^(16 - tag bits) rows.
//!
//! Nothing in this module copies row data. [`Tables`] stores one [`TableLayout`]
//! per table id and decodes a row on demand from the borrowed stream bytes.

pub mod coded;
mod lookup;
mod rows;

pub use coded::CodedIndex;
pub use lookup::sort_key_column;
pub use rows::*;

use alloc::vec::Vec;

use crate::error::{Diagnostic, DiagnosticCode, Error, ErrorKind, Result, Strictness};
use crate::reader::{Reader, read_uint_at};
use crate::token::{TableId, Token};

const CTX: &str = "table stream";

/// The largest number of columns any table has (`Assembly` and `AssemblyRef`).
pub const MAX_COLUMNS: usize = 9;

/// The number of table id slots; ids are one byte and the high bit is unused.
const TABLE_SLOTS: usize = 64;

/// What one column of a table holds.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ColumnKind {
    /// A 2-byte constant.
    U16,
    /// A 4-byte constant.
    U32,
    /// An index into `#Strings`.
    String,
    /// An index into `#Blob`.
    Blob,
    /// An index into `#GUID`.
    Guid,
    /// A simple index into another table.
    Rid(TableId),
    /// A coded index.
    Coded(CodedIndex),
}

/// The computed geometry of one table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TableLayout {
    /// The number of rows, after any clamping applied while parsing.
    pub row_count: u32,
    /// The size of one row in bytes.
    pub row_size: u16,
    /// The number of columns.
    pub column_count: u8,
    /// Byte offset of each column within a row.
    pub column_offsets: [u8; MAX_COLUMNS],
    /// Byte width of each column.
    pub column_widths: [u8; MAX_COLUMNS],
    /// Offset of the first row within the table stream.
    pub data_offset: usize,
}

impl Default for TableLayout {
    fn default() -> Self {
        TableLayout {
            row_count: 0,
            row_size: 0,
            column_count: 0,
            column_offsets: [0; MAX_COLUMNS],
            column_widths: [0; MAX_COLUMNS],
            data_offset: 0,
        }
    }
}

impl TableLayout {
    /// The total size of the table in bytes.
    pub const fn byte_size(&self) -> usize {
        (self.row_count as usize) * (self.row_size as usize)
    }
}

/// A cursor that walks the columns of one row.
///
/// Columns must be read in declaration order; each read advances to the next
/// column using the widths computed for the image.
#[derive(Debug)]
pub struct RowCursor<'a> {
    bytes: &'a [u8],
    layout: TableLayout,
    column: usize,
    base: usize,
}

impl RowCursor<'_> {
    /// Reads the next column as a zero-extended unsigned value.
    pub fn uint(&mut self) -> Result<u32> {
        let index = self.column;
        if index >= self.layout.column_count as usize {
            return Err(Error::new(ErrorKind::Malformed, self.base, "table row"));
        }
        let offset = self.layout.column_offsets[index] as usize;
        let width = self.layout.column_widths[index];
        self.column += 1;
        read_uint_at(self.bytes, offset, width).ok_or(Error::new(
            ErrorKind::Truncated,
            self.base.saturating_add(offset),
            "table row",
        ))
    }

    /// Reads the next column and decodes it as a coded index.
    pub fn coded(&mut self, kind: CodedIndex) -> Result<Token> {
        let offset = self.layout.column_offsets.get(self.column).copied().unwrap_or(0) as usize;
        let value = self.uint()?;
        kind.decode(value, self.base.saturating_add(offset))
    }
}

/// A metadata table row that can be decoded from a [`RowCursor`].
pub trait TableRow: Copy + Sized {
    /// The table this row belongs to.
    const TABLE: TableId;
    /// The column layout of the table, in declaration order.
    const COLUMNS: &'static [ColumnKind];

    /// Decodes one row, consuming every column in order.
    fn decode(cursor: &mut RowCursor<'_>) -> Result<Self>;
}

/// The parsed `#~` or `#-` stream.
#[derive(Clone, Debug)]
pub struct Tables<'a> {
    data: &'a [u8],
    base: usize,
    major_version: u8,
    minor_version: u8,
    heap_sizes: u8,
    valid: u64,
    declared_sorted: u64,
    verified_sorted: u64,
    uncompressed: bool,
    extra_data: Option<u32>,
    layouts: [TableLayout; TABLE_SLOTS],
}

impl<'a> Tables<'a> {
    /// An empty table stream, used when an image has no `#~` or `#-`.
    pub fn empty() -> Self {
        Tables {
            data: &[],
            base: 0,
            major_version: 2,
            minor_version: 0,
            heap_sizes: 0,
            valid: 0,
            declared_sorted: 0,
            verified_sorted: !0,
            uncompressed: false,
            extra_data: None,
            layouts: [TableLayout::default(); TABLE_SLOTS],
        }
    }

    /// Parses a table stream.
    ///
    /// `base` is the absolute offset of `data` in the input, used for error and
    /// diagnostic offsets. `uncompressed` selects `#-` semantics, which only
    /// affects how the stream is reported; the binary layout is identical.
    pub fn parse(
        data: &'a [u8],
        base: usize,
        uncompressed: bool,
        strictness: Strictness,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<Self> {
        let mut r = Reader::new(data, base, CTX);
        let _reserved = r.u32()?;
        let major_version = r.u8()?;
        let minor_version = r.u8()?;
        let heap_sizes = r.u8()?;
        let _reserved2 = r.u8()?;
        let valid = r.u64()?;
        let declared_sorted = r.u64()?;

        const KNOWN_HEAP_BITS: u8 = 0x01 | 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;
        if heap_sizes & !KNOWN_HEAP_BITS != 0 {
            if strictness.is_strict() {
                return Err(Error::new(ErrorKind::Malformed, base + 6, CTX));
            }
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::UnknownHeapSizeBits,
                base + 6,
                u64::from(heap_sizes),
            ));
        }

        // Row counts: one u32 per set bit of `Valid`, in ascending table order.
        let mut row_counts = [0u32; TABLE_SLOTS];
        for (slot, count_slot) in row_counts.iter_mut().enumerate() {
            if valid & (1u64 << slot) == 0 {
                continue;
            }
            let at = r.absolute();
            let count = r.u32()?;
            match TableId::from_u8(slot as u8) {
                Some(_) => *count_slot = count,
                None => {
                    if count != 0 || strictness.is_strict() {
                        return Err(Error::new(ErrorKind::Unsupported, at, CTX));
                    }
                    diagnostics.push(Diagnostic::new(
                        DiagnosticCode::ReservedTablePresent,
                        at,
                        slot as u64,
                    ));
                }
            }
        }

        let extra_data = if heap_sizes & 0x40 != 0 { Some(r.u32()?) } else { None };

        let strings_wide = heap_sizes & 0x01 != 0;
        let guids_wide = heap_sizes & 0x02 != 0;
        let blobs_wide = heap_sizes & 0x04 != 0;

        let mut layouts = [TableLayout::default(); TABLE_SLOTS];
        let mut cursor = r.position();
        let mut exhausted = false;
        for &id in TableId::ALL {
            let slot = id.to_u8() as usize;
            let mut count = row_counts[slot];
            let columns = columns_of(id);
            let mut layout = TableLayout {
                row_count: 0,
                row_size: 0,
                column_count: columns.len() as u8,
                column_offsets: [0; MAX_COLUMNS],
                column_widths: [0; MAX_COLUMNS],
                data_offset: cursor,
            };
            let mut offset = 0u16;
            for (i, kind) in columns.iter().enumerate() {
                let width = column_width(*kind, &row_counts, strings_wide, guids_wide, blobs_wide);
                layout.column_offsets[i] = offset as u8;
                layout.column_widths[i] = width;
                offset += u16::from(width);
            }
            layout.row_size = offset;

            if count > 0 {
                let available = data.len().saturating_sub(cursor);
                let needed = (count as u64) * u64::from(layout.row_size);
                if exhausted || needed > available as u64 {
                    if strictness.is_strict() {
                        return Err(Error::new(ErrorKind::Truncated, base + cursor, CTX));
                    }
                    diagnostics.push(Diagnostic::new(
                        DiagnosticCode::StreamRangeClamped,
                        base + cursor,
                        needed,
                    ));
                    count = if layout.row_size == 0 {
                        0
                    } else {
                        (available / layout.row_size as usize) as u32
                    };
                    exhausted = true;
                }
            }
            layout.row_count = count;
            cursor = cursor.saturating_add(layout.byte_size());
            layouts[slot] = layout;
        }

        let mut tables = Tables {
            data,
            base,
            major_version,
            minor_version,
            heap_sizes,
            valid,
            declared_sorted,
            verified_sorted: 0,
            uncompressed,
            extra_data,
            layouts,
        };
        tables.verified_sorted = tables.verify_sortedness(strictness, diagnostics)?;
        Ok(tables)
    }

    /// The raw stream bytes.
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The absolute offset of the stream in the parsed input.
    pub const fn base(&self) -> usize {
        self.base
    }

    /// The stream schema major version, normally 2.
    pub const fn major_version(&self) -> u8 {
        self.major_version
    }

    /// The stream schema minor version, normally 0.
    pub const fn minor_version(&self) -> u8 {
        self.minor_version
    }

    /// The raw `HeapSizes` byte.
    pub const fn heap_sizes(&self) -> u8 {
        self.heap_sizes
    }

    /// True when `#Strings` indices are 4 bytes wide.
    pub const fn strings_wide(&self) -> bool {
        self.heap_sizes & 0x01 != 0
    }

    /// True when `#GUID` indices are 4 bytes wide.
    pub const fn guids_wide(&self) -> bool {
        self.heap_sizes & 0x02 != 0
    }

    /// True when `#Blob` indices are 4 bytes wide.
    pub const fn blobs_wide(&self) -> bool {
        self.heap_sizes & 0x04 != 0
    }

    /// True when the stream was `#-` rather than `#~`.
    pub const fn is_uncompressed(&self) -> bool {
        self.uncompressed
    }

    /// The extra 4 bytes present when `HeapSizes` bit `0x40` is set.
    pub const fn extra_data(&self) -> Option<u32> {
        self.extra_data
    }

    /// The raw `Valid` bitvector.
    pub const fn valid_bits(&self) -> u64 {
        self.valid
    }

    /// The raw `Sorted` bitvector.
    pub const fn sorted_bits(&self) -> u64 {
        self.declared_sorted
    }

    /// True when the `Valid` bitvector marks this table present.
    pub const fn is_present(&self, table: TableId) -> bool {
        self.valid & (1u64 << table.to_u8()) != 0
    }

    /// True when the `Sorted` bitvector marks this table sorted.
    pub const fn is_declared_sorted(&self, table: TableId) -> bool {
        self.declared_sorted & (1u64 << table.to_u8()) != 0
    }

    /// True when this table has a sort key and its rows really are ordered.
    ///
    /// Lookups fall back to a linear scan when this is false, so results stay
    /// correct on images whose `Sorted` bitvector lies.
    pub const fn is_sorted(&self, table: TableId) -> bool {
        self.verified_sorted & (1u64 << table.to_u8()) != 0
    }

    /// The number of rows in a table.
    pub const fn row_count(&self, table: TableId) -> u32 {
        self.layouts[table.to_u8() as usize].row_count
    }

    /// The number of logically addressable rows, which is the `*Ptr` table row
    /// count when an indirection table is present.
    pub fn logical_row_count(&self, table: TableId) -> u32 {
        match table.ptr_source() {
            Some(ptr) if self.row_count(ptr) > 0 => self.row_count(ptr),
            _ => self.row_count(table),
        }
    }

    /// The computed layout of a table.
    pub const fn layout(&self, table: TableId) -> &TableLayout {
        &self.layouts[table.to_u8() as usize]
    }

    /// The bytes of one row, by 1-based RID.
    pub fn row_bytes(&self, table: TableId, rid: u32) -> Result<&'a [u8]> {
        let layout = self.layout(table);
        if rid == 0 || rid > layout.row_count {
            return Err(Error::new(ErrorKind::OutOfRange, self.base, table.name()));
        }
        let start = layout.data_offset + (rid as usize - 1) * layout.row_size as usize;
        let end = start + layout.row_size as usize;
        self.data.get(start..end).ok_or(Error::new(
            ErrorKind::Truncated,
            self.base.saturating_add(start),
            table.name(),
        ))
    }

    /// Decodes one row without applying any `*Ptr` indirection.
    pub fn row<R: TableRow>(&self, rid: u32) -> Result<R> {
        let layout = *self.layout(R::TABLE);
        let bytes = self.row_bytes(R::TABLE, rid)?;
        let start = layout.data_offset + (rid as usize - 1) * layout.row_size as usize;
        let mut cursor =
            RowCursor { bytes, layout, column: 0, base: self.base.saturating_add(start) };
        R::decode(&mut cursor)
    }

    /// Decodes one row, following the `*Ptr` indirection when present.
    pub fn row_indirect<R: TableRow>(&self, rid: u32) -> Result<R> {
        let physical = self.resolve_indirection(R::TABLE, rid)?;
        self.row::<R>(physical)
    }

    /// Maps a logical RID through the matching `*Ptr` table, if there is one.
    pub fn resolve_indirection(&self, table: TableId, rid: u32) -> Result<u32> {
        let Some(ptr) = table.ptr_source() else { return Ok(rid) };
        if self.row_count(ptr) == 0 {
            return Ok(rid);
        }
        Ok(match ptr {
            TableId::FieldPtr => self.row::<FieldPtrRow>(rid)?.field.get(),
            TableId::MethodPtr => self.row::<MethodPtrRow>(rid)?.method.get(),
            TableId::ParamPtr => self.row::<ParamPtrRow>(rid)?.param.get(),
            TableId::EventPtr => self.row::<EventPtrRow>(rid)?.event.get(),
            TableId::PropertyPtr => self.row::<PropertyPtrRow>(rid)?.property.get(),
            _ => rid,
        })
    }

    /// Reads one raw column value of a row, without decoding it.
    pub fn raw_column(&self, table: TableId, rid: u32, column: usize) -> Result<u32> {
        let layout = self.layout(table);
        if column >= layout.column_count as usize {
            return Err(Error::new(ErrorKind::OutOfRange, self.base, table.name()));
        }
        let bytes = self.row_bytes(table, rid)?;
        read_uint_at(bytes, layout.column_offsets[column] as usize, layout.column_widths[column])
            .ok_or(Error::new(ErrorKind::Truncated, self.base, table.name()))
    }

    /// Iterates every row of a table in RID order, without indirection.
    pub fn iter<R: TableRow>(&self) -> RowIter<'_, 'a, R> {
        RowIter {
            tables: self,
            rid: 1,
            end: self.row_count(R::TABLE) + 1,
            _row: core::marker::PhantomData,
        }
    }

    /// Iterates every logical row of a table, applying `*Ptr` indirection.
    pub fn iter_indirect<R: TableRow>(&self) -> IndirectRowIter<'_, 'a, R> {
        IndirectRowIter {
            tables: self,
            rid: 1,
            end: self.logical_row_count(R::TABLE) + 1,
            _row: core::marker::PhantomData,
        }
    }

    fn verify_sortedness(
        &self,
        strictness: Strictness,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<u64> {
        let mut bits = 0u64;
        for &id in TableId::ALL {
            let Some(column) = lookup::sort_key_column(id) else { continue };
            let count = self.row_count(id);
            if count <= 1 {
                bits |= 1u64 << id.to_u8();
                continue;
            }
            let mut sorted = true;
            let mut previous = self.raw_column(id, 1, column)?;
            for rid in 2..=count {
                let value = self.raw_column(id, rid, column)?;
                if value < previous {
                    sorted = false;
                    break;
                }
                previous = value;
            }
            if sorted {
                bits |= 1u64 << id.to_u8();
            } else {
                if strictness.is_strict() && self.is_declared_sorted(id) {
                    return Err(Error::new(ErrorKind::Malformed, self.base, id.name()));
                }
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::TableNotSorted,
                    self.base,
                    u64::from(id.to_u8()),
                ));
            }
        }
        Ok(bits)
    }
}

/// Iterator over the rows of one table; see [`Tables::iter`].
#[derive(Debug)]
pub struct RowIter<'t, 'a, R> {
    tables: &'t Tables<'a>,
    rid: u32,
    end: u32,
    _row: core::marker::PhantomData<fn() -> R>,
}

impl<R: TableRow> Iterator for RowIter<'_, '_, R> {
    type Item = (u32, Result<R>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rid >= self.end {
            return None;
        }
        let rid = self.rid;
        self.rid += 1;
        Some((rid, self.tables.row::<R>(rid)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = (self.end - self.rid) as usize;
        (n, Some(n))
    }
}

impl<R: TableRow> ExactSizeIterator for RowIter<'_, '_, R> {}

/// Iterator over the logical rows of one table; see [`Tables::iter_indirect`].
#[derive(Debug)]
pub struct IndirectRowIter<'t, 'a, R> {
    tables: &'t Tables<'a>,
    rid: u32,
    end: u32,
    _row: core::marker::PhantomData<fn() -> R>,
}

impl<R: TableRow> Iterator for IndirectRowIter<'_, '_, R> {
    type Item = (u32, Result<R>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rid >= self.end {
            return None;
        }
        let rid = self.rid;
        self.rid += 1;
        Some((rid, self.tables.row_indirect::<R>(rid)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = (self.end - self.rid) as usize;
        (n, Some(n))
    }
}

impl<R: TableRow> ExactSizeIterator for IndirectRowIter<'_, '_, R> {}

fn column_width(
    kind: ColumnKind,
    row_counts: &[u32; TABLE_SLOTS],
    strings_wide: bool,
    guids_wide: bool,
    blobs_wide: bool,
) -> u8 {
    match kind {
        ColumnKind::U16 => 2,
        ColumnKind::U32 => 4,
        ColumnKind::String => {
            if strings_wide {
                4
            } else {
                2
            }
        }
        ColumnKind::Guid => {
            if guids_wide {
                4
            } else {
                2
            }
        }
        ColumnKind::Blob => {
            if blobs_wide {
                4
            } else {
                2
            }
        }
        ColumnKind::Rid(target) => {
            // A list column addresses the `*Ptr` table when one is present, and
            // both tables must be reachable, so take the larger row count.
            let mut rows = row_counts[target.to_u8() as usize];
            if let Some(ptr) = target.ptr_source() {
                rows = rows.max(row_counts[ptr.to_u8() as usize]);
            }
            if rows < 0x1_0000 { 2 } else { 4 }
        }
        ColumnKind::Coded(coded) => {
            let mut max = 0u32;
            for table in coded.tables().iter().flatten() {
                max = max.max(row_counts[table.to_u8() as usize]);
            }
            coded.column_width(max)
        }
    }
}

/// The column layout of a table id, from its row type.
pub fn columns_of(table: TableId) -> &'static [ColumnKind] {
    macro_rules! arm {
        ($($id:ident => $row:ident),* $(,)?) => {
            match table {
                $( TableId::$id => <$row as TableRow>::COLUMNS, )*
            }
        };
    }
    arm! {
        Module => ModuleRow,
        TypeRef => TypeRefRow,
        TypeDef => TypeDefRow,
        FieldPtr => FieldPtrRow,
        Field => FieldRow,
        MethodPtr => MethodPtrRow,
        MethodDef => MethodDefRow,
        ParamPtr => ParamPtrRow,
        Param => ParamRow,
        InterfaceImpl => InterfaceImplRow,
        MemberRef => MemberRefRow,
        Constant => ConstantRow,
        CustomAttribute => CustomAttributeRow,
        FieldMarshal => FieldMarshalRow,
        DeclSecurity => DeclSecurityRow,
        ClassLayout => ClassLayoutRow,
        FieldLayout => FieldLayoutRow,
        StandAloneSig => StandAloneSigRow,
        EventMap => EventMapRow,
        EventPtr => EventPtrRow,
        Event => EventRow,
        PropertyMap => PropertyMapRow,
        PropertyPtr => PropertyPtrRow,
        Property => PropertyRow,
        MethodSemantics => MethodSemanticsRow,
        MethodImpl => MethodImplRow,
        ModuleRef => ModuleRefRow,
        TypeSpec => TypeSpecRow,
        ImplMap => ImplMapRow,
        FieldRva => FieldRvaRow,
        EncLog => EncLogRow,
        EncMap => EncMapRow,
        Assembly => AssemblyRow,
        AssemblyProcessor => AssemblyProcessorRow,
        AssemblyOs => AssemblyOsRow,
        AssemblyRef => AssemblyRefRow,
        AssemblyRefProcessor => AssemblyRefProcessorRow,
        AssemblyRefOs => AssemblyRefOsRow,
        File => FileRow,
        ExportedType => ExportedTypeRow,
        ManifestResource => ManifestResourceRow,
        NestedClass => NestedClassRow,
        GenericParam => GenericParamRow,
        MethodSpec => MethodSpecRow,
        GenericParamConstraint => GenericParamConstraintRow,
        Document => DocumentRow,
        MethodDebugInformation => MethodDebugInformationRow,
        LocalScope => LocalScopeRow,
        LocalVariable => LocalVariableRow,
        LocalConstant => LocalConstantRow,
        ImportScope => ImportScopeRow,
        StateMachineMethod => StateMachineMethodRow,
        CustomDebugInformation => CustomDebugInformationRow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_has_at_most_max_columns() {
        for &id in TableId::ALL {
            let columns = columns_of(id);
            assert!(!columns.is_empty(), "{} has no columns", id.name());
            assert!(columns.len() <= MAX_COLUMNS, "{} has {} columns", id.name(), columns.len());
        }
    }

    #[test]
    fn simple_index_width_switches_at_65536_rows() {
        let mut counts = [0u32; TABLE_SLOTS];
        let kind = ColumnKind::Rid(TableId::TypeDef);
        counts[TableId::TypeDef.to_u8() as usize] = 0xFFFF;
        assert_eq!(column_width(kind, &counts, false, false, false), 2);
        counts[TableId::TypeDef.to_u8() as usize] = 0x1_0000;
        assert_eq!(column_width(kind, &counts, false, false, false), 4);
    }

    #[test]
    fn list_column_width_accounts_for_the_ptr_table() {
        let mut counts = [0u32; TABLE_SLOTS];
        let kind = ColumnKind::Rid(TableId::Field);
        counts[TableId::Field.to_u8() as usize] = 10;
        counts[TableId::FieldPtr.to_u8() as usize] = 0x1_0000;
        assert_eq!(column_width(kind, &counts, false, false, false), 4);
    }

    #[test]
    fn heap_index_widths_follow_heap_sizes() {
        let counts = [0u32; TABLE_SLOTS];
        for bits in 0u8..8 {
            let s = bits & 1 != 0;
            let g = bits & 2 != 0;
            let b = bits & 4 != 0;
            assert_eq!(column_width(ColumnKind::String, &counts, s, g, b), if s { 4 } else { 2 });
            assert_eq!(column_width(ColumnKind::Guid, &counts, s, g, b), if g { 4 } else { 2 });
            assert_eq!(column_width(ColumnKind::Blob, &counts, s, g, b), if b { 4 } else { 2 });
        }
    }

    #[test]
    fn coded_index_width_uses_the_largest_tagged_table() {
        let mut counts = [0u32; TABLE_SLOTS];
        let kind = ColumnKind::Coded(CodedIndex::TypeDefOrRef);
        counts[TableId::TypeSpec.to_u8() as usize] = 0x3FFF;
        assert_eq!(column_width(kind, &counts, false, false, false), 2);
        counts[TableId::TypeSpec.to_u8() as usize] = 0x4000;
        assert_eq!(column_width(kind, &counts, false, false, false), 4);
        // A table that is not tagged by this coded index has no effect.
        let mut counts = [0u32; TABLE_SLOTS];
        counts[TableId::Param.to_u8() as usize] = 0xFFFF;
        assert_eq!(column_width(kind, &counts, false, false, false), 2);
    }

    #[test]
    fn empty_stream_is_usable() {
        let tables = Tables::empty();
        assert_eq!(tables.row_count(TableId::TypeDef), 0);
        assert!(tables.row::<TypeDefRow>(1).is_err());
        assert_eq!(tables.iter::<TypeDefRow>().count(), 0);
    }
}
