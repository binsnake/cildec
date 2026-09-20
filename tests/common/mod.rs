//! A metadata builder for tests that need a shape no compiler produces.
//!
//! Rows are written out by hand, so every test that uses this is also a
//! statement about the on-disk layout: heap indices are 2 bytes wide because
//! `HeapSizes` is 0, and coded indices are 2 bytes wide because the tables are
//! small. A test that needs the 4-byte forms should say so explicitly rather
//! than grow this helper.

#![allow(dead_code)]

pub mod dump;
pub mod sources;

use cildec::TableId;

/// Builds a metadata region one table at a time.
pub struct MetadataBuilder {
    strings: Vec<u8>,
    blobs: Vec<u8>,
    rows: Vec<(TableId, u32, Vec<u8>)>,
    sorted: u64,
}

impl MetadataBuilder {
    pub fn new() -> Self {
        MetadataBuilder { strings: vec![0], blobs: vec![0], rows: Vec::new(), sorted: 0 }
    }

    /// Interns a `#Strings` entry and returns its 2-byte index.
    pub fn string(&mut self, value: &str) -> u16 {
        let index = self.strings.len() as u16;
        self.strings.extend_from_slice(value.as_bytes());
        self.strings.push(0);
        index
    }

    /// Interns a `#Blob` entry and returns its 2-byte index.
    ///
    /// Only lengths below 0x80 are supported, which keeps the prefix one byte.
    pub fn blob(&mut self, value: &[u8]) -> u16 {
        assert!(value.len() < 0x80, "the builder writes one-byte blob lengths");
        let index = self.blobs.len() as u16;
        self.blobs.push(value.len() as u8);
        self.blobs.extend_from_slice(value);
        index
    }

    /// Adds a table with its raw row bytes.
    pub fn table(&mut self, table: TableId, rows: u32, data: Vec<u8>) {
        self.rows.push((table, rows, data));
    }

    /// Marks a table as sorted in the stream header, whether or not it is.
    pub fn declare_sorted(&mut self, table: TableId) {
        self.sorted |= 1u64 << table.to_u8();
    }

    /// Serialises the region, naming the table stream `#~` or `#-`.
    pub fn build(mut self, stream_name: &str) -> Vec<u8> {
        self.rows.sort_by_key(|(table, _, _)| table.to_u8());

        let mut stream = Vec::new();
        stream.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        stream.push(2); // MajorVersion
        stream.push(0); // MinorVersion
        stream.push(0); // HeapSizes: every heap index is 2 bytes
        stream.push(1); // Reserved
        let valid: u64 = self.rows.iter().map(|(t, _, _)| 1u64 << t.to_u8()).sum();
        stream.extend_from_slice(&valid.to_le_bytes());
        stream.extend_from_slice(&self.sorted.to_le_bytes());
        for (_, count, _) in &self.rows {
            stream.extend_from_slice(&count.to_le_bytes());
        }
        for (_, _, data) in &self.rows {
            stream.extend_from_slice(data);
        }

        let guids = [0u8; 16];
        let streams: [(&str, &[u8]); 4] = [
            (stream_name, &stream),
            ("#Strings", &self.strings),
            ("#Blob", &self.blobs),
            ("#GUID", &guids),
        ];

        let version = b"v4.0.30319\0\0";
        let mut header = Vec::new();
        header.extend_from_slice(&0x424A_5342u32.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&(version.len() as u32).to_le_bytes());
        header.extend_from_slice(version);
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&(streams.len() as u16).to_le_bytes());

        let directory: usize =
            streams.iter().map(|(name, _)| 8 + (name.len() + 1).next_multiple_of(4)).sum();
        let mut offset = header.len() + directory;
        let mut payload = Vec::new();
        for (name, data) in streams {
            header.extend_from_slice(&(offset as u32).to_le_bytes());
            header.extend_from_slice(&(data.len() as u32).to_le_bytes());
            let mut name_bytes = name.as_bytes().to_vec();
            name_bytes.push(0);
            while name_bytes.len() % 4 != 0 {
                name_bytes.push(0);
            }
            header.extend_from_slice(&name_bytes);
            payload.extend_from_slice(data);
            offset += data.len();
        }
        header.extend_from_slice(&payload);
        header
    }
}

impl Default for MetadataBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A `Module` row, which every well-formed region has exactly one of.
pub fn module_row(name: u16) -> Vec<u8> {
    let mut row = Vec::new();
    row.extend_from_slice(&0u16.to_le_bytes()); // Generation
    row.extend_from_slice(&name.to_le_bytes());
    row.extend_from_slice(&1u16.to_le_bytes()); // Mvid
    row.extend_from_slice(&0u16.to_le_bytes()); // EncId
    row.extend_from_slice(&0u16.to_le_bytes()); // EncBaseId
    row
}

/// Encodes a `TypeDefOrRefOrSpec` for a signature blob: a 2-bit tag and a RID,
/// compressed. RIDs below 0x20 fit in one byte.
pub fn type_def_or_ref_or_spec(tag: u8, rid: u32) -> u8 {
    let value = (rid << 2) | u32::from(tag);
    assert!(value < 0x80, "the helper writes one-byte compressed integers");
    value as u8
}
