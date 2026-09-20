//! PE container shapes, built from scratch.
//!
//! The committed fixtures are PE32, and the only PE32+ image at hand is a real
//! CoreLib, which is not always installed. So the images here are assembled
//! byte by byte: both optional-header forms, a section whose raw range runs
//! past the file, a method RVA that no section maps, and a CLI header whose
//! declared size is wrong. Each of these is a real-world shape from the
//! deviations list, and none of them needs a .NET install to reproduce.

use cildec::{CliFlags, DiagnosticCode, EntryPoint, PeImage, Strictness, TableId, Token};

const SECTION_RVA: u32 = 0x2000;
const SECTION_FILE_OFFSET: usize = 0x200;
const CLI_HEADER_RVA: u32 = SECTION_RVA;
const METADATA_RVA: u32 = SECTION_RVA + 0x50;

/// A metadata region with an empty `#~` stream.
fn minimal_metadata() -> Vec<u8> {
    let mut stream = Vec::new();
    stream.extend_from_slice(&0u32.to_le_bytes());
    stream.extend_from_slice(&[2, 0, 0, 1]);
    stream.extend_from_slice(&0u64.to_le_bytes());
    stream.extend_from_slice(&0u64.to_le_bytes());

    let version = b"v4.0.30319\0\0";
    let mut out = Vec::new();
    out.extend_from_slice(&0x424A_5342u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(version.len() as u32).to_le_bytes());
    out.extend_from_slice(version);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    let directory = 8 + 4;
    out.extend_from_slice(&((out.len() + directory) as u32).to_le_bytes());
    out.extend_from_slice(&(stream.len() as u32).to_le_bytes());
    out.extend_from_slice(b"#~\0\0");
    out.extend_from_slice(&stream);
    out
}

struct Options {
    pe32_plus: bool,
    cli_header_size: u32,
    cli_flags: u32,
    entry_point: u32,
    /// Bytes to add to the section `SizeOfRawData`, past the end of the file.
    raw_size_overhang: u32,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            pe32_plus: false,
            cli_header_size: 72,
            cli_flags: 0x0000_0001,
            entry_point: 0,
            raw_size_overhang: 0,
        }
    }
}

fn build(options: &Options) -> Vec<u8> {
    let metadata = minimal_metadata();

    // The mapped section: CLI header, then the metadata region.
    let mut section = vec![0u8; 0x400];
    let mut cli = Vec::new();
    cli.extend_from_slice(&options.cli_header_size.to_le_bytes());
    cli.extend_from_slice(&2u16.to_le_bytes()); // MajorRuntimeVersion
    cli.extend_from_slice(&5u16.to_le_bytes()); // MinorRuntimeVersion
    cli.extend_from_slice(&METADATA_RVA.to_le_bytes());
    cli.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    cli.extend_from_slice(&options.cli_flags.to_le_bytes());
    cli.extend_from_slice(&options.entry_point.to_le_bytes());
    cli.resize(72, 0); // the remaining directories are all empty
    section[..cli.len()].copy_from_slice(&cli);
    let metadata_at = (METADATA_RVA - SECTION_RVA) as usize;
    section[metadata_at..metadata_at + metadata.len()].copy_from_slice(&metadata);

    let optional_size: usize = if options.pe32_plus { 240 } else { 224 };
    let headers_size = 0x80 + 4 + 20 + optional_size + 40;
    assert!(headers_size <= SECTION_FILE_OFFSET);

    let mut out = vec![0u8; SECTION_FILE_OFFSET];
    out[0] = b'M';
    out[1] = b'Z';
    out[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    out[0x80..0x84].copy_from_slice(b"PE\0\0");

    let coff = 0x84;
    let machine: u16 = if options.pe32_plus { 0x8664 } else { 0x014C };
    out[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
    out[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    out[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
    out[coff + 18..coff + 20].copy_from_slice(&0x2022u16.to_le_bytes()); // Characteristics

    let opt = coff + 20;
    let magic: u16 = if options.pe32_plus { 0x020B } else { 0x010B };
    out[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
    out[opt + 16..opt + 20].copy_from_slice(&0u32.to_le_bytes()); // AddressOfEntryPoint
    let dir_count_at = if options.pe32_plus {
        out[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        opt + 108
    } else {
        out[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        opt + 92
    };
    out[opt + 32..opt + 36].copy_from_slice(&0x2000u32.to_le_bytes()); // SectionAlignment
    out[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    out[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes()); // SizeOfImage
    out[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    out[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem
    out[dir_count_at..dir_count_at + 4].copy_from_slice(&16u32.to_le_bytes());

    // Data directory 14 is the CLI header.
    let dirs = dir_count_at + 4;
    let cli_dir = dirs + 14 * 8;
    out[cli_dir..cli_dir + 4].copy_from_slice(&CLI_HEADER_RVA.to_le_bytes());
    out[cli_dir + 4..cli_dir + 8].copy_from_slice(&72u32.to_le_bytes());

    let sections = opt + optional_size;
    out[sections..sections + 8].copy_from_slice(b".text\0\0\0");
    out[sections + 8..sections + 12].copy_from_slice(&(section.len() as u32).to_le_bytes());
    out[sections + 12..sections + 16].copy_from_slice(&SECTION_RVA.to_le_bytes());
    let raw_size = section.len() as u32 + options.raw_size_overhang;
    out[sections + 16..sections + 20].copy_from_slice(&raw_size.to_le_bytes());
    out[sections + 20..sections + 24].copy_from_slice(&(SECTION_FILE_OFFSET as u32).to_le_bytes());
    out[sections + 36..sections + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    out.extend_from_slice(&section);
    out
}

#[test]
fn a_pe32_image_parses() {
    let bytes = build(&Options::default());
    let image = PeImage::parse(&bytes).expect("parse");
    assert!(!image.is_pe32_plus());
    assert_eq!(image.machine(), 0x014C);
    assert_eq!(image.image_base(), 0x0040_0000);
    assert_eq!(image.sections().len(), 1);
    assert_eq!(image.sections()[0].name(), Some(".text"));
    assert_eq!(image.rva_to_offset(SECTION_RVA), Some(SECTION_FILE_OFFSET));

    let header = image.cli_header().expect("CLI header");
    assert_eq!(header.size, 72);
    assert_eq!((header.major_runtime_version, header.minor_runtime_version), (2, 5));
    assert!(header.flags.il_only());
    assert_eq!(header.entry_point, EntryPoint::None);
    assert!(header.resources.is_empty());

    let metadata = image.metadata().expect("metadata");
    assert_eq!(metadata.version_string(), "v4.0.30319");
    assert_eq!(metadata.tables().row_count(TableId::TypeDef), 0);
    assert!(image.diagnostics().is_empty());
    assert!(image.cli_header_diagnostics().is_empty());
}

#[test]
fn a_pe32_plus_image_parses() {
    let bytes = build(&Options { pe32_plus: true, ..Options::default() });
    let image = PeImage::parse(&bytes).expect("parse");
    assert!(image.is_pe32_plus());
    assert_eq!(image.machine(), 0x8664);
    assert_eq!(image.image_base(), 0x0000_0001_4000_0000);
    assert_eq!(image.section_alignment(), 0x2000);
    assert_eq!(image.file_alignment(), 0x200);
    assert_eq!(image.subsystem(), 3);
    assert!(image.cli_header().is_ok());
    assert!(image.metadata().is_ok());
}

#[test]
fn both_header_forms_agree_about_everything_but_the_base() {
    let pe32 = build(&Options::default());
    let pe32_plus = build(&Options { pe32_plus: true, ..Options::default() });
    let a = PeImage::parse(&pe32).expect("parse");
    let b = PeImage::parse(&pe32_plus).expect("parse");
    assert_eq!(a.rva_to_offset(METADATA_RVA), b.rva_to_offset(METADATA_RVA));
    assert_eq!(a.cli_header().unwrap().metadata, b.cli_header().unwrap().metadata);
    assert_eq!(a.metadata().unwrap().version_string(), b.metadata().unwrap().version_string());
}

#[test]
fn an_entry_point_token_is_classified() {
    let token = Token::new(TableId::MethodDef, 3);
    let bytes = build(&Options { entry_point: token.value(), ..Options::default() });
    let image = PeImage::parse(&bytes).expect("parse");
    assert_eq!(image.cli_header().unwrap().entry_point, EntryPoint::Token(token));
    assert_eq!(image.entry_point_token(), Some(token));

    // With NATIVE_ENTRYPOINT the same field is an RVA.
    let bytes =
        build(&Options { entry_point: 0x2100, cli_flags: 0x0000_0011, ..Options::default() });
    let image = PeImage::parse(&bytes).expect("parse");
    assert_eq!(image.cli_header().unwrap().entry_point, EntryPoint::Rva(0x2100));
    assert_eq!(image.entry_point_token(), None);
}

#[test]
fn a_section_running_past_the_file_is_clamped() {
    let bytes = build(&Options { raw_size_overhang: 0x1000, ..Options::default() });
    let image = PeImage::parse(&bytes).expect("parse");
    assert!(
        image.diagnostics().iter().any(|d| d.code == DiagnosticCode::SectionRangeClamped),
        "expected a clamped-section diagnostic"
    );
    // Reads stay inside the file even though the header claimed more.
    let available = image.rva_available(SECTION_RVA).expect("mapped");
    assert!(available <= bytes.len() - SECTION_FILE_OFFSET);
    assert!(image.rva_slice(SECTION_RVA, available).is_ok());
    assert!(image.rva_slice(SECTION_RVA, available + 1).is_err());
    assert!(PeImage::parse_with(&bytes, Strictness::Strict).is_err());
}

#[test]
fn an_rva_no_section_maps_is_a_per_method_error() {
    use cildec::MethodBody;
    use cildec::tables::MethodDefRow;

    let bytes = build(&Options::default());
    let image = PeImage::parse(&bytes).expect("parse");
    // The image itself is fine.
    assert!(image.metadata().is_ok());

    // A method whose RVA is outside every section fails on its own.
    let row = MethodDefRow { rva: 0x9000, ..MethodDefRow::default() };
    assert!(MethodBody::from_image(&image, &row).is_err());
    // And one inside the headers, which the loader maps but no section covers.
    let row = MethodDefRow { rva: 0x40, ..MethodDefRow::default() };
    let _ = MethodBody::from_image(&image, &row);
    // A zero RVA simply has no body.
    let row = MethodDefRow::default();
    assert!(MethodBody::from_image(&image, &row).unwrap().is_none());
}

#[test]
fn a_cli_header_size_other_than_72_is_diagnosed() {
    let bytes = build(&Options { cli_header_size: 80, ..Options::default() });
    let image = PeImage::parse(&bytes).expect("parse");
    assert_eq!(image.cli_header().unwrap().size, 80);
    assert!(image.cli_header_diagnostics().iter().any(|d| d.code == DiagnosticCode::CliHeaderSize));
    let strict = PeImage::parse_with(&bytes, Strictness::Strict).expect("the container is fine");
    assert!(strict.cli_header().is_err(), "strict mode rejects the header itself");
}

#[test]
fn bitness_flags_are_exposed_separately() {
    // .NET Core images set 32BITPREFERRED without 32BITREQUIRED.
    let bytes = build(&Options { cli_flags: 0x0002_0001, ..Options::default() });
    let image = PeImage::parse(&bytes).expect("parse");
    let flags = image.cli_header().unwrap().flags;
    assert!(flags.il_only());
    assert!(flags.prefers_32bit());
    assert!(!flags.requires_32bit());
    assert!(
        image
            .cli_header_diagnostics()
            .iter()
            .any(|d| d.code == DiagnosticCode::BitnessFlagsInconsistent)
    );
    assert_eq!(CliFlags(0x0002_0001).bits(), 0x0002_0001);
}

#[test]
fn every_truncation_of_a_synthetic_image_is_handled() {
    for pe32_plus in [false, true] {
        let bytes = build(&Options { pe32_plus, ..Options::default() });
        let step = (bytes.len() / 512).max(1);
        let mut len = 0;
        while len < bytes.len() {
            let _ = PeImage::parse(&bytes[..len]);
            let _ = PeImage::parse_with(&bytes[..len], Strictness::Strict);
            len += step;
        }
        assert!(PeImage::parse(&bytes).is_ok());
    }
}
