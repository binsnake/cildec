//! Large-image smoke test.
//!
//! Parses a real multi-megabyte assembly and walks every method body, every
//! signature and every heap entry. The image is located at test time and never
//! committed: set `CILDEC_SMOKE_IMAGE` to a path, or let the test find a
//! `System.Private.CoreLib.dll` in an installed .NET shared framework. When no
//! image is found the test reports that and passes, so a checkout without a
//! .NET install still builds green; CI installs .NET so the test really runs.

use std::path::PathBuf;
use std::time::Instant;

use cildec::tables::{
    FieldRow, MemberRefRow, MethodDefRow, MethodSpecRow, PropertyRow, StandAloneSigRow, TypeSpecRow,
};
use cildec::{
    FieldSig, LocalVarSig, MethodBody, MethodSig, MethodSpecSig, PeImage, PropertySig, Strictness,
    TypeSpecSig,
};

fn candidate_images() -> Vec<PathBuf> {
    if let Ok(path) = std::env::var("CILDEC_SMOKE_IMAGE") {
        return vec![PathBuf::from(path)];
    }
    let mut search: Vec<PathBuf> = [
        "C:/Program Files/dotnet",
        "/usr/share/dotnet",
        "/usr/lib/dotnet",
        "/usr/local/share/dotnet",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Ok(root) = std::env::var("DOTNET_ROOT") {
        search.insert(0, PathBuf::from(root));
    }

    let mut roots = Vec::new();
    for root in search {
        let root = root.join("shared/Microsoft.NETCore.App");
        let Ok(entries) = std::fs::read_dir(&root) else { continue };
        for entry in entries.flatten() {
            let candidate = entry.path().join("System.Private.CoreLib.dll");
            if candidate.is_file() {
                roots.push(candidate);
            }
        }
    }
    // Newest version last in directory order is not guaranteed, so sort for
    // determinism and take the highest-sorting path.
    roots.sort();
    roots.into_iter().next_back().into_iter().collect()
}

#[test]
fn parses_a_large_real_image_without_errors() {
    let Some(path) = candidate_images().into_iter().next() else {
        eprintln!("no CoreLib found; set CILDEC_SMOKE_IMAGE to run this test");
        return;
    };
    let bytes = std::fs::read(&path).expect("read image");
    eprintln!("smoke image: {} ({} bytes)", path.display(), bytes.len());

    let start = Instant::now();
    let image = PeImage::parse(&bytes).expect("parse PE");
    let metadata = image.metadata().expect("parse metadata");
    let tables = metadata.tables();
    let open_time = start.elapsed();

    let diagnostics: Vec<String> =
        image.diagnostics().iter().chain(metadata.diagnostics()).map(|d| d.to_string()).collect();
    assert!(
        diagnostics.is_empty(),
        "unexpected diagnostics on a well-formed image: {diagnostics:?}"
    );

    // Every method body decodes, and its instruction sizes tile the code exactly.
    let start = Instant::now();
    let mut bodies = 0usize;
    let mut instructions = 0usize;
    let mut code_bytes = 0usize;
    for (rid, row) in tables.iter::<MethodDefRow>() {
        let row: MethodDefRow = row.unwrap_or_else(|e| panic!("MethodDef {rid}: {e}"));
        let Some(body) = MethodBody::from_image(&image, &row)
            .unwrap_or_else(|e| panic!("MethodDef {rid} body: {e}"))
        else {
            continue;
        };
        bodies += 1;
        code_bytes += body.code_size();

        let mut total = 0u64;
        let mut offsets = Vec::new();
        for item in body.instructions() {
            let instruction = item.unwrap_or_else(|e| panic!("MethodDef {rid} IL: {e}"));
            assert!(instruction.size > 0);
            assert_eq!(instruction.offset as u64, total, "MethodDef {rid} offset drift");
            total += u64::from(instruction.size);
            offsets.push(instruction.offset);
            instructions += 1;
        }
        assert_eq!(total, body.code_size() as u64, "MethodDef {rid} sizes do not tile the code");

        // Every branch target lands on an instruction boundary.
        for item in body.instructions() {
            let instruction = item.expect("already decoded once");
            for &target in instruction.operand.branch_targets() {
                assert!(
                    offsets.binary_search(&target).is_ok(),
                    "MethodDef {rid}: branch target {target:#x} is not an instruction boundary"
                );
            }
        }

        for item in body.folded_instructions() {
            item.unwrap_or_else(|e| panic!("MethodDef {rid} folded IL: {e}"));
        }

        body.validate_handlers().unwrap_or_else(|e| panic!("MethodDef {rid} exception table: {e}"));

        if let Some(token) = body.local_var_sig {
            let sig: StandAloneSigRow = tables
                .stand_alone_sig(token.rid())
                .unwrap_or_else(|e| panic!("MethodDef {rid} locals row: {e}"));
            let blob = metadata.blobs().get(sig.signature).expect("locals blob");
            LocalVarSig::parse(blob).unwrap_or_else(|e| panic!("MethodDef {rid} LocalVarSig: {e}"));
        }
    }
    let body_time = start.elapsed();

    // Every signature blob in the image parses.
    for (rid, row) in tables.iter::<MethodDefRow>() {
        let row: MethodDefRow = row.unwrap();
        let blob = metadata.blobs().get(row.signature).expect("method sig blob");
        MethodSig::parse(blob).unwrap_or_else(|e| panic!("MethodDef {rid} sig: {e}"));
    }
    for (rid, row) in tables.iter::<FieldRow>() {
        let row: FieldRow = row.unwrap();
        let blob = metadata.blobs().get(row.signature).expect("field sig blob");
        FieldSig::parse(blob).unwrap_or_else(|e| panic!("Field {rid} sig: {e}"));
    }
    for (rid, row) in tables.iter::<TypeSpecRow>() {
        let row: TypeSpecRow = row.unwrap();
        let blob = metadata.blobs().get(row.signature).expect("typespec blob");
        TypeSpecSig::parse(blob).unwrap_or_else(|e| panic!("TypeSpec {rid} sig: {e}"));
    }
    for (rid, row) in tables.iter::<MethodSpecRow>() {
        let row: MethodSpecRow = row.unwrap();
        let blob = metadata.blobs().get(row.instantiation).expect("methodspec blob");
        MethodSpecSig::parse(blob).unwrap_or_else(|e| panic!("MethodSpec {rid} sig: {e}"));
    }
    for (rid, row) in tables.iter::<PropertyRow>() {
        let row: PropertyRow = row.unwrap();
        let blob = metadata.blobs().get(row.type_signature).expect("property blob");
        PropertySig::parse(blob).unwrap_or_else(|e| panic!("Property {rid} sig: {e}"));
    }
    for (rid, row) in tables.iter::<MemberRefRow>() {
        let row: MemberRefRow = row.unwrap();
        let blob = metadata.blobs().get(row.signature).expect("memberref blob");
        // A `MemberRef` is either a method or a field reference.
        if blob.first().copied().map(|b| b & 0x0F) == Some(0x06) {
            FieldSig::parse(blob).unwrap_or_else(|e| panic!("MemberRef {rid} field sig: {e}"));
        } else {
            MethodSig::parse(blob).unwrap_or_else(|e| panic!("MemberRef {rid} method sig: {e}"));
        }
    }

    // Every heap entry is readable.
    assert!(metadata.strings().iter().count() > 1000);
    assert!(metadata.blobs().iter().count() > 1000);
    assert!(metadata.user_strings().iter().count() > 100);

    eprintln!(
        "open {open_time:?}; {bodies} bodies, {instructions} instructions, \
         {code_bytes} code bytes in {body_time:?}"
    );
    assert!(bodies > 10_000, "expected a large image, got {bodies} bodies");
}

#[test]
fn a_large_real_image_also_parses_in_strict_mode() {
    let Some(path) = candidate_images().into_iter().next() else { return };
    let bytes = std::fs::read(&path).expect("read image");
    let image = PeImage::parse_with(&bytes, Strictness::Strict).expect("strict PE parse");
    let metadata = image.metadata().expect("strict metadata parse");
    assert!(metadata.tables().row_count(cildec::TableId::MethodDef) > 0);
}

/// Sweeps every managed image in a directory tree.
///
/// Set `CILDEC_SMOKE_DIR` to a folder such as a .NET shared framework or a
/// NuGet package cache. Unmanaged DLLs in the tree are skipped rather than
/// reported, since they have no CLI header.
#[test]
fn sweeps_a_directory_of_images() {
    let Ok(root) = std::env::var("CILDEC_SMOKE_DIR") else { return };
    let mut images = Vec::new();
    collect(PathBuf::from(root).as_path(), &mut images);
    images.sort();
    assert!(!images.is_empty(), "CILDEC_SMOKE_DIR matched no files");

    let mut managed = 0usize;
    let mut bodies = 0usize;
    for path in &images {
        let Ok(bytes) = std::fs::read(path) else { continue };
        let Ok(image) = PeImage::parse(&bytes) else { continue };
        let Ok(metadata) = image.metadata() else { continue };
        managed += 1;
        let tables = metadata.tables();
        for (rid, row) in tables.iter::<MethodDefRow>() {
            let row: MethodDefRow =
                row.unwrap_or_else(|e| panic!("{}: MethodDef {rid}: {e}", path.display()));
            let Some(body) = MethodBody::from_image(&image, &row)
                .unwrap_or_else(|e| panic!("{}: MethodDef {rid} body: {e}", path.display()))
            else {
                continue;
            };
            bodies += 1;
            let mut total = 0u64;
            for item in body.instructions() {
                let instruction =
                    item.unwrap_or_else(|e| panic!("{}: MethodDef {rid} IL: {e}", path.display()));
                total += u64::from(instruction.size);
            }
            assert_eq!(total, body.code_size() as u64, "{}: MethodDef {rid}", path.display());
            for item in body.folded_instructions() {
                item.unwrap_or_else(|e| panic!("{}: MethodDef {rid} folded: {e}", path.display()));
            }
        }
    }
    eprintln!("swept {} files, {managed} managed, {bodies} bodies", images.len());
    assert!(managed > 0);
}

fn collect(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("dll")) {
            out.push(path);
        }
    }
}
