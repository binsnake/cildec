//! Differential testing against every real .NET assembly on the machine.
//!
//! The committed fixtures in `tests/golden.rs` pin two small assemblies that
//! this project controls. This test does the same comparison against whatever
//! is actually installed: it dumps every assembly of a .NET shared framework
//! with System.Reflection.Metadata, dumps the same assemblies with cildec, and
//! compares them line by line.
//!
//! That is a few hundred thousand types and a few million instructions decoded
//! twice by unrelated implementations. Anything cildec reads differently — a
//! signature, a layout, an exception clause, one operand of one instruction —
//! shows up as a line that does not match.
//!
//! The test skips itself when no .NET SDK is present, and when `tools/` is
//! absent as it is in the published package, so a checkout without a .NET
//! install still builds green; CI installs the SDK, so there it really runs.
//!
//! The assemblies come from [`common::sources`], which spans every .NET
//! runtime, reference pack and GAC entry on the machine rather than only the
//! newest shared framework: metadata written for .NET Framework 2.0 differs
//! from metadata written for .NET 10 in heap widths, table population, PE
//! bitness and which constructs the compiler of the day emitted.

mod common;

use common::dump::{dump, first_difference};
use common::sources::real_assemblies;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use cildec::PeImage;

/// Builds `tools/gen-golden` once and returns the executable.
///
/// Returns `None` when there is no .NET SDK, which is the signal to skip.
fn build_harness(out_dir: &Path) -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    // The published package excludes `tools/`, so there is nothing to build.
    if !manifest.join("tools/gen-golden").is_dir() {
        eprintln!("no tools/gen-golden; skipping (this is the published package layout)");
        return None;
    }
    let status = Command::new("dotnet")
        .args(["build", "-c", "Release", "--nologo", "-v", "quiet"])
        .arg(manifest.join("tools/gen-golden"))
        .arg("-o")
        .arg(out_dir)
        .current_dir(manifest)
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => panic!("building tools/gen-golden failed with {status}"),
        Err(e) => {
            eprintln!("no dotnet SDK ({e}); skipping the differential test");
            return None;
        }
    }
    for name in ["gen-golden.exe", "gen-golden"] {
        let candidate = out_dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    panic!("gen-golden built but produced no executable in {}", out_dir.display());
}

#[test]
fn cildec_agrees_with_system_reflection_metadata_on_real_assemblies() {
    let images = real_assemblies();
    if images.is_empty() {
        eprintln!("no .NET assemblies found; skipping the differential test");
        return;
    }

    let work = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/differential");
    let harness_dir = work.join("harness");
    let dumps = work.join("dumps");
    std::fs::create_dir_all(&harness_dir).expect("create the work directory");
    let _ = std::fs::remove_dir_all(&dumps);

    let Some(harness) = build_harness(&harness_dir) else { return };

    // A whole framework is a thousand paths, past what a command line holds on
    // Windows, so the list goes in a file.
    let list = work.join("assemblies.txt");
    let listing: Vec<String> = images.iter().map(|p| p.display().to_string()).collect();
    std::fs::write(&list, listing.join("\n")).expect("write the assembly list");

    let start = Instant::now();
    let status = Command::new(&harness)
        .arg("--out")
        .arg(&dumps)
        .arg(format!("@{}", list.display()))
        .status()
        .expect("run gen-golden");
    assert!(status.success(), "gen-golden exited with {status}");
    let reference_time = start.elapsed();

    let start = Instant::now();
    let mut compared = 0usize;
    let mut skipped = 0usize;
    let mut mismatches: Vec<(PathBuf, String)> = Vec::new();

    for (index, image) in images.iter().enumerate() {
        // The harness names dumps by position, because the same assembly name
        // occurs in every installed framework version.
        let stem = format!("{index:05}");
        let expected_path = dumps.join(format!("{stem}.txt"));
        let Ok(expected) = std::fs::read_to_string(&expected_path) else {
            // Either an unmanaged DLL, or one the reference reader rejected.
            // Those are recorded as `.skip` beside the dumps.
            skipped += 1;
            continue;
        };
        let bytes = std::fs::read(image).expect("read the assembly");

        // The reference read it, so cildec must too.
        PeImage::parse(&bytes).unwrap_or_else(|e| {
            panic!("{}: cildec could not parse a managed image: {e}", image.display())
        });

        let actual = dump(&bytes);
        compared += 1;
        if actual != expected.replace("\r\n", "\n") {
            let diff = first_difference(&expected, &actual);
            let actual_path = dumps.join(format!("{stem}.actual.txt"));
            std::fs::write(&actual_path, &actual).ok();
            mismatches.push((image.clone(), diff));
        }
    }
    let compare_time = start.elapsed();

    eprintln!(
        "differential: {compared} assemblies compared, {skipped} skipped; \
         reference {reference_time:?}, cildec {compare_time:?}"
    );
    assert!(compared > 20, "expected a real framework, only compared {compared} assemblies");

    if !mismatches.is_empty() {
        let mut report = format!(
            "{} of {compared} assemblies differ from System.Reflection.Metadata\n",
            mismatches.len()
        );
        for (image, _) in &mismatches {
            report.push_str(&format!("  {}\n", image.display()));
        }
        report.push_str(&format!(
            "\nfirst difference, in {}:\n{}",
            mismatches[0].0.display(),
            mismatches[0].1
        ));
        report.push_str(&format!("\nfull dumps are under {}\n", dumps.display()));
        panic!("{report}");
    }
}

/// Every managed assembly the reference reader accepts must also survive a full
/// cildec walk with no errors and no diagnostics.
///
/// This overlaps the dump comparison but fails faster and more specifically, so
/// a regression in, say, exception-table validation names itself rather than
/// showing up as a missing line several thousand lines into a diff.
#[test]
fn every_real_assembly_walks_cleanly() {
    use cildec::MethodBody;
    use cildec::tables::MethodDefRow;

    let images = real_assemblies();
    if images.is_empty() {
        return;
    }
    let mut managed = 0usize;
    let mut bodies = 0usize;

    for image in &images {
        let Ok(bytes) = std::fs::read(image) else { continue };
        let Ok(pe) = PeImage::parse(&bytes) else { continue };
        let Ok(metadata) = pe.metadata() else { continue };
        managed += 1;

        let diagnostics: Vec<String> =
            pe.diagnostics().iter().chain(metadata.diagnostics()).map(|d| d.to_string()).collect();
        assert!(
            diagnostics.is_empty(),
            "{}: unexpected diagnostics on a shipped assembly: {diagnostics:?}",
            image.display()
        );

        for (rid, row) in metadata.tables().iter::<MethodDefRow>() {
            let row: MethodDefRow =
                row.unwrap_or_else(|e| panic!("{}: MethodDef {rid}: {e}", image.display()));
            let Some(body) = MethodBody::from_image(&pe, &row)
                .unwrap_or_else(|e| panic!("{}: MethodDef {rid} body: {e}", image.display()))
            else {
                continue;
            };
            bodies += 1;
            body.validate_handlers().unwrap_or_else(|e| {
                panic!("{}: MethodDef {rid} exception table: {e}", image.display())
            });
            // A folded span covers its prefixes as well as the instruction,
            // so it is `total_size` that tiles the code; `instruction.size`
            // would be short by the prefix bytes.
            let mut total = 0u64;
            let mut next = 0u32;
            for item in body.folded_instructions() {
                let folded =
                    item.unwrap_or_else(|e| panic!("{}: MethodDef {rid} IL: {e}", image.display()));
                assert_eq!(
                    folded.first_offset,
                    next,
                    "{}: MethodDef {rid} folded spans leave a gap",
                    image.display()
                );
                next = folded.end_offset();
                total += u64::from(folded.total_size());
            }
            assert_eq!(
                total,
                body.code_size() as u64,
                "{}: MethodDef {rid} folded spans do not tile the code",
                image.display()
            );
        }
    }

    eprintln!("walked {managed} managed assemblies, {bodies} method bodies");
    assert!(managed > 20, "expected a real framework, only found {managed} managed assemblies");
}
