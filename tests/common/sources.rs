//! Where the differential and invariant tests find real assemblies.
//!
//! Shared by the tests that compare against real images.
//!
//! The point is breadth of *metadata vintage*, not breadth of code. An
//! assembly built for .NET Framework 2.0 in 2005 and one built for .NET 10 in
//! 2026 are both ECMA-335, but they differ in metadata version string, heap
//! index widths, table population, PE bitness, and which constructs the
//! compiler of the day emitted. A decoder that only ever sees the newest
//! framework is only tested against one corner of the format.
//!
//! Sources, in the order they are searched:
//!
//! * every `Microsoft.NETCore.App` and `Microsoft.AspNetCore.App` shared
//!   framework, all versions installed;
//! * the reference assemblies under `dotnet/packs`, whose method bodies are
//!   stripped — every `MethodDef` has RVA 0, which is a shape no runtime
//!   assembly has;
//! * `%WINDIR%/Microsoft.NET/Framework{,64}/v*`, which reaches back to
//!   .NET Framework 1.x and 2.0;
//! * the GAC, which holds shipped assemblies from every framework generation;
//! * the Windows SDK reference assemblies.
//!
//! Set `CILDEC_DIFF_DIR` to scan one directory instead, or
//! `CILDEC_DIFF_NUGET=1` to add the NuGet package cache, which is usually the
//! largest and most varied source on a developer machine.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// One place to look, and how deep to go.
struct Source {
    root: PathBuf,
    depth: usize,
}

fn dotnet_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    // `actions/setup-dotnet` and user-local installs set this, so it wins.
    if let Ok(root) = std::env::var("DOTNET_ROOT") {
        roots.push(PathBuf::from(root));
    }
    for fixed in [
        "C:/Program Files/dotnet",
        "C:/Program Files (x86)/dotnet",
        "/usr/share/dotnet",
        "/usr/lib/dotnet",
        "/usr/local/share/dotnet",
    ] {
        roots.push(PathBuf::from(fixed));
    }
    if let Ok(home) = std::env::var("HOME") {
        roots.push(PathBuf::from(home).join(".dotnet"));
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        roots.push(PathBuf::from(profile).join(".dotnet"));
    }
    roots
}

fn sources() -> Vec<Source> {
    if let Ok(dir) = std::env::var("CILDEC_DIFF_DIR") {
        return vec![Source { root: PathBuf::from(dir), depth: 8 }];
    }

    let mut out = Vec::new();
    for root in dotnet_roots() {
        for shared in ["shared/Microsoft.NETCore.App", "shared/Microsoft.AspNetCore.App"] {
            out.push(Source { root: root.join(shared), depth: 2 });
        }
        // Reference packs: every method body is stripped, so RVA 0 is the rule
        // rather than the exception.
        out.push(Source { root: root.join("packs"), depth: 5 });
    }

    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:/Windows".to_owned());
    let windir = PathBuf::from(windir);
    for framework in ["Microsoft.NET/Framework", "Microsoft.NET/Framework64"] {
        out.push(Source { root: windir.join(framework), depth: 2 });
    }
    // The GAC holds assemblies from every framework generation that was ever
    // installed on the machine.
    out.push(Source { root: windir.join("Microsoft.NET/assembly"), depth: 5 });

    for reference in [
        "C:/Program Files (x86)/Reference Assemblies/Microsoft/Framework",
        "C:/Program Files/Reference Assemblies/Microsoft/Framework",
    ] {
        out.push(Source { root: PathBuf::from(reference), depth: 5 });
    }

    if std::env::var("CILDEC_DIFF_NUGET").is_ok() {
        for home in ["HOME", "USERPROFILE"] {
            if let Ok(dir) = std::env::var(home) {
                out.push(Source { root: PathBuf::from(dir).join(".nuget/packages"), depth: 8 });
            }
        }
    }
    out
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>, budget: &mut usize) {
    if depth == 0 || *budget == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    // Sorted so that a limit takes the same assemblies on every machine.
    children.sort();
    for path in children {
        if *budget == 0 {
            return;
        }
        if path.is_dir() {
            walk(&path, depth - 1, out, budget);
        } else if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("dll")) {
            out.push(path);
            *budget -= 1;
        }
    }
}

/// Every candidate assembly on the machine, deduplicated and in a stable order.
///
/// Deduplication is by file name and length: the GAC and the framework
/// directories hold the same assembly many times over, and comparing one
/// hundred copies of `mscorlib` proves nothing the first copy did not.
pub fn real_assemblies() -> Vec<PathBuf> {
    // A default `cargo test` should stay brisk, so it takes a deterministic
    // sample spread across the sources; `CILDEC_DIFF_ALL=1`, which is what CI
    // sets, compares everything. Debug builds dump an order of magnitude
    // slower than release, so their sample is smaller again.
    let default_limit: usize = if cfg!(debug_assertions) { 150 } else { 600 };
    let limit = if std::env::var("CILDEC_DIFF_ALL").is_ok() {
        usize::MAX
    } else {
        std::env::var("CILDEC_DIFF_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_limit)
    };

    let mut found = Vec::new();
    let mut budget = usize::MAX;
    for source in sources() {
        walk(&source.root, source.depth, &mut found, &mut budget);
    }

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for path in found {
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase());
        if !seen.insert((name, meta.len())) {
            continue;
        }
        out.push(path);
    }
    out.sort();

    if out.len() > limit {
        // Take an evenly spread sample rather than a prefix, so the subset
        // still covers every source and framework vintage.
        let stride = out.len().div_ceil(limit);
        out = out.into_iter().step_by(stride).collect();
        out.truncate(limit);
    }
    out
}

/// A short label for reporting, e.g. `Microsoft.NETCore.App/9.0.17`.
pub fn label(path: &Path) -> String {
    let parent =
        path.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned());
    let grandparent = path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned());
    match (grandparent, parent) {
        (Some(g), Some(p)) => format!("{g}/{p}"),
        (None, Some(p)) => p,
        _ => path.display().to_string(),
    }
}
