# Rebuilds the fixtures and their golden dumps. Run from anywhere.
#
# The .NET SDK version is pinned by global.json. A different patch level
# usually changes the output, so regenerate the golden dumps with it.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Output 'building Features.dll'
    dotnet build fixtures/src/Features -c Release -o (Join-Path $tmp 'features') --nologo
    Copy-Item (Join-Path $tmp 'features/Features.dll') fixtures/Features.dll -Force

    Write-Output 'building IlFeatures.dll'
    dotnet run --project tools/gen-fixtures -- fixtures/IlFeatures.dll

    Write-Output 'regenerating golden dumps'
    New-Item -ItemType Directory -Force -Path fixtures/golden | Out-Null
    foreach ($name in @('Features', 'IlFeatures')) {
        dotnet run --project tools/gen-golden -- "fixtures/$name.dll" |
            Set-Content -Path "fixtures/golden/$name.txt" -NoNewline
    }

    Write-Output 're-seeding the fuzz corpus'
    cargo run --release --quiet --example corpus-pack -- unpack fuzz/corpus
    foreach ($name in @('Features', 'IlFeatures')) {
        cargo run --release --example seed-corpus -- "fixtures/$name.dll" fuzz/corpus
    }
    cargo run --release --quiet --example corpus-pack -- pack fuzz/corpus

    Write-Output "done; run 'cargo test' to check the golden comparison"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
