Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$baseDir = Split-Path -Parent $PSScriptRoot
$configSchema = Join-Path $baseDir "docs/config.schema.json"
$policiesSchemaDir = Join-Path $baseDir "policies/schema"

New-Item -ItemType Directory -Force -Path $policiesSchemaDir | Out-Null

Write-Host "+ cargo run -q -p pasion-config --bin config-schema"
$configJson = & cargo run -q -p pasion-config --bin config-schema
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($configSchema, ($configJson -join "`n") + "`n", $utf8NoBom)

$oldOutDir = $env:OUT_DIR
$env:OUT_DIR = $policiesSchemaDir
try {
    Write-Host "+ cargo run -q -p pasion-policy --bin policy-schema"
    & cargo run -q -p pasion-policy --bin policy-schema
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    if ($null -eq $oldOutDir) {
        Remove-Item Env:OUT_DIR -ErrorAction SilentlyContinue
    }
    else {
        $env:OUT_DIR = $oldOutDir
    }
}
