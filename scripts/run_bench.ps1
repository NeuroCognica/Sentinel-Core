Param()
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root\..

$outDir = "crates\sentinel_bench\bench-results"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$ts = Get-Date -Format yyyyMMddTHHmmss
$outFile = "$outDir\bench-$ts.txt"

Write-Output "Running sentinel_bench (release). Output -> $outFile"
Set-Location crates\sentinel_bench
cargo run --release 2>&1 | Tee-Object -FilePath "..\$outFile"
Write-Output "Done. Results: $outFile"
Pop-Location
