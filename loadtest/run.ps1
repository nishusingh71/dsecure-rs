# P0-17 local load estimate (Windows, no Docker). Driver source: crates/testkit/src/bin/loadtest.rs
# Needs the LOCAL MySQL from .dev/dev.env (127.0.0.1:3307). Never touches TiDB.
# Usage (repo root):  powershell -File loadtest\run.ps1 [-Rps 100] [-Seconds 30] [-Logins 50] [-Port 4817]
param(
  [int]$Rps = 100,
  [int]$Seconds = 30,
  [int]$Logins = 50,
  [int]$Port = 4817
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
cargo build --release -p api -p testkit
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& .\target\release\dsecure-loadtest.exe --api-bin .\target\release\dsecure-api.exe `
  --port $Port --rps $Rps --seconds $Seconds --logins $Logins
exit $LASTEXITCODE
