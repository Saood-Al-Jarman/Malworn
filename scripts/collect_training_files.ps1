# Malworn fine-tuning: collect ~40 benign Windows programs and DLLs for the TRAINING set.
# Run on Windows (PowerShell), from the repo folder:
#     powershell -ExecutionPolicy Bypass -File scripts\collect_training_files.ps1
# Copies them to %USERPROFILE%\malworn-train\ (prefix x64_/x86_/net_ so names don't clash),
# skips every file whose SHA-256 is in data\test_hashes.txt (the group's corpus and the demo
# files), writes hashes.csv and zips the folder to %USERPROFILE%\malworn-train.zip.
# Only legitimate Windows files: nothing is downloaded and nothing is run.

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$out = Join-Path $env:USERPROFILE "malworn-train"
$zip = "$out.zip"
$sys = Join-Path $env:WINDIR "System32"
$wow = Join-Path $env:WINDIR "SysWOW64"
$net = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319"

$picks = @(
  @{dir=$sys; tag="x64"; names=@("ping.exe","ipconfig.exe","tasklist.exe","whoami.exe","certutil.exe",
      "robocopy.exe","xcopy.exe","sort.exe","where.exe","hostname.exe","netstat.exe","schtasks.exe",
      "reg.exe","sc.exe","advapi32.dll","crypt32.dll","wininet.dll","bcrypt.dll","ole32.dll","msvcrt.dll",
      "dbghelp.dll","winhttp.dll","iphlpapi.dll","shlwapi.dll")},
  @{dir=$wow; tag="x86"; names=@("ping.exe","ipconfig.exe","tasklist.exe","certutil.exe","reg.exe",
      "advapi32.dll","crypt32.dll","wininet.dll","msvcrt.dll","ole32.dll","shlwapi.dll","winhttp.dll")},
  @{dir=$net; tag="net"; names=@("csc.exe","InstallUtil.exe","RegAsm.exe","vbc.exe")}
)

$exclude = @{}
$testList = Join-Path $repo "data\test_hashes.txt"
if (Test-Path $testList) {
  Get-Content $testList | ForEach-Object { if ($_ -match '^\s*([0-9a-fA-F]{64})') { $exclude[$Matches[1].ToLower()] = $true } }
}
Write-Host "Excluding $($exclude.Count) test files listed in data\test_hashes.txt"

New-Item -ItemType Directory -Force -Path $out | Out-Null
$rows = @()
foreach ($p in $picks) {
  foreach ($n in $p.names) {
    $src = Join-Path $p.dir $n
    if (-not (Test-Path $src)) { Write-Host "  not found, skipped: $src"; continue }
    $sha = (Get-FileHash $src -Algorithm SHA256).Hash.ToLower()
    if ($exclude.ContainsKey($sha)) { Write-Host "  test file, skipped: $src"; continue }
    if ($rows | Where-Object { $_.sha256 -eq $sha }) { Write-Host "  duplicate, skipped: $src"; continue }
    $dest = Join-Path $out "$($p.tag)_$n"
    Copy-Item $src $dest -Force
    $rows += [pscustomobject]@{file="$($p.tag)_$n"; source=$src; sha256=$sha; size=(Get-Item $src).Length}
  }
}
$rows | Export-Csv -NoTypeInformation -Path (Join-Path $out "hashes.csv")
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path (Join-Path $out "*") -DestinationPath $zip
Write-Host ""
Write-Host "Collected $($rows.Count) files into $out"
Write-Host "Zip for the VM: $zip"
