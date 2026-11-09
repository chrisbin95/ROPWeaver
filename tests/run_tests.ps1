# ROPWeaver Comprehensive Regression Test Suite (PowerShell)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path "$ScriptDir\..").Path
$BinDir = "$ProjectRoot\build-win"
$Ropweaver = "$BinDir\ropweaver.exe"

if (-not (Test-Path $Ropweaver)) {
    Write-Error "[!] ropweaver.exe not found at $Ropweaver. Build the project first."
    exit 1
}

$Passed = 0
$Failed = 0

function Assert-Test {
    param(
        [string]$Name,
        [bool]$Condition,
        [string]$Details = ""
    )
    if ($Condition) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        $script:Passed++
    } else {
        Write-Host "  [FAIL] ${Name}: ${Details}" -ForegroundColor Red
        $script:Failed++
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         ROPWeaver Comprehensive Regression Test Suite       " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Ensure reports directory
$CwdReports = "$ProjectRoot\reports"
if (-not (Test-Path $CwdReports)) { New-Item -ItemType Directory -Path $CwdReports -Force | Out-Null }
$OutJson = "$CwdReports\output.json"
if (Test-Path $OutJson) { Remove-Item $OutJson -Force }

Set-Location -Path $ProjectRoot

# Test 1: ELF64 Analysis and Auto-Chain Synthesis
Write-Host "`n[*] Test 1: ELF64 Analysis & Auto-Chain (binsh_test)..." -ForegroundColor Yellow
$ElfBinary = "$ProjectRoot\test_binaries\binsh_test"

$rawOutput = & $Ropweaver $ElfBinary -a -p 2>&1
$outputStr = $rawOutput -join "`n"
$exitCode = $LASTEXITCODE

Assert-Test -Name "ELF Execution returns code 0" -Condition ($exitCode -eq 0)
Assert-Test -Name "ELF Detected architecture x86_64" -Condition ($outputStr -match "Detected architecture:\s*x86_64")
Assert-Test -Name "ELF Found /bin/sh" -Condition ($outputStr -match "Found /bin/sh")
Assert-Test -Name "ELF Auto-chain synthesized successfully" -Condition ($outputStr -match "ROP chain created successfully")
Assert-Test -Name "ELF Report JSON exists" -Condition (Test-Path $OutJson)

if (Test-Path $OutJson) {
    $json = Get-Content $OutJson -Raw | ConvertFrom-Json
    Assert-Test -Name "JSON file_type is ELF" -Condition ($json.file_type -eq "ELF")
    Assert-Test -Name "JSON contains gadgets" -Condition ($json.gadgets.Count -ge 5)
    Assert-Test -Name "JSON gadgets have byte_verified=true" -Condition ($json.gadgets[0].byte_verified -eq $true)
    Assert-Test -Name "JSON gadgets have multi-dim categories" -Condition ($json.gadgets[0].categories.Count -ge 1)
    Assert-Test -Name "JSON RELRO mitigation present for ELF" -Condition ($json.protections.RELRO -ne $null)
}

# Test 2: PE64 Analysis and Mitigation Detection (classic_bof.exe)
Write-Host "`n[*] Test 2: PE64 Analysis & Mitigation Detection (classic_bof.exe)..." -ForegroundColor Yellow
$PeBinary = "$ProjectRoot\test_binaries\classic_bof.exe"
if (Test-Path $OutJson) { Remove-Item $OutJson -Force }

$rawOutput = & $Ropweaver $PeBinary -p 2>&1
$outputStr = $rawOutput -join "`n"
$exitCode = $LASTEXITCODE

Assert-Test -Name "PE Execution returns code 0" -Condition ($exitCode -eq 0)
Assert-Test -Name "PE Detected architecture x86_64" -Condition ($outputStr -match "Detected architecture:\s*x86_64")
Assert-Test -Name "PE DEP/NX mitigation detected" -Condition ($outputStr -match "DEP/NX=ON")
Assert-Test -Name "PE ASLR mitigation detected" -Condition ($outputStr -match "ASLR=ON")
Assert-Test -Name "PE HighEntropyVA detected" -Condition ($outputStr -match "HighEntropyVA=ON")
Assert-Test -Name "PE output does NOT display RELRO" -Condition ($outputStr -notmatch "RELRO=")

if (Test-Path $OutJson) {
    $json = Get-Content $OutJson -Raw | ConvertFrom-Json
    Assert-Test -Name "JSON file_type is PE" -Condition ($json.file_type -eq "PE")
    Assert-Test -Name "JSON protections do NOT contain RELRO for PE" -Condition ($json.protections.PSObject.Properties['RELRO'] -eq $null)
    Assert-Test -Name "JSON protections contain DEP_NX for PE" -Condition ($json.protections.DEP_NX -eq $true)
    Assert-Test -Name "JSON protections contain ASLR_PIE for PE" -Condition ($json.protections.ASLR_PIE -eq $true)
    Assert-Test -Name "JSON protections contain HighEntropyVA for PE" -Condition ($json.protections.HighEntropyVA -eq $true)
    Assert-Test -Name "PE gadgets discovered" -Condition ($json.gadgets.Count -gt 50)
}

# Test 3: Malformed Binary Handling (truncated file)
Write-Host "`n[*] Test 3: Malformed Binary Error Handling..." -ForegroundColor Yellow
$MalformedFile = "$CwdReports\malformed.bin"
[System.IO.File]::WriteAllBytes($MalformedFile, [byte[]]@(0x7F, 0x45, 0x4C, 0x46)) # truncated ELF header

$rawOutput = & $Ropweaver $MalformedFile 2>&1
$outputStr = $rawOutput -join "`n"
$exitCode = $LASTEXITCODE

Assert-Test -Name "Malformed binary exits with non-zero error" -Condition ($exitCode -ne 0)
Assert-Test -Name "Graceful error message reported" -Condition ($outputStr -match "Error|Failed|Invalid")

if (Test-Path $MalformedFile) { Remove-Item $MalformedFile -Force }

# Test 4: Clean Exit on Empty / Non-Executable File
Write-Host "`n[*] Test 4: Empty / Text File Handling..." -ForegroundColor Yellow
$TextFile = "$CwdReports\not_a_binary.txt"
Set-Content -Path $TextFile -Value "This is just a text file, not a binary executable."

$rawOutput = & $Ropweaver $TextFile 2>&1
$outputStr = $rawOutput -join "`n"
$exitCode = $LASTEXITCODE

Assert-Test -Name "Text file exits with error code" -Condition ($exitCode -ne 0)
Assert-Test -Name "Appropriate error displayed" -Condition ($outputStr -match "Error|Failed|Invalid|Unsupported")

if (Test-Path $TextFile) { Remove-Item $TextFile -Force }

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "Test Results: $Passed Passed, $Failed Failed" -ForegroundColor $(if ($Failed -eq 0) { "Green" } else { "Red" })
Write-Host "============================================================" -ForegroundColor Cyan

if ($Failed -gt 0) { exit 1 } else { exit 0 }
