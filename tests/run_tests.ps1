# tests/run_tests.ps1
# Comprehensive Regression Test Suite for ROPWeaver v1.2.4

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         ROPWeaver Comprehensive Regression Test Suite       " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName
$Ropweaver   = "$ProjectRoot\build-win\ropweaver.exe"
$CwdReports  = "$ProjectRoot\reports"
$OutJson     = "$CwdReports\output.json"

if (-not (Test-Path $Ropweaver)) {
    Write-Host "[!] Error: ROPWeaver executable not found at $Ropweaver. Build it first." -ForegroundColor Red
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
        Write-Host "  [PASS] ${Name}" -ForegroundColor Green
        $script:Passed++
    } else {
        Write-Host "  [FAIL] ${Name}: ${Details}" -ForegroundColor Red
        $script:Failed++
    }
}

# -------------------------------------------------------------
# Test 1: ELF64 Analysis & Auto-Chain (binsh_test)
# -------------------------------------------------------------
Write-Host "`n[*] Test 1: ELF64 Analysis & Auto-Chain (binsh_test)..." -ForegroundColor Yellow
$ElfBinary = "$ProjectRoot\test_binaries\binsh_test"
if (Test-Path $OutJson) { Remove-Item $OutJson -Force }

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
    Assert-Test -Name "ELF payload status is Success" -Condition ($json.raw_payload.status -eq "Success")
    Assert-Test -Name "ELF payload verified_padding_offset is set" -Condition ($json.raw_payload.verified_padding_offset -eq 104)
}

# -------------------------------------------------------------
# Test 2: PE64 Analysis, Mitigations & Address Representation (classic_bof.exe)
# -------------------------------------------------------------
Write-Host "`n[*] Test 2: PE64 Analysis & Mitigation Detection (classic_bof.exe)..." -ForegroundColor Yellow
$PeBinary = "$ProjectRoot\test_binaries\classic_bof.exe"
if (Test-Path $OutJson) { Remove-Item $OutJson -Force }

$rawOutput = & $Ropweaver $PeBinary -a -p 2>&1
$outputStr = $rawOutput -join "`n"
$exitCode = $LASTEXITCODE

Assert-Test -Name "PE Execution returns code 0" -Condition ($exitCode -eq 0)
Assert-Test -Name "PE Detected architecture x86_64" -Condition ($outputStr -match "Detected architecture:\s*x86_64")
Assert-Test -Name "PE NX_COMPAT detected" -Condition ($outputStr -match "NX_COMPAT.*COMPATIBLE")
Assert-Test -Name "PE DYNAMIC_BASE detected" -Condition ($outputStr -match "DYNAMIC_BASE.*COMPATIBLE")
Assert-Test -Name "PE HIGH_ENTROPY_VA detected" -Condition ($outputStr -match "HIGH_ENTROPY_VA.*COMPATIBLE")
Assert-Test -Name "PE CET reported as UNKNOWN" -Condition ($outputStr -match "CET=.*UNKNOWN")
Assert-Test -Name "PE GS-Cookie reported as NOT_DETECTED" -Condition ($outputStr -match "GS-Cookie=.*NOT_DETECTED")
Assert-Test -Name "PE SafeSEH reported as NOT_APPLICABLE" -Condition ($outputStr -match "SafeSEH=.*NOT_APPLICABLE")
Assert-Test -Name "PE output does NOT display RELRO" -Condition ($outputStr -notmatch "RELRO=")
Assert-Test -Name "PE reports automated chain unsupported" -Condition ($outputStr -match "unsupported for Windows PE")

if (Test-Path $OutJson) {
    $json = Get-Content $OutJson -Raw | ConvertFrom-Json
    Assert-Test -Name "JSON file_type is PE" -Condition ($json.file_type -eq "PE")
    Assert-Test -Name "JSON total_gadgets matches collection size" -Condition ($json.total_gadgets -eq $json.gadgets.Count)
    Assert-Test -Name "JSON protections do NOT contain RELRO for PE" -Condition ($json.protections.PSObject.Properties['RELRO'] -eq $null)
    Assert-Test -Name "JSON protections NX_COMPAT static indicator is COMPATIBLE" -Condition ($json.protections.NX_COMPAT.static_indicator -eq "COMPATIBLE")
    Assert-Test -Name "JSON protections DYNAMIC_BASE static indicator is COMPATIBLE" -Condition ($json.protections.DYNAMIC_BASE.static_indicator -eq "COMPATIBLE")
    Assert-Test -Name "JSON protections HIGH_ENTROPY_VA static indicator is COMPATIBLE" -Condition ($json.protections.HIGH_ENTROPY_VA.static_indicator -eq "COMPATIBLE")
    Assert-Test -Name "JSON protections CET_COMPAT static indicator is UNKNOWN" -Condition ($json.protections.CET_COMPAT.static_indicator -eq "UNKNOWN")
    Assert-Test -Name "JSON protections GS_COOKIE is NOT_DETECTED" -Condition ($json.protections.GS_COOKIE.static_indicator -eq "NOT_DETECTED")
    Assert-Test -Name "JSON rop_chain_generation status is Unsupported" -Condition ($json.rop_chain_generation.status -like "*Unsupported*")
    Assert-Test -Name "JSON rop_chain_generation target_syscall is N/A" -Condition ($json.rop_chain_generation.target_syscall -eq "N/A")
    Assert-Test -Name "JSON raw_payload status is Unsupported" -Condition ($json.raw_payload.status -like "*Unsupported*")
    Assert-Test -Name "JSON raw_payload verified_padding_offset is null" -Condition ($json.raw_payload.verified_padding_offset -eq $null)

    # Address Representation Validation
    $g0 = $json.gadgets[0]
    Assert-Test -Name "Gadget has preferred_va hex format" -Condition ($g0.preferred_va -match "^0x[0-9a-fA-F]{16}$")
    Assert-Test -Name "Gadget has rva hex format" -Condition ($g0.rva -match "^0x[0-9a-fA-F]{8}$")
    Assert-Test -Name "Gadget has file_offset hex format" -Condition ($g0.file_offset -match "^0x[0-9a-fA-F]{8}$")
    Assert-Test -Name "Gadget runtime_va is null for ASLR binary" -Condition ($g0.runtime_va -eq $null)
    Assert-Test -Name "Gadget runtime_va_note explains ASLR randomization" -Condition ($g0.runtime_va_note -match "ASLR")
    Assert-Test -Name "Gadget byte_verified is true" -Condition ($g0.byte_verified -eq $true)

    # Classification: Memory Read vs Write for CMP / TEST
    $pureCmpGadgets = $json.gadgets | Where-Object { 
        ($_.instructions -match "cmp.*\[|test.*\[") -and 
        ($_.instructions -notmatch "add\s+.*\[|mov\s+.*\[|sub\s+.*\[|push") 
    }
    $cmpMemWriteClean = $true
    foreach ($cg in $pureCmpGadgets) {
        if ($cg.has_memory_write -eq $true) { $cmpMemWriteClean = $false; break }
    }
    Assert-Test -Name "CMP/TEST memory access is classified as memory_read and NEVER memory_write" -Condition ($cmpMemWriteClean -eq $true -and $pureCmpGadgets.Count -gt 0)

    # Classification: Stack Adjustment vs Pivot for ADD RSP
    $addRspGadgets = $json.gadgets | Where-Object { $_.instructions -match "add\s+rsp" }
    $addRspClean = $true
    if ($addRspGadgets) {
        foreach ($arg in $addRspGadgets) {
            if ($arg.categories -contains "stack_pivot") { $addRspClean = $false; break }
        }
    }
    Assert-Test -Name "ADD RSP is classified as stack_adjustment and NOT stack_pivot" -Condition ($addRspClean -eq $true)
}

# -------------------------------------------------------------
# Test 3: Malformed Binary Handling (truncated file)
# -------------------------------------------------------------
Write-Host "`n[*] Test 3: Malformed Binary Error Handling..." -ForegroundColor Yellow
$MalformedFile = "$CwdReports\malformed.bin"
[System.IO.File]::WriteAllBytes($MalformedFile, [byte[]]@(0x7F, 0x45, 0x4C, 0x46)) # truncated ELF header

$rawOutput = & $Ropweaver $MalformedFile 2>&1
$outputStr = $rawOutput -join "`n"
$exitCode = $LASTEXITCODE

Assert-Test -Name "Malformed binary exits with non-zero error" -Condition ($exitCode -ne 0)
Assert-Test -Name "Graceful error message reported" -Condition ($outputStr -match "Error|Failed|Invalid")

if (Test-Path $MalformedFile) { Remove-Item $MalformedFile -Force }

# -------------------------------------------------------------
# Test 4: Clean Exit on Empty / Non-Executable File
# -------------------------------------------------------------
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
