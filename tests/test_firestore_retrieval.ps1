[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$ReportId = "classic_bof_c5140d3fe9acfbce",

    [Parameter()]
    [string]$ConfigFile = "config/firebase_config.json",

    [Parameter()]
    [string]$ProjectId,

    [Parameter()]
    [string]$ApiKey,

    [Parameter()]
    [switch]$UseEmulator
)

$ErrorActionPreference = "Stop"

# Determine target endpoints and credentials
if ($UseEmulator -or $env:FIRESTORE_EMULATOR_HOST) {
    $rawHost = if ($env:FIRESTORE_EMULATOR_HOST) { $env:FIRESTORE_EMULATOR_HOST.Trim() } else { "127.0.0.1:8088" }

    # Disallow URL schemes or paths
    if ($rawHost -match "^https?://" -or $rawHost -match "/") {
        Write-Error "[x] Invalid FIRESTORE_EMULATOR_HOST '$rawHost': schemes (http://) and paths are not permitted."
        exit 1
    }

    # Parse host and port
    $hostPart = ""
    $portPart = 8088

    if ($rawHost -match "^\[([^\]]+)\](?::(\d+))?$") {
        # IPv6 format [::1] or [::1]:8088
        $hostPart = $matches[1]
        if ($matches[2]) { $portPart = [int]$matches[2] }
    } elseif ($rawHost -match "^([^:]+)(?::(\d+))?$") {
        $hostPart = $matches[1]
        if ($matches[2]) { $portPart = [int]$matches[2] }
    } else {
        Write-Error "[x] Invalid FIRESTORE_EMULATOR_HOST '$rawHost': malformed host:port syntax."
        exit 1
    }

    # Strict loopback host enforcement
    $allowedHosts = @("127.0.0.1", "localhost", "::1")
    if ($allowedHosts -notcontains $hostPart.ToLower()) {
        Write-Error "[x] Security Violation: FIRESTORE_EMULATOR_HOST '$rawHost' resolved to '$hostPart', which is not a permitted loopback host (allowed: 127.0.0.1, localhost, ::1)."
        exit 1
    }

    # Validate port range
    if ($portPart -lt 1 -or $portPart -gt 65535) {
        Write-Error "[x] Invalid FIRESTORE_EMULATOR_HOST '$rawHost': port $portPart out of range (1-65535)."
        exit 1
    }

    $formattedHost = if ($hostPart -match ":") { "[$hostPart]:$portPart" } else { "$hostPart`:$portPart" }
    $proj = if ($ProjectId) { $ProjectId } else { "rop-weaver" }
    $uri = "http://$formattedHost/v1/projects/$proj/databases/(default)/documents/reports/$ReportId"
    Write-Host "[INFO] Mode: LOCAL EMULATOR READ-ONLY" -ForegroundColor Cyan
    Write-Host "[INFO] Host: $formattedHost (Loopback verified)"
    Write-Host "[INFO] Endpoint: $uri"
} else {
    # Dynamically resolve project ID and API key from configuration file if not explicitly supplied
    if (Test-Path $ConfigFile) {
        $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        if (-not $ProjectId) { $ProjectId = $cfg.projectId }
        if (-not $ApiKey) { $ApiKey = $cfg.apiKey }
    }
    if (-not $ProjectId) {
        $ProjectId = "rop-weaver"
    }
    if (-not $ApiKey -and $env:FIREBASE_WEB_API_KEY) {
        $ApiKey = $env:FIREBASE_WEB_API_KEY
    }

    if (-not $ApiKey) {
        Write-Error "[x] An API key is required for production Firestore access. Supply -ApiKey, set `$env:FIREBASE_WEB_API_KEY, or ensure $ConfigFile exists."
        exit 1
    }

    $uri = "https://firestore.googleapis.com/v1/projects/$ProjectId/databases/(default)/documents/reports/$ReportId?key=$ApiKey"
    $maskedKey = $ApiKey.Substring(0, [Math]::Min(8, $ApiKey.Length)) + "..."
    Write-Host "[INFO] Mode: PRODUCTION REST READ-ONLY (GET only)" -ForegroundColor Green
    Write-Host "[INFO] Project: $ProjectId"
    Write-Host "[INFO] Document: $ReportId"
    Write-Host "[INFO] API Key: $maskedKey"
}

try {
    # Strictly read-only GET request
    $doc = Invoke-RestMethod -Uri $uri -Method Get

    [PSCustomObject]@{
        DocumentName            = $doc.name
        ToolVersion             = $doc.fields.tool_version.stringValue
        BuildId                 = $doc.fields.build_id.stringValue
        ReportId                = $doc.fields.report_id.stringValue
        FileType                = $doc.fields.file_type.stringValue
        TotalGadgets            = $doc.fields.total_gadgets.integerValue
        UploadStatus            = $doc.fields.upload_status.stringValue
        GadgetsStoredSeparately = $doc.fields.gadgets_stored_separately.booleanValue
        NxCompat                = $doc.fields.protections.mapValue.fields.NX_COMPAT.mapValue.fields.static_indicator.stringValue
        DynamicBase             = $doc.fields.protections.mapValue.fields.DYNAMIC_BASE.mapValue.fields.static_indicator.stringValue
        CetCompat               = $doc.fields.protections.mapValue.fields.CET_COMPAT.mapValue.fields.static_indicator.stringValue
        GsCookie                = $doc.fields.protections.mapValue.fields.GS_COOKIE.mapValue.fields.static_indicator.stringValue
        SafeSEH                 = $doc.fields.protections.mapValue.fields.SafeSEH.mapValue.fields.static_indicator.stringValue
        RelroPresent            = ($doc.fields.protections.mapValue.fields.RELRO -ne $null)
        RopChainStatus          = $doc.fields.rop_chain_generation.mapValue.fields.status.stringValue
        RawPayloadStatus        = $doc.fields.raw_payload.mapValue.fields.status.stringValue
    } | Format-List
} catch {
    Write-Host "[!] Document retrieval failed: $($_.Exception.Message)" -ForegroundColor Yellow
}
