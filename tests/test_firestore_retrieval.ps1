$uri = "https://firestore.googleapis.com/v1/projects/ropweaver/databases/(default)/documents/reports/classic_bof_c5140d3fe9acfbce?key=AIzaSyDZ3BEfUstg32hqnbctG7X3LQ5onNJ98qs"
$doc = Invoke-RestMethod -Uri $uri -Method Get

[PSCustomObject]@{
    DocumentName   = $doc.name
    ToolVersion    = $doc.fields.tool_version.stringValue
    BuildId        = $doc.fields.build_id.stringValue
    ReportId       = $doc.fields.report_id.stringValue
    FileType       = $doc.fields.file_type.stringValue
    TotalGadgets   = $doc.fields.total_gadgets.integerValue
    GadgetsCount   = $doc.fields.gadgets.arrayValue.values.Count
    NxCompat       = $doc.fields.protections.mapValue.fields.NX_COMPAT.mapValue.fields.static_indicator.stringValue
    DynamicBase    = $doc.fields.protections.mapValue.fields.DYNAMIC_BASE.mapValue.fields.static_indicator.stringValue
    CetCompat      = $doc.fields.protections.mapValue.fields.CET_COMPAT.mapValue.fields.static_indicator.stringValue
    GsCookie       = $doc.fields.protections.mapValue.fields.GS_COOKIE.mapValue.fields.static_indicator.stringValue
    SafeSEH        = $doc.fields.protections.mapValue.fields.SafeSEH.mapValue.fields.static_indicator.stringValue
    RelroPresent   = ($doc.fields.protections.mapValue.fields.RELRO -ne $null)
    RopChainStatus = $doc.fields.rop_chain_generation.mapValue.fields.status.stringValue
    RawPayloadStatus = $doc.fields.raw_payload.mapValue.fields.status.stringValue
    PaddingOffset  = $doc.fields.raw_payload.mapValue.fields.verified_padding_offset.nullValue
} | Format-List
