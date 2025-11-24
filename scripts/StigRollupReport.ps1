<#
.SYNOPSIS
    STIG Rollup / CORA-style HTML report from Evaluate-STIG CSV exports.

.DESCRIPTION
    - Walks:  <ShareRoot>\<RoleName>\<Host>\Checklist\*.csv
    - Aggregates Open / Not Reviewed findings by Severity.
    - DEDUPES findings per role:
        STIG + VulnId + RuleId + Severity + Status
      and aggregates Host list as pills.
    - Produces a CORA-style summary and detailed tables grouped by STIG.

    Designed to work whether ShareRoot is a drive (F:\stig-results)
    or a UNC path (\\appsvr1\stig-results).

.PARAMETER ShareRoot
    Root folder of STIG results. Example:
        F:\stig-results
        \\appsvr1\stig-results

.PARAMETER RoleName
    Logical role folder under ShareRoot. Example:
        domain_controllers
        member_servers
        workstations

.PARAMETER OutputName
    Name of the HTML file to write (in <ShareRoot>\Reports).
    Example:
        SummaryReport-domain_controllers.html
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,

    [Parameter(Mandatory = $true)]
    [string]$RoleName,

    [Parameter(Mandatory = $true)]
    [string]$OutputName
)

# ----------------- Normalize Inputs -----------------
$ShareRoot  = $ShareRoot.Trim().TrimEnd('\')
$RoleName   = $RoleName.Trim()
$OutputName = $OutputName.Trim()

$rolePath     = Join-Path -Path $ShareRoot -ChildPath $RoleName
$outputFolder = Join-Path -Path $ShareRoot -ChildPath "Reports"

if (-not (Test-Path $rolePath)) {
    Write-Host "❌ Role path not found: $rolePath"
    throw "Role path '$rolePath' does not exist. Verify ShareRoot and RoleName."
}

if (-not (Test-Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

Write-Host "=== STIG Rollup Report (CSV-based, deduped) ==="
Write-Host "Share Root : $ShareRoot"
Write-Host "Role Name  : $RoleName"
Write-Host "Output Name: $OutputName"
Write-Host "Role Path  : $rolePath"
Write-Host "Output Dir : $outputFolder"

# ----------------- Helper: property resolution -----------------
function Get-ColValue {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Row,

        [Parameter(Mandatory = $true)]
        [string[]]$NameHints  # e.g. 'Vuln ID','VulnID'
    )

    $props = $Row.PSObject.Properties.Name
    foreach ($hint in $NameHints) {
        $match = $props | Where-Object { $_ -imatch [Regex]::Escape($hint) } | Select-Object -First 1
        if ($match) {
            return $Row.$match
        }
    }
    return $null
}

function Normalize-Severity {
    param([string]$Severity)

    if (-not $Severity) { return "Unknown" }
    $val = $Severity.Trim().ToLower()

    switch -Regex ($val) {
        'cat\s*1'      { "High"; break }
        'high'         { "High"; break }
        'cat\s*2'      { "Medium"; break }
        'medium'       { "Medium"; break }
        'cat\s*3'      { "Low"; break }
        'low'          { "Low"; break }
        default        { $Severity.Trim() }
    }
}

function Normalize-Status {
    param([string]$Status)

    if (-not $Status) { return "Unknown" }
    $val = $Status.Trim().ToLower()

    switch -Regex ($val) {
        '^open'                    { "Open"; break }
        'not[_\s]*reviewed'        { "Not Reviewed"; break }
        'not[_\s]*a[_\s]*finding'  { "Not a Finding"; break }
        'not[_\s]*app'             { "Not Applicable"; break }
        'na\b'                     { "Not Applicable"; break }
        'closed'                   { "Not a Finding"; break }
        default                    { $Status.Trim() }
    }
}

# ----------------- Collect Raw Data (CSV only) -----------------
$rawFindings = @()

$hostDirs = Get-ChildItem -Path $rolePath -Directory -ErrorAction SilentlyContinue
if (-not $hostDirs) {
    Write-Host "⚠ No host directories found under $rolePath"
}

foreach ($hostDir in $hostDirs) {
    $hostName = $hostDir.Name
    $checklistPath = Join-Path -Path $hostDir.FullName -ChildPath "Checklist"

    if (-not (Test-Path $checklistPath)) {
        Write-Host "  ⚠ Skipping $hostName - no Checklist folder."
        continue
    }

    $csvFiles = Get-ChildItem -Path $checklistPath -Filter *.csv -ErrorAction SilentlyContinue

    if (-not $csvFiles) {
        Write-Host "  ⚠ Skipping $hostName - no CSV files in Checklist."
        continue
    }

    foreach ($csv in $csvFiles) {
        Write-Host "  📥 Processing CSV: $($csv.FullName)"

        try {
            $data = Import-Csv -Path $csv.FullName -ErrorAction Stop
        }
        catch {
            Write-Host "    ❌ Failed to read CSV: $($_.Exception.Message)"
            continue
        }

        foreach ($row in $data) {
            $vulnId  = Get-ColValue -Row $row -NameHints @('Vuln ID','VulnID','Vulnerability ID')
            $ruleId  = Get-ColValue -Row $row -NameHints @('Rule ID','RuleID')
            $status  = Get-ColValue -Row $row -NameHints @('Status','Check Status','Finding Status')
            $sev     = Get-ColValue -Row $row -NameHints @('Severity','Severity Level')
            $stig    = Get-ColValue -Row $row -NameHints @('STIG','Benchmark','STIG Name','STIG Title')
            $asset   = Get-ColValue -Row $row -NameHints @('Host Name','Asset Name','Computer Name','System Name')

            if (-not $asset) { $asset = $hostName }
            $severityNorm = Normalize-Severity -Severity $sev
            $statusNorm   = Normalize-Status   -Status   $status

            # Only care about things that are Open / Not Reviewed for reporting
            if ($statusNorm -in @('Open','Not Reviewed')) {
                $rawFindings += [PSCustomObject]@{
                    Host     = $asset
                    STIG     = if ($stig) { $stig } else { '(Unknown STIG)' }
                    VulnId   = if ($vulnId) { $vulnId } else { '' }
                    RuleId   = if ($ruleId) { $ruleId } else { '' }
                    Severity = $severityNorm
                    Status   = $statusNorm
                }
            }
        }
    }
}

if (-not $rawFindings) {
    Write-Host "✅ No Open or Not Reviewed findings found for role '$RoleName'."
}

# ----------------- DEDUPE Findings (per role) -----------------
# Key: STIG + VulnId + RuleId + Severity + Status
$dedup = @{}

foreach ($f in $rawFindings) {
    $key = "{0}|{1}|{2}|{3}|{4}" -f $f.STIG, $f.VulnId, $f.RuleId, $f.Severity, $f.Status

    if (-not $dedup.ContainsKey($key)) {
        $dedup[$key] = [ordered]@{
            STIG     = $f.STIG
            VulnId   = $f.VulnId
            RuleId   = $f.RuleId
            Severity = $f.Severity
            Status   = $f.Status
            Hosts    = @($f.Host)
        }
    }
    else {
        if (-not ($dedup[$key].Hosts -contains $f.Host)) {
            $dedup[$key].Hosts += $f.Host
        }
    }
}

# Final deduped rows for reporting
$rows = @()
if ($dedup.Count -gt 0) {
    $rows = $dedup.Values
}

# Unique host count (based on raw findings)
$totalHosts = ($rawFindings | Select-Object -ExpandProperty Host -Unique).Count

# ----------------- Build CORA-style summary (based on deduped findings) -----------------
$severityOrder = @('High','Medium','Low')
$summary = @()

foreach ($sev in $severityOrder) {
    $rowsBySev = $rows | Where-Object { $_.Severity -eq $sev }

    if (-not $rowsBySev) {
        $summary += [PSCustomObject]@{
            Severity    = $sev
            Open        = 0
            NotReviewed = 0
            Total       = 0
            PctNR       = 0
        }
        continue
    }

    $open        = ($rowsBySev | Where-Object { $_.Status -eq 'Open' }).Count
    $notReviewed = ($rowsBySev | Where-Object { $_.Status -eq 'Not Reviewed' }).Count
    $total       = $open + $notReviewed
    $pctNR       = if ($total -gt 0) { [math]::Round(($notReviewed * 100.0) / $total, 1) } else { 0 }

    $summary += [PSCustomObject]@{
        Severity    = $sev
        Open        = $open
        NotReviewed = $notReviewed
        Total       = $total
        PctNR       = $pctNR
    }
}

# Weighted average & risk label
$weights = @{
    'High'   = 3
    'Medium' = 2
    'Low'    = 1
}

$weightedNumerator = 0.0
$weightedDenom     = 0.0

foreach ($row in $summary) {
    $w = $weights[$row.Severity]
    if (-not $w) { continue }
    $weightedNumerator += $row.PctNR * $w * $row.Total
    $weightedDenom     += $w * $row.Total
}

$weightedAverage = if ($weightedDenom -gt 0) {
    [math]::Round($weightedNumerator / $weightedDenom, 1)
} else { 0 }

function Get-RiskRating {
    param([double]$Score)

    if     ($Score -ge 80) { "Very High Risk" }
    elseif ($Score -ge 60) { "High Risk" }
    elseif ($Score -ge 40) { "Moderate Risk" }
    elseif ($Score -ge 20) { "Low Risk" }
    else                   { "Very Low Risk" }
}

$riskRating = Get-RiskRating -Score $weightedAverage

# ----------------- Build HTML -----------------
$timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$css = @"
<style>
    body {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background-color: #f5f7fb;
        color: #222;
        margin: 0;
        padding: 0;
    }
    .page {
        max-width: 1200px;
        margin: 24px auto;
        background: #ffffff;
        border-radius: 10px;
        box-shadow: 0 4px 16px rgba(15,23,42,0.12);
        padding: 24px 28px 32px 28px;
    }
    h1 {
        font-size: 24px;
        margin-top: 0;
        margin-bottom: 4px;
    }
    h2 {
        font-size: 18px;
        margin-top: 32px;
        margin-bottom: 8px;
    }
    h3 {
        font-size: 16px;
        margin-top: 24px;
        margin-bottom: 6px;
    }
    .meta {
        font-size: 12px;
        color: #6b7280;
        margin-bottom: 18px;
    }
    .pill {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: .04em;
    }
    .pill-role      { background: #eff6ff; color: #1d4ed8; }
    .pill-generated { background: #ecfdf3; color: #16a34a; }
    .pill-weighted  { background: #fef3c7; color: #92400e; }

    table {
        border-collapse: collapse;
        width: 100%;
        margin-top: 8px;
        margin-bottom: 18px;
        font-size: 13px;
    }
    th, td {
        padding: 6px 8px;
        border: 1px solid #e5e7eb;
    }
    th {
        background: #f9fafb;
        text-align: left;
        font-weight: 600;
    }
    tr:nth-child(even) td {
        background-color: #f9fafb;
    }
    .sev-high   { color: #b91c1c; font-weight: 600; }
    .sev-medium { color: #c05621; font-weight: 600; }
    .sev-low    { color: #065f46; font-weight: 600; }
    .status-open         { color: #b91c1c; }
    .status-notreviewed  { color: #92400e; }
    .status-na           { color: #4b5563; }

    .section-header {
        background: #eff6ff;
        padding: 8px 10px;
        margin-top: 20px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 13px;
    }
    .tiny {
        font-size: 11px;
        color: #6b7280;
    }
    .host-pill {
        display: inline-block;
        padding: 2px 8px;
        margin: 2px 4px 2px 0;
        border-radius: 999px;
        background: #eff6ff;
        color: #111827;
        font-size: 11px;
        border: 1px solid #d1d5db;
    }
</style>
"@

$html = @()
$html += "<!DOCTYPE html>"
$html += "<html lang='en'>"
$html += "<head>"
$html += "  <meta charset='utf-8' />"
$html += "  <title>STIG Rollup Report - Role: $RoleName</title>"
$html += $css
$html += "</head>"
$html += "<body>"
$html += "<div class='page'>"

$html += "<h1>STIG Rollup Report &mdash; Role: $RoleName</h1>"
$html += "<div class='meta'>"
$html += "  <span class='pill pill-role'>Role: $RoleName</span>"
$html += "  <span class='pill pill-generated'>Generated: $timeStamp</span>"
$html += "  <span class='pill pill-weighted'>Weighted CORA Score: $weightedAverage`%</span>"
$html += "  <div>Total Unique Hosts with Open/NR Findings: $totalHosts</div>"
$html += "  <div>Risk Rating: <strong>$riskRating</strong></div>"
$html += "</div>"

# CORA Summary table
$html += "<h2>CORA Risk Summary (Deduped Findings)</h2>"
$html += "<table>"
$html += "  <thead>"
$html += "    <tr><th>Category</th><th>Severity</th><th>Open</th><th>Not Reviewed</th><th>Total Unique Findings</th><th>% NR Open</th></tr>"
$html += "  </thead>"
$html += "  <tbody>"

foreach ($row in $summary) {
    $sevClass = switch ($row.Severity) {
        'High'   { 'sev-high' }
        'Medium' { 'sev-medium' }
        'Low'    { 'sev-low' }
        default  { '' }
    }
    $cat = switch ($row.Severity) {
        'High'   { 'CAT I' }
        'Medium' { 'CAT II' }
        'Low'    { 'CAT III' }
        default  { '' }
    }
    $html += "    <tr>"
    $html += "      <td>$cat</td>"
    $html += "      <td class='$sevClass'>$($row.Severity)</td>"
    $html += "      <td>$($row.Open)</td>"
    $html += "      <td>$($row.NotReviewed)</td>"
    $html += "      <td>$($row.Total)</td>"
    $html += "      <td>$($row.PctNR)%</td>"
    $html += "    </tr>"
}

$html += "  </tbody>"
$html += "</table>"
$html += "<div class='tiny'>Counts are based on deduplicated findings per role (STIG + Vuln + Rule + Severity + Status). Hosts are aggregated per finding.</div>"

# Detailed findings by STIG
$groupedByStig = $rows | Sort-Object STIG, Severity, VulnId, RuleId | Group-Object STIG

foreach ($stigGroup in $groupedByStig) {
    $stigName = $stigGroup.Name
    $html += "<div class='section-header'>STIG: $stigName</div>"

    $html += "<table>"
    $html += "  <thead>"
    $html += "    <tr><th>Vuln ID</th><th>Rule ID</th><th>Severity</th><th>Status</th><th>Affected Hosts</th></tr>"
    $html += "  </thead>"
    $html += "  <tbody>"

    foreach ($item in $stigGroup.Group) {
        $sevClass = switch ($item.Severity) {
            'High'   { 'sev-high' }
            'Medium' { 'sev-medium' }
            'Low'    { 'sev-low' }
            default  { '' }
        }
        $statusClass = switch ($item.Status) {
            'Open'          { 'status-open' }
            'Not Reviewed'  { 'status-notreviewed' }
            'Not Applicable'{ 'status-na' }
            default         { '' }
        }

        $hostHtml = ($item.Hosts | Sort-Object | ForEach-Object {
            "<span class='host-pill'>$_</span>"
        }) -join " "

        $html += "    <tr>"
        $html += "      <td>$($item.VulnId)</td>"
        $html += "      <td>$($item.RuleId)</td>"
        $html += "      <td class='$sevClass'>$($item.Severity)</td>"
        $html += "      <td class='$statusClass'>$($item.Status)</td>"
        $html += "      <td>$hostHtml</td>"
        $html += "    </tr>"
    }

    $html += "  </tbody>"
    $html += "</table>"
}

if (-not $rows) {
    $html += "<h2>No Open or Not Reviewed findings</h2>"
    $html += "<p>All findings for this role appear to be closed or not applicable based on the CSV data.</p>"
}

$html += "</div>"   # .page
$html += "</body>"
$html += "</html>"

# ----------------- Write Output -----------------
$outFile = Join-Path -Path $outputFolder -ChildPath $OutputName
$html -join "`r`n" | Set-Content -Path $outFile -Encoding UTF8

Write-Host "✅ STIG rollup report created:"
Write-Host "   $outFile"
