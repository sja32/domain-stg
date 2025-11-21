param(
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,        # e.g. \\192.168.10.198\STIG-Results

    [Parameter(Mandatory = $true)]
    [string]$RoleName,         # e.g. domain_controllers, member_servers, workstations

    [string]$OutputName = "SummaryReport-Rollup.html"
)

Write-Host "=== STIG Rollup Report (CKL-based) ==="
Write-Host "Share Root : $ShareRoot"
Write-Host "Role Name  : $RoleName"
Write-Host "Output Name: $OutputName"

# Example expected layout:
# \\server\STIG-Results\<RoleName>\<Host>\Checklist\*.ckl

$rolePath = Join-Path -Path $ShareRoot -ChildPath $RoleName

if (-not (Test-Path -Path $rolePath)) {
    throw "Role path '$rolePath' does not exist. Verify ShareRoot and RoleName."
}

# Collect host folders (each host has its own subfolder)
$hostDirs = Get-ChildItem -Path $rolePath -Directory
if ($hostDirs.Count -eq 0) {
    throw "No host folders found under '$rolePath'."
}

# Hashtable to hold rollup by finding key
# Key will be VulnId (e.g. V-12345)
$findingsIndex = @{}

# Helper function: pick overall status based on per-host statuses
function Get-OverallStatus {
    param(
        [string[]]$Statuses
    )

    if ($Statuses -contains "Open") { return "Open" }
    if ($Statuses -contains "Not Reviewed") { return "Not Reviewed" }
    if ($Statuses -contains "Not_Reviewed") { return "Not Reviewed" }
    if ($Statuses -contains "Not Applicable" -and $Statuses.Count -eq 1) { return "Not Applicable" }
    if ($Statuses -contains "NotAFinding") { return "Not a Finding" }

    return ($Statuses | Select-Object -First 1)
}

# Track some STIG metadata (best-effort from CKL STIG_INFO)
$globalStigTitle   = $null
$globalStigVersion = $null
$globalEvalVersion = "N/A (CKL-based)"

foreach ($hostDir in $hostDirs) {
    $hostName = $hostDir.Name
    $cklFolder = Join-Path -Path $hostDir.FullName -ChildPath "Checklist"

    if (-not (Test-Path -Path $cklFolder)) {
        Write-Warning "Checklist folder not found for host '$hostName' at '$cklFolder'. Skipping."
        continue
    }

    $cklFiles = Get-ChildItem -Path $cklFolder -Filter "*.ckl" -File
    if (-not $cklFiles) {
        Write-Warning "No CKL files found for host '$hostName' in '$cklFolder'. Skipping."
        continue
    }

    foreach ($ckl in $cklFiles) {
        Write-Host "Processing CKL: $($ckl.FullName) for host $hostName"

        [xml]$xml = Get-Content -Path $ckl.FullName

        # CKL structure: CHECKLIST -> STIGS -> (STIG or iSTIG) -> VULN
        $checklist = $xml.CHECKLIST
        if (-not $checklist) {
            Write-Warning "No <CHECKLIST> root found in '$($ckl.FullName)'. Skipping."
            continue
        }

        $stigNodes = @()

        if ($checklist.STIGS) {
            if ($checklist.STIGS.STIG)   { $stigNodes += $checklist.STIGS.STIG }
            if ($checklist.STIGS.iSTIG)  { $stigNodes += $checklist.STIGS.iSTIG }
        }

        if (-not $stigNodes -or $stigNodes.Count -eq 0) {
            Write-Warning "No <STIG> or <iSTIG> nodes found in CKL '$($ckl.FullName)'."
            continue
        }

        # Grab some metadata from the first STIG_INFO we see
        if (-not $globalStigTitle -or -not $globalStigVersion) {
            $firstStig = $stigNodes[0]
            $siData = $firstStig.STIG_INFO.SI_DATA
            if ($siData) {
                $titleNode   = $siData | Where-Object { $_.SID_NAME -eq "title" }
                $versionNode = $siData | Where-Object { $_.SID_NAME -eq "version" }

                if ($titleNode)   { $globalStigTitle   = $titleNode.SID_DATA }
                if ($versionNode) { $globalStigVersion = $versionNode.SID_DATA }
            }
        }

        foreach ($stig in $stigNodes) {
            # Each STIG has many VULN nodes
            $vulns = $stig.VULN
            if (-not $vulns) { continue }

            foreach ($v in $vulns) {
                # Build a lookup table of STIG_DATA attributes
                $dataMap = @{}

                foreach ($sd in $v.STIG_DATA) {
                    $attr = $sd.VULN_ATTRIBUTE
                    $val  = $sd.ATTRIBUTE_DATA
                    if ($attr) {
                        $dataMap[$attr] = $val
                    }
                }

                # STATUS is a direct child under VULN
                if ($v.STATUS) { $dataMap["STATUS"] = $v.STATUS }

                $vulnId     = $dataMap["Vuln_Num"]
                $ruleId     = $dataMap["Rule_ID"]
                $ruleTitle  = $dataMap["Rule_Title"]
                $riskRating = $dataMap["Severity"]
                $status     = $dataMap["STATUS"]

                if ([string]::IsNullOrWhiteSpace($vulnId)) {
                    # If VulnId is missing, fall back to RuleId as key
                    $vulnId = $ruleId
                }

                if ([string]::IsNullOrWhiteSpace($vulnId)) {
                    continue
                }

                if (-not $findingsIndex.ContainsKey($vulnId)) {
                    $findingsIndex[$vulnId] = [PSCustomObject]@{
                        VulnId       = $vulnId
                        RuleId       = $ruleId
                        RuleTitle    = $ruleTitle
                        RiskRating   = $riskRating
                        HostStatuses = @{}        # host -> status
                        StigTitle    = $globalStigTitle
                        StigVersion  = $globalStigVersion
                        EvalVersion  = $globalEvalVersion
                    }
                }

                $record = $findingsIndex[$vulnId]
                $record.HostStatuses[$hostName] = $status
            }
        }
    }
}

# Compute rollup stats
$totalHosts  = $hostDirs.Count
$allFindings = $findingsIndex.Values

if (-not $allFindings -or $allFindings.Count -eq 0) {
    throw "No findings were parsed from CKLs under '$rolePath'."
}

# For each finding, compute overall status + host counts
$rolledUp = foreach ($rec in $allFindings) {
    $statusesByHost = $rec.HostStatuses
    $hostsAffected  = $statusesByHost.Keys
    $statusValues   = $statusesByHost.Values

    $overallStatus = Get-OverallStatus -Statuses $statusValues

    $affectedHosts = @(
        foreach ($kvp in $statusesByHost.GetEnumerator()) {
            if ($kvp.Value -ne "NotAFinding" -and $kvp.Value -ne "Not a Finding") {
                $kvp.Key
            }
        }
    )

    [PSCustomObject]@{
        VulnId        = $rec.VulnId
        RuleId        = $rec.RuleId
        RuleTitle     = $rec.RuleTitle
        RiskRating    = $rec.RiskRating
        OverallStatus = $overallStatus
        TotalHosts    = $totalHosts
        AffectedCount = $affectedHosts.Count
        AffectedHosts = if ($affectedHosts.Count -gt 0) { $affectedHosts -join ", " } else { "" }
        StigTitle     = $rec.StigTitle
        StigVersion   = $rec.StigVersion
        EvalVersion   = $rec.EvalVersion
    }
}

# Filter to only relevant overall statuses
$openFindings        = $rolledUp | Where-Object { $_.OverallStatus -eq "Open" }
$notReviewedFindings = $rolledUp | Where-Object { $_.OverallStatus -eq "Not Reviewed" }
$naFindings          = $rolledUp | Where-Object { $_.OverallStatus -eq "Not Applicable" }

$totalUniqueFindings = $rolledUp.Count
$totalOpen           = $openFindings.Count
$totalNotReviewed    = $notReviewedFindings.Count
$totalNA             = $naFindings.Count

# Simple "compliance %" = 1 - (open / total)
$compliancePercent = if ($totalUniqueFindings -gt 0) {
    [math]::Round(100 * (($totalUniqueFindings - $totalOpen) / $totalUniqueFindings), 2)
} else {
    0
}

# Use metadata from the first finding as overall STIG info (already set above)
$now = Get-Date

# Build HTML (same layout you liked, just CKL-backed)
$html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>STIG Rollup Report - $RoleName</title>
    <style>
        body {
            font-family: Segoe UI, Arial, sans-serif;
            margin: 20px;
        }
        h1, h2, h3 {
            color: #333333;
        }
        .summary-card {
            border: 1px solid #dddddd;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 6px;
        }
        .summary-grid {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .stat-box {
            flex: 1 1 150px;
            border-radius: 6px;
            padding: 10px;
            color: #ffffff;
        }
        .stat-open { background-color: #c0392b; }
        .stat-notreviewed { background-color: #f39c12; }
        .stat-na { background-color: #7f8c8d; }
        .stat-compliance { background-color: #27ae60; }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 10px;
        }
        th, td {
            border: 1px solid #dddddd;
            padding: 6px 8px;
            text-align: left;
            font-size: 13px;
        }
        th {
            background-color: #f5f5f5;
        }
        .status-open { background-color: #fdecea; }
        .status-notreviewed { background-color: #fff6e5; }
        .status-na { background-color: #f2f2f2; }
        .risk-high { font-weight: bold; color: #c0392b; }
        .risk-medium { font-weight: bold; color: #f39c12; }
        .risk-low { font-weight: bold; color: #27ae60; }
        .small-text {
            font-size: 11px;
            color: #666666;
        }
    </style>
</head>
<body>

<h1>STIG Rollup Report - $RoleName</h1>

<div class="summary-card">
    <h2>Overview</h2>
    <p><strong>Generated:</strong> $($now.ToString("yyyy-MM-dd HH:mm:ss"))</p>
    <p><strong>Total Hosts in Scope:</strong> $totalHosts</p>
    <p><strong>STIG:</strong> $globalStigTitle</p>
    <p><strong>STIG Version:</strong> $globalStigVersion</p>
    <p><strong>Evaluate-STIG Version:</strong> $globalEvalVersion</p>
</div>

<div class="summary-card">
    <h2>High-Level Status</h2>
    <div class="summary-grid">
        <div class="stat-box stat-open">
            <h3>Open Findings</h3>
            <p><strong>$totalOpen</strong> unique</p>
        </div>
        <div class="stat-box stat-notreviewed">
            <h3>Not Reviewed</h3>
            <p><strong>$totalNotReviewed</strong> unique</p>
        </div>
        <div class="stat-box stat-na">
            <h3>Not Applicable</h3>
            <p><strong>$totalNA</strong> unique</p>
        </div>
        <div class="stat-box stat-compliance">
            <h3>Compliance</h3>
            <p><strong>$compliancePercent %</strong> (by unique finding)</p>
        </div>
    </div>
</div>

<div class="summary-card">
    <h2>Open & Not Reviewed Findings (Rolled Up)</h2>
    <p class="small-text">
        Each finding is listed once. The <strong>Affected Hosts</strong> column shows
        how many systems are impacted and which ones, e.g. <em>"2 of 2 $RoleName (Hosts affected: dc1, windc2)"</em>.
    </p>
    <table>
        <thead>
            <tr>
                <th>Vuln ID</th>
                <th>Rule ID</th>
                <th>Title</th>
                <th>Risk</th>
                <th>Overall Status</th>
                <th>Affected Hosts</th>
            </tr>
        </thead>
        <tbody>
"@

# Add Open + Not Reviewed rows
$rows = @()

foreach ($item in ($rolledUp | Where-Object { $_.OverallStatus -in @("Open", "Not Reviewed") } | Sort-Object RiskRating, VulnId)) {

    $rowClass = ""
    switch ($item.OverallStatus) {
        "Open"         { $rowClass = "status-open" }
        "Not Reviewed" { $rowClass = "status-notreviewed" }
    }

    $riskClass = ""
    switch -Regex ($item.RiskRating) {
        "High"   { $riskClass = "risk-high" }
        "Medium" { $riskClass = "risk-medium" }
        "Low"    { $riskClass = "risk-low" }
    }

    $affectedSummary = if ($item.AffectedCount -gt 0) {
        "$($item.AffectedCount) of $($item.TotalHosts) $RoleName (Hosts affected: $($item.AffectedHosts))"
    }
    else {
        "0 of $($item.TotalHosts) $RoleName"
    }

    $rows += @"
            <tr class="$rowClass">
                <td>$($item.VulnId)</td>
                <td>$($item.RuleId)</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($item.RuleTitle))</td>
                <td class="$riskClass">$($item.RiskRating)</td>
                <td>$($item.OverallStatus)</td>
                <td>$affectedSummary</td>
            </tr>
"@
}

if ($rows.Count -eq 0) {
    $rows += @"
            <tr>
                <td colspan="6">No Open or Not Reviewed findings in this rollup.</td>
            </tr>
"@
}

$html += ($rows -join "`r`n")

$html += @"
        </tbody>
    </table>
</div>

</body>
</html>
"@

# Write the HTML file to the role folder (next to the host folders)
$outputPath = Join-Path -Path $rolePath -ChildPath $OutputName
$html | Set-Content -Path $outputPath -Encoding UTF8

Write-Host "Rollup report written to: $outputPath"
