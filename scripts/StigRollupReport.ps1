param(
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,        # e.g. \\server\STIG-Results

    [Parameter(Mandatory = $true)]
    [string]$RoleName,         # e.g. Domain-Controllers, Member-Servers, Workstations

    [string]$OutputName = "SummaryReport-Rollup.html"
)

Write-Host "=== STIG Rollup Report ==="
Write-Host "Share Root : $ShareRoot"
Write-Host "Role Name  : $RoleName"
Write-Host "Output Name: $OutputName"

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
# Key will be VulnId (e.g. V-12345) – adjust if your XML uses a different ID
$findingsIndex = @{}

# Helper function: pick overall status based on per-host statuses
function Get-OverallStatus {
    param(
        [string[]]$Statuses
    )

    # Adjust priorities if your workflow uses different values
    if ($Statuses -contains "Open") { return "Open" }
    if ($Statuses -contains "Not Reviewed") { return "Not Reviewed" }
    if ($Statuses -contains "Not_Reviewed") { return "Not Reviewed" }
    if ($Statuses -contains "Not Applicable" -and $Statuses.Count -eq 1) { return "Not Applicable" }
    if ($Statuses -contains "NotAFinding") { return "Not a Finding" }

    return ($Statuses | Select-Object -First 1)
}

# Loop each host's SummaryReport.xml
foreach ($hostDir in $hostDirs) {
    $hostName = $hostDir.Name
    $summaryPath = Join-Path -Path $hostDir.FullName -ChildPath "SummaryReport.xml"

    if (-not (Test-Path -Path $summaryPath)) {
        Write-Warning "SummaryReport.xml not found for host '$hostName' at '$summaryPath'. Skipping."
        continue
    }

    Write-Host "Processing $summaryPath for host $hostName"

    [xml]$xml = Get-Content -Path $summaryPath

    # ⚠️ ADJUST THESE XPATHS/PROPERTIES TO MATCH YOUR ACTUAL SummaryReport.xml
    # Assumed structure:
    # <SummaryReport>
    #   <Metadata>
    #     <ComputerName>dc1</ComputerName>
    #     <StigTitle>...</StigTitle>
    #     <StigVersion>...</StigVersion>
    #     <EvaluateStigVersion>...</EvaluateStigVersion>
    #   </Metadata>
    #   <Findings>
    #     <Finding>
    #       <VulnId>V-12345</VulnId>
    #       <RuleId>SV-12345r1_rule</RuleId>
    #       <RuleTitle>Some rule</RuleTitle>
    #       <RiskRating>Medium</RiskRating>   # CORA rating
    #       <Status>Open</Status>            # Open / NotAFinding / Not Reviewed / Not Applicable
    #     </Finding>
    #   </Findings>
    # </SummaryReport>

    $metadata = $xml.SummaryReport.Metadata
    if (-not $metadata) {
        Write-Warning "Metadata node not found in $summaryPath"
    }

    $stigTitle           = $metadata.StigTitle
    $stigVersion         = $metadata.StigVersion
    $evalStigVersion     = $metadata.EvaluateStigVersion
    $summaryComputerName = $metadata.ComputerName

    if ($summaryComputerName -and ($summaryComputerName -ne $hostName)) {
        Write-Host "Note: Host folder '$hostName' has metadata ComputerName '$summaryComputerName'"
    }

    $findings = $xml.SummaryReport.Findings.Finding
    if (-not $findings) {
        Write-Warning "No <Finding> elements found in $summaryPath"
        continue
    }

    foreach ($f in $findings) {
        $vulnId     = ($f.VulnId   | Out-String).Trim()
        $ruleId     = ($f.RuleId   | Out-String).Trim()
        $ruleTitle  = ($f.RuleTitle| Out-String).Trim()
        $riskRating = ($f.RiskRating | Out-String).Trim()
        $status     = ($f.Status   | Out-String).Trim()

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
                StigTitle    = $stigTitle
                StigVersion  = $stigVersion
                EvalVersion  = $evalStigVersion
            }
        }

        $record = $findingsIndex[$vulnId]
        $record.HostStatuses[$hostName] = $status
    }
}

# Compute rollup stats
$totalHosts       = $hostDirs.Count
$allFindings      = $findingsIndex.Values

# For each finding, compute overall status + host counts
$rolledUp = foreach ($rec in $allFindings) {
    $statusesByHost = $rec.HostStatuses
    $hostsAffected  = $statusesByHost.Keys
    $statusValues   = $statusesByHost.Values

    $overallStatus = Get-OverallStatus -Statuses $statusValues

    # Count hosts where status is not "NotAFinding"
    $affectedHosts = @(
        foreach ($kvp in $statusesByHost.GetEnumerator()) {
            if ($kvp.Value -ne "NotAFinding" -and $kvp.Value -ne "Not a Finding") {
                $kvp.Key
            }
        }
    )

    [PSCustomObject]@{
        VulnId          = $rec.VulnId
        RuleId          = $rec.RuleId
        RuleTitle       = $rec.RuleTitle
        RiskRating      = $rec.RiskRating
        OverallStatus   = $overallStatus
        TotalHosts      = $totalHosts
        AffectedCount   = $affectedHosts.Count
        AffectedHosts   = if ($affectedHosts.Count -gt 0) { $affectedHosts -join ", " } else { "" }
        StigTitle       = $rec.StigTitle
        StigVersion     = $rec.StigVersion
        EvalVersion     = $rec.EvalVersion
    }
}

# Filter to only relevant overall statuses
$openFindings         = $rolledUp | Where-Object { $_.OverallStatus -eq "Open" }
$notReviewedFindings  = $rolledUp | Where-Object { $_.OverallStatus -eq "Not Reviewed" }
$naFindings           = $rolledUp | Where-Object { $_.OverallStatus -eq "Not Applicable" }

$totalUniqueFindings  = $rolledUp.Count
$totalOpen            = $openFindings.Count
$totalNotReviewed     = $notReviewedFindings.Count
$totalNA              = $naFindings.Count

# Simple "compliance %" = 1 - (open / total)
$compliancePercent = if ($totalUniqueFindings -gt 0) {
    [math]::Round(100 * (($totalUniqueFindings - $totalOpen) / $totalUniqueFindings), 2)
} else {
    0
}

# Use metadata from the first finding as overall STIG info
$sample = $rolledUp | Select-Object -First 1
$globalStigTitle   = $sample.StigTitle
$globalStigVersion = $sample.StigVersion
$globalEvalVersion = $sample.EvalVersion

$now = Get-Date

# Build HTML
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
        how many systems are impacted and which ones, e.g. <em>"2 of 2 Domain Controllers (Hosts affected: dc1, windc2)"</em>.
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

# Write the HTML file to the role folder
$outputPath = Join-Path -Path $rolePath -ChildPath $OutputName
$html | Set-Content -Path $outputPath -Encoding UTF8

Write-Host "Rollup report written to: $outputPath"

