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

# --------------------------------------------------------
# 0. Prep & basic validation
# --------------------------------------------------------
$rolePath = Join-Path -Path $ShareRoot -ChildPath $RoleName

if (-not (Test-Path -Path $rolePath)) {
    throw "Role path '$rolePath' does not exist. Verify ShareRoot and RoleName."
}

$hostDirs = Get-ChildItem -Path $rolePath -Directory -ErrorAction SilentlyContinue
if (-not $hostDirs -or $hostDirs.Count -eq 0) {
    throw "No host folders found under '$rolePath'."
}

# We'll collect all findings here, keyed by VulnId (Vuln_Num)
$findingsIndex = @{}

# For global STIG metadata (title/version) we just grab the first CKL we see
$globalStigTitle   = $null
$globalStigVersion = $null
$globalEvalVersion = "N/A (CKL only)"

# --------------------------------------------------------
# Helper: pick overall status based on per-host statuses
# --------------------------------------------------------
function Get-OverallStatus {
    param(
        [string[]]$Statuses
    )

    # Normalize case
    $Statuses = $Statuses | ForEach-Object { ($_ -as [string]).Trim() }

    if ($Statuses -contains "Open") { return "Open" }

    if ($Statuses -contains "Not Reviewed" -or $Statuses -contains "Not_Reviewed") {
        return "Not Reviewed"
    }

    if ($Statuses -contains "Not Applicable" -and $Statuses.Count -eq 1) {
        return "Not Applicable"
    }

    if ($Statuses -contains "NotAFinding" -or $Statuses -contains "Not a Finding") {
        return "Not a Finding"
    }

    # Fallback
    return ($Statuses | Select-Object -First 1)
}

# --------------------------------------------------------
# Helper: pull a STIG_DATA value from a VULN by attribute name
# --------------------------------------------------------
function Get-StigDataValue {
    param(
        [xml]$VulnNode,
        [string]$AttributeName
    )

    $match = $VulnNode.STIG_DATA |
        Where-Object { $_.VULN_ATTRIBUTE -eq $AttributeName } |
        Select-Object -First 1

    if ($null -eq $match) { return "" }

    # Use Out-String + Trim to be safe
    return ($match.ATTRIBUTE_DATA | Out-String).Trim()
}

# --------------------------------------------------------
# 1. Walk each host folder and parse all CKLs
# --------------------------------------------------------
foreach ($hostDir in $hostDirs) {
    $hostName = $hostDir.Name

    # Find all CKLs under this host (Checklist subfolder, etc.)
    $cklFiles = Get-ChildItem -Path $hostDir.FullName -Filter '*.ckl' -Recurse -ErrorAction SilentlyContinue

    if (-not $cklFiles -or $cklFiles.Count -eq 0) {
        Write-Warning "No CKL files found for host '$hostName' under '$($hostDir.FullName)'. Skipping."
        continue
    }

    foreach ($ckl in $cklFiles) {
        Write-Host "Processing CKL: $($ckl.FullName) for host $hostName"

        [xml]$cklXml = Get-Content -Path $ckl.FullName

        $stigNodes = $cklXml.CHECKLIST.STIGS.STIG
        if (-not $stigNodes) {
            Write-Warning "No <STIG> nodes found in CKL '$($ckl.FullName)'."
            continue
        }

        # Grab metadata (title/version/release) from the first STIG once
        if (-not $globalStigTitle -or -not $globalStigVersion) {
            $firstStig = $stigNodes | Select-Object -First 1
            if ($firstStig.STIG_INFO) {
                $si = $firstStig.STIG_INFO.SI_DATA
                if ($si) {
                    $meta = @{}
                    foreach ($m in $si) {
                        $name = ($m.SID_NAME | Out-String).Trim()
                        $data = ($m.SID_DATA | Out-String).Trim()
                        if ($name) { $meta[$name] = $data }
                    }

                    $globalStigTitle   = $meta['title']
                    $globalStigVersion = $meta['releaseinfo']
                }
            }
        }

        # For each STIG node, parse its VULNs
        foreach ($stig in $stigNodes) {
            $vulns = $stig.VULN
            if (-not $vulns) { continue }

            foreach ($v in $vulns) {
                $vulnId    = Get-StigDataValue -VulnNode $v -AttributeName 'Vuln_Num'
                $ruleId    = Get-StigDataValue -VulnNode $v -AttributeName 'Rule_ID'
                $ruleTitle = Get-StigDataValue -VulnNode $v -AttributeName 'Rule_Title'
                $severity  = Get-StigDataValue -VulnNode $v -AttributeName 'Severity'

                # CKL STATUS (Open / NotAFinding / Not_Reviewed / Not Applicable)
                $statusRaw = ($v.STATUS | Out-String).Trim()

                if ([string]::IsNullOrWhiteSpace($vulnId) -and -not [string]::IsNullOrWhiteSpace($ruleId)) {
                    $vulnId = $ruleId
                }
                if ([string]::IsNullOrWhiteSpace($vulnId)) {
                    continue
                }

                # Normalize status a bit
                $status = switch ($statusRaw) {
                    "NotAFinding"   { "Not a Finding" }
                    "Not_Reviewed"  { "Not Reviewed" }
                    "Not_Applicable" { "Not Applicable" }
                    default         { $statusRaw }
                }

                if (-not $findingsIndex.ContainsKey($vulnId)) {
                    $findingsIndex[$vulnId] = [PSCustomObject]@{
                        VulnId       = $vulnId
                        RuleId       = $ruleId
                        RuleTitle    = $ruleTitle
                        RiskRating   = $severity   # using CKL severity as "risk"
                        HostStatuses = @{}         # host -> status
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

# --------------------------------------------------------
# 2. Compute rollup stats
# --------------------------------------------------------
$totalHosts  = $hostDirs.Count
$allFindings = $findingsIndex.Values

if (-not $allFindings -or $allFindings.Count -eq 0) {
    throw "No findings were parsed from CKLs under '$rolePath'."
}

$rolledUp = foreach ($rec in $allFindings) {
    $statusesByHost = $rec.HostStatuses
    $hostsAffected  = $statusesByHost.Keys
    $statusValues   = $statusesByHost.Values

    $overallStatus = Get-OverallStatus -Statuses $statusValues

    # Hosts where status is not "Not a Finding"
    $affectedHosts = @(
        foreach ($kvp in $statusesByHost.GetEnumerator()) {
            if ($kvp.Value -ne "Not a Finding") {
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

$openFindings        = $rolledUp | Where-Object { $_.OverallStatus -eq "Open" }
$notReviewedFindings = $rolledUp | Where-Object { $_.OverallStatus -eq "Not Reviewed" }
$naFindings          = $rolledUp | Where-Object { $_.OverallStatus -eq "Not Applicable" }

$totalUniqueFindings = $rolledUp.Count
$totalOpen           = $openFindings.Count
$totalNotReviewed    = $notReviewedFindings.Count
$totalNA             = $naFindings.Count

# Simple compliance % (by unique finding)
$compliancePercent = if ($totalUniqueFindings -gt 0) {
    [math]::Round(100 * (($totalUniqueFindings - $totalOpen) / $totalUniqueFindings), 2)
} else {
    0
}

# If for some reason we never set metadata, just default
if (-not $globalStigTitle)   { $globalStigTitle   = "Unknown STIG" }
if (-not $globalStigVersion) { $globalStigVersion = "Unknown Version" }

$now = Get-Date

# Needed for HTML encoding of titles
Add-Type -AssemblyName System.Web

# --------------------------------------------------------
# 3. Build HTML (same look & feel you had)
# --------------------------------------------------------
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
    <p><strong>Source:</strong> CKL files (Evaluate-STIG version not available from CKL)</p>
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
                <th>Severity</th>
                <th>Overall Status</th>
                <th>Affected Hosts</th>
            </tr>
        </thead>
        <tbody>
"@

# Build table rows
$rows = @()

$interesting = $rolledUp |
    Where-Object { $_.OverallStatus -in @("Open", "Not Reviewed") } |
    Sort-Object RiskRating, VulnId

foreach ($item in $interesting) {
    $rowClass = ""
    switch ($item.OverallStatus) {
        "Open"         { $rowClass = "status-open" }
        "Not Reviewed" { $rowClass = "status-notreviewed" }
    }

    $riskClass = ""
    switch -Regex ($item.RiskRating) {
        "high"   { $riskClass = "risk-high" }
        "medium" { $riskClass = "risk-medium" }
        "low"    { $riskClass = "risk-low" }
    }

    $affectedSummary = if ($item.AffectedCount -gt 0) {
        "$($item.AffectedCount) of $($item.TotalHosts) $RoleName (Hosts affected: $($item.AffectedHosts))"
    }
    else {
        "0 of $($item.TotalHosts) $RoleName"
    }

    $encodedTitle = [System.Web.HttpUtility]::HtmlEncode($item.RuleTitle)

    $rows += @"
            <tr class="$rowClass">
                <td>$($item.VulnId)</td>
                <td>$($item.RuleId)</td>
                <td>$encodedTitle</td>
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

# --------------------------------------------------------
# 4. Write HTML to local ProgramData\StigRollup
# --------------------------------------------------------
$localDir = "C:\ProgramData\StigRollup"
if (-not (Test-Path -Path $localDir)) {
    New-Item -ItemType Directory -Path $localDir -Force | Out-Null
}

$outputPath = Join-Path -Path $localDir -ChildPath $OutputName
$html | Set-Content -Path $outputPath -Encoding UTF8

Write-Host "Rollup report written to: $outputPath"
