param(
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,            # e.g. \\192.168.10.198\STIG-Results

    [Parameter(Mandatory = $true)]
    [string]$RoleName,             # domain_controllers, member_servers, workstations

    [string]$OutputName = "SummaryReport-Rollup.html",

    [string]$OutputFolder = ""     # e.g. \\192.168.10.198\STIG-Results\Reports
)

# --- AWX-safe: Do NOT modify UNC slashes ---
$ShareRoot    = $ShareRoot.Trim()
$OutputFolder = $OutputFolder.Trim()

Write-Host "=== STIG Rollup Report (CKL-based) ==="
Write-Host "Share Root : $ShareRoot"
Write-Host "Role Name  : $RoleName"
Write-Host "Output Name: $OutputName"
Write-Host "OutputFolder: $OutputFolder"

# Build: \\server\STIG-Results\<role>
$rolePath = Join-Path -Path $ShareRoot -ChildPath $RoleName

if (-not (Test-Path -Path $rolePath)) {
    throw "Role path '$rolePath' does not exist. Verify ShareRoot and RoleName."
}

# list DC1, WINDC2, etc.
$hostDirs = Get-ChildItem -Directory -Path $rolePath | Where-Object { $_.Name -ne "Reports" }

if ($hostDirs.Count -eq 0) {
    throw "No host folders found under '$rolePath'."
}

# ---------- FINDINGS ROLLOUP ----------
$findingsIndex = @{}

function Get-OverallStatus {
    param([string[]]$Statuses)

    if ($Statuses -contains "Open") { return "Open" }
    if ($Statuses -contains "Not Reviewed") { return "Not Reviewed" }
    if ($Statuses -contains "Not_Reviewed") { return "Not Reviewed" }
    if ($Statuses -contains "Not Applicable" -and $Statuses.Count -eq 1) { return "Not Applicable" }
    if ($Statuses -contains "NotAFinding") { return "Not a Finding" }

    return ($Statuses | Select-Object -First 1)
}

foreach ($hostDir in $hostDirs) {

    $hostName = $hostDir.Name
    $cklFolder = Join-Path -Path $hostDir.FullName -ChildPath "Checklist"

    if (-not (Test-Path $cklFolder)) {
        Write-Warning "Checklist folder missing for host '$hostName'"
        continue
    }

    # Get all CKL files inside Checklist folder
    $cklFiles = Get-ChildItem -Path $cklFolder -Filter *.ckl

    if ($cklFiles.Count -eq 0) {
        Write-Warning "No CKLs found for host '$hostName' in $cklFolder"
        continue
    }

    foreach ($ckl in $cklFiles) {
        Write-Host "Processing CKL: $($ckl.FullName) for host $hostName"

        [xml]$xml = Get-Content -Path $ckl.FullName

        # Extract <STIGS><iSTIG><VULN>
        $vulns = $xml.CHECKLIST.STIGS.iSTIG.VULN

        if (-not $vulns) {
            Write-Warning "No <VULN> entries found in CKL '$($ckl.FullName)'"
            continue
        }

        foreach ($v in $vulns) {

            $vulnId = ($v.VULN_ATTRIBUTE | Where-Object { $_.ATTR_NAME -eq "Vuln_Num" }).ATTRIBUTE_DATA
            $ruleId = ($v.VULN_ATTRIBUTE | Where-Object { $_.ATTR_NAME -eq "Rule_ID" }).ATTRIBUTE_DATA
            $ruleTitle = ($v.VULN_ATTRIBUTE | Where-Object { $_.ATTR_NAME -eq "Rule_Title" }).ATTRIBUTE_DATA
            $severity = ($v.VULN_ATTRIBUTE | Where-Object { $_.ATTR_NAME -eq "Severity" }).ATTRIBUTE_DATA
            $status = $v.STATUS

            if ([string]::IsNullOrWhiteSpace($vulnId)) {
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
                    RiskRating   = $severity
                    HostStatuses = @{}
                }
            }

            $findingsIndex[$vulnId].HostStatuses[$hostName] = $status
        }
    }
}

# --------- BUILD FINAL ROLLOUP ARRAY ----------
$totalHosts = $hostDirs.Count
$rolledUp = foreach ($rec in $findingsIndex.Values) {

    $statuses = $rec.HostStatuses.Values
    $overall = Get-OverallStatus -Statuses $statuses

    $affectedHosts = @(
        foreach ($kv in $rec.HostStatuses.GetEnumerator()) {
            if ($kv.Value -ne "NotAFinding" -and $kv.Value -ne "Not a Finding") {
                $kv.Key
            }
        }
    )

    [PSCustomObject]@{
        VulnId        = $rec.VulnId
        RuleId        = $rec.RuleId
        RuleTitle     = $rec.RuleTitle
        RiskRating    = $rec.RiskRating
        OverallStatus = $overall
        AffectedCount = $affectedHosts.Count
        AffectedHosts = ($affectedHosts -join ", ")
    }
}

$now = Get-Date

# ---------- HTML REPORT ----------
$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>STIG Rollup Report - $RoleName</title>
<style>
body { font-family: Segoe UI, Arial; margin: 20px; }
h1 { color: #333; }
table { width: 100%; border-collapse: collapse; margin-top: 15px; }
th, td { border: 1px solid #ccc; padding: 6px 8px; }
th { background: #f0f0f0; }
.status-open { background-color: #fdecea; }
.status-notreviewed { background-color: #fff6e5; }
.risk-high { color: #c0392b; font-weight: bold; }
.risk-medium { color: #f39c12; font-weight: bold; }
.risk-low { color: #27ae60; font-weight: bold; }
</style>
</head>
<body>

<h1>STIG Rollup - $RoleName</h1>
<p><strong>Generated:</strong> $($now.ToString("yyyy-MM-dd HH:mm:ss"))</p>

<table>
<thead>
<tr>
    <th>Vuln ID</th>
    <th>Rule ID</th>
    <th>Title</th>
    <th>Risk</th>
    <th>Status</th>
    <th>Affected Hosts</th>
</tr>
</thead>
<tbody>
"@

foreach ($item in $rolledUp | Sort-Object RiskRating, VulnId) {

    switch ($item.OverallStatus) {
        "Open"         { $rowClass = "status-open" }
        "Not Reviewed" { $rowClass = "status-notreviewed" }
        default        { $rowClass = "" }
    }

    switch -Regex ($item.RiskRating) {
        "high"   { $riskClass = "risk-high" }
        "medium" { $riskClass = "risk-medium" }
        "low"    { $riskClass = "risk-low" }
        default  { $riskClass = "" }
    }

    $html += @"
<tr class="$rowClass">
    <td>$($item.VulnId)</td>
    <td>$($item.RuleId)</td>
    <td>$([System.Web.HttpUtility]::HtmlEncode($item.RuleTitle))</td>
    <td class="$riskClass">$($item.RiskRating)</td>
    <td>$($item.OverallStatus)</td>
    <td>$($item.AffectedHosts)</td>
</tr>
"@
}

$html += @"
</tbody>
</table>

</body>
</html>
"@

# -------- OUTPUT LOCATION --------
if ($OutputFolder -ne "") {
    $outputPath = Join-Path -Path $OutputFolder -ChildPath $OutputName
} else {
    $outputPath = Join-Path -Path $rolePath -ChildPath $OutputName
}

$html | Set-Content -Path $outputPath -Encoding UTF8

Write-Host "Rollup report written to: $outputPath"
