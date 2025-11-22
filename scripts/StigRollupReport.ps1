<#
.SYNOPSIS
    Consolidate multiple CKL files into a single rollup HTML report.

.DESCRIPTION
    This script parses DISA STIG CKL files under:
        \\SERVER\STIG-Results\<RoleName>\<Host>\Checklist\*.ckl

    It extracts:
        - VulnID (V-####)
        - RuleID
        - RuleTitle
        - Status (Open, NotAFinding, Not Reviewed, Not Applicable)
        - Severity (High/Medium/Low)

    It rolls them up across all hosts and generates ONE report per role.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,                 # e.g. \\192.168.10.198\STIG-Results

    [Parameter(Mandatory = $true)]
    [string]$RoleName,                  # domain_controllers, member_servers, workstations

    [string]$OutputName = "SummaryReport-Rollup.html",

    [string]$OutputFolder = ""          # If provided, report goes here
)

# --- SANITIZE UNC PATHS (Fix Double-Slash Issues) ---
function Fix-Unc {
    param([string]$p)
    if ($p -match '^\\[^\\]') {
        return ('\\' + $p)   # ensure UNC begins with \\ 
    }
    return $p
}

$ShareRoot    = Fix-Unc $ShareRoot
$OutputFolder = Fix-Unc $OutputFolder

Write-Host "=== STIG Rollup Report (CKL-based) ==="
Write-Host "Share Root : $ShareRoot"
Write-Host "Role Name  : $RoleName"
Write-Host "Output Name: $OutputName"
Write-Host "OutputFolder: $OutputFolder"

# Role folder: \\server\STIG-Results\domain_controllers
$rolePath = Join-Path -Path $ShareRoot -ChildPath $RoleName

if (-not (Test-Path -Path $rolePath)) {
    throw "Role path '$rolePath' does not exist. Verify ShareRoot and RoleName."
}

# Each host has a folder under domain_controllers
$hostDirs = Get-ChildItem -Directory -Path $rolePath | Where-Object { $_.Name -ne "Reports" }

if ($hostDirs.Count -eq 0) {
    throw "No host folders found under '$rolePath'."
}

# CKL Rollup storage
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
    $cklPath = Join-Path -Path $hostDir.FullName -ChildPath "Checklist"

    if (-not (Test-Path $cklPath)) {
        Write-Warning "Checklist folder missing for host '$hostName'"
        continue
    }

    $cklFiles = Get-ChildItem -Path $cklPath -Filter *.ckl
    if ($cklFiles.Count -eq 0) {
        Write-Warning "No CKL files found for host '$hostName' under '$cklPath'."
        continue
    }

    foreach ($cklFile in $cklFiles) {

        Write-Host "Processing CKL: $($cklFile.FullName) for host $hostName"

        [xml]$xml = Get-Content $cklFile.FullName

        # Correct DISA namespace path
        $stigNodes = $xml.CHECKLIST.STIGS.iSTIG

        if (-not $stigNodes) {
            Write-Warning "No <iSTIG> nodes found in CKL '$($cklFile.FullName)'."
            continue
        }

        foreach ($stig in $stigNodes) {
            $stigTitle   = $stig.STIG_INFO.SI_DATA | Where-Object { $_.SID_NAME -eq "title" } | Select-Object -ExpandProperty SID_DATA
            $stigVersion = $stig.STIG_INFO.SI_DATA | Where-Object { $_.SID_NAME -eq "version" } | Select-Object -ExpandProperty SID_DATA

            foreach ($vuln in $stig.VULN) {

                $vulnId     = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Vuln_Num" }).ATTRIBUTE_DATA
                $ruleId     = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Rule_ID" }).ATTRIBUTE_DATA
                $ruleTitle  = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Rule_Title" }).ATTRIBUTE_DATA
                $severity   = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Severity" }).ATTRIBUTE_DATA
                $status     = $vuln.STATUS

                if ([string]::IsNullOrWhiteSpace($vulnId)) {
                    $vulnId = $ruleId
                }
                if ([string]::IsNullOrWhiteSpace($vulnId)) { continue }

                if (-not $findingsIndex.ContainsKey($vulnId)) {
                    $findingsIndex[$vulnId] = [PSCustomObject]@{
                        VulnId       = $vulnId
                        RuleId       = $ruleId
                        RuleTitle    = $ruleTitle
                        Severity     = $severity
                        HostStatuses = @{}
                        StigTitle    = $stigTitle
                        StigVersion  = $stigVersion
                    }
                }

                $findingsIndex[$vulnId].HostStatuses[$hostName] = $status
            }
        }
    }
}

# Rollup
$totalHosts = $hostDirs.Count
$rolledUp = foreach ($rec in $findingsIndex.Values) {

    $statuses = $rec.HostStatuses.Values
    $overall = Get-OverallStatus -Statuses $statuses

    $affected = @(
        foreach ($kvp in $rec.HostStatuses.GetEnumerator()) {
            if ($kvp.Value -ne "NotAFinding") { $kvp.Key }
        }
    )

    [PSCustomObject]@{
        VulnId        = $rec.VulnId
        RuleId        = $rec.RuleId
        RuleTitle     = $rec.RuleTitle
        Severity      = $rec.Severity
        OverallStatus = $overall
        AffectedCount = $affected.Count
        AffectedHosts = $affected -join ", "
        TotalHosts    = $totalHosts
        StigTitle     = $rec.StigTitle
        StigVersion   = $rec.StigVersion
    }
}

# Build HTML
$now = Get-Date
$sample = $rolledUp | Select-Object -First 1

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>STIG Rollup Report - $RoleName</title>
<style>
body { font-family: Segoe UI, Arial; margin: 20px; }
.summary-card { border:1px solid #ccc; padding:10px; margin-bottom:15px; border-radius:6px; }
table { border-collapse: collapse; width:100%; }
th,td { border:1px solid #ccc; padding:6px; font-size:13px; }
</style>
</head>
<body>

<h1>STIG Rollup Report - $RoleName</h1>
<p><strong>Generated:</strong> $now</p>
<p><strong>Total Hosts:</strong> $totalHosts</p>
<p><strong>STIG:</strong> $($sample.StigTitle)</p>
<p><strong>Version:</strong> $($sample.StigVersion)</p>

<table>
<thead>
<tr>
    <th>Vuln ID</th>
    <th>Rule Title</th>
    <th>Severity</th>
    <th>Status</th>
    <th>Affected Hosts</th>
</tr>
</thead>
<tbody>
"@

foreach ($item in $rolledUp | Sort-Object Severity, VulnId) {

    $html += @"
<tr>
    <td>$($item.VulnId)</td>
    <td>$([System.Web.HttpUtility]::HtmlEncode($item.RuleTitle))</td>
    <td>$($item.Severity)</td>
    <td>$($item.OverallStatus)</td>
    <td>$($item.AffectedHosts)</td>
</tr>
"@
}

$html += @"
</tbody></table>
</body></html>
"@

# Output Path
if ($OutputFolder -and (Test-Path $OutputFolder)) {
    $outputPath = Join-Path $OutputFolder $OutputName
}
else {
    $outputPath = Join-Path $rolePath $OutputName
}

$html | Set-Content -Path $outputPath -Encoding UTF8

Write-Host "Rollup report written to: $outputPath"
