<# =====================================================================
   StigRollupReport.ps1
   Enterprise CKL Rollup Generator
   Parses Evaluate-STIG CKLs and produces a rolled-up HTML report
    ===================================================================== #>

param(
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,        # UNC share root (ex: \\192.168.10.198\STIG-Results)

    [Parameter(Mandatory = $true)]
    [string]$RoleName,         # domain_controllers, member_servers, workstations

    [string]$OutputName = "SummaryReport-$RoleName.html"
)

Write-Host "=== STIG Rollup Report (CKL-based) ==="
Write-Host "Share Root : $ShareRoot"
Write-Host "Role Name  : $RoleName"
Write-Host "Output Name: $OutputName"

$rolePath = Join-Path $ShareRoot $RoleName

if (-not (Test-Path $rolePath)) {
    throw "Role path '$rolePath' does not exist."
}

# Host folders
$hostDirs = Get-ChildItem $rolePath -Directory
if ($hostDirs.Count -eq 0) {
    throw "No host folders found under '$rolePath'"
}

# This holds all findings by VulnId
$FindingsIndex = @{}

function Get-OverallStatus {
    param ([string[]]$Statuses)

    if ($Statuses -contains "Open") { return "Open" }
    if ($Statuses -contains "Not Reviewed" -or $Statuses -contains "Not_Reviewed") { return "Not Reviewed" }
    if ($Statuses -contains "Not Applicable" -and $Statuses.Count -eq 1) { return "Not Applicable" }
    if ($Statuses -contains "NotAFinding") { return "Not a Finding" }

    return ($Statuses | Select-Object -First 1)
}

foreach ($hostDir in $hostDirs) {

    $host = $hostDir.Name

    # FIXED — CKLs are inside /Checklist/
    $cklPath = Join-Path $hostDir.FullName "Checklist"

    if (-not (Test-Path $cklPath)) {
        Write-Warning "Host '$host' has no Checklist folder. Skipping."
        continue
    }

    # FIXED — Only look inside Checklist folder
    $cklFiles = Get-ChildItem -Path $cklPath -Filter *.ckl -ErrorAction SilentlyContinue

    if (-not $cklFiles -or $cklFiles.Count -eq 0) {
        Write-Warning "No CKL files found for host '$host' under '$cklPath'"
        continue
    }

    foreach ($ckl in $cklFiles) {

        Write-Host "Processing CKL: $($ckl.FullName) for host $host"

        [xml]$xml = Get-Content $ckl.FullName

        # Evaluate-STIG CKL Format:
        # <CHECKLIST>
        #   <STIGS>
        #      <iSTIG>
        #          <STIG_INFO>...</STIG_INFO>
        #          <VULN>
        #              <STIG_DATA><ATTRIBUTE_DATA>V-XXXXX</ATTRIBUTE_DATA></STIG_DATA>
        #              <STATUS>Open|NotAFinding|Not_Reviewed|Not Applicable</STATUS>
        #              <SEVERITY>high/medium/low</SEVERITY>
        #              <RULE_TITLE>...</RULE_TITLE>
        #          </VULN>
        #      </iSTIG>
        #   </STIGS>
        # </CHECKLIST>

        $stigNodes = $xml.CHECKLIST.STIGS.iSTIG
        if (-not $stigNodes) {
            Write-Warning "No <STIG> nodes found in CKL '$($ckl.FullName)'."
            continue
        }

        foreach ($stig in $stigNodes) {

            $vulns = $stig.VULN
            foreach ($v in $vulns) {

                # Extract VulnId
                $vulnId = ($v.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Vuln-ID" }).ATTRIBUTE_DATA
                if (-not $vulnId) { continue }

                $ruleId     = ($v.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Rule-ID" }).ATTRIBUTE_DATA
                $ruleTitle  = $v.RULE_TITLE
                $severity   = $v.SEVERITY
                $status     = $v.STATUS

                if (-not $FindingsIndex.ContainsKey($vulnId)) {
                    $FindingsIndex[$vulnId] = [PSCustomObject]@{
                        VulnId       = $vulnId
                        RuleId       = $ruleId
                        RuleTitle    = $ruleTitle
                        Severity     = $severity
                        HostStatuses = @{}
                    }
                }

                $rec = $FindingsIndex[$vulnId]
                $rec.HostStatuses[$host] = $status
            }
        }
    }
}

if ($FindingsIndex.Count -eq 0) {
    throw "No findings were parsed from CKLs under '$rolePath'."
}

# Convert into rollup objects
$totalHosts = $hostDirs.Count
$rolledUp = foreach ($rec in $FindingsIndex.Values) {

    $statuses = $rec.HostStatuses.Values
    $overall  = Get-OverallStatus $statuses

    $affected = @(
        foreach ($kvp in $rec.HostStatuses.GetEnumerator()) {
            if ($kvp.Value -ne "NotAFinding" -and $kvp.Value -ne "Not a Finding") {
                $kvp.Key
            }
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
    }
}

# Filter counts
$open           = $rolledUp | Where-Object { $_.OverallStatus -eq "Open" }
$notReviewed    = $rolledUp | Where-Object { $_.OverallStatus -eq "Not Reviewed" }
$na             = $rolledUp | Where-Object { $_.OverallStatus -eq "Not Applicable" }

$totalFindings  = $rolledUp.Count
$compliancePct  = [math]::Round(100 * (($totalFindings - $open.Count) / $totalFindings), 2)

$now = Get-Date

#============================
# Generate HTML Output
#============================
$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>STIG Rollup Report - $RoleName</title>
<style>
body { font-family: Segoe UI, Arial; margin:20px; }
h1,h2 { color:#333; }
table { width:100%; border-collapse:collapse; margin-top:10px; }
th,td { border:1px solid #ccc; padding:6px; font-size:13px; }
th { background:#f5f5f5; }
.status-open { background:#fdecea; }
.status-notreviewed { background:#fff4e5; }
.status-na { background:#f2f2f2; }
.risk-high { color:#c0392b; font-weight:bold; }
.risk-medium { color:#f39c12; font-weight:bold; }
.risk-low { color:#27ae60; font-weight:bold; }
</style>
</head>

<body>

<h1>STIG Rollup Report – $RoleName</h1>
<p><strong>Generated:</strong> $now</p>
<p><strong>Total Hosts:</strong> $totalHosts</p>
<p><strong>Total Unique Findings:</strong> $totalFindings</p>
<p><strong>Open Findings:</strong> $($open.Count)</p>
<p><strong>Not Reviewed:</strong> $($notReviewed.Count)</p>
<p><strong>Compliance:</strong> $compliancePct %</p>

<h2>Open & Not Reviewed Findings</h2>

<table>
<thead>
<tr>
    <th>Vuln ID</th>
    <th>Rule ID</th>
    <th>Title</th>
    <th>Severity</th>
    <th>Status</th>
    <th>Affected Hosts</th>
</tr>
</thead>
<tbody>
"@

foreach ($item in ($rolledUp | Where-Object { $_.OverallStatus -in @("Open","Not Reviewed") })) {

    $rowClass = switch ($item.OverallStatus) {
        "Open"         { "status-open" }
        "Not Reviewed" { "status-notreviewed" }
        default        { "" }
    }

    $sev = switch ($item.Severity) {
        "high"   { "risk-high" }
        "medium" { "risk-medium" }
        "low"    { "risk-low" }
        default  { "" }
    }

$html += @"
<tr class='$rowClass'>
    <td>$($item.VulnId)</td>
    <td>$($item.RuleId)</td>
    <td>$([System.Web.HttpUtility]::HtmlEncode($item.RuleTitle))</td>
    <td class='$sev'>$($item.Severity)</td>
    <td>$($item.OverallStatus)</td>
    <td>$($item.AffectedCount) of $totalHosts ($($item.AffectedHosts))</td>
</tr>
"@
}

$html += @"
</tbody>
</table>
</body>
</html>
"@

# Output
$outputPath = Join-Path $rolePath $OutputName
$html | Set-Content -Path $outputPath -Encoding UTF8

Write-Host "Rollup written to: $outputPath"
