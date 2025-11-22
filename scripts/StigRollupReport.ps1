param(
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,   # e.g. F:\STIG-Results  (or UNC if you ever go back to that)

    [Parameter(Mandatory = $true)]
    [string]$RoleName,    # domain_controllers, member_servers, workstations

    [Parameter(Mandatory = $true)]
    [string]$OutputName   # e.g. SummaryReport-domain_controllers.html
)

# ----------------- Normalize Inputs -----------------
$ShareRoot = $ShareRoot.Trim().TrimEnd('\')
$RoleName  = $RoleName.Trim()
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

Write-Host "=== STIG Rollup Report (CKL-based) ==="
Write-Host "Share Root : $ShareRoot"
Write-Host "Role Name  : $RoleName"
Write-Host "Output Name: $OutputName"
Write-Host "OutputFolder: $outputFolder"

# ----------------- Collect Data -----------------
$rows = @()

# Host folders under the role path
$hostDirs = Get-ChildItem -Path $rolePath -Directory -ErrorAction SilentlyContinue

if (-not $hostDirs -or $hostDirs.Count -eq 0) {
    Write-Warning "No host folders found under role path: $rolePath"
}

foreach ($hostDir in $hostDirs) {
    $hostName = $hostDir.Name
    $cklFolder = Join-Path -Path $hostDir.FullName -ChildPath "Checklist"

    if (-not (Test-Path $cklFolder)) {
        Write-Warning "Checklist folder missing for host '$hostName' at $cklFolder"
        continue
    }

    $cklFiles = Get-ChildItem -Path $cklFolder -Filter *.ckl -File -ErrorAction SilentlyContinue
    if (-not $cklFiles -or $cklFiles.Count -eq 0) {
        Write-Warning "No CKL files found for host '$hostName' in $cklFolder"
        continue
    }

    foreach ($ckl in $cklFiles) {
        try {
            [xml]$cklXml = Get-Content -LiteralPath $ckl.FullName -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to load CKL '$($ckl.FullName)': $_"
            continue
        }

        # Try to grab STIG title (best-effort)
        $stigTitle = ""
        if ($cklXml.CHECKLIST -and $cklXml.CHECKLIST.STIGS -and $cklXml.CHECKLIST.STIGS.STIG) {
            $firstStig = $cklXml.CHECKLIST.STIGS.STIG[0]
            if ($firstStig.STIG_INFO -and $firstStig.STIG_INFO.SI_DATA) {
                $titleNode = $firstStig.STIG_INFO.SI_DATA | Where-Object { $_.SID_NAME -eq 'title' } | Select-Object -First 1
                if ($titleNode) {
                    $stigTitle = $titleNode.SID_DATA
                }
            }
        }

        # Each VULN is one record
        $vulns = $cklXml.CHECKLIST.STIGS.STIG.VULN
        if (-not $vulns) {
            continue
        }

        foreach ($vuln in $vulns) {
            # Helper to pull ATTRIBUTE_DATA by name (PS 5.1-safe)
            $vulnId = ""
            $ruleId = ""
            $severity = ""

            if ($vuln.STIG_DATA) {
                # VulnId (Vuln_Num or Vuln ID)
                $vulnNumNode = $vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln_Num' } | Select-Object -First 1
                if ($vulnNumNode) {
                    $vulnId = $vulnNumNode.ATTRIBUTE_DATA
                } else {
                    $vulnIdNodeAlt = $vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln ID' } | Select-Object -First 1
                    if ($vulnIdNodeAlt) {
                        $vulnId = $vulnIdNodeAlt.ATTRIBUTE_DATA
                    }
                }

                # Rule ID
                $ruleNode = $vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Rule_ID' } | Select-Object -First 1
                if ($ruleNode) {
                    $ruleId = $ruleNode.ATTRIBUTE_DATA
                }

                # Severity
                $sevNode = $vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Severity' } | Select-Object -First 1
                if ($sevNode) {
                    $severity = $sevNode.ATTRIBUTE_DATA
                }
            }

            $status = ""
            if ($vuln.STATUS) {
                $status = [string]$vuln.STATUS
            }

            $findingDetails = ""
            if ($vuln.FINDING_DETAILS) {
                $findingDetails = [string]$vuln.FINDING_DETAILS
            }

            $rows += [PSCustomObject]@{
                Host      = $hostName
                STIG      = $stigTitle
                VulnId    = $vulnId
                RuleId    = $ruleId
                Severity  = $severity
                Status    = $status
                Finding   = $findingDetails
                SourceCkl = $ckl.Name
            }
        }
    }
}

if (-not $rows -or $rows.Count -eq 0) {
    Write-Warning "No vulnerability data collected for role '$RoleName'."
}

# ----------------- Summary Calculations -----------------
# Overall status counts
$statusGroups = $rows | Group-Object -Property Status | Sort-Object Name

# Severity x Status matrix
$severityStatusGroups = $rows | Group-Object -Property Severity, Status

# Per-host Open counts
$openPerHost = $rows | Where-Object { $_.Status -match 'Open' } |
    Group-Object -Property Host |
    Sort-Object -Property Count -Descending

# ----------------- Build HTML -----------------
$now = Get-Date

$htmlHeader = @"
<html>
<head>
  <title>STIG Rollup Report - $RoleName</title>
  <style>
    body { font-family: Arial, sans-serif; font-size: 13px; }
    h1, h2, h3 { font-family: Segoe UI, Arial, sans-serif; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #ccc; padding: 4px 6px; }
    th { background-color: #f0f0f0; text-align: left; }
    .status-Open { background-color: #ffe0e0; }
    .status-NotAFinding, .status-'Not a Finding' { background-color: #e0ffe0; }
    .status-Not_Applicable, .status-'Not Applicable', .status-NA { background-color: #e0e0ff; }
    .severity-high { background-color: #ffcccc; }
    .severity-medium { background-color: #fff0cc; }
    .severity-low { background-color: #e5ffcc; }
    .small { font-size: 11px; color: #555; }
  </style>
</head>
<body>
<h1>STIG Rollup Report - Role: $RoleName</h1>
<p class="small">Generated: $now</p>
"@

# Overall status summary
$statusTable = @"
<h2>Overall Status Summary</h2>
<table>
  <tr>
    <th>Status</th>
    <th>Count</th>
  </tr>
"@

foreach ($grp in $statusGroups) {
    $st = if ($grp.Name) { $grp.Name } else { "(blank)" }
    $statusTable += "  <tr><td>$st</td><td>$($grp.Count)</td></tr>`r`n"
}
$statusTable += "</table>`r`n"

# Open findings per host
$hostOpenTable = @"
<h2>Open Findings per Host</h2>
<table>
  <tr>
    <th>Host</th>
    <th>Open Count</th>
  </tr>
"@

foreach ($h in $openPerHost) {
    $hostOpenTable += "  <tr><td>$($h.Name)</td><td>$($h.Count)</td></tr>`r`n"
}
$hostOpenTable += "</table>`r`n"

# Detailed findings table
$detailTable = @"
<h2>Detailed Findings</h2>
<table>
  <tr>
    <th>Host</th>
    <th>STIG</th>
    <th>Vuln ID</th>
    <th>Rule ID</th>
    <th>Severity</th>
    <th>Status</th>
    <th>Source CKL</th>
    <th>Finding Details</th>
  </tr>
"@

foreach ($row in $rows) {
    $severityClass = ""
    $sevLower = ($row.Severity + "").ToLower()

    if ($sevLower -eq "high" -or $sevLower -eq "cat i" -or $sevLower -eq "category i") {
        $severityClass = "severity-high"
    } elseif ($sevLower -eq "medium" -or $sevLower -eq "cat ii" -or $sevLower -eq "category ii") {
        $severityClass = "severity-medium"
    } elseif ($sevLower -eq "low" -or $sevLower -eq "cat iii" -or $sevLower -eq "category iii") {
        $severityClass = "severity-low"
    }

    $statusClass = ""
    $statusLower = ($row.Status + "").ToLower()
    if ($statusLower -like "open*") {
        $statusClass = "status-Open"
    } elseif ($statusLower -like "notafinding*" -or $statusLower -like "not a finding*") {
        $statusClass = "status-NotAFinding"
    } elseif ($statusLower -like "not_applicable*" -or $statusLower -like "not applicable*" -or $statusLower -eq "na") {
        $statusClass = "status-Not_Applicable"
    }

    # Basic HTML-escape by replacing < and >
    $findingHtml = ($row.Finding + "") -replace "<","&lt;" -replace ">","&gt;"

    $detailTable += @"
  <tr class="$severityClass $statusClass">
    <td>$($row.Host)</td>
    <td>$($row.STIG)</td>
    <td>$($row.VulnId)</td>
    <td>$($row.RuleId)</td>
    <td>$($row.Severity)</td>
    <td>$($row.Status)</td>
    <td>$($row.SourceCkl)</td>
    <td><pre style="white-space: pre-wrap; margin:0;">$findingHtml</pre></td>
  </tr>
"@
}

$detailTable += "</table>`r`n"

$htmlFooter = @"
</body>
</html>
"@

$html = $htmlHeader + $statusTable + $hostOpenTable + $detailTable + $htmlFooter

# ----------------- Write Output -----------------
$outputPath = Join-Path -Path $outputFolder -ChildPath $OutputName
$html | Out-File -FilePath $outputPath -Encoding UTF8 -Force

Write-Host "✔ Rollup report written to: $outputPath"
