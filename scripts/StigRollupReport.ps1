<#
.SYNOPSIS
  Generates a STIG Rollup HTML report by combining Evaluate-STIG CKL outputs
  across all hosts in a given role (e.g. domain_controllers).

.DESCRIPTION
  - Parses *.ckl files from:
        <ShareRoot>\<RoleName>\<Host>\Checklist\*.ckl
  - Groups findings by STIG (title + version/release info).
  - De-duplicates findings so each Vuln ID / Rule ID appears once per STIG,
    with merged host statuses (per finding) in Affected Hosts.
  - Shows per-STIG summary like:
        High: X   Medium: Y   Low: Z   Not Reviewed: W
    where High/Medium/Low = *Open only* and Not Reviewed is separate.
  - Builds sections per STIG as Bootstrap 5 accordion items (collapsed by default).
  - Client-side filter bar:
        - Checkboxes: High / Medium / Low
        - Checkbox: Show Not Reviewed
    => you can show any combination of severities and optionally hide Not_Reviewed.
  - Computes CORA-style risk at *role* level:
        - Not_Reviewed is treated as Open for CORA only.
        - Uses CAT I/II/III (High/Medium/Low) with weighted average.

  Per-STIG CSV export:
    For each STIG, a CSV is written to:
        <ShareRoot>\Reports\<RoleName>\csv\<RoleName>_<SafeStigName>.csv
    Includes:
        VulnId, RuleId, Severity, Title, StatusGroup, AffectedHosts

.PARAMETER ShareRoot
  Root share containing role folders (e.g. \\appsvr1\stig-results)

.PARAMETER RoleName
  Role folder under the share (e.g. domain_controllers, member_servers, workstations)

.PARAMETER OutputName
  Base file name for the generated HTML (e.g. STIG-Rollup.html).
  The script will automatically timestamp the final file:
      STIG-Rollup_<RoleName>_yyyyMMdd-HHmm.html
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,

    [Parameter(Mandatory = $true)]
    [string]$RoleName,

    [Parameter(Mandatory = $true)]
    [string]$OutputName
)

# ---------------- Helper functions ----------------

function Normalize-Status {
    param (
        [string]$Raw
    )
    if (-not $Raw) { return "Not_Reviewed" }

    $v = $Raw.Trim()

    switch -Regex ($v) {
        "^(?i)open$"                      { return "Open" }
        "^(?i)not.?reviewed$"             { return "Not_Reviewed" }
        "^(?i)not.?a.?finding$"           { return "NotAFinding" }
        "^(?i)pass$"                      { return "NotAFinding" }
        "^(?i)not.?applicable$"           { return "Not_Applicable" }
        "^(?i)na$"                        { return "Not_Applicable" }
        default                           { return $v }
    }
}

function Get-SiValue {
    param (
        [xml.XmlElement]$iStigNode,
        [string]$Name
    )
    if (-not $iStigNode -or -not $iStigNode.STIG_INFO) { return $null }
    foreach ($si in $iStigNode.STIG_INFO.SI_DATA) {
        if ($si.SID_NAME -eq $Name) {
            return [string]$si.SID_DATA
        }
    }
    return $null
}

function Get-StigDisplayInfo {
    param (
        [xml.XmlElement]$iStig
    )

    $titleRaw    = Get-SiValue -iStigNode $iStig -name "title"
    if (-not $titleRaw) {
        $titleRaw = Get-SiValue -iStigNode $iStig -name "STIG Title"
    }
    if (-not $titleRaw) { $titleRaw = "Unknown STIG" }

    $version     = Get-SiValue -iStigNode $iStig -name "version"
    $releaseInfo = Get-SiValue -iStigNode $iStig -name "releaseinfo"

    $releaseNum  = $null
    $benchDate   = $null

    if ($releaseInfo) {
        # Handle patterns like:
        #   "Release: 2 Benchmark Date: 02 Jul 2025"
        #   "Windows Server 2022 ... :: Version 2, Release 5 :: 14 Nov 2024"
        if ($releaseInfo -match "Release\s*[: ]\s*(\d+)") {
            $releaseNum = $matches[1]
        }
        if (-not $benchDate -and $releaseInfo -match "Benchmark Date:\s*(.+)$") {
            $benchDate = $matches[1].Trim()
        }
        if (-not $benchDate -and $releaseInfo -match "::\s*([0-9]{1,2}\s+\w+\s+[0-9]{4})\s*$") {
            $benchDate = $matches[1].Trim()
        }
        if (-not $version -and $releaseInfo -match "Version\s+(\d+)") {
            $version = $matches[1]
        }
    }

    # Shorten the title: replace "Security Technical Implementation Guide" with "STIG"
    $displayTitle = $titleRaw -replace "Security Technical Implementation Guide","STIG"
    $displayTitle = $displayTitle.Trim()

    # Build a nice "Version X, Release Y, Date" line OR fall back to raw
    $metaParts = @()
    if ($version)    { $metaParts += ("Version {0}" -f $version) }
    if ($releaseNum) { $metaParts += ("Release {0}" -f $releaseNum) }
    if ($benchDate)  { $metaParts += $benchDate }

    if ($metaParts.Count -gt 0) {
        $releaseText = ($metaParts -join ", ")
    }
    elseif ($releaseInfo) {
        $releaseText = $releaseInfo
    }
    else {
        $releaseText = ""
    }

    return [pscustomobject]@{
        TitleRaw     = $titleRaw
        DisplayTitle = $displayTitle
        Version      = $version
        ReleaseNum   = $releaseNum
        BenchDate    = $benchDate
        ReleaseText  = $releaseText
        Key          = "{0}|{1}" -f $titleRaw, $releaseText
    }
}

function Get-Percent {
    param (
        [int]$Open,
        [int]$Total
    )
    if ($Total -le 0) { return 0.0 }
    return [math]::Round(100.0 * $Open / $Total, 1)
}

function Get-SafeFileName {
    param(
        [string]$Name
    )
    if (-not $Name) { return "Unknown" }
    $invalid = [IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = "[{0}]" -f [Regex]::Escape($invalid)
    $safe = $Name -replace $pattern, "_"
    # Also trim and collapse spaces
    $safe = $safe.Trim()
    $safe = $safe -replace "\s+","_"
    if (-not $safe) { $safe = "Unknown" }
    return $safe
}

# ---------------- Discover scope & output paths ----------------

$rolePath = Join-Path $ShareRoot $RoleName
if (-not (Test-Path $rolePath)) {
    throw "Role path not found: $rolePath"
}

# Reports\<RoleName>\ and CSV subfolder
$reportsRoot    = Join-Path $ShareRoot "Reports"
if (-not (Test-Path $reportsRoot)) {
    New-Item -Path $reportsRoot -ItemType Directory -Force | Out-Null
}

$roleReportPath = Join-Path $reportsRoot $RoleName
if (-not (Test-Path $roleReportPath)) {
    New-Item -Path $roleReportPath -ItemType Directory -Force | Out-Null
}

$csvFolder = Join-Path $roleReportPath "csv"
if (-not (Test-Path $csvFolder)) {
    New-Item -Path $csvFolder -ItemType Directory -Force | Out-Null
}

# Build timestamped HTML name under Reports\<RoleName>
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputName)
if (-not $baseName) { $baseName = "STIG-Rollup" }

$ext = [System.IO.Path]::GetExtension($OutputName)
if (-not $ext) { $ext = ".html" }

$safeRole = ($RoleName -replace "[^A-Za-z0-9_\-]", "_")
$tsFile   = Get-Date -Format "yyyyMMdd-HHmm"
$outFileName = "{0}_{1}_{2}{3}" -f $baseName, $safeRole, $tsFile, $ext
$outPath = Join-Path $roleReportPath $outFileName

# Discover host folders
$hostFolders = Get-ChildItem -Path $rolePath -Directory | Sort-Object Name
if (-not $hostFolders) {
    # Still generate a minimal HTML so AWX doesn't fail
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $htmlNoHosts = @"
<html>
<head>
  <meta charset="utf-8" />
  <title>STIG Rollup Report - $RoleName</title>
</head>
<body>
  <h1>STIG Rollup Report - $RoleName</h1>
  <p>Generated: $timeStamp</p>
  <p>No host folders were found under <code>$rolePath</code>.</p>
</body>
</html>
"@
    $htmlNoHosts | Out-File -FilePath $outPath -Encoding UTF8
    Write-Host "⚠ No host folders found. Empty report generated at: $outPath"
    return
}

$totalHosts = $hostFolders.Count
Write-Host "Found $totalHosts host(s) under '$RoleName'."

# ---------------- Data model ----------------

# Per-STIG data: keyed by "TitleRaw|ReleaseText"
$byStig = @{}

# CORA counters (role level) — Not_Reviewed counted as Open for CORA only
$cat1Total = 0  # High
$cat2Total = 0  # Medium
$cat3Total = 0  # Low

$cat1Open  = 0  # Open + Not_Reviewed
$cat2Open  = 0
$cat3Open  = 0

$anyFindings = $false

# ---------------- Parse CKLs ----------------

foreach ($hostFolder in $hostFolders) {
    $hostName = $hostFolder.Name
    $checklistPath = Join-Path $hostFolder.FullName "Checklist"

    if (-not (Test-Path $checklistPath)) {
        Write-Warning "No Checklist folder for host $hostName. Skipping."
        continue
    }

    $ckls = Get-ChildItem -Path $checklistPath -Filter *.ckl -File
    if (-not $ckls) {
        Write-Warning "No CKL files for host $hostName. Skipping."
        continue
    }

    Write-Host "Processing $($ckls.Count) CKL file(s) for host $hostName..." -ForegroundColor Cyan

    foreach ($ckl in $ckls) {
        try {
            [xml]$xml = Get-Content -Path $ckl.FullName -Raw
        }
        catch {
            Write-Warning "Failed to read '$($ckl.FullName)' ($hostName): $_"
            continue
        }

        if (-not $xml.CHECKLIST -or -not $xml.CHECKLIST.STIGS) {
            Write-Warning "Invalid CKL structure in '$($ckl.Name)'. Skipping."
            continue
        }

        # Collect iSTIG nodes
        $iStigs = @()
        foreach ($child in $xml.CHECKLIST.STIGS.ChildNodes) {
            if ($child.Name -match "i?STIG") { $iStigs += $child }
        }
        if (-not $iStigs -or $iStigs.Count -eq 0) {
            $iStigs = $xml.CHECKLIST.STIGS.SelectNodes(".//iSTIG")
        }
        if (-not $iStigs -or $iStigs.Count -eq 0) {
            Write-Warning "No iSTIG blocks in '$($ckl.Name)' for $hostName."
            continue
        }

        foreach ($iStig in $iStigs) {

            $info = Get-StigDisplayInfo -iStig $iStig
            $stigKey = $info.Key

            if (-not $byStig.ContainsKey($stigKey)) {
                $byStig[$stigKey] = [ordered]@{
                    TitleRaw     = $info.TitleRaw
                    DisplayTitle = $info.DisplayTitle
                    ReleaseText  = $info.ReleaseText
                    Findings     = @{}   # key -> row object
                }
            }

            $stigEntry = $byStig[$stigKey]

            # Get all VULN elements
            $vulns = $iStig.SelectNodes("./VULN")
            if (-not $vulns -or $vulns.Count -eq 0) {
                $vulns = $iStig.SelectNodes(".//VULN")
            }
            if (-not $vulns -or $vulns.Count -eq 0) {
                Write-Warning "No VULN entries in '$($ckl.Name)' ($hostName) for STIG '$($info.DisplayTitle)'."
                continue
            }

            foreach ($v in $vulns) {
                # Build STIG_DATA map
                $stigData = @{}
                foreach ($sd in $v.STIG_DATA) {
                    $n = [string]$sd.VULN_ATTRIBUTE
                    $val = [string]$sd.ATTRIBUTE_DATA
                    if ($n -and -not $stigData.ContainsKey($n)) {
                        $stigData[$n] = $val
                    }
                }

                $vulnId = $null
                if ($stigData.ContainsKey("Vuln_Num")) { $vulnId = $stigData["Vuln_Num"] }

                $ruleId = $null
                if ($stigData.ContainsKey("Rule_ID")) { $ruleId = $stigData["Rule_ID"] }

                $title = $null
                if ($stigData.ContainsKey("Rule_Title")) { $title = $stigData["Rule_Title"] }

                if (-not $title)   { $title   = "No title" }
                if (-not $vulnId -and -not $ruleId) { continue }

                # Severity: prefer VULN.SEVERITY, fallback to STIG_DATA["Severity"]
                $sevRaw = $null
                if ($v.SEVERITY) {
                    $sevRaw = [string]$v.SEVERITY
                }
                elseif ($stigData.ContainsKey("Severity")) {
                    $sevRaw = [string]$stigData["Severity"]
                }

                $sevNorm = "Other"
                if ($sevRaw) {
                    switch -Regex ($sevRaw.Trim()) {
                        "^(?i)high$"   { $sevNorm = "High" }
                        "^(?i)medium$" { $sevNorm = "Medium" }
                        "^(?i)low$"    { $sevNorm = "Low" }
                        default        { $sevNorm = $sevRaw.Trim() }
                    }
                }

                $statusNorm = Normalize-Status $v.STATUS

                # ---------- CORA counters (role level) ----------
                # Treat Not_Applicable as not part of total.
                if (($sevNorm -eq "High") -or ($sevNorm -eq "Medium") -or ($sevNorm -eq "Low")) {
                    if ($statusNorm -ne "Not_Applicable") {
                        switch ($sevNorm) {
                            "High"   { $cat1Total++ }
                            "Medium" { $cat2Total++ }
                            "Low"    { $cat3Total++ }
                        }
                    }

                    if (($statusNorm -eq "Open") -or ($statusNorm -eq "Not_Reviewed")) {
                        switch ($sevNorm) {
                            "High"   { $cat1Open++ }
                            "Medium" { $cat2Open++ }
                            "Low"    { $cat3Open++ }
                        }
                    }
                }

                # We only *display* Open / Not_Reviewed in the rollup tables.
                if (($statusNorm -ne "Open") -and ($statusNorm -ne "Not_Reviewed")) {
                    continue
                }

                $anyFindings = $true

                # ---------- Per-STIG finding de-duplication ----------
                $rowKey = if ($vulnId) { $vulnId } else { $ruleId }

                if (-not $stigEntry.Findings.ContainsKey($rowKey)) {
                    $statusGroup = if ($statusNorm -eq "Open") { "Open" } else { "Not_Reviewed" }

                    $row = [ordered]@{
                        VulnId      = $vulnId
                        RuleId      = $ruleId
                        Title       = $title
                        Severity    = $sevNorm       # High/Medium/Low/Other
                        StatusGroup = $statusGroup   # Open or Not_Reviewed (worst across hosts)
                        Hosts       = @{}            # hostName -> status (Open / Not_Reviewed)
                    }
                    $stigEntry.Findings[$rowKey] = $row
                }

                $rowRef = $stigEntry.Findings[$rowKey]

                # Merge host status
                $rowRef.Hosts[$hostName] = $statusNorm

                # Escalate StatusGroup if any host is Open
                if ($statusNorm -eq "Open" -and $rowRef.StatusGroup -ne "Open") {
                    $rowRef.StatusGroup = "Open"
                }
            } # end foreach VULN

            # Save back
            $byStig[$stigKey] = $stigEntry
        } # end foreach iSTIG
    } # end foreach CKL
} # end foreach hostFolder

# ---------------- If no findings, generate minimal report ----------------

if (-not $anyFindings) {
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $minimalHtml = @"
<html>
<head>
  <meta charset="utf-8" />
  <title>STIG Rollup Report - $RoleName</title>
</head>
<body>
  <h1>STIG Rollup Report - $RoleName</h1>
  <p><b>Generated:</b> $timeStamp</p>
  <p>No Open or Not Reviewed findings detected under <code>$rolePath</code>.</p>
</body>
</html>
"@

    $minimalHtml | Out-File -FilePath $outPath -Encoding UTF8
    Write-Host "✅ No Open/Not Reviewed findings. Minimal report created:"
    Write-Host "   $outPath"
    return
}

# ---------------- Compute per-STIG counts ----------------

foreach ($k in $byStig.Keys) {
    $s = $byStig[$k]

    $highOpen = 0
    $medOpen  = 0
    $lowOpen  = 0
    $nrCount  = 0

    foreach ($f in $s.Findings.Values) {
        $sev = $f.Severity
        $sg  = $f.StatusGroup

        if ($sg -eq "Open") {
            switch ($sev) {
                "High"   { $highOpen++ }
                "Medium" { $medOpen++ }
                "Low"    { $lowOpen++ }
            }
        }
        elseif ($sg -eq "Not_Reviewed") {
            $nrCount++
        }
    }

    $s.HighOpen      = $highOpen
    $s.MediumOpen    = $medOpen
    $s.LowOpen       = $lowOpen
    $s.NotReviewedCt = $nrCount

    $byStig[$k] = $s
}

# ---------------- CORA Risk Rating (role level) ----------------

$p1 = Get-Percent -Open $cat1Open -Total $cat1Total
$p2 = Get-Percent -Open $cat2Open -Total $cat2Total
$p3 = Get-Percent -Open $cat3Open -Total $cat3Total

$weightedAvg = 0.0
if (($cat1Total + $cat2Total + $cat3Total) -gt 0) {
    # Using 10 / 4 / 1 weights as before
    $weightedAvg = [math]::Round((( $p1 * 10.0 ) + ( $p2 * 4.0 ) + ( $p3 * 1.0 )) / 15.0, 1)
}

# Risk Rating thresholds (as previously discussed)
# Very High: >= 20%
# High:      >= 10% and < 20%
# Moderate:  > 0% and < 10%
# Low:       0 CAT I, < 5% CAT II & III   (still > 0 overall)
# Very Low:  0%
$riskRating = "Very Low Risk"

if ($weightedAvg -ge 20.0) {
    $riskRating = "Very High Risk"
}
elseif ($weightedAvg -ge 10.0) {
    $riskRating = "High Risk"
}
elseif ($weightedAvg -gt 0.0) {
    if ( ($cat1Open -eq 0) -and ($p2 -lt 5.0) -and ($p3 -lt 5.0) ) {
        $riskRating = "Low Risk"
    }
    else {
        $riskRating = "Moderate Risk"
    }
}
else {
    $riskRating = "Very Low Risk"
}

# ---------------- Generate HTML (Bootstrap + filters + accordions) ----------------

Add-Type -AssemblyName System.Web

$timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$style = @"
<style>
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #f3f4f6;
  margin: 0;
  padding: 16px;
}
.page {
  max-width: 1200px;
  margin: 0 auto;
}
.card-main {
  background: #ffffff;
  border-radius: 12px;
  box-shadow: 0 4px 16px rgba(15,23,42,0.12);
  padding: 20px 22px 26px 22px;
}
h1 {
  font-size: 24px;
  margin-bottom: 6px;
}
.meta {
  font-size: 12px;
  color: #6b7280;
  margin-bottom: 12px;
}
.badge-role {
  background-color: #eff6ff;
  color: #1d4ed8;
}
.badge-generated {
  background-color: #ecfdf3;
  color: #16a34a;
}
.badge-weighted {
  background-color: #fef3c7;
  color: #92400e;
}
.cora-summary {
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 12px 14px;
  background: #ffffff;
  margin-bottom: 16px;
}
.cora-summary table {
  font-size: 12px;
}
.cora-summary th, .cora-summary td {
  padding: 4px 6px;
}
.filter-panel {
  border-radius: 10px;
  border: 1px solid #e5e7eb;
  background: #f9fafb;
  padding: 10px 12px;
  margin-bottom: 14px;
  font-size: 13px;
}
.filter-panel label {
  margin-right: 12px;
}
.accordion-button .stig-badges span {
  margin-left: 6px;
}
.table-findings {
  font-size: 12px;
}
.table-findings th, .table-findings td {
  padding: 4px 6px;
}
.sev-high {
  color: #b91c1c;
  font-weight: 600;
}
.sev-medium {
  color: #92400e;
  font-weight: 600;
}
.sev-low {
  color: #065f46;
  font-weight: 600;
}
.status-open {
  color: #b91c1c;
  font-weight: 600;
}
.status-nr {
  color: #92400e;
  font-weight: 600;
}
.tiny {
  font-size: 11px;
  color: #6b7280;
}
</style>
"@

$scriptBlock = @'
<script>
function applyStigFilters() {
  var showHigh = document.getElementById("filterHigh").checked;
  var showMed  = document.getElementById("filterMed").checked;
  var showLow  = document.getElementById("filterLow").checked;
  var showNR   = document.getElementById("filterNR").checked;

  var rows = document.querySelectorAll("tr.finding-row");
  rows.forEach(function(row) {
    var sev    = row.getAttribute("data-severity"); // High/Medium/Low/Other
    var status = row.getAttribute("data-status");   // Open/Not_Reviewed

    var visible = false;

    if (sev === "High" && showHigh)   { visible = true; }
    if (sev === "Medium" && showMed)  { visible = true; }
    if (sev === "Low" && showLow)     { visible = true; }

    // If severity is not one of High/Med/Low (e.g. "Other"), always show if any severity checkbox is on
    if (sev !== "High" && sev !== "Medium" && sev !== "Low") {
      if (showHigh || showMed || showLow) {
        visible = true;
      }
    }

    // Hide Not_Reviewed if toggle is off
    if (!showNR && status === "Not_Reviewed") {
      visible = false;
    }

    row.style.display = visible ? "" : "none";
  });
}

function resetStigFilters() {
  document.getElementById("filterHigh").checked = true;
  document.getElementById("filterMed").checked  = true;
  document.getElementById("filterLow").checked  = true;
  document.getElementById("filterNR").checked   = true;
  applyStigFilters();
}

document.addEventListener("DOMContentLoaded", function() {
  var ids = ["filterHigh","filterMed","filterLow","filterNR"];
  ids.forEach(function(id) {
    var el = document.getElementById(id);
    if (el) {
      el.addEventListener("change", applyStigFilters);
    }
  });
  applyStigFilters();
});
</script>
'@

$html = @()
$html += "<!DOCTYPE html>"
$html += "<html lang='en'>"
$html += "<head>"
$html += "  <meta charset='utf-8' />"
$html += "  <title>STIG Rollup Report - $RoleName</title>"
$html += "  <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet' />"
$html += $style
$html += "</head>"
$html += "<body>"
$html += "<div class='page'>"
$html += "  <div class='card-main'>"
$html += "    <h1>STIG Rollup Report &mdash; Role: $RoleName</h1>"
$html += "    <div class='meta'>"
$html += "      <span class='badge badge-role me-2'>Role: $RoleName</span>"
$html += "      <span class='badge badge-generated me-2'>Generated: $timeStamp</span>"
$html += "      <span class='badge badge-weighted me-2'>Weighted CORA Score: $weightedAvg`%</span>"
$html += "      <div>Total Hosts: $totalHosts</div>"
$html += "      <div>Risk Rating: <strong>$riskRating</strong></div>"
$html += "    </div>"

# CORA summary
$html += "    <div class='cora-summary'>"
$html += "      <h5 class='mb-2'>CORA Risk Summary (Role: $RoleName)</h5>"
$html += ("      <p class='mb-1'><b>Risk Rating:</b> {0}<br/><b>Weighted Average:</b> {1}% (Not Reviewed counted as Open)</p>" -f $riskRating, $weightedAvg)
$html += "      <table class='table table-sm table-bordered mb-0'>"
$html += "        <thead><tr><th>Category</th><th>Severity</th><th>Open + Not Reviewed</th><th>Total Applicable</th><th>% Open/NR</th></tr></thead>"
$html += "        <tbody>"
$html += ("        <tr><td>CAT I</td><td>High</td><td>{0}</td><td>{1}</td><td>{2}%</td></tr>" -f $cat1Open, $cat1Total, $p1)
$html += ("        <tr><td>CAT II</td><td>Medium</td><td>{0}</td><td>{1}</td><td>{2}%</td></tr>" -f $cat2Open, $cat2Total, $p2)
$html += ("        <tr><td>CAT III</td><td>Low</td><td>{0}</td><td>{1}</td><td>{2}%</td></tr>" -f $cat3Open, $cat3Total, $p3)
$html += "        </tbody>"
$html += "      </table>"
$html += "    </div>"

# Filter panel
$html += "    <div class='filter-panel'>"
$html += "      <div class='fw-semibold mb-1'>Filters</div>"
$html += "      <div class='d-flex flex-wrap align-items-center'>"
$html += "        <div class='form-check form-check-inline'>"
$html += "          <input class='form-check-input' type='checkbox' id='filterHigh' checked>"
$html += "          <label class='form-check-label' for='filterHigh'>High</label>"
$html += "        </div>"
$html += "        <div class='form-check form-check-inline'>"
$html += "          <input class='form-check-input' type='checkbox' id='filterMed' checked>"
$html += "          <label class='form-check-label' for='filterMed'>Medium</label>"
$html += "        </div>"
$html += "        <div class='form-check form-check-inline'>"
$html += "          <input class='form-check-input' type='checkbox' id='filterLow' checked>"
$html += "          <label class='form-check-label' for='filterLow'>Low</label>"
$html += "        </div>"
$html += "        <div class='form-check form-check-inline ms-3'>"
$html += "          <input class='form-check-input' type='checkbox' id='filterNR' checked>"
$html += "          <label class='form-check-label' for='filterNR'>Show Not Reviewed</label>"
$html += "        </div>"
$html += "        <button type='button' class='btn btn-sm btn-outline-secondary ms-3' onclick='resetStigFilters()'>Reset</button>"
$html += "      </div>"
$html += "      <div class='tiny mt-1'>Severity filters apply to all STIG sections below. Not Reviewed can be hidden without affecting CORA math.</div>"
$html += "    </div>"

# Accordion for STIGs
$html += "    <div class='accordion' id='stigAccordion'>"

$stigIndex = 0

foreach ($s in ($byStig.Values | Sort-Object DisplayTitle)) {

    if (-not $s.Findings.Values -or $s.Findings.Count -eq 0) { continue }

    $stigIndex++
    $accordionId = "stig$stigIndex"
    $headingId   = "heading$stigIndex"
    $collapseId  = "collapse$stigIndex"

    $displayTitle = [System.Web.HttpUtility]::HtmlEncode($s.DisplayTitle)
    $releaseText  = if ($s.ReleaseText) { [System.Web.HttpUtility]::HtmlEncode($s.ReleaseText) } else { "" }

    $highCount = $s.HighOpen
    $medCount  = $s.MediumOpen
    $lowCount  = $s.LowOpen
    $nrCount   = $s.NotReviewedCt

    # Build CSV rows for this STIG
    $csvRows = @()
    foreach ($f in $s.Findings.Values) {
        $hostsList = ($f.Hosts.Keys | Sort-Object) -join ", "
        $csvRows += [pscustomobject]@{
            VulnId        = $f.VulnId
            RuleId        = $f.RuleId
            Severity      = $f.Severity
            Title         = $f.Title
            StatusGroup   = $f.StatusGroup
            AffectedHosts = $hostsList
        }
    }

    $safeStigName = Get-SafeFileName $s.DisplayTitle
    $csvFileName  = "{0}_{1}.csv" -f $safeRole, $safeStigName
    $csvPathFull  = Join-Path $csvFolder $csvFileName

    if ($csvRows.Count -gt 0) {
        $csvRows | Export-Csv -Path $csvPathFull -NoTypeInformation -Encoding UTF8
    }

    # For displaying path in HTML
    $csvPathDisplay = Join-Path (Join-Path (Join-Path $ShareRoot "Reports") $RoleName) (Join-Path "csv" $csvFileName)
    $csvPathDisplayHtml = [System.Web.HttpUtility]::HtmlEncode($csvPathDisplay)

    # Accordion header
    $html += "      <div class='accordion-item'>"
    $html += "        <h2 class='accordion-header' id='$headingId'>"
    $html += "          <button class='accordion-button collapsed' type='button' data-bs-toggle='collapse' data-bs-target='#$collapseId' aria-expanded='false' aria-controls='$collapseId'>"
    $html += "            <div>"
    $html += "              <div class='fw-semibold'>$displayTitle</div>"
    if ($releaseText) {
        $html += "              <div class='small text-muted'>$releaseText</div>"
    }
    $html += "            </div>"
    $html += "            <div class='stig-badges ms-auto d-flex align-items-center'>"
    $html += "              <span class='badge text-bg-danger'>High: $highCount</span>"
    $html += "              <span class='badge text-bg-warning ms-1'>Medium: $medCount</span>"
    $html += "              <span class='badge text-bg-success ms-1'>Low: $lowCount</span>"
    $html += "              <span class='badge text-bg-secondary ms-1'>Not Reviewed: $nrCount</span>"
    $html += "            </div>"
    $html += "          </button>"
    $html += "        </h2>"

    # Accordion body
    $html += "        <div id='$collapseId' class='accordion-collapse collapse' aria-labelledby='$headingId' data-bs-parent='#stigAccordion'>"
    $html += "          <div class='accordion-body'>"

    $html += "            <div class='d-flex justify-content-between align-items-center mb-1'>"
    $html += "              <div class='tiny'>Findings are de-duplicated by Vuln ID / Rule ID across hosts. Affected Hosts shows all impacted systems.</div>"
    if ($csvRows.Count -gt 0) {
        $html += "              <button type='button' class='btn btn-sm btn-outline-primary' disabled>CSV exported to: $csvFileName</button>"
    }
    $html += "            </div>"

    if ($csvRows.Count -gt 0) {
        $html += "            <div class='tiny mb-2'>CSV Path: <code>$csvPathDisplayHtml</code></div>"
    }

    # Single table with all severities; filtered client-side
    $html += "            <table class='table table-sm table-striped table-bordered table-findings'>"
    $html += "              <thead>"
    $html += "                <tr><th>Vuln ID</th><th>Rule ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Affected Hosts</th></tr>"
    $html += "              </thead>"
    $html += "              <tbody>"

    foreach ($row in ($s.Findings.Values | Sort-Object Severity, VulnId, RuleId)) {
        $sev = $row.Severity
        $sg  = $row.StatusGroup
        $hostsList = ($row.Hosts.Keys | Sort-Object) -join ", "

        $sevClass = ""
        switch ($sev) {
            "High"   { $sevClass = "sev-high" }
            "Medium" { $sevClass = "sev-medium" }
            "Low"    { $sevClass = "sev-low" }
        }

        $statusClass = if ($sg -eq "Open") { "status-open" } else { "status-nr" }

        $sevHtml    = [System.Web.HttpUtility]::HtmlEncode($sev)
        $statusHtml = [System.Web.HttpUtility]::HtmlEncode(($sg -replace "_"," "))
        $vulnHtml   = [System.Web.HttpUtility]::HtmlEncode($row.VulnId)
        $ruleHtml   = [System.Web.HttpUtility]::HtmlEncode($row.RuleId)
        $titleHtml  = [System.Web.HttpUtility]::HtmlEncode($row.Title)
        $hostsHtml  = [System.Web.HttpUtility]::HtmlEncode($hostsList)

        $dataSeverity = $sevHtml
        $dataStatus   = ($sg -eq "Not_Reviewed") ? "Not_Reviewed" : "Open"

        $html += "                <tr class='finding-row $sevClass $statusClass' data-severity='$dataSeverity' data-status='$dataStatus'>"
        $html += "                  <td>$vulnHtml</td>"
        $html += "                  <td>$ruleHtml</td>"
        $html += "                  <td>$titleHtml</td>"
        $html += "                  <td class='$sevClass'>$sevHtml</td>"
        $html += "                  <td class='$statusClass'>$statusHtml</td>"
        $html += "                  <td>$hostsHtml</td>"
        $html += "                </tr>"
    }

    $html += "              </tbody>"
    $html += "            </table>"

    $html += "          </div>"  # accordion-body
    $html += "        </div>"    # collapse
    $html += "      </div>"      # accordion-item
}

$html += "    </div>"  # accordion
$html += "  </div>"    # card-main
$html += "</div>"      # page

$html += "<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'></script>"
$html += $scriptBlock
$html += "</body>"
$html += "</html>"

# ---------------- Write output ----------------

($html -join "`r`n") | Out-File -FilePath $outPath -Encoding UTF8

Write-Host "✅ STIG rollup report created:"
Write-Host "   $outPath"
Write-Host "   Per-STIG CSVs written to: $csvFolder"
