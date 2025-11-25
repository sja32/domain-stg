<#
.SYNOPSIS
  Generates a STIG Rollup HTML report by combining Evaluate-STIG CKL outputs
  across all hosts in a given role (e.g. domain_controllers).

.DESCRIPTION
  - Parses *.ckl files from:
        <ShareRoot>\<RoleName>\<Host>\Checklist\*.ckl
  - Groups findings by STIG (title + version/release info).
  - De-duplicates findings so each Vuln ID / Rule ID appears once per STIG,
    with merged hosts in the "Affected Hosts" column.
  - Only displays findings where STATUS is Open or Not_Reviewed.
    (Not_Reviewed is treated as "open" for CORA metrics.)
  - Shows a CORA-style risk summary at the role level.
  - Each STIG section is collapsible (<details>/<summary>), collapsed by default.
  - Includes a client-side filter bar to toggle:
        High / Medium / Low / Not Reviewed
    (any combination).

.PARAMETER ShareRoot
  Root share containing role folders (e.g. \\appsvr1\stig-results)

.PARAMETER RoleName
  Role folder under the share (e.g. domain_controllers, member_servers)

.PARAMETER OutputName
  Base file name for the generated HTML (e.g. STIG-Rollup.html).
  The script will automatically produce:
      STIG-Rollup_<role>_yyyyMMdd-HHmm.html
  and save it under:
      <ShareRoot>\Reports\<RoleName>\
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

# Ensure System.Web (for HtmlEncode) is available
[void][Reflection.Assembly]::LoadWithPartialName("System.Web")

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
        # Handle "Version 2, Release 5 :: 09 Nov 2023" and similar
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

    # Build a nice "Version X, Release Y, Date" string
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

# ---------------- Discover scope ----------------

$rolePath = Join-Path $ShareRoot $RoleName
if (-not (Test-Path $rolePath)) {
    throw "Role path not found: $rolePath"
}

$hostFolders = Get-ChildItem -Path $rolePath -Directory | Sort-Object Name
if (-not $hostFolders) {
    throw "No host folders found under $rolePath"
}

$totalHosts = $hostFolders.Count
Write-Host "Found $totalHosts host(s) under '$RoleName'."

# ---------------- Data model ----------------

# Per-STIG data: keyed by "TitleRaw|ReleaseText"
$byStig = @{}

# CORA counters (role level)
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

# ---------------- Bail out if nothing ----------------

if (-not $anyFindings) {
    throw "No Open or Not Reviewed findings detected under $rolePath."
}

# ---------------- Compute per-STIG counts ----------------
# NEW: High/Medium/Low counts now include BOTH Open and Not_Reviewed.
# NotReviewedCt still counts all Not_Reviewed findings (all severities).

foreach ($k in $byStig.Keys) {
    $s = $byStig[$k]

    $highTotal = 0
    $medTotal  = 0
    $lowTotal  = 0
    $nrCount   = 0

    foreach ($f in $s.Findings.Values) {
        $sev = $f.Severity
        $sg  = $f.StatusGroup   # Open / Not_Reviewed

        switch ($sev) {
            "High"   { $highTotal++ }
            "Medium" { $medTotal++ }
            "Low"    { $lowTotal++ }
        }

        if ($sg -eq "Not_Reviewed") {
            $nrCount++
        }
    }

    $s.HighTotal      = $highTotal
    $s.MediumTotal    = $medTotal
    $s.LowTotal       = $lowTotal
    $s.NotReviewedCt  = $nrCount

    $byStig[$k] = $s
}

# ---------------- CORA Risk Rating (role level) ----------------

function Get-Percent {
    param (
        [int]$Open,
        [int]$Total
    )
    if ($Total -le 0) { return 0.0 }
    return [math]::Round(100.0 * $Open / $Total, 1)
}

$p1 = Get-Percent -Open $cat1Open -Total $cat1Total
$p2 = Get-Percent -Open $cat2Open -Total $cat2Total
$p3 = Get-Percent -Open $cat3Open -Total $cat3Total

$weightedAvg = 0.0
if (($cat1Total + $cat2Total + $cat3Total) -gt 0) {
    # Original weighting: CAT I = 10, CAT II = 4, CAT III = 1 (total 15)
    $weightedAvg = [math]::Round((( $p1 * 10.0 ) + ( $p2 * 4.0 ) + ( $p3 * 1.0 )) / 15.0, 1)
}

# Risk Rating thresholds (unchanged from your earlier logic)
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

# ---------------- Generate HTML ----------------

$timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$style = @"
<style>
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
  margin: 20px;
  background: #f3f4f6;
  color: #111827;
}
h1 {
  margin-bottom: 5px;
}
p, div {
  font-size: 13px;
}
.main-card {
  max-width: 1200px;
  margin: 0 auto;
  background: #ffffff;
  border-radius: 10px;
  box-shadow: 0 4px 16px rgba(15,23,42,0.12);
  padding: 20px 24px 28px 24px;
}
.badge-row {
  margin-top: 4px;
  margin-bottom: 14px;
}
.badge {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .04em;
  padding: 3px 10px;
  border-radius: 999px;
  margin-right: 6px;
}
.badge-role { background:#eff6ff; color:#1d4ed8; }
.badge-generated { background:#ecfdf3; color:#16a34a; }
.badge-risk { background:#fef3c7; color:#92400e; }

.filter-bar {
  margin: 10px 0 6px 0;
  padding: 8px 10px;
  border-radius: 6px;
  background:#f9fafb;
  border:1px solid #e5e7eb;
  font-size: 12px;
}
.filter-bar label {
  margin-right: 12px;
  cursor:pointer;
}
.filter-bar input[type=checkbox] {
  vertical-align: middle;
}

.legend-row {
  font-size: 12px;
  margin-bottom: 16px;
  color:#374151;
}

table {
  border-collapse: collapse;
  width: 100%;
  margin-bottom: 18px;
}
th, td {
  border: 1px solid #e5e7eb;
  padding: 5px 8px;
  text-align: left;
  font-size: 12px;
}
th {
  background: #f9fafb;
}
tr:nth-child(even) td {
  background-color: #f9fafb;
}
.sev-high   { color: #b91c1c; font-weight: 600; }
.sev-medium { color: #c05621; font-weight: 600; }
.sev-low    { color: #065f46; font-weight: 600; }

.cora-summary {
  border: 1px solid #e5e7eb;
  background: #ffffff;
  padding: 10px 12px;
  border-radius: 6px;
  margin-bottom: 20px;
}
.cora-summary h2 {
  margin: 0 0 6px 0;
  font-size: 15px;
}
.cora-summary table {
  width: auto;
  margin-top: 8px;
}
.cora-summary th, .cora-summary td {
  font-size: 12px;
  padding: 3px 6px;
}

.stig-block {
  border:1px solid #e5e7eb;
  border-radius: 8px;
  margin-bottom: 14px;
  background:#ffffff;
}
.stig-block > summary {
  list-style: none;
  cursor: pointer;
  padding: 8px 10px;
  display:flex;
  align-items:center;
  justify-content: space-between;
  background:#f9fafb;
  border-radius:8px 8px 0 0;
}
.stig-block[open] > summary {
  border-bottom:1px solid #e5e7eb;
  background:#eff6ff;
}
.stig-title {
  font-weight:600;
  font-size: 13px;
}
.stig-counts {
  font-size: 12px;
  color:#374151;
}
.stig-counts span {
  margin-left:10px;
}
.stig-body {
  padding: 8px 10px 12px 10px;
}
.stig-meta {
  font-size: 12px;
  margin-bottom: 6px;
  color:#4b5563;
}
.group-heading {
  margin-top: 10px;
  margin-bottom: 4px;
  font-size: 13px;
  font-weight:600;
}
.host-pill {
  display:inline-block;
  padding:2px 8px;
  margin:1px 4px 1px 0;
  border-radius:999px;
  background:#eef2ff;
  color:#3730a3;
  font-size:11px;
}
.tiny {
  font-size: 11px;
  color: #6b7280;
  margin-top: -8px;
  margin-bottom: 12px;
}

/* Dot icons for severity summary */
.dot {
  display:inline-block;
  width:10px;
  height:10px;
  border-radius:999px;
  margin-right:4px;
  vertical-align:middle;
}
.dot-high   { background:#ef4444; }  /* red */
.dot-medium { background:#fbbf24; }  /* yellow */
.dot-low    { background:#e5e7eb; }  /* light gray */
.dot-nr     { background:#111827; }  /* almost black */
</style>
"@

$scriptBlock = @"
<script>
function applySeverityFilters() {
  var showHigh = document.getElementById('filterHigh').checked;
  var showMed  = document.getElementById('filterMed').checked;
  var showLow  = document.getElementById('filterLow').checked;
  var showNR   = document.getElementById('filterNR').checked;

  var rows = document.querySelectorAll('tr.data-row');
  rows.forEach(function(row) {
    var sev = row.getAttribute('data-sev');      // High/Medium/Low/Other
    var st  = row.getAttribute('data-status');   // Open / Not_Reviewed

    var visible = true;

    if (sev === 'High' && !showHigh)   visible = false;
    if (sev === 'Medium' && !showMed)  visible = false;
    if (sev === 'Low' && !showLow)     visible = false;

    if (st === 'Not_Reviewed' && !showNR) {
      visible = false;
    }

    row.style.display = visible ? '' : 'none';
  });
}

document.addEventListener('DOMContentLoaded', function() {
  // Initial filter application (all boxes checked by default)
  applySeverityFilters();

  var boxes = document.querySelectorAll('.filter-bar input[type=checkbox]');
  boxes.forEach(function(cb) {
    cb.addEventListener('change', applySeverityFilters);
  });
});
</script>
"@

$html = @()
$html += "<html><head><title>STIG Rollup Report - $RoleName</title>$style</head><body>"
$html += "<div class='main-card'>"
$html += "<h1>STIG Rollup Report - $RoleName</h1>"
$html += "<div class='badge-row'>"
$html += "<span class='badge badge-role'>Role: $RoleName</span>"
$html += "<span class='badge badge-generated'>Generated: $timeStamp</span>"
$html += "<span class='badge badge-risk'>Risk: $riskRating</span>"
$html += "</div>"
$html += "<p class='tiny'>Not_Reviewed findings are treated as Open for CORA calculations.</p>"

# CORA summary (role level)
$html += "<div class='cora-summary'>"
$html += "<h2>CORA Risk Summary (Role Level)</h2>"
$html += ("<p><b>Risk Rating:</b> {0}<br/>" -f $riskRating)
$html += ("<b>Weighted Average:</b> {0}% (Not_Reviewed counted as Open)</p>" -f $weightedAvg)

$html += "<table>"
$html += "<tr><th>Category</th><th>Severity</th><th>Open + Not Reviewed</th><th>Total Applicable</th><th>% Open/NR</th></tr>"
$html += ("<tr><td>CAT I</td><td>High</td><td>{0}</td><td>{1}</td><td>{2}%</td></tr>" -f $cat1Open, $cat1Total, $p1)
$html += ("<tr><td>CAT II</td><td>Medium</td><td>{0}</td><td>{1}</td><td>{2}%</td></tr>" -f $cat2Open, $cat2Total, $p2)
$html += ("<tr><td>CAT III</td><td>Low</td><td>{0}</td><td>{1}</td><td>{2}%</td></tr>" -f $cat3Open, $cat3Total, $p3)
$html += "</table>"
$html += "</div>"

# Global filter bar
$html += "<div class='filter-bar'>"
$html += "<b>Filter Findings:&nbsp;</b>"
$html += "<label><input type='checkbox' id='filterHigh' checked> High</label>"
$html += "<label><input type='checkbox' id='filterMed' checked> Medium</label>"
$html += "<label><input type='checkbox' id='filterLow' checked> Low</label>"
$html += "<label><input type='checkbox' id='filterNR' checked> Not Reviewed</label>"
$html += "</div>"

# Optional global legend (matches per-STIG dots)
$html += "<div class='legend-row'>"
$html += "<span><span class='dot dot-high'></span><strong>High</strong></span>&nbsp;&nbsp;"
$html += "<span><span class='dot dot-medium'></span><strong>Medium</strong></span>&nbsp;&nbsp;"
$html += "<span><span class='dot dot-low'></span><strong>Low</strong></span>&nbsp;&nbsp;"
$html += "<span><span class='dot dot-nr'></span><strong>Not Reviewed</strong></span>"
$html += "</div>"

# Per-STIG sections
foreach ($s in ($byStig.Values | Sort-Object DisplayTitle)) {

    # Skip STIGs that ended up with no Open/NR findings
    if (-not $s.Findings.Values -or $s.Findings.Count -eq 0) { continue }

    $encTitle   = [System.Web.HttpUtility]::HtmlEncode($s.DisplayTitle)
    $encRelease = if ($s.ReleaseText) { [System.Web.HttpUtility]::HtmlEncode($s.ReleaseText) } else { "" }

    $html += "<details class='stig-block'>"
    $html += "<summary>"
    $html += "<span class='stig-title'>$encTitle</span>"
    $html += "<span class='stig-counts'>"
    $html += "<span><span class='dot dot-high'></span><strong>High:</strong> $($s.HighTotal)</span>"
    $html += "<span><span class='dot dot-medium'></span><strong>Medium:</strong> $($s.MediumTotal)</span>"
    $html += "<span><span class='dot dot-low'></span><strong>Low:</strong> $($s.LowTotal)</span>"
    $html += "<span><span class='dot dot-nr'></span><strong>Not Reviewed:</strong> $($s.NotReviewedCt)</span>"
    $html += "</span>"
    $html += "</summary>"
    $html += "<div class='stig-body'>"

    if ($s.ReleaseText) {
        $html += ("<div class='stig-meta'>Release Info: {0}</div>" -f $encRelease)
    }

    # Group findings
    $highRows = @()
    $medRows  = @()
    $lowRows  = @()
    $nrRows   = @()

    foreach ($f in $s.Findings.Values) {
        if ($f.StatusGroup -eq "Open") {
            switch ($f.Severity) {
                "High"   { $highRows += $f }
                "Medium" { $medRows  += $f }
                "Low"    { $lowRows  += $f }
                default  { }
            }
        }
        elseif ($f.StatusGroup -eq "Not_Reviewed") {
            $nrRows += $f
        }
    }

    function Add-GroupTable {
        param (
            [string]$Label,
            [array]$RowsRef
        )
        if (-not $RowsRef -or $RowsRef.Count -eq 0) { return }

        $script:html += ("<div class='group-heading'>{0}</div>" -f $Label)
        $script:html += "<table><tr><th>Vuln ID</th><th>Rule ID</th><th>Title</th><th>Severity</th><th>Affected Hosts</th></tr>"

        foreach ($row in ($RowsRef | Sort-Object VulnId, RuleId)) {
            $sevClass = ""
            switch ($row.Severity) {
                "High"   { $sevClass = "sev-high" }
                "Medium" { $sevClass = "sev-medium" }
                "Low"    { $sevClass = "sev-low" }
            }

            # Host list – names only, de-duplicated
            $hostNames  = $row.Hosts.Keys | Sort-Object
            $hostPills  = @()
            foreach ($hn in $hostNames) {
                $hostPills += ("<span class='host-pill'>{0}</span>" -f `
                    [System.Web.HttpUtility]::HtmlEncode($hn))
            }
            $hostsHtml = ($hostPills -join "")

            $statusAttr = $row.StatusGroup  # Open / Not_Reviewed

            $script:html += ("<tr class='data-row' data-sev='{0}' data-status='{1}'>" -f `
                             [System.Web.HttpUtility]::HtmlEncode($row.Severity),
                             [System.Web.HttpUtility]::HtmlEncode($statusAttr))

            $script:html += ("<td>{0}</td><td>{1}</td><td>{2}</td><td class='{3}'>{4}</td><td>{5}</td></tr>" -f `
                             [System.Web.HttpUtility]::HtmlEncode($row.VulnId),
                             [System.Web.HttpUtility]::HtmlEncode($row.RuleId),
                             [System.Web.HttpUtility]::HtmlEncode($row.Title),
                             $sevClass,
                             [System.Web.HttpUtility]::HtmlEncode($row.Severity),
                             $hostsHtml)
        }

        $script:html += "</table>"
    }

    Add-GroupTable -Label "High Severity (Open)"    -RowsRef $highRows
    Add-GroupTable -Label "Medium Severity (Open)"  -RowsRef $medRows
    Add-GroupTable -Label "Low Severity (Open)"     -RowsRef $lowRows
    Add-GroupTable -Label "Not Reviewed"            -RowsRef $nrRows

    $html += "</div>"  # .stig-body
    $html += "</details>"
}

$html += "</div>" # .main-card
$html += $scriptBlock
$html += "</body></html>"

# ---------------- Write output file ----------------

# Timestamped output name: STIG-Rollup_<role>_yyyyMMdd-HHmm.html
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputName)
if (-not $baseName) { $baseName = "STIG-Rollup" }

$ext = [System.IO.Path]::GetExtension($OutputName)
if (-not $ext) { $ext = ".html" }

$safeRole = ($RoleName -replace "[^A-Za-z0-9_\-]", "_")
$tsFile   = Get-Date -Format "yyyyMMdd-HHmm"

$outFileName = "{0}_{1}_{2}{3}" -f $baseName, $safeRole, $tsFile, $ext

# Write to <ShareRoot>\Reports\<RoleName>\
$reportsRoot   = Join-Path $ShareRoot "Reports"
$roleReportDir = Join-Path $reportsRoot $RoleName

if (-not (Test-Path $roleReportDir)) {
    New-Item -Path $roleReportDir -ItemType Directory -Force | Out-Null
}

$outPath = Join-Path $roleReportDir $outFileName

($html -join "`r`n") | Out-File -FilePath $outPath -Encoding UTF8

Write-Host "✅ STIG rollup report created:" -ForegroundColor Green
Write-Host "   $outPath"
