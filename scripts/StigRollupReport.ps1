<#
.SYNOPSIS
  Generates a STIG Rollup HTML report by combining Evaluate-STIG CKL outputs
  across all hosts in a given role (e.g. domain_controllers).

.DESCRIPTION
  - Parses *.ckl files from:
        <ShareRoot>\<RoleName>\<Host>\Checklist\*.ckl
  - Groups findings by STIG (title + version/release info).
  - De-duplicates findings so each Vuln ID / Rule ID appears once per STIG,
    with merged host statuses in the "Hosts (Status)" column.
  - Shows per-STIG summary like:
        High: X   Medium: Y   Low: Z   Not Reviewed: W
    where High/Medium/Low = *Open only* and Not Reviewed is separate.
  - Builds sections per STIG:
        High Severity (Open)
        Medium Severity (Open)
        Low Severity (Open)
        Not Reviewed
  - Computes CORA-style risk at *role* level:
        - Not_Reviewed is treated as Open for CORA only.
        - Uses CAT I/II/III (High/Medium/Low) with weighted average
          10 / 4 / 1 and Risk Rating thresholds.

.PARAMETER ShareRoot
  Root share containing role folders (e.g. \\server\STIG-Results)

.PARAMETER RoleName
  Role folder under the share (e.g. domain_controllers, member_servers)

.PARAMETER OutputName
  Base file name for the generated HTML (e.g. STIG-Rollup.html).
  The script will automatically timestamp the final file:
      STIG-Rollup_<role>_yyyyMMdd-HHmm.html
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
        "^(?i)open$"              { return "Open" }
        "^(?i)not[_]?reviewed$"   { return "Not_Reviewed" }
        "^(?i)notafinding$"       { return "NotAFinding" }
        "^(?i)not.?a.?finding$"   { return "NotAFinding" }
        "^(?i)pass$"              { return "NotAFinding" }
        "^(?i)not[_]?applicable$" { return "Not_Applicable" }
        "^(?i)na$"                { return "Not_Applicable" }
        default                   { return $v }
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

    # Clean up the title for display
    $displayTitle = $titleRaw -replace "Security Technical Implementation Guide","STIG"
    $displayTitle = $displayTitle.Trim()

    # Build "Version / Release / Benchmark Date" line
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

                # ---------- Display filter: ONLY Open / Not_Reviewed ----------
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
            $nrCount++`
        }
    }

    $s.HighOpen      = $highOpen
    $s.MediumOpen    = $medOpen
    $s.LowOpen       = $lowOpen
    $s.NotReviewedCt = $nrCount

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
    $weightedAvg = [math]::Round((( $p1 * 10.0 ) + ( $p2 * 4.0 ) + ( $p3 * 1.0 )) / 15.0, 1)
}

function Get-RiskRating {
    param([double]$Score, [int]$Cat1Open, [double]$P2, [double]$P3)

    if ($Score -ge 20.0) { return "Very High Risk" }
    elseif ($Score -ge 10.0) { return "High Risk" }
    elseif ($Score -gt 0.0) {
        if ( ($Cat1Open -eq 0) -and ($P2 -lt 5.0) -and ($P3 -lt 5.0) ) {
            return "Low Risk"
        }
        else {
            return "Moderate Risk"
        }
    }
    else {
        return "Very Low Risk"
    }
}

$riskRating = Get-RiskRating -Score $weightedAvg -Cat1Open $cat1Open -P2 $p2 -P3 $p3

# ---------------- Generate HTML (Modern Light) ----------------

$timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$style = @"
<style>
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  margin: 0;
  padding: 24px;
  background: #f5f7fb;
  color: #111827;
}
.page {
  max-width: 1200px;
  margin: 0 auto;
  background: #ffffff;
  border-radius: 12px;
  box-shadow: 0 10px 25px rgba(15,23,42,0.12);
  padding: 24px 28px 32px;
}
h1 {
  margin-bottom: 4px;
  font-size: 24px;
}
h2 {
  margin-top: 24px;
  margin-bottom: 8px;
  font-size: 18px;
}
h3 {
  margin-top: 18px;
  margin-bottom: 6px;
  font-size: 15px;
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
  margin-right: 8px;
}
.pill-role      { background: #eff6ff; color: #1d4ed8; }
.pill-generated { background: #ecfdf3; color: #16a34a; }
.pill-risk      { background: #fef3c7; color: #92400e; }

table {
  border-collapse: collapse;
  width: 100%;
  margin-bottom: 18px;
  font-size: 13px;
}
th, td {
  border: 1px solid #e5e7eb;
  padding: 6px 8px;
  text-align: left;
}
th {
  background: #f9fafb;
  font-weight: 600;
}
tr:nth-child(even) td {
  background-color: #f9fafb;
}
.open {
  color: #b91c1c;
  font-weight: 600;
}
.nr {
  color: #92400e;
  font-weight: 600;
}
.na {
  color: #4b5563;
}
.stig-meta {
  font-size: 12px;
  margin-bottom: 6px;
  color: #4b5563;
}
.stig-counts {
  font-size: 12px;
  margin-bottom: 10px;
}
.cora-summary {
  border: 1px solid #e5e7eb;
  background: #ffffff;
  padding: 10px 12px;
  border-radius: 8px;
  margin-bottom: 24px;
}
.cora-summary table {
  width: auto;
  margin-top: 8px;
}
.cora-summary th, .cora-summary td {
  font-size: 12px;
  padding: 3px 6px;
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

Add-Type -AssemblyName System.Web

$html = @()
$html += "<html><head><title>STIG Rollup Report - $RoleName</title>$style</head><body>"
$html += "<div class='page'>"
$html += "<h1>STIG Rollup Report - $RoleName</h1>"
$html += "<div class='meta'>"
$html += "<span class='pill pill-role'>Role: $RoleName</span>"
$html += "<span class='pill pill-generated'>Generated: $timeStamp</span>"
$html += "<span class='pill pill-risk'>Risk: $riskRating</span>"
$html += "<div>Total Hosts Evaluated: $totalHosts</div>"
$html += "</div>"

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

# Per-STIG sections
foreach ($s in ($byStig.Values | Sort-Object DisplayTitle)) {

    if (-not $s.Findings.Values -or $s.Findings.Count -eq 0) { continue }

    $html += ("<h2>{0}</h2>" -f [System.Web.HttpUtility]::HtmlEncode($s.DisplayTitle))

    if ($s.ReleaseText) {
        $html += ("<div class='stig-meta'>Release Info: {0}</div>" -f [System.Web.HttpUtility]::HtmlEncode($s.ReleaseText))
    }

    $html += ("<div class='stig-counts'><b>High (Open):</b> {0} &nbsp;&nbsp; <b>Medium (Open):</b> {1} &nbsp;&nbsp; <b>Low (Open):</b> {2} &nbsp;&nbsp; <b>Not Reviewed:</b> {3}</div>" -f `
              $s.HighOpen, $s.MediumOpen, $s.LowOpen, $s.NotReviewedCt)

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
            [array]$RowsRef,
            [ref]$htmlRef
        )
        if (-not $RowsRef -or $RowsRef.Count -eq 0) { return }

        $htmlRef.Value += ("<h3>{0}</h3>" -f $Label)
        $htmlRef.Value += "<table><tr><th>Vuln ID</th><th>Rule ID</th><th>Title</th><th>Severity</th><th>Affected Hosts</th></tr>"

        foreach ($row in ($RowsRef | Sort-Object VulnId, RuleId)) {
            $hostsHtmlParts = @()
            foreach ($hn in ($row.Hosts.Keys | Sort-Object)) {
                $st = $row.Hosts[$hn]
                $cls = if ($st -eq "Open") { "open" } else { "nr" }

                $hostsHtmlParts += ("<span class='host-pill'>{0} - <span class='{1}'>{2}</span></span>" -f `
                                    [System.Web.HttpUtility]::HtmlEncode($hn),
                                    $cls,
                                    [System.Web.HttpUtility]::HtmlEncode(($st -replace "_"," ")))
            }
            $hostsHtml = ($hostsHtmlParts -join " ")

            $htmlRef.Value += ("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>" -f `
                             [System.Web.HttpUtility]::HtmlEncode($row.VulnId),
                             [System.Web.HttpUtility]::HtmlEncode($row.RuleId),
                             [System.Web.HttpUtility]::HtmlEncode($row.Title),
                             [System.Web.HttpUtility]::HtmlEncode($row.Severity),
                             $hostsHtml)
        }

        $htmlRef.Value += "</table>"
    }

    Add-GroupTable -Label "High Severity (Open)"   -RowsRef $highRows -htmlRef ([ref]$html)
    Add-GroupTable -Label "Medium Severity (Open)" -RowsRef $medRows  -htmlRef ([ref]$html)
    Add-GroupTable -Label "Low Severity (Open)"    -RowsRef $lowRows  -htmlRef ([ref]$html)
    Add-GroupTable -Label "Not Reviewed"           -RowsRef $nrRows   -htmlRef ([ref]$html)
}

$html += "</div></body></html>"

# ---------------- Write output file ----------------

$baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputName)
if (-not $baseName) { $baseName = "STIG-Rollup" }

$ext = [System.IO.Path]::GetExtension($OutputName)
if (-not $ext) { $ext = ".html" }

$safeRole = ($RoleName -replace "[^A-Za-z0-9_\-]", "_")
$tsFile   = Get-Date -Format "yyyyMMdd-HHmm"

$outFileName = "{0}_{1}_{2}{3}" -f $baseName, $safeRole, $tsFile, $ext
$outPath = Join-Path $rolePath $outFileName

($html -join "`r`n") | Out-File -FilePath $outPath -Encoding UTF8

Write-Host "✅ STIG rollup report created:" -ForegroundColor Green
Write-Host "   $outPath"
