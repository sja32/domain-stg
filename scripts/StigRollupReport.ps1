param(
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,        # THIS WILL BE "R:\" ONLY

    [Parameter(Mandatory = $true)]
    [string]$RoleName,

    [string]$OutputName = "SummaryReport.html"
)

Write-Host "=== STIG Rollup Report ==="
Write-Host "Share Root : $ShareRoot"
Write-Host "Role Name  : $RoleName"
Write-Host "Output Name: $OutputName"

# Build role folder under mapped R:\ drive
$rootClean = $ShareRoot.TrimEnd('\')
$rolePath  = Join-Path $rootClean $RoleName

if (-not (Test-Path -Path $rolePath)) {
    throw "Role path '$rolePath' does not exist. Verify ShareRoot and RoleName."
}

# Enumerate host folders
$hostDirs = Get-ChildItem $rolePath -Directory
if ($hostDirs.Count -eq 0) {
    throw "No host folders found under '$rolePath'."
}

# Build rollup table
$findingsIndex = @{}

foreach ($host in $hostDirs) {
    $hostSummary = Join-Path $host.FullName "SummaryReport.xml"
    if (-not (Test-Path $hostSummary)) { continue }

    [xml]$xml = Get-Content $hostSummary -ErrorAction Stop

    foreach ($finding in $xml.SelectNodes("//Finding")) {
        $id = $finding.VulnId
        if (-not $findingsIndex.ContainsKey($id)) {
            $findingsIndex[$id] = @()
        }

        $findingsIndex[$id] += [pscustomobject]@{
            Hostname = $host.Name
            Status   = $finding.Status
            RuleId   = $finding.RuleId
            Title    = $finding.RuleTitle
        }
    }
}

# Generate HTML
$htmlPath = Join-Path $rolePath $OutputName

$body = @()
$body += "<html><body><h1>STIG Rollup – $RoleName</h1>"
$body += "<table border='1' cellpadding='5'>"
$body += "<tr><th>Vuln ID</th><th>Rule</th><th>Hostname</th><th>Status</th></tr>"

foreach ($id in $findingsIndex.Keys) {
    foreach ($entry in $findingsIndex[$id]) {
        $body += "<tr><td>$($id)</td><td>$($entry.Title)</td><td>$($entry.Hostname)</td><td>$($entry.Status)</td></tr>"
    }
}

$body += "</table></body></html>"

$body -join "`n" | Set-Content -Path $htmlPath -Force -Encoding UTF8

Write-Host "Rollup saved to: $htmlPath"
