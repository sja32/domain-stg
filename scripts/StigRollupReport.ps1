param(
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,      # UNC root (\\server\STIG-Results)

    [Parameter(Mandatory = $true)]
    [string]$RoleName,       # domain_controllers, member_servers, workstations

    [Parameter(Mandatory = $true)]
    [string]$Username,       # SMB username (voughtnet\svc-ansible)

    [Parameter(Mandatory = $true)]
    [string]$Password,       # SMB password

    [string]$OutputName = "SummaryReport-Rollup.html"
)

Write-Host "=== STIG Rollup Report ==="
Write-Host "Share Root : $ShareRoot"
Write-Host "Role Name  : $RoleName"
Write-Host "Output Name: $OutputName"

# -------------------------------------------------------------------
# Authenticate to UNC share (fixes double-hop issue in WinRM)
# -------------------------------------------------------------------
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)

# Create temporary mapped drive
New-PSDrive -Name "STIG" -PSProvider FileSystem -Root $ShareRoot -Credential $Cred -Scope Script -ErrorAction Stop

$rolePath = "STIG:\$RoleName"

if (-not (Test-Path -Path $rolePath)) {
    throw "Role path '$rolePath' does not exist. Verify ShareRoot and RoleName."
}

$hostDirs = Get-ChildItem -Path $rolePath -Directory
if ($hostDirs.Count -eq 0) {
    throw "No host folders found under '$rolePath'."
}

# -------------------------------------------------------------------
# Collect & aggregate XML SummaryReport.xml files
# -------------------------------------------------------------------
$results = @()

foreach ($host in $hostDirs) {

    $summaryFile = Join-Path $host.FullName -ChildPath "SummaryReport.xml"
    if (-not (Test-Path $summaryFile)) { continue }

    [xml]$xml = Get-Content $summaryFile

    foreach ($rule in $xml.SelectNodes("//RULE")) {
        $id = $rule.ID
        $status = $rule.STATUS

        $results += [PSCustomObject]@{
            Host   = $host.Name
            RuleID = $id
            Status = $status
        }
    }
}

# -------------------------------------------------------------------
# Generate simple HTML rollup
# -------------------------------------------------------------------

$html = @()
$html += "<html><head><title>STIG Rollup - $RoleName</title></head><body>"
$html += "<h2>STIG Rollup Summary - $RoleName</h2>"
$html += "<table border='1' cellpadding='4'><tr><th>Host</th><th>Rule ID</th><th>Status</th></tr>"

foreach ($r in $results) {
    $html += "<tr><td>$($r.Host)</td><td>$($r.RuleID)</td><td>$($r.Status)</td></tr>"
}

$html += "</table></body></html>"

$dest = "STIG:\$RoleName\$OutputName"
$html -join "`n" | Out-File -FilePath $dest -Encoding utf8

Write-Host "Report written to: $dest"
