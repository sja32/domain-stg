param(
    [Parameter(Mandatory=$true)]
    [string] $ShareRoot,

    [Parameter(Mandatory=$true)]
    [string] $RoleName,

    [Parameter(Mandatory=$true)]
    [string] $OutputName
)

# Normalize paths
$rolePath = Join-Path -Path $ShareRoot -ChildPath $RoleName

Write-Host "=== STIG Rollup Report ==="
Write-Host "Share Root : $ShareRoot"
Write-Host "Role Name  : $RoleName"
Write-Host "Output Name: $OutputName"

# Validate role folder
if (-not (Test-Path -Path $rolePath)) {
    throw "Role path '$rolePath' does not exist. Verify ShareRoot and RoleName."
}

# Get all checklist XML files
$cklFiles = Get-ChildItem -Path $rolePath -Filter '*.ckl' -Recurse -ErrorAction SilentlyContinue

if ($cklFiles.Count -eq 0) {
    throw "No CKL files found under '$rolePath'."
}

# Build HTML
$body  = "<html><body>"
$body += "<h1>STIG Rollup - $RoleName</h1>"
$body += "<table border='1' cellpadding='5'>"
$body += "<tr><th>Host</th><th>Vuln ID</th><th>Status</th></tr>"

foreach ($file in $cklFiles) {
    [xml]$xml = Get-Content $file.FullName -ErrorAction Stop
    $hostName = $xml.Checklist.Asset.Asset_Identification.Host_Name

    foreach ($vul in $xml.Checklist.Vuln) {
        $vulnID = $vul.Vuln_Num.InnerText
        $status = $vul.Status.InnerText

        $body += "<tr><td>$hostName</td><td>$vulnID</td><td>$status</td></tr>"
    }
}

$body += "</table></body></html>"

# Write output
$outputFile = Join-Path -Path $PSScriptRoot -ChildPath $OutputName
$body | Out-File -FilePath $outputFile -Encoding ASCII

Write-Host "Rollup saved to: $outputFile"
