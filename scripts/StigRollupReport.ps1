param(
    [Parameter(Mandatory = $true)]
    [string]$ShareRoot,

    [Parameter(Mandatory = $true)]
    [string]$RoleName,

    [Parameter(Mandatory = $true)]
    [string]$OutputName
)

# ----------------- Normalize Inputs -----------------
$ShareRoot  = $ShareRoot.Trim().TrimEnd('\')
$RoleName   = $RoleName.Trim()
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

foreach ($host in $hostDirs) {

    $hostName = $host.Name

    # *** PATCHED: No more Checklist subfolder ***
    $cklPath  = $host.FullName
    $cklFiles = Get-ChildItem -Path $cklPath -Filter "*.ckl" -ErrorAction SilentlyContinue

    if ($cklFiles.Count -eq 0) {
        Write-Host "⚠️ No CKL files found for $hostName"
        continue
    }

    foreach ($ckl in $cklFiles) {

        try {
            $xml = [xml](Get-Content $ckl.FullName)
        }
        catch {
            Write-Host "⚠️ Failed to read $($ckl.Name)"
            continue
        }

        # PARSE CKL CONTENT
        $vulns = $xml.CHECKLIST.STIGS.iSTIG.VULN

        foreach ($v in $vulns) {
            $rows += [pscustomobject]@{
                HostName  = $hostName
                VulnID    = $v.VULN_ATTRIBUTE |
                            Where-Object { $_.ATTRIBUTE_NAME -eq "Vuln_Num" } |
                            Select-Object -ExpandProperty ATTRIBUTE_DATA

                RuleID    = $v.STIG_DATA |
                            Where-Object { $_.VULN_ATTRIBUTE.ATTRIBUTE_NAME -eq "Rule_ID" } |
                            Select-Object -ExpandProperty VULN_ATTRIBUTE |
                            Select-Object -ExpandProperty ATTRIBUTE_DATA

                Status    = $v.STATUS
                Severity  = $v.SEVERITY
                Comments  = $v.COMMENTS
            }
        }
    }
}

# ----------------- Generate HTML -----------------
$html = $rows | Sort-Object HostName, VulnID | ConvertTo-Html -Title "STIG Rollup Report" |
    Out-String

$outFile = Join-Path -Path $outputFolder -ChildPath $OutputName

$html | Out-File -FilePath $outFile -Encoding UTF8

Write-Host "✅ Rollup Complete: $outFile"
