param(
    [string]$ComputerName,
    [string]$EvalShare = "\\192.168.10.198\Evaluate-STIG",
    [string]$ResultsShare = "\\192.168.10.198\stig-results"
)

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host " 🚀  Starting Evaluate-STIG Scan on $ComputerName"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host ""

### Map Shares
Write-Host "🔄  Mapping Evaluate-STIG Share..."
New-PSDrive -Name Z -PSProvider FileSystem -Root $EvalShare -ErrorAction SilentlyContinue | Out-Null
Write-Host " ✅"

Write-Host "🔄  Mapping Results Share..."
New-PSDrive -Name Y -PSProvider FileSystem -Root $ResultsShare -ErrorAction SilentlyContinue | Out-Null
Write-Host " ✅"

### Paths
$Version = "Evaluate-STIG_1.2507.5"
$LocalInstall = "C:\ProgramData\$Version"
$RemoteInstall = "Z:\$Version"

$ChecklistOutputRoot = "Y:\$ComputerName\Checklist"

Write-Host "📁  Ensuring Local Install Folder Exists..."
New-Item -ItemType Directory -Force -Path $LocalInstall | Out-Null
Write-Host " ✅"

### Copy Evaluate-STIG Locally
Write-Host "📦  Copying Evaluate-STIG Toolkit Locally..."
Copy-Item -Path "$RemoteInstall\*" -Destination $LocalInstall -Recurse -Force
Write-Host " ✅"

### Ensure Certificates
Write-Host "🔓  Importing STIG Certificates..."
Get-ChildItem -Path "$LocalInstall\Certs\*.cer" | ForEach-Object {
    Import-Certificate -FilePath $_.FullName -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Out-Null
}
Write-Host " ✅"

### Create Output Folder With Timestamp
$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$RunOutputFolder = "$ChecklistOutputRoot\$Timestamp"

Write-Host "🗂  Creating Output Folder: $RunOutputFolder"
New-Item -ItemType Directory -Force -Path $RunOutputFolder | Out-Null
Write-Host " ✅"

### Run Evaluation
Write-Host "📜  Running Evaluation... (This may take several minutes)"
& "$LocalInstall\Evaluate-STIG.ps1" `
    -Mode Eval `
    -CKLRoot $RunOutputFolder `
    -ResultsRoot $RunOutputFolder `
    -SystemType Windows `
    -Silent

Write-Host " ✅  Scan Complete!"

Write-Host ""
Write-Host "📦  Results Saved To:"
Write-Host "   $RunOutputFolder"
Write-Host ""
Write-Host "✨  STIG Scan Finished Successfully!"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host ""
