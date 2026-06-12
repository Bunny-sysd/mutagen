# Setup script for Mutagen workspace exclusions in Windows Defender.
# Safe & targeted to only this specific workspace directory.

$currentDir = Get-Location
$path = $currentDir.Path

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Mutagen Workspace Exclusions Setup" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Workspace target path: $path" -ForegroundColor White
Write-Host ""

# Check for Administrator privileges
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] ERROR: This script must be run from an Elevated PowerShell console (Run as Administrator)." -ForegroundColor Red
    Write-Host "    Excluding folders from Windows Defender requires administrative access." -ForegroundColor Yellow
    Write-Host "    Please close this and open PowerShell as Administrator." -ForegroundColor Yellow
    Write-Host ""
    Exit 1
}

try {
    Write-Host "[*] Adding Defender exclusion path: $path" -ForegroundColor Yellow
    Add-MpPreference -ExclusionPath $path
    Write-Host "[+] SUCCESS: Exclusion added successfully!" -ForegroundColor Green
    Write-Host "    Windows Defender will no longer scan or block security test binaries in this folder." -ForegroundColor Gray
}
catch {
    Write-Host "[-] ERROR: Failed to add exclusion path: $_" -ForegroundColor Red
}
Write-Host ""
