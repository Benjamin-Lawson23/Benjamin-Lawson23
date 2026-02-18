<#
.SYNOPSIS
   Checks whether the NoDriveTypeAutoRun registry value under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer 
   is set to REG_DWORD 255 (0xFF) and creates or corrects it to enforce AutoPlay disabled on all drives if noncompliant.

.NOTES
    Author          : Benjamin Lawson
    LinkedIn        : linkedin.com/in/benjamin-lawson06/
    GitHub          : github.com/Benjamin-Lawson23
    Date Created    : 2026-02-17
    Last Modified   : 2026-02-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000190

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000190.ps1 
#>

# Registry path and value
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$ValueName = "NoDriveTypeAutoRun"
$ExpectedValue = 255

Write-Host "Checking NoDriveTypeAutoRun setting..." -ForegroundColor Cyan

# Check if registry path exists
if (-not (Test-Path $RegPath)) {
    Write-Host "Registry path does not exist. This is a finding." -ForegroundColor Red
    $Compliant = $false
}
else {
    try {
        $CurrentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName

        if ($CurrentValue -eq $ExpectedValue) {
            Write-Host "Compliant: NoDriveTypeAutoRun is set to 255 (0xFF)." -ForegroundColor Green
            $Compliant = $true
        }
        else {
            Write-Host "Finding: Value is set to $CurrentValue. Expected 255." -ForegroundColor Red
            $Compliant = $false
        }
    }
    catch {
        Write-Host "Registry value does not exist. This is a finding." -ForegroundColor Red
        $Compliant = $false
    }
}

# Remediation if non-compliant
if (-not $Compliant) {
    Write-Host "Remediating setting..." -ForegroundColor Yellow

    # Ensure registry path exists
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }

    # Set correct value
    New-ItemProperty `
        -Path $RegPath `
        -Name $ValueName `
        -Value $ExpectedValue `
        -PropertyType DWord `
        -Force | Out-Null

    Write-Host "Remediation complete. NoDriveTypeAutoRun set to 255 (0xFF)." -ForegroundColor Green
}

Write-Host "Done."
