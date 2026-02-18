<#
.SYNOPSIS
  The script checks whether the AllowGameDVR registry value under HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR
  is set to 0 (disabled) as required and, if not compliant, creates or updates the value to disable Windows Game 
  Recording and Broadcasting.

.NOTES
    Author          : Benjamin Lawson
    LinkedIn        : linkedin.com/in/benjamin-lawson06/
    GitHub          : github.com/Benjamin-Lawson23
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000252

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000252.ps1 
#>

$osInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$releaseId = $osInfo.ReleaseId
$editionId = $osInfo.EditionID

if (($editionId -like "*LTSB*" -or $editionId -like "*LTSC*") -and 
    ($releaseId -eq "1507" -or $releaseId -eq "1607")) {

    Write-Output "NA: Windows 10 LTSC/LTSB version $releaseId"
    return
}

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
$valueName = "AllowGameDVR"
$expectedValue = 0

if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($currentValue -ne $expectedValue) {
    New-ItemProperty -Path $regPath `
                     -Name $valueName `
                     -PropertyType DWord `
                     -Value $expectedValue `
                     -Force | Out-Null

    Write-Output "Finding corrected: AllowGameDVR set to 0."
}
else {
    Write-Output "Not a finding: System compliant."
}
