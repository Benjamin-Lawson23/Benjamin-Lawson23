<#
.SYNOPSIS
  This script verifies that the local security policy “Password must meet complexity requirements” is enabled and, if not
  (and no approved password filter exception applies), updates the system security policy to enforce password complexity.

.NOTES
    Author          : Benjamin Lawson
    LinkedIn        : linkedin.com/in/benjamin-lawson06/
    GitHub          : github.com/Benjamin-Lawson23
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000040

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000040.ps1 
#>

$desiredValue = 1
$tempFile = "$env:TEMP\secpol.cfg"

secedit /export /cfg $tempFile /quiet
$content = Get-Content $tempFile
$line = ($content | Select-String "^PasswordComplexity").Line

if ($line) {
    $currentValue = [int](($line -split "=")[1].Trim())
} else {
    $currentValue = 0
}

if ($currentValue -ne $desiredValue) {
    Write-Output "Finding: Password complexity is Disabled."

    $content = if ($content -match "^PasswordComplexity") {
        $content -replace "^PasswordComplexity\s*=\s*\d+", "PasswordComplexity = $desiredValue"
    } else {
        $content + "PasswordComplexity = $desiredValue"
    }

    $content | Set-Content $tempFile
    secedit /configure /db "$env:SystemRoot\security\local.sdb" /cfg $tempFile /areas SECURITYPOLICY /quiet

    Write-Output "Finding corrected: Password complexity Enabled."
}
else {
    Write-Output "Not a finding: Password complexity is Enabled."
}

Write-Output "Note: If an approved password filter requires complexity to be Disabled, this would not be considered a finding."

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
