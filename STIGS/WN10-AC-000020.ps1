<#
.SYNOPSIS
   The remediation script exports the local security policy, sets the “Enforce password history” (PasswordHistorySize) value to 24
   if it is lower, and re-imports the configuration to apply the updated password history requirement on the system.

.NOTES
    Author          : Benjamin Lawson
    LinkedIn        : linkedin.com/in/benjamin-lawson06/
    GitHub          : github.com/Benjamin-Lawson23
    Date Created    : 2026-02-17
    Last Modified   : 2026-02-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000020

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000020.ps1 
#>

# Set Enforce Password History to 24

$tempFile = "$env:TEMP\secpol.cfg"

# Export current policy
secedit /export /cfg $tempFile | Out-Null

# Replace or set PasswordHistorySize to 24
$content = Get-Content $tempFile

if ($content -match "PasswordHistorySize") {
    $content = $content -replace "PasswordHistorySize\s*=\s*\d+", "PasswordHistorySize = 24"
} else {
    $content += "PasswordHistorySize = 24"
}

# Save updated config
$content | Set-Content $tempFile

# Apply updated security policy
secedit /configure /db secedit.sdb /cfg $tempFile /areas SECURITYPOLICY | Out-Null

Write-Host "Password history policy configured to 24."

# Cleanup
Remove-Item $tempFile -Force
