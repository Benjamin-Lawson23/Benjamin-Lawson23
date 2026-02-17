<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Benjamin Lawson
    LinkedIn        : linkedin.com/in/benjamin-lawson06/
    GitHub          : github.com/Benjamin-Lawson23
    Date Created    : 2026-02-16
    Last Modified   : 2026-02-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>


# Define registry path
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"

# Create the key if it doesn't exist
If (-Not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set MaxSize to 0x8000 (32768 in decimal)
New-ItemProperty -Path $regPath `
                 -Name "MaxSize" `
                 -PropertyType DWord `
                 -Value 32768 `
                 -Force
