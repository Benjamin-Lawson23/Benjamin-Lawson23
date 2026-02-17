<#
.SYNOPSIS
    This PowerShell script sets the Windows 10 account lockout duration so that locked user accounts automatically unlock after 15 minutes.

.NOTES
    Author          : Benjamin Lawson
    LinkedIn        : linkedin.com/in/benjamin-lawson06/
    GitHub          : github.com/Benjamin-Lawson23
    Date Created    : 2026-02-17
    Last Modified   : 2026-02-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-AC-000005).ps1 
#>

# Run PowerShell as Administrator

# Set account lockout duration to 15 minutes
net accounts /lockoutduration:15

# Verify the setting
net accounts
