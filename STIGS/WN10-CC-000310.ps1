<#
.SYNOPSIS
   This PowerShell script checks whether the HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl registry value exists and is set to 0, and if it is missing or 
   incorrectly configured, automatically creates or corrects it to enforce the security policy that prevents users from having control over Windows Installer installations.

.NOTES
    Author          : Benjamin Lawson
    LinkedIn        : linkedin.com/in/benjamin-lawson06/
    GitHub          : github.com/Benjamin-Lawson23
    Date Created    : 2026-02-17
    Last Modified   : 2026-02-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000310

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000310.ps1 
#>

# Define registry location and value
$regHive = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valueName = "EnableUserControl"
$expectedValue = 0

# Check if the registry key exists
if (Test-Path $regHive) {
    # Get the current value
    $currentValue = Get-ItemProperty -Path $regHive -Name $valueName -ErrorAction SilentlyContinue

    if ($null -eq $currentValue) {
        Write-Output "Finding: '$valueName' does not exist in $regHive. Applying remediation..."
        Set-ItemProperty -Path $regHive -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediation applied: '$valueName' set to $expectedValue"
    }
    elseif ($currentValue.$valueName -ne $expectedValue) {
        Write-Output "Finding: '$valueName' is set to $($currentValue.$valueName), expected $expectedValue. Applying remediation..."
        Set-ItemProperty -Path $regHive -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediation applied: '$valueName' set to $expectedValue"
    }
    else {
        Write-Output "Compliant: '$valueName' is correctly set to $expectedValue"
    }
}
else {
    Write-Output "Finding: Registry path $regHive does not exist. Creating key and applying remediation..."
    # Create the key and set the value
    New-Item -Path $regHive -Force | Out-Null
    New-ItemProperty -Path $regHive -Name $valueName -Value $expectedValue -PropertyType DWord -Force | Out-Null
    Write-Output "Remediation applied: '$valueName' created and set to $expectedValue"
}
