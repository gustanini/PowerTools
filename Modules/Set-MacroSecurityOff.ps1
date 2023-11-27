<#
.SYNOPSIS
Disables macro security by editing the registry, if it is enabled.

.DESCRIPTION
The Set-MacroSecurityOff function disables macro security by modifying the registry. It checks if the specified registry key exists and, if present, sets the "level" value to 4, representing "No security check." If the key does not exist, the user is prompted to find the correct key path using Set-MacroSecurityKeyOff -Key <Key_Path>. The current value is printed to the screen before changing to facilitate cleanup.

.PARAMETER SecurityKey
Specifies the registry key path where the macro security setting is configured. The default is 'HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security'.

.EXAMPLE
Set-MacroSecurityOff -SecurityKey 'HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security'

This example disables macro security for Microsoft Office Outlook by setting the "level" value to 4 in the specified registry key path.

.NOTES
File: Set-MacroSecurityOff.ps1
Author: Rafael Pimentel
Version: 1.0
Date: 27 Nov 2023
#>

function Set-MacroSecurityOff {
    # optional parameter
    param(
        [Parameter(Mandatory = $false, ParameterSetName = "Key")]
        [string]$SecurityKey = 'HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security'
    )

    # first print current security level (for cleanup later)
    Write-Host "The current macro security level is:" (Get-ItemProperty $SecurityKey).level

    # test if key exists
    if (Test-Path $SecurityKey) {
        # check key value
        if ((Get-ItemProperty $SecurityKey).level -ne 4) {
            Set-ItemProperty -Path $SecurityKey -Name level -Value 4
            Write-Host -ForegroundColor Green 'Value set to "No security Check" (4)'
        }
        # security is already off
        else {
            Write-Host -ForegroundColor Green 'Macro security is already set to "No security check" (4).'
        }
    }
    # key does not exist
    else {
        Write-Host -ForegroundColor Red "Key does not exist at this location: $SecurityKey, find key path and select it using Set-MacroSecurityKeyOff -Key <Key_Path>."
    }
}