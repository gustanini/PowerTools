# script that disables macro security by editing the registry, if it is enabled
function Set-MacroSecurityOff {
    # optional parameter
    param(
        [Parameter(Mandatory = $false, ParameterSetName = "Key")]
        [string]$SecurityKey = 'HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security'
    )

    # test if key exists
    if (Test-Path $SecurityKey)
        {
            # check key value
            if ((Get-ItemProperty $SecurityKey).level -ne 4) 
            {
                Set-ItemProperty -Path $SecurityKey -Name level -value 4
                Write-Host -ForegroundColor Green 'Value set to "No security Check" (4)'
            }
            # security is already off
            else
            {
                Write-Host -ForegroundColor Green 'Macro security is already set to "No security check" (4).' | Set-
            }
        }
    # key does not exist
    else 
    {
        Write-Host -ForegroundColor Red "Key does not exist at this location: $SecurityKey, find key path and select it using Set-MacroSecurityKeyOff -Key <Key_Path>."
    }
}