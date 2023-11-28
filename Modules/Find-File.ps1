function Find-File2 {
    <#
    .SYNOPSIS
    Searches for files containing a specified string in a specified path on a local or remote computer.

    .DESCRIPTION
    The Find-File function performs a search for files that contain a specified string within their names. It supports searching on the local machine or a remote computer using either HTTP access or CIFS access. If searching on a remote computer, ensure that the appropriate access is available.

    .PARAMETER searchString
    Specifies the string to search for within file names. The default value is "password".

    .PARAMETER Path
    Specifies the path to start the search. The default is "C:\Users\".

    .PARAMETER computerName
    Specifies the name of the remote computer to search. If provided, the function performs a remote query using either HTTP access or CIFS access.

    .PARAMETER Cifs
    Switch parameter that indicates whether to use CIFS access for the remote query. If specified, the function uses CIFS access and expects the $Path parameter to be specified using the drivename$ syntax.

    .EXAMPLE
    Find-File -searchString "pass" -Path "c$\Users" -computerName "RemoteComputer" -Cifs

    This example searches for files with names that match the string "pass" in the "C:\Users" directory on the remote computer "RemoteComputer" leveraging CIFS access.

    .EXAMPLE
    Find-File -searchString "confidential" -Path "C:\Documents"

    This example searches for files containing the string "confidential" in the "C:\Documents" directory on the local machine.

    .NOTES
    File: Find-File.ps1
    Author: Rafael Pimentel @gustanini
    Version: 1.0
    Date: Nov 23 2023
    #>
    [CmdletBinding()]
    param(
        [string]$searchString = "password",
        [string]$Path = "C:\Users\",
        [string]$computerName,

        [switch]$Cifs
    )

    # Message
    Write-Host "Finding files containing string $searchString in $computerName $Path" -ForegroundColor Cyan

    # perform remote query if computer is specified (need HTTP access)
    if ($computername) {
        Invoke-Command -ComputerName $computerName -ScriptBlock {
                Get-ChildItem -Path $Path -File -Recurse | 
                    Where-Object {$_.Name -match "$searchString"} -ErrorAction SilentlyContinue | 
                        Select-Object Directory, Name
            }
    }
    
    # perform remote query leveraging cifs access only (specify path using drivename$ syntax)
    elseif ($Cifs){
        Get-ChildItem -Path "\\$computerName\$Path" -File -Recurse | 
            Where-Object {$_.Name -match "$searchString"} -ErrorAction SilentlyContinue | 
                Select-Object Directory, Name
    }

    # perform localhost query
    else {
        Get-ChildItem -Path $Path -File -Recurse | 
            Where-Object {$_.Name -match "$searchString"} -ErrorAction SilentlyContinue | 
                Select-Object Directory, Name 
    }
}