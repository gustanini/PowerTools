function ConvertFrom-ObjectSid{
    <#
    .SYNOPSIS
    Converts Active Directory Security Identifier (SID) to object name or searches for objects in Active Directory based on SID.
    .DESCRIPTION
    This PowerShell function, ConvertFrom-ObjectSid, translates an Active Directory Security Identifier (SID) to the corresponding object name. The SID represents a security context for a user, group, or computer in an Active Directory environment.

    In search mode, the function searches for objects in Active Directory that have the specified SID.

    Credits to Windows OS Hub: https://woshub.com/convert-sid-to-username-and-vice-versa/
    .PARAMETER SID
    Specifies the Security Identifier (SID) to be translated. Currently only supports  This parameter is mandatory.
    .PARAMETER Domain
    Specifies the domain that owns the specified SID. Default is the user's domain ($env:USERDOMAIN).
    .PARAMETER Search
    Switch parameter to enable search mode. If specified, the function searches for objects in Active Directory with the specified SID and Domain. Outputs the object's name + distinguished name to avoid confusion.
    .EXAMPLE
    ConvertFrom-ObjectSid -SID "S-1-5-21-3623811015-3361044348-30300844-1013"

    This example converts the specified SID to its corresponding object name.
    .EXAMPLE
    ConvertFrom-ObjectSid -SID "S-1-5-21-3623811015-3361044348-30300820-1013" -Domain "OtherDomain" -Search

    This example searches for objects in Active Directory with the specified SID in the "OtherDomain" domain.
    .NOTES
    File: ConvertFrom-ObjectSid.ps1
    Author: Rafael Pimentel @gustanini
    Version: 1.0
    Date: Nov 26 2023

    Note: This function's search mode has a dependency on the Active Directory module. Ensure that the module is installed and available before using this function.
    #>  

    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [Alias("SID")]
        [string]$SecurityIdentifier,

        [switch]$Search,
        [string]$Domain = $env:USERDOMAIN
    )

    # search mode uses ad-module to find an object with the specified SID
    if ($Search) {
        Get-ADObject -Filter {objectSID -eq "$SecurityIdentifier"} -Server $Domain |
            Select-Object Name, DistinguishedName | 
                Format-List
    }
    # normal mode uses System.Security.Principal.SecurityIdentifier to translate the specified SID
    else {
    # Translate SID
    $objSID = New-Object System.Security.Principal.SecurityIdentifier ($SecurityIdentifier)
    $Object = $objSID.Translate($SecurityIdentifier)

    $Object.Value
    }
}