function Find-ADInterestingACL {
    <#
    .SYNOPSIS
    Finds and lists all Active Directory Objects' Access Control Lists (in the current domain) filtering by interesting rights and provided identities.

    Author: Rafael Pimentel (@gustanini)
    Required Dependency: Active Directory Module

    .DESCRIPTION
    The Find-ADInterestingACL function searches Active Directory objects and filters their Access Control Lists (ACLs) based on specified rights and identity parameters. It enumerates all AD objects, retrieves their ACLs, and then filters these ACLs to find specific permissions related to the provided identities.

    .PARAMETER Rights
    Specifies the types of rights to filter for in the ACLs. The default values are 'write|all|force|self' to ensure that only exploitable rights are displayed. This parameter accepts a string that represents a regular expression pattern to match against the Active Directory rights.

    .PARAMETER Identity
    Specifies the identity to filter for in the ACLs. Think of it as the already compromised user you want to check. This is a mandatory parameter. The function will match this parameter value against the IdentityReference property of ACL entries.

    .PARAMETER Domain
    Specifies the domain to be used for the retrieval of Active Directory objects and their Access Control Lists (ACLs). If this parameter is not provided, the function operates in the current domain context.

    .EXAMPLE
    PS C:\> Find-ADInterestingACL -Identity 'CompromisedUser|CompromisedGroup'
    This example finds and lists all AD objects where the ACLs includes exploitable rights for 'CompromisedUser' and 'CompromisedGroup'.

    .EXAMPLE
    PS C:\> Find-ADInterestingACL -Rights 'write|modify' -Identity 'JohnDoe'
    This example finds and lists all AD objects where the ACLs include 'write' or 'modify' rights for the user 'JohnDoe'.

    .INPUTS
    None. You cannot pipe objects to Find-ADInterestingACL.

    .OUTPUTS
    The function outputs a formatted list of AD objects with specific ACL entries matching the given criteria. Each entry includes the target distinguished name, rights, access control type, and identity reference.

    .NOTES
    This function requires the Active Directory module for PowerShell. Ensure that the Microsoft Active Directory Module is installed and available in your PowerShell session. This module is typically available on systems that have the Active Directory Domain Services (AD DS) role installed, or by installing the Remote Server Administration Tools (RSAT) package.

    .LINK
    https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adobject
    #>
    # params        
    [CmdletBinding()]
    param (
        [string]$Rights = 'write|all|force|self',
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        [string]$Domain
    )

    # Create PSDrive for the specified domain
    if ($Domain) {
        New-PSDrive -Name AD2 -PSProvider ActiveDirectory -Server $Domain -Root "//RootDSE/"
        $ADPathPrefix = "AD2:\"
    } else {
        # if no domain specified, use the domain of the current session
        $Domain = (Get-AdDomain).DnsRoot
        $ADPathPrefix = "AD:\"
    }

    # Save all AD objects as DN for get-acl
    (Get-ADObject -Filter * -Server $Domain).DistinguishedName | ForEach-Object {
        $acl = (Get-Acl -Path ("$ADPathPrefix$_") -Filter *)

        # filter using rights and identity
        $acl.Access | Where-Object {
            $_.ActiveDirectoryRights -match $Rights -and
            $_.IdentityReference -match $Identity
        } | Select-Object @{
            Name = 'TargetDN'
            Expression = {$acl.PSPath -replace '.*DSE\/', ''}
        }, ActiveDirectoryRights, AccessControlType, IdentityReference
    } | Format-List

    # Remove PSDrive if it was created
    if ($ADPathPrefix -eq "AD2:\") {
        Remove-PSDrive -Name AD2
    }
}