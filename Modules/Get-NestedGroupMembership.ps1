function Get-NestedGroupMembership {
    <#
    .SYNOPSIS
    Recursively retrieves nested group memberships for a specified user account.

    .DESCRIPTION
    This function, Get-NestedGroupMembership, uses the Active Directory module to recursively retrieve nested group memberships for a specified user account. It starts by querying the direct group memberships and then recursively retrieves nested memberships.

    .PARAMETER SamAccountName
    Specifies the SamAccountName of the user for whom nested group memberships are to be retrieved.

    .EXAMPLE
    Get-NestedGroupMembership -SamAccountName "JohnDoe"
    This example retrieves nested group memberships for the user with the SamAccountName "JohnDoe".

    .NOTES
    File: Get-NestedGroupMembership.ps1
    Author: Rafael Pimentel @gustanini
    Version: 1.0
    Date: Nov 27 2023
    #>

    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string]$SamAccountName
    )

    # Retrieve direct group memberships
    $groups = @(
        Get-ADPrincipalGroupMembership -Identity $SamAccountName | 
            Select-Object -ExpandProperty DistinguishedName
        )

    # Output direct group memberships
    $groups

    # Recursively retrieve nested group memberships
    if ($groups.Count -gt 0) {
        foreach ($group in $groups) {
            Get-NestedGroupMembership -SamAccountName $group
        }
    }
}