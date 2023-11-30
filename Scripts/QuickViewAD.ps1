# Users Block
function Get-ADEnumUsers
{
    <#
    .SYNOPSIS
    Enumerates information about users in the Active Directory.

    .DESCRIPTION
    This function retrieves details about users in the Active Directory, including all users,
    users with SPNs (Service Principal Names), and admin users.

    .NOTES
    File Name       : QuickEnumAD.ps1
    Author          : Rafael Pimentel (@gustanini)
    Prerequisite    : Requires the Active Directory PowerShell module.
    Hacker Hermanos : https://linktr.ee/hackerhermanos

    #>
    Write-Host "Users" -ForegroundColor Cyan 
    # small pause
    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: All users" -ForegroundColor Yellow

    Start-Sleep -Seconds 1

    # piping all commands to out-host at the end to flush the output before moving on to the next command
    get-aduser -filter * | 
        Select-Object SamAccountName, enabled | 
            Out-Host
    
    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Users with SPNs" -ForegroundColor Yellow
    
    Start-Sleep -Seconds 1

    get-adserviceaccount -filter * | 
        Select-Object samaccountname, SID, objectclass, ObjectGuid, distinguishedname, enabled | 
            format-list | 
                Out-Host
    
    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Admin Users" -ForegroundColor Yellow
    
    get-aduser -filter * | 
        Where-Object{$_.samaccountname -match "admin"} | 
            Select-Object samaccountname | 
                Out-Host

    Start-Sleep -Seconds 1
}

# Computers Block
function Get-ADEnumComputers
{
    <#
    .SYNOPSIS
    Enumerates information about computers in the Active Directory.

    .DESCRIPTION
    This function retrieves details about computers in the Active Directory, including all computer names,
    accessible computers using ICMP, and domain controllers.

    .NOTES
    Author          : Rafael Pimentel (@gustanini)
    Prerequisite    : Requires the Active Directory PowerShell module.
    Hacker Hermanos : https://linktr.ee/hackerhermanos

    #>
    Write-Host "Computers" -ForegroundColor Cyan 
    
    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: All computer names + machine account names + SIDs" -ForegroundColor Yellow
    
    Start-Sleep -Seconds 1

    Get-ADComputer -filter * | 
        Select-Object dnshostname, SamAccountName, SID | 
            Out-Host

    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Accessible Computers (ICMP)" -ForegroundColor Yellow
    
    get-adcomputer -filter * | 
        ForEach-Object{Test-Connection -Count 1 -ComputerName $_.DNSHostName -erroraction silentlycontinue} | 
            Select-Object -expandproperty Address | 
                Out-Host

    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Domain Controllers" -ForegroundColor Yellow
    
    Get-ADDomainController -filter * | 
        select-object ComputerObjectDN, domain, enabled, forest, hostname, ipv4address, isglobalcatalog, ldapport, name, operatingsystem, serverobjectdn | 
            Format-List | 
                Out-Host

    Start-Sleep -Seconds 1
}

# Groups Block
function Get-ADEnumGroups 
{
    <#
    .SYNOPSIS
    Enumerates information about groups in the Active Directory.

    .DESCRIPTION
    This function retrieves details about groups in the Active Directory, including group names and SIDs,
    admin groups, domain admins group members, and enterprise admins.

    .NOTES
    Author         : Rafael Pimentel (@gustanini)
    Prerequisite   : Requires the Active Directory PowerShell module.
    Hacker Hermanos : https://linktr.ee/hackerhermanos

    #>
    Write-Host "Groups" -ForegroundColor Cyan 
    
    Start-Sleep -Seconds 1

    # Consider only copying non default groups to notes
    Write-Host "Enumerating: Group Names + SIDs" -ForegroundColor Yellow
    
    Start-Sleep -Seconds 1

    get-adgroup -filter * | 
        Select-Object name, sid | 
            Out-Host

    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Admin Groups" -ForegroundColor Yellow

    Start-Sleep -Seconds 1

    get-adgroup -filter 'Name -like "*admin*"' | 
        Select-Object Name,sid | 
            Out-Host

    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Domain Admins Group Members" -ForegroundColor Yellow

    Start-Sleep -Seconds 1

    get-adgroupmember "Domain Admins" -Recursive | 
        Out-Host

    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Enterprise Admins" -ForegroundColor Yellow

    Start-Sleep -Seconds 1

    get-adgroupmember "Enterprise Admins" -Recursive -Server (Get-ADForest).Name | 
        Out-Host

    Start-Sleep -Seconds 1
}

# Domain Block
function Get-ADEnumDomain
{
    <#
    .SYNOPSIS
    Enumerates information about the current domain in the Active Directory.

    .DESCRIPTION
    This function retrieves details about the current domain in the Active Directory.

    .NOTES
    Author         : Rafael Pimentel (@gustanini)
    Prerequisite   : Requires the Active Directory PowerShell module.
    Hacker Hermanos : https://linktr.ee/hackerhermanos

    #>
    Write-Host "Domains" -ForegroundColor Cyan

    Start-Sleep -Seconds 1

    Write-Host "Enumerating: Current Domain Information" -ForegroundColor Yellow

    Start-Sleep -Seconds 1

    get-addomain | 
        Select-Object Name, InfrastructureMaster, DistinguishedName, domainsid, LinkedGroupPolicyObjects, ChildDomains, ComputersContainer, DomainControllersContainer, Forest, ParentDomain, DNSRoot | 
            Out-Host

    Start-Sleep -Seconds 1
}

# Trusts Block
function Get-ADEnumTrusts
{
    <#
    .SYNOPSIS
    Enumerates information about trusts in the Active Directory.

    .DESCRIPTION
    This function retrieves details about trusts in the Active Directory, including forest information,
    domains in the current forest, global catalogs, current domain trusts, and current forest trusts.

    .NOTES
    Author          : Rafael Pimentel (@gustanini)
    Prerequisite    : Requires the Active Directory PowerShell module.
    Hacker Hermanos : https://linktr.ee/hackerhermanos

    #>
    Write-Host "Trusts" -ForegroundColor Cyan 

    Start-Sleep -Seconds 1

    Write-Host "Enumerating: Forest Information" -ForegroundColor Yellow

    Start-Sleep -Seconds 1


    Get-ADForest | 
        Out-Host

    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Domains in Current Forest" -ForegroundColor Yellow | 
        Out-Host

    Start-Sleep -Seconds 1

    (Get-ADForest).domains | 
        Out-Host

    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Global Catalogs" -ForegroundColor Yellow
    
    Start-Sleep -Seconds 1

    (Get-ADForest).globalcatalogs | 
        Out-Host

    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Current Domain Trusts" -ForegroundColor Yellow
    
    Start-Sleep -Seconds 1

    Get-ADTrust -Filter * | 
        Out-Host

    Start-Sleep -Seconds 1
    
    Write-Host "Enumerating: Current Forest Trusts" -ForegroundColor Yellow
    
    Start-Sleep -Seconds 1

    Get-ADTrust -Filter 'intraForest -ne $True' -Server (Get-ADForest).Name
    
    Start-Sleep -Seconds 1
}

# Shares Block
function Get-ADEnumShares
{
    <#
    .SYNOPSIS
    Enumerates information about shares in the Active Directory.

    .DESCRIPTION
    This function retrieves details about shares in the Active Directory.

    .NOTES
    Author         : Rafael Pimentel (@gustanini)
    Prerequisite   : Requires the Active Directory PowerShell module.
    Hacker Hermanos : https://linktr.ee/hackerhermanos

    #>
    Write-Host "Shares Enumeration" -ForegroundColor Cyan 
    
    Start-Sleep -Seconds 1

    Write-Host "Enumerating: Shares on the domain" -ForegroundColor Yellow
    
    Start-Sleep -Seconds 1

    Get-ADComputer -filter * -properties Name | 
        Select-Object -ExpandProperty Name | 
            ForEach-Object {Get-CIMInstance -Class win32_share -ComputerName $_ -ErrorAction SilentlyContinue} | 
                Out-Host

    Start-Sleep -Seconds 1
}

# call all functions
function Invoke-AllEnum
{
    <#
    .SYNOPSIS
    Invokes all enumeration functions with pauses in between.

    .DESCRIPTION
    This function calls all enumeration functions with pauses to ensure a synchronous execution.

    .NOTES
    Author          : Rafael Pimentel (@gustanini)
    Prerequisite    : Requires the Active Directory PowerShell module.
    Hacker Hermanos : https://linktr.ee/hackerhermanos

    #>
    Get-ADEnumUsers

    Start-Sleep -Seconds 1

    Get-ADEnumGroups

    Start-Sleep -Seconds 1

    Get-ADEnumComputers

    Start-Sleep -Seconds 1

    Get-ADEnumDomain

    Start-Sleep -Seconds 1

    Get-ADEnumTrusts

    Start-Sleep -Seconds 1

    Get-ADEnumShares

    Start-Sleep -Seconds 1

    Write-Host "Done." -ForegroundColor Green
}