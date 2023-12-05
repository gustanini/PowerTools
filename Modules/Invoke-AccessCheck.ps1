function Test-Smb{
    <#
    .SYNOPSIS
    Checks access using SMB/CIFS to the specified or default computer.

    .DESCRIPTION
    The Test-Smb function checks for access to the C$ share on the specified or default computer using the SMB/CIFS protocol. It prints information about the access status to the console.

    .PARAMETER Domain
    Specifies the domain for which the SMB access should be checked.

    Aliases: Server

    Default Value: The current Active Directory domain obtained using Get-ADDomain.

    .NOTES
        Author         : Karim Elsobky (https://www.linkedin.com/in/karimelsobky/)
        Author         : Rafael Pimentel (https://www.linkedin.com/in/rafa-pimentel/) (https://linktr.ee/hackerhermanos)
        Prerequisite   : AD-Module

    .EXAMPLE
    Test-Smb
    Checks SMB access to the C$ share on all computers in the current Active Directory domain.

    #>
    [CmdletBinding()]
    Param (
        [Alias("Server")]
        [string]$Domain = (Get-ADDomain).DNSRoot
    )
    # define computers
    $ComputerName = (Get-ADComputer -Filter * -Server $Domain)
    # print info
    [Console]::WriteLine("[+] Checking Access on all computers in $Domain using SMB/CIFS")
    # check CIFS access
    ($ComputerName).dnshostname | 
        ForEach-Object {
            if (Get-ChildItem "\\$_\c$" -ErrorAction SilentlyContinue){
                Write-Host "[*] Found Access to: $_\c$"
        }
    }
}

function Test-PSRemoting{
    <#
    .SYNOPSIS
        Checks access using PowerShell Remoting (PSRemoting) over HTTP to the specified or default computer.

    .DESCRIPTION
        The Test-PSRemoting function checks for access to the specified or default computer using PowerShell Remoting (PSRemoting) over HTTP. It prints information about the access status to the console.

    .PARAMETER Domain
        Specifies the domain for which the PSRemoting over HTTP access should be checked.

        Aliases: Server

        Default Value: The current Active Directory domain obtained using Get-ADDomain.

    .NOTES
        Author         : Karim Elsobky (https://www.linkedin.com/in/karimelsobky/)
        Author         : Rafael Pimentel (https://www.linkedin.com/in/rafa-pimentel/) (https://linktr.ee/hackerhermanos)
        Prerequisite   : AD-Module

    .EXAMPLE
        Test-PSRemoting
        Checks PSRemoting over HTTP access to all computers in the current Active Directory domain.

    #>
    [CmdletBinding()]
    Param (
        [Alias("Server")]
        [string]$Domain = (Get-ADDomain).DNSRoot
    )
    # define computers
    $ComputerName = (Get-ADComputer -Filter * -Server $Domain)
    # print info
    [Console]::WriteLine("[+] Checking Access on all computers in $Domain using PSRemoting/HTTP")
    # check http access
    ($ComputerName).dnshostname | 
        ForEach-Object {
            if (Invoke-Command -ComputerName "$_" -ScriptBlock {hostname} -ErrorAction SilentlyContinue){
                Write-Host "[*] Found Access to: $_"
        }
    }
}

function Invoke-AccessCheck{
    <#
    .SYNOPSIS
        Checks access on all computers in the current domain using SMB/CIFS or PSRemoting over HTTP.

    .DESCRIPTION
        The Invoke-AccessCheck function checks for access on all computers in the current domain using
        either SMB/CIFS or PSRemoting over HTTP. It provides options to check access separately for
        SMB/CIFS or PSRemoting, and it pulls the Active Directory module from GitHub if not already imported.

    .PARAMETER SMB
        Switch parameter to indicate whether to check access using SMB/CIFS. If specified, the function
        checks access on all computers in the current domain using SMB/CIFS.

    .PARAMETER PSRemoting
        Switch parameter to indicate whether to check access using PSRemoting over HTTP. If specified,
        the function checks access on all computers in the current domain using PSRemoting over HTTP.

    .PARAMETER Domain
        Specifies the domain for which the PSRemoting over HTTP access should be checked.

        Aliases: Server

        Default Value: The current Active Directory domain obtained using Get-ADDomain.

    .NOTES
        Author         : Karim Elsobky (https://www.linkedin.com/in/karimelsobky/)
        Author         : Rafael Pimentel (https://www.linkedin.com/in/rafa-pimentel/) (https://linktr.ee/hackerhermanos)
        Prerequisite   : AD-Module (if not installed, this function will try to fetch it from Github Automatically)

    .EXAMPLE
        Invoke-AccessCheck -SMB
        Checks access using SMB/CIFS on all computers in the current domain.

    .EXAMPLE
        Invoke-AccessCheck -PSRemoting
        Checks access using PSRemoting over PSRemoting/HTTP on all computers in the current domain.

    .EXAMPLE
        Invoke-AccessCheck -PSRemoting -SMB
        Checks access using PSRemoting over PSRemoting/HTTP and SMB/CIFS on all computers in the current domain.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $false)]
        [switch]$SMB,        
        [Parameter(Position = 1, Mandatory = $false)]
        [switch]$PSRemoting,
        [Alias("Server")]
        [string]$Domain = (Get-ADDomain).DNSRoot
    )
    # Message
    [Console]::WriteLine("[+] Checking for Access Around The Network")
    
    # check for access on all computers in current domain
    try {
        # check for AD Module in current session
        if (!(Get-Module -Name ActiveDirectory)) {
            # dependency not met
            [Console]::WriteLine("[+] Didn't find ActiveDirectory Module, pulling from Github and importing it, this will take a minute...")
            # pull and import
            Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1')
            Import-ActiveDirectory
        }

        # check all computers in the current domain via HTTP
        if ($SMB) {
            Test-Smb -Domain $Domain
        }
    
        # check all computers in the current domain via HTTP
        if ($PSRemoting) {
            Test-PSRemoting -Domain $Domain
        }
    
        # If neither $PSRemoting nor $SMB is specified, print an error
        if (!($PSRemoting -or $SMB)) {
            throw "[-] Usage: Invoke-AccessCheck -SMB <or> Invoke-AccessCheck -PSRemoting"
        }
    }
    catch {
        [Console]::WriteLine("Error: $_")
        return
    }
}