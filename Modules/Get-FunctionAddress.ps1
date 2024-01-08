function Get-FunctionAddress {
  <#
  .SYNOPSIS
      Get-FunctionAddress retrieves the memory address of a specified function within Microsoft.Win32.UnsafeNativeMethods using System.dll and GetType.

  .DESCRIPTION
      This tool allows you to find the memory addresses of functions within the Microsoft.Win32.UnsafeNativeMethods class. It leverages System.dll and GetType to dynamically retrieve the function address.
      
  .PARAMETER ModuleName
      Specifies the name of the DLL module where the function is located. Default is 'user32.dll'.

  .PARAMETER FunctionName
      Specifies the name of the function whose address you want to retrieve. Default is 'MessageBoxA'.

  .EXAMPLE
      Get-FunctionAddress
      Retrieves the address of the 'MessageBoxA' function within the 'user32.dll' module.

  .EXAMPLE
      Get-FunctionAddress -ModuleName kernel32.dll -FunctionName CreateFileA
      Retrieves the address of the 'CreateFileA' function within the 'kernel32.dll' module.

  .NOTES
      File Name      : Get-FunctionAddress.ps1
      Prerequisite   : PowerShell V2
      Author         : Rafael Pimentel (@gustanini) https://www.linkedin.com/in/rafa-pimentel/
      Hacker Hermanos: https://linktr.ee/hackerhermanos
  #>

  [CmdletBinding()]
  Param(
      [Parameter(Position = 0)]
      [string]$ModuleName = 'user32.dll',

      [Parameter(Position = 1)]
      [string]$FunctionName = 'MessageBoxA'
  )

  # get all loaded assemblies
	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    # select System.dll
    Where-Object { 
      $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
        Equals('System.dll') 
    }).
      # load reflectively win32 unsafe native methods ( contains getprocaddress and getmodulehandle )
      GetType('Microsoft.Win32.UnsafeNativeMethods')

    # create an empty array for getprocaddress
    $tmp=@()

    # populate array with all getprocaddress instances ( there are multiple instances of getprocaddress inside of unsafenativemethods on Win10 )
    $assem.GetMethods() | 
      ForEach-Object {
        If ($_.Name -eq 'GetProcAddress') {
          $tmp+=$_
        }
      }
  # get function address. "0" means the function was not found
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($ModuleName)), $FunctionName))
}