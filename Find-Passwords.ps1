# Find-Passwords is a simple PS enumeration script by @gustanini
# Cool for CTFs for quick password file enumeration on C:\Users\, easy to read output
function Find-Passwords {
    # Variables
    $directoryToSearch = "C:\Users\"
    $searchString = "password"
    $searchString2 = "pass"
    $PCName = hostname
    
    # Message
    Write-Host "Finding files containing string password in $PCName C:\Users\" -ForegroundColor Cyan

    # find files containing string "password"
    Get-ChildItem -Path $directoryToSearch -File -Recurse | 
        Where-Object { Select-String -Path $_ -Pattern $searchString -ErrorAction SilentlyContinue } |
            select -expandproperty Name |
                Write-Host -ForegroundColor Yellow

    # Message
    Write-Host "Finding filenames containing pass in $PCName C:\Users\" -ForegroundColor Cyan

    # find filenames containing "pass"
    Get-ChildItem -Path $directoryToSearch -File -Recurse | 
        Where-Object { $_.Name -like "*$searchString2*" } |
            select -ExpandProperty Name |
                Write-Host -ForegroundColor Yellow
}
# call
Find-Passwords