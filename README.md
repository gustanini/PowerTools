# Powershell Tools
Powershell tools used for Red Team / Pentesting. As of Nov 23 2023 all tools are unified into a script named PowerTools for ease of use. 

## Modules
You can get individual modules from the modules folder.

## Tools Included

### ConvertFrom-ObjectSid
ConvertFrom-ObjectSid, translates an Active Directory Security Identifier (SID) to the corresponding object name. The SID represents a security context for a user, group, or computer in an Active Directory environment.

### Find-ADInterestingACL
Find-ADInterestingACL searches Active Directory objects and filters their Access Control Lists (ACLs) based on specified rights and identity parameters. It enumerates all AD objects, retrieves their ACLs, and then filters these ACLs to find specific permissions related to the provided identities.

### Find-File
Find-File performs a search for files that contain a specified string within their names. It supports searching on the local machine or a remote computer using either HTTP access or CIFS access. If searching on a remote computer, ensure that the appropriate access is available.

### Get-NestedGroupMembership
Get-NestedGroupMembership uses the Active Directory module to recursively retrieve nested group memberships for a specified user account. It starts by querying the direct group memberships and then recursively retrieves nested memberships.

### Get-TrustTicket
This script generates the command required for crafting inter-realm/referral TGTs and subsequent TGS for Mimikatz, Kekeo and Rubeus.

### Set-MacroSecurityOff
The Set-MacroSecurityOff function disables macro security by modifying the registry. It checks if the specified registry key exists and, if present, sets the "level" value to 4, representing "No security check." If the key does not exist, the user is prompted to find the correct key path using `Set-MacroSecurityKeyOff -Key Key_Path`. The current value is printed to the screen before changing to facilitate cleanup.