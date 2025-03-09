# MSSQL Enumeration

## CMD
```
setspn -T corp1 -Q MSSQLSvc/*
```

## PowerShell
```powershell
# Native
([adsisearcher]"(servicePrincipalName=MSSQLSvc*)").findAll() | ForEach-Object { Write-Host "" ; $_.properties.cn ; $_.properties.serviceprincipalname }
```

## PowerUp

```powershell
# Discovery (SPN Scanning)
Get-SQLInstanceDomain

# Discovery (Broadcast Domain)
Get-SqlInstanceBroadcast

# Discovery (Broadcast Domain)
Get-SqlInstanceScanUDP
Get-SqlInstanceScanUDPThreaded

# Check Accessibility
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose

#Gather Information
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```
## SQLRecon
```powershell
.\SQLRecon.exe /enum:sqlspns /d:corp1.com
.\SQLRecon.exe /a:WinToken /host:DC01,appsrv01 /m:info
```

