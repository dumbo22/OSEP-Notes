This directory contains Shellcode execution techniques in PowerShell. 

## Convert Shellcode to single line (if required)
Use CyberChef for a nice easy way to put shellcode on a single line: https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false)

## Encrypt shellcode with Invoke-EncyptAES.ps1 
Use the PowerShell script below to encrypt the shellcode
Invoke-EncryptAES.ps1: https://github.com/The-Viper-One/OSEP-Notes/blob/main/Helpers/Invoke-EncryptAES.ps1
```
Invoke-EncryptAES -bytes "0x02, 0x03, 0x00"
```
Take the output and place it into any of the Shellcode templates

### Shellcode Runner templates
https://github.com/The-Viper-One/OSEP-Notes/blob/main/Shellcode_Templates/Shellcode_Templates/PowerShell/AES_Shellcode_Runner_Delegate_Dynamic.ps1

```powershell
# Multiple Keys
Invoke-EncryptAES -InputStrings "WaitForSingleObject, VirtualAlloc, CreateThread, VirtualProtect, system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule" -MultipleKeys

# Single Key
Invoke-EncryptAES  -InputStrings "WaitForSingleObject, VirtualAlloc, CreateThread, VirtualProtect, system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule"

# XOR
Invoke-XOR2ByteArray -InputStrings "WaitForSingleObject, VirtualAlloc, CreateThread, VirtualProtect, system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule"
```
### Shellcode Runner alternate
```powershell
# Multiple Keys
Invoke-EncryptAES -InputStrings "kernel32.dll, HeapCreate, HeapAlloc, HeapFree, EnumSystemGeoID" -MultipleKeys

# Single Key
Invoke-EncryptAES -InputStrings "kernel32.dll, HeapCreate, HeapAlloc, HeapFree, EnumSystemGeoID"

# XOR 
Invoke-XOR2ByteArray -InputStrings "kernel32.dll, HeapCreate, HeapAlloc, HeapFree, EnumSystemGeoID"
```
### Process Injection
```powershell
# Multiple Keys
Invoke-EncryptAES -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, OpenProcess, VirtualAllocEx, ReadProcessMemory, WriteProcessMemory, CreateRemoteThread" -MultipleKeys

# Single Key
Invoke-EncryptAES -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, OpenProcess, VirtualAllocEx, ReadProcessMemory, WriteProcessMemory, CreateRemoteThread"

# XOR 
Invoke-XOR2ByteArray -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, OpenProcess, VirtualAllocEx, ReadProcessMemory, WriteProcessMemory, CreateRemoteThread"
```
### Process Injection Alternative
https://github.com/The-Viper-One/OSEP-Notes/blob/main/Shellcode_Templates/Shellcode_Templates/PowerShell/AES_Process_Injection_Delegate_inMemory_Alternative.ps1
```powershell
# Multiple Keys
Invoke-EncryptAES  -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule, ntdll.dll, OpenProcess, CreateRemoteThread, NtClose, NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection"

# Single Key
Invoke-EncryptAES -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule, ntdll.dll, OpenProcess, CreateRemoteThread, NtClose, NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection"

# XOR 
Invoke-XOR2ByteArray -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule, ntdll.dll, OpenProcess, CreateRemoteThread, NtClose, NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection"
```
### Process Hollowing
https://github.com/The-Viper-One/OSEP-Notes/blob/main/Shellcode_Templates/Shellcode_Templates/PowerShell/AES_Process_Hollowing_Delegate_InMemory.ps1
```powershell
# Multiple Keys
Invoke-EncryptAES  -MultipleKeys -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule, ntdll.dll, ReadProcessMemory, WriteProcessMemory, ResumeThread, CloseHandle, ZwQueryInformationProcess"

# Single Key
Invoke-EncryptAES  -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule, ntdll.dll, ReadProcessMemory, WriteProcessMemory, ResumeThread, CloseHandle, ZwQueryInformationProcess"

# XOR
Invoke-XOR2ByteArray -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule, ntdll.dll, ReadProcessMemory, WriteProcessMemory, ResumeThread, CloseHandle, ZwQueryInformationProcess"
```

### PrintSpooferNet
```powershell
Invoke-EncryptAES -csharp -InputStrings "Kernel32.dll, ntdll.dll, CreateRemoteThread, NtClose, NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection, CreateProcessWithTokenW, CreateNamedPipe, ConnectNamedPipe, ImpersonateNamedPipeClient, OpenThreadToken, DuplicateTokenEx, advapi32.dll"
```
