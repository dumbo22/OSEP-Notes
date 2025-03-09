using System;
using System.Runtime.InteropServices;
using System.Configuration.Install;

[System.ComponentModel.RunInstaller(true)]
public class WarheadInstaller : Installer
{
    // This gets trigger when running /Uninstall
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        Code.Main();
    }
}

public class Code
{
    // Import required WinAPI functions


    // Main method to execute the payload
    public static void Main()
    {
        // Shellcode
        byte[] Warhead = new byte[] { 0xfc, 0x48, 0x83, 0xe4 };

    }

    //Optional: Additional Import required WinAPI functions
}
