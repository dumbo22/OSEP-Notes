using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace IgnoreCLM
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = runspace;

            while (true)
            {
                Console.Write("PS> ");
                string input = Console.ReadLine();

                if (input.Trim().ToLower() == "exit")
                {
                    break;
                }

                ps.Commands.Clear();
                ps.AddScript(input);

                try
                {
                    Collection<PSObject> results = ps.Invoke();

                    foreach (PSObject obj in results)
                    {
                        if (obj.BaseObject is System.Diagnostics.Process process)
                        {
                            Console.WriteLine($"{process.ProcessName,-30} {process.Id,5} {process.WorkingSet64 / 1024 / 1024,5} MB");
                        }
                        else
                        {
                            Console.WriteLine(obj.ToString());
                        }
                    }

                    if (ps.Streams.Error.Count > 0)
                    {
                        foreach (var error in ps.Streams.Error)
                        {
                            Console.WriteLine("Error: " + error.ToString());
                        }
                        ps.Streams.Error.Clear();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }
            }

            runspace.Close();
        }
    }
}
