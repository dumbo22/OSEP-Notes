using System;
using System.Management;

namespace DomainCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                using (ManagementObject computerSystem = new ManagementObject($"Win32_ComputerSystem.Name='{Environment.MachineName}'"))
                {
                    computerSystem.Get();
                    bool partOfDomain = (bool)computerSystem["PartOfDomain"];

                    if (!partOfDomain)
                    {
                        // not domain joined, terminate
                        return;
                    }

                    string domainName = computerSystem["Domain"].ToString();
                    Console.WriteLine("" + domainName);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }
    }
}
