using System;

namespace Program
{
    class Program
    {
        static void Main(string[] args)
        {
            DateTime startTime = DateTime.Now;
            System.Threading.Thread.Sleep(2000);
            double elapsedSeconds = (DateTime.Now - startTime).TotalSeconds;

            if (elapsedSeconds < 1.5)
            {
                // terminate
                Environment.Exit(0);
            }
        }
    }
}
