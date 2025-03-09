
// Options 1: Standard usage
// ======================================================================================================================================================================================================
using System;
using System.Runtime.InteropServices;

namespace Program
{
    class Program
    {
        // Import FlsAlloc from kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint FlsAlloc(IntPtr callback);

        static void Main(string[] args)
        {
            // Allocate an FLS index without a callback
            uint flsAllocResult = FlsAlloc(IntPtr.Zero);

            // Check if the allocation failed
            if (flsAllocResult == uint.MaxValue)
            {
                // terminate
                return;
            }
 
        }
    }
}

// ======================================================================================================================================================================================================

// Options 2: Delegate usage
// ======================================================================================================================================================================================================

using System;
using System.Runtime.InteropServices;

namespace Program
{
    class Program
    {
        // Import kernel32.dll functions
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        static extern IntPtr LoadLibraryA(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        // Define the delegate that matches the FlsAlloc function signature
        private delegate uint FlsAllocDelegate(IntPtr callback);

        static void Main(string[] args)
        {
            // Load kernel32.dll
            IntPtr kernel32Handle = LoadLibraryA("kernel32.dll");

            // Get the address of FlsAlloc function
            IntPtr pFlsAlloc = GetProcAddress(kernel32Handle, "FlsAlloc");

            // Convert the function pointer to a delegate
            FlsAllocDelegate FlsAlloc = (FlsAllocDelegate)Marshal.GetDelegateForFunctionPointer(pFlsAlloc, typeof(FlsAllocDelegate));

            // Allocate an FLS index without a callback
            uint flsAllocResult = FlsAlloc(IntPtr.Zero);

            // Check if the allocation failed
            if (flsAllocResult == uint.MaxValue)
            {
                // terminate
                return;
            }
        }
    }
}
// ======================================================================================================================================================================================================
