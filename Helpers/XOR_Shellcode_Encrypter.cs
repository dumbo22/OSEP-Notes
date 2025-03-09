using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace XOR_Shellcode_Encrypter_Helper
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

            byte[] buf = new byte[2] { 0xfc, 0x48 };

            byte[] encoded = new byte[buf.Length];
            byte xorKey = ((byte)NextInt(1000, 1000000));

            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(buf[i] ^ xorKey);
            }

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }

            if (hex.Length > 0)
            {
                hex.Length -= 2;
            }

            Console.WriteLine();

            string fileContent = $"byte[] buf = new byte[{ buf.Length }] {{" + hex.ToString() + "};";
            string path = "xor_out.txt";
            File.WriteAllText(path, fileContent);

            Console.WriteLine($"[+] XOR Key         : {xorKey.ToString()}\r");
            Console.WriteLine("[+] Output File     : xor_out.txt");
            Console.WriteLine("[+] Encrypted Bytes :");
            Console.WriteLine();
            Console.WriteLine($"byte[] buf = new byte[{buf.Length}] {{" + hex.ToString() + "};");

        }

    }

}
