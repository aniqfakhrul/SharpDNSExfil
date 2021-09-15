using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpDnsExfil.Utils
{
    class EncryptionUtils
    {
        private static Random random = new Random();

        public static byte[] GetRandomKey(int MAX_SIZE)
        {
            byte[] key = new byte[MAX_SIZE];

            for (int i = 0; i < 32; i++)
            {
                random.NextBytes(key);
            }
            return key;
        }

        public static byte[] GetRandomIV()
        {
            byte[] iv = new byte[16];

            for (int i = 0; i < 16; i++)
            {
                random.NextBytes(iv);
            }
            
            return iv;
        }
        
        public static string GenerateRandomKey(int length)
        {
            const string chars = "ABCDE!+FGHIJKLMNOPQRSTUVWXY!+Zabcdefghijklmnopqrs!+tuvwxyz0123456789!+";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
