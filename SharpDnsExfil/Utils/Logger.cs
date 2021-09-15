using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpDnsExfil.Utils
{
    class Logger
    {
        public static void WriteLine(string message, bool Verbose)
        {
            if (Verbose)
            {
                message = $"[VERBOSE] {message}";
                Console.WriteLine(message);
            }
        }
    }
}
