using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;

namespace SharpDnsExfil.Utils
{
    class Options
    {
        [Option('v', "verbose", Required = false, HelpText = "Set output to verbose messages.")]
        public bool Verbose { get; set; }

        [Option('f', "file", Required = true, HelpText = "Full filepath to target file")]
        public string FilePath { get; set; }

        [Option('s', "server", Required = true, HelpText = "Remote DNSServer IP/Hostname")]
        public string Server { get; set; }

        [Option('d', "domain", Required = false, HelpText = "Custom domain name [ Default = \"fakedomain.my\" ]")]
        public string Domain { get; set; } = "fakedomain.my";

        [Option('e', "encrypt", Required = false, HelpText = "Encrypt key [OPSEC]")]
        public bool Encrypt { get; set; }

    }
}
