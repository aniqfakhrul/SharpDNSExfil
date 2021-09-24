using System;
using System.IO;
using System.Text;
using ICSharpCode.SharpZipLib.Core;
using ICSharpCode.SharpZipLib.Zip;

namespace SharpDnsExfil.Utils
{
    class Zip
    {
        public static String BytesToString(long byteCount)
        {
            string[] suf = { "B", "KB", "MB", "GB", "TB", "PB", "EB" }; //Longs run out around EB
            if (byteCount == 0)
                return "0" + suf[0];
            long bytes = Math.Abs(byteCount);
            int place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
            double num = Math.Round(bytes / Math.Pow(1024, place), 1);
            return (Math.Sign(byteCount) * num).ToString() + suf[place];
        }

        public static (MemoryStream memStream, int entryCount) CompressFilesMemoryStream(Options opts, string[] filePaths, string password, string rootDirectory = "", int maxFileSize = 0)
        {

            int entryCount = 0;
            MemoryStream outputMemStream = new MemoryStream();

            using (ZipOutputStream zipStream = new ZipOutputStream(outputMemStream))
            {

                zipStream.SetLevel(9);
                zipStream.Password = password;

                foreach (var filePath in filePaths)
                {
                    try
                    {

                        using (FileStream file = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                        {
                            if ((file.Length / 1048576.0) <= maxFileSize || maxFileSize == 0)
                            {
                                ZipEntry newEntry = null;
                                if (string.IsNullOrEmpty(rootDirectory))
                                {
                                    newEntry = new ZipEntry(Path.GetFileName(filePath));
                                    Logger.WriteLine($"[+] Compressing {filePath} {BytesToString(file.Length)}", opts.Verbose);
                                }
                                else
                                {
                                    Logger.WriteLine($"[+] Compressing {filePath.Substring(rootDirectory.Length).TrimStart('\\')} {BytesToString(file.Length)}",opts. Verbose);
                                    newEntry = new ZipEntry(filePath.Substring(rootDirectory.Length).TrimStart('\\'));
                                }
                                newEntry.DateTime = DateTime.UtcNow;

                                zipStream.PutNextEntry(newEntry);
                                entryCount++;
                                StreamUtils.Copy(file, zipStream, new byte[4096]);
                                zipStream.CloseEntry();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        if (string.IsNullOrEmpty(rootDirectory))
                            Console.WriteLine($"[!] Failed to compress {filePath} , file locked by another process?");
                        else
                            Console.WriteLine($"[!] Failed to compress {filePath.Substring(rootDirectory.Length).TrimStart('\\')}, file locked by another process?");
                    }
                }

                zipStream.IsStreamOwner = false;
                zipStream.Close();

                outputMemStream.Position = 0;



                return (outputMemStream, entryCount);
            }

        }
    }
}
