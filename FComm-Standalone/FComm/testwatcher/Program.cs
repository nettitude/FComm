using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading;

namespace testwatcher
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("TestWatcher!");
            Console.WriteLine(Path.GetDirectoryName(args[1]));
            Console.WriteLine(Path.GetFileName(args[1]));
            Console.WriteLine();
            if (args[0] == "writer")
            {
                while (true)
                {
                    try
                    {
                        writeCommand(args[1]);
                    }catch (Exception E)
                    {
                        Console.WriteLine(E.Message);
                        Console.WriteLine(E.StackTrace);
                    }
                }
            }
            else if (args[0] == "reader")
            {
                while (true)
                {
                    Thread.Sleep(5000);
                    readCommand(args[1]);
                }
            }
        }

        static void writeCommand(string FilePath)
        {
            Console.Write("> ");
            string command = Console.ReadLine();
            FileStream f = null;
            while (f == null)
            {
                try
                {
                    f = new FileStream(FilePath, FileMode.Create, FileAccess.Write);
                    StreamWriter sr = new StreamWriter(f);
                    sr.WriteLine(command);
                    sr.Close();
                    f.Close();
                    sr.Dispose();
                    f.Dispose();
                }
                catch (IOException)
                {
                    Thread.Sleep(300);
                }
            }
        }

        static void readCommand(string FilePath)
        {
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
                        Console.WriteLine("Command Read 1 : " + line);
                    }
                    sr.Close();
                    f.Close();
                    sr.Dispose();
                    f.Dispose();
                    File.Delete(FilePath);
                }
                catch (IOException)
                {
                    Thread.Sleep(500);
                }
            }
            Console.WriteLine("out of f check.");
        }
    }
}
