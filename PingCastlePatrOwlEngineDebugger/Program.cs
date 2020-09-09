using PingCastlePatrOwlEngine;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace PingCastlePatrOwlEngineDebugger
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This program is designed to debug the PingCastlePatrOwlEngine program");
            Console.WriteLine("This program needs to be run as admin or grant the current user to open the binding with netsh");
            Console.WriteLine("Any exception or trace will be displayed in this console");
            Console.WriteLine("=======================");
            //redirect the configuration file to the service file
            // important : the path is cached so this MUST be the first instruction
            string path = AppDomain.CurrentDomain.BaseDirectory + "PingCastlePatrOwlEngine.exe.config";
            Console.WriteLine("using config file : " + path);
            AppDomain.CurrentDomain.SetData("APP_CONFIG_FILE", path);

            Trace.Listeners.Add(new ConsoleTraceListener());
            Trace.AutoFlush = true;

            Service service = new Service();
            try
            {
                Console.WriteLine("Starting PingCastlePatrOwlEngine");
                Listener listener = new Listener();
                listener.Start();
                Console.WriteLine("Press enter to stop"); // Prompt
                string line = Console.ReadLine();
                listener.Stop();

            }
            catch (Exception ex)
            {
                Console.WriteLine("=======================");
                Console.WriteLine("Got exception:");
                while (ex != null)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine("");
                    Console.WriteLine(ex.StackTrace);
                    ex = ex.InnerException;
                    Console.WriteLine("=======================");
                }
            }
        }
    }
}
