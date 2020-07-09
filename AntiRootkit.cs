using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Stoppad
{
    class Program
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern UIntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(UIntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint ExitCode);

        static void Main(string[] args)
        {
            Process.EnterDebugMode();
            Console.WriteLine("Setting privileges...");
            Console.WriteLine("Start analysis...");

            Thread.Sleep(3000);

            List<int> Normal = new List<int>();

            List<int> PB = new List<int>();

            Process[] processlist = Process.GetProcesses();

            foreach (Process theprocess in processlist)
            {
               
                Normal.Add(theprocess.Id);
            }


            uint exitCode;

            for (uint x = 0; x < 0xFFFF; x = x + 4)
            {
            UIntPtr handle = OpenProcess(0x0400 | 0x0010, false, x);
       

            if ((int)handle!=0)
            {

            GetExitCodeProcess((IntPtr)(int)(uint)handle, out exitCode);
                    
            if (exitCode == 259)

                    {

                   
                        PB.Add((int)x);
                   
                    }
                  }
              }

            PB = PB.Except(Normal).ToList();     

            if (PB.Count>0)

            {
                Console.ForegroundColor = ConsoleColor.Red;
                foreach (var element in PB)
                {
                    Console.WriteLine("Possible hidden process: " + element + " Re-check in TaskManager. If visible - ok. Else - possible Rootkit!");
                }
            }
            else
            
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("No hidden process found!");
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
        }
    }
