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
