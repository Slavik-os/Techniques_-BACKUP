	Most scanning tools have a timeout when waiting for a response so if they aren't getting a response back from the service, or doesn't response in a spesific time the service / port would be marked as closed ,
so it's critical to do manualle scanning.

--------
# Use Cases

-   Audit the security aspects of networks
-   Simulate penetration tests
-   Check firewall and IDS settings and configurations
-   Types of possible connections
-   Network mapping
-   Response analysis
-   Identify open ports
-   Vulnerability assessment as well.
--------

# Nmap Architecture
-   Host discovery
-   Port scanning
-   Service enumeration and detection
-   OS detection
-   Scriptable interaction with the target service (Nmap Scripting Engine)

Syntax
```bash
nmap <scan types> <options> <target>
```
--------
# Three way handshak

![[Pasted image 20230324195618.png]]

----------------
# Arguments

- -sS : set to default when running as root sience nmap needs to create raw tcp sockets , sends hyst the SYN packets, and doesn't need to wait for the ACK, preforming only half three way hadnshake.
 if the target sends a SYN / ACK packet nmap resolve the port as open,
 if it sends a RST packet then thats a closed port. and if no packet is sent back to nmap it often treats it as filtered for the port could be behind a fire-wall .
- -sn : Disable port scanning,  comes in handy when doing a network range scan for new hosts, 10.0.0.0/24.
- -iL : scan from list
```bash
sudo nmap -sn -oA tnet -iL host.lst
```
- -PE : ICMP echo requests, if the target replies, nmap treats the target as alive
- nmap sends an ARP ping resulting in an ARP reply. to the target as it first initials the scan, and this could be confirmed with "--packet-trace" .
- --packet-trace : show all the packets sent and recieved .
- --reason : An other way to determine why nmap has seen the target as "alive".
- -Pn : disable ICMP echo .
- -sT : default if not ran as root, most stealthy scan, because it doesn't leave an unfinished scan or unsent packets on the target host, which makes it less likely tobe detected by instruction detection system (IDS) or IPS .
--------------
# Host  and Port scanning

- There's 6 diffrent states

| State           | Description                                                                                                                                                            |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| open            | This indicates that the connection to the scanned port has been established. these connections can be TCP, UDP datagrames or SCTP associations.                        |
| closed          | When the port is shown closed, the TCP protocol indicates that the packet recieved containts a RST flag. this method can also determen if our targetr is alive or not. |
| filtered        | Nmap cannot edentify if the port is closed or not, often the TCP protocol doesn't response back or just drops the packets, or we get a code error.                     |
| unfiltered      | this state accurent in the SYN-ACK state where the port appears accecible but it cannot be determined if its open or not .                                             |
| filtered/open   | we get a response back form specific port, this indicates that a firewall is packet filter may be protecting the port.                                                 |
| closed/filtered | this state only accurs in the IP ids scans that is impossible to detemine if the port is open .                                                                        |

Html output
```bash
xsltproc <file.xml> > <file.html>
```
--------------
# Important

sometimes the service reply with more information after the three-way-hand shake is compeleted through a PSH flag, therefore nmap doenst know what to do with it, and miss it out .
- we could work around this using #tcpdump & #nc, or just set --packet-trace flag .

- TCPDUMP
```bash
Sauuron@htb[/htb]$ sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode

listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
```

- NC
```bash
Sauuron@htb[/htb]$  nc -nv 10.129.2.28 25

Connection to 10.129.2.28 port 25 [tcp/*] succeeded!
220 inlane ESMTP Postfix (Ubuntu)
```

- TCPDUMP - intercepted Traffic
```bash
18:28:07.128564 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [S], seq 1798872233, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 331260178 ecr 0,sackOK,eol], length 0
18:28:07.255151 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [S.], seq 1130574379, ack 1798872234, win 65160, options [mss 1460,sackOK,TS val 1800383922 ecr 331260178,nop,wscale 7], length 0
18:28:07.255281 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 1, win 2058, options [nop,nop,TS val 331260304 ecr 1800383922], length 0
18:28:07.319306 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [P.], seq 1:36, ack 1, win 510, options [nop,nop,TS val 1800383985 ecr 331260304], length 35: SMTP: 220 inlane ESMTP Postfix (Ubuntu)
18:28:07.319426 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 36, win 2058, options [nop,nop,TS val 331260368 ecr 1800383985], length 0
```
--------------
# Preformance

#RTT, Round-tip-time, lets you use text to communicate durring phone call,  and is the amount of time it takes for a signal to be sent to desntination and back .
--initial-rtt-timeout : 50ms, 
--max-rtt-timeout : 100ms 

--max-rate : send number of packets , nmap try to keep the number of those packets accordenly .

- Timing
| time | description |
| ---- | ----------- |
| -T 0 | paranoid    |
| -T 1 | sneaky      |
| -T 2 | polite      |
| -T 3 | normal      |
| -T 4 | aggresive   |
| -T 5 | insane      |

----------------
# Firewall and IDS/IPS Evasion

-sA : ACK scan, sends ACK packets which confuse the IDS/IPS if the packets are sent externaly or internaly .

-D : decoy flag, generate random IP addresses,and changes it in the packet header takes also RND flag.

```bash
nmap <HOST> -D RND:<number of ips> 
```

-S : scans the target using diffrent source IP.
-e : sends all requests through sepecific interface.
--source-port : sepecify source port, for most of the times internal DNS is moret trusted to use , administrators forgets to controll this porn and does not filter IDS/IPS properly, therefore our TCP packet would be trusted and passed through.

```bash
nmap -p5000 --source-port 53 -sS 10.10.10.1 -Pn -n --disable-arp-ping --packet-trace
```
