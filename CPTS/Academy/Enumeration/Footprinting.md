
--------
# Enumeration
1. understand the company internal and external infrastricture, get a general idea what services the company might be using .

-  <mark style="background: #FF5582A6;">What can we see?</mark>
-  <mark style="background: #FF5582A6;">What reasons can we have for seeing it?</mark>
-  <mark style="background: #FF5582A6;">What reasons can we have for seeing it?</mark>
-  <mark style="background: #FF5582A6;">What can we not see?</mark>
-  <mark style="background: #FF5582A6;">What can we not see?</mark>
-  <mark style="background: #FF5582A6;">What can we not see?</mark>
-  <mark style="background: #FF5582A6;">What image results for us from what we do not see?</mark>
-  <mark style="background: #FF5582A6;">What image results for us from what we do not see?</mark>

1. principles

| No. | principle                                                              |
| --- | ---------------------------------------------------------------------- |
| 1.  | There is more than meets the eye. Consider all points of view.         |
| 2.  | Distinguish between what we see and what we do not see.                |
| 3.  | There are always ways to gain more information. Understand the target. |                                                                        |

------------------

# Enumeration approch  (labyrinth)

![[enum-method3.png]]

1. Internet presence : find , hosts, domains, subdomains, interfaces,  netblocks. and many 
 - <mark style="background: #BBFABBA6;">the goal of this layer is to identify all the target system interfaces that can be tested .</mark>

2. Gateway : find , what IPS/IDS being in use, the gateway architecture,vhosts, ...etc,
- <mark style="background: #BBFABBA6;"> the goal is to understand what we're dealing with and what do we need to watch out for .</mark>

3. Accessible servicses : find services running and understand what the points of having them, otherwise understand them .
- <mark style="background: #BBFABBA6;">this layer aims to understand the reason funcionality of the target system and gain necessery knowledge to to communicat with it and exploit it for our purpose effectievly .</mark>

4. Processes : each time a command is executed it create a proccess
- <mark style="background: #BBFABBA6;">Our goal is to identify ad understand the factor of the dependecies between the destination and the process .</mark>

5. Privileges : Each service runs through a specific user in a particular group with permissions and privleges defiened by Administrator, this privleges often provides us with functionalities the administrator overlooked .
- <mark style="background: #BBFABBA6;">It is crucial to identify these and understand what is and is not possible with these privileges.</mark>


6. OS Setup : Here we collect informations about the internal system and get an over view about the internal security and reflects the skills and capabilities of the company's administrative teams.
- <mark style="background: #BBFABBA6;">The goal here is to see how the administrators manage the systems and what sensitive internal information we can glean from them.</mark>

# Internat enumerations

1. Shodan
2. Dig
3. crt.sh
4. domain.glass
5. GrayHatWarfare

# #FTP

- TFTP/UDP, rely on UDP-assisted application layer recovery.
config :
```bash
cat	/etc/vsftpd.conf | grep -v "#"
```

Blacklisted users from accessing TFTP
```bash
cat /etc/ftpusers
```

- Dangerous Settings

| Setting                      | Description                                                             |
| ---------------------------- | ----------------------------------------------------------------------- |
| anonymous_enableed=YES       | Allow anonymous login ?                                                 |
| anon_upload_enabled=YES      | Alow anonymous upload files?                                            |
| anon_mkdir_write_enable=YES  | Allowing anonymous to create new directories?                           |
| no_anon_password=YES         | Do not ask anonymous for password ?                                     |
| anon_root=/home/username/ftp | Directory for anonymous                                                 |
| write_enable=YES             | Allow usage of FTP commands: STOR,DELE,RNFR,RNTO,MKD,RMD,APPE,and SITE? |

- Show more aditional informations
 - debug, trace

- FTP via SSL/TLS connect
```bash
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```


# #SMB

#smb : Server message block, designed for OS/2 communication module for windows .
#samba : open project unix based to allow hosts to comunicate with smb on older, newer,  machines 
#CIFS : Extention of samba designed by windows, communicate to older machines and pass commands through NetBIOS service, it usually connects to samba server over TCP ports , 137, 138, 139, but CIFS uses port 445.

- <mark style="background: #FFB86CA6;">SMB Version, that could help identify the Windows version .</mark>

| SMB VERSION | Supported                           | Featres                                                                |
| ----------- | ----------------------------------- | ---------------------------------------------------------------------- |
| CIFS        | Windows NT 4.0                      | Communication via NetBIOS interface                                    |
| SMB 1.0     | Windows 2000                        | Direct connection via TCP                                              |
| SMB 2.0     | Windows Vista, Windows Server 2008  | Performance upgrades, improved message signing, caching feature        |
| SMB 2.1     | Windows 7, Windows Server 2008 R2   | Locking mechanisms                                                     |
| SMB 3.0     | Windows 8, Windows Server 2012      | Multichannel connections, end-to-end encryption, remote storage access |
| SMB 3.0.2   | Windows 8.1, Windows Server 2012 R2 |                                                                        |
| SMB 3.1.1   | Windows 10, Windows Server 2016     | Integrity checking, AES-128 encryption                                 |

With Version 3, the Samba server gained the ability to be full member of the active directory domain.

NetBios environment, when a machine goes online, it needs a name, that is done through name registration procedure. Ether each host reverves its hostname on the network, or the NetBIOS Name Server (NBNS) is used,
it's also ben enhenced to Windows Internet Name Service (WINS).

```shell
sudo smbstatus // Show Machines connected to smb.
```

SMB enumeration though RCP

```shell
rpcclient $> srvinfo 

        DEVSMB         Wk Sv PrQ Unx NT SNT DEVSM
        platform_id     :        500
        os version      :       6.1
        server type     :       0x809a03
		
		
rpcclient $> enumdomains

name:[DEVSMB] idx:[0x0]
name:[Builtin] idx:[0x1]


rpcclient $> querydominfo

Domain:         DEVOPS
Server:         DEVSMB
Comment:        DEVSM
Total Users:    2
Total Groups:   0
Total Aliases:  0
Sequence No:    1632361158
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1


rpcclient $> netshareenumall

netname: print$
        remark: Printer Drivers
        path:   C:\var\lib\samba\printers
        password:
netname: home
        remark: INFREIGHT Samba
        path:   C:\home\
        password:
netname: dev
        remark: DEVenv
        path:   C:\home\sambauser\dev\
        password:
netname: notes
        remark: CheckIT
        path:   C:\mnt\notes\
        password:
netname: IPC$
        remark: IPC Service (DEVSM)
        path:   C:\tmp
        password:
		
		
rpcclient $> netsharegetinfo notes

netname: notes
        remark: CheckIT
        path:   C:\mnt\notes\
        password:
        type:   0x0
        perms:  0
        max_uses:       -1
        num_uses:       1
revision: 1
type: 0x8004: SEC_DESC_DACL_PRESENT SEC_DESC_SELF_RELATIVE 
DACL
        ACL     Num ACEs:       1       revision:       2
        ---
        ACE
                type: ACCESS ALLOWED (0) flags: 0x00 
                Specific bits: 0x1ff
                Permissions: 0x101f01ff: Generic all access SYNCHRONIZE_ACCESS WRITE_OWNER_ACCESS WRITE_DAC_ACCESS READ_CONTROL_ACCESS DELETE_ACCESS 
                SID: S-1-1-0
```


# User enumeration
- RPC
```shell
rpcclient $> enumdomusers

user:[mrb3n] rid:[0x3e8]
user:[cry0l1t3] rid:[0x3e9]


rpcclient $> queryuser 0x3e9

        User Name   :   cry0l1t3
        Full Name   :   cry0l1t3
        Home Drive  :   \\devsmb\cry0l1t3
        Dir Drive   :
        Profile Path:   \\devsmb\cry0l1t3\profile
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Do, 01 Jan 1970 01:00:00 CET
        Logoff Time              :      Mi, 06 Feb 2036 16:06:39 CET
        Kickoff Time             :      Mi, 06 Feb 2036 16:06:39 CET
        Password last set Time   :      Mi, 22 Sep 2021 17:50:56 CEST
        Password can change Time :      Mi, 22 Sep 2021 17:50:56 CEST
        Password must change Time:      Do, 14 Sep 30828 04:48:05 CEST
        unknown_2[0..31]...
        user_rid :      0x3e9
        group_rid:      0x201
        acb_info :      0x00000014
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...


rpcclient $> queryuser 0x3e8

        User Name   :   mrb3n
        Full Name   :
        Home Drive  :   \\devsmb\mrb3n
        Dir Drive   :
        Profile Path:   \\devsmb\mrb3n\profile
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Do, 01 Jan 1970 01:00:00 CET
        Logoff Time              :      Mi, 06 Feb 2036 16:06:39 CET
        Kickoff Time             :      Mi, 06 Feb 2036 16:06:39 CET
        Password last set Time   :      Mi, 22 Sep 2021 17:47:59 CEST
        Password can change Time :      Mi, 22 Sep 2021 17:47:59 CEST
        Password must change Time:      Do, 14 Sep 30828 04:48:05 CEST
        unknown_2[0..31]...
        user_rid :      0x3e8
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
```

- Rpcclient - Group Information
```shell
rpcclient $> querygroup 0x201

        Group Name:     None
        Description:    Ordinary Users
        Group Attribute:7
        Num Members:2
```

- Rpcclient - user bruteforce RID
```bash
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

- Impacket - bruteforce user RID
```bash
samrdump.py <ip add>
```

- Crackmapexec
```bash
crackmapexec smb 10.129.14.128 --shares -u '' -p ''
```

------
# #NFS
- nmap enumeration
```shell
sudo nmap --script nfs* 10.0.0.1 -sv -p111,2049
```

- show available mounts
```shell
showmount -e 10.0.0.1
```

- Mount NFS share
```shell
sudo mount -t nfs 10.0.0.1:/<dir> ./target-NFS -o nolocks
```

- Mount NFS macOS work around
```bash
sudo mount -o resvport,nolocks  -t nfs 10.129.202.5:/var/nfs nfs/
```

# NFS no_root_squash/no_all_squash misconfiguration
<mark style="background: yellow; color :red">if the no_root_squash flag is set,  "read /etc/exports " , we can priv esc as root</mark>


# #DNS

| Server Type                  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| DNS ROOT SERVER              | The root servers of the DNS are responsible for the top-level domains (`TLD`). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The [Internet Corporation for Assigned Names and Numbers](https://www.icann.org/) (`ICANN`) coordinates the work of the root name servers. There are `13` such root servers around the globe. |
| Authorative Nameserver       | Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point.                                                                                                                                                                                                            |
| Non-authoritative Nameserver | Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying.                                                                                                                                                                                                                                                                               |
| Caching DNS Server           | Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.                                                                                                                                                                                                                                                                                                                             |
| Forwarding Server            | Forwarding servers perform only one function: they forward DNS queries to another DNS server.                                                                                                                                                                                                                                                                                                                                                                                            |
| Resolver                     | Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.                                                                                                                                                                                                                                                                                                                                                                               |

![[Pasted image 20230331220559.png]]

usefull #DNS queries to atrive records

| DNS Record | Descriptpion                                                                                                                                                                                                                                      |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A          | Returns an IPV4 address of the requested domain as a result.                                                                                                                                                                                      |
| AAAA       | Returns an IPV6 address of the requested domain as a result.                                                                                                                                                                                      |
| MX         | Returns the responsible mail server as a result.                                                                                                                                                                                                  |
| NS         | Returns the DNS servers (nameservers) of the domain.                                                                                                                                                                                              |
| TXT        | This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam. |
| CNAME      | serves as alias. if the domin www.hackthebox.euy should point to the same IP address, and we create an A record for one and CNAME record for the other.                                                                                           |
| PTR        | Reverse lookup from ip to valid domain names.                                                                                                                                                                                                     |
| SOA        | Provides information about the corresponding DNS zone and email address of the administrative contact.                                                                                                                                            |
| ANY        | View all the available records.                                                                                                                                                                                                                   |
| CH         | Show aditional information I,E verion.                                                                                                                                                                                                            |
| AXFR       | Full transferzone.                                                                                                                                                                                                                                |


```shell
dig soa www.inlanefreight.com

; <<>> DiG 9.16.27-Debian <<>> soa www.inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15876
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;www.inlanefreight.com.         IN      SOA

;; AUTHORITY SECTION:
inlanefreight.com.      900     IN      SOA     ns-161.awsdns-20.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400

;; Query time: 16 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Thu Jan 05 12:56:10 GMT 2023
;; MSG SIZE  rcvd: 128

```
(.) is replaced with @ ; ns-161@awsdns-20.com (Administrator Accomunt)

## Dangerous Settings

| Option          | Description                                                                    |
| --------------- | ------------------------------------------------------------------------------ |
| allow-query     | Defines which hosts are allowed to send requests to the DNS server.            |
| allow-recursion | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| allow-transfer  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| zone-statistics | Collects statistical data of zones.                                            |

# Enumerate DNS verison 
```shell
dig CH TXT version.bind <IP>
```

## Subdomain Brute Force
- DIG
```shell
for sub in $(cat /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

- DNSenum

```shell
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

# #IMAP/POP3

- Connection plain text
```shell
curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd -v
```

- Connection SSL/TLS

```shell
openssl s_client -connect 10.129.14.128:pop3s # POP3
openssl s_client -connect 10.129.14.128:imaps # IMAP
```

# #mssql

- SQL
```sql
# Databases name
select name from sys.databases

# Tables name
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES

# Clause
SELECT NAME, PASSWORD FROM <TABLE_NMAE> WHERE name = 'TEST';
```

- nmap scripts enumeration
```shell
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

- Metasploit auxilary scan
```shell
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248
msf6 auxiliary(scanner/mssql/mssql_ping) > run
```

- Connect to server
```shell
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

# #OracleTNS

Oracle TNS can be remotely managed in `Oracle 8i`/`9i` but not in Oracle 10g/11g.

The configuration files for Oracle TNS are called<mark style="color: lightgreen; background:none"> tnsnames.ora</mark> and <mark style="color: lightgreen; background:none">listener.ora </mark>and are typically located in the <mark style="color: lightgreen; background:none">ORACLE_HOME/network/admin</mark> directory.

The Oracle DBSNMP service also uses a default password, <mark style="background: #BBFABBA6;">dbsnmp</mark> .
- Bruteforcing SID's
```shell
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```

### odat install.sh
```bash
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien python3-pip -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
sudo submodule update
sudo apt install oracle-instantclient-basic oracle-instantclient-devel oracle-instantclient-sqlplus -y
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor pycryptodome passlib python-libnmap
sudo pip3 install argcomplete && sudo activate-global-python-argcomplete
```

```shell
 ./odat.py all -s 10.129.204.235
```

#### SQLplus - Log In
```shell
sqlplus scott/tiger@10.129.204.235/XE;
```

libraries: libsqlplus.so error  solution 
```shell
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```

### sqlplus commands
https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985

```sql
select table_name from all_tables;
select * from user_role_privs;
```

### switching to (sysdba)
possible when the user has the appropriate privileges typically granted by the database administrator or used by the administrator him/herself.
```shell
sqlplus scott/tiger@10.129.204.235/XE as sysdba
```
### dump passwords hashes

```sql
select name, password from sys.user$;
```

### uploading a file 
```shell
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```


# #IPMI

### Footprinting
```shell
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

### Metasploit Version Scan

```shell
Metasploit use auxiliary/scanner/ipmi/ipmi_version 
```

### Default passwords

| Product         | Username      | Password                                                                  |
| --------------- | ------------- | ------------------------------------------------------------------------- |
| Dell iDRAC      | root          | calvin                                                                    |
| HP ILO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                                                     |

### #RSYNC

- Used for copying, backups, list shares ... etc, over ssh
- <a href="https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync" >Hacktricks</a>
```shell
 nc -nv 127.0.0.1 873

(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
dev            	Dev Tools
@RSYNCD: EXIT
```

#### Enumerating an Open Share
```shell
rsync -av --list-only rsync://127.0.0.1/dev

receiving incremental file list
drwxr-xr-x             48 2022/09/19 09:43:10 .
-rw-r--r--              0 2022/09/19 09:34:50 build.sh
-rw-r--r--              0 2022/09/19 09:36:02 secrets.yaml
drwx------             54 2022/09/19 09:43:10 .ssh

sent 25 bytes  received 221 bytes  492.00 bytes/sec
total size is 0  speedup is 0.00
```

From here we can pull the files by syncing all files to our attack box .
```shell
rsync -av rsync://127.0.0.1/dev
```
If rsync using ssh we could modify our command, if none standard port is used for ssh, <a href="https://phoenixnap.com/kb/how-to-rsync-over-ssh" > Syntax</a> .
```shell 
-e "ssh -p2222"
```

------------------

### #R-commands 

-   rcp (`remote copy`)
-   rexec (`remote execution`)
-   rlogin (`remote login`)
-   rsh (`remote shell`)
-   rstat
-   ruptime
-   rwho (`remote who`)
config 
```shell
 /etc/hosts.equiv
```


----------

### #RDP

```shell
rdp-sec-check.pl => https://github.com/CiscoCXSecurity/rdp-sec-check.git 
```

```shell
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```

### #WINRM

```shell
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```

### #WMI

```shell
 /usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
```
