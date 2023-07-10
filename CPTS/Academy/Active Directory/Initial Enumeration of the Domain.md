
## <span style="color:yellow">Finding Hosts</span>

1. Find ARP Records
2. MDSN
3. SPING
4. Fping
5. arping
6. ping sweep


#### Nmap from hosts

```bash
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```


## <span style="color:yellow">Identifying Users </span>

### Kerbrute - Internal AD Username Enumeration

```shell
Sauuron@htb[/htb]$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

##  <span style="color:yellow">Identifying Potential Vulnerabilities </span>

#### Local system account
NT AUTHORITY\SYSTEM 
1. Remote Windows Exploits .
2. Abuse running services, or abuse service account seImpersonate privileges using [Juicy Potato](https://github.com/ohpe/juicy-potato). ( Patched on  > Windows 19) .
3. Local Privilege escalation flaws such as Windows 10 Task Scheduler 0-day .
4. Gaining admin access on a domain-joined host with a local account , Using PSexec to launch cmd .

#### <span style="color:yellow">After getting SYSTEM-level access </span>

- Enumerate the domain using built-in tools or offensive tools such as BloodHound and PowerView.
- Perform Kerberoasting / ASREPRoasting attacks within the same domain.
- Run tools such as Inveigh to gather Net-NTLMv2 hashes or perform SMB relay attacks.
- Perform token impersonation to hijack a privileged domain user account.
- Carry out ACL attacks.
