## <span style="color:yellow"> Valid Users list</span>

#### Enum4linux smb null Authentication
```shell
Sauuron@htb[/htb]$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

#### Using rpcclient

```shell
Sauuron@htb[/htb]$ rpcclient -U "" -N 172.16.5.5
```

#### CrackMapExec

```shell
Sauuron@htb[/htb]$ crackmapexec smb 172.16.5.5 --users
```



#### Using CrackMapExec with Valid Credentials

```shell
Sauuron@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

#### Using windapsearch

```shell
Sauuron@htb[/htb]$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```


#### Ldapsearch

```shell
Sauuron@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```


## <span style="color:yellow"> No access at all to validate users</span>

```shell
Sauuron@htb[/htb]$  kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

