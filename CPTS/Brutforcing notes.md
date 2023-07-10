Generate custome wordlist with rules
```shell
hashcat --force <password.list>  -r <custume.rule> --stdout > wordlist.list
```

Narrow down password attempts
```shell
cat wordlist.list | grep -E "^.{11,}$" # 11chars + 
```

### Crackmapexec
- brute smb
```shell
cme smb <ip> -u <user/users.list> -p <password/passwords.list>
```

- Enum password policy

```shell
cme smb <ip> -u <user/users.list> -p <password/passwords.list> --pass-pol
```