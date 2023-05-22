Generate custome wordlist with rules
```shell
hashcat --force <password.list>  -r <custume.rule> --stdout > wordlist.list
```

Narrow down password attempts
```shell
cat wordlist.list | grep -E "^.{11,}$" # 11chars + 
```

