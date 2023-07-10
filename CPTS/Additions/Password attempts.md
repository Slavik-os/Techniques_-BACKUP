-  Check default passwords 
```bash
admin:admin
admin:password
admin:<Machine name>
admin:<Cms name>
<Cms name>:<Cms name>
<Username>:<Username>
Google default creds
Node : pass password as object
{"username" : "admin", "password" : {"password": 1}}, username=admin&password[password]=1
```


### #Cewl 

- Generate custome word list from web page
```shell
Sauuron@htb[/htb]$ cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10
```