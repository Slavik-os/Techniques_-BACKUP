- Domains and subdomains .
- IP Ranges .
- Infrastructure .
- Virtual Hosts .

### <span style='color :#13f213'>Passive enumeration </span>
 - Gather public information, no need to interact directly with the host, using shodan, whois ... etc .

### <span style='color :#13f213'>Active enumeration </span>
 - Directly interact with the host,  contains  ports scanning, host enumeration, DNS, Directory bruteforcing, vhost enumeration, web application crawling/spidering,... etc .


# Passive subdomains enumeration

- Curl
```shell
Sauuron@htb[/htb]$ export TARGET="facebook.com"
Sauuron@htb[/htb]$ curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"
```

-  Openssl
```shell
Sauuron@htb[/htb]$ export TARGET="facebook.com"
Sauuron@htb[/htb]$ export PORT="443"
Sauuron@htb[/htb]$ openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u

*.facebook.com
*.facebook.net
*.fbcdn.net
*.fbsbx.com
*.m.facebook.com
*.messenger.com
*.xx.fbcdn.net
*.xy.fbcdn.net
*.xz.fbcdn.net
facebook.com
messenger.com
```

### <span style='color :#13f213'>The harvester </span>
- sources.txt
```shell
baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

```shell
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
```

```shell
Sauuron@htb[/htb]$ cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```
```shell
Sauuron@htb[/htb]$ cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
Sauuron@htb[/htb]$ cat facebook.com_subdomains_passive.txt | wc -l

11947
```

- ###  Older version
http://web.archive.org

### WafW00f
```shell
Sauuron@htb[/htb]$ wafw00f -v https://www.tesla.com

                   ______
                  /      \
                 (  Woof! )
                  \  ____/                      )
                  ,,                           ) (_
             .-. -    _______                 ( |__|
            ()``; |==|_______)                .)|__|
            / ('        /|\                  (  |__|
        (  /  )        / | \                  . |__|
         \(_)_))      /  |  \                   |__|

                    ~ WAFW00F : v2.1.0 ~
    The Web Application Firewall Fingerprinting Toolkit

[*] Checking https://www.tesla.com
[+] The site https://www.tesla.com is behind CacheWall (Varnish) WAF.
[~] Number of requests: 2
```

# Active Subdomain Enumeration

- Online zonetransfer : 
	https://hackertarget.com/zone-transfer/

- nslookup
```shell
nslookup -type=NS zometransfer.me # -type=any & -query=AXFR
```

- Gobuster with patern
	-   `dns`: Launch the DNS module
	-   `-q`: Don't print the banner and other noise.
	-   `-r`: Use custom DNS server
	-   `-d`: A target domain name
	-   `-p`: Path to the patterns file
	-   `-w`: Path to the wordlist
	-   `-o`: Output file

```sql
Sauuron@htb[/htb]$ export TARGET="facebook.com"
Sauuron@htb[/htb]$ export NS="d.ns.facebook.com"
Sauuron@htb[/htb]$ export WORDLIST="numbers.txt"
Sauuron@htb[/htb]$ gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"

Found: lert-api-shv-01-sin6.facebook.com
Found: atlas-pp-shv-01-sin6.facebook.com
Found: atlas-pp-shv-02-sin6.facebook.com
Found: atlas-pp-shv-03-sin6.facebook.com
Found: lert-api-shv-03-sin6.facebook.com
Found: lert-api-shv-02-sin6.facebook.com
Found: lert-api-shv-04-sin6.facebook.com
Found: atlas-pp-shv-04-sin6.facebook.com
```

- FQDN 
```shell
dig ns <domain> @ip
```

- Zone-transfer
```shell
dig axfr <domain> @ip
```



### #VHOST

```shell
Sauuron@htb[/htb]$ cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done
```

- FFUF subfolders fuzzing

```shell
Sauuron@htb[/htb]$ ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
```

### #Cewl

```shell
Sauuron@htb[/htb]$ cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10
```

- Ffuf with extensions from Cewl
```sql
Sauuron@htb[/htb]$ ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS
```
