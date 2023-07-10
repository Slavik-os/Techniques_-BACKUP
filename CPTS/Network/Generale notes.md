- Standar ports  between 0-1023 , well known or #SystemPorts (65,535 in Total) .

# Commen ports

| PORT(S)             | PROTOCOL        |
| ------------------- | --------------- |
| 20/21(TCP)          | FTP             |
| 22                  | SSH             |
| 23                  | Telnet          |
| 25 (TCP)            | SMTP            |
| 80                  | HTTP            |
| 161  (UDP)          | SNMP            |
| 389                 | LDAP            |
| 443                 | SSL/TLS (HTTPS) |
| 445 (TCP)           | SMB             |
| 3389                | RDP             |
| 111,2049            | NFS             |
| 1521 (TCP)          | Oracle TNS      |
| 161,162 (UDP)       | SNMP/SNMP HOP   |
| 53 (TCP / UDP)      | DNS             |
| 623 (UDP)           | IPMI            |
| 873 (TCP)           | RSYNC           |
| 512, 513, 514 (TCP) | R-services      |
| 5985,5986           | WINRM           |
| 135 (TCP)           | WMI             |


- Mount windows share on windows
```shell
sudo mount -t cifs //10.129.7.183/David share/ -o username=david,password=gRzX7YbeTcDG7
```