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
### Active Subdomain Enumeration
### Virtual Hosts
### Crawling

# Vulnerability Assessment

# File Transfers

# Shells & Payloads

# Password Attacks

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
